//! Isolated proxy objects built from an already verified managed snapshot.

use std::{cmp::Reverse, collections::HashMap, path::Path, sync::Arc};

use pingap_core::{ManagedSiteContext, ProxyTrust};
use pingap_location::ServerLocationRoute;
use pingap_proxy::{ManagedRequestSite, ManagedSiteSelector, Server};
use pingora::{
    apps::{HttpServerApp, HttpServerOptions, ReusedHttpStream},
    protocols::http::{ServerSession, v2::server::H2Options},
    proxy::{HttpProxy, Session},
    server::ShutdownWatch,
};
use pingwaf_agent::managed::{
    Candidate, Compiled, CompiledSite, Forwarding, Listener,
};
use uuid::Uuid;

use super::convert_proxy_config;

#[cfg(any(feature = "openssl", feature = "tls-rustls"))]
mod tls;

struct View {
    rules: Compiled,
    sites: HashMap<Uuid, ManagedRequestSite>,
    #[cfg(any(feature = "openssl", feature = "tls-rustls"))]
    tls: HashMap<Uuid, tls::TlsSite>,
}

impl View {
    fn build(candidate: &Candidate, cache_dir: &Path) -> anyhow::Result<Self> {
        let rules = candidate.compile()?;
        let sites = rules
            .sites()
            .map(|(id, site)| Ok((id, build_site(site, cache_dir)?)))
            .collect::<anyhow::Result<_>>()?;
        #[cfg(any(feature = "openssl", feature = "tls-rustls"))]
        let tls = candidate
            .sites()
            .iter()
            .filter(|(_, site)| {
                site.ingress.as_ref().is_some_and(|ingress| {
                    ingress.protocol() == pingwaf_proto::IngressProtocol::Https
                })
            })
            .map(|(id, _)| {
                use anyhow::Context;
                let ssl = rules
                    .site(*id)
                    .and_then(|site| site.rules.ssl_config.as_ref())
                    .with_context(|| {
                        format!(
                            "missing TLS configuration for managed site {id}"
                        )
                    })?;
                Ok((
                    *id,
                    tls::TlsSite::build(ssl).with_context(|| {
                        format!("TLS configuration for managed site {id}")
                    })?,
                ))
            })
            .collect::<anyhow::Result<_>>()?;
        Ok(Self {
            rules,
            sites,
            #[cfg(any(feature = "openssl", feature = "tls-rustls"))]
            tls,
        })
    }
}

fn build_site(
    site: &CompiledSite,
    cache_dir: &Path,
) -> anyhow::Result<ManagedRequestSite> {
    let (config, mut names) =
        convert_proxy_config(&site.translation_input(), cache_dir, false);
    // Stable sort preserves the same generated order for equal weights.
    names.sort_by_key(|name| Reverse(config.locations[name].get_weight()));
    let locations = crate::locations::isolated_locations(&config.locations)?;
    let route = Arc::new(ServerLocationRoute::build(names, |name| {
        locations.get(name)
    }));
    let upstreams = crate::upstreams::isolated_upstreams(
        &config.upstreams,
        config.basic.origin_verify_cert,
    )?;
    let plugins = crate::plugin::isolated_plugins(config.plugins)?;
    let trust = &site.rules.proxy_trust;
    Ok(ManagedRequestSite {
        context: ManagedSiteContext {
            id: site.rules.site_id.clone(),
            rules: site.rules.clone(),
        },
        route,
        trust: ProxyTrust::new(
            trust.enabled,
            trust.effective_header(),
            trust.last_hop_only,
            &trust.trusted_ranges,
        ),
        locations,
        plugins,
        upstreams,
    })
}

struct Selector {
    view: Arc<View>,
    listener: Listener,
    tls_site: Option<Uuid>,
}

impl ManagedSiteSelector for Selector {
    fn select(
        &self,
        _: &Session,
        hostname: &str,
    ) -> Option<ManagedRequestSite> {
        let (id, _) = self.view.rules.select(self.listener, hostname)?;
        if self.tls_site.is_some_and(|selected| selected != id) {
            return None;
        }
        self.view.sites.get(&id).cloned()
    }
}

/// Pingora's HTTP/2 dispatch spawns the per-stream `process_new_http` future
/// independently of the connection. Fence at that boundary as well as around
/// the transport so revocation drops live proxy requests, not just their client.
struct AuthorizedProxy {
    forwarding: Arc<Forwarding<Arc<View>>>,
    app: Arc<HttpProxy<Server>>,
}

#[async_trait::async_trait]
impl HttpServerApp for AuthorizedProxy {
    async fn process_new_http(
        self: &Arc<Self>,
        session: ServerSession,
        shutdown: &ShutdownWatch,
    ) -> Option<ReusedHttpStream> {
        self.forwarding
            .run(|_| self.app.process_new_http(session, shutdown))
            .await
            .flatten()
    }

    fn h2_options(&self) -> Option<H2Options> {
        self.app.h2_options()
    }

    fn server_options(&self) -> Option<&HttpServerOptions> {
        self.app.server_options()
    }
}

async fn serve_http(
    forwarding: Forwarding<Arc<View>>,
    tcp: tokio::net::TcpStream,
    listener: Listener,
    shutdown: ShutdownWatch,
    h2c: bool,
) -> Option<anyhow::Result<()>> {
    use pingora::services::listening::Service;

    let Listener::Custom { port, protocol } = listener else {
        return Some(Err(anyhow::anyhow!(
            "expected a custom ingress listener"
        )));
    };
    let forwarding = Arc::new(forwarding);
    forwarding
        .run(|view| async {
            let stream = super::ingress::downstream_stream(tcp);
            let (stream, tls_site): (pingora::protocols::Stream, _) =
                match protocol {
                    pingwaf_proto::IngressProtocol::Http => {
                        (Box::new(stream), None)
                    },
                    #[cfg(any(feature = "openssl", feature = "tls-rustls"))]
                    pingwaf_proto::IngressProtocol::Https => {
                        let (stream, id) = tokio::time::timeout(
                            std::time::Duration::from_secs(10),
                            tls::accept(stream, view, listener),
                        )
                        .await??;
                        (stream, Some(id))
                    },
                    _ => anyhow::bail!("unsupported managed ingress transport"),
                };
            let selector = Arc::new(Selector {
                view: view.clone(),
                listener,
                tls_site,
            });
            let mut app = super::ingress::http_proxy(port, |server| {
                server.with_managed_selector(selector)
            })?;
            if let Some(options) = app.server_options.as_mut() {
                options.h2c = h2c && tls_site.is_none();
            }
            let app = AuthorizedProxy {
                forwarding: forwarding.clone(),
                app: Arc::new(app),
            };
            Service::handle_event(stream, Arc::new(app), shutdown).await;
            Ok(())
        })
        .await
}

#[cfg(target_os = "linux")]
mod tests {
    use super::*;
    use pingwaf_agent::managed::{AppliedState, PullWindow, Receiver};
    use pingwaf_proto::{
        CacheRule, IngressProtocol, ManagedSite, ManagedSiteConfig,
        ManagedSnapshot, RouteConfig, RuleBundle, Site, SiteIngress,
        UpstreamConfig, UpstreamPeer,
    };
    use prost::Message;
    use sha2::{Digest, Sha256};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::task::JoinSet;

    fn site(port: Option<u16>, origin: std::net::SocketAddr) -> ManagedSite {
        let id = Uuid::new_v4().to_string();
        ManagedSite {
            site: Some(Site {
                id: id.clone(),
                domain: "shared.example".into(),
                alternate_domains: vec!["alias.example".into()],
                rules: Some(RuleBundle {
                    site_id: id,
                    upstreams: vec![UpstreamConfig {
                        pool_id: "same-pool".into(),
                        is_default: true,
                        peers: vec![UpstreamPeer {
                            address: origin.to_string(),
                            weight: 1,
                            tls: false,
                        }],
                        ..Default::default()
                    }],
                    routes: ["lower", "first", "second"]
                        .into_iter()
                        .zip([1, 10, 10])
                        .map(|(route_id, priority)| RouteConfig {
                            id: route_id.into(),
                            path: "/route".into(),
                            pool_id: "same-pool".into(),
                            priority: Some(priority),
                            enabled: true,
                            rewrite_path: format!("/{route_id}"),
                            ..Default::default()
                        })
                        .collect(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ingress: port.map(|port| SiteIngress {
                port: port.into(),
                protocol: IngressProtocol::Http as i32,
            }),
            ..Default::default()
        }
    }

    fn listener(port: u16) -> Listener {
        Listener::Custom {
            port,
            protocol: IngressProtocol::Http,
        }
    }

    fn apply(
        sites: Vec<ManagedSite>,
        cache_dir: &Path,
    ) -> (Arc<AppliedState<Arc<View>>>, Uuid) {
        let config = ManagedSiteConfig { sites }.encode_to_vec();
        let session = Uuid::new_v4();
        let mut receiver = Receiver::default();
        receiver.set_session(Some(session));
        let received = PullWindow::start(&receiver)
            .unwrap()
            .receive(
                &mut receiver,
                ManagedSnapshot {
                    session_id: session.to_string(),
                    authority_epoch: Uuid::new_v4().to_string(),
                    generation: 1,
                    config_hash: hex::encode(Sha256::digest(&config)),
                    config,
                    lease_seconds: 30,
                },
            )
            .unwrap()
            .unwrap();
        let state = Arc::new(AppliedState::default());
        state.start_session(session);
        let pending = state.prepare(received).unwrap().unwrap();
        let view =
            Arc::new(View::build(pending.candidate(), cache_dir).unwrap());
        assert!(state.publish(pending, view).unwrap());
        (state, session)
    }

    #[cfg(any(feature = "openssl", feature = "tls-rustls"))]
    #[tokio::test]
    async fn managed_https_pins_sni_site_and_uses_its_client_ca() {
        use rcgen::{
            BasicConstraints, CertificateParams, CertifiedIssuer,
            ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
        };
        use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
        use tokio_rustls::TlsConnector;

        tokio::time::timeout(Duration::from_secs(10), async {
            let mut tasks = JoinSet::new();
            let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = proxy.local_addr().unwrap();
            let listener = Listener::Custom { port: addr.port(), protocol: IngressProtocol::Https };
            let mut roots = RootCertStore::empty();
            let mut sites = Vec::new();
            let mut client_identities = Vec::new();
            for (name, alias) in [("shared.example", "alias.example"), ("other.example", "other-alias.example")] {
                let origin_socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let mut item = site(Some(addr.port()), origin_socket.local_addr().unwrap());
                item.ingress.as_mut().unwrap().protocol = IngressProtocol::Https as i32;
                let row = item.site.as_mut().unwrap();
                row.domain = name.into();
                row.alternate_domains = vec![alias.into()];
                let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
                // A distinct issuer name lets clients select their certificate
                // by the advertised CA, as they would in a real handshake.
                ca.distinguished_name.push(rcgen::DnType::CommonName, name);
                ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
                ca.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyCertSign];
                let ca = CertifiedIssuer::self_signed(ca, KeyPair::generate().unwrap()).unwrap();
                roots.add(ca.der().clone()).unwrap();
                let mut server = CertificateParams::new(vec![name.to_owned(), alias.to_owned()]).unwrap();
                server.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
                let server_key = KeyPair::generate().unwrap();
                let server = server.signed_by(&server_key, &ca).unwrap();
                let mut client = CertificateParams::new(Vec::<String>::new()).unwrap();
                client.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
                let client_key = KeyPair::generate().unwrap();
                let client = client.signed_by(&client_key, &ca).unwrap();
                client_identities.push((client.der().clone(), client_key.serialized_der().to_vec()));
                row.rules.as_mut().unwrap().ssl = Some(pingwaf_proto::SslConfig {
                    enabled: true,
                    min_tls_version: if name == "shared.example" { "1.3" } else { "1.2" }.into(),
                    max_tls_version: if name == "shared.example" { "1.3" } else { "1.2" }.into(),
                    mtls_enabled: true,
                    http2_enabled: Some(name == "shared.example"),
                    mtls_require_client_cert: true,
                    mtls_client_ca: ca.pem(),
                    cert_pem: server.pem(),
                    key_pem: server_key.serialize_pem(),
                    ..Default::default()
                });
                sites.push(item);
                tasks.spawn(origin(origin_socket, name, false));
            }

            let cache = tempfile::tempdir().unwrap();
            let (state, _) = apply(sites, cache.path());
            for name in ["shared.example", "other.example"] {
                let upstream = state.forwarding().unwrap().run(|view| {
                    let id = view.rules.select(listener, name).unwrap().0;
                    std::future::ready(view.sites[&id].upstreams.get("same-pool").unwrap())
                }).await.unwrap();
                upstream.run_health_check().await.unwrap();
            }

            let config = |identity: Option<usize>, alpn: &[u8], sni: bool, tls12_only: bool| {
                use rustls::version::{TLS12, TLS13};
                let versions = if tls12_only { &[&TLS12][..] } else { &[&TLS13, &TLS12][..] };
                let builder = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
                    .with_protocol_versions(versions).unwrap().with_root_certificates(roots.clone());
                let mut config = if let Some(i) = identity {
                    let (cert, key) = &client_identities[i];
                    builder.with_client_auth_cert(vec![cert.clone()], rustls::pki_types::PrivatePkcs8KeyDer::from(key.clone()).into()).unwrap()
                } else {
                    builder.with_no_client_auth()
                };
                config.enable_sni = sni;
                config.alpn_protocols.push(alpn.to_vec());
                TlsConnector::from(Arc::new(config))
            };
            let connect = |client: TlsConnector, name: &'static str| {
                let proxy = &proxy;
                let state = &state;
                async move {
                    let join = tokio::spawn({
                        let io = TcpStream::connect(addr).await.unwrap();
                        async move { client.connect(ServerName::try_from(name).unwrap(), io).await }
                    });
                    let (tcp, _) = proxy.accept().await.unwrap();
                    let forwarding = state.forwarding().unwrap();
                    let server = tokio::spawn(async move {
                        let (_shutdown, watch) = tokio::sync::watch::channel(false);
                        serve_http(forwarding, tcp, listener, watch, false).await.unwrap()
                    });
                    (join.await.unwrap(), server)
                }
            };

            for (identity, name, sni) in [(None, "shared.example", true), (Some(1), "shared.example", true), (Some(0), "unknown.example", true), (Some(0), "shared.example", false)] {
                let (client, server) = connect(config(identity, b"http/1.1", sni, false), name).await;
                // TLS 1.3 clients may finish their side before seeing the
                // server's rejection; assert at the accepting server.
                assert!(server.await.unwrap().is_err());
                drop(client);
            }

            for (name, config) in [
                ("shared.example", config(Some(0), b"http/1.1", true, true)),
                ("other.example", config(Some(1), b"h2", true, false)),
            ] {
                let (client, server) = connect(config, name).await;
                assert!(server.await.unwrap().is_err());
                drop(client);
            }

            let reusable_client = config(Some(0), b"http/1.1", true, false);
            for _ in 0..2 {
                let (client, server) = connect(reusable_client.clone(), "shared.example").await;
                let mut client = client.unwrap();
                let session = client.get_ref().1;
                assert_eq!(session.alpn_protocol(), Some(&b"http/1.1"[..]));
                assert_ne!(session.handshake_kind().unwrap(), rustls::HandshakeKind::Resumed);
                client.write_all(b"GET /route HTTP/1.1\r\nHost: other.example\r\nConnection: close\r\n\r\n").await.unwrap();
                client.flush().await.unwrap();
                let response = read_closed_tls_response(&mut client).await;
                server.await.unwrap().unwrap();
                assert!(response.starts_with("HTTP/1.1 421"), "{response}");
                assert!(response.contains("\r\n\r\n"));
            }

            let (client, server) = connect(config(Some(0), b"h2", true, false), "shared.example").await;
            let client = client.unwrap();
            assert_eq!(client.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
            let (mut sender, connection) = h2::client::handshake(client).await.unwrap();
            let driver = tokio::spawn(connection);
            let request = http::Request::builder().uri("https://alias.example/route").body(()).unwrap();
            let (response, _) = sender.send_request(request, true).unwrap();
            let response = response.await.unwrap();
            assert_eq!(response.status(), 200);
            let mut body = response.into_body();
            assert_eq!(body.data().await.unwrap().unwrap().as_ref(), b"shared.example");
            drop(body);

            let request = http::Request::builder().uri("https://other.example/route").body(()).unwrap();
            let (response, _) = sender.send_request(request, true).unwrap();
            assert_eq!(response.await.unwrap().status(), 421);
            driver.abort();
            let _ = driver.await;
            server.await.unwrap().unwrap();

            let (client, server) = connect(config(Some(1), b"http/1.1", true, false), "other.example").await;
            let mut client = client.unwrap();
            assert_eq!(client.get_ref().1.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_2));
            client.write_all(b"GET /route HTTP/1.1\r\nHost: other.example\r\nConnection: close\r\n\r\n").await.unwrap();
            client.flush().await.unwrap();
            let response = read_closed_tls_response(&mut client).await;
            server.await.unwrap().unwrap();
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
            assert!(response.ends_with("other.example"), "{response}");
            while let Some(result) = tasks.join_next().await {
                result.unwrap();
            }
        }).await.unwrap();
    }

    #[cfg(any(feature = "openssl", feature = "tls-rustls"))]
    async fn read_closed_tls_response(
        io: &mut (impl tokio::io::AsyncRead + Unpin),
    ) -> String {
        let mut response = Vec::new();
        if let Err(error) = io.read_to_end(&mut response).await {
            // Pingora may drop a Connection: close stream without sending a
            // TLS close_notify. The caller still verifies HTTP framing/body.
            assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
        }
        String::from_utf8(response).unwrap()
    }

    async fn read_origin_headers(io: &mut TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            assert!(request.len() < 8192);
            match io.read_u8().await {
                Ok(byte) => request.push(byte),
                Err(err)
                    if request.is_empty()
                        && err.kind() == std::io::ErrorKind::UnexpectedEof =>
                {
                    break;
                },
                Err(err) => panic!("origin request: {err}"),
            }
        }
        request
    }

    async fn origin(socket: TcpListener, marker: &str, check_cookies: bool) {
        loop {
            let (mut io, _) = socket.accept().await.unwrap();
            let request = read_origin_headers(&mut io).await;
            if request.is_empty() {
                continue;
            } // TCP health probe.
            assert!(
                request.starts_with(b"GET /first HTTP/1.1\r\n"),
                "{}",
                String::from_utf8_lossy(&request)
            );
            let extra = if check_cookies {
                let request =
                    String::from_utf8(request).unwrap().to_ascii_lowercase();
                assert!(!request.contains("__pingwaf_managed_"), "{request}");
                assert!(request.contains("cookie: theme=blue"), "{request}");
                "Set-Cookie: __pingwaf_managed_clearance_test=origin\r\nSet-Cookie: theme=green\r\n"
            } else {
                ""
            };
            io.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{marker}", marker.len()).as_bytes()).await.unwrap();
            return;
        }
    }

    async fn request(addr: std::net::SocketAddr, host: &str) -> String {
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(format!("GET /route HTTP/1.1\r\nHost: {host}\r\nCookie: __pingwaf_managed_clearance_test=client; theme=blue\r\nCookie: __pingwaf_managed_oidc_test=client\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();
        response
    }

    #[tokio::test]
    async fn managed_snapshot_builds_and_serves_isolated_http_routes() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut tasks = JoinSet::new();
            let mut endpoints = Vec::new();
            let unused_default_origin =
                TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut sites =
                vec![site(None, unused_default_origin.local_addr().unwrap())];
            for marker in [Some("from-a"), Some("from-b"), None] {
                let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = proxy.local_addr().unwrap();
                endpoints.push((addr, proxy, marker));
                if let Some(marker) = marker {
                    let socket =
                        TcpListener::bind("127.0.0.1:0").await.unwrap();
                    sites.push(site(
                        Some(addr.port()),
                        socket.local_addr().unwrap(),
                    ));
                    tasks.spawn(origin(socket, marker, true));
                }
            }
            let cache = tempfile::tempdir().unwrap();
            let (state, _) = apply(sites, cache.path());
            let forwarded = state.forwarding().unwrap();
            let [a_origin, b_origin] = forwarded
                .run(|view| {
                    let upstreams = [0, 1].map(|index| {
                        let id = view
                            .rules
                            .select(
                                listener(endpoints[index].0.port()),
                                "alias.example",
                            )
                            .unwrap()
                            .0;
                        view.sites[&id].upstreams.get("same-pool").unwrap()
                    });
                    std::future::ready(upstreams)
                })
                .await
                .unwrap();
            assert!(!Arc::ptr_eq(&a_origin, &b_origin));
            a_origin.run_health_check().await.unwrap();
            b_origin.run_health_check().await.unwrap();

            let mut clients = Vec::new();
            for (addr, proxy, marker) in endpoints {
                let state = state.clone();
                tasks.spawn(async move {
                    let (tcp, _) = proxy.accept().await.unwrap();
                    let (_shutdown, watch) = tokio::sync::watch::channel(false);
                    serve_http(
                        state.forwarding().unwrap(),
                        tcp,
                        listener(addr.port()),
                        watch,
                        false,
                    )
                    .await
                    .unwrap()
                    .unwrap();
                });
                clients.push((addr, marker));
            }
            for (addr, marker) in clients {
                // Deliberately give the authority the wrong port on every socket.
                let response = request(addr, "alias.example:8888").await;
                if let Some(marker) = marker {
                    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
                    assert!(response.ends_with(marker), "{response}");
                    assert!(
                        !response.contains("__pingwaf_managed_"),
                        "{response}"
                    );
                    assert!(
                        response
                            .to_ascii_lowercase()
                            .contains("set-cookie: theme=green"),
                        "{response}"
                    );
                } else {
                    assert!(response.starts_with("HTTP/1.1 421"), "{response}");
                }
            }
            while let Some(result) = tasks.join_next().await {
                result.unwrap();
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn revocation_stops_actual_http1_and_concurrent_http2_origin_requests()
     {
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut tasks = JoinSet::new();
            let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = socket.local_addr().unwrap();
            let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let cache = tempfile::tempdir().unwrap();
            let mut managed =
                site(Some(addr.port()), origin.local_addr().unwrap());
            managed
                .site
                .as_mut()
                .unwrap()
                .rules
                .as_mut()
                .unwrap()
                .cache_rules
                .push(CacheRule {
                    match_expression:
                        r#"http.request.uri.path starts_with "/""#.into(),
                    edge_ttl_seconds: 60,
                    cache_eligible: true,
                    enabled: true,
                    ..Default::default()
                });
            let (state, session) = apply(vec![managed], cache.path());
            let (h1, accepted) =
                tokio::join!(TcpStream::connect(addr), socket.accept());
            let mut h1 = h1.unwrap();
            let h1_server = accepted.unwrap().0;
            let (h2, accepted) =
                tokio::join!(TcpStream::connect(addr), socket.accept());
            let h2_server = accepted.unwrap().0;
            let (_shutdown, watch) = tokio::sync::watch::channel(false);
            for (tcp, h2c) in [(h1_server, false), (h2_server, true)] {
                let forwarded = state.forwarding().unwrap();
                let watch = watch.clone();
                tasks.spawn(async move {
                    assert!(
                        serve_http(
                            forwarded,
                            tcp,
                            listener(addr.port()),
                            watch,
                            h2c
                        )
                        .await
                        .is_none()
                    );
                });
            }
            h1.write_all(b"GET /route HTTP/1.1\r\nHost: alias.example\r\n\r\n")
                .await
                .unwrap();
            let (mut h2, conn) =
                h2::client::handshake(h2.unwrap()).await.unwrap();
            tasks.spawn(async move {
                let _ = conn.await;
            });
            let mut responses = Vec::new();
            for _ in 0..2 {
                h2 = h2.ready().await.unwrap();
                let (response, _) = h2
                    .send_request(
                        http::Request::builder()
                            .uri("http://alias.example/route")
                            .body(())
                            .unwrap(),
                        true,
                    )
                    .unwrap();
                responses.push(response);
            }
            let mut upstreams = Vec::new();
            for _ in 0..3 {
                let (mut io, _) = origin.accept().await.unwrap();
                assert!(
                    read_origin_headers(&mut io)
                        .await
                        .starts_with(b"GET /first HTTP/1.1\r\n")
                );
                upstreams.push(io);
            }
            // The origin has not sent any response. Simultaneous active streams
            // must stop at their actual origin sockets before the lease times out.
            state.end_session(session);
            assert!(state.forwarding().is_none());
            for mut io in upstreams {
                assert_eq!(io.read(&mut [0u8; 1]).await.unwrap(), 0);
            }
            assert_eq!(h1.read(&mut [0u8; 1]).await.unwrap(), 0);
            for response in responses {
                assert!(response.await.is_err());
            }
            while let Some(result) = tasks.join_next().await {
                result.unwrap();
            }
        })
        .await
        .unwrap();
    }
}
