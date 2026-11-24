//! Isolated proxy objects built from an already verified managed snapshot.

use std::{cmp::Reverse, collections::HashMap, path::Path, sync::Arc};

use pingap_core::{ManagedSiteContext, ProxyTrust};
use pingap_location::ServerLocationRoute;
use pingap_proxy::{ManagedRequestSite, ManagedSiteSelector};
use pingora::proxy::Session;
use pingwaf_agent::managed::{Candidate, Compiled, CompiledSite, Listener};
use uuid::Uuid;

use super::convert_proxy_config;

struct View {
    rules: Compiled,
    sites: HashMap<Uuid, ManagedRequestSite>,
}

impl View {
    fn build(candidate: &Candidate, cache_dir: &Path) -> anyhow::Result<Self> {
        let rules = candidate.compile()?;
        let sites = rules
            .sites()
            .map(|(id, site)| Ok((id, build_site(site, cache_dir)?)))
            .collect::<anyhow::Result<_>>()?;
        Ok(Self { rules, sites })
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
}

impl ManagedSiteSelector for Selector {
    fn select(
        &self,
        _: &Session,
        hostname: &str,
    ) -> Option<ManagedRequestSite> {
        let (id, _) = self.view.rules.select(self.listener, hostname)?;
        self.view.sites.get(&id).cloned()
    }
}

#[cfg(target_os = "linux")]
mod tests {
    use super::*;
    use pingora::{
        protocols::l4::stream::Stream, services::listening::Service,
    };
    use pingwaf_agent::managed::{AppliedState, PullWindow, Receiver};
    use pingwaf_proto::{
        IngressProtocol, ManagedSite, ManagedSiteConfig, ManagedSnapshot,
        RouteConfig, RuleBundle, Site, SiteIngress, UpstreamConfig,
        UpstreamPeer,
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

    async fn origin(socket: TcpListener, marker: &str) {
        loop {
            let (mut io, _) = socket.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                assert!(request.len() < 8192);
                match io.read_u8().await {
                    Ok(byte) => request.push(byte),
                    Err(err)
                        if request.is_empty()
                            && err.kind()
                                == std::io::ErrorKind::UnexpectedEof =>
                    {
                        break;
                    },
                    Err(err) => panic!("origin request: {err}"),
                }
            }
            if request.is_empty() {
                continue;
            } // TCP health probe.
            assert!(
                request.starts_with(b"GET /first HTTP/1.1\r\n"),
                "{}",
                String::from_utf8_lossy(&request)
            );
            io.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{marker}", marker.len()).as_bytes()).await.unwrap();
            return;
        }
    }

    async fn request(addr: std::net::SocketAddr, host: &str) -> String {
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(format!("GET /route HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
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
                    tasks.spawn(origin(socket, marker));
                }
            }
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
            let pending = state.prepare(received).unwrap();
            let cache = tempfile::tempdir().unwrap();
            let view = Arc::new(
                View::build(pending.candidate(), cache.path()).unwrap(),
            );
            let a = view
                .rules
                .select(listener(endpoints[0].0.port()), "alias.example")
                .unwrap()
                .0;
            let b = view
                .rules
                .select(listener(endpoints[1].0.port()), "shared.example")
                .unwrap()
                .0;
            let a_origin = view.sites[&a].upstreams.get("same-pool").unwrap();
            let b_origin = view.sites[&b].upstreams.get("same-pool").unwrap();
            assert!(!Arc::ptr_eq(&a_origin, &b_origin));
            a_origin.run_health_check().await.unwrap();
            b_origin.run_health_check().await.unwrap();
            assert!(state.publish(pending, view).unwrap());

            let mut clients = Vec::new();
            for (addr, proxy, marker) in endpoints {
                let state = state.clone();
                tasks.spawn(async move {
                    let (tcp, _) = proxy.accept().await.unwrap();
                    state
                        .forwarding()
                        .unwrap()
                        .run(|view| async move {
                            let id = listener(addr.port());
                            let app = super::super::ingress::http_proxy(
                                addr.port(),
                                |server| {
                                    server.with_managed_selector(Arc::new(
                                        Selector {
                                            view: view.clone(),
                                            listener: id,
                                        },
                                    ))
                                },
                            )
                            .unwrap();
                            let (_shutdown, watch) =
                                tokio::sync::watch::channel(false);
                            Service::handle_event(
                                Box::new(Stream::from(tcp)),
                                Arc::new(app),
                                watch,
                            )
                            .await;
                        })
                        .await
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
}
