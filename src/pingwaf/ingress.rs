//! Preconfigured ingress socket lifecycle, independent of the default proxy.

use super::{LOG_TARGET, public_listen_addr};
use pingap_proxy::{AppContext, Server, ServerConf, ServerLocationsProvider};
use pingora::apps::HttpServerOptions;
use pingora::protocols::{GetSocketDigest, SocketDigest, l4::stream::Stream};
use pingora::proxy::HttpProxy;
use pingora::server::{ShutdownWatch, configuration};
use pingora::services::listening::Service;
use pingwaf_agent::cache::RuleCache;
use pingwaf_proto::{
    IngressBindState, IngressListenerStatus, IngressListeners, IngressProtocol,
    MAX_INGRESS_LISTENERS,
};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{info, warn};

const LISTENERS_ENV: &str = "PINGWAF_INGRESS_LISTENERS";
const MAX_CONNECTIONS_PER_LISTENER: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Endpoint {
    addr: SocketAddr,
    protocol: IngressProtocol,
}

impl Endpoint {
    fn parse(value: &str) -> Option<Self> {
        let (protocol, addr) = value.trim().split_once('@')?;
        let protocol = match protocol {
            "http" => IngressProtocol::Http,
            "https" => IngressProtocol::Https,
            _ => return None,
        };
        let addr = match addr.parse::<u16>() {
            Ok(port) => SocketAddr::from(([0, 0, 0, 0], port)),
            Err(_) => addr.parse::<SocketAddr>().ok()?,
        };
        if addr.port() == 0
            || matches!(addr, SocketAddr::V6(v6) if v6.ip().to_ipv4_mapped().is_some())
        {
            return None;
        }
        Some(Self { addr, protocol })
    }

    fn status(self, state: IngressBindState) -> IngressListenerStatus {
        IngressListenerStatus {
            port: u32::from(self.addr.port()),
            protocol: self.protocol as i32,
            state: state as i32,
        }
    }
}

fn parse_list(value: &str) -> Vec<Endpoint> {
    if value.trim().is_empty() {
        return Vec::new();
    }
    if value.split(',').take(MAX_INGRESS_LISTENERS + 1).count()
        > MAX_INGRESS_LISTENERS
    {
        warn!(target: LOG_TARGET, limit = MAX_INGRESS_LISTENERS, "custom ingress list exceeds limit; no custom sockets opened");
        return Vec::new();
    }
    let mut by_port = BTreeMap::new();
    for (index, entry) in value.split(',').enumerate() {
        if let Some(endpoint) = Endpoint::parse(entry) {
            let port = endpoint.addr.port();
            by_port.entry(port).and_modify(|value| {
                *value = None;
                warn!(target: LOG_TARGET, port, "duplicate custom ingress port; no socket opened for this port");
            }).or_insert(Some(endpoint));
        } else {
            warn!(target: LOG_TARGET, entry = index + 1, "invalid custom ingress; expected http@port or https@port, optionally with an explicit IP address");
        }
    }
    by_port.into_values().flatten().collect()
}

fn reserved_ports(control_ports: Vec<u16>) -> BTreeSet<u16> {
    let mut ports = BTreeSet::from([80, 443]);
    ports.extend(control_ports);
    for addr in [
        public_listen_addr(
            "PINGWAF_LISTEN_HTTP_ADDR",
            "PINGWAF_ANALYSIS_HTTP_ADDR",
            80,
        ),
        public_listen_addr(
            "PINGWAF_LISTEN_HTTPS_ADDR",
            "PINGWAF_ANALYSIS_HTTPS_ADDR",
            443,
        ),
    ] {
        // The default listener accepts a list and DNS names. Port ownership
        // does not depend on the resolved family/address or on DNS being up.
        ports.extend(addr.split(',').filter_map(|part| {
            let (_, port) = part.trim().rsplit_once(':')?;
            port.parse::<u16>().ok()
        }));
    }
    ports
}

fn bind(addr: SocketAddr) -> io::Result<TcpListener> {
    let socket = Socket::new(
        Domain::for_address(addr),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    if let SocketAddr::V6(v6) = addr {
        socket.set_only_v6(!v6.ip().is_unspecified())?;
    }
    // No SO_REUSEPORT, including when an unrelated service already owns it.
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    TcpListener::from_std(socket.into())
}

/// We own the accept loop, so attach the socket metadata Pingora's
/// listener would normally supply to the request and TLS layers.
pub(super) fn downstream_stream(tcp: TcpStream) -> Stream {
    #[cfg(unix)]
    let digest = SocketDigest::from_raw_fd(tcp.as_raw_fd());
    #[cfg(windows)]
    let digest = SocketDigest::from_raw_socket(tcp.as_raw_socket());
    // Snapshot both addresses before ownership can pass to an H2 request
    // outliving the connection. A recycled fd then cannot supply its IP.
    let _ = digest.peer_addr.set(tcp.peer_addr().ok().map(Into::into));
    let _ = digest.local_addr.set(tcp.local_addr().ok().map(Into::into));
    let mut stream = Stream::from(tcp);
    stream.set_socket_digest(digest);
    stream
}

// Deliberate deny-all until custom ingress has an authorized applied view.
// The default proxy's live locations must never be used on these sockets.
struct Unassigned;

impl ServerLocationsProvider for Unassigned {
    fn get(
        &self,
        _name: &str,
    ) -> Option<Arc<pingap_location::ServerLocationRoute>> {
        None
    }
}

fn unassigned_http(port: u16) -> anyhow::Result<HttpProxy<Server>> {
    http_proxy(port, std::convert::identity)
}

pub(super) fn http_proxy(
    port: u16,
    configure: impl FnOnce(Server) -> Server,
) -> anyhow::Result<HttpProxy<Server>> {
    let server = Server::new(
        &ServerConf {
            name: format!("pingwaf_ingress_{port}"),
            http1_enabled: true,
            downstream_read_timeout: Some(Duration::from_secs(60)),
            downstream_write_timeout: Some(Duration::from_secs(60)),
            ..Default::default()
        },
        AppContext {
            server_locations_provider: Arc::new(Unassigned),
            location_provider: crate::locations::new_location_provider(),
            upstream_provider: crate::upstreams::new_upstream_provider(),
            plugin_provider: crate::plugin::new_plugin_provider(),
            certificate_provider: crate::certificates::new_certificate_provider(
            ),
            config_manager: Arc::new(pingap_config::new_memory_config_manager(
                "", None,
            )),
            logger: None,
        },
    )?;
    let mut proxy = HttpProxy::new(
        configure(server),
        Arc::new(configuration::ServerConf::default()),
    );
    proxy.handle_init_modules();
    let mut options = HttpServerOptions::default();
    options.keepalive_request_limit = Some(1000);
    proxy.server_options = Some(options);
    Ok(proxy)
}

async fn serve(
    listener: TcpListener,
    _endpoint: Endpoint,
    _host: super::IngressHost,
    app: Option<Arc<HttpProxy<Server>>>,
    shutdown: ShutdownWatch,
) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            // Reap completed handlers even if the socket always has work.
            _ = connections.join_next(), if !connections.is_empty() => {},
            accepted = listener.accept() => match accepted {
                Ok((tcp, _)) => {
                    if connections.len() >= MAX_CONNECTIONS_PER_LISTENER { continue; }
                    let _ = tcp.set_nodelay(true);
                    #[cfg(target_os = "linux")]
                    if let Some(host) = &_host {
                        let identity = pingwaf_agent::managed::Listener::Custom {
                            port: _endpoint.addr.port(), protocol: _endpoint.protocol,
                        };
                        let host = host.clone();
                        let shutdown = shutdown.clone();
                        connections.spawn(async move { host.serve(tcp, identity, shutdown).await });
                        continue;
                    }
                    if let Some(app) = &app {
                        connections.spawn(Service::handle_event(
                            Box::new(downstream_stream(tcp)), app.clone(), shutdown.clone(),
                        ));
                    }
                },
                Err(error) => {
                    warn!(target: LOG_TARGET, addr = ?listener.local_addr(), %error, "custom ingress accept failed");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                },
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub(super) fn configured() -> bool {
    std::env::var(LISTENERS_ENV)
        .is_ok_and(|value| !parse_list(&value).is_empty())
}

pub(super) async fn run(
    cache: Arc<RuleCache>,
    control_ports: Vec<u16>,
    host: super::IngressHost,
) {
    let fixed: BTreeMap<_, _> = parse_list(&std::env::var(LISTENERS_ENV).unwrap_or_default())
        .into_iter().map(|endpoint| (endpoint.addr.port(), endpoint)).collect();
    if fixed.is_empty() && host.is_none() { return; }
    let management_ports: BTreeSet<_> = control_ports.iter().copied().collect();
    let reserved = reserved_ports(control_ports);
    let (_shutdown, watch) = watch::channel(false);
    let mut running = BTreeMap::<u16, (Endpoint, JoinSet<()>)>::new();
    let mut previous = None;
    let (directory_updates, directories) = watch::channel(std::collections::HashMap::new());
    #[cfg(target_os = "linux")]
    if host.is_some() {
        tokio::spawn(async move {
            loop {
                let inventory = tokio::task::spawn_blocking(pingwaf_agent::static_dirs::inventory).await;
                let report = match inventory {
                    Ok(Ok(report)) => report,
                    error => {
                        warn!(target: LOG_TARGET, ?error, "static directory inventory unavailable");
                        Default::default()
                    }
                };
                if directory_updates.send(report).is_err() { break; }
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });
    }
    loop {
        let mut desired = fixed.clone();
        let shared_ports: Vec<u16>;
        #[cfg(target_os = "linux")]
        { shared_ports = host.as_ref().map(|host| host.shared_ports()).unwrap_or_default(); }
        #[cfg(not(target_os = "linux"))]
        { shared_ports = Vec::new(); }
        #[cfg(target_os = "linux")]
        if let Some(host) = &host {
            for &port in &shared_ports {
                desired.insert(port, Endpoint {
                    addr: SocketAddr::from(([0, 0, 0, 0], port)),
                    protocol: if port == 443 { IngressProtocol::Https } else { IngressProtocol::Http },
                });
            }
            let mut dynamic = host.live_listeners();
            dynamic.sort_by_key(|listener| match listener {
                pingwaf_agent::managed::Listener::Custom { port, .. } => *port,
                _ => 0,
            });
            for listener in dynamic {
                if let pingwaf_agent::managed::Listener::Custom { port, protocol } = listener {
                    if desired.len() >= MAX_INGRESS_LISTENERS { break; }
                    desired.entry(port).or_insert(Endpoint {
                        addr: SocketAddr::from(([0, 0, 0, 0], port)), protocol,
                    });
                }
            }
        }
        // Join retired accept loops before reusing their ports with a different protocol.
        let retired: Vec<_> = running.iter().filter_map(|(port, (endpoint, _))|
            (desired.get(port) != Some(endpoint)).then_some(*port)).collect();
        for port in retired {
            if let Some((_, mut tasks)) = running.remove(&port) {
                tasks.shutdown().await;
            }
        }
        let mut report = IngressListeners { dynamic_bind: host.is_some(), supports_site_handlers: host.is_some(), supports_site_archives: host.is_some(), listeners: Vec::new(), static_directories: directories.borrow().clone() };
        for (port, endpoint) in desired {
            let assigned_standard = (!fixed.contains_key(&port) || shared_ports.contains(&port)) && matches!(
                (port, endpoint.protocol),
                (80, IngressProtocol::Http) | (443, IngressProtocol::Https)
            );
            let state = if management_ports.contains(&port) || (reserved.contains(&port) && !assigned_standard) {
                IngressBindState::Reserved
            } else {
                let (_, tasks) = running.entry(port).or_insert_with(|| (endpoint, JoinSet::new()));
                let _ = tasks.try_join_next();
                if tasks.is_empty() {
                    match start(endpoint, watch.clone(), tasks, host.clone()) {
                        Ok(()) => IngressBindState::Bound,
                        Err(_) => IngressBindState::BindFailed,
                    }
                } else {
                    IngressBindState::Bound
                }
            };
            report.listeners.push(endpoint.status(state));
        }
        if previous.as_ref() != Some(&report) {
            info!(target: LOG_TARGET, listeners = ?report.listeners, "ingress inventory changed");
            previous = Some(report.clone());
            cache.set_ingress_listeners(report);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

fn start(
    endpoint: Endpoint,
    shutdown: ShutdownWatch,
    tasks: &mut JoinSet<()>,
    host: super::IngressHost,
) -> anyhow::Result<()> {
    let app = if host.is_none() && endpoint.protocol == IngressProtocol::Http {
        Some(Arc::new(unassigned_http(endpoint.addr.port())?))
    } else {
        None
    };
    let listener = bind(endpoint.addr)?;
    tasks.spawn(serve(listener, endpoint, host, app, shutdown));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn downstream_addresses_survive_transport_drop() {
        let listener = bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let local = listener.local_addr().unwrap();
        let client = TcpStream::connect(local).await.unwrap();
        let (accepted, peer) = listener.accept().await.unwrap();
        let stream = downstream_stream(accepted);
        let digest = stream.get_socket_digest().unwrap();
        drop(stream);
        assert_eq!(client.local_addr().unwrap(), peer);
        assert_eq!(digest.peer_addr().unwrap().as_inet(), Some(&peer));
        assert_eq!(digest.local_addr().unwrap().as_inet(), Some(&local));
    }

    #[test]
    fn list_accepts_ip_literals_only_and_rejects_every_duplicate() {
        let endpoints = parse_list(
            "http@127.0.0.1:81,https@[::]:82, http@[::1]:83,https@127.0.0.1:83,http@127.0.0.1:83,http@localhost:84,http@127.0.0.1:0,http@127.0.0.1:65536,http@[::ffff:127.0.0.1]:85,ftp@127.0.0.1:86",
        );
        assert_eq!(
            endpoints,
            [
                Endpoint::parse("http@127.0.0.1:81").unwrap(),
                Endpoint::parse("https@[::]:82").unwrap()
            ]
        );
        assert!(parse_list(" \t").is_empty());
    }

    #[test]
    fn list_over_budget_opens_nothing() {
        let entries: Vec<_> = (1..=MAX_INGRESS_LISTENERS + 1)
            .map(|port| format!("http@127.0.0.1:{port}"))
            .collect();
        assert_eq!(
            parse_list(&entries[..MAX_INGRESS_LISTENERS].join(",")).len(),
            MAX_INGRESS_LISTENERS
        );
        assert!(parse_list(&entries.join(",")).is_empty());
    }
}
