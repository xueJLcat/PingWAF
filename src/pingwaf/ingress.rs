//! Socket lifecycle for endpoints authorized by the current panel snapshot.

use super::LOG_TARGET;
use pingap_proxy::{AppContext, Server, ServerConf, ServerLocationsProvider};
use pingora::apps::HttpServerOptions;
use pingora::protocols::{GetSocketDigest, SocketDigest, l4::stream::Stream};
use pingora::proxy::HttpProxy;
use pingora::server::{ShutdownWatch, configuration};
use pingwaf_agent::cache::RuleCache;
use pingwaf_proto::{
    IngressBindState, IngressListenerStatus, IngressListeners, IngressProtocol,
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

const MAX_CONNECTIONS_PER_LISTENER: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Endpoint {
    addr: SocketAddr,
    protocol: IngressProtocol,
}

impl Endpoint {
    fn status(self, state: IngressBindState) -> IngressListenerStatus {
        IngressListenerStatus {
            port: u32::from(self.addr.port()),
            protocol: self.protocol as i32,
            state: state as i32,
        }
    }
}

fn bind(addr: SocketAddr) -> io::Result<TcpListener> {
    let socket = Socket::new(
        Domain::for_address(addr),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
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
                },
                Err(error) => {
                    warn!(target: LOG_TARGET, addr = ?listener.local_addr(), %error, "custom ingress accept failed");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                },
            }
        }
    }
}

pub(super) async fn run(
    cache: Arc<RuleCache>,
    control_ports: Vec<u16>,
    host: super::IngressHost,
) {
    if host.is_none() { return; }
    let management_ports: BTreeSet<_> = control_ports.into_iter().collect();
    let (_shutdown, watch) = watch::channel(false);
    let mut running = BTreeMap::<SocketAddr, (Endpoint, JoinSet<()>)>::new();
    let mut retries = BTreeMap::<SocketAddr, (Endpoint, tokio::time::Instant, Duration, String)>::new();
    let mut previous = None;
    let (directory_updates, directories) = watch::channel((std::collections::HashMap::new(), Vec::<String>::new(), None));
    #[cfg(target_os = "linux")]
    if host.is_some() {
        tokio::spawn(async move {
            loop {
                let inventory = tokio::task::spawn_blocking(|| {
                    let report = pingwaf_agent::static_dirs::directory_report();
                    let roots = pingwaf_agent::static_dirs::inventory().unwrap_or_default();
                    (roots, pingwaf_agent::static_dirs::retained_directories(), Some(report))
                }).await;
                let report = match inventory {
                    Ok(report) => report,
                    error => {
                        warn!(target: LOG_TARGET, ?error, "static directory inventory unavailable");
                        Default::default()
                    }
                };
                if directory_updates.send(report).is_err() { break; }
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(60)) => {},
                    _ = pingwaf_agent::static_dirs::registry_changed() => {},
                }
            }
        });
    }
    loop {
        let mut desired = BTreeMap::<SocketAddr, Endpoint>::new();
        let mut panel = pingwaf_proto::PanelListenerReport::default();
        #[cfg(target_os = "linux")]
        if let Some(host) = &host {
            let (version, endpoints) = host.live_endpoints();
            panel = version;
            for (addr, protocol) in endpoints {
                desired.insert(addr, Endpoint { addr, protocol });
            }
        }
        retries.retain(|addr, (endpoint, _, _, _)| desired.get(addr) == Some(endpoint));
        // Join retired accept loops before reusing their ports with a different protocol.
        let retired: Vec<_> = running.iter().filter_map(|(port, (endpoint, _))|
            (desired.get(port) != Some(endpoint)).then_some(*port)).collect();
        for port in retired {
            if let Some((_, mut tasks)) = running.remove(&port) {
                tasks.shutdown().await;
            }
        }
        let (static_directories, prepared_directories, static_root_registry) = directories.borrow().clone();
        let mut report = IngressListeners { panel: None, dynamic_bind: host.is_some(), supports_site_handlers: host.is_some(), supports_site_archives: host.is_some(), listeners: Vec::new(), static_directories, prepared_directories, static_root_registry };
        let mut by_port = BTreeMap::new();
        for (addr, endpoint) in desired {
            let port = addr.port();
            let state = if management_ports.contains(&port) {
                IngressBindState::Reserved
            } else if retries.get(&addr).is_some_and(|(_, next, _, _)| *next > tokio::time::Instant::now()) {
                IngressBindState::BindFailed
            } else {
                let (_, tasks) = running.entry(addr).or_insert_with(|| (endpoint, JoinSet::new()));
                let _ = tasks.try_join_next();
                if tasks.is_empty() {
                    match start(endpoint, watch.clone(), tasks, host.clone()) {
                        Ok(()) => {
                            retries.remove(&addr);
                            IngressBindState::Bound
                        }
                        Err(error) => {
                            let delay = retries.get(&addr).map_or(Duration::from_secs(1), |(_, _, delay, _)| {
                                (*delay * 2).min(Duration::from_secs(30))
                            });
                            warn!(target: LOG_TARGET, %addr, %error, ?delay, "unable to bind panel listener");
                            retries.insert(addr, (endpoint, tokio::time::Instant::now() + delay, delay, error.to_string()));
                            IngressBindState::BindFailed
                        }
                    }
                } else {
                    IngressBindState::Bound
                }
            };
            let entry = by_port.entry(port).or_insert_with(|| endpoint.status(state));
            if state != IngressBindState::Bound { entry.state = state as i32; }
            let error = if state == IngressBindState::Reserved { "infrastructure port".into() }
                else { retries.get(&addr).map(|v| v.3.clone()).unwrap_or_default() };
            panel.sockets.push(pingwaf_proto::PanelSocketStatus {
                address: addr.ip().to_string(), listener: Some(endpoint.status(state)), error,
            });
        }
        if panel.sockets.iter().any(|s| s.listener.as_ref().is_none_or(|l| l.state() != IngressBindState::Bound)) {
            panel.applied_generation = 0;
        }
        report.panel = Some(panel);
        report.listeners = by_port.into_values().collect();
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
    let listener = bind(endpoint.addr)?;
    tasks.spawn(serve(listener, endpoint, host, shutdown));
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
}
