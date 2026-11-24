//! Preconfigured ingress socket lifecycle, independent of the default proxy.

use super::{LOG_TARGET, public_listen_addr};
use pingap_proxy::{AppContext, Server, ServerConf, ServerLocationsProvider};
use pingora::apps::HttpServerOptions;
use pingora::protocols::l4::stream::Stream;
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
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
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
        let addr = addr.parse::<SocketAddr>().ok()?;
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
            warn!(target: LOG_TARGET, entry = index + 1, "invalid custom ingress; expected http@IP:port or https@IP:port");
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
                    // HTTPS currently reserves TCP only. Never hand these
                    // connections to HTTP or borrow the legacy certificate.
                    if let Some(app) = &app
                        && connections.len() < MAX_CONNECTIONS_PER_LISTENER
                    {
                        let _ = tcp.set_nodelay(true);
                        connections.spawn(Service::handle_event(
                            Box::new(Stream::from(tcp)), app.clone(), shutdown.clone(),
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

pub(super) async fn run(cache: Arc<RuleCache>, control_ports: Vec<u16>) {
    let endpoints = match std::env::var(LISTENERS_ENV) {
        Ok(value) if value.trim().is_empty() => return,
        Ok(value) => parse_list(&value),
        Err(std::env::VarError::NotPresent) => return,
        Err(std::env::VarError::NotUnicode(_)) => {
            warn!(target: LOG_TARGET, "custom ingress list must be UTF-8");
            Vec::new()
        },
    };
    let mut report = IngressListeners::default();
    let mut tasks = JoinSet::new();
    let reserved = if endpoints.is_empty() {
        BTreeSet::new()
    } else {
        reserved_ports(control_ports)
    };
    let (_shutdown, watch) = watch::channel(false);
    for endpoint in endpoints {
        let state = if reserved.contains(&endpoint.addr.port()) {
            warn!(target: LOG_TARGET, addr = %endpoint.addr, "custom ingress port reserved by a default or control-plane listener");
            IngressBindState::Reserved
        } else {
            match start(endpoint, watch.clone(), &mut tasks) {
                Ok(()) => {
                    info!(target: LOG_TARGET, addr = %endpoint.addr, protocol = ?endpoint.protocol, "custom ingress TCP socket bound; no site applied");
                    IngressBindState::Bound
                },
                Err(error) => {
                    warn!(target: LOG_TARGET, addr = %endpoint.addr, protocol = ?endpoint.protocol, %error, "custom ingress could not start");
                    IngressBindState::BindFailed
                },
            }
        };
        report.listeners.push(endpoint.status(state));
    }
    cache.set_ingress_listeners(report);
    if let Some(outcome) = tasks.join_next().await {
        // serve() does not exit normally. If a task fails, do not keep
        // claiming readiness for any socket from this stopped task group.
        warn!(target: LOG_TARGET, ?outcome, "custom ingress task stopped unexpectedly; stopping remaining custom ingress");
        tasks.shutdown().await;
        cache.set_ingress_listeners(IngressListeners::default());
    }
}

fn start(
    endpoint: Endpoint,
    shutdown: ShutdownWatch,
    tasks: &mut JoinSet<()>,
) -> anyhow::Result<()> {
    let app = if endpoint.protocol == IngressProtocol::Http {
        Some(Arc::new(unassigned_http(endpoint.addr.port())?))
    } else {
        None
    };
    let listener = bind(endpoint.addr)?;
    tasks.spawn(serve(listener, app, shutdown));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
