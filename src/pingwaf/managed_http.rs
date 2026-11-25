//! Isolated proxy objects built from an already verified managed snapshot.

use anyhow::Context as _;
use std::{cmp::Reverse, collections::HashMap, path::Path, sync::Arc};

use pingap_core::{ManagedSiteContext, ProxyTrust};
use pingap_location::ServerLocationRoute;
use pingap_proxy::{ManagedRequestSite, ManagedRouteMiss, ManagedSiteSelector, Server};
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


#[cfg(any(feature = "openssl", feature = "tls-rustls"))]
mod tls;
mod shared;
mod integrity;

#[derive(Debug)]
struct ContentFailure(&'static str);

impl std::fmt::Display for ContentFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(self.0) }
}

pub(super) struct Host {
    shared: std::sync::RwLock<HashMap<u16, Arc<shared::DefaultApp>>>,
    state: pingwaf_agent::managed::AppliedState<Arc<View>>,
    cache: Arc<pingwaf_agent::cache::RuleCache>,
    defaults: std::sync::Mutex<Option<DefaultProjection>>,
    default_routes: std::sync::RwLock<DefaultRoutes>,
    worker: std::sync::Mutex<Option<tokio::task::AbortHandle>>,
    session: std::sync::Mutex<HostSession>,
}

#[derive(Default)]
struct HostSession {
    id: Option<Uuid>,
    version: Option<pingwaf_agent::managed::Version>,
    tunnel_timer: Option<tokio::task::AbortHandle>,
}

impl HostSession {
    fn revoke_tunnels(&mut self) {
        if let Some(timer) = self.tunnel_timer.take() { timer.abort(); }
        if let Some(registry) = pingwaf_tunnel::installed_registry() { registry.apply_policies(Vec::new()); }
    }
}

#[derive(Default)]
struct DefaultRoutes {
    expected_hash: String,
    expected: HashMap<Uuid, String>,
    applied_hash: Option<Arc<str>>,
    applied: HashMap<Uuid, String>,
}

#[derive(PartialEq)]
struct DefaultProjection {
    config: pingwaf_proto::SiteConfig,
    tunnels: Vec<pingwaf_proto::TunnelConfig>,
    settings: Option<pingwaf_proto::TunnelSettings>,
}

impl DefaultRoutes {
    fn expect(&mut self, candidate: &Candidate, hash: &str) {
        self.expected = candidate.sites().iter()
            .filter(|(_, envelope)| envelope.ingress.is_none() && envelope.site.as_ref().is_some_and(|site| site.status == pingwaf_proto::SiteStatusEnum::SiteStatusActive as i32))
            .map(|(id, envelope)| (*id, envelope.site_revision.clone())).collect();
        self.applied.retain(|id, revision| self.expected.get(id) == Some(revision));
        self.expected_hash = hash.to_owned();
    }
}

impl Host {
    pub(super) fn has_received_default_config(&self) -> bool {
        self.defaults.lock().unwrap_or_else(|e| e.into_inner()).is_some()
    }

    pub(super) fn default_routes_applied(&self, hash: Arc<str>) {
        let mut routes = self.default_routes.write().unwrap_or_else(|e| e.into_inner());
        if routes.expected_hash == hash.as_ref() {
            routes.applied = routes.expected.clone();
            routes.applied_hash = Some(hash);
        }
    }

    fn default_routes_ready(&self) -> bool {
        self.default_routes.read().unwrap_or_else(|e| e.into_inner()).applied_hash.as_ref() == Some(&self.cache.config_hash())
    }

    fn has_default_routes(&self) -> bool {
        !self.default_routes.read().unwrap_or_else(|e| e.into_inner()).applied.is_empty()
    }
    pub(super) fn register_default(self: &Arc<Self>, port: u16, server: Server, conf: Arc<pingora::server::configuration::ServerConf>) -> anyhow::Result<()> {
        let listener = Listener::Custom { port, protocol: if port == 443 { pingwaf_proto::IngressProtocol::Https } else { pingwaf_proto::IngressProtocol::Http } };
        let selector = StandardSelector { host: Arc::downgrade(self), listener };
        let app = Arc::new(shared::DefaultApp::new(port, server.with_managed_selector(Arc::new(selector)), conf)?);
        self.shared.write().unwrap_or_else(|e| e.into_inner()).insert(port, app);
        Ok(())
    }

    pub(super) fn live_endpoints(&self) -> (pingwaf_proto::PanelListenerReport, Vec<(std::net::SocketAddr, pingwaf_proto::IngressProtocol)>) {
        let shared = self.shared.read().unwrap_or_else(|e| e.into_inner());
        let (mut report, live) = self.state.live_endpoints();
        let mut endpoints = Vec::new();
        for (addr, protocol, listener) in live {
            if listener == Listener::Default && !self.default_routes_ready() {
                report.applied_generation = 0;
            }
            if listener == Listener::Default && (!shared.contains_key(&addr.port()) || !self.has_default_routes()) {
                report.applied_generation = 0;
            } else {
                endpoints.push((addr, protocol));
            }
        }
        (report, endpoints)
    }

    pub(super) fn certificate_orders(&self) -> Option<Arc<std::collections::BTreeMap<String, pingap_config::CertificateConf>>> {
        self.state.forwarding().map(|grant| grant.view().certificate_orders.clone())
    }

    pub(super) fn new(
        cache: Arc<pingwaf_agent::cache::RuleCache>,
    ) -> Arc<Self> {
        Arc::new(Self {
            shared: Default::default(),
            state: Default::default(),
            cache,
            defaults: Default::default(),
            default_routes: Default::default(),
            worker: Default::default(),
            session: Default::default(),
        })
    }
    fn cancel_worker(&self) {
        if let Some(worker) =
            self.worker.lock().unwrap_or_else(|e| e.into_inner()).take()
        {
            worker.abort();
        }
    }

    async fn apply(
        &self,
        pending: pingwaf_agent::managed::Pending,
    ) -> anyhow::Result<()> {
        let dir = self.cache.cache_dir().to_owned();
        let mut policies = HashMap::new();
        for (id, envelope) in pending.candidate().sites() {
            if !envelope.protected_pages.is_empty() {
                policies.insert(*id, integrity::prepare(*id, &envelope.protected_pages).await?);
            }
            if let Some(pingwaf_proto::managed_site::Handler::StaticRelease(spec)) = &envelope.handler {
                if spec.directory_id.is_empty() {
                    let target = pingwaf_agent::static_dirs::release_path(*id, &spec.digest)?;
                    if !tokio::fs::try_exists(&target).await? {
                        let agent = pingwaf_agent::agent_instance().ok_or_else(|| anyhow::anyhow!("agent unavailable"))?;
                        let bytes = agent.client.download_site_archive(*id, &spec.digest).await.context(ContentFailure("content_download"))?;
                        let digest = spec.digest.clone();
                        tokio::task::spawn_blocking(move || pingwaf_agent::static_dirs::install_archive(&target, &digest, &bytes)).await?.context(ContentFailure("content_validation"))?;
                    }
                }
            }
        }
        let (pending, view) = tokio::task::spawn_blocking(move || {
            View::with_policies(pending.candidate(), &dir, policies)
                .map(|view| (pending, Arc::new(view)))
        })
        .await??;
        view.check_upstreams().await?;
        let failures = view.tls_failures.clone();
        if self.state.publish_with_failures(pending, view, failures)?
            && let Some(forwarding) = self.state.forwarding()
        {
            forwarding.run(|view| view.refresh_upstreams()).await;
        }
        Ok(())
    }

    pub(super) async fn serve(
        &self,
        tcp: tokio::net::TcpStream,
        listener: Listener,
        shutdown: ShutdownWatch,
    ) {
        let fallback = match listener {
            Listener::Custom {port, ..} => self.shared.read().unwrap_or_else(|e| e.into_inner()).get(&port).cloned(),
            _ => None,
        };
        let mut stream = super::ingress::downstream_stream(tcp);
        let forwarding = self.state.forwarding_for(listener);
        if matches!(listener, Listener::Custom { port: 80, .. })
            && let Some(app) = fallback.as_ref()
            && let Some(grant) = self.state.scoped_forwarding(Listener::Default).or_else(|| forwarding.clone()) {
            let _ = app.serve(stream, shutdown, grant, TlsIdentity::Plain).await;
            return;
        }
        if let Some(fallback) = fallback
            && self.has_default_routes()
            && let Some(default_authorization) = self.state.scoped_forwarding(Listener::Default)
        {
            if !matches!(listener, Listener::Custom { port: 443, .. }) {
                let _ = fallback.serve(stream, shutdown, default_authorization, TlsIdentity::Plain).await;
                return;
            }
            let Ok(Ok(sni)) = tokio::time::timeout(std::time::Duration::from_secs(10), tls::read_sni(&mut stream)).await else { return; };
            let hostname = sni.as_deref().unwrap_or("");
            let managed = forwarding.as_ref().and_then(|f| f.request_view(listener))
                .is_some_and(|view| view.rules.select(listener, hostname).is_some());
            if !managed {
                if let Some((id, grant)) = default_authorization.site_grant(Listener::Default, hostname) {
                    if !self.default_routes.read().unwrap_or_else(|e| e.into_inner()).applied.contains_key(&id) {
                        return;
                    }
                    grant.run(|_| fallback.serve(stream, shutdown, default_authorization, TlsIdentity::Known(id))).await;
                } else {
                    let _ = fallback.serve(stream, shutdown, default_authorization, TlsIdentity::Unknown).await;
                }
                return;
            }
        }
        if let Some(forwarding) = forwarding {
            let _ =
                serve_http_stream(forwarding, stream, listener, shutdown, false).await;
        }
    }
}

struct HostCallbacks(Arc<Host>);

impl Host {
    pub(super) fn callbacks(
        self: &Arc<Self>,
    ) -> Arc<dyn pingwaf_agent::client::ManagedHost> {
        Arc::new(HostCallbacks(self.clone()))
    }
}

impl pingwaf_agent::client::ManagedHost for HostCallbacks {
    fn application_report(&self) -> Option<pingwaf_proto::ManagedApplyReport> {
        self.0
            .state
            .application_report(&self.0.cache.ingress_listeners()?, self.0.default_routes_ready())
    }

    fn session_started(&self, session: Uuid) {
        let mut current = self.0.session.lock().unwrap_or_else(|e| e.into_inner());
        current.revoke_tunnels();
        current.id = Some(session);
        current.version = None;
        self.0.cancel_worker();
        self.0.state.start_session(session);
    }
    fn session_ended(&self, session: Uuid) {
        let mut current = self.0.session.lock().unwrap_or_else(|e| e.into_inner());
        if current.id != Some(session) { return; }
        current.id = None;
        current.version = None;
        current.revoke_tunnels();
        self.0.state.end_session(session);
        self.0.cancel_worker();
    }
    fn candidate_received(&self, received: pingwaf_agent::managed::Received) {
        let host = self.0.clone();
        let mut current = self.0.session.lock().unwrap_or_else(|e| e.into_inner());
        let version = received.candidate.version();
        if current.id != Some(version.session) || current.version.is_some_and(|last|
            last.authority != version.authority || last.generation >= version.generation) { return; }
        current.version = Some(version);
        let lease = received.lease.clone();
        let pending = match host.state.prepare(received) {
            Ok(pending) => pending,
            Err(error) => {
                current.revoke_tunnels();
                tracing::warn!(%error, "managed authorization failed");
                return;
            },
        };
        if !lease.permits(version) {
            current.revoke_tunnels();
            return;
        }
        if pingwaf_tunnel::installed_registry().is_some() {
            if let Some(timer) = current.tunnel_timer.take() { timer.abort(); }
            let weak = Arc::downgrade(&host);
            current.tunnel_timer = Some(tokio::spawn(async move {
                let _ = lease.wait_for_expiry().await;
                if let Some(host) = weak.upgrade() {
                    let mut current = host.session.lock().unwrap_or_else(|e| e.into_inner());
                    if current.version == Some(version) { current.revoke_tunnels(); }
                }
            }).abort_handle());
        }
        let Some(pending) = pending else { return; };
        host.cancel_worker();
        let policy = pending.candidate().sites().values().filter_map(|s| s.site.as_ref())
            .filter(|s| s.status == pingwaf_proto::SiteStatusEnum::SiteStatusActive as i32)
            .min_by(|a, b| a.id.cmp(&b.id)).and_then(|s| s.rules.as_ref());
        let defaults = DefaultProjection {
            config: pending.candidate().default_config(),
            tunnels: policy.map(|p| p.tunnels.clone()).unwrap_or_default(),
            settings: policy.and_then(|p| p.tunnel_settings),
        };
        let mut previous =
            host.defaults.lock().unwrap_or_else(|e| e.into_inner());
        if previous.as_ref() != Some(&defaults) {
            let mut config = defaults.config.clone();
            config.config_hash =
                hex::encode(pending.candidate().version().hash);
            host.default_routes.write().unwrap_or_else(|e| e.into_inner()).expect(pending.candidate(), &config.config_hash);
            if let Err(error) = host.cache.update_from_site_config_with_policy(&config, policy) {
                current.revoke_tunnels();
                tracing::warn!(%error, "default configuration update failed");
                return;
            }
            *previous = Some(defaults);
        }
        super::apply_tunnel_policies(&host.cache.all_sites());
        drop(previous);
        let task = tokio::spawn(async move {
            let version = pending.candidate().version();
            if let Err(error) = host.apply(pending).await {
                let code = error.downcast_ref::<ContentFailure>().map_or("config_apply", |failure| failure.0);
                host.state.preparation_failed(version, code);
                tracing::warn!(%error, "managed snapshot could not be applied");
            }
        });
        *self.0.worker.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(task.abort_handle());
    }
}

struct View {
    certificate_orders: Arc<std::collections::BTreeMap<String, pingap_config::CertificateConf>>,
    unmatched: Option<pingap_plugin::FallbackPagePlugin>,
    tls_failures: HashMap<Uuid, &'static str>,
    rules: Compiled,
    sites: HashMap<Uuid, ManagedRequestSite>,
    tunnel_sites: HashMap<Uuid, Option<u16>>,
    cache_dir: std::path::PathBuf,
    tunnel_routes: std::sync::RwLock<(u64, HashMap<Uuid, ManagedRequestSite>)>,
    #[cfg(any(feature = "openssl", feature = "tls-rustls"))]
    tls: HashMap<Uuid, tls::TlsSite>,
}

impl View {
    fn tunnel_generation() -> u64 {
        pingwaf_tunnel::installed_registry().map_or(0, |registry| registry.generation())
    }

    fn request_site(&self, id: Uuid) -> Option<ManagedRequestSite> {
        if !self.tunnel_sites.contains_key(&id) {
            return self.sites.get(&id).cloned();
        }
        let current = self.tunnel_routes.read().ok()?;
        (current.0 == Self::tunnel_generation()).then(|| current.1.get(&id).cloned()).flatten()
    }

    fn refresh_tunnel_routes(&self) -> anyhow::Result<()> {
        let generation = Self::tunnel_generation();
        if self.tunnel_sites.is_empty() || self.tunnel_routes.read().unwrap_or_else(|e| e.into_inner()).0 == generation {
            return Ok(());
        }
        let mut next = HashMap::new();
        for (&id, &oidc) in &self.tunnel_sites {
            let rules = self.rules.site(id).context("missing tunnel site")?;
            let mut site = build_site(rules, oidc, &self.cache_dir, None, self.sites[&id].policy.clone())?;
            site.serve_http01 = self.sites[&id].serve_http01;
            next.insert(id, site);
        }
        *self.tunnel_routes.write().unwrap_or_else(|e| e.into_inner()) = (generation, next);
        Ok(())
    }

    async fn refresh_upstreams(&self) {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            if let Err(error) = self.check_upstreams().await {
                tracing::warn!(%error, "managed upstream check failed");
            }
        }
    }

    async fn check_upstreams(&self) -> anyhow::Result<()> {
        self.refresh_tunnel_routes()?;
        let mut seen = std::collections::HashSet::new();
        for id in self.sites.keys() {
            let Some(site) = self.request_site(*id) else { continue };
            for (_, upstream) in site.upstreams.list() {
                if seen.insert(Arc::as_ptr(&upstream) as usize) {
                    upstream.run_health_check().await?;
                }
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn build(candidate: &Candidate, cache_dir: &Path) -> anyhow::Result<Self> {
        Self::with_policies(candidate, cache_dir, HashMap::new())
    }

    fn with_policies(candidate: &Candidate, cache_dir: &Path, mut policies: HashMap<Uuid, Arc<pingwaf_content::protection::Policy>>) -> anyhow::Result<Self> {
        let rules = candidate.compile()?;
        let mut certificate_orders = std::collections::BTreeMap::new();
        for (id, envelope) in candidate.sites() {
            if envelope.ingress.is_none() || !envelope.site.as_ref().is_some_and(|s| s.status() == pingwaf_proto::SiteStatusEnum::SiteStatusActive) { continue; }
            let endpoints = envelope.ingress.iter().chain(&envelope.additional_ingresses);
            if !endpoints.clone().all(|e| matches!((e.port, e.protocol()),
                (80, pingwaf_proto::IngressProtocol::Http) | (443, pingwaf_proto::IngressProtocol::Https))) { continue; }
            let Some(site) = rules.site(*id) else { continue };
            let Some(ssl) = site.rules.ssl_config.as_ref().filter(|s| s.acme_enabled && s.enabled && !s.acme_email.is_empty()) else { continue };
            if ssl.acme_challenge_type == "AcmeHttp01" && !endpoints.clone().any(|e| e.port == 80) { continue; }
            let domains = std::iter::once(site.rules.domain.as_ref()).chain(site.rules.alternate_domains.iter().map(AsRef::as_ref)).collect::<Vec<&str>>().join(",");
            if let Some(mut order) = super::acme_certificate_conf(ssl, domains) {
                if !ssl.cert_pem.is_empty() && !ssl.key_pem.is_empty() {
                    order.tls_cert = Some(ssl.cert_pem.clone());
                    order.tls_key = Some(ssl.key_pem.clone());
                }
                certificate_orders.insert(format!("{id}_cert"), order);
            }
        }
        let unmatched = if candidate.unmatched_pages.is_empty() { None } else {
            let pages = candidate.unmatched_pages.iter().map(|p|
                (i64::from(p.status_code), p.content_type.as_str(), p.body_template.as_str(), p.name.as_str()));
            Some(pingap_plugin::FallbackPagePlugin::new(&super::unmatched_plugin_config(pages))?)
        };
        let generation = Self::tunnel_generation();
        let mut tunnel_sites = HashMap::new();
        let sites: HashMap<_, _> = rules
            .sites()
            .filter_map(|(id, site)| {
                Some((id, site, candidate.sites().get(&id)?.ingress.as_ref()?))
            })
            .map(|(id, site, ingress)| {
                let oidc = managed_oidc(&rules, id, site, ingress)?;
                let envelope = &candidate.sites()[&id];
                if envelope.handler.is_none() && site.rules.upstreams.iter().any(|pool| !pool.tunnel_id.is_empty()) {
                    tunnel_sites.insert(id, oidc);
                }
                let mut request_site = build_site(site, oidc, cache_dir, envelope.handler.as_ref(), policies.remove(&id))?;
                request_site.serve_http01 = certificate_orders.get(&format!("{id}_cert")).is_some_and(|c| c.dns_challenge != Some(true));
                Ok((id, request_site))
            })
            .collect::<anyhow::Result<_>>()?;
        let mut tls_failures = HashMap::new();
        #[cfg(any(feature = "openssl", feature = "tls-rustls"))]
        let tls = candidate
            .sites()
            .iter()
            .filter(|(_, site)| {
                site.ingress.iter().chain(&site.additional_ingresses).any(|ingress| {
                    ingress.protocol() == pingwaf_proto::IngressProtocol::Https
                })
            })
            .filter_map(|(id, _)| {
                let ssl = rules
                    .site(*id)
                    .and_then(|site| site.rules.ssl_config.as_ref());
                match ssl.context("missing TLS configuration").and_then(tls::TlsSite::build) {
                    Ok(tls) => Some((*id, tls)),
                    Err(error) => {
                        tracing::warn!(site_id = %id, %error, "HTTPS configuration could not be loaded");
                        tls_failures.insert(*id, "tls_config");
                        None
                    }
                }
            })
            .collect();
        Ok(Self {
            certificate_orders: Arc::new(certificate_orders),
            tunnel_routes: std::sync::RwLock::new((generation, tunnel_sites.keys()
                .map(|id| (*id, sites[id].clone())).collect())),
            tunnel_sites,
            cache_dir: cache_dir.to_path_buf(),
            unmatched,
            tls_failures,
            rules,
            sites,
            #[cfg(any(feature = "openssl", feature = "tls-rustls"))]
            tls,
        })
    }
}

fn managed_oidc(
    rules: &Compiled,
    id: Uuid,
    site: &CompiledSite,
    ingress: &pingwaf_proto::SiteIngress,
) -> anyhow::Result<Option<u16>> {
    use anyhow::{Context, ensure};
    let Some(oidc) = site.rules.oidc.as_ref().filter(|oidc| oidc.enabled)
    else {
        return Ok(None);
    };
    ensure!(
        matches!(oidc.auth_mode.trim(), "" | "oidc" | "local" | "both"),
        "unknown managed authentication mode"
    );
    ensure!(
        ingress.protocol() == pingwaf_proto::IngressProtocol::Https,
        "managed OIDC requires a custom HTTPS ingress"
    );
    let port = u16::try_from(ingress.port)?;
    let url = url::Url::parse(&oidc.redirect_url)
        .context("managed OIDC requires an explicit HTTPS callback URL")?;
    let host = url
        .host_str()
        .context("managed OIDC callback needs a host")?;
    ensure!(
        url.scheme() == "https" && !host.ends_with('.'),
        "managed OIDC requires a canonical HTTPS callback URL"
    );
    let callback_path = if oidc.redirect_path.is_empty() {
        "/oauth2/callback"
    } else {
        &oidc.redirect_path
    };
    ensure!(
        url.path() == callback_path,
        "managed authentication callback path mismatch"
    );
    let listener = Listener::Custom {
        port,
        protocol: ingress.protocol(),
    };
    // Check the full listener index: another site's exact alias may outrank
    // this site's wildcard.
    ensure!(
        rules
            .select(listener, host)
            .is_some_and(|(selected, _)| selected == id),
        "managed OIDC callback must select site {id}"
    );
    Ok(Some(port))
}

fn build_site(
    site: &CompiledSite,
    oidc_listener_port: Option<u16>,
    cache_dir: &Path,
    handler: Option<&pingwaf_proto::managed_site::Handler>,
    policy: Option<Arc<pingwaf_content::protection::Policy>>,
) -> anyhow::Result<ManagedRequestSite> {
    use pingwaf_proto::managed_site::Handler;
    let handler = match handler {
        Some(Handler::Redirect(spec)) => {
            anyhow::ensure!(matches!(spec.status, 301 | 302 | 307 | 308), "invalid redirect status");
            let mut conf = pingap_config::PluginConf::new();
            conf.insert("category".into(), "redirect".into());
            conf.insert("target".into(), spec.target.clone().into());
            conf.insert("status".into(), i64::from(spec.status).into());
            conf.insert("preserve_path".into(), spec.preserve_path.into());
            conf.insert("preserve_query".into(), spec.preserve_query.into());
            Some(conf)
        }
        Some(Handler::StaticRelease(spec)) => {
            anyhow::ensure!(spec.digest.len() == 64 && spec.digest.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()), "invalid static release digest");
            let site_id = uuid::Uuid::parse_str(&site.rules.site_id)?;
            let mut root = pingwaf_agent::static_dirs::release_path(site_id, &spec.digest)?;
            if spec.directory_id.is_empty() {
                let fingerprint = std::fs::read_to_string(root.join("tree.sha256"))?;
                root = root.join("public");
                anyhow::ensure!(pingwaf_agent::static_dirs::digest(&root)? == fingerprint, "stored archive failed integrity check");
            } else {
                pingwaf_agent::static_dirs::prepare_registered(&spec.directory_id, &spec.digest, &root).context(ContentFailure("content_validation"))?;
            }
            anyhow::ensure!(root.join("index.html").is_file(), "static release is not prepared");
            let mut conf = pingap_config::PluginConf::new();
            conf.insert("category".into(), "directory".into());
            conf.insert("path".into(), root.to_string_lossy().into_owned().into());
            conf.insert("follow_symlinks".into(), false.into());
            conf.insert("autoindex".into(), false.into());
            if let Some(policy) = &policy {
                conf.insert("chunk_size".into(), "512 KiB".into());
                let mut paths: Vec<_> = policy.paths.keys().cloned().collect();
                paths.sort();
                conf.insert("public_pages".into(), toml::Value::try_from(paths)?);
            }
            Some(conf)
        }
        None => None,
    };
    let rules = site.translation_input();
    if handler.is_some() {
        anyhow::ensure!(site.rules.upstreams.iter().all(|pool| pool.peers.is_empty()) && site.rules.routes.is_empty(), "terminal site cannot have origins or origin routes");
    }
    let (mut config, mut names) =
        super::convert_proxy_config_with_handler(&rules, cache_dir, false, handler.as_ref());
    if let Some(port) = oidc_listener_port {
        use anyhow::Context;
        let id = site.rules.site_id.as_ref();
        let auth = site
            .rules
            .oidc
            .as_ref()
            .context("missing site authentication settings")?;
        let mode = auth.auth_mode.trim();
        let required: &[&str] = match mode {
            "local" => &["visitor_auth"],
            "both" => &["visitor_auth", "oidc"],
            _ => &["oidc"],
        };
        for kind in required {
            let plugin = config
                .plugins
                .get_mut(&format!("{id}_{kind}"))
                .with_context(|| {
                    format!("managed {kind} plugin missing for site {id}")
                })?;
            plugin.insert(
                "managed_site_id".into(),
                toml::Value::String(id.to_string()),
            );
            plugin.insert(
                "managed_listener_port".into(),
                toml::Value::Integer(port.into()),
            );
            plugin.insert(
                "redirect_url".into(),
                toml::Value::String(auth.redirect_url.clone()),
            );
            if mode == "both" && *kind == "visitor_auth" {
                // The visitor gate derives the managed OIDC cookie name from the site UUID.
                plugin.insert(
                    "oidc_cookie_name".into(),
                    toml::Value::String("oidc".into()),
                );
                let callback = if auth.redirect_path.is_empty() {
                    "/oauth2/callback"
                } else {
                    &auth.redirect_path
                };
                let mut paths = vec![callback.into()];
                if !auth.logout_path.is_empty() {
                    paths.push(auth.logout_path.clone().into());
                }
                plugin.insert(
                    "delegated_paths".into(),
                    toml::Value::Array(paths),
                );
            }
        }
    }
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
        serve_http01: false,
        policy,
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
    forwarding: Arc<Forwarding<Arc<View>>>,
    listener: Listener,
    tls_site: Option<Uuid>,
}

type SiteGrant = Forwarding<Arc<View>>;
#[derive(Clone, Copy)]
enum TlsIdentity { Plain, Known(Uuid), Unknown }

tokio::task_local! {
    static REQUEST_GRANT: std::cell::RefCell<Option<tokio::sync::oneshot::Sender<SiteGrant>>>;
    static TLS_IDENTITY: TlsIdentity;
}

fn pin_request(grant: SiteGrant) -> Result<(), ManagedRouteMiss> {
    REQUEST_GRANT.try_with(|slot| {
        slot.borrow_mut().take().ok_or(ManagedRouteMiss::Unavailable)?
            .send(grant).map_err(|_| ManagedRouteMiss::Unavailable)
    }).map_err(|_| ManagedRouteMiss::Unavailable)?
}

struct StandardSelector {
    host: std::sync::Weak<Host>,
    listener: Listener,
}

impl ManagedSiteSelector for StandardSelector {
    fn select(&self, session: &Session, hostname: &str) -> Result<Option<ManagedRequestSite>, ManagedRouteMiss> {
        let host = self.host.upgrade().ok_or(ManagedRouteMiss::Unavailable)?;
        let tls = TLS_IDENTITY.try_with(|id| *id).map_err(|_| ManagedRouteMiss::Unavailable)?;
        let default = host.state.scoped_forwarding(Listener::Default);
        let custom = host.state.scoped_forwarding(self.listener);
        for (listener, handle) in [(self.listener, custom.as_ref()), (Listener::Default, default.as_ref())] {
            let Some(handle) = handle else { continue };
            let Some(view) = handle.request_view(listener) else { return Err(ManagedRouteMiss::Unavailable) };
            let Some((id, _)) = view.rules.select(listener, hostname) else { continue };
            if matches!(tls, TlsIdentity::Unknown) || matches!(tls, TlsIdentity::Known(sni) if sni != id) {
                return Err(ManagedRouteMiss::Misdirected);
            }
            let (selected, grant) = handle.site_grant(listener, hostname).ok_or(ManagedRouteMiss::Unavailable)?;
            if selected != id { return Err(ManagedRouteMiss::Unavailable); }
            let site = if listener == Listener::Default {
                if !host.default_routes.read().unwrap_or_else(|e| e.into_inner()).applied.contains_key(&id) {
                    return Err(ManagedRouteMiss::Unavailable);
                }
                None
            } else {
                Some(grant.view().request_site(id).ok_or(ManagedRouteMiss::Unavailable)?)
            };
            pin_request(grant)?;
            return Ok(site);
        }
        if matches!(tls, TlsIdentity::Known(_)) { return Err(ManagedRouteMiss::Misdirected); }
        let active = host.state.forwarding().ok_or(ManagedRouteMiss::Unavailable)?;
        let response = active.view().unmatched.as_ref().and_then(|p| p.unmatched_response(hostname, session.req_header().uri.path()));
        Err(ManagedRouteMiss::Unmatched(response))
    }
}

impl ManagedSiteSelector for Selector {
    fn select(
        &self,
        session: &Session,
        hostname: &str,
    ) -> Result<Option<ManagedRequestSite>, ManagedRouteMiss> {
        let view = self.forwarding.request_view(self.listener).ok_or(ManagedRouteMiss::Unavailable)?;
        let Some((id, _)) = view.rules.select(self.listener, hostname) else {
            if self.tls_site.is_some() { return Err(ManagedRouteMiss::Misdirected); }
            let page = view.unmatched.as_ref().and_then(|p| p.unmatched_response(hostname, session.req_header().uri.path()));
            return Err(ManagedRouteMiss::Unmatched(page));
        };
        if self.tls_site.is_some_and(|selected| selected != id) {
            return Err(ManagedRouteMiss::Misdirected);
        }
        let (granted_id, grant) = self.forwarding.site_grant(self.listener, hostname)
            .ok_or(ManagedRouteMiss::Unavailable)?;
        if granted_id != id { return Err(ManagedRouteMiss::Unavailable); }
        let site = grant.view().request_site(id).ok_or(ManagedRouteMiss::Unavailable)?;
        pin_request(grant)?;
        Ok(Some(site))
    }
}

/// Pingora's HTTP/2 dispatch spawns the per-stream `process_new_http` future
/// independently of the connection. Fence at that boundary as well as around
/// the transport so revocation drops live proxy requests, not just their client.
struct AuthorizedProxy {
    forwarding: Arc<Forwarding<Arc<View>>>,
    app: Arc<HttpProxy<Server>>,
    tls: TlsIdentity,
}

#[async_trait::async_trait]
impl HttpServerApp for AuthorizedProxy {
    async fn process_new_http(
        self: &Arc<Self>,
        session: ServerSession,
        shutdown: &ShutdownWatch,
    ) -> Option<ReusedHttpStream> {
        self.forwarding.run(|_| async {
            let (sender, receiver) = tokio::sync::oneshot::channel();
            let request = REQUEST_GRANT.scope(std::cell::RefCell::new(Some(sender)),
                TLS_IDENTITY.scope(self.tls, self.app.process_new_http(session, shutdown)));
            tokio::pin!(request);
            tokio::select! {
                result = &mut request => result,
                grant = receiver => match grant {
                    Ok(grant) => grant.run(|_| request).await.flatten(),
                    Err(_) => request.await,
                },
            }
        }).await.flatten()
    }

    fn h2_options(&self) -> Option<H2Options> {
        self.app.h2_options()
    }

    fn server_options(&self) -> Option<&HttpServerOptions> {
        self.app.server_options()
    }
}

#[cfg(test)]
async fn serve_http(
    forwarding: Forwarding<Arc<View>>,
    tcp: tokio::net::TcpStream,
    listener: Listener,
    shutdown: ShutdownWatch,
    h2c: bool,
) -> Option<anyhow::Result<()>> {
    serve_http_stream(forwarding, super::ingress::downstream_stream(tcp), listener, shutdown, h2c).await
}

async fn serve_http_stream(
    forwarding: Forwarding<Arc<View>>,
    mut stream: pingora::protocols::l4::stream::Stream,
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
        .run(|_| async {
            let (stream, tls_site, tls_grant): (pingora::protocols::Stream, _, Option<SiteGrant>) =
                match protocol {
                    pingwaf_proto::IngressProtocol::Http => {
                        (Box::new(stream), None, None)
                    },
                    #[cfg(any(feature = "openssl", feature = "tls-rustls"))]
                    pingwaf_proto::IngressProtocol::Https => {
                        tokio::time::timeout(std::time::Duration::from_secs(10), async {
                            let sni = tls::read_sni(&mut stream).await?.context("managed HTTPS requires SNI")?;
                            let (id, grant) = forwarding.site_grant(listener, &sni).context("SNI is not assigned to this listener")?;
                            let stream = grant.run(|view| tls::accept(stream, view, id, &sni))
                                .await.context("site authorization withdrawn")??;
                            Ok::<_, anyhow::Error>((stream, Some(id), Some(grant)))
                        }).await??
                    },
                    _ => anyhow::bail!("unsupported managed ingress transport"),
                };
            let selector = Arc::new(Selector {
                forwarding: forwarding.clone(),
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
                tls: tls_site.map_or(TlsIdentity::Plain, TlsIdentity::Known),
            };
            let service = Service::handle_event(stream, Arc::new(app), shutdown);
            if let Some(grant) = tls_grant {
                grant.run(|_| service).await;
            } else {
                service.await;
            }
            Ok(())
        })
        .await
}

#[cfg(target_os = "linux")]
#[cfg(test)]
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

    #[tokio::test]
    async fn invalid_tls_material_only_fails_its_own_site() {
        let origin = "127.0.0.1:8123".parse().unwrap();
        let healthy = site(Some(81), origin);
        let mut invalid = site(Some(83), origin);
        let identity = invalid.site.as_mut().unwrap();
        identity.id = Uuid::new_v4().to_string();
        identity.rules.as_mut().unwrap().site_id = identity.id.clone();
        let id = identity.id.clone();
        invalid.ingress.as_mut().unwrap().protocol = IngressProtocol::Https as i32;
        let (session, incoming) = receive(vec![healthy, invalid]);
        let temp = tempfile::tempdir().unwrap();
        let state = AppliedState::default();
        state.start_session(session);
        let pending = state.prepare(incoming).unwrap().unwrap();
        let view = View::build(pending.candidate(), temp.path()).unwrap();
        assert!(view.rules.select(listener(81), "alias.example").is_some());
        assert_eq!(view.tls_failures.len(), 1);
        assert_eq!(view.tls_failures[&Uuid::parse_str(&id).unwrap()], "tls_config");
        assert!(!view.tls.contains_key(&Uuid::parse_str(&id).unwrap()));
        let failures = view.tls_failures.clone();
        assert!(state.publish_with_failures(pending, view, failures).unwrap());
        let report = state.application_report(&Default::default(), true).unwrap();
        assert_eq!(report.received_sites.len(), 1);
        assert_eq!(report.received_sites[0].site_id, id);
        assert_eq!(report.received_sites[0].failure_code, "tls_config");
    }

    fn receive(
        sites: Vec<ManagedSite>,
    ) -> (Uuid, pingwaf_agent::managed::Received) {
        let session = Uuid::new_v4();
        let mut receiver = Receiver::default();
        receiver.set_session(Some(session));
        (session, receive_version(&mut receiver, session, Uuid::new_v4(), 1, sites))
    }

    #[test]
    fn explicit_standard_listeners_supply_orders_without_default_routes() {
        let dir = tempfile::tempdir().unwrap();
        for (port, additional, allowed) in [(80, None, true), (80, Some(81), false), (81, None, false)] {
            let mut item = site(Some(port), "127.0.0.1:18001".parse().unwrap());
            item.handler = Some(pingwaf_proto::managed_site::Handler::Redirect(pingwaf_proto::SiteRedirect {
                target: "https://destination.example/".into(), status: 302, ..Default::default()
            }));
            let rules = item.site.as_mut().unwrap().rules.as_mut().unwrap();
            rules.upstreams.clear();
            rules.routes.clear();
            rules.ssl = Some(pingwaf_proto::SslConfig {
                enabled: true, acme_enabled: true, acme_email: "fixture@example.test".into(), ..Default::default()
            });
            if let Some(port) = additional {
                item.additional_ingresses.push(pingwaf_proto::SiteIngress { port, protocol: IngressProtocol::Http as i32 });
            }
            let (_, received) = receive(vec![item]);
            assert!(received.candidate.default_config().sites.is_empty());
            let view = View::build(&received.candidate, dir.path()).unwrap();
            assert_eq!(!view.certificate_orders.is_empty(), allowed);
            assert_eq!(view.sites.values().next().unwrap().serve_http01, allowed);
        }
    }

    fn receive_version(receiver: &mut Receiver, session: Uuid, authority: Uuid, generation: i64, sites: Vec<ManagedSite>) -> pingwaf_agent::managed::Received {
        let config = ManagedSiteConfig::from_sites(sites).encode_to_vec();
        PullWindow::start(receiver)
            .unwrap()
            .receive(
                receiver,
                ManagedSnapshot {
                    session_id: session.to_string(),
                    authority_epoch: authority.to_string(),
                    generation,
                    config_hash: hex::encode(Sha256::digest(&config)),
                    config,
                    lease_seconds: 30,
                },
            )
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    async fn live_h1_and_h2_requests_follow_the_published_site_on_the_same_connections() {
        tokio::time::timeout(Duration::from_secs(15), async {
            let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = proxy.local_addr().unwrap();
            let ingress = listener(addr.port());
            let mut item = site(Some(addr.port()), addr);
            let rules = item.site.as_mut().unwrap().rules.as_mut().unwrap();
            rules.upstreams.clear();
            rules.routes.clear();
            let (session, authority) = (Uuid::new_v4(), Uuid::new_v4());
            let mut receiver = Receiver::default();
            receiver.set_session(Some(session));
            let state = AppliedState::default();
            state.start_session(session);
            let directory = tempfile::tempdir().unwrap();
            let mut neighbor = item.clone();
            let identity = neighbor.site.as_mut().unwrap();
            identity.id = Uuid::new_v4().to_string();
            identity.rules.as_mut().unwrap().site_id = identity.id.clone();
            identity.domain = "neighbor.example".into();
            identity.alternate_domains.clear();
            let mut prepare = |generation, status| {
                item.handler = Some(pingwaf_proto::managed_site::Handler::Redirect(pingwaf_proto::SiteRedirect {
                    target: "https://destination.example/".into(), status, ..Default::default()
                }));
                neighbor.handler = item.handler.clone();
                let sites = if generation < 3 { vec![item.clone(), neighbor.clone()] } else { vec![item.clone()] };
                let incoming = receive_version(&mut receiver, session, authority, generation, sites);
                let pending = state.prepare(incoming).unwrap().unwrap();
                let view = Arc::new(View::build(pending.candidate(), directory.path()).unwrap());
                (pending, view)
            };
            let (first, view) = prepare(1, 302);
            assert!(state.publish(first, view).unwrap());
            let (_shutdown, watch) = tokio::sync::watch::channel(false);
            let mut tasks = JoinSet::new();
            let connect = |h2c| {
                let watch = watch.clone();
                let handle = state.forwarding_for(ingress).unwrap();
                let proxy = &proxy;
                async move {
                    let (client, accepted) = tokio::join!(TcpStream::connect(addr), proxy.accept());
                    let tcp = accepted.unwrap().0;
                    let task = async move { serve_http(handle, tcp, ingress, watch, h2c).await };
                    (client.unwrap(), task)
                }
            };
            let (mut h1, server) = connect(false).await;
            tasks.spawn(server);
            let (tcp, server) = connect(true).await;
            tasks.spawn(server);
            let (mut h2, connection) = h2::client::handshake(tcp).await.unwrap();
            let driver = tokio::spawn(connection);
            let mut staged = None;
            let (_, old_neighbor) = state.forwarding_for(ingress).unwrap().site_grant(ingress,"neighbor.example").unwrap();
            for (phase, expected) in [302, 302, 307, 307].into_iter().enumerate() {
                if phase == 1 { staged = Some(prepare(2, 307)); }
                if phase == 2 {
                    let (pending, view) = staged.take().unwrap();
                    assert!(state.publish(pending, view).unwrap());
                }
                if phase == 3 {
                    let (pending, view) = prepare(3, 307);
                    assert!(old_neighbor.run(|_| std::future::ready(())).await.is_none());
                    assert!(state.publish(pending, view).unwrap());
                }
                h1.write_all(b"HEAD /route HTTP/1.1\r\nHost: alias.example\r\n\r\n").await.unwrap();
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") {
                    headers.push(h1.read_u8().await.unwrap());
                    assert!(headers.len() < 8192);
                }
                assert!(String::from_utf8(headers).unwrap().starts_with(&format!("HTTP/1.1 {expected}")));
                let request = http::Request::builder().method("HEAD").uri("http://alias.example/route").body(()).unwrap();
                let (response, _) = h2.send_request(request, true).unwrap();
                assert_eq!(response.await.unwrap().status().as_u16(), expected);
            }
            state.end_session(session);
            driver.abort();
            while let Some(result) = tasks.join_next().await { result.unwrap(); }
        }).await.unwrap();
    }

    fn apply(
        sites: Vec<ManagedSite>,
        cache_dir: &Path,
    ) -> (Arc<AppliedState<Arc<View>>>, Uuid) {
        let (session, received) = receive(sites);
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
                if name == "other.example" {
                    row.rules.as_mut().unwrap().oidc = Some(pingwaf_proto::OidcConfig {
                        enabled: true,
                        issuer: "https://idp.example".into(),
                        client_id: "managed-site-test".into(),
                        cookie_secret: "test-cookie-key-not-for-deployment".into(),
                        redirect_url: "https://other.example:8443/oauth2/callback".into(),
                        logout_path: "/logout".into(),
                        session_ttl_seconds: 600,
                        path: "/private".into(),
                        ..Default::default()
                    });
                }
                sites.push(item);
                tasks.spawn(origin(origin_socket, name, false));
            }

            let cache = tempfile::tempdir().unwrap();
            let (state, _) = apply(sites.clone(), cache.path());
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
            let connect = |client: TlsConnector, name: &'static str, forwarding_state: Arc<AppliedState<Arc<View>>>| {
                let proxy = &proxy;

                async move {
                    let join = tokio::spawn({
                        let io = TcpStream::connect(addr).await.unwrap();
                        async move { client.connect(ServerName::try_from(name).unwrap(), io).await }
                    });
                    let (tcp, _) = proxy.accept().await.unwrap();
                    let forwarding = forwarding_state.forwarding().unwrap();
                    let server = tokio::spawn(async move {
                        let (_shutdown, watch) = tokio::sync::watch::channel(false);
                        serve_http(forwarding, tcp, listener, watch, false).await.unwrap()
                    });
                    (join.await.unwrap(), server)
                }
            };

            for (identity, name, sni) in [(None, "shared.example", true), (Some(1), "shared.example", true), (Some(0), "unknown.example", true), (Some(0), "shared.example", false)] {
                let (client, server) = connect(config(identity, b"http/1.1", sni, false), name, state.clone()).await;
                // TLS 1.3 clients may finish their side before seeing the
                // server's rejection; assert at the accepting server.
                assert!(server.await.unwrap().is_err());
                drop(client);
            }

            for (name, config) in [
                ("shared.example", config(Some(0), b"http/1.1", true, true)),
                ("other.example", config(Some(1), b"h2", true, false)),
            ] {
                let (client, server) = connect(config, name, state.clone()).await;
                assert!(server.await.unwrap().is_err());
                drop(client);
            }

            let reusable_client = config(Some(0), b"http/1.1", true, false);
            for _ in 0..2 {
                let (client, server) = connect(reusable_client.clone(), "shared.example", state.clone()).await;
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

            let (client, server) = connect(config(Some(0), b"h2", true, false), "shared.example", state.clone()).await;
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

            for (path, host, status, expected) in [
                ("/private", "other.example", 421, "Use the configured HTTPS origin"),
                ("/private", "other.example.:8443", 421, "Use the configured HTTPS origin"),
                ("/private", "other-alias.example:8443", 421, "Use the configured HTTPS origin"),
                ("/private", "other.example:8443", 401, "Login required"),
                ("/oauth2/callback?code=unused&state=unused", "other.example:8443", 400, "this login was not started here"),
                ("/logout", "other.example:8443", 405, "allow: POST"),
                ("/route", "other.example:8443", 200, "other.example"),
            ] {
                let (client, server) = connect(config(Some(1), b"http/1.1", true, false), "other.example", state.clone()).await;
                let mut client = client.unwrap();
                assert_eq!(client.get_ref().1.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_2));
                client.write_all(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nX-Forwarded-Host: other.example:8443\r\nX-Forwarded-Proto: https\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
                client.flush().await.unwrap();
                let response = read_closed_tls_response(&mut client).await;
                server.await.unwrap().unwrap();
                assert!(response.starts_with(&format!("HTTP/1.1 {status}")), "{response}");
                assert!(response.to_ascii_lowercase().contains(&expected.to_ascii_lowercase()), "{response}");
            }

            for mode in ["local", "both"] {
                let mut rows = sites.clone();
                let auth = rows.iter_mut().find_map(|row| row.site.as_mut()?.rules.as_mut()?.oidc.as_mut()).unwrap();
                auth.auth_mode = mode.into();
                let (scoped, _) = apply(rows, cache.path());
                for (path, host, expected) in [
                    ("/private", "other.example:8443", 401),
                    ("/private", "other.example:9443", 403),
                    ("/_pingwaf/logout", "other.example:8443", 403),
                    ("/oauth2/callback", "other.example:8443", if mode == "both" { 400 } else { 401 }),
                ] {
                    let (client, server) = connect(config(Some(1), b"http/1.1", true, false), "other.example", scoped.clone()).await;
                    let mut client = client.unwrap();
                    client.write_all(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
                    let response = read_closed_tls_response(&mut client).await;
                    server.await.unwrap().unwrap();
                    assert!(response.starts_with(&format!("HTTP/1.1 {expected}")), "{mode} {path}: {response}");
                }
            }
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
        client.write_all(format!("GET /route HTTP/1.1\r\nHost: {host}\r\nCookie: __pingwaf_managed_clearance_test=client; theme=blue\r\nCookie: __pingwaf_managed_oidc_test=client; __pingwaf_managed_visitor_test=visitor\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
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
            let rules = pingwaf_agent::cache::RuleCache::new(
                cache.path().into(),
                "integration".into(),
            )
            .unwrap();
            let host = Host::new(rules.clone());
            let callbacks = host.callbacks();
            for site in &mut sites {
                site.site_revision = "ab".repeat(32);
            }
            rules.set_ingress_listeners(pingwaf_proto::IngressListeners {
                panel: Some(pingwaf_proto::PanelListenerReport {
                    infrastructure_ports: Vec::new(),
                    desired_generation: 1, applied_generation: 1, policy_revision: 0,
                    sockets: endpoints.iter().filter(|(_,_,marker)| marker.is_some()).map(|(addr,_,_)|
                        pingwaf_proto::PanelSocketStatus { address: "0.0.0.0".into(), error: String::new(),
                            listener: Some(pingwaf_proto::IngressListenerStatus { port: addr.port().into(),
                                protocol: IngressProtocol::Http as i32, state: pingwaf_proto::IngressBindState::Bound as i32 })
                        }).collect(),
                }),
                supports_site_handlers: false,
                supports_site_archives: false,
                static_directories: Default::default(),
            prepared_directories: Vec::new(),
            static_root_registry: None,
                dynamic_bind: false,
                listeners: endpoints
                    .iter()
                    .map(|(addr, _, _)| pingwaf_proto::IngressListenerStatus {
                        port: addr.port().into(),
                        protocol: IngressProtocol::Http as i32,
                        state: pingwaf_proto::IngressBindState::Bound as i32,
                    })
                    .collect(),
            });
            assert!(callbacks.application_report().is_none());
            let (session, received) = receive(sites);
            let defaults = received.candidate.default_config();
            assert_eq!(defaults.sites.len(), 1);
            assert_eq!(
                defaults.sites[0]
                    .rules
                    .as_ref()
                    .unwrap()
                    .site_policies
                    .len(),
                1
            );
            callbacks.session_started(session);
            callbacks.candidate_received(received);
            assert_eq!(rules.all_sites().sites.len(), 1);
            assert!(
                rules.get_site_rules_by_id(&defaults.sites[0].id).is_some()
            );
            while host.state.forwarding().is_none() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }

            let report = callbacks.application_report().unwrap();
            assert_eq!(report.sites.len(), 2);
            assert_eq!(report.session_id, session.to_string());
            assert!(
                report
                    .sites
                    .iter()
                    .all(|row| row.site_revision == "ab".repeat(32))
            );
            rules.set_ingress_listeners(Default::default());
            assert!(callbacks.application_report().unwrap().sites.is_empty());
            let mut clients = Vec::new();
            for (addr, proxy, marker) in endpoints {
                let host = host.clone();
                tasks.spawn(async move {
                    let (tcp, _) = proxy.accept().await.unwrap();
                    let (_shutdown, watch) = tokio::sync::watch::channel(false);
                    host.serve(tcp, listener(addr.port()), watch).await;
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
                    assert!(response.starts_with("HTTP/1.1 404"), "{response}");
                    assert!(response.split_once("\r\n\r\n").is_some_and(|(_,body)| body.contains("<html")));
                }
            }
            callbacks.session_ended(session);
            assert!(callbacks.application_report().is_none());
            assert!(host.state.forwarding().is_none());
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
