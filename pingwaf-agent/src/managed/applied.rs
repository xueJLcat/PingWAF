use std::collections::HashMap;
use std::future::{poll_fn, Future};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::Poll;

use tokio::sync::watch;
use uuid::Uuid;

use super::{Candidate, Lease, Listener, Received, Version};

// The receipt identifies a site by its primary entrance. A default site
// still requires both HTTP and HTTPS to be bound before it can be applied.
fn report_ingress(site: &pingwaf_proto::ManagedSite) -> pingwaf_proto::SiteIngress {
    site.ingress.unwrap_or(pingwaf_proto::SiteIngress {
        port: 80, protocol: pingwaf_proto::IngressProtocol::Http as i32,
    })
}

/// A full, immutable proxy view is published as a unit. A caller must not use
/// this store to publish a reference to providers that can be reloaded in place.
pub struct AppliedState<T>(Arc<Mutex<State<T>>>);

struct State<T> {
    session: Option<Uuid>,
    latest: Option<Version>,
    receipt: Option<(Lease, pingwaf_proto::ManagedApplyReport)>,
    active: Option<Arc<Applied<T>>>,
    listeners: HashMap<Listener, Forwarding<T>>,
    sites: HashMap<(Listener, Uuid), Forwarding<T>>,
}

struct Applied<T> {
    policy: Candidate,
    view: T,
    site_failures: HashMap<Uuid, &'static str>,
    authorization: watch::Sender<Authorization>,
}

struct Authorization {
    lease: Lease,
    revoked: bool,
}

impl Authorization {
    fn is_live(&self) -> bool {
        !self.revoked && self.lease.permits(self.lease.version())
    }
}

/// Exclusive, one-use ticket for the view being compiled in isolation.
pub struct Pending {
    received: Received,
}

impl Pending {
    pub fn candidate(&self) -> &Candidate {
        &self.received.candidate
    }
}

/// Pin an applied view for one connection. The caller must run *all* I/O,
/// including the handshake and keep-alive streams, inside `run`.
pub struct Forwarding<T>(Arc<Applied<T>>, watch::Sender<Authorization>, std::sync::Weak<Mutex<State<T>>>);

impl<T> Clone for Forwarding<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone(), self.1.clone(), self.2.clone())
    }
}

impl<T> Default for AppliedState<T> {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(State {
            session: None,
            latest: None,
            receipt: None,
            active: None,
            listeners: HashMap::new(),
            sites: HashMap::new(),
        })))
    }
}

impl<T> State<T> {
    fn revoke(&mut self) {
        for (_, site) in self.sites.drain() {
            site.1.send_modify(|a| a.revoked = true);
        }
        for (_, scoped) in self.listeners.drain() {
            scoped.1.send_modify(|a| a.revoked = true);
        }
        self.revoke_snapshot();
    }

    fn revoke_snapshot(&mut self) {
        self.receipt = None;
        if let Some(active) = self.active.take() {
            active.authorization.send_modify(|a| a.revoked = true);
        }
    }
}

impl<T> AppliedState<T> {
    fn lock(&self) -> MutexGuard<'_, State<T>> {
        // State is only ever changed here; callers never run under the lock.
        self.0.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    pub fn start_session(&self, session: Uuid) {
        let mut state = self.lock();
        state.revoke();
        state.latest = None;
        state.session = Some(session);
    }

    /// An ended session must not revoke a newer session.
    pub fn end_session(&self, session: Uuid) {
        let mut state = self.lock();
        if state.session == Some(session) {
            state.revoke();
            state.session = None;
            state.latest = None;
        }
    }

    /// Renew a live equivalent view, or withdraw it before building a
    /// replacement. Even a newer candidate received too late can withdraw
    /// traffic. Returning `None` alone is not evidence of renewal.
    pub fn prepare(
        &self,
        received: Received,
    ) -> anyhow::Result<Option<Pending>> {
        let version = received.candidate.version();
        let mut state = self.lock();
        if state.session != Some(version.session)
            || state.latest.is_some_and(|latest| {
                version.authority != latest.authority
                    || version.generation <= latest.generation
            })
        {
            return Ok(None);
        }
        state.latest = Some(version);
        // Revoke incompatible transports immediately. An equivalent policy
        // can renew here; a changed request policy waits for publication.
        let mut failure = None;
        state.listeners.retain(|listener, scoped| {
            if scoped
                .0
                .policy
                .can_prepare_content(&received.candidate, *listener)
            {
                match renew_authorization(&scoped.1, &received.lease) {
                    Ok(true) => return true,
                    Err(error) => failure = Some(error),
                    Ok(false) => {},
                }
            }
            // A changed request policy may finish preparing under the old
            // transport lease. Only publication can extend that lease.
            if scoped.is_live() && received.lease.permits(version)
                && scoped.0.policy.same_transport(&received.candidate, *listener)
            {
                return true;
            }
            scoped.1.send_modify(|a| a.revoked = true);
            false
        });
        if let Some(error) = failure {
            state.revoke();
            return Err(error);
        }
        let State { sites, listeners, .. } = &mut *state;
        sites.retain(|(listener, id), grant| {
            let valid = listeners.contains_key(listener)
                && grant.0.policy.same_site_transport(&received.candidate, *listener, *id)
                && grant.is_live() && received.lease.permits(version);
            if !valid { grant.1.send_modify(|a| a.revoked = true); }
            valid
        });
        if let Some(active) = state
            .active
            .as_ref()
            .filter(|a| a.policy.same_policy(&received.candidate))
        {
            match renew_authorization(&active.authorization, &received.lease) {
                Ok(true) => {
                    for grant in state.sites.values() {
                        renew_authorization(&grant.1, &received.lease)?;
                    }
                    return Ok(None);
                },
                Ok(false) => {},
                Err(error) => {
                    state.revoke();
                    return Err(error);
                },
            }
        }
        state.revoke_snapshot();
        let pending = received
            .lease
            .permits(version)
            .then_some(Pending { received });
        if let Some(p) = &pending {
            let received_sites = p
                .candidate()
                .sites()
                .iter()
                .filter_map(|(id, site)| {
                    Some(pingwaf_proto::ManagedSiteApplication {
                    failure_code: String::new(),
                        site_id: id.to_string(),
                        site_revision: site.site_revision.clone(),
                        ingress: Some(report_ingress(site)),
                    })
                })
                .collect();
            state.receipt = Some((
                p.received.lease.clone(),
                pingwaf_proto::ManagedApplyReport {
                    applied_config_hash: String::new(),
                    session_id: version.session.to_string(),
                    authority_epoch: version.authority.to_string(),
                    generation: version.generation,
                    received_sites,
                    sites: Vec::new(),
                },
            ));
        }
        Ok(pending)
    }

    pub fn preparation_failed(&self, version: Version, code: &'static str) {
        let mut state = self.lock();
        if state.latest == Some(version) {
            if let Some((_, report)) = &mut state.receipt {
                for site in &mut report.received_sites {
                    site.failure_code = code.into();
                }
            }
        }
    }

    /// A timer must be armed before publishing; a timer error is fail-closed.
    /// Call on the data-plane runtime, not from a blocking compiler thread.
    pub fn publish(&self, pending: Pending, view: T) -> anyhow::Result<bool> {
        self.publish_with_failures(pending, view, HashMap::new())
    }

    pub fn publish_with_failures(&self, pending: Pending, view: T, site_failures: HashMap<Uuid, &'static str>) -> anyhow::Result<bool> {
        let version = pending.candidate().version();
        let lease = pending.received.lease;
        let mut state = self.lock();
        if state.session != Some(version.session)
            || state.latest != Some(version)
            || !lease.permits(version)
        {
            return Ok(false);
        }
        let active = Arc::new(Applied {
            authorization: new_authorization(&lease)?,
            policy: pending.received.candidate,
            view,
            site_failures,
        });
        let mut listeners = HashMap::new();
        for listener in active
            .policy
            .routes
            .keys()
        {
            let auth = match state.listeners.get(listener) {
                Some(scoped) if scoped.0.policy.same_transport(&active.policy, *listener)
                    && renew_authorization(&scoped.1, &lease)? => scoped.1.clone(),
                Some(scoped) => {
                    let replacement = new_authorization(&lease)?;
                    scoped.1.send_modify(|authorization| authorization.revoked = true);
                    replacement
                },
                _ => new_authorization(&lease)?,
            };
            listeners.insert(*listener, Forwarding(active.clone(), auth, Arc::downgrade(&self.0)));
        }
        state.receipt = None;
        let mut sites = HashMap::new();
        for (listener, names) in &active.policy.routes {
            for id in names.values() {
                let key = (*listener, *id);
                if sites.contains_key(&key) { continue; }
                let auth = match state.sites.get(&key) {
                    Some(old) if renew_authorization(&old.1, &lease)? => old.1.clone(),
                    _ => new_authorization(&lease)?,
                };
                sites.insert(key, Forwarding(active.clone(), auth, Arc::downgrade(&self.0)));
            }
        }
        state.sites = sites;
        state.listeners = listeners;
        state.active = Some(active);
        Ok(true)
    }

    /// Sample only the live, published policy under the same lock as revoke.
    pub fn application_report(
        &self,
        bound: &pingwaf_proto::IngressListeners,
        defaults_ready: bool,
    ) -> Option<pingwaf_proto::ManagedApplyReport> {
        let state = self.lock();
        if let Some((lease, receipt)) = &state.receipt {
            if !lease.permits(lease.version()) {
                return None;
            }
            let mut report = receipt.clone();
            (report.sites, report.received_sites) =
                report.received_sites.into_iter().partition(|row| {
                    let Some(ingress) = &row.ingress else {
                        return false;
                    };
                    let Ok(port) = u16::try_from(ingress.port) else {
                        return false;
                    };
                    let listener = Listener::Custom {
                        port,
                        protocol: ingress.protocol(),
                    };
                    state
                        .listeners
                        .get(&listener)
                        .is_some_and(|current| current.is_live() &&
                            Uuid::parse_str(&row.site_id).ok().filter(|id| !current.0.site_failures.contains_key(id)).and_then(|id| current.0.policy.sites().get(&id))
                                .is_some_and(|site| site.ingress.is_some() && site.site_revision == row.site_revision &&
                                    site.additional_ingresses.is_empty()))
                        && bound.panel.as_ref().is_some_and(|p| p.desired_generation == lease.version().generation)
                        && bound.listeners.iter().any(|socket| {
                            socket.port == ingress.port
                                && socket.protocol == ingress.protocol
                                && socket.state()
                                    == pingwaf_proto::IngressBindState::Bound
                        })
                });
            for site in &mut report.sites { site.failure_code.clear(); }
            return Some(report);
        }
        let active = state.active.as_ref()?;
        let auth = active.authorization.borrow();
        if !auth.is_live() {
            return None;
        }
        let version = auth.lease.version();
        let mut sites: Vec<_> = active
            .policy
            .sites()
            .iter()
            .filter_map(|(id, site)| {
                let panel = bound.panel.as_ref()?;
                let id_text = id.to_string();
                let mut expected = active.policy.endpoints().iter().filter(|e| e.site_ids.contains(&id_text)).peekable();
                if active.site_failures.contains_key(id) || site.site_revision.is_empty() || (site.ingress.is_none() && !defaults_ready)
                    || panel.desired_generation != version.generation || panel.policy_revision != active.policy.policy_revision
                    || expected.peek().is_none() || !expected.all(|e| {
                        let Some(ingress) = e.ingress else { return false };
                        e.addresses.iter().all(|addr| panel.sockets.iter().any(|s| s.address == *addr &&
                            s.listener.is_some_and(|l| l.port == ingress.port && l.protocol == ingress.protocol &&
                                l.state() == pingwaf_proto::IngressBindState::Bound)))
                    }) { return None; }
                Some(pingwaf_proto::ManagedSiteApplication {
                    failure_code: String::new(),
                    site_id: id.to_string(),
                    site_revision: site.site_revision.clone(),
                    ingress: Some(report_ingress(site)),
                })
            })
            .collect();
        sites.sort_unstable_by(|a, b| a.site_id.cmp(&b.site_id));
        let complete = active.site_failures.is_empty()
            && bound.panel.as_ref().is_some_and(|p| p.applied_generation == version.generation)
            && active.policy.endpoints().iter().flat_map(|e| &e.site_ids)
                .all(|id| sites.iter().any(|site| &site.site_id == id));
        Some(pingwaf_proto::ManagedApplyReport {
            applied_config_hash: if complete { hex::encode(version.hash) } else { String::new() },
            session_id: version.session.to_string(),
            authority_epoch: version.authority.to_string(),
            generation: version.generation,
            sites,
            received_sites: active.site_failures.iter().filter_map(|(id, failure)| {
                let site = active.policy.sites().get(id)?;
                Some(pingwaf_proto::ManagedSiteApplication {
                    site_id: id.to_string(), site_revision: site.site_revision.clone(),
                    ingress: Some(report_ingress(site)), failure_code: (*failure).to_owned(),
                })
            }).collect(),
        })
    }

    pub fn live_endpoints(&self) -> (pingwaf_proto::PanelListenerReport, Vec<(std::net::SocketAddr, pingwaf_proto::IngressProtocol, Listener)>) {
        let state = self.lock();
        let mut endpoints = Vec::new();
        for (listener, forwarding) in &state.listeners {
            if !forwarding.is_live() { continue; }
            let policy = &forwarding.0.policy;
            for endpoint in policy.endpoints().iter().filter(|e| policy.endpoint_applies(e, *listener)) {
                let ingress = endpoint.ingress.as_ref().expect("validated endpoint");
                for address in &endpoint.addresses {
                    let ip = address.parse().expect("validated bind address");
                    endpoints.push((std::net::SocketAddr::new(ip, ingress.port as u16), ingress.protocol(), *listener));
                }
            }
        }
        let active = state.active.as_ref().filter(|a| a.authorization.borrow().is_live());
        let report = pingwaf_proto::PanelListenerReport {
            desired_generation: state.latest.map_or(0, |v| v.generation),
            applied_generation: active.map_or(0, |a| a.authorization.borrow().lease.version().generation),
            policy_revision: active.map_or(-1, |a| a.policy.policy_revision),
            infrastructure_ports: Vec::new(),
            sockets: Vec::new(),
        };
        (report, endpoints)
    }

    pub fn forwarding(&self) -> Option<Forwarding<T>> {
        let state = self.lock();
        let active = state.active.as_ref()?;
        let forwarding =
            Forwarding(active.clone(), active.authorization.clone(), Arc::downgrade(&self.0));
        forwarding.is_live().then_some(forwarding)
    }

    /// The caller must derive this identity from the accepting socket.
    pub fn scoped_forwarding(&self, listener: Listener) -> Option<Forwarding<T>> {
        self.lock().listeners.get(&listener).filter(|f| f.is_live()).cloned()
    }

    pub fn forwarding_for(&self, listener: Listener) -> Option<Forwarding<T>> {
        let state = self.lock();
        if let Some(scoped) = state.listeners.get(&listener) {
            return scoped.is_live().then(|| scoped.clone());
        }
        // Empty listeners still produce the published view's unknown-host
        // response. Revocation clears this fallback before replacement.
        let active = state.active.as_ref()?;
        let handle = Forwarding(active.clone(), active.authorization.clone(), Arc::downgrade(&self.0));
        handle.is_live().then_some(handle)
    }
}

fn new_authorization(
    lease: &Lease,
) -> anyhow::Result<watch::Sender<Authorization>> {
    let timer = lease.expiry_timer()?;
    let (auth, _) = watch::channel(Authorization {
        lease: lease.clone(),
        revoked: false,
    });
    watch_expiry(auth.clone(), lease.version(), timer);
    Ok(auth)
}

fn renew_authorization(
    auth: &watch::Sender<Authorization>,
    lease: &Lease,
) -> anyhow::Result<bool> {
    let version = lease.version();
    let timer = lease.expiry_timer()?;
    let renewed = auth.send_if_modified(|current| {
        if !current.is_live() || !lease.permits(version) {
            return false;
        }
        current.lease = lease.clone();
        true
    });
    if renewed {
        watch_expiry(auth.clone(), version, timer);
    }
    Ok(renewed)
}

fn watch_expiry(
    auth: watch::Sender<Authorization>,
    version: Version,
    timer: super::lease::ExpiryTimer,
) {
    let mut notice = auth.subscribe();
    tokio::spawn(async move {
        tokio::select! {
            _ = notice.wait_for(|a| a.revoked || a.lease.version() != version) => {},
            _ = timer.wait() => {
                auth.send_if_modified(|a| {
                    if a.lease.version() != version || a.revoked {
                        return false;
                    }
                    a.revoked = true;
                    true
                });
            },
        }
    });
}

impl<T> Drop for AppliedState<T> {
    fn drop(&mut self) {
        self.lock().revoke();
    }
}

impl<T> Forwarding<T> {
    /// Resolve the hostname and pin the site's authorization in one critical section.
    pub fn site_grant(&self, listener: Listener, name: &str) -> Option<(Uuid, Self)> {
        let shared = self.2.upgrade()?;
        let state = shared.lock().unwrap_or_else(|e| e.into_inner());
        let current = state.listeners.get(&listener)?;
        if !self.is_live() || !(self.1.same_channel(&current.1) || self.1.same_channel(&current.0.authorization)) {
            return None;
        }
        let id = current.0.policy.site_id(listener, name)?;
        let grant = state.sites.get(&(listener,id))?;
        grant.is_live().then(|| (id,grant.clone()))
    }

    pub fn view(&self) -> &T { &self.0.view }
    /// Pick one immutable policy for the request while its transport still
    /// belongs to the same listener. Never reattach an expired connection.
    pub fn request_view(&self, listener: Listener) -> Option<T> where T: Clone {
        let shared = self.2.upgrade()?;
        let state = shared.lock().unwrap_or_else(|e| e.into_inner());
        if !self.is_live() { return None; }
        if let Some(current) = state.listeners.get(&listener)
            .filter(|current| self.1.same_channel(&current.1))
        {
            return Some(current.0.view.clone());
        }
        let current = state.active.as_ref()?;
        self.1.same_channel(&current.authorization).then(|| current.view.clone())
    }

    pub fn version(&self) -> Version {
        self.1.borrow().lease.version()
    }

    fn is_live(&self) -> bool {
        self.1.borrow().is_live()
    }

    pub async fn run<'a, F, R>(
        &'a self,
        serve: impl FnOnce(&'a T) -> F,
    ) -> Option<R>
    where
        F: Future<Output = R>,
    {
        let mut notice = self.1.subscribe();
        if !self.is_live() {
            return None;
        }
        let mut io = std::pin::pin!(serve(&self.0.view));
        tokio::select! {
            biased;
            _ = notice.wait_for(|a| a.revoked) => None,
            result = poll_fn(|cx| {
                // If the machine just resumed, a ready socket can be
                // scheduled before the timer task. Check again before I/O.
                if !self.is_live() {
                    return Poll::Ready(None);
                }
                io.as_mut().poll(cx).map(|result| self.is_live().then_some(result))
            }) => result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed::{PullWindow, Receiver};
    use pingwaf_proto::{
        ManagedSite, ManagedSiteConfig, ManagedSnapshot, RuleBundle, Site,
        SiteCacheSettings,
    };
    use prost::Message;
    use sha2::{Digest, Sha256};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn received(
        receiver: &mut Receiver,
        session: Uuid,
        epoch: Uuid,
        generation: i64,
        seconds: u32,
    ) -> Received {
        receive_config(
            receiver,
            session,
            epoch,
            generation,
            seconds,
            ManagedSiteConfig::from_sites(Vec::new()).encode_to_vec(),
        )
    }

    fn receive_config(
        receiver: &mut Receiver,
        session: Uuid,
        epoch: Uuid,
        generation: i64,
        seconds: u32,
        config: Vec<u8>,
    ) -> Received {
        PullWindow::start(receiver)
            .unwrap()
            .receive(
                receiver,
                ManagedSnapshot {
                    session_id: session.to_string(),
                    authority_epoch: epoch.to_string(),
                    generation,
                    config_hash: hex::encode(Sha256::digest(&config)),
                    config,
                    lease_seconds: seconds,
                },
            )
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    async fn stale_compilation_and_ended_sessions_cannot_publish() {
        let state = AppliedState::default();
        let (session, epoch) = (Uuid::new_v4(), Uuid::new_v4());
        let mut receiver = Receiver::default();
        receiver.set_session(Some(session));
        state.start_session(session);
        let old = state
            .prepare(received(&mut receiver, session, epoch, 1, 10))
            .unwrap()
            .unwrap();
        let current = state
            .prepare(received(&mut receiver, session, epoch, 2, 10))
            .unwrap()
            .unwrap();
        assert!(state.forwarding().is_none());
        assert!(!state.publish(old, 1).unwrap());
        assert!(state.publish(current, 2).unwrap());
        state.end_session(Uuid::new_v4());
        let forwarding = state.forwarding().unwrap();
        assert_eq!(forwarding.version().generation, 2);
        assert_eq!(
            forwarding.run(|view| std::future::ready(*view)).await,
            Some(2)
        );
        let different = config(Uuid::new_v4(), "hash", 100);
        let in_progress = state
            .prepare(receive_config(
                &mut receiver,
                session,
                epoch,
                3,
                10,
                different,
            ))
            .unwrap()
            .unwrap();
        assert_eq!(forwarding.run(|_| std::future::ready(())).await, None);
        state.end_session(session);
        assert!(!state.publish(in_progress, 3).unwrap());
        assert!(state.forwarding().is_none());
    }

    #[tokio::test]
    async fn revocation_cancels_in_flight_work() {
        let state = AppliedState::default();
        let (session, epoch) = (Uuid::new_v4(), Uuid::new_v4());
        let mut receiver = Receiver::default();
        receiver.set_session(Some(session));
        state.start_session(session);
        let pending = state
            .prepare(received(&mut receiver, session, epoch, 1, 10))
            .unwrap()
            .unwrap();
        assert!(state.publish(pending, ()).unwrap());
        let forwarding = state.forwarding().unwrap();
        let (started, wait) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            forwarding
                .run(|_| async {
                    started.send(()).unwrap();
                    std::future::pending::<()>().await;
                })
                .await
        });
        wait.await.unwrap();
        state.end_session(session);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap(),
            None
        );
        assert!(state.forwarding().is_none());
    }

    #[tokio::test]
    async fn expiry_cancels_in_flight_work_without_a_new_snapshot() {
        let state = AppliedState::default();
        let (session, epoch) = (Uuid::new_v4(), Uuid::new_v4());
        let mut receiver = Receiver::default();
        receiver.set_session(Some(session));
        state.start_session(session);
        let pending = state
            .prepare(received(&mut receiver, session, epoch, 1, 1))
            .unwrap()
            .unwrap();
        assert!(state.publish(pending, ()).unwrap());
        let forwarding = state.forwarding().unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            forwarding.run(|_| std::future::pending::<()>()),
        )
        .await
        .unwrap();
        assert_eq!(result, None);
        assert!(state.forwarding().is_none());
    }

    #[tokio::test]
    async fn revocation_drops_both_ends_of_an_active_proxy_connection() {
        use tokio::net::{TcpListener, TcpStream};

        let state = AppliedState::default();
        let (session, epoch) = (Uuid::new_v4(), Uuid::new_v4());
        let mut receiver = Receiver::default();
        receiver.set_session(Some(session));
        state.start_session(session);

        let ingress = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pending = state
            .prepare(received(&mut receiver, session, epoch, 1, 10))
            .unwrap()
            .unwrap();
        assert!(state
            .publish(pending, origin.local_addr().unwrap())
            .unwrap());
        let forwarding = state.forwarding().unwrap();
        let mut client = TcpStream::connect(ingress.local_addr().unwrap())
            .await
            .unwrap();
        let (mut downstream, _) = ingress.accept().await.unwrap();
        let task = tokio::spawn(async move {
            forwarding
                .run(|origin_addr| async move {
                    let mut upstream =
                        TcpStream::connect(origin_addr).await.unwrap();
                    tokio::io::copy_bidirectional(
                        &mut downstream,
                        &mut upstream,
                    )
                    .await
                })
                .await
        });

        tokio::time::timeout(Duration::from_secs(2), async {
            let (mut upstream, _) = origin.accept().await.unwrap();
            client.write_all(b"x").await.unwrap();
            assert_eq!(upstream.read_u8().await.unwrap(), b'x');
            upstream.write_all(b"y").await.unwrap();
            assert_eq!(client.read_u8().await.unwrap(), b'y');
            state.end_session(session);
            assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
            assert_eq!(upstream.read(&mut [0]).await.unwrap(), 0);
            assert!(task.await.unwrap().is_none());
        })
        .await
        .unwrap();
    }

    fn config(id: Uuid, hash: &str, cap: u32) -> Vec<u8> {
        let id = id.to_string();
        ManagedSiteConfig::from_sites(vec![ManagedSite {
                site: Some(Site {
                    id: id.clone(),
                    domain: "example.com".into(),
                    rules: Some(RuleBundle {
                        site_id: id,
                        config_hash: hash.into(),
                        cache_settings: Some(SiteCacheSettings {
                            type_max_file_size_mb: [
                                ("html".into(), cap),
                                ("css".into(), 4),
                            ]
                            .into(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }])
        .encode_to_vec()
    }

    #[tokio::test]
    async fn pending_site_receipt_ends_with_its_session() {
        let state = AppliedState::<()>::default();
        let (session, epoch, id) =
            (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let mut receiver = Receiver::default();
        receiver.set_session(Some(session));
        state.start_session(session);
        let mut wire =
            ManagedSiteConfig::decode(config(id, "rules", 1).as_slice())
                .unwrap();
        wire.sites[0].ingress = Some(pingwaf_proto::SiteIngress {
            port: 81,
            protocol: pingwaf_proto::IngressProtocol::Http as i32,
        });
        wire.sites[0].site_revision = "ab".repeat(32);
        wire.listeners = Some(pingwaf_proto::PanelListeners::for_sites(&wire.sites));
        let next = receive_config(
            &mut receiver,
            session,
            epoch,
            1,
            10,
            wire.encode_to_vec(),
        );
        let pending = state.prepare(next).unwrap().unwrap();
        let report = state.application_report(&Default::default(), false).unwrap();
        assert!(report.sites.is_empty());
        assert_eq!(report.received_sites.len(), 1);
        assert_eq!(report.received_sites[0].site_id, id.to_string());
        state.end_session(session);
        assert!(state.application_report(&Default::default(), false).is_none());
        assert!(!state.publish(pending, ()).unwrap());
    }

    #[tokio::test]
    async fn changing_one_listener_keeps_only_equivalent_sockets_authorized() {
        let state = AppliedState::default();
        let (session, epoch) = (Uuid::new_v4(), Uuid::new_v4());
        let mut receiver = Receiver::default();
        receiver.set_session(Some(session));
        state.start_session(session);
        let listener = |port| Listener::Custom {
            port,
            protocol: pingwaf_proto::IngressProtocol::Http,
        };
        let mut wire = ManagedSiteConfig::default();
        for port in [81, 82] {
            let mut seed = ManagedSiteConfig::decode(
                config(Uuid::new_v4(), "rules", 1).as_slice(),
            )
            .unwrap();
            let mut site = seed.sites.remove(0);
            site.ingress = Some(pingwaf_proto::SiteIngress {
                port,
                protocol: pingwaf_proto::IngressProtocol::Http as i32,
            });
            site.site_revision = "ab".repeat(32);
            wire.sites.push(site);
        }
        wire.listeners = Some(pingwaf_proto::PanelListeners::for_sites(&wire.sites));
        let first = receive_config(
            &mut receiver,
            session,
            epoch,
            1,
            10,
            wire.encode_to_vec(),
        );
        let initial = state.prepare(first).unwrap().unwrap();
        assert!(state.publish(initial, 1).unwrap());
        let old_a = state.forwarding_for(listener(81)).unwrap();
        let old_b = state.forwarding_for(listener(82)).unwrap();
        wire.sites[0].site.as_mut().unwrap().rules.as_mut().unwrap().observation_mode = true;
        wire.sites[0].site_revision = "cd".repeat(32);
        let update = receive_config(&mut receiver, session, epoch, 2, 10, wire.encode_to_vec());
        let pending = state.prepare(update).unwrap().unwrap();
        assert_eq!(old_a.request_view(listener(81)), Some(1));
        assert!(state.publish(pending, 2).unwrap());
        assert_eq!(old_a.request_view(listener(81)), Some(2));
        assert!(old_b.is_live());

        wire.sites.remove(0);
        wire.listeners = Some(pingwaf_proto::PanelListeners::for_sites(&wire.sites));
        let second = receive_config(
            &mut receiver,
            session,
            epoch,
            3,
            10,
            wire.encode_to_vec(),
        );
        let pending = state.prepare(second).unwrap().unwrap();
        assert!(!old_a.is_live());
        assert_eq!(old_a.request_view(listener(81)), None);
        assert!(state.forwarding_for(listener(81)).is_none());
        assert!(old_b.is_live());
        assert!(state.forwarding_for(listener(82)).is_some());
        assert!(state.publish(pending, 2).unwrap());
        assert_eq!(old_b.run(|v| std::future::ready(*v)).await, Some(1));
        assert_eq!(
            state
                .forwarding_for(listener(82))
                .unwrap()
                .run(|v| std::future::ready(*v))
                .await,
            Some(2)
        );
        state.end_session(session);
        assert!(!old_b.is_live());
        assert!(state.forwarding_for(listener(82)).is_none());
    }

    #[tokio::test]
    async fn equivalent_config_renews_pinned_view_past_old_deadline() {
        let state = AppliedState::default();
        let (session, epoch, id) =
            (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let mut receiver = Receiver::default();
        receiver.set_session(Some(session));
        state.start_session(session);
        let old = receive_config(
            &mut receiver,
            session,
            epoch,
            1,
            1,
            config(id, "first-wire-hash", 2),
        );
        let old_version = old.candidate.version();
        let pending = state.prepare(old).unwrap().unwrap();
        assert!(state.publish(pending, 42).unwrap());
        let forwarding = state.forwarding().unwrap();
        let equivalent = receive_config(
            &mut receiver,
            session,
            epoch,
            2,
            10,
            config(id, "second-wire-hash", 2),
        );
        let equivalent_version = equivalent.candidate.version();
        assert_ne!(old_version.hash, equivalent_version.hash);
        assert!(state.prepare(equivalent).unwrap().is_none());
        assert_eq!(forwarding.version(), equivalent_version);
        assert_eq!(
            forwarding
                .run(|view| async move {
                    tokio::time::sleep(Duration::from_millis(1100)).await;
                    *view
                })
                .await,
            Some(42)
        );

        let changed = receive_config(
            &mut receiver,
            session,
            epoch,
            3,
            10,
            config(id, "second-wire-hash", 3),
        );
        assert!(state.prepare(changed).unwrap().is_some());
        assert!(state.forwarding().is_none());
        assert_eq!(forwarding.run(|_| std::future::ready(())).await, None);
    }

    #[tokio::test]
    async fn equivalent_config_after_expiry_requires_a_new_view() {
        let state = AppliedState::default();
        let (session, epoch) = (Uuid::new_v4(), Uuid::new_v4());
        let mut receiver = Receiver::default();
        receiver.set_session(Some(session));
        state.start_session(session);
        let first = state
            .prepare(received(&mut receiver, session, epoch, 1, 1))
            .unwrap()
            .unwrap();
        assert!(state.publish(first, 1).unwrap());
        let expired = state.forwarding().unwrap();
        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(3),
                expired.run(|_| std::future::pending::<()>())
            )
            .await
            .unwrap(),
            None
        );
        let fresh = state
            .prepare(received(&mut receiver, session, epoch, 2, 10))
            .unwrap()
            .unwrap();
        assert!(state.publish(fresh, 2).unwrap());
        assert_eq!(expired.run(|_| std::future::ready(())).await, None);
        assert_eq!(state.forwarding().unwrap().version().generation, 2);
    }
}
