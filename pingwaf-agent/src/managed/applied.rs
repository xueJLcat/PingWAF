use std::future::{poll_fn, Future};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::Poll;

use tokio::sync::watch;
use uuid::Uuid;

use super::{Candidate, Lease, Received, Version};

/// A full, immutable proxy view is published as a unit. A caller must not use
/// this store to publish a reference to providers that can be reloaded in place.
pub struct AppliedState<T>(Mutex<State<T>>);

struct State<T> {
    session: Option<Uuid>,
    latest: Option<Version>,
    active: Option<Arc<Applied<T>>>,
}

struct Applied<T> {
    policy: Candidate,
    view: T,
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
pub struct Forwarding<T>(Arc<Applied<T>>);

impl<T> Default for AppliedState<T> {
    fn default() -> Self {
        Self(Mutex::new(State {
            session: None,
            latest: None,
            active: None,
        }))
    }
}

impl<T> State<T> {
    fn revoke(&mut self) {
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
        let mut pending = Some(Pending { received });
        let renewable = state.active.as_ref().filter(|active| {
            pending.as_ref().is_some_and(|candidate| {
                candidate.received.lease.permits(version)
                    && active.authorization.borrow().is_live()
                    && active.policy.same_policy(candidate.candidate())
            })
        });
        if let Some(active) = renewable {
            match active.renew(&mut pending) {
                Ok(true) => return Ok(None),
                Ok(false) => {},
                Err(error) => {
                    state.revoke();
                    return Err(error);
                },
            }
        }
        state.revoke();
        Ok(pending.filter(|p| p.received.lease.permits(version)))
    }

    /// A timer must be armed before publishing; a timer error is fail-closed.
    /// Call on the data-plane runtime, not from a blocking compiler thread.
    pub fn publish(&self, pending: Pending, view: T) -> anyhow::Result<bool> {
        let version = pending.candidate().version();
        let lease = pending.received.lease;
        let mut state = self.lock();
        if state.session != Some(version.session)
            || state.latest != Some(version)
            || !lease.permits(version)
        {
            return Ok(false);
        }
        let timer = lease.expiry_timer()?;
        let (authorization, _) = watch::channel(Authorization {
            lease,
            revoked: false,
        });
        watch_expiry(authorization.clone(), version, timer);
        state.active = Some(Arc::new(Applied {
            policy: pending.received.candidate,
            view,
            authorization,
        }));
        Ok(true)
    }

    pub fn forwarding(&self) -> Option<Forwarding<T>> {
        let state = self.lock();
        let active = state.active.as_ref()?;
        let forwarding = Forwarding(active.clone());
        forwarding.is_live().then_some(forwarding)
    }
}

impl<T> Applied<T> {
    fn renew(&self, pending: &mut Option<Pending>) -> anyhow::Result<bool> {
        let Some(candidate) = pending.as_ref() else {
            return Ok(false);
        };
        let version = candidate.candidate().version();
        // Start the timer first; never resurrect a connection when either
        // lease expired while comparison or timer setup was in progress.
        let timer = candidate.received.lease.expiry_timer()?;
        let auth = &self.authorization;
        let renewed = auth.send_if_modified(|current| {
            if !current.is_live()
                || !pending
                    .as_ref()
                    .is_some_and(|p| p.received.lease.permits(version))
            {
                return false;
            }
            let Some(pending) = pending.take() else {
                return false;
            };
            current.lease = pending.received.lease;
            true
        });
        if renewed {
            watch_expiry(auth.clone(), version, timer);
        }
        Ok(renewed)
    }
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
    pub fn version(&self) -> Version {
        self.0.authorization.borrow().lease.version()
    }

    fn is_live(&self) -> bool {
        self.0.authorization.borrow().is_live()
    }

    pub async fn run<'a, F, R>(
        &'a self,
        serve: impl FnOnce(&'a T) -> F,
    ) -> Option<R>
    where
        F: Future<Output = R>,
    {
        let mut notice = self.0.authorization.subscribe();
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
            Vec::new(),
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
        ManagedSiteConfig {
            sites: vec![ManagedSite {
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
            }],
        }
        .encode_to_vec()
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
