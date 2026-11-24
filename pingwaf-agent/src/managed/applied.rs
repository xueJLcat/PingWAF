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
    version: Version,
    lease: Lease,
    view: T,
    revoked: watch::Sender<bool>,
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
            active.revoked.send_replace(true);
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

    /// Withdraw the old view before attempting to build a replacement. Even
    /// a newer candidate received too late to serve can withdraw traffic.
    pub fn prepare(&self, received: Received) -> Option<Pending> {
        let version = received.candidate.version();
        let mut state = self.lock();
        if state.session != Some(version.session)
            || state.latest.is_some_and(|latest| {
                version.authority != latest.authority
                    || version.generation <= latest.generation
            })
        {
            return None;
        }
        state.revoke();
        state.latest = Some(version);
        received
            .lease
            .permits(version)
            .then_some(Pending { received })
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
        let (revoked, mut notice) = watch::channel(false);
        let expiry_signal = revoked.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = notice.wait_for(|revoked| *revoked) => {},
                _ = timer.wait() => { expiry_signal.send_replace(true); },
            }
        });
        state.active = Some(Arc::new(Applied {
            version,
            lease,
            view,
            revoked,
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

impl<T> Drop for AppliedState<T> {
    fn drop(&mut self) {
        self.lock().revoke();
    }
}

impl<T> Forwarding<T> {
    pub fn version(&self) -> Version {
        self.0.version
    }

    fn is_live(&self) -> bool {
        self.0.lease.permits(self.0.version) && !*self.0.revoked.borrow()
    }

    pub async fn run<'a, F, R>(
        &'a self,
        serve: impl FnOnce(&'a T) -> F,
    ) -> Option<R>
    where
        F: Future<Output = R>,
    {
        let mut notice = self.0.revoked.subscribe();
        if !self.is_live() {
            return None;
        }
        let mut io = std::pin::pin!(serve(&self.0.view));
        tokio::select! {
            biased;
            _ = notice.wait_for(|revoked| *revoked) => None,
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
    use pingwaf_proto::ManagedSnapshot;
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
        PullWindow::start(receiver)
            .unwrap()
            .receive(
                receiver,
                ManagedSnapshot {
                    session_id: session.to_string(),
                    authority_epoch: epoch.to_string(),
                    generation,
                    config_hash: hex::encode(Sha256::digest([])),
                    config: Vec::new(),
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
            .unwrap();
        let current = state
            .prepare(received(&mut receiver, session, epoch, 2, 10))
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
        let in_progress = state
            .prepare(received(&mut receiver, session, epoch, 3, 10))
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
}
