use anyhow::{ensure, Context};
use pingwaf_proto::{ManagedSnapshot, MAX_MANAGED_LEASE_SECONDS};
use rustix::time::{
    clock_gettime, timerfd_create, timerfd_settime, ClockId, Itimerspec,
    TimerfdClockId, TimerfdFlags, TimerfdTimerFlags, Timespec,
};
use tokio::io::unix::AsyncFd;
use uuid::Uuid;

use super::{Candidate, Receiver, Version};

/// One in-flight pull. Construct before sending its authenticated request;
/// consuming it with the RPC result prevents restarting its clock on receipt.
pub struct PullWindow {
    session: Uuid,
    started: Timespec,
}

pub struct Received {
    pub candidate: Candidate,
    pub lease: Lease,
}

/// In-memory permission for exactly one version. The caller must still check
/// listener/UUID membership in the applied view and cancel on revocation.
pub struct Lease {
    version: Version,
    deadline: Timespec,
}

fn now() -> Timespec {
    clock_gettime(ClockId::Boottime)
}

impl PullWindow {
    pub fn start(receiver: &Receiver) -> anyhow::Result<Self> {
        Ok(Self {
            session: receiver.session.context("no managed session")?,
            started: now(),
        })
    }

    pub fn receive(
        self,
        receiver: &mut Receiver,
        snapshot: ManagedSnapshot,
    ) -> anyhow::Result<Option<Received>> {
        self.receive_at(receiver, snapshot, now())
    }

    fn receive_at(
        self,
        receiver: &mut Receiver,
        snapshot: ManagedSnapshot,
        received_at: Timespec,
    ) -> anyhow::Result<Option<Received>> {
        ensure!(
            receiver.session == Some(self.session),
            "managed pull session changed"
        );
        let seconds = snapshot.lease_seconds;
        ensure!(
            (1..=MAX_MANAGED_LEASE_SECONDS).contains(&seconds),
            "invalid managed lease duration"
        );
        let deadline = self
            .started
            .checked_add(Timespec {
                tv_sec: i64::from(seconds),
                tv_nsec: 0,
            })
            .context("managed deadline overflow")?;
        ensure!(
            received_at >= self.started,
            "managed pull preceded its request"
        );
        // A delayed response can still withdraw a site. Hand it to the
        // caller with an already-expired lease rather than losing that info.
        Ok(receiver.receive(snapshot)?.map(|candidate| Received {
            lease: Lease {
                version: candidate.version(),
                deadline,
            },
            candidate,
        }))
    }
}

impl Lease {
    pub fn permits(&self, applied: Version) -> bool {
        self.permits_at(applied, now())
    }

    fn permits_at(&self, applied: Version, at: Timespec) -> bool {
        self.version == applied && at < self.deadline
    }

    /// Completes on expiry, including if the kernel crossed the deadline
    /// while suspended. A timer error must also stop forwarding.
    pub async fn wait_for_expiry(&self) -> anyhow::Result<()> {
        self.expiry_timer()?.wait().await
    }

    pub(super) fn expiry_timer(&self) -> anyhow::Result<ExpiryTimer> {
        let fd = timerfd_create(
            TimerfdClockId::Boottime,
            TimerfdFlags::NONBLOCK | TimerfdFlags::CLOEXEC,
        )?;
        timerfd_settime(
            &fd,
            TimerfdTimerFlags::ABSTIME,
            &Itimerspec {
                it_interval: Timespec::default(),
                it_value: self.deadline,
            },
        )?;
        // SAFETY: OwnedFd keeps this nonblocking timer descriptor open and
        // unchanged until AsyncFd deregisters and drops it.
        let timer = unsafe {
            AsyncFd::register_with_interest(fd, tokio::io::Interest::READABLE)
        }?;
        Ok(ExpiryTimer(timer))
    }
}

pub(super) struct ExpiryTimer(AsyncFd<rustix::fd::OwnedFd>);

impl ExpiryTimer {
    pub(super) async fn wait(&self) -> anyhow::Result<()> {
        let mut fired = [0; 8];
        self.0
            .async_io(tokio::io::Interest::READABLE, |fd| {
                rustix::io::read(fd, &mut fired).map_err(Into::into)
            })
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn empty(
        session: Uuid,
        authority: Uuid,
        generation: i64,
        lease_seconds: u32,
    ) -> ManagedSnapshot {
        ManagedSnapshot {
            session_id: session.to_string(),
            authority_epoch: authority.to_string(),
            generation,
            lease_seconds,
            config: Vec::new(),
            config_hash: hex::encode(Sha256::digest([])),
        }
    }

    fn at(tv_sec: i64) -> Timespec {
        Timespec { tv_sec, tv_nsec: 0 }
    }

    #[test]
    fn delayed_replayed_or_wrong_session_pulls_cannot_extend_permission() {
        let session = Uuid::new_v4();
        let authority = Uuid::new_v4();
        let mut receiver = Receiver::default();
        assert!(PullWindow::start(&receiver).is_err());
        receiver.set_session(Some(session));
        let pull = |tv_sec| PullWindow {
            session,
            started: at(tv_sec),
        };
        for seconds in [0, MAX_MANAGED_LEASE_SECONDS + 1] {
            assert!(pull(100)
                .receive_at(
                    &mut receiver,
                    empty(session, authority, 1, seconds),
                    at(101)
                )
                .is_err());
        }
        let snapshot = empty(session, authority, 1, 10);
        let received = pull(100)
            .receive_at(&mut receiver, snapshot.clone(), at(109))
            .unwrap()
            .unwrap();
        let version = received.candidate.version();
        assert!(received.lease.permits_at(version, at(109)));
        assert!(!received.lease.permits_at(version, at(110)));
        assert!(!received.lease.permits_at(
            Version {
                generation: 2,
                ..version
            },
            at(109)
        ));
        assert!(pull(108)
            .receive_at(&mut receiver, snapshot, at(109))
            .unwrap()
            .is_none());
        let delayed = pull(90)
            .receive_at(
                &mut receiver,
                empty(session, authority, 2, 10),
                at(100),
            )
            .unwrap()
            .unwrap();
        assert!(delayed.candidate.sites().is_empty());
        assert!(!delayed
            .lease
            .permits_at(delayed.candidate.version(), at(100)));
        let next = Uuid::new_v4();
        receiver.set_session(Some(next));
        assert!(pull(110)
            .receive_at(&mut receiver, empty(next, authority, 3, 10), at(111))
            .is_err());
        assert!(!received.lease.permits_at(
            Version {
                session: next,
                ..version
            },
            at(109)
        ));
    }

    #[tokio::test]
    async fn os_timer_uses_the_forwarding_deadline() {
        let session = Uuid::new_v4();
        let mut receiver = Receiver::default();
        receiver.set_session(Some(session));
        let window = PullWindow::start(&receiver).unwrap();
        let mut received = window
            .receive(&mut receiver, empty(session, Uuid::new_v4(), 1, 10))
            .unwrap()
            .unwrap();
        let version = received.candidate.version();
        assert!(received.lease.permits(version));
        received.lease.deadline = now()
            .checked_add(Timespec {
                tv_sec: 0,
                tv_nsec: 20_000_000,
            })
            .unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            received.lease.wait_for_expiry(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(!received.lease.permits(version));
        received.lease.wait_for_expiry().await.unwrap();
    }
}
