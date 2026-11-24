use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tokio::sync::{Mutex, Notify};
use tonic::{transport::Channel, Code};
use tracing::warn;
use uuid::Uuid;

use crate::managed::{parse_uuid, PullWindow, Received, Receiver};

use super::{proto, ProtoClient};

const PULL_INTERVAL: Duration = Duration::from_secs(15);
const MIN_PULL_SPACING: Duration = Duration::from_secs(1);
const PULL_TIMEOUT: Duration = Duration::from_secs(8);

/// Host callbacks are serialized by the session driver. A host must revoke
/// the old assignment before attempting to build any replacement and must
/// honor the candidate's lease only for the exact applied version.
pub trait ManagedHost: Send + Sync {
    fn application_report(&self) -> Option<proto::ManagedApplyReport> {
        None
    }
    fn session_started(&self, session: Uuid);
    fn candidate_received(&self, candidate: Received);
    fn session_ended(&self, session: Uuid);
}

pub(super) struct Transport {
    pub(super) host: Arc<dyn ManagedHost>,
    // Keep the received generation across connections, not across process
    // restarts. Only this loop writes it; the lock never spans an RPC.
    receiver: Mutex<Receiver>,
}

pub(super) struct Session<'a> {
    transport: &'a Transport,
    id: Uuid,
    receiver: tokio::sync::MutexGuard<'a, Receiver>,
}

impl Transport {
    pub(super) fn new(host: Arc<dyn ManagedHost>) -> Self {
        Self {
            host,
            receiver: Mutex::new(Receiver::default()),
        }
    }

    pub(super) async fn open(&self, id: &str) -> anyhow::Result<Session<'_>> {
        let id = parse_uuid(id)?;
        let mut receiver = self.receiver.lock().await;
        receiver.set_session(Some(id));
        self.host.session_started(id);
        Ok(Session {
            transport: self,
            id,
            receiver,
        })
    }
}

impl Drop for Session<'_> {
    fn drop(&mut self) {
        self.receiver.set_session(None);
        self.transport.host.session_ended(self.id);
    }
}

impl Session<'_> {
    pub(super) async fn pull(
        &mut self,
        channel: Channel,
        token: &str,
        hint: &Notify,
    ) -> anyhow::Result<()> {
        let mut client = ProtoClient::new(channel);
        loop {
            match self.pull_once(&mut client, token).await {
                Ok(()) => {},
                Err(error) => {
                    // RPCs rejected for transient database or transport errors
                    // cannot renew the old lease. End on explicit revocation
                    // or malformed state so the host cancels immediately.
                    let transient = error
                        .downcast_ref::<tonic::Status>()
                        .is_some_and(|status| {
                            matches!(
                                status.code(),
                                Code::Aborted
                                    | Code::DeadlineExceeded
                                    | Code::Unavailable
                                    | Code::Internal
                                    | Code::ResourceExhausted
                            )
                        });
                    if !transient {
                        return Err(error);
                    }
                    warn!(code = ?error.downcast_ref::<tonic::Status>().map(tonic::Status::code), "managed configuration pull failed");
                },
            }
            // Bound request rate under floods of hints, and always poll in
            // case a different server replica performed the mutation.
            let poll_at = tokio::time::Instant::now() + PULL_INTERVAL;
            tokio::time::sleep(MIN_PULL_SPACING).await;
            tokio::select! {
                _ = hint.notified() => {},
                _ = tokio::time::sleep_until(poll_at) => {},
            }
        }
    }

    async fn pull_once(
        &mut self,
        client: &mut ProtoClient<Channel>,
        token: &str,
    ) -> anyhow::Result<()> {
        let window = PullWindow::start(&self.receiver)?;
        let response = tokio::time::timeout(
            PULL_TIMEOUT,
            client.get_managed_snapshot(proto::GetManagedSnapshotRequest {
                agent_token: token.to_string(),
            }),
        )
        .await
        .map_err(|_| {
            tonic::Status::deadline_exceeded("managed pull timed out")
        })??;
        let candidate = window
            .receive(&mut self.receiver, response.into_inner())
            .context("control plane returned an invalid managed snapshot")?;
        if let Some(candidate) = candidate {
            self.transport.host.candidate_received(candidate);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    #[derive(Default)]
    struct Host(StdMutex<Vec<(Uuid, bool)>>);

    impl ManagedHost for Host {
        fn session_started(&self, session: Uuid) {
            self.0.lock().unwrap().push((session, true));
        }

        fn candidate_received(&self, _candidate: Received) {}

        fn session_ended(&self, session: Uuid) {
            self.0.lock().unwrap().push((session, false));
        }
    }

    #[tokio::test]
    async fn cancelling_the_driver_ends_the_session() {
        let host = Arc::new(Host::default());
        let transport = Arc::new(Transport::new(host.clone()));
        let session = Uuid::new_v4();
        let (started, wait) = tokio::sync::oneshot::channel();
        let task = tokio::spawn({
            let transport = transport.clone();
            async move {
                let _session =
                    transport.open(&session.to_string()).await.unwrap();
                started.send(()).unwrap();
                std::future::pending::<()>().await;
            }
        });
        wait.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(
            *host.0.lock().unwrap(),
            [(session, true), (session, false)]
        );
        assert!(PullWindow::start(&*transport.receiver.lock().await).is_err());
    }
}
