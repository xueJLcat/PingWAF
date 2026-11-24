//! In-memory registry of agents that currently hold an open `Heartbeat` stream.
//!
//! The control plane pushes commands to agents over the bidirectional heartbeat
//! stream, so the REST API needs a way to reach a live stream from a handler
//! that knows nothing about gRPC. [`AgentRegistry`] is that bridge: the gRPC
//! service registers a sender when a stream opens, and API handlers call
//! [`AgentRegistry::send_command`].
//!
//! Agents that are not connected get their commands queued (bounded) and
//! drained on the next heartbeat, so a rule change issued from the dashboard is
//! never silently lost as long as the agent reconnects.
//!
//! The registry also holds the counters of each connected agent's last
//! heartbeat ([`HeartbeatMetrics`]). The heartbeat is otherwise consumed and
//! dropped, and `requests_per_second` in particular is stored nowhere else, so
//! this is the only source of a live RPS figure for `/api/v1/system/nodes`.
//!
//! Finally it remembers the hash of the configuration last issued to each
//! agent ([`ConfigSync`]). A push is fire-and-forget — the stream it entered
//! may already be dead — so the hash every heartbeat reports is checked
//! against it, and an agent that stays on something else is pushed again.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use pingwaf_proto::control_plane::{
    server_command::Payload, CommandType, IngressBindState, IngressListeners,
    IngressProtocol, ManagedConfigChangedCommand, ServerCommand,
};
use pingwaf_proto::MAX_INGRESS_LISTENERS;
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;

/// Buffer depth of the per-agent command channel.
pub const COMMAND_CHANNEL_CAPACITY: usize = 64;
/// Maximum number of commands retained for an agent that is currently offline.
pub const PENDING_COMMAND_LIMIT: usize = 64;
/// Consecutive heartbeats that must report a stale hash before the
/// configuration is pushed again. The heartbeat that was already on the wire
/// when a push went out legitimately carries the old one.
pub const CONFIG_DRIFT_GRACE: u32 = 2;
/// Wait after the first re-push before the next; doubles per re-push that
/// did not converge, up to [`CONFIG_REPUSH_COOLDOWN_MAX`]. An agent that
/// cannot apply the configuration at all is then pushed a full bundle every
/// ten minutes, not every heartbeat.
pub const CONFIG_REPUSH_COOLDOWN: Duration = Duration::from_secs(60);
pub const CONFIG_REPUSH_COOLDOWN_MAX: Duration = Duration::from_secs(600);

struct Connection {
    sender: mpsc::Sender<ServerCommand>,
    session: Option<Uuid>,
    connected_at: DateTime<Utc>,
    /// Monotonic per-registry stream id. Teardown only removes the entry
    /// when this id still matches, so a stale stream finishing after the
    /// agent reconnected cannot delete the live connection (2026-10-18
    /// audit: the old stream used to mark the new one offline).
    generation: u64,
    /// Only observations from this stream are retained. Not an authorization
    /// or an acknowledgement of applied site configuration.
    ingress: Option<(Instant, IngressListeners)>,
    application: Option<(Instant, ApplicationObservation)>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ApplicationObservation {
    pub observed_at: DateTime<Utc>,
    pub authority_epoch: Uuid,
    pub generation: i64,
    pub sites: Vec<SiteApplication>,
    pub received_sites: Vec<SiteApplication>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct SiteApplication {
    pub site_id: Uuid,
    pub site_revision: String,
    pub port: u16,
    pub protocol: &'static str,
}

#[derive(Default)]
struct Inner {
    connected: HashMap<Uuid, Connection>,
    pending: HashMap<Uuid, VecDeque<ServerCommand>>,
    /// Counters of the last heartbeat on the live stream, one entry per agent.
    metrics: HashMap<Uuid, HeartbeatMetrics>,
    /// Why the data plane of an agent is not running the configuration it
    /// received, as of its last heartbeat. Absent when it applied in full.
    apply_errors: HashMap<Uuid, String>,
    /// What each agent should be running, and how far it has drifted.
    config: HashMap<Uuid, ConfigSync>,
    /// Log entries each agent has discarded since its process started, as
    /// of its last heartbeat. Kept across reconnects: the count belongs to
    /// the agent process, not to the stream.
    log_drops: HashMap<Uuid, u64>,
    next_generation: u64,
}

/// Reconciliation state of one agent's configuration.
#[derive(Default)]
struct ConfigSync {
    /// Hash of the configuration last issued to the agent, at registration or
    /// by an `UpdateSite` command. `None` until this process issued one.
    target: Option<String>,
    /// Consecutive heartbeats that reported a different hash.
    mismatches: u32,
    /// Re-pushes since the agent was last in sync.
    repushes: u32,
    last_repush: Option<Instant>,
}

/// What a heartbeat's `config_hash` says about the agent's configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigDrift {
    /// The agent runs the configuration last issued to it.
    InSync,
    /// It reports something else, but a push may still be on its way or the
    /// last re-push is too recent to repeat.
    Settling,
    /// It stayed on something else: push the configuration again. `expected`
    /// is the hash it should have reported, `None` when this process never
    /// issued one.
    Repush { expected: Option<String> },
}

/// Hash of the configuration an `UpdateSite` command carries.
fn update_site_hash(command: &ServerCommand) -> Option<&str> {
    match &command.payload {
        Some(Payload::UpdateSite(update)) => update
            .site_config
            .as_ref()
            .map(|config| config.config_hash.as_str()),
        _ => None,
    }
}

fn is_config_command(command: &ServerCommand) -> bool {
    matches!(
        command.payload,
        Some(
            Payload::RuleUpdate(_)
                | Payload::ConfigReload(_)
                | Payload::UpdateSite(_)
        )
    )
}

fn config_changed(command: ServerCommand) -> ServerCommand {
    ServerCommand {
        r#type: CommandType::CommandManagedConfigChanged as i32,
        payload: Some(Payload::ManagedConfigChanged(
            ManagedConfigChangedCommand {},
        )),
        ..command
    }
}

fn repush_cooldown(repushes: u32) -> Duration {
    let doublings = repushes.saturating_sub(1).min(16);
    CONFIG_REPUSH_COOLDOWN
        .saturating_mul(1 << doublings)
        .min(CONFIG_REPUSH_COOLDOWN_MAX)
}

fn validated_ingress(report: &IngressListeners) -> Option<IngressListeners> {
    if report.listeners.len() > MAX_INGRESS_LISTENERS || report.static_directories.len() > 16
        || report.static_directories.iter().any(|(id, digest)| {
            id.is_empty() || id.len() > 64 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            || !(digest.is_empty() || digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()))
        }) {
        return None;
    }
    let mut report = report.clone();
    report
        .listeners
        .sort_unstable_by_key(|listener| listener.port);
    let valid = report.listeners.iter().all(|listener| {
        (1..=u32::from(u16::MAX)).contains(&listener.port)
            && matches!(
                listener.protocol(),
                IngressProtocol::Http | IngressProtocol::Https
            )
            && listener.state() != IngressBindState::Unspecified
    }) && report
        .listeners
        .windows(2)
        .all(|pair| pair[0].port != pair[1].port);
    valid.then_some(report)
}

/// Cheap-to-clone handle to the live agent connections.
#[derive(Clone)]
pub struct AgentRegistry {
    pub(crate) admin_port: u16,
    inner: Arc<RwLock<Inner>>,
}

/// Counters the agent reported in its most recent heartbeat.
///
/// The heartbeat itself is kept nowhere: the control plane folds CPU and memory
/// into `host_samples`, the connection gauge into `agent_metrics`, and drops the
/// rest — which is why the node view could not answer RPS at all and had to
/// reconstruct the other figures from stored samples. Retaining the last report
/// of each connected agent gives `/api/v1/system/nodes` fresh values (at most
/// one heartbeat interval old) and the one figure nothing else carries.
///
/// A zero is what the agent reported, not "unknown": the wire fields are plain
/// integers, so the two cannot be told apart here. A node with no entry has not
/// heartbeated since it connected and is reported as unknown by the API.
///
/// The one exception is `process_rss_bytes`: it is the first tri-state counter,
/// an `Option` on the wire. `None` means the agent never reported it (an agent
/// older than the field), which is distinct from `Some(0)`. The other counters
/// keep the zero-sentinel convention for wire compatibility.
#[derive(Debug, Clone, Copy, Default)]
pub struct HeartbeatMetrics {
    /// CPU usage over the agent's last heartbeat interval, in percent.
    pub cpu_percent: f64,
    /// Memory in use on the node, in bytes.
    pub memory_bytes: u64,
    /// Connections the edge is handling.
    pub connections: u64,
    /// Requests per second the edge served over the last interval.
    pub rps: u64,
    /// RSS of the agent process itself, in bytes. The first tri-state counter:
    /// `None` = the agent never reported it (pre-field build), not zero.
    pub process_rss_bytes: Option<u64>,
}

/// Snapshot of one live connection, used by the `/api/v1/agents` endpoints.
#[derive(Debug, Clone)]
pub struct ConnectedAgent {
    pub id: Uuid,
    pub connected_at: DateTime<Utc>,
    pub queued_commands: usize,
}

impl Default for AgentRegistry {
    fn default() -> Self {
        Self::with_admin_port(9080)
    }
}

impl AgentRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn with_admin_port(admin_port: u16) -> Self {
        Self {
            admin_port,
            inner: Default::default(),
        }
    }

    /// Attaches a freshly opened heartbeat stream and returns everything that
    /// was queued while the agent was away.
    pub(super) async fn connect_session(
        &self,
        agent_id: Uuid,
        sender: mpsc::Sender<ServerCommand>,
        session: Option<Uuid>,
    ) -> (u64, VecDeque<ServerCommand>) {
        let mut inner = self.inner.write().await;
        inner.next_generation = inner.next_generation.wrapping_add(1);
        let generation = inner.next_generation;
        inner.connected.insert(
            agent_id,
            Connection {
                sender,
                session,
                connected_at: Utc::now(),
                generation,
                ingress: None,
                application: None,
            },
        );
        // Counters belong to the stream that reported them: a reconnect starts
        // empty and is filled by the opening heartbeat, which already carries
        // them.
        inner.metrics.remove(&agent_id);
        inner.apply_errors.remove(&agent_id);
        let mut drained = inner.pending.remove(&agent_id).unwrap_or_default();
        if session.is_some() {
            // The initial pull is authoritative; queued config is obsolete.
            drained.retain(|command| !is_config_command(command));
            inner.config.remove(&agent_id);
        }
        if !drained.is_empty() {
            tracing::info!(
                %agent_id,
                queued = drained.len(),
                "delivering commands queued while the agent was offline"
            );
        }
        (generation, drained)
    }

    #[cfg(test)]
    async fn connect(
        &self,
        agent_id: Uuid,
        sender: mpsc::Sender<ServerCommand>,
    ) -> (u64, VecDeque<ServerCommand>) {
        self.connect_session(agent_id, sender, None).await
    }

    pub(super) async fn is_current_stream(
        &self,
        agent_id: Uuid,
        generation: u64,
    ) -> bool {
        self.inner
            .read()
            .await
            .connected
            .get(&agent_id)
            .is_some_and(|c| c.generation == generation)
    }

    /// `None` means this replica has no managed stream for the node. A full
    /// or closed queue returns `Some(false)` rather than queueing old config.
    pub(super) async fn hint_managed_config(
        &self,
        agent_id: &Uuid,
    ) -> Option<bool> {
        let inner = self.inner.read().await;
        let connection = inner
            .connected
            .get(agent_id)
            .filter(|c| c.session.is_some())?;
        let hint = config_changed(ServerCommand {
            command_id: Uuid::new_v4().to_string(),
            issued_at: super::config::now_timestamp(),
            ..Default::default()
        });
        Some(connection.sender.try_send(hint).is_ok())
    }

    /// Drops the connection when a heartbeat stream ends. Only the stream
    /// that owns the current generation may remove it (see [`Connection`]).
    pub async fn disconnect(&self, agent_id: &Uuid, generation: u64) {
        let mut inner = self.inner.write().await;
        let current = inner
            .connected
            .get(agent_id)
            .map(|connection| connection.generation);
        match current {
            Some(current) if current == generation => {
                inner.connected.remove(agent_id);
                inner.metrics.remove(agent_id);
                inner.apply_errors.remove(agent_id);
                tracing::debug!(%agent_id, "agent heartbeat stream closed");
            },
            Some(_) => {
                tracing::debug!(
                    %agent_id,
                    "stale heartbeat stream closed; keeping the live connection"
                );
            },
            None => {},
        }
    }

    /// Unconditionally drops the connection (REST-triggered disconnect, where
    /// the caller has no stream generation). The stream's own teardown then
    /// sees no matching entry and does nothing.
    pub async fn force_disconnect(&self, agent_id: &Uuid) {
        let mut inner = self.inner.write().await;
        if inner.connected.remove(agent_id).is_some() {
            tracing::debug!(%agent_id, "agent connection closed by request");
        }
        // The counters are as stale as the connection they came from: a node
        // the operator just disconnected must not keep reporting its last
        // heartbeat.
        inner.metrics.remove(agent_id);
        inner.apply_errors.remove(agent_id);
    }

    /// Forgets queued commands for agents that no longer exist. Called by
    /// the offline-agent sweep so `pending` cannot outlive the rows it
    /// belongs to.
    pub async fn forget(&self, agent_ids: &[Uuid]) {
        if agent_ids.is_empty() {
            return;
        }
        let mut inner = self.inner.write().await;
        let mut dropped = 0usize;
        for agent_id in agent_ids {
            if inner.pending.remove(agent_id).is_some() {
                dropped += 1;
            }
            inner.metrics.remove(agent_id);
            inner.apply_errors.remove(agent_id);
            inner.config.remove(agent_id);
            inner.log_drops.remove(agent_id);
        }
        if dropped > 0 {
            tracing::info!(
                agents = dropped,
                "dropped queued commands for pruned agents"
            );
        }
    }

    /// Retains the counters of one heartbeat. Called for every message on the
    /// stream, including the opening one, so a reconnecting agent is current
    /// before its second heartbeat.
    pub async fn record_heartbeat(
        &self,
        agent_id: Uuid,
        metrics: HeartbeatMetrics,
    ) {
        self.inner.write().await.metrics.insert(agent_id, metrics);
    }

    /// Last reported counters, one entry per agent that heartbeated on its
    /// current stream. A clone per poll of `/api/v1/system/nodes`: the fleet is
    /// small and the map is flat.
    pub async fn metrics(&self) -> HashMap<Uuid, HeartbeatMetrics> {
        self.inner.read().await.metrics.clone()
    }

    pub(crate) async fn record_ingress(
        &self,
        agent_id: Uuid,
        generation: u64,
        report: Option<&IngressListeners>,
    ) {
        let report = report.and_then(validated_ingress);
        let mut inner = self.inner.write().await;
        let Some(connection) = inner.connected.get_mut(&agent_id) else {
            return;
        };
        if connection.generation != generation {
            return;
        }
        if connection.ingress.as_ref().map(|(_, report)| report)
            != report.as_ref()
        {
            tracing::info!(%agent_id, ?report, "agent TCP ingress inventory changed");
        }
        connection.ingress = report.map(|report| (Instant::now(), report));
    }

    pub(crate) async fn record_application(
        &self,
        agent: Uuid,
        stream: u64,
        session: Option<Uuid>,
        visible: &[Uuid],
        report: Option<&pingwaf_proto::ManagedApplyReport>,
    ) {
        let mut inner = self.inner.write().await;
        let Some(conn) = inner
            .connected
            .get_mut(&agent)
            .filter(|c| c.generation == stream)
        else {
            return;
        };
        conn.application = (|| {
            let report = report?;
            if conn.session.is_none()
                || conn.session != session
                || Uuid::parse_str(&report.session_id).ok()? != session?
                || report.generation <= 0
                || report
                    .sites
                    .len()
                    .saturating_add(report.received_sites.len())
                    > visible.len()
            {
                return None;
            }
            let authority_epoch = Uuid::parse_str(&report.authority_epoch)
                .ok()
                .filter(|id| !id.is_nil())?;
            let bound = &conn.ingress.as_ref()?.1.listeners;
            let permitted: std::collections::HashSet<_> =
                visible.iter().copied().collect();
            let mut seen = std::collections::HashSet::new();
            let mut sites = Vec::with_capacity(report.sites.len());
            let mut received_sites =
                Vec::with_capacity(report.received_sites.len());
            for (receiving, row) in report
                .sites
                .iter()
                .map(|r| (false, r))
                .chain(report.received_sites.iter().map(|r| (true, r)))
            {
                let site_id = Uuid::parse_str(&row.site_id).ok()?;
                let ingress = row.ingress.as_ref()?;
                if !permitted.contains(&site_id)
                    || !seen.insert(site_id)
                    || row.site_revision.len() != 64
                    || !row.site_revision.bytes().all(|c| {
                        c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
                    })
                    || (!receiving
                        && !bound.iter().any(|s| {
                            s.port == ingress.port
                                && s.protocol == ingress.protocol
                                && s.state() == IngressBindState::Bound
                        }))
                {
                    return None;
                }
                let protocol = match ingress.protocol() {
                    IngressProtocol::Http => "http",
                    IngressProtocol::Https => "https",
                    _ => return None,
                };
                let destination = if receiving {
                    &mut received_sites
                } else {
                    &mut sites
                };
                destination.push(SiteApplication {
                    site_id,
                    site_revision: row.site_revision.clone(),
                    port: u16::try_from(ingress.port).ok()?,
                    protocol,
                });
            }
            Some((
                Instant::now(),
                ApplicationObservation {
                    observed_at: Utc::now(),
                    authority_epoch,
                    generation: report.generation,
                    received_sites,
                    sites,
                },
            ))
        })();
    }

    pub async fn application_observations(
        &self,
        freshness: Duration,
    ) -> HashMap<Uuid, ApplicationObservation> {
        self.inner
            .read()
            .await
            .connected
            .iter()
            .filter_map(|(id, c)| {
                let (at, report) = c.application.as_ref()?;
                (at.elapsed() < freshness).then(|| (*id, report.clone()))
            })
            .collect()
    }

    /// Sample inventory and application from the same authenticated connection.
    pub(super) async fn site_observation(
        &self,
        agent: Uuid,
        session: Uuid,
        port: i32,
        protocol: &str,
        site: Uuid,
        epoch: Uuid,
    ) -> (
        Option<bool>,
        Option<(DateTime<Utc>, Option<String>, Option<String>)>,
    ) {
        let inner = self.inner.read().await;
        let Some(conn) = inner
            .connected
            .get(&agent)
            .filter(|c| c.session == Some(session))
        else {
            return (None, None);
        };
        let fresh = Duration::from_secs(60);
        let bound = conn
            .ingress
            .as_ref()
            .filter(|(at, _)| at.elapsed() < fresh)
            .map(|(_, report)| {
                report.listeners.iter().any(|l| {
                    l.port as i32 == port
                        && l.state() == IngressBindState::Bound
                        && matches!(
                            (protocol, l.protocol()),
                            ("http", IngressProtocol::Http)
                                | ("https", IngressProtocol::Https)
                        )
                })
            });
        let applied = conn
            .application
            .as_ref()
            .filter(|(at, report)| {
                at.elapsed() < fresh && report.authority_epoch == epoch
            })
            .map(|(_, report)| {
                let revision = |sites: &[SiteApplication]| {
                    sites
                        .iter()
                        .find(|r| {
                            r.site_id == site
                                && i32::from(r.port) == port
                                && r.protocol == protocol
                        })
                        .map(|r| r.site_revision.clone())
                };
                (
                    report.observed_at,
                    revision(&report.sites),
                    revision(&report.received_sites),
                )
            });
        (bound, applied)
    }

    pub(super) async fn managed_stream_ids(&self) -> Vec<Uuid> {
        self.inner
            .read()
            .await
            .connected
            .iter()
            .filter_map(|(id, connection)| connection.session.map(|_| *id))
            .collect()
    }

    pub(super) async fn session_ingress(&self, id: Uuid, session: Uuid) -> Option<IngressListeners> {
        let inner = self.inner.read().await;
        let (at, report) = inner.connected.get(&id)
            .filter(|connection| connection.session == Some(session))?
            .ingress.as_ref()?;
        (at.elapsed() < Duration::from_secs(60)).then(|| report.clone())
    }

    pub(super) async fn bound_ingresses(
        &self,
        id: Uuid,
        session: Uuid,
    ) -> Vec<(i32, &'static str)> {
        let inner = self.inner.read().await;
        let Some((_, report)) = inner
            .connected
            .get(&id)
            .filter(|connection| connection.session == Some(session))
            .and_then(|connection| connection.ingress.as_ref())
            .filter(|(at, _)| at.elapsed() < Duration::from_secs(60))
        else {
            return Vec::new();
        };
        report
            .listeners
            .iter()
            .filter(|l| {
                l.state() == IngressBindState::Bound
                    && l.port != u32::from(self.admin_port)
            })
            .filter_map(|l| match l.protocol() {
                IngressProtocol::Http => Some((l.port as i32, "http")),
                IngressProtocol::Https => Some((l.port as i32, "https")),
                _ => None,
            })
            .collect()
    }

    /// Latest validated TCP inventory on this stream. Callers must supply a
    /// freshness limit; an open gRPC stream alone is not a recent report.
    pub async fn ingress_listeners(
        &self,
        agent_id: Uuid,
        max_age: Duration,
    ) -> Option<IngressListeners> {
        let inner = self.inner.read().await;
        let (recorded_at, report) =
            inner.connected.get(&agent_id)?.ingress.as_ref()?;
        (recorded_at.elapsed() < max_age).then(|| report.clone())
    }

    /// Retains why the agent's data plane is not running the configuration it
    /// received (empty = it is). Returns whether this differs from the
    /// previous heartbeat, so the caller logs transitions rather than every
    /// heartbeat of a node that stays degraded.
    pub async fn record_apply_error(
        &self,
        agent_id: Uuid,
        error: &str,
    ) -> bool {
        let mut inner = self.inner.write().await;
        if error.is_empty() {
            return inner.apply_errors.remove(&agent_id).is_some();
        }
        if inner.apply_errors.get(&agent_id).map(String::as_str) == Some(error)
        {
            return false;
        }
        inner.apply_errors.insert(agent_id, error.to_string());
        true
    }

    /// Retains the agent's running total of discarded log entries and
    /// returns how many were discarded since the previous report.
    ///
    /// The total restarts with the agent process, so a lower value than the
    /// one on record is a fresh count, all of it new.
    pub async fn record_log_drops(&self, agent_id: Uuid, total: u64) -> u64 {
        let mut inner = self.inner.write().await;
        if total == 0 {
            inner.log_drops.remove(&agent_id);
            return 0;
        }
        let previous = inner.log_drops.insert(agent_id, total).unwrap_or(0);
        if total >= previous {
            total - previous
        } else {
            total
        }
    }

    /// Log entries the agent has discarded since its process started, as of
    /// its last heartbeat.
    pub async fn log_drops(&self, agent_id: &Uuid) -> u64 {
        self.inner
            .read()
            .await
            .log_drops
            .get(agent_id)
            .copied()
            .unwrap_or(0)
    }

    /// Why the agent's data plane is not running its configuration, if its
    /// last heartbeat said so.
    pub async fn apply_error(&self, agent_id: &Uuid) -> Option<String> {
        self.inner.read().await.apply_errors.get(agent_id).cloned()
    }

    /// Starts a registration: the configuration about to be built for the
    /// response replaces whatever was issued before.
    ///
    /// Queued `UpdateSite` commands are dropped — each carries the agent's
    /// whole configuration, so the fresher one in the response supersedes
    /// them, and replaying them after it would roll the agent back. Call this
    /// *before* building that configuration: a change committed afterwards
    /// queues its own command, which then survives to be replayed.
    pub async fn begin_registration(&self, agent_id: Uuid) {
        let mut inner = self.inner.write().await;
        if let Some(queue) = inner.pending.get_mut(&agent_id) {
            queue.retain(|command| update_site_hash(command).is_none());
        }
        inner.config.insert(agent_id, ConfigSync::default());
    }

    /// Records the hash of the configuration handed out at registration.
    /// A push issued since [`Self::begin_registration`] is newer and keeps
    /// its place as the target.
    pub async fn note_initial_config(&self, agent_id: Uuid, config_hash: &str) {
        let mut inner = self.inner.write().await;
        let sync = inner.config.entry(agent_id).or_default();
        if sync.target.is_none() {
            sync.target = Some(config_hash.to_string());
            sync.mismatches = 0;
        }
    }

    /// Checks the hash a heartbeat reported against the configuration last
    /// issued to the agent and decides whether it has to be pushed again.
    ///
    /// The comparison is against the hash that was *sent*, never against a
    /// freshly built bundle: the fingerprint of two builds of the same
    /// configuration can differ, which would read as permanent drift.
    pub async fn observe_config_hash(
        &self,
        agent_id: Uuid,
        reported: &str,
        now: Instant,
    ) -> ConfigDrift {
        let mut inner = self.inner.write().await;
        let sync = inner.config.entry(agent_id).or_default();
        if !reported.is_empty() && sync.target.as_deref() == Some(reported) {
            sync.mismatches = 0;
            sync.repushes = 0;
            sync.last_repush = None;
            return ConfigDrift::InSync;
        }
        sync.mismatches = sync.mismatches.saturating_add(1);
        if sync.mismatches < CONFIG_DRIFT_GRACE {
            return ConfigDrift::Settling;
        }
        if let Some(last) = sync.last_repush {
            if now.saturating_duration_since(last)
                < repush_cooldown(sync.repushes)
            {
                return ConfigDrift::Settling;
            }
        }
        sync.last_repush = Some(now);
        sync.repushes = sync.repushes.saturating_add(1);
        sync.mismatches = 0;
        ConfigDrift::Repush {
            expected: sync.target.clone(),
        }
    }

    /// Makes `command` the agent's configuration target when it is an
    /// `UpdateSite`. Each one replaces the agent's whole configuration, so
    /// the ones still queued are obsolete: left in place they would be
    /// replayed on the next reconnect, after this newer one.
    async fn note_config_issued(
        &self,
        agent_id: &Uuid,
        command: &ServerCommand,
    ) {
        let Some(hash) = update_site_hash(command) else {
            return;
        };
        let mut inner = self.inner.write().await;
        if inner
            .connected
            .get(agent_id)
            .is_some_and(|c| c.session.is_some())
        {
            return;
        }
        if let Some(queue) = inner.pending.get_mut(agent_id) {
            queue.retain(|queued| update_site_hash(queued).is_none());
        }
        let sync = inner.config.entry(*agent_id).or_default();
        sync.target = Some(hash.to_string());
        sync.mismatches = 0;
    }

    /// True when the agent currently holds an open stream.
    pub async fn is_connected(&self, agent_id: &Uuid) -> bool {
        self.inner.read().await.connected.contains_key(agent_id)
    }

    /// Number of agents with a live stream.
    pub async fn connected_count(&self) -> usize {
        self.inner.read().await.connected.len()
    }

    /// Live connections with their queue depth.
    pub async fn snapshot(&self) -> Vec<ConnectedAgent> {
        let inner = self.inner.read().await;
        let mut out: Vec<ConnectedAgent> = inner
            .connected
            .iter()
            .map(|(id, conn)| ConnectedAgent {
                id: *id,
                connected_at: conn.connected_at,
                queued_commands: inner
                    .pending
                    .get(id)
                    .map(|q| q.len())
                    .unwrap_or(0),
            })
            .collect();
        out.sort_by_key(|agent| agent.connected_at);
        out
    }

    /// Sends a command immediately when the agent is connected, otherwise queues
    /// it for the next heartbeat.
    ///
    /// Returns `true` when the command was delivered on a live stream.
    pub async fn send_command(
        &self,
        agent_id: &Uuid,
        command: ServerCommand,
    ) -> bool {
        // Recorded whether or not the command reaches a live stream: the
        // target is what the agent should run, and a push that got lost is
        // exactly what the heartbeat comparison has to notice.
        self.note_config_issued(agent_id, &command).await;

        // Grab the sender while holding the read lock only: `send().await`
        // must not block other registry operations.
        let connection = {
            let inner = self.inner.read().await;
            inner
                .connected
                .get(agent_id)
                .map(|c| (c.sender.clone(), c.session.is_some()))
        };

        if let Some((sender, managed)) = connection {
            if managed && is_config_command(&command) {
                // Lost hints are repaired by periodic pulls, never replayed.
                return sender.try_send(config_changed(command)).is_ok();
            }
            match sender.try_send(command) {
                Ok(()) => {
                    tracing::debug!(%agent_id, "command pushed to agent");
                    return true;
                },
                Err(mpsc::error::TrySendError::Full(command)) => {
                    tracing::warn!(%agent_id, "agent command channel full, queueing instead");
                    self.enqueue(agent_id, command).await;
                    return false;
                },
                Err(mpsc::error::TrySendError::Closed(command)) => {
                    tracing::debug!(%agent_id, "agent stream closed, queueing command");
                    self.enqueue(agent_id, command).await;
                    return false;
                },
            }
        }

        self.enqueue(agent_id, command).await;
        false
    }

    /// Sends a command only when the agent is connected and has room for it.
    ///
    /// Unlike [`Self::send_command`] nothing is queued: a stale command that
    /// makes no sense after reconnecting (flush the log buffer) must not be
    /// replayed later. Returns `true` when it entered the live stream.
    pub async fn send_command_now(
        &self,
        agent_id: &Uuid,
        command: ServerCommand,
    ) -> bool {
        let connection = {
            let inner = self.inner.read().await;
            inner
                .connected
                .get(agent_id)
                .map(|c| (c.sender.clone(), c.session.is_some()))
        };
        match connection {
            Some((sender, true)) if is_config_command(&command) => {
                sender.try_send(config_changed(command)).is_ok()
            },
            Some((sender, _)) => sender.try_send(command).is_ok(),
            None => false,
        }
    }

    /// Pushes a command to every connected agent, queueing for the offline ones.
    ///
    /// Returns how many agents received it live.
    pub async fn broadcast(
        &self,
        build: impl Fn(Uuid) -> ServerCommand,
    ) -> usize {
        let ids: Vec<Uuid> = {
            let inner = self.inner.read().await;
            inner.connected.keys().copied().collect()
        };
        let mut delivered = 0;
        for id in ids {
            if self.send_command(&id, build(id)).await {
                delivered += 1;
            }
        }
        delivered
    }

    /// Number of commands waiting for an offline agent.
    pub async fn pending_count(&self, agent_id: &Uuid) -> usize {
        self.inner
            .read()
            .await
            .pending
            .get(agent_id)
            .map(|q| q.len())
            .unwrap_or(0)
    }

    async fn enqueue(&self, agent_id: &Uuid, command: ServerCommand) {
        let mut inner = self.inner.write().await;
        let queue = inner.pending.entry(*agent_id).or_default();
        if queue.len() >= PENDING_COMMAND_LIMIT {
            // Drop the oldest command rather than growing without bound.
            queue.pop_front();
        }
        queue.push_back(command);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingwaf_proto::control_plane::RestartAgentCommand;

    #[tokio::test]
    async fn managed_stream_discards_queued_configs_and_only_gets_live_hints() {
        let registry = AgentRegistry::new();
        let agent = Uuid::new_v4();
        let reload = ServerCommand {
            payload: Some(Payload::ConfigReload(
                pingwaf_proto::ConfigReloadCommand::default(),
            )),
            ..Default::default()
        };
        let incremental = ServerCommand {
            payload: Some(Payload::RuleUpdate(
                pingwaf_proto::RuleUpdateCommand::default(),
            )),
            ..Default::default()
        };
        let replacements = [incremental, reload, update_site("legacy")];
        for command in &replacements {
            assert!(!registry.send_command(&agent, command.clone()).await);
        }
        assert!(!registry.send_command(&agent, restart("operator")).await);
        let (sender, mut receiver) = mpsc::channel(1);
        let (stream, queued) = registry
            .connect_session(agent, sender, Some(Uuid::new_v4()))
            .await;
        assert!(registry.is_current_stream(agent, stream).await);
        assert_eq!(queued.len(), 1);
        assert!(matches!(queued[0].payload, Some(Payload::RestartAgent(_))));
        for command in replacements {
            assert!(registry.send_command(&agent, command.clone()).await);
            assert!(!registry.send_command(&agent, command).await);
            assert_eq!(registry.pending_count(&agent).await, 0);
            let hint = receiver.try_recv().unwrap();
            assert_eq!(
                hint.r#type,
                CommandType::CommandManagedConfigChanged as i32
            );
            assert!(matches!(
                hint.payload,
                Some(Payload::ManagedConfigChanged(_))
            ));
        }
        let (sender, _) = mpsc::channel(1);
        let (next, queued) = registry.connect(agent, sender).await;
        assert!(!registry.is_current_stream(agent, stream).await);
        assert!(registry.is_current_stream(agent, next).await);
        assert!(queued.is_empty());
    }

    fn restart(reason: &str) -> ServerCommand {
        ServerCommand {
            command_id: Uuid::new_v4().to_string(),
            r#type: 7, // COMMAND_RESTART_AGENT
            issued_at: None,
            payload: Some(pingwaf_proto::control_plane::server_command::Payload::RestartAgent(
                RestartAgentCommand {
                    reason: reason.to_string(),
                    graceful: true,
                },
            )),
        }
    }

    #[tokio::test]
    async fn commands_are_queued_while_offline_and_drained_on_connect() {
        let registry = AgentRegistry::new();
        let agent = Uuid::new_v4();

        registry.send_command(&agent, restart("a")).await;
        assert_eq!(registry.pending_count(&agent).await, 1);

        let (tx, mut rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (generation, drained) = registry.connect(agent, tx).await;
        assert_eq!(drained.len(), 1);
        assert_eq!(registry.pending_count(&agent).await, 0);
        assert!(registry.is_connected(&agent).await);

        assert!(registry.send_command(&agent, restart("b")).await);
        assert!(rx.try_recv().is_ok());

        registry.disconnect(&agent, generation).await;
        assert!(!registry.is_connected(&agent).await);

        // A stale stream (older generation) must not remove a live one.
        let (tx, _rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (new_generation, _) = registry.connect(agent, tx).await;
        registry.disconnect(&agent, generation).await;
        assert!(registry.is_connected(&agent).await);
        registry.disconnect(&agent, new_generation).await;
        assert!(!registry.is_connected(&agent).await);
    }

    #[tokio::test]
    async fn pending_queue_is_bounded() {
        let registry = AgentRegistry::new();
        let agent = Uuid::new_v4();
        for i in 0..(PENDING_COMMAND_LIMIT + 10) {
            registry
                .send_command(&agent, restart(&format!("cmd-{i}")))
                .await;
        }
        assert_eq!(registry.pending_count(&agent).await, PENDING_COMMAND_LIMIT);
    }

    fn update_site(hash: &str) -> ServerCommand {
        use pingwaf_proto::control_plane::{SiteConfig, UpdateSiteCommand};
        ServerCommand {
            command_id: Uuid::new_v4().to_string(),
            r#type: 2, // COMMAND_UPDATE_SITE
            issued_at: None,
            payload: Some(Payload::UpdateSite(UpdateSiteCommand {
                site_config: Some(SiteConfig {
                    config_hash: hash.to_string(),
                    ..Default::default()
                }),
            })),
        }
    }

    fn hashes(commands: &VecDeque<ServerCommand>) -> Vec<Option<&str>> {
        commands.iter().map(update_site_hash).collect()
    }

    /// A push that never reached the agent is noticed from the heartbeat: the
    /// first stale report is tolerated (it may have crossed the push on the
    /// wire), the second asks for a re-push.
    #[tokio::test]
    async fn stale_hash_is_repushed_after_the_grace_heartbeat() {
        let registry = AgentRegistry::new();
        let agent = Uuid::new_v4();
        let now = Instant::now();

        registry.begin_registration(agent).await;
        registry.note_initial_config(agent, "v1").await;
        assert_eq!(
            registry.observe_config_hash(agent, "v1", now).await,
            ConfigDrift::InSync
        );

        // The push is issued while the agent has no stream: it is recorded as
        // the target even though it only reached the pending queue.
        assert!(!registry.send_command(&agent, update_site("v2")).await);
        assert_eq!(
            registry.observe_config_hash(agent, "v1", now).await,
            ConfigDrift::Settling
        );
        assert_eq!(
            registry.observe_config_hash(agent, "v1", now).await,
            ConfigDrift::Repush {
                expected: Some("v2".to_string())
            }
        );

        // The agent caught up: back in sync, and the next drift starts over
        // with a full grace period and no cooldown.
        assert_eq!(
            registry.observe_config_hash(agent, "v2", now).await,
            ConfigDrift::InSync
        );
        registry.send_command(&agent, update_site("v3")).await;
        assert_eq!(
            registry.observe_config_hash(agent, "v2", now).await,
            ConfigDrift::Settling
        );
        assert_eq!(
            registry.observe_config_hash(agent, "v2", now).await,
            ConfigDrift::Repush {
                expected: Some("v3".to_string())
            }
        );
    }

    /// An agent that cannot converge is not pushed a full bundle on every
    /// heartbeat: re-pushes are spaced 60 s apart, doubling up to 10 min.
    #[tokio::test]
    async fn repushes_back_off_while_the_agent_does_not_converge() {
        let registry = AgentRegistry::new();
        let agent = Uuid::new_v4();
        let start = Instant::now();
        registry.begin_registration(agent).await;
        registry.note_initial_config(agent, "want").await;

        let mut repushed_at = Vec::new();
        // One heartbeat every 10 s for an hour, always on the wrong hash.
        for tick in 0..360u64 {
            let now = start + Duration::from_secs(tick * 10);
            if let ConfigDrift::Repush { expected } =
                registry.observe_config_hash(agent, "have", now).await
            {
                assert_eq!(expected.as_deref(), Some("want"));
                repushed_at.push(tick * 10);
            }
        }
        let gaps: Vec<u64> = repushed_at
            .windows(2)
            .map(|pair| pair[1] - pair[0])
            .collect();
        assert_eq!(repushed_at[0], 10, "second stale heartbeat");
        assert_eq!(&gaps[..5], &[60, 120, 240, 480, 600]);
        assert!(gaps[5..].iter().all(|gap| *gap == 600));

        assert_eq!(repush_cooldown(0), CONFIG_REPUSH_COOLDOWN);
        assert_eq!(repush_cooldown(1), CONFIG_REPUSH_COOLDOWN);
        assert_eq!(repush_cooldown(u32::MAX), CONFIG_REPUSH_COOLDOWN_MAX);
    }

    /// An agent reporting no hash at all, or one this process never issued
    /// (control plane restarted and the agent did not re-register), is
    /// pushed its configuration too.
    #[tokio::test]
    async fn unknown_target_and_empty_hash_are_repushed() {
        let registry = AgentRegistry::new();
        let agent = Uuid::new_v4();
        let now = Instant::now();

        assert_eq!(
            registry.observe_config_hash(agent, "old", now).await,
            ConfigDrift::Settling
        );
        assert_eq!(
            registry.observe_config_hash(agent, "old", now).await,
            ConfigDrift::Repush { expected: None }
        );

        let empty = Uuid::new_v4();
        registry.note_initial_config(empty, "").await;
        registry.observe_config_hash(empty, "", now).await;
        assert!(
            matches!(
                registry.observe_config_hash(empty, "", now).await,
                ConfigDrift::Repush { .. }
            ),
            "an empty hash never counts as in sync"
        );
    }

    /// Every `UpdateSite` carries the agent's whole configuration, so only
    /// the newest may be replayed: an older one delivered after it would roll
    /// the agent back. Other queued commands are untouched.
    #[tokio::test]
    async fn newer_configuration_supersedes_queued_ones() {
        let registry = AgentRegistry::new();
        let agent = Uuid::new_v4();

        registry.send_command(&agent, update_site("v1")).await;
        registry.send_command(&agent, restart("keep")).await;
        registry.send_command(&agent, update_site("v2")).await;

        let (tx, _rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (_, drained) = registry.connect(agent, tx).await;
        assert_eq!(hashes(&drained), vec![None, Some("v2")]);
    }

    /// Registration hands out a fresh configuration: what was queued before
    /// it is obsolete, what is issued after it started is newer and stays —
    /// both in the queue and as the target.
    #[tokio::test]
    async fn registration_drops_stale_pushes_but_keeps_newer_ones() {
        let registry = AgentRegistry::new();
        let agent = Uuid::new_v4();
        let now = Instant::now();

        registry.send_command(&agent, update_site("stale")).await;
        registry.send_command(&agent, restart("keep")).await;
        registry.begin_registration(agent).await;
        // A change committed while the response is being built.
        registry.send_command(&agent, update_site("newer")).await;
        registry.note_initial_config(agent, "initial").await;

        let (tx, _rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (_, drained) = registry.connect(agent, tx).await;
        assert_eq!(hashes(&drained), vec![None, Some("newer")]);

        assert_eq!(
            registry.observe_config_hash(agent, "newer", now).await,
            ConfigDrift::InSync,
            "the push issued during registration is the target"
        );

        // Without a concurrent push the registration config is the target.
        registry.begin_registration(agent).await;
        registry.note_initial_config(agent, "initial").await;
        assert_eq!(
            registry.observe_config_hash(agent, "initial", now).await,
            ConfigDrift::InSync
        );
    }

    /// The reload failure belongs to the stream that reported it, and the
    /// return value marks transitions only.
    #[tokio::test]
    async fn apply_error_tracks_transitions_and_the_stream_lifecycle() {
        let registry = AgentRegistry::new();
        let agent = Uuid::new_v4();
        let (tx, _rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (generation, _) = registry.connect(agent, tx).await;

        assert!(!registry.record_apply_error(agent, "").await);
        assert_eq!(registry.apply_error(&agent).await, None);

        assert!(registry.record_apply_error(agent, "plugins: boom").await);
        assert!(!registry.record_apply_error(agent, "plugins: boom").await);
        assert!(registry.record_apply_error(agent, "upstreams: boom").await);
        assert_eq!(
            registry.apply_error(&agent).await.as_deref(),
            Some("upstreams: boom")
        );

        assert!(registry.record_apply_error(agent, "").await);
        assert_eq!(registry.apply_error(&agent).await, None);

        registry.record_apply_error(agent, "plugins: boom").await;
        registry.disconnect(&agent, generation + 1).await;
        assert!(
            registry.apply_error(&agent).await.is_some(),
            "a superseded stream closing keeps the live report"
        );
        registry.disconnect(&agent, generation).await;
        assert_eq!(registry.apply_error(&agent).await, None);

        registry.record_apply_error(agent, "plugins: boom").await;
        let (tx, _rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        registry.connect(agent, tx).await;
        assert_eq!(registry.apply_error(&agent).await, None);

        registry.record_apply_error(agent, "plugins: boom").await;
        registry.force_disconnect(&agent).await;
        assert_eq!(registry.apply_error(&agent).await, None);
    }

    /// The agent reports a running total; what matters to the operator is
    /// each increase, including the first report after either side restarted.
    #[tokio::test]
    async fn log_drops_report_the_increase_and_survive_reconnects() {
        let registry = AgentRegistry::new();
        let agent = Uuid::new_v4();

        assert_eq!(registry.record_log_drops(agent, 0).await, 0);
        assert_eq!(registry.log_drops(&agent).await, 0);

        assert_eq!(registry.record_log_drops(agent, 5).await, 5);
        assert_eq!(registry.record_log_drops(agent, 5).await, 0);
        assert_eq!(registry.record_log_drops(agent, 12).await, 7);

        // A reconnect does not reset the agent's counter, so it must not
        // look like 12 new losses either.
        let (tx, _rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (generation, _) = registry.connect(agent, tx).await;
        registry.disconnect(&agent, generation).await;
        assert_eq!(registry.log_drops(&agent).await, 12);
        assert_eq!(registry.record_log_drops(agent, 12).await, 0);

        // The agent process restarted and has lost entries again.
        assert_eq!(registry.record_log_drops(agent, 3).await, 3);
        assert_eq!(registry.log_drops(&agent).await, 3);
    }

    /// A pruned agent leaves nothing behind.
    #[tokio::test]
    async fn forget_drops_configuration_state() {
        let registry = AgentRegistry::new();
        let agent = Uuid::new_v4();
        registry.send_command(&agent, update_site("v1")).await;
        registry.record_apply_error(agent, "plugins: boom").await;
        registry.record_log_drops(agent, 7).await;

        registry.forget(&[agent]).await;

        let inner = registry.inner.read().await;
        assert!(!inner.log_drops.contains_key(&agent));
        assert!(!inner.config.contains_key(&agent));
        assert!(!inner.apply_errors.contains_key(&agent));
        assert!(!inner.pending.contains_key(&agent));
    }

    fn counters(cpu_percent: f64, rps: u64) -> HeartbeatMetrics {
        HeartbeatMetrics {
            cpu_percent,
            memory_bytes: 3 << 30,
            process_rss_bytes: Some(256 << 20),
            connections: 17,
            rps,
        }
    }

    /// The counters live and die with the stream that reported them: recorded
    /// while it is open, untouched by a stale stream closing, dropped when the
    /// owning stream ends.
    #[tokio::test]
    async fn heartbeat_metrics_follow_the_stream_lifecycle() {
        let registry = AgentRegistry::new();
        let agent = Uuid::new_v4();
        assert!(
            !registry.metrics().await.contains_key(&agent),
            "a node that never heartbeated has no entry, not a zeroed one"
        );

        let (tx, _rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (generation, _) = registry.connect(agent, tx).await;
        registry.record_heartbeat(agent, counters(12.5, 42)).await;

        let metrics = registry.metrics().await;
        let entry = metrics.get(&agent).expect("counters of the live stream");
        assert!((entry.cpu_percent - 12.5).abs() < f64::EPSILON);
        assert_eq!(entry.memory_bytes, 3 << 30);
        assert_eq!(entry.connections, 17);
        assert_eq!(entry.rps, 42);
        // The tri-state field survives the retention verbatim: the None that
        // means "never reported" must not collapse into Some(0) on the way
        // through the registry.
        assert_eq!(entry.process_rss_bytes, Some(256 << 20));

        // A superseded stream finishing must not erase the live counters.
        registry.disconnect(&agent, generation + 1).await;
        assert!(registry.metrics().await.contains_key(&agent));

        registry.disconnect(&agent, generation).await;
        assert!(!registry.metrics().await.contains_key(&agent));
    }

    #[tokio::test]
    async fn application_observations_require_current_session_grant_and_socket()
    {
        use pingwaf_proto::{
            IngressListenerStatus, ManagedApplyReport, ManagedSiteApplication,
            SiteIngress,
        };
        let registry = AgentRegistry::new();
        let (agent, session, site) =
            (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let (sender, _) = mpsc::channel(1);
        let (stream, _) =
            registry.connect_session(agent, sender, Some(session)).await;
        let bound = IngressListeners {
            supports_site_handlers: false,
            static_directories: Default::default(),
            dynamic_bind: false,
            listeners: vec![IngressListenerStatus {
                port: 81,
                protocol: IngressProtocol::Http as i32,
                state: IngressBindState::Bound as i32,
            }],
        };
        let report = ManagedApplyReport {
            received_sites: Vec::new(),
            session_id: session.to_string(),
            authority_epoch: Uuid::new_v4().to_string(),
            generation: 3,
            sites: vec![ManagedSiteApplication {
                site_id: site.to_string(),
                site_revision: "af".repeat(32),
                ingress: Some(SiteIngress {
                    port: 81,
                    protocol: IngressProtocol::Http as i32,
                }),
            }],
        };
        for (s, visible, bound, accepted) in [
            (session, vec![site], None, false),
            (session, vec![site], Some(&bound), true),
            (Uuid::new_v4(), vec![site], Some(&bound), false),
            (session, Vec::new(), Some(&bound), false),
        ] {
            registry.record_ingress(agent, stream, bound).await;
            registry
                .record_application(
                    agent,
                    stream,
                    Some(s),
                    &visible,
                    Some(&report),
                )
                .await;
            assert_eq!(
                registry
                    .application_observations(Duration::from_secs(60))
                    .await
                    .contains_key(&agent),
                accepted
            );
            assert!(registry
                .application_observations(Duration::ZERO)
                .await
                .is_empty());
        }
    }

    #[tokio::test]
    async fn ingress_inventory_belongs_only_to_the_current_stream() {
        use pingwaf_proto::IngressListenerStatus;

        let registry = AgentRegistry::new();
        let agent = Uuid::new_v4();
        let fresh = Duration::from_secs(60);
        let (sender, _receiver) = mpsc::channel(1);
        let (first, _) = registry.connect(agent, sender).await;
        let mut report = IngressListeners {
            supports_site_handlers: false,
            static_directories: Default::default(),
            dynamic_bind: false,
            listeners: vec![IngressListenerStatus {
                port: 81,
                protocol: IngressProtocol::Http as i32,
                state: IngressBindState::Bound as i32,
            }],
        };
        registry.record_ingress(agent, first, Some(&report)).await;
        assert_eq!(
            registry.ingress_listeners(agent, fresh).await,
            Some(report.clone())
        );
        assert_eq!(
            registry.ingress_listeners(agent, Duration::ZERO).await,
            None
        );

        let (sender, _receiver) = mpsc::channel(1);
        let (current, _) = registry.connect(agent, sender).await;
        registry.record_ingress(agent, first, Some(&report)).await;
        assert_eq!(registry.ingress_listeners(agent, fresh).await, None);
        registry.record_ingress(agent, current, Some(&report)).await;
        registry.disconnect(&agent, first).await;
        assert_eq!(
            registry.ingress_listeners(agent, fresh).await,
            Some(report.clone())
        );

        report.listeners.push(report.listeners[0]);
        registry.record_ingress(agent, current, Some(&report)).await;
        assert_eq!(registry.ingress_listeners(agent, fresh).await, None);
        report.listeners.pop();
        registry.record_ingress(agent, current, Some(&report)).await;
        registry.record_ingress(agent, current, None).await;
        assert_eq!(registry.ingress_listeners(agent, fresh).await, None);
        registry.record_ingress(agent, current, Some(&report)).await;
        registry.disconnect(&agent, current).await;
        assert_eq!(registry.ingress_listeners(agent, fresh).await, None);
    }

    /// A reconnect starts with no counters (the opening heartbeat refills
    /// them), and both cleanup paths — a pruned row and a REST disconnect —
    /// take the last report with them.
    #[tokio::test]
    async fn reconnect_and_cleanup_drop_stale_metrics() {
        let registry = AgentRegistry::new();
        let agent = Uuid::new_v4();

        let (tx, _rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        registry.connect(agent, tx).await;
        registry.record_heartbeat(agent, counters(1.0, 1)).await;
        let (tx, _rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        registry.connect(agent, tx).await;
        assert!(!registry.metrics().await.contains_key(&agent));

        registry.record_heartbeat(agent, counters(2.0, 2)).await;
        registry.forget(&[agent]).await;
        assert!(!registry.metrics().await.contains_key(&agent));

        registry.record_heartbeat(agent, counters(3.0, 3)).await;
        registry.force_disconnect(&agent).await;
        assert!(!registry.metrics().await.contains_key(&agent));
    }

    /// Every writer goes through the same lock: concurrent heartbeats all land,
    /// each with its own values.
    #[tokio::test]
    async fn concurrent_heartbeats_keep_every_agent() {
        let registry = AgentRegistry::new();
        let agents: Vec<Uuid> = (0..32).map(|_| Uuid::new_v4()).collect();
        let mut tasks = Vec::with_capacity(agents.len());
        for (index, agent) in agents.iter().copied().enumerate() {
            let registry = registry.clone();
            tasks.push(tokio::spawn(async move {
                registry
                    .record_heartbeat(
                        agent,
                        counters(index as f64, index as u64),
                    )
                    .await;
            }));
        }
        for task in tasks {
            task.await.expect("record task");
        }

        let metrics = registry.metrics().await;
        assert_eq!(metrics.len(), agents.len());
        for (index, agent) in agents.iter().enumerate() {
            let entry = metrics.get(agent).expect("every agent is present");
            assert_eq!(entry.rps, index as u64);
        }
    }
}
