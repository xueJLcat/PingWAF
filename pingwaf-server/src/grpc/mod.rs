//! gRPC control plane service, agent registry and configuration builder.
//!
//! This module exposes three submodules:
//! - [`config`] — builds protocol messages from database rows
//! - [`control_plane`] — implements the `ControlPlane` gRPC service
//! - [`registry`] — in-memory map of live agent heartbeat streams
//!
//! The key integration point for the REST API is [`notify_config_changed`], which
//! pushes a fresh `SiteConfig` to every agent that serves the changed site.

pub mod cache_status;
pub mod config;
pub mod control_plane;
mod managed;
pub(crate) use managed::{
    check_agent_site, check_assigned_ingress, check_site_ingress,
    node_site_entries, NodeSiteEntries, ingress_agent_options, deployment_summaries, EntrySummary, site_deployment, IngressAgentOption, SiteDeployment,
};
pub mod registry;
pub mod tunnel_registry;
pub mod visitor_auth;

pub use cache_status::{CacheStatusRegistry, SiteCacheStatus};
pub use control_plane::ControlPlaneService;
pub use registry::{
    AgentRegistry, ConfigDrift, ConnectedAgent, ManualSyncReceipt, COMMAND_CHANNEL_CAPACITY,
};
pub(crate) use registry::ManualDelivery;
pub use tunnel_registry::TUNNEL_CONNECTORS;

use pingwaf_proto::control_plane::{
    server_command::Payload, ServerCommand, SiteConfig, UpdateSiteCommand,
};
use sea_orm::{
    ColumnTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter, QuerySelect, QueryTrait,
};
use std::collections::HashMap;
use uuid::Uuid;

use crate::api::agents::command_type;
use crate::api::state::AppState;
use crate::config_history::{self, VersionScope};
use crate::grpc::config::{
    build_site_config, history_config_hash, now_timestamp,
};
use crate::models::{agent, agent_sites, api_key, config_version, site};

/// The sites an agent serves: its binding when it has one, otherwise every
/// site owned by its API key's user. Mirrors the gRPC `visible_sites`, and is
/// what an `UpdateSite` payload must carry — the agent applies the payload
/// authoritatively, dropping any cached site the payload does not list.
pub(crate) async fn agent_visible_site_ids<C>(
    db: &C,
    agent_row: &agent::Model,
) -> Result<Vec<Uuid>, DbErr>
where
    C: sea_orm::ConnectionTrait,
{
    agent_site_query(agent_row).select_only().column(site::Column::Id)
        .into_tuple::<Uuid>().all(db).await
}

/// The binding and the owning API key must agree in the same database read.
pub(crate) fn agent_site_query(row: &agent::Model) -> sea_orm::Select<site::Entity> {
    let owner = api_key::Entity::find().select_only().column(api_key::Column::UserId)
        .filter(api_key::Column::Id.eq(row.api_key_id)).into_query();
    let query = site::Entity::find().filter(site::Column::UserId.in_subquery(owner));
    match row.site_scope.as_str() {
        "selected" => {
            let assigned = agent_sites::Entity::find().select_only().column(agent_sites::Column::SiteId)
                .filter(agent_sites::Column::AgentId.eq(row.id)).into_query();
            query.filter(site::Column::Id.in_subquery(assigned))
        }
        "all" => {
            match row.site_id {
                Some(id) => query.filter(site::Column::Id.eq(id)),
                None => query,
            }
        }
        _ => query.filter(site::Column::Id.is_null()),
    }
}

/// The command that replaces an agent's configuration with `site_config`.
fn update_site_command(site_config: SiteConfig) -> ServerCommand {
    ServerCommand {
        command_id: Uuid::new_v4().to_string(),
        r#type: command_type::UPDATE_SITE,
        issued_at: now_timestamp(),
        payload: Some(Payload::UpdateSite(UpdateSiteCommand {
            site_config: Some(site_config),
        })),
    }
}

/// Pushes one agent the configuration it should be running, built fresh.
///
/// This is the repair for a push that never arrived: the heartbeat handler
/// calls it when an agent keeps reporting a `config_hash` other than the one
/// last issued to it (see [`AgentRegistry::observe_config_hash`]). Returns
/// whether the command entered a live stream; `Ok(false)` also covers an agent
/// whose row is gone.
pub(crate) async fn repush_agent_config(
    db: &DatabaseConnection,
    registry: &AgentRegistry,
    agent_id: Uuid,
) -> Result<bool, DbErr> {
    if let Some(delivered) = registry.hint_managed_config(&agent_id).await {
        return Ok(delivered);
    }
    let Some(row) = agent::Entity::find_by_id(agent_id).one(db).await? else {
        return Ok(false);
    };
    let command = legacy_agent_command(db, &row).await?;
    Ok(registry
        .send_command(&agent_id, command)
        .await)
}

async fn legacy_agent_command(db: &DatabaseConnection, row: &agent::Model) -> Result<ServerCommand, DbErr> {
    let visible = agent_visible_site_ids(db, row).await?;
    Ok(update_site_command(build_site_config(db, Some(&visible)).await?))
}

pub(crate) async fn manual_agent_sync(state: &AppState, row: &agent::Model) -> Result<ManualDelivery, DbErr> {
    match state.agents.manual_delivery(row.id, None).await {
        ManualDelivery::BuildLegacy(stream) => {
            let command = legacy_agent_command(&state.db, row).await?;
            Ok(state.agents.manual_delivery(row.id, Some((stream, command))).await)
        },
        result => Ok(result),
    }
}

/// Notifies every connected agent that the configuration for `site_id` changed.
///
/// This is a best-effort operation: it logs failures but never propagates them
/// to the caller. The REST API handler has already committed the change; a push
/// that does not arrive is repaired from the heartbeat, which reports the hash
/// the agent runs — one that stays behind the hash issued here gets the
/// configuration pushed again (see [`repush_agent_config`]). Managed streams
/// get only a pull hint; this queue cannot advance their applied generation.
///
/// Also records a configuration version (unless the latest
/// version already carries this fingerprint), which is what makes the console
/// and the `pingwaf config` CLI able to list and roll back changes.
pub async fn notify_config_changed(
    state: &AppState,
    site_id: Uuid,
    actor: Option<&str>,
) {
    // Schedule the version capture independently of delivery, including
    // when no agent is connected to receive it.
    // The ~19-table capture is best-effort and off the request path (same
    // detached-task pattern as notification delivery): a slow capture must
    // not stretch every API mutation. Hash-based dedup happens inside
    // record_version, so repeat pushes stay cheap even when two spawns race.
    let db = state.db.clone();
    let actor = actor.map(str::to_string);
    tokio::spawn(async move {
        let config_hash = match history_config_hash(&db, &[site_id]).await {
            Ok(hash) => hash,
            Err(err) => {
                tracing::warn!(%site_id, error = %err, "failed to fingerprint site configuration history");
                // An empty hash disables history deduplication, not capture.
                String::new()
            },
        };
        if let Err(err) = config_history::record_version(
            &db,
            VersionScope::Site(site_id),
            config_version::source::API,
            actor.as_deref(),
            &config_hash,
        )
        .await
        {
            tracing::warn!(%site_id, error = %err, "could not record the configuration version");
        }
    });

    // Deliver to every agent that serves this site: agents bound to it, and
    // unbound agents of the owning user (they run all of the owner's sites).
    let agents = match agent::Entity::find().all(&state.db).await {
        Ok(rows) => rows,
        Err(err) => {
            tracing::warn!(%site_id, error = %err, "failed to list agents for config push");
            return;
        },
    };

    let mut delivered = 0usize;
    for row in &agents {
        let visible = match agent_visible_site_ids(&state.db, row).await {
            Ok(visible) if visible.contains(&site_id) => visible,
            Ok(_) => continue,
            Err(err) => {
                tracing::warn!(agent_id = %row.id, %site_id, error = %err, "failed to resolve the sites of an agent");
                continue;
            },
        };
        if let Some(hinted) = state.agents.hint_managed_config(&row.id).await {
            delivered += usize::from(hinted);
            continue;
        }
        // Even for a single binding use the legacy builder: moving the site
        // to custom ingress must send an empty replacement, not its history.
        let payload = match build_site_config(&state.db, Some(&visible)).await {
            Ok(payload) => payload,
            Err(err) => {
                tracing::warn!(
                    agent_id = %row.id,
                    %site_id,
                    error = %err,
                    "failed to build the config payload for an agent"
                );
                continue;
            },
        };
        let command = update_site_command(payload);
        if state.agents.send_command(&row.id, command).await {
            delivered += 1;
        }
    }

    if delivered == 0 {
        // A skipped push leaves the edge running stale configuration — an
        // agent-side task (like ACME issuance) that depends on this config
        // then never fires and the dashboard shows a wedged state. Surface
        // it loudly instead of at debug: this exact silence used to hide
        // agents auto-bound to a single site never learning about later
        // ones.
        tracing::warn!(
            %site_id,
            total = agents.len(),
            "no agent served this site, config change was not pushed — it \
             stays in the database until an agent syncs it"
        );
    } else {
        tracing::info!(
            %site_id,
            total = agents.len(),
            delivered,
            "config change pushed to agents"
        );
    }
}

/// Notifies every registered agent that a deployment-wide setting changed.
///
/// Meant for changes that land in *every* site's bundle (the global error
/// pages today): calling [`notify_config_changed`] per site would rebuild one
/// site at a time and fan a single edit out into as many database passes as
/// there are sites. Instead the affected site ids are collected from the agent
/// table and built in one pass; each agent then receives only its own site, the
/// same payload a normal push carries, so an agent's cache never grows beyond
/// the site it is bound to.
pub async fn notify_all_config_changed(state: &AppState, actor: Option<&str>) {
    let agents = match agent::Entity::find().all(&state.db).await {
        Ok(rows) => rows,
        Err(err) => {
            tracing::warn!(error = %err, "failed to list agents for config push");
            return;
        },
    };

    // The union of every agent's visible sites feeds the version snapshot.
    let mut visible_per_agent: HashMap<String, Vec<Uuid>> = HashMap::new();
    let mut all_site_ids: std::collections::HashSet<Uuid> =
        std::collections::HashSet::new();
    for row in &agents {
        match agent_visible_site_ids(&state.db, row).await {
            Ok(ids) => {
                all_site_ids.extend(ids.iter().copied());
                visible_per_agent.insert(row.id.to_string(), ids);
            },
            Err(err) => {
                tracing::warn!(
                    agent_id = %row.id,
                    error = %err,
                    "failed to resolve the sites of an agent"
                );
            },
        };
    }
    let site_count = all_site_ids.len();
    let site_ids: Vec<Uuid> = all_site_ids.into_iter().collect();

    // Global settings (defense mode, error pages) get their own version,
    // snapshotted from the tables that feed every site's bundle. Recorded
    // before the empty-registry bail-out: the change is committed either way.
    // Detached like the per-site path — the push must not wait on the
    // snapshot capture.
    let db = state.db.clone();
    let actor = actor.map(str::to_string);
    tokio::spawn(async move {
        let config_hash = match history_config_hash(&db, &site_ids).await {
            Ok(hash) => hash,
            Err(err) => {
                tracing::warn!(error = %err, "failed to fingerprint global configuration history");
                String::new()
            },
        };
        if let Err(err) = config_history::record_version(
            &db,
            VersionScope::Global,
            config_version::source::API,
            actor.as_deref(),
            &config_hash,
        )
        .await
        {
            tracing::warn!(error = %err, "could not record the global configuration version");
        }
    });

    if agents.is_empty() {
        tracing::debug!("no agents registered, skipping config push");
        return;
    }

    // One bundle per distinct visibility set: unbound agents of one owner all
    // share the same payload, so it is built once.
    let mut bundle_cache: HashMap<Vec<Uuid>, SiteConfig> = HashMap::new();
    let mut delivered = 0usize;
    for row in &agents {
        let Some(visible) = visible_per_agent.get(&row.id.to_string()) else {
            continue;
        };
        if push_visible_bundle(
            &state.db,
            &state.agents,
            row,
            visible,
            &mut bundle_cache,
        )
        .await
        {
            delivered += 1;
        }
    }

    tracing::info!(
        sites = site_count,
        total = agents.len(),
        delivered,
        "global config change pushed to agents"
    );
}

/// Pushes the current configuration to every registered agent.
///
/// Used by the gRPC pairing path, which has no `AppState` to hand to
/// [`notify_all_config_changed`]. No configuration version is recorded: pairing
/// changes no site, it only changes the tunnel policy a bundle carries.
pub async fn push_config_to_all(
    db: &DatabaseConnection,
    registry: &AgentRegistry,
) -> usize {
    let agents = match agent::Entity::find().all(db).await {
        Ok(rows) => rows,
        Err(err) => {
            tracing::warn!(error = %err, "failed to list agents for config push");
            return 0;
        },
    };
    let mut bundle_cache: HashMap<Vec<Uuid>, SiteConfig> = HashMap::new();
    let mut delivered = 0usize;
    for row in &agents {
        let visible = match agent_visible_site_ids(db, row).await {
            Ok(ids) => ids,
            Err(err) => {
                tracing::warn!(
                    agent_id = %row.id,
                    error = %err,
                    "failed to resolve the sites of an agent"
                );
                continue;
            },
        };
        if push_visible_bundle(db, registry, row, &visible, &mut bundle_cache)
            .await
        {
            delivered += 1;
        }
    }
    delivered
}

/// Pushes one connector's current policy, or a revocation, over its control
/// stream. Returns whether a live stream received it.
pub async fn notify_tunnel_connectors(
    db: &DatabaseConnection,
    tunnel_id: Uuid,
    revoked: Option<String>,
) -> bool {
    use pingwaf_proto::control_plane::{
        tunnel_connector_command, TunnelConnectorCommand,
        TunnelConnectorRevoked,
    };
    let command = match revoked {
        Some(message) => TunnelConnectorCommand {
            kind: Some(tunnel_connector_command::Kind::Revoked(
                TunnelConnectorRevoked { message },
            )),
        },
        None => {
            match crate::tunnel_policy::connector_config(db, tunnel_id).await {
                Ok(Some(config)) => TunnelConnectorCommand {
                    kind: Some(tunnel_connector_command::Kind::Config(config)),
                },
                Ok(None) => TunnelConnectorCommand {
                    kind: Some(tunnel_connector_command::Kind::Revoked(
                        TunnelConnectorRevoked {
                            message: "the tunnel was deleted".to_string(),
                        },
                    )),
                },
                Err(err) => {
                    tracing::warn!(%tunnel_id, error = %err, "failed to build the tunnel policy");
                    return false;
                },
            }
        },
    };
    TUNNEL_CONNECTORS.push(tunnel_id, command).await
}

/// Pushes the current policy to every connected connector (global settings
/// changed, ingress list changed).
pub async fn notify_all_tunnel_connectors(db: &DatabaseConnection) {
    let online: Vec<Uuid> =
        TUNNEL_CONNECTORS.online().await.keys().copied().collect();
    for tunnel_id in online {
        notify_tunnel_connectors(db, tunnel_id, None).await;
    }
}

/// Sends one agent the authoritative bundle of the sites it serves.
///
/// An empty visibility set is meaningful too: once an agent's last site is
/// gone it needs the empty bundle rather than silence, or it keeps serving the
/// deleted site. Returns whether the command reached a live stream.
async fn push_visible_bundle(
    db: &DatabaseConnection,
    registry: &AgentRegistry,
    row: &agent::Model,
    visible: &[Uuid],
    bundle_cache: &mut HashMap<Vec<Uuid>, SiteConfig>,
) -> bool {
    if let Some(delivered) = registry.hint_managed_config(&row.id).await {
        return delivered;
    }
    let payload = match bundle_cache.get(visible) {
        Some(config) => config.clone(),
        None => {
            let config = match build_site_config(db, Some(visible)).await {
                Ok(config) => config,
                Err(err) => {
                    tracing::warn!(
                        agent_id = %row.id,
                        error = %err,
                        "failed to build the config payload for an agent"
                    );
                    return false;
                },
            };
            bundle_cache.insert(visible.to_vec(), config.clone());
            config
        },
    };
    registry
        .send_command(&row.id, update_site_command(payload))
        .await
}

/// Ids of the agents that currently serve `site_id`.
///
/// Must be resolved *before* the site row is deleted: afterwards a bound
/// agent's `site_id` is NULL (`ON DELETE SET NULL`) and the site is gone from
/// its owner's list, so nothing links the agent to the site any more.
pub async fn agents_serving_site(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Vec<Uuid>, DbErr> {
    let mut serving = Vec::new();
    for row in agent::Entity::find().all(db).await? {
        if agent_visible_site_ids(db, &row).await?.contains(&site_id) {
            serving.push(row.id);
        }
    }
    Ok(serving)
}

/// Tells the agents that served a deleted site what they serve now.
///
/// `agent_ids` comes from [`agents_serving_site`], taken before the delete.
/// [`notify_config_changed`] cannot do this: it addresses agents by the site
/// they serve, and no agent serves a site that no longer exists — the edge
/// kept proxying it until something else happened to trigger a full push.
/// Visibility is re-read here, after the delete, so a formerly bound agent
/// receives whatever its unbound state now covers.
pub async fn notify_site_deleted(
    state: &AppState,
    site_id: Uuid,
    agent_ids: &[Uuid],
) {
    if agent_ids.is_empty() {
        tracing::debug!(%site_id, "no agent served the deleted site");
        return;
    }
    let agents = match agent::Entity::find()
        .filter(agent::Column::Id.is_in(agent_ids.iter().copied()))
        .all(&state.db)
        .await
    {
        Ok(rows) => rows,
        Err(err) => {
            tracing::warn!(%site_id, error = %err, "failed to list agents for site removal push");
            return;
        },
    };

    let mut bundle_cache: HashMap<Vec<Uuid>, SiteConfig> = HashMap::new();
    let mut delivered = 0usize;
    for row in &agents {
        let visible = match agent_visible_site_ids(&state.db, row).await {
            Ok(ids) => ids,
            Err(err) => {
                tracing::warn!(
                    agent_id = %row.id,
                    %site_id,
                    error = %err,
                    "failed to resolve the sites of an agent"
                );
                continue;
            },
        };
        if push_visible_bundle(
            &state.db,
            &state.agents,
            row,
            &visible,
            &mut bundle_cache,
        )
        .await
        {
            delivered += 1;
        }
    }

    tracing::info!(
        %site_id,
        total = agents.len(),
        delivered,
        "site removal pushed to agents"
    );
}

#[cfg(test)]
pub(crate) async fn check_legacy_ingress_delivery(
    db: &DatabaseConnection,
    owner_id: &str,
) {
    use crate::auth::password::hash_password_with_cost;
    use pingwaf_proto::control_plane::{
        control_plane_server::ControlPlane, GetSiteConfigRequest,
        RegisterAgentRequest, SyncRulesRequest,
    };
    use sea_orm::{ConnectionTrait, DbBackend, Statement};
    use tokio_stream::StreamExt;
    use tonic::{Code, Request};

    let sites = site::Entity::find().all(db).await.unwrap();
    let default = sites.iter().find(|s| s.ingress_port.is_none()).unwrap();
    let custom = sites
        .iter()
        .find(|s| s.ingress_port == Some(81) && s.domain == default.domain)
        .unwrap();
    let ids: Vec<_> = sites.iter().map(|s| s.id).collect();
    let assert_legacy = |config: &SiteConfig| {
        assert_eq!(config.sites.len(), 1);
        assert_eq!(config.sites[0].id, default.id.to_string());
        let rules = config.sites[0].rules.as_ref().unwrap();
        assert_eq!(rules.site_policies.len(), 1);
        assert_eq!(rules.site_policies[0].domain, default.domain);
    };
    assert_legacy(&build_site_config(db, Some(&ids)).await.unwrap());
    let history_before = history_config_hash(db, &[custom.id]).await.unwrap();
    assert_ne!(
        history_before,
        build_site_config(db, Some(&[custom.id]))
            .await
            .unwrap()
            .config_hash
    );
    let snapshot = crate::config_catalog::capture(
        db,
        VersionScope::Site(custom.id),
        false,
    )
    .await
    .unwrap();
    assert_eq!(snapshot["tables"]["sites"][0]["ingress_port"], 81);
    for port in [84, 81] {
        db.execute(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE sites SET ingress_port = $1 WHERE id = $2",
            [port.into(), custom.id.into()],
        ))
        .await
        .unwrap();
        assert_eq!(
            history_config_hash(db, &[custom.id]).await.unwrap()
                == history_before,
            port == 81
        );
    }

    let key_id = Uuid::new_v4();
    let raw_key = "pwk_legacy_delivery_test";
    db.execute(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "INSERT INTO api_keys (id, user_id, name, key_hash, key_prefix, created_at) \
         VALUES ($1, $2, 'legacy test', $3, 'pwk_lega', now())",
        [key_id.into(), Uuid::parse_str(owner_id).unwrap().into(), hash_password_with_cost(raw_key, 4).unwrap().into()],
    )).await.unwrap();
    let registry = AgentRegistry::new();
    let service = ControlPlaneService::new(
        db.clone(),
        std::sync::Arc::new(crate::config::ServerConfig::default()),
        registry.clone(),
        None,
        CacheStatusRegistry::new(),
    );
    let registered = service
        .register_agent(Request::new(RegisterAgentRequest {
            api_key: raw_key.into(),
            hostname: "legacy-delivery".into(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_legacy(registered.initial_config.as_ref().unwrap());
    let request_config = |site_id: String| {
        Request::new(GetSiteConfigRequest {
            agent_id: registered.agent_id.clone(),
            agent_token: registered.agent_token.clone(),
            site_id,
        })
    };
    let request_rules = |site_id: String| {
        Request::new(SyncRulesRequest {
            agent_id: registered.agent_id.clone(),
            agent_token: registered.agent_token.clone(),
            site_id,
            ..Default::default()
        })
    };
    for id in [String::new(), default.id.to_string()] {
        assert_legacy(
            &service
                .get_site_config(request_config(id.clone()))
                .await
                .unwrap()
                .into_inner(),
        );
        let mut stream = service
            .sync_rules(request_rules(id))
            .await
            .unwrap()
            .into_inner();
        let bundle = stream.next().await.unwrap().unwrap();
        assert_eq!(bundle.site_id, default.id.to_string());
        assert_eq!(bundle.site_policies.len(), 1);
        assert!(stream.next().await.is_none());
    }
    assert_eq!(
        service
            .get_site_config(request_config(custom.id.to_string()))
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    assert_eq!(
        service
            .sync_rules(request_rules(custom.id.to_string()))
            .await
            .err()
            .unwrap()
            .code(),
        Code::PermissionDenied
    );

    let agent_id = Uuid::parse_str(&registered.agent_id).unwrap();
    let (sender, mut rx) = tokio::sync::mpsc::channel(1);
    registry.connect_session(agent_id, sender, None).await;
    assert!(repush_agent_config(db, &registry, agent_id).await.unwrap());
    let Some(Payload::UpdateSite(update)) = rx.try_recv().unwrap().payload
    else {
        panic!("expected a legacy update");
    };
    assert_legacy(update.site_config.as_ref().unwrap());

    // The legacy single-binding branch must send an authoritative empty
    // replacement (discarding a previously served site), not silence.
    db.execute(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "UPDATE agents SET site_id = $1 WHERE id = $2",
        [custom.id.into(), agent_id.into()],
    ))
    .await
    .unwrap();
    assert!(repush_agent_config(db, &registry, agent_id).await.unwrap());
    let Some(Payload::UpdateSite(update)) = rx.try_recv().unwrap().payload
    else {
        panic!("expected an authoritative empty legacy update");
    };
    assert!(update.site_config.unwrap().sites.is_empty());

    managed::check_postgres(db, &service, raw_key, key_id, default, custom)
        .await;
}
