//! Ordered snapshots. The transaction owns authorization, visibility, content
//! and ordering; no envelope may leave the process before it commits.

use chrono::Utc;
use pingwaf_proto::ManagedSnapshot;
use prost::Message;
use sea_orm::{
    AccessMode, ColumnTrait, ConnectionTrait, DatabaseConnection,
    DatabaseTransaction, DbBackend, DbErr, EntityTrait, IsolationLevel,
    QueryFilter, QueryOrder, RuntimeErr, Statement, TransactionTrait,
};
use sha2::{Digest, Sha256};
use tonic::Status;
use uuid::Uuid;

use crate::api::keys::key_allows_agent;
use crate::models::{
    agent, agent_sites, api_key, role, site, site_oidc, site_status, user,
};

use super::config::assemble_managed_config;

pub(super) async fn build_snapshot(
    db: &DatabaseConnection,
    agent_id: Uuid,
    session_id: Uuid,
) -> Result<ManagedSnapshot, Status> {
    const MAX_ATTEMPTS: usize = 3;
    for _ in 0..MAX_ATTEMPTS {
        match build_once(db, agent_id, session_id).await {
            Ok(snapshot) => return Ok(snapshot),
            Err(BuildError::Forbidden) => {
                return Err(Status::permission_denied(
                    "agent is not authorized",
                ));
            },
            Err(BuildError::Storage(err)) if is_serialization_failure(&err) => {
            },
            Err(BuildError::TooLarge) => {
                return Err(Status::resource_exhausted(
                    "configuration exceeds snapshot limit",
                ));
            },
            Err(BuildError::Storage(err)) => {
                tracing::warn!(%agent_id, error = %err, "managed snapshot unavailable");
                return Err(Status::internal("configuration unavailable"));
            },
        }
    }
    Err(Status::aborted("configuration changed; retry snapshot"))
}

/// Refresh the report scope even on an already-open stream. Registration or
/// site changes may have been committed by a different control-plane replica.
pub(super) async fn heartbeat_scope(
    db: &DatabaseConnection,
    agent_id: Uuid,
    session_id: Uuid,
) -> Result<Vec<Uuid>, Status> {
    async fn read_scope(
        db: &DatabaseConnection,
        agent_id: Uuid,
        session_id: Uuid,
    ) -> Result<Vec<Uuid>, BuildError> {
        let tx = db
            .begin_with_config(
                Some(IsolationLevel::RepeatableRead),
                Some(AccessMode::ReadOnly),
            )
            .await?;
        require_session(&tx, agent_id, session_id).await?;
        let (agent, owner_id) = authorize(&tx, agent_id).await?;
        let sites = visible_sites(&tx, &agent, owner_id).await?;
        tx.commit().await?;
        Ok(sites.into_iter().map(|site| site.id).collect())
    }
    status_for_scope(agent_id, read_scope(db, agent_id, session_id).await)
}

pub(super) async fn authorize_session(
    db: &DatabaseConnection,
    agent_id: Uuid,
    session_id: Uuid,
) -> Result<agent::Model, Status> {
    async fn read_identity(
        db: &DatabaseConnection,
        agent_id: Uuid,
        session_id: Uuid,
    ) -> Result<agent::Model, BuildError> {
        let tx = db
            .begin_with_config(
                Some(IsolationLevel::RepeatableRead),
                Some(AccessMode::ReadOnly),
            )
            .await?;
        require_session(&tx, agent_id, session_id).await?;
        let (row, _) = authorize(&tx, agent_id).await?;
        tx.commit().await?;
        Ok(row)
    }
    status_for_scope(agent_id, read_identity(db, agent_id, session_id).await)
}

pub(super) async fn visitor_site(
    db: &DatabaseConnection,
    agent_id: Uuid,
    session_id: Uuid,
    site_id: Uuid,
) -> Result<site::Model, Status> {
    async fn read_site(
        db: &DatabaseConnection,
        agent_id: Uuid,
        session_id: Uuid,
        site_id: Uuid,
    ) -> Result<site::Model, BuildError> {
        let tx = db
            .begin_with_config(
                Some(IsolationLevel::RepeatableRead),
                Some(AccessMode::ReadOnly),
            )
            .await?;
        require_session(&tx, agent_id, session_id).await?;
        let (agent, owner) = authorize(&tx, agent_id).await?;
        if agent.site_scope != "selected"
            || agent_sites::Entity::find()
                .filter(agent_sites::Column::AgentId.eq(agent.id))
                .filter(agent_sites::Column::SiteId.eq(site_id))
                .one(&tx)
                .await?
                .is_none()
        {
            return Err(BuildError::Forbidden);
        }
        let site = site::Entity::find_by_id(site_id)
            .filter(site::Column::UserId.eq(owner))
            .filter(site::Column::Status.eq(site_status::ACTIVE))
            .filter(site::Column::IngressPort.is_not_null())
            .filter(site::Column::IngressProtocol.eq("https"))
            .one(&tx)
            .await?
            .ok_or(BuildError::Forbidden)?;
        let permits_visitor =
            site_oidc::Entity::find()
                .filter(site_oidc::Column::SiteId.eq(site_id))
                .filter(site_oidc::Column::Enabled.eq(true))
                .filter(site_oidc::Column::AuthMode.is_in([
                    site_oidc::AuthMode::LOCAL,
                    site_oidc::AuthMode::BOTH,
                ]))
                .one(&tx)
                .await?
                .is_some();
        if !permits_visitor {
            return Err(BuildError::Forbidden);
        }
        tx.commit().await?;
        Ok(site)
    }
    status_for_scope(
        agent_id,
        read_site(db, agent_id, session_id, site_id).await,
    )
}

fn status_for_scope<T>(
    agent_id: Uuid,
    result: Result<T, BuildError>,
) -> Result<T, Status> {
    match result {
        Ok(value) => Ok(value),
        Err(BuildError::Forbidden) => {
            Err(Status::permission_denied("agent is not authorized"))
        },
        Err(err) => {
            tracing::warn!(%agent_id, error = ?err, "managed authorization unavailable");
            Err(Status::internal("authorization unavailable"))
        },
    }
}

#[derive(Debug)]
enum BuildError {
    Forbidden,
    TooLarge,
    Storage(DbErr),
}

impl From<DbErr> for BuildError {
    fn from(err: DbErr) -> Self {
        Self::Storage(err)
    }
}

fn is_serialization_failure(err: &DbErr) -> bool {
    match err {
        DbErr::Exec(RuntimeErr::SqlxError(sea_orm::sqlx::Error::Database(
            pg,
        )))
        | DbErr::Query(RuntimeErr::SqlxError(
            sea_orm::sqlx::Error::Database(pg),
        )) => pg.code().as_deref() == Some("40001"),
        _ => false,
    }
}

async fn build_once(
    db: &DatabaseConnection,
    agent_id: Uuid,
    session_id: Uuid,
) -> Result<ManagedSnapshot, BuildError> {
    let tx = db
        .begin_with_config(Some(IsolationLevel::RepeatableRead), None)
        .await?;
    let snapshot = build_in_view(&tx, agent_id, session_id).await?;
    tx.commit().await?;
    Ok(snapshot)
}

async fn build_in_view(
    tx: &DatabaseTransaction,
    agent_id: Uuid,
    session_id: Uuid,
) -> Result<ManagedSnapshot, BuildError> {
    require_session(tx, agent_id, session_id).await?;
    let (agent, owner_id) = authorize(tx, agent_id).await?;
    let sites = visible_sites(tx, &agent, owner_id).await?;
    let config = assemble_managed_config(tx, &sites).await?;
    if config.encoded_len() > pingwaf_proto::MAX_MANAGED_CONFIG_BYTES {
        return Err(BuildError::TooLarge);
    }
    let config = config.encode_to_vec();
    let authority_epoch = authority_epoch(tx).await?;
    let generation = allocate_generation(tx, agent_id, session_id).await?;
    Ok(ManagedSnapshot {
        authority_epoch: authority_epoch.to_string(),
        generation,
        config_hash: hex::encode(Sha256::digest(&config)),
        config,
        session_id: session_id.to_string(),
        lease_seconds: 0, // Only the authenticated RPC grants forwarding.
    })
}

async fn require_session(
    tx: &DatabaseTransaction,
    agent_id: Uuid,
    session_id: Uuid,
) -> Result<(), BuildError> {
    if current_session(tx, agent_id).await? != Some(session_id) {
        return Err(BuildError::Forbidden);
    }
    Ok(())
}

async fn authorize(
    tx: &impl ConnectionTrait,
    agent_id: Uuid,
) -> Result<(agent::Model, Uuid), BuildError> {
    let row = agent::Entity::find_by_id(agent_id)
        .one(tx)
        .await?
        .ok_or(BuildError::Forbidden)?;
    let key = api_key::Entity::find_by_id(
        row.api_key_id.ok_or(BuildError::Forbidden)?,
    )
    .one(tx)
    .await?
    .ok_or(BuildError::Forbidden)?;
    if !key_allows_agent(&key)
        || key.expires_at.is_some_and(|when| when <= Utc::now())
    {
        return Err(BuildError::Forbidden);
    }
    let owner = user::Entity::find_by_id(key.user_id)
        .one(tx)
        .await?
        .ok_or(BuildError::Forbidden)?;
    if owner.disabled || !role::is_valid(&owner.role) {
        return Err(BuildError::Forbidden);
    }
    Ok((row, owner.id))
}

fn unavailable(reason: &str) -> crate::api::error::ApiError {
    crate::api::error::ApiError::BadRequest(reason.into())
        .with_code("site.ingress_unavailable")
}

/// Check both the durable identity and the inventory of that exact authenticated stream.
pub(crate) async fn check_agent_ingress(
    tx: &impl ConnectionTrait,
    agents: &super::AgentRegistry,
    agent_id: Uuid,
    owner: Uuid,
    port: i32,
    protocol: &str,
) -> Result<(), crate::api::error::ApiError> {
    let (agent, key_owner) =
        authorize(tx, agent_id).await.map_err(|err| match err {
            BuildError::Storage(db) => crate::api::error::ApiError::from(db),
            _ => unavailable("agent authorization is unavailable"),
        })?;
    if key_owner != owner || agent.site_scope != "selected" {
        return Err(unavailable(
            "agent must have explicit site scope and the same owner",
        ));
    }
    let session = current_session(tx, agent_id)
        .await?
        .ok_or_else(|| unavailable("agent has no current managed session"))?;
    let inventory = agents.session_ingress(agent_id, session).await
        .ok_or_else(|| unavailable("node listener inventory is unavailable"))?;
    let usable = match inventory.listeners.iter().find(|entry| entry.port as i32 == port) {
        Some(entry) => entry.state() == pingwaf_proto::IngressBindState::Bound
            && matches!((entry.protocol(), protocol),
                (pingwaf_proto::IngressProtocol::Http, "http") |
                (pingwaf_proto::IngressProtocol::Https, "https")),
        None => inventory.dynamic_bind && inventory.listeners.len() < pingwaf_proto::MAX_INGRESS_LISTENERS,
    };
    if !usable || port == i32::from(agents.admin_port) {
        return Err(unavailable(
            "agent has no recent bound listener for the requested port and protocol",
        ));
    }
    Ok(())
}

#[derive(serde::Serialize)]
pub(crate) struct IngressAgentOption {
    id: Uuid,
    name: String,
    dynamic_bind: bool,
    listeners: Vec<(i32, &'static str)>,
}

/// Validate all endpoints against the same site's assignment. Older agents
/// decode only the primary listener, even when their inventory contains all ports.
pub(crate) async fn check_agent_site(
    tx: &impl ConnectionTrait,
    agents: &super::AgentRegistry,
    id: Uuid,
    site: &site::Model,
) -> Result<(), crate::api::error::ApiError> {
    let (Some(port), Some(protocol)) = (site.ingress_port, site.ingress_protocol.as_deref()) else { return Ok(()); };
    check_agent_ingress(tx, agents, id, site.user_id, port, protocol).await?;
    if !site.additional_ingresses.is_empty() {
        let session = current_session(tx, id).await?.ok_or_else(|| unavailable("node session has ended"))?;
        if !agents.session_ingress(id, session).await.is_some_and(|report| report.dynamic_bind) {
            return Err(unavailable("node does not support multiple site listeners"));
        }
        for entry in &site.additional_ingresses {
            let (port, protocol) = site::parse_listener(entry).ok_or_else(|| unavailable("invalid site listener"))?;
            check_agent_ingress(tx, agents, id, site.user_id, i32::from(port), protocol).await?;
        }
    }
    Ok(())
}

pub(crate) async fn ingress_agent_options(
    db: &impl ConnectionTrait,
    registry: &super::AgentRegistry,
    owner: Uuid,
) -> Result<Vec<IngressAgentOption>, DbErr> {
    let mut options = Vec::new();
    for id in registry.managed_stream_ids().await {
        let Some(session) = current_session(db, id).await? else {
            continue;
        };
        let listeners = registry.bound_ingresses(id, session).await;
        let dynamic_bind = registry.session_ingress(id, session).await.is_some_and(|report| report.dynamic_bind);
        if listeners.is_empty() && !dynamic_bind {
            continue;
        }
        match authorize(db, id).await {
            Ok((agent, key_owner))
                if key_owner == owner && agent.site_scope == "selected" =>
            {
                options.push(IngressAgentOption {
                    id,
                    name: agent.display_name.unwrap_or(agent.hostname),
                    dynamic_bind,
                    listeners,
                });
            },
            Err(BuildError::Storage(err)) => return Err(err),
            _ => {},
        }
    }
    options.sort_by(|a, b| (&a.name, a.id).cmp(&(&b.name, b.id)));
    Ok(options)
}

#[derive(serde::Serialize)]
pub(crate) struct SiteDeployment {
    desired_revision: Option<String>,
    nodes: Vec<DeploymentNode>,
}

#[derive(serde::Serialize)]
struct DeploymentNode {
    id: Uuid,
    name: String,
    bound: Option<bool>,
    observed_at: Option<chrono::DateTime<Utc>>,
    applied_revision: Option<String>,
    state: &'static str,
}

pub(crate) async fn site_deployment(
    tx: &DatabaseTransaction,
    registry: &super::AgentRegistry,
    model: &site::Model,
) -> Result<SiteDeployment, DbErr> {
    let mut result = SiteDeployment {
        desired_revision: None,
        nodes: Vec::new(),
    };
    let (Some(port), Some(protocol)) =
        (model.ingress_port, model.ingress_protocol.as_deref())
    else {
        return Ok(result);
    };
    if model.status == site_status::ACTIVE {
        let bundle =
            assemble_managed_config(tx, std::slice::from_ref(model)).await?;
        result.desired_revision =
            bundle.sites.into_iter().next().map(|s| s.site_revision);
    }
    let epoch = authority_epoch(tx).await?;
    let assignments = agent_sites::Entity::find()
        .filter(agent_sites::Column::SiteId.eq(model.id))
        .order_by_asc(agent_sites::Column::AgentId)
        .all(tx)
        .await?;
    for row in assignments {
        let id = row.agent_id;
        let agent = match authorize(tx, id).await {
            Ok((agent, owner))
                if owner == model.user_id && agent.site_scope == "selected" =>
            {
                agent
            },
            Err(BuildError::Storage(db)) => return Err(db),
            _ => continue,
        };
        let (bound, report) = match current_session(tx, id).await? {
            Some(session) => {
                registry
                    .site_observation(
                        id, session, port, protocol, model.id, epoch,
                    )
                    .await
            },
            None => (None, None),
        };
        let (observed_at, applied_revision, received_revision) = report
            .map(|(at, rev, receipt)| (Some(at), rev, receipt))
            .unwrap_or_default();
        let state = match (
            result.desired_revision.as_ref(),
            applied_revision.as_ref(),
            bound,
            observed_at,
        ) {
            (None, Some(_), _, _) => "revoking",
            (None, None, _, Some(_)) => "withdrawn",
            (Some(want), Some(have), Some(true), _) if want == have => {
                "applied"
            },
            (Some(want), _, _, Some(_))
                if received_revision.as_ref() == Some(want) =>
            {
                "received"
            },
            (_, _, None, _) | (_, _, _, None) => "unknown",
            _ => "pending",
        };
        result.nodes.push(DeploymentNode {
            id,
            name: agent.display_name.unwrap_or(agent.hostname),
            bound,
            observed_at,
            applied_revision,
            state,
        });
    }
    Ok(result)
}

pub(crate) async fn check_site_ingress(
    tx: &DatabaseTransaction,
    agents: &super::AgentRegistry,
    site: &site::Model,
) -> Result<(), crate::api::error::ApiError> {
    if site.ingress_port.is_none() {
        return Ok(());
    }
    let assignments = agent_sites::Entity::find()
        .filter(agent_sites::Column::SiteId.eq(site.id)).all(tx).await?;
    if assignments.is_empty() {
        return Err(unavailable("active custom ingress requires an explicitly assigned agent"));
    }
    for assignment in assignments {
        check_agent_site(tx, agents, assignment.agent_id, site).await?;
    }
    Ok(())
}

pub(crate) async fn check_assigned_ingress(
    tx: &impl ConnectionTrait,
    agents: &super::AgentRegistry,
    site_id: Uuid,
    owner: Uuid,
    port: i32,
    protocol: &str,
    active: bool,
) -> Result<(), crate::api::error::ApiError> {
    let assignments = agent_sites::Entity::find()
        .filter(agent_sites::Column::SiteId.eq(site_id))
        .all(tx)
        .await?;
    if active && assignments.is_empty() {
        return Err(unavailable(
            "active custom ingress requires an explicitly assigned agent",
        ));
    }
    for row in assignments {
        check_agent_ingress(tx, agents, row.agent_id, owner, port, protocol)
            .await?;
    }
    Ok(())
}

async fn visible_sites(
    tx: &DatabaseTransaction,
    row: &agent::Model,
    owner_id: Uuid,
) -> Result<Vec<site::Model>, BuildError> {
    let query = site::Entity::find().filter(site::Column::UserId.eq(owner_id));
    let selected = row.site_scope == "selected";
    let query = match row.site_scope.as_str() {
        "selected" => {
            let ids: Vec<_> = agent_sites::Entity::find()
                .filter(agent_sites::Column::AgentId.eq(row.id))
                .all(tx)
                .await?
                .into_iter()
                .map(|assignment| assignment.site_id)
                .collect();
            if ids.is_empty() {
                return Ok(Vec::new());
            }
            query.filter(site::Column::Id.is_in(ids))
        },
        "all" => {
            let query = query.filter(site::Column::IngressPort.is_null());
            if let Some(id) = row.site_id {
                query.filter(site::Column::Id.eq(id))
            } else {
                query
            }
        },
        _ => return Err(BuildError::Forbidden),
    };
    let mut sites = query
        .order_by_asc(site::Column::Domain)
        .order_by_asc(site::Column::IngressPort)
        .order_by_asc(site::Column::Id)
        .all(tx)
        .await?;
    if selected {
        sites.retain(|row| {
            row.ingress_port.is_none() || row.status == site_status::ACTIVE
        });
    }
    Ok(sites)
}

async fn authority_epoch(tx: &DatabaseTransaction) -> Result<Uuid, DbErr> {
    tx.query_one(Statement::from_string(
        DbBackend::Postgres,
        "SELECT epoch FROM managed_config_authority WHERE id = 1 FOR SHARE",
    ))
    .await?
    .ok_or_else(|| {
        DbErr::Custom("managed configuration authority is missing".into())
    })?
    .try_get_by_index(0)
}

/// Serialize the read-or-create registration for a key/hostname across replicas.
/// A hash collision only serializes unrelated registrations.
pub(super) async fn lock_registration(
    tx: &DatabaseTransaction,
    key_id: Uuid,
    hostname: &str,
) -> Result<(), DbErr> {
    tx.execute(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
        [format!("pingwaf-register:{key_id}:{hostname}").into()],
    ))
    .await?;
    Ok(())
}

pub(super) async fn register_session(
    tx: &DatabaseTransaction,
    agent_id: Uuid,
    session_id: Option<Uuid>,
) -> Result<(), DbErr> {
    let sql = if session_id.is_some() {
        "INSERT INTO managed_config_generations (agent_id, session_id)
         VALUES ($1, $2) ON CONFLICT (agent_id) DO UPDATE SET session_id = $2"
    } else {
        "UPDATE managed_config_generations SET session_id = $2
         WHERE agent_id = $1 AND session_id IS NOT NULL"
    };
    tx.execute(Statement::from_sql_and_values(
        DbBackend::Postgres,
        sql,
        [agent_id.into(), session_id.into()],
    ))
    .await?;
    Ok(())
}

pub(super) async fn current_session(
    db: &impl ConnectionTrait,
    agent_id: Uuid,
) -> Result<Option<Uuid>, DbErr> {
    let row = db.query_one(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT session_id FROM managed_config_generations WHERE agent_id = $1",
        [agent_id.into()],
    ))
    .await?;
    match row {
        Some(row) => row.try_get_by_index(0),
        None => Ok(None),
    }
}

async fn allocate_generation(
    tx: &DatabaseTransaction,
    agent_id: Uuid,
    session_id: Uuid,
) -> Result<i64, BuildError> {
    tx.query_one(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "UPDATE managed_config_generations SET generation = generation + 1
         WHERE agent_id = $1 AND session_id = $2
         RETURNING generation",
        [agent_id.into(), session_id.into()],
    ))
    .await?
    .ok_or(BuildError::Forbidden)?
    .try_get_by_index(0)
    .map_err(Into::into)
}

#[cfg(test)]
pub(super) async fn check_postgres(
    db: &DatabaseConnection,
    service: &super::ControlPlaneService,
    raw_key: &str,
    key_id: Uuid,
    default: &site::Model,
    custom: &site::Model,
) {
    use pingwaf_proto::{
        GetManagedSnapshotRequest, GetSiteConfigRequest,
        MANAGED_PROTOCOL_VERSION, ManagedSiteConfig, RegisterAgentRequest,
        SyncRulesRequest, control_plane_server::ControlPlane,
    };
    use tonic::{Code, Request};

    let register = |version| async move {
        service
            .register_agent(Request::new(RegisterAgentRequest {
                hostname: "managed-test".into(),
                api_key: raw_key.into(),
                managed_protocol_version: version,
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner()
    };
    let fetch = |token: String| async move {
        service
            .get_managed_snapshot(Request::new(GetManagedSnapshotRequest {
                agent_token: token,
            }))
            .await
            .map(tonic::Response::into_inner)
    };
    let unauthorized = register(MANAGED_PROTOCOL_VERSION + 1).await;
    assert_eq!(unauthorized.managed_protocol_version, 0);
    assert_eq!(
        fetch(unauthorized.agent_token.clone())
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );

    let managed = register(MANAGED_PROTOCOL_VERSION).await;
    assert_eq!(managed.managed_protocol_version, MANAGED_PROTOCOL_VERSION);
    assert_eq!(managed.agent_id, unauthorized.agent_id);
    assert!(managed.initial_config.is_none());
    let token = managed.agent_token;
    let id = Uuid::parse_str(&managed.agent_id).unwrap();
    let pull_legacy = |agent_token| async {
        service
            .get_site_config(Request::new(GetSiteConfigRequest {
                agent_token,
                ..Default::default()
            }))
            .await
    };
    assert_eq!(
        pull_legacy(token.clone()).await.unwrap_err().code(),
        Code::FailedPrecondition
    );
    assert_eq!(
        pull_legacy(unauthorized.agent_token)
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    assert_eq!(
        service
            .sync_rules(Request::new(SyncRulesRequest {
                agent_token: token.clone(),
                ..Default::default()
            }))
            .await
            .err()
            .unwrap()
            .code(),
        Code::FailedPrecondition
    );
    let decode = |snapshot: &ManagedSnapshot| {
        assert_eq!(
            snapshot.config_hash,
            hex::encode(Sha256::digest(&snapshot.config))
        );
        assert!(Uuid::parse_str(&snapshot.authority_epoch).is_ok());
        ManagedSiteConfig::decode(snapshot.config.as_slice()).unwrap()
    };
    let first = fetch(token.clone()).await.unwrap();
    assert_eq!(
        first.lease_seconds,
        pingwaf_proto::MAX_MANAGED_LEASE_SECONDS
    );
    let session = Uuid::parse_str(&first.session_id).unwrap();
    assert_eq!(first.session_id, managed.managed_session_id);
    assert_eq!(
        heartbeat_scope(db, id, session).await.unwrap(),
        [default.id]
    );
    assert_eq!(first.generation, 1);
    let config = decode(&first);
    assert_eq!(config.sites.len(), 1);
    assert_eq!(
        config.sites[0].site.as_ref().unwrap().id,
        default.id.to_string()
    );

    // Missing settings behave like the legacy defaults in a read-only
    // transaction. Start that view before another connection changes a row.
    db.execute_unprepared("DELETE FROM cache_settings; DELETE FROM origin_settings; DELETE FROM log_retention_settings;")
        .await.unwrap();
    let read = db
        .begin_with_config(
            Some(IsolationLevel::RepeatableRead),
            Some(sea_orm::AccessMode::ReadOnly),
        )
        .await
        .unwrap();
    let old_rows = visible_sites(
        &read,
        &authorize(&read, id).await.unwrap().0,
        default.user_id,
    )
    .await
    .unwrap();
    db.execute_unprepared("INSERT INTO origin_settings (id, verify_cert, updated_at) VALUES (1, true, now())").await.unwrap();
    let old = assemble_managed_config(&read, &old_rows).await.unwrap();
    let old_bundle =
        old.sites[0].site.as_ref().unwrap().rules.as_ref().unwrap();
    assert_eq!(old_bundle.origin_verify_cert, Some(false));
    assert_eq!(
        old_bundle.global_cache.as_ref().unwrap().max_file_size_mb,
        Some(16)
    );
    assert_eq!(
        old_bundle
            .log_settings
            .as_ref()
            .unwrap()
            .skip_static_access_logs,
        Some(true)
    );
    read.commit().await.unwrap();
    let latest = fetch(token.clone()).await.unwrap();
    assert_eq!(
        decode(&latest).sites[0]
            .site
            .as_ref()
            .unwrap()
            .rules
            .as_ref()
            .unwrap()
            .origin_verify_cert,
        Some(true)
    );

    let exec = |sql: &'static str, values: Vec<sea_orm::Value>| async move {
        db.execute(Statement::from_sql_and_values(
            DbBackend::Postgres,
            sql,
            values,
        ))
        .await
        .unwrap();
    };
    let ready = db
        .begin_with_config(Some(IsolationLevel::RepeatableRead), None)
        .await
        .unwrap();
    assert_eq!(current_session(&ready, id).await.unwrap(), Some(session));
    exec(
        "UPDATE agents SET site_scope = 'selected' WHERE id = $1",
        vec![id.into()],
    )
    .await;
    exec(
        "INSERT INTO agent_sites (agent_id, site_id) VALUES ($1, $2)",
        vec![id.into(), custom.id.into()],
    )
    .await;
    exec(
        "UPDATE sites SET status = 'active' WHERE id = $1",
        vec![custom.id.into()],
    )
    .await;
    let registry = super::AgentRegistry::new();
    let (sender, _rx) = tokio::sync::mpsc::channel(1);
    let (stream, _) = registry.connect_session(id, sender, Some(session)).await;
    let tx = db.begin().await.unwrap();
    assert_eq!(
        check_site_ingress(&tx, &registry, custom)
            .await
            .unwrap_err()
            .code(),
        "site.ingress_unavailable"
    );
    let bound = pingwaf_proto::IngressListeners {
        dynamic_bind: false,
        listeners: vec![pingwaf_proto::IngressListenerStatus {
            port: 81,
            protocol: pingwaf_proto::IngressProtocol::Http as i32,
            state: pingwaf_proto::IngressBindState::Bound as i32,
        }],
    };
    assert!(
        ingress_agent_options(&tx, &registry, custom.user_id)
            .await
            .unwrap()
            .is_empty()
    );
    registry.record_ingress(id, stream, Some(&bound)).await;
    let options = ingress_agent_options(&tx, &registry, custom.user_id)
        .await
        .unwrap();
    assert_eq!(options.len(), 1);
    assert_eq!(options[0].id, id);
    assert_eq!(options[0].listeners, [(81, "http")]);
    assert!(
        ingress_agent_options(&tx, &registry, Uuid::new_v4())
            .await
            .unwrap()
            .is_empty()
    );
    check_site_ingress(&tx, &registry, custom).await.unwrap();
    assert!(
        check_agent_ingress(&tx, &registry, id, custom.user_id, 81, "https")
            .await
            .is_err()
    );
    let stored = site::Entity::find_by_id(custom.id)
        .one(&tx)
        .await
        .unwrap()
        .unwrap();
    let initial = site_deployment(&tx, &registry, &stored).await.unwrap();
    assert_eq!(initial.nodes.len(), 1);
    assert_eq!(initial.nodes[0].state, "unknown");
    let wanted = initial.desired_revision.unwrap();
    let mut report = pingwaf_proto::ManagedApplyReport {
        received_sites: Vec::new(),
        session_id: session.to_string(),
        authority_epoch: first.authority_epoch.clone(),
        generation: 1,
        sites: vec![pingwaf_proto::ManagedSiteApplication {
            site_id: custom.id.to_string(),
            site_revision: wanted.clone(),
            ingress: Some(pingwaf_proto::SiteIngress {
                port: 81,
                protocol: pingwaf_proto::IngressProtocol::Http as i32,
            }),
        }],
    };
    for (epoch, revision, state) in [
        (first.authority_epoch.clone(), wanted.clone(), "applied"),
        (first.authority_epoch.clone(), "ff".repeat(32), "pending"),
        (Uuid::new_v4().to_string(), wanted.clone(), "unknown"),
    ] {
        report.authority_epoch = epoch;
        report.sites[0].site_revision = revision;
        registry
            .record_application(
                id,
                stream,
                Some(session),
                &[custom.id],
                Some(&report),
            )
            .await;
        let view = site_deployment(&tx, &registry, &stored).await.unwrap();
        assert_eq!(view.nodes[0].state, state);
        assert_eq!(view.nodes[0].bound, Some(true));
    }
    report.authority_epoch = first.authority_epoch.clone();
    report.sites[0].site_revision = wanted.clone();
    report.received_sites = std::mem::take(&mut report.sites);
    registry
        .record_application(
            id,
            stream,
            Some(session),
            &[custom.id],
            Some(&report),
        )
        .await;
    let received = site_deployment(&tx, &registry, &stored).await.unwrap();
    assert_eq!(received.nodes[0].state, "received");
    assert!(received.nodes[0].applied_revision.is_none());
    let (sender, _rx) = tokio::sync::mpsc::channel(1);
    let (replacement, _) = registry
        .connect_session(id, sender, Some(Uuid::new_v4()))
        .await;
    registry.record_ingress(id, replacement, Some(&bound)).await;
    assert!(
        ingress_agent_options(&tx, &registry, custom.user_id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(check_site_ingress(&tx, &registry, custom).await.is_err());
    tx.commit().await.unwrap();
    let assigned = fetch(token.clone()).await.unwrap();
    assert_eq!(heartbeat_scope(db, id, session).await.unwrap(), [custom.id]);
    let row = service.authorize(&token).await.unwrap();
    assert!(
        service
            .legacy_delivery_sites(&row)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(assigned.generation > latest.generation);
    assert_eq!(assigned.authority_epoch, first.authority_epoch);
    let config = decode(&assigned);
    let repeated = fetch(token.clone()).await.unwrap();
    assert_eq!(config.sites[0].site_revision, wanted);
    assert_eq!(config.sites[0].site_revision.len(), 64);
    assert_eq!(
        config.sites[0].site_revision,
        decode(&repeated).sites[0].site_revision
    );
    assert_eq!(config.sites.len(), 1);
    assert_eq!(config.sites[0].ingress.as_ref().unwrap().port, 81);
    let site = config.sites[0].site.as_ref().unwrap();
    assert_eq!(site.id, custom.id.to_string());
    assert!(site.rules.as_ref().unwrap().site_policies.is_empty());
    super::visitor_auth::check_managed_password_postgres(
        service, &token, raw_key, id, default, custom,
    )
    .await;
    let Err(BuildError::Storage(stale)) =
        build_in_view(&ready, id, session).await
    else {
        panic!("a stale view must not get a generation after newer content");
    };
    assert!(is_serialization_failure(&stale), "{stale}");
    ready.rollback().await.unwrap();

    // Inject a storage error after authorization. No partial bundle or new
    // generation can leave the transaction.
    db.execute_unprepared(
        "ALTER TABLE origin_settings RENAME TO origin_settings_test_hidden",
    )
    .await
    .unwrap();
    let failed = fetch(token.clone()).await.unwrap_err();
    db.execute_unprepared(
        "ALTER TABLE origin_settings_test_hidden RENAME TO origin_settings",
    )
    .await
    .unwrap();
    assert_eq!(failed.code(), Code::Internal);
    exec(
        "UPDATE sites SET status = 'paused' WHERE id = $1",
        vec![custom.id.into()],
    )
    .await;
    let revoked = fetch(token.clone()).await.unwrap();
    assert!(heartbeat_scope(db, id, session).await.unwrap().is_empty());
    assert_eq!(revoked.generation, repeated.generation + 1);
    assert!(decode(&revoked).sites.is_empty());
    exec(
        "UPDATE api_keys SET expires_at = now() WHERE id = $1",
        vec![key_id.into()],
    )
    .await;
    assert_eq!(
        fetch(token.clone()).await.unwrap_err().code(),
        Code::PermissionDenied
    );
    exec(
        "UPDATE api_keys SET expires_at = NULL WHERE id = $1",
        vec![key_id.into()],
    )
    .await;

    let next = register(MANAGED_PROTOCOL_VERSION).await;
    assert_eq!(next.agent_id, id.to_string());
    assert_eq!(
        heartbeat_scope(db, id, session).await.unwrap_err().code(),
        Code::PermissionDenied
    );
    assert_eq!(
        service.authorize(&token).await.unwrap_err().code(),
        Code::PermissionDenied
    );
    assert_eq!(
        fetch(token).await.unwrap_err().code(),
        Code::PermissionDenied
    );
    let renewed = fetch(next.agent_token.clone()).await.unwrap();
    assert_ne!(renewed.session_id, first.session_id);
    assert_eq!(renewed.generation, revoked.generation + 1);
    check_stream(db, id, &next.agent_token, &register).await;
    assert_eq!(
        fetch(next.agent_token).await.unwrap_err().code(),
        Code::PermissionDenied
    );
}

#[cfg(test)]
async fn check_stream<F, Fut>(
    db: &DatabaseConnection,
    id: Uuid,
    agent_token: &str,
    register: &F,
) where
    F: Fn(u32) -> Fut,
    Fut: std::future::Future<Output = pingwaf_proto::RegisterAgentResponse>,
{
    use pingwaf_proto::{
        AgentHeartbeat, control_plane_client::ControlPlaneClient,
        control_plane_server::ControlPlaneServer, server_command::Payload,
    };
    use tokio::{
        net::TcpListener,
        sync::mpsc,
        time::{Duration, timeout},
    };
    use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};

    // A separate service and registry share only the database with the
    // registration endpoint. The network namespace only has loopback.
    let stream_registry = super::AgentRegistry::new();
    let service = super::ControlPlaneService::new(
        db.clone(),
        std::sync::Arc::new(crate::config::ServerConfig::default()),
        stream_registry.clone(),
        None,
        super::CacheStatusRegistry::new(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(ControlPlaneServer::new(service))
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    let result = timeout(Duration::from_secs(8), async {
        let mut client = ControlPlaneClient::connect(endpoint).await.unwrap();
        let heartbeat = AgentHeartbeat {
            agent_id: id.to_string(),
            agent_token: agent_token.into(),
            config_hash: "not-an-applied-snapshot".into(),
            last_config_sync_at: super::config::now_timestamp(),
            ..Default::default()
        };
        let (tx, rx) = mpsc::channel(1);
        tx.send(heartbeat.clone()).await.unwrap();
        let mut stream = client
            .heartbeat(ReceiverStream::new(rx))
            .await
            .unwrap()
            .into_inner();
        assert!(
            super::repush_agent_config(db, &stream_registry, id)
                .await
                .unwrap()
        );
        assert!(matches!(
            stream.message().await.unwrap().unwrap().payload,
            Some(Payload::ManagedConfigChanged(_))
        ));
        let legacy = register(0).await;
        assert_eq!(legacy.agent_id, id.to_string());
        assert!(legacy.managed_session_id.is_empty());
        assert!(legacy.initial_config.is_some());
        tx.send(heartbeat).await.unwrap();
        assert!(stream.message().await.unwrap().is_none());
        assert!(!stream_registry.is_connected(&id).await);
        let row = agent::Entity::find_by_id(id)
            .one(db)
            .await
            .unwrap()
            .unwrap();
        assert!(row.config_hash.is_none());
        assert!(row.last_config_sync_at.is_none());
    })
    .await;
    server.abort();
    result.expect("managed stream round trip timed out");
}
