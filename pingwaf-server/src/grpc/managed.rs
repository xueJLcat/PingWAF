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
    agent, agent_sites, api_key, role, site, site_status, user,
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
    tx: &DatabaseTransaction,
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
        control_plane_server::ControlPlane, GetManagedSnapshotRequest,
        GetSiteConfigRequest, ManagedSiteConfig, RegisterAgentRequest,
        SyncRulesRequest, MANAGED_PROTOCOL_VERSION,
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
    let assigned = fetch(token.clone()).await.unwrap();
    assert_eq!(heartbeat_scope(db, id, session).await.unwrap(), [custom.id]);
    let row = service.authorize(&token).await.unwrap();
    assert!(service
        .legacy_delivery_sites(&row)
        .await
        .unwrap()
        .is_empty());
    assert!(assigned.generation > latest.generation);
    assert_eq!(assigned.authority_epoch, first.authority_epoch);
    let config = decode(&assigned);
    assert_eq!(config.sites.len(), 1);
    assert_eq!(config.sites[0].ingress.as_ref().unwrap().port, 81);
    let site = config.sites[0].site.as_ref().unwrap();
    assert_eq!(site.id, custom.id.to_string());
    assert!(site.rules.as_ref().unwrap().site_policies.is_empty());
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
    assert_eq!(revoked.generation, assigned.generation + 1);
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
        control_plane_client::ControlPlaneClient,
        control_plane_server::ControlPlaneServer, server_command::Payload,
        AgentHeartbeat,
    };
    use tokio::{
        net::TcpListener,
        sync::mpsc,
        time::{timeout, Duration},
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
        assert!(super::repush_agent_config(db, &stream_registry, id)
            .await
            .unwrap());
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
