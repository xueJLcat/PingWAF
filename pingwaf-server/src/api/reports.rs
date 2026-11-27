use super::{error::ApiError, state::AppState};
use crate::auth::AuthUser;
use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, StatusCode},
    response::Response,
    routing::{delete, get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use sea_orm::{ConnectionTrait, DbBackend, Statement, TransactionTrait};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};
use uuid::Uuid;

mod export;
mod snapshot;
#[cfg(test)]
mod tests;
mod worker;
pub(crate) use worker::start;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Selection {
    pub sites: Vec<Uuid>,
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    pub timezone: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct MetricRow {
    site: Uuid,
    domain: String,
    bucket: DateTime<Utc>,
    local_time: String,
    requests: Option<i64>,
    blocked: Option<i64>,
    challenged: Option<i64>,
    covered: bool,
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Node {
    id: Uuid,
    name: String,
    heartbeat: Option<DateTime<Utc>>,
    online: bool,
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Snapshot {
    selection: Selection,
    generated_at: DateTime<Utc>,
    metrics: Vec<MetricRow>,
    categories: Vec<(String, i64)>,
    nodes: Vec<Node>,
}

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/reports", get(list).post(create))
        .route("/reports/{id}", delete(remove))
        .route("/reports/{id}/{format}", get(download))
        .route("/reports/live", post(live))
}

async fn remove(State(s): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> Result<StatusCode, ApiError> {
    super::common::require_write(&user)?;
    let result = s.db.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "DELETE FROM protection_reports WHERE id=$1 AND owner_id=$2 AND status IN ('ready','failed')",
        [id.into(), user.id.into()])).await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("completed report not available".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn create(
    State(s): State<AppState>,
    user: AuthUser,
    Json(mut selection): Json<Selection>,
) -> Result<Json<Uuid>, ApiError> {
    selection.sites.sort_unstable();
    selection.sites.dedup();
    let tx = s.db.begin().await?;
    snapshot::scope(&tx, &user, &selection).await?;
    tx.execute_unprepared("SELECT pg_advisory_xact_lock(74511631)")
        .await?;
    let id = Uuid::new_v4();
    let row=tx.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "INSERT INTO protection_reports(id,owner_id,selection) SELECT $1,$2,$3 WHERE
         (SELECT count(*) FROM protection_reports WHERE owner_id=$2 AND status IN ('running','queued'))<3
         AND (SELECT count(*) FROM protection_reports WHERE expires_at>now())<64",
        [id.into(),user.id.into(),json!(selection).into()])).await?;
    if row.rows_affected() == 0 {
        return Err(ApiError::Conflict(
            "report queue or storage quota reached".into(),
        ));
    }
    tx.commit().await?;
    Ok(Json(id))
}

async fn list(
    State(s): State<AppState>,
    user: AuthUser,
) -> Result<Json<Vec<Value>>, ApiError> {
    let rows=s.db.query_all_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT jsonb_build_object('id',id,'created_at',created_at,'expires_at',expires_at,'status',status,'error',error,
         'from',selection->'from','to',selection->'to','timezone',selection->'timezone')
         FROM protection_reports WHERE owner_id=$1 AND expires_at>now() ORDER BY created_at DESC LIMIT 64",[user.id.into()])).await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| r.try_get_by_index(0))
            .collect::<Result<_, _>>()?,
    ))
}

async fn download(
    State(s): State<AppState>,
    user: AuthUser,
    Path((id, format)): Path<(Uuid, String)>,
) -> Result<Response, ApiError> {
    let (column, mime) = match format.as_str() {
        "pdf" => ("pdf", "application/pdf"),
        "csv" => ("csv", "text/csv; charset=utf-8"),
        _ => return Err(ApiError::NotFound("unknown format".into())),
    };
    let tx =
        s.db.begin_with_config(
            Some(sea_orm::IsolationLevel::RepeatableRead),
            Some(sea_orm::AccessMode::ReadOnly),
        )
        .await?;
    let row=tx.query_one_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        format!("SELECT selection,{column} AS body FROM protection_reports WHERE id=$1 AND owner_id=$2 AND expires_at>now() AND status='ready'"),
        [id.into(),user.id.into()])).await?.ok_or_else(||ApiError::NotFound("report not available".into()))?;
    let selection: Selection = serde_json::from_value(
        row.try_get("", "selection")?,
    )
    .map_err(|_| ApiError::Internal("invalid stored selection".into()))?;
    snapshot::scope(&tx, &user, &selection).await?;
    let bytes: Vec<u8> = row.try_get("", "body")?;
    tx.commit().await?;
    Response::builder()
        .header(header::CONTENT_TYPE, mime)
        .header(header::CACHE_CONTROL, "private, no-store")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"pingwaf-{id}.{format}\""),
        )
        .body(Body::from(bytes))
        .map_err(|_| ApiError::Internal("download response".into()))
}

#[derive(Deserialize)]
struct LiveRequest {
    sites: Vec<Uuid>,
    timezone: String,
}
type Cache = BTreeMap<(Vec<Uuid>, String), (Instant, Arc<Snapshot>)>;
#[derive(Clone, Default)]
pub(crate) struct LiveCache(Arc<tokio::sync::Mutex<Cache>>);

async fn live(
    State(s): State<AppState>,
    user: AuthUser,
    Json(mut input): Json<LiveRequest>,
) -> Result<Json<Snapshot>, ApiError> {
    input.sites.sort_unstable();
    input.sites.dedup();
    let now = Utc::now();
    let selection = Selection {
        sites: input.sites,
        timezone: input.timezone,
        from: now - chrono::Duration::minutes(15),
        to: now,
    };
    let tx = s.db.begin().await?;
    snapshot::scope(&tx, &user, &selection).await?;
    tx.commit().await?;
    let key = (selection.sites.clone(), selection.timezone.clone());
    let mut cache = s.live_reports.0.lock().await;
    cache.retain(|_, (age, _)| age.elapsed() < Duration::from_secs(15));
    if let Some((_, value)) = cache.get(&key) {
        return Ok(Json((**value).clone()));
    }
    let value = snapshot::collect(&s.db, &user, selection, true).await?;
    if cache.len() < 32 {
        cache.insert(key, (Instant::now(), Arc::new(value.clone())));
    }
    Ok(Json(value))
}
