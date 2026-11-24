use super::{common, error::ApiError, state::AppState};
use crate::auth::AuthUser;
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, post},
};
use sea_orm::{ConnectionTrait, DbBackend, Statement, TransactionTrait};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/sites/{id}/integrity", get(list).post(create))
        .route("/sites/{id}/integrity/{rule}", get(preview).delete(revoke))
        .route("/sites/{id}/integrity/{rule}/approve", post(approve))
        .route("/sites/{id}/integrity/{rule}/dynamic", post(dynamic))
        .route("/sites/{id}/dynamic/disable", post(disable_dynamic))
}

#[derive(Deserialize)]
struct NewRule {
    path: String,
}

#[derive(Deserialize)]
struct Approval {
    digest: String,
    content_type: String,
    mode: String,
}

async fn list(
    State(s): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<Value>>, ApiError> {
    common::load_site_read(&s.db, id, &user).await?;
    let rows = s.db.query_all(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT jsonb_build_object('id',id,'path',path,'mode',mode,'active_version',active_version,
         'candidate_digest',candidate_digest,'candidate_at',candidate_at) FROM page_integrity_rules WHERE site_id=$1 ORDER BY path",
        [id.into()])).await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| row.try_get_by_index(0))
            .collect::<Result<_, _>>()?,
    ))
}

async fn create(
    State(s): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<NewRule>,
) -> Result<Json<Uuid>, ApiError> {
    common::require_write(&user)?;
    let site = common::load_site_write(&s.db, id, &user).await?;
    if site.ingress_port.is_none()
        || site
            .site_handler
            .as_ref()
            .is_some_and(|handler| handler["kind"] == "redirect")
    {
        return Err(ApiError::BadRequest(
            "select a managed proxy or static site with a listening port"
                .into(),
        ));
    }
    if !body.path.starts_with('/')
        || body.path.len() > 2048
        || body.path.contains(['?', '#', '*', '\\'])
        || body.path.contains("//")
        || body.path.bytes().any(|c| c.is_ascii_control() || c == b' ')
        || body.path.split('/').any(|part| matches!(part, "." | ".."))
    {
        return Err(ApiError::BadRequest(
            "expected an exact resource path".into(),
        ));
    }
    let rule = Uuid::new_v4();
    let tx = s.db.begin().await?;
    tx.query_one(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT id FROM sites WHERE id=$1 FOR UPDATE",
        [id.into()],
    ))
    .await?
    .ok_or_else(|| ApiError::NotFound("site not found".into()))?;
    let count = tx
        .query_one(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT count(*) FROM page_integrity_rules WHERE site_id=$1",
            [id.into()],
        ))
        .await?
        .ok_or_else(|| ApiError::Conflict("site unavailable".into()))?
        .try_get_by_index::<i64>(0)?;
    if count >= 32 {
        return Err(ApiError::BadRequest(
            "site limit of 32 protected paths reached".into(),
        ));
    }
    let row=tx.execute(Statement::from_sql_and_values(DbBackend::Postgres,
        "INSERT INTO page_integrity_rules(id,site_id,path) VALUES($1,$2,$3) ON CONFLICT(site_id,path) DO NOTHING",
        [rule.into(),id.into(),body.path.into()])).await?;
    if row.rows_affected() == 0 {
        return Err(ApiError::Conflict("path already registered".into()));
    }
    tx.commit().await?;
    crate::grpc::notify_config_changed(&s, id, Some(&user.email)).await;
    Ok(Json(rule))
}

async fn preview(
    State(s): State<AppState>,
    user: AuthUser,
    Path((id, rule)): Path<(Uuid, Uuid)>,
) -> Result<Json<Value>, ApiError> {
    common::load_site_read(&s.db, id, &user).await?;
    let row=s.db.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT jsonb_build_object('path',r.path,'mode',r.mode,'candidate_digest',r.candidate_digest,
         'dynamic_stage',r.dynamic_stage,'dynamic_region',r.dynamic_region,'candidate_type',r.candidate_type,'candidate_base64',encode(r.candidate_body,'base64'),
         'active_version',r.active_version,'approved_type',v.content_type,'approved_digest',v.digest,
         'approved_base64',encode(v.body,'base64'),'approved_at',v.approved_at,'approved_by',v.approved_by,
         'events',(SELECT coalesce(jsonb_agg(to_jsonb(e)-'rule_id'),'[]'::jsonb) FROM
           (SELECT * FROM page_integrity_events WHERE rule_id=r.id ORDER BY last_seen DESC LIMIT 100) e))
         FROM page_integrity_rules r LEFT JOIN page_integrity_versions v ON (v.rule_id,v.version)=(r.id,r.active_version)
         WHERE r.site_id=$1 AND r.id=$2", [id.into(),rule.into()])).await?
        .ok_or_else(|| ApiError::NotFound("rule not found".into()))?;
    Ok(Json(row.try_get_by_index(0)?))
}

async fn approve(
    State(s): State<AppState>,
    user: AuthUser,
    Path((id, rule)): Path<(Uuid, Uuid)>,
    Json(body): Json<Approval>,
) -> Result<Json<i64>, ApiError> {
    common::require_write(&user)?;
    if !matches!(body.mode.as_str(), "alert" | "trusted_copy") {
        return Err(ApiError::BadRequest("invalid mode".into()));
    }
    let tx = s.db.begin().await?;
    common::load_site_write(&tx, id, &user).await?;
    let row=tx.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT candidate_body,candidate_digest,candidate_type,coalesce(active_version,0)+1 AS version FROM page_integrity_rules
         WHERE site_id=$1 AND id=$2 FOR UPDATE",[id.into(),rule.into()])).await?.ok_or_else(||ApiError::NotFound("rule not found".into()))?;
    let bytes: Option<Vec<u8>> = row.try_get("", "candidate_body")?;
    let bytes = bytes
        .ok_or_else(|| ApiError::Conflict("awaiting public resource".into()))?;
    let digest: String = row.try_get("", "candidate_digest")?;
    let content_type: String = row.try_get("", "candidate_type")?;
    if body.digest != digest
        || body.content_type != content_type
        || pingwaf_content::protection::body_digest(&bytes) != digest
    {
        return Err(ApiError::Conflict(
            "candidate changed; preview again".into(),
        ));
    }
    let version: i64 = row.try_get("", "version")?;
    tx.execute(Statement::from_sql_and_values(DbBackend::Postgres,
        "INSERT INTO page_integrity_versions(rule_id,version,digest,content_type,body,approved_by) VALUES($1,$2,$3,$4,$5,$6)",
        [rule.into(),version.into(),digest.into(),content_type.into(),bytes.into(),user.id.into()])).await?;
    tx.execute(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "UPDATE page_integrity_rules SET active_version=$2,mode=$3 WHERE id=$1",
        [rule.into(), version.into(), body.mode.into()],
    ))
    .await?;
    tx.commit().await?;
    crate::grpc::notify_config_changed(&s, id, Some(&user.email)).await;
    Ok(Json(version))
}

async fn revoke(
    State(s): State<AppState>,
    user: AuthUser,
    Path((id, rule)): Path<(Uuid, Uuid)>,
) -> Result<axum::http::StatusCode, ApiError> {
    common::require_write(&user)?;
    common::load_site_write(&s.db, id, &user).await?;
    let row =
        s.db.execute(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "DELETE FROM page_integrity_rules WHERE site_id=$1 AND id=$2",
            [id.into(), rule.into()],
        ))
        .await?;
    if row.rows_affected() == 0 {
        return Err(ApiError::NotFound("rule not found".into()));
    }
    crate::grpc::notify_config_changed(&s, id, Some(&user.email)).await;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm_migration::MigratorTrait;

    #[tokio::test]
    #[ignore = "requires a fresh disposable PostgreSQL database"]
    async fn integrity_approval_postgres() {
        let db = sea_orm::Database::connect(
            std::env::var("PINGWAF_TEST_DATABASE_URL").unwrap(),
        )
        .await
        .unwrap();
        let empty = db.query_one(Statement::from_string(DbBackend::Postgres,
            "SELECT to_regclass('seaql_migrations') IS NULL AND to_regclass('sites') IS NULL")).await.unwrap().unwrap();
        assert!(empty.try_get_by_index::<bool>(0).unwrap());
        crate::migration::Migrator::up(&db, None).await.unwrap();
        let admin =
            AuthUser::new(Uuid::new_v4(), "review@example.test", "admin");
        let site = Uuid::new_v4();
        db.execute(Statement::from_sql_and_values(DbBackend::Postgres,
            "INSERT INTO users(id,email,password_hash,created_at,updated_at) VALUES($1,$2,'unused',now(),now())",
            [admin.id.into(),admin.email.clone().into()])).await.unwrap();
        db.execute(Statement::from_sql_and_values(DbBackend::Postgres,
            "INSERT INTO sites(id,user_id,name,domain,ingress_protocol,ingress_port,created_at,updated_at) VALUES($1,$2,'test','review.example.test','http',18815,now(),now())",
            [site.into(),admin.id.into()])).await.unwrap();
        let state = State(AppState::new(
            db.clone(),
            Default::default(),
            crate::grpc::AgentRegistry::new(),
        ));
        let rule = create(
            state.clone(),
            admin.clone(),
            Path(site),
            Json(NewRule {
                path: "/index.html".into(),
            }),
        )
        .await
        .unwrap()
        .0;
        let body = b"approved".to_vec();
        let digest = pingwaf_content::protection::body_digest(&body);
        db.execute(Statement::from_sql_and_values(DbBackend::Postgres,
            "UPDATE page_integrity_rules SET candidate_digest=$2,candidate_body=$3,candidate_type='text/html' WHERE id=$1",
            [rule.into(),digest.clone().into(),body.into()])).await.unwrap();
        let choose = |digest: String| {
            Json(Approval {
                digest,
                content_type: "text/html".into(),
                mode: "trusted_copy".into(),
            })
        };
        assert!(matches!(
            approve(
                state.clone(),
                admin.clone(),
                Path((site, rule)),
                choose("stale".into())
            )
            .await,
            Err(ApiError::Conflict(_))
        ));
        assert_eq!(
            approve(
                state.clone(),
                admin.clone(),
                Path((site, rule)),
                choose(digest.clone())
            )
            .await
            .unwrap()
            .0,
            1
        );
        let outsider =
            AuthUser::new(Uuid::new_v4(), "other@example.test", "viewer");
        assert!(matches!(
            preview(state.clone(), outsider, Path((site, rule))).await,
            Err(ApiError::NotFound(_))
        ));
        assert_eq!(
            preview(state.clone(), admin.clone(), Path((site, rule)))
                .await
                .unwrap()
                .0["approved_digest"],
            digest
        );
        revoke(state.clone(), admin.clone(), Path((site, rule)))
            .await
            .unwrap();
        assert!(list(state, admin, Path(site)).await.unwrap().0.is_empty());
        crate::migration::Migrator::down(&db, Some(1))
            .await
            .unwrap();
    }
}

#[derive(Deserialize)]
struct DynamicSelection {
    stage: String,
    region: String,
    digest: String,
}

async fn dynamic(
    State(s): State<AppState>,
    user: AuthUser,
    Path((site, rule)): Path<(Uuid, Uuid)>,
    Json(input): Json<DynamicSelection>,
) -> Result<Json<Value>, ApiError> {
    common::require_write(&user)?;
    common::load_site_write(&s.db, site, &user).await?;
    let tx = s.db.begin().await?;
    let row = tx.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT dynamic_stage,dynamic_region,dynamic_preview_digest,candidate_digest,candidate_body,candidate_type FROM page_integrity_rules WHERE site_id=$1 AND id=$2 FOR UPDATE",
        [site.into(),rule.into()])).await?.ok_or_else(||ApiError::NotFound("page not found".into()))?;
    let mut token = None;
    let mut token_digest = String::new();
    if input.stage != "off" {
        let digest: Option<String> = row.try_get("", "candidate_digest")?;
        let media: Option<String> = row.try_get("", "candidate_type")?;
        if digest.as_deref() != Some(&input.digest)
            || !media.as_deref().is_some_and(|m| {
                m.split(';')
                    .next()
                    .is_some_and(|t| t.trim().eq_ignore_ascii_case("text/html"))
            })
        {
            return Err(ApiError::Conflict(
                "refresh the public HTML preview".into(),
            ));
        }
        let body: Vec<u8> = row.try_get("", "candidate_body")?;
        let preview = pingwaf_content::dynamic::transform(&body, &input.region)
            .map_err(|reason| ApiError::BadRequest(reason.into()))?;
        match input.stage.as_str() {
            "preview" => {
                return Ok(Json(
                    serde_json::json!({"html":String::from_utf8_lossy(&preview),"digest":digest}),
                ));
            },
            "test" => {
                let secret = Uuid::new_v4().to_string();
                token_digest =
                    pingwaf_content::protection::body_digest(secret.as_bytes());
                token = Some(secret);
            },
            "live"
                if row.try_get::<String>("", "dynamic_stage")? == "test"
                    && row.try_get::<String>("", "dynamic_region")?
                        == input.region
                    && row
                        .try_get::<String>("", "dynamic_preview_digest")?
                        == input.digest => {},
            _ => {
                return Err(ApiError::Conflict(
                    "test this region before publication".into(),
                ));
            },
        }
    }
    tx.execute(Statement::from_sql_and_values(DbBackend::Postgres,
        "UPDATE page_integrity_rules SET dynamic_stage=$3,dynamic_region=$4,dynamic_test_digest=$5,dynamic_preview_digest=$6 WHERE site_id=$1 AND id=$2",
        [site.into(),rule.into(),input.stage.into(),input.region.into(),token_digest.into(),input.digest.into()])).await?;
    tx.commit().await?;
    crate::grpc::notify_config_changed(&s, site, Some(&user.email)).await;
    Ok(Json(serde_json::json!({"test_token":token})))
}

async fn disable_dynamic(
    State(s): State<AppState>,
    user: AuthUser,
    Path(site): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    common::require_write(&user)?;
    common::load_site_write(&s.db, site, &user).await?;
    s.db.execute(Statement::from_sql_and_values(DbBackend::Postgres,
        "UPDATE page_integrity_rules SET dynamic_stage='off',dynamic_test_digest='' WHERE site_id=$1 AND dynamic_stage<>'off'",[site.into()])).await?;
    crate::grpc::notify_config_changed(&s, site, Some(&user.email)).await;
    Ok(Json(serde_json::json!({"disabled":true})))
}
