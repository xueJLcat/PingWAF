//! Owner-scoped static site drafts. No archive entry is written to the filesystem.
use super::{common::require_write, error::ApiError, state::AppState};
use crate::auth::AuthUser;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use sea_orm::{ConnectionTrait, DbBackend, Statement, TransactionTrait};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read};
use uuid::Uuid;
use zip::ZipArchive;

use pingwaf_content::{MAX_EXPANDED, MAX_UPLOAD};
static ARCHIVE_WORKERS: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(2);

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/static-drafts",
            post(upload).layer(DefaultBodyLimit::max(MAX_UPLOAD)),
        )
        .route("/static-drafts/{id}", delete(discard))
        .route("/static-drafts/{id}/preview-session", post(preview_session))
        .route("/draft-preview/{id}/{ticket}/{*path}", get(preview_asset))
        .route("/sites/{id}/static-versions", get(versions))
        .route("/static-drafts/{id}/preview/{*path}", get(preview))
}

#[derive(Serialize)]
struct Version {
    digest: String,
    published_at: chrono::DateTime<chrono::Utc>,
}

async fn versions(
    State(state): State<AppState>,
    current: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<Version>>, ApiError> {
    super::common::load_site(&state.db, id, &current, false).await?;
    let rows = state.db.query_all(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT digest,published_at FROM static_releases WHERE site_id=$1 ORDER BY published_at DESC,digest", [id.into()])).await?;
    let mut versions = Vec::with_capacity(rows.len());
    for row in rows {
        versions.push(Version {
            digest: row.try_get("", "digest")?,
            published_at: row.try_get("", "published_at")?,
        });
    }
    Ok(Json(versions))
}

/// Bind an owner's unexpired upload to a site inside its configuration write.
/// A rollback without a draft can reference only content already owned by this site.
pub(super) async fn bind_version(
    tx: &sea_orm::DatabaseTransaction,
    site: Uuid,
    owner: Uuid,
    handler: Option<&serde_json::Value>,
    draft: Option<Uuid>,
) -> Result<(), ApiError> {
    let digest = handler
        .filter(|handler| handler["kind"] == "zip")
        .and_then(|handler| handler["digest"].as_str());
    let Some(digest) = digest else {
        return if draft.is_none() {
            Ok(())
        } else {
            Err(invalid("upload requires a ZIP site"))
        };
    };
    if let Some(id) = draft {
        let moved = tx.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
            "WITH content AS (DELETE FROM static_drafts WHERE id=$1 AND owner_id=$2 AND digest=$3 AND expires_at>now()
                RETURNING digest,archive)
             INSERT INTO static_releases(site_id,digest,archive) SELECT $4,digest,archive FROM content
             ON CONFLICT(site_id,digest) DO UPDATE SET published_at=now() RETURNING digest",
            [id.into(), owner.into(), digest.into(), site.into()])).await?;
        if moved.is_none() {
            return Err(invalid("upload expired or inaccessible"));
        }
    } else if tx
        .query_one(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT 1 FROM static_releases WHERE site_id=$1 AND digest=$2",
            [site.into(), digest.into()],
        ))
        .await?
        .is_none()
    {
        return Err(invalid("unknown site version"));
    }
    Ok(())
}

#[derive(Serialize)]
struct Draft {
    id: Uuid,
    sha256: String,
    files: Vec<String>,
}

fn invalid(message: &str) -> ApiError {
    ApiError::BadRequest(message.to_owned())
}

fn check_archive(input: &[u8]) -> Result<Vec<String>, ApiError> {
    pingwaf_content::inspect(input, None)
        .map_err(|err| invalid(&err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::{ZipWriter, write::SimpleFileOptions};

    fn bundle(files: &[&str]) -> Vec<u8> {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        for name in files {
            writer
                .start_file(*name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(b"test").unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    #[tokio::test]
    #[ignore = "requires a fresh disposable PostgreSQL database"]
    async fn draft_lifecycle_postgres() {
        use sea_orm_migration::MigratorTrait;
        let db = sea_orm::Database::connect(
            std::env::var("PINGWAF_TEST_DATABASE_URL").unwrap(),
        )
        .await
        .unwrap();
        let row = db.query_one(Statement::from_string(DbBackend::Postgres, "SELECT to_regclass('users') IS NULL AND to_regclass('seaql_migrations') IS NULL AS fresh")).await.unwrap().unwrap();
        assert!(row.try_get::<bool>("", "fresh").unwrap());
        crate::migration::Migrator::up(&db, None).await.unwrap();
        let state = AppState::new(
            db.clone(),
            Default::default(),
            crate::grpc::AgentRegistry::new(),
        );
        let owner =
            AuthUser::new(Uuid::new_v4(), "draft@example.test", "admin");
        let other =
            AuthUser::new(Uuid::new_v4(), "other@example.test", "admin");
        db.execute(Statement::from_sql_and_values(DbBackend::Postgres,
            "INSERT INTO users(id,email,password_hash,created_at,updated_at) VALUES($1,$2,'unused',now(),now())",
            [owner.id.into(), owner.email.clone().into()])).await.unwrap();
        let bytes = Bytes::from(bundle(&["index.html"]));
        let draft = upload(State(state.clone()), owner.clone(), bytes.clone())
            .await
            .unwrap()
            .0;
        let entry = (draft.id, String::from("index.html"));
        assert!(matches!(
            preview(State(state.clone()), other.clone(), Path(entry.clone()))
                .await,
            Err(ApiError::NotFound(_))
        ));
        discard(State(state.clone()), other, Path(draft.id))
            .await
            .unwrap();
        let response =
            preview(State(state.clone()), owner.clone(), Path(entry.clone()))
                .await
                .unwrap();
        assert!(
            response.headers()["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("sandbox")
        );
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 4)
                .await
                .unwrap()
                .as_ref(),
            b"test"
        );
        for _ in 1..4 {
            let _ = upload(State(state.clone()), owner.clone(), bytes.clone())
                .await
                .unwrap();
        }
        assert!(matches!(
            upload(State(state.clone()), owner.clone(), bytes.clone()).await,
            Err(ApiError::Conflict(_))
        ));
        discard(State(state.clone()), owner.clone(), Path(draft.id))
            .await
            .unwrap();
        assert!(matches!(
            preview(State(state.clone()), owner.clone(), Path(entry)).await,
            Err(ApiError::NotFound(_))
        ));
        let _ = upload(State(state), owner, bytes).await.unwrap();
    }

    #[test]
    fn draft_validates_paths_and_requires_an_index() {
        assert_eq!(
            check_archive(&bundle(&["index.html", "assets/a.css"])).unwrap(),
            ["assets/a.css", "index.html"]
        );
        for files in [
            vec!["a.txt"],
            vec!["index.html", "../bad"],
            vec!["index.html", ".env"],
            vec!["index.html", "assets", "assets/a.css"],
            vec!["index.html", "/bad"],
        ] {
            assert!(check_archive(&bundle(&files)).is_err(), "{files:?}");
        }
    }
}

async fn upload(
    State(state): State<AppState>,
    current: AuthUser,
    body: Bytes,
) -> Result<Json<Draft>, ApiError> {
    require_write(&current)?;
    let permit = ARCHIVE_WORKERS.try_acquire().map_err(|_| {
        ApiError::TooManyRequests("archive validation busy".into())
    })?;
    let (files, sha256, archive) = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let files = check_archive(&body)?;
        Ok::<_, ApiError>((
            files,
            hex::encode(Sha256::digest(&body)),
            body.to_vec(),
        ))
    })
    .await
    .map_err(ApiError::internal)??;
    let txn = state.db.begin().await?;
    let db = DbBackend::Postgres;
    txn.query_one(Statement::from_sql_and_values(
        db,
        "SELECT id FROM users WHERE id=$1 FOR UPDATE",
        [current.id.into()],
    ))
    .await?;
    txn.execute(Statement::from_string(
        db,
        "DELETE FROM static_drafts WHERE expires_at <= now()",
    ))
    .await?;
    let id = Uuid::new_v4();
    let result = txn.execute(Statement::from_sql_and_values(db,
        "INSERT INTO static_drafts(id,owner_id,archive,digest) SELECT $1,$2,$3,$4 WHERE (SELECT count(*) FROM static_drafts WHERE owner_id=$2)<4",
        [id.into(), current.id.into(), archive.into(), sha256.clone().into()])).await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::Conflict(
            "discard a draft before uploading another".into(),
        ));
    }
    txn.commit().await?;
    Ok(Json(Draft { id, sha256, files }))
}

async fn discard(
    State(state): State<AppState>,
    current: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<axum::http::StatusCode, ApiError> {
    require_write(&current)?;
    state
        .db
        .execute(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "DELETE FROM static_drafts WHERE id=$1 AND owner_id=$2",
            [id.into(), current.id.into()],
        ))
        .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

async fn preview(
    State(state): State<AppState>,
    current: AuthUser,
    Path((id, path)): Path<(Uuid, String)>,
) -> Result<Response, ApiError> {
    let permit = ARCHIVE_WORKERS.try_acquire().map_err(|_| {
        ApiError::TooManyRequests("archive preview busy".into())
    })?;
    let row = state.db.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT archive FROM static_drafts WHERE id=$1 AND owner_id=$2 AND expires_at>now()", [id.into(), current.id.into()])).await?
        .ok_or_else(|| ApiError::NotFound("draft not found".into()))?;
    let bytes: Vec<u8> = row.try_get("", "archive")?;
    render_asset(bytes, path, permit).await
}

async fn preview_session(
    State(state): State<AppState>,
    current: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let ticket = Uuid::new_v4().simple().to_string();
    let hash = hex::encode(Sha256::digest(ticket.as_bytes()));
    let updated = state.db.execute(Statement::from_sql_and_values(DbBackend::Postgres,
        "UPDATE static_drafts SET preview_hash=$3,preview_until=now()+interval '10 minutes'
         WHERE id=$1 AND owner_id=$2 AND expires_at>now()", [id.into(), current.id.into(), hash.into()])).await?;
    if updated.rows_affected() != 1 {
        return Err(ApiError::NotFound("draft not found".into()));
    }
    let url = format!("/api/v1/draft-preview/{id}/{ticket}/index.html");
    Ok((
        [("cache-control", "private, no-store")],
        Json(serde_json::json!({"url": url})),
    )
        .into_response())
}

async fn preview_asset(
    State(state): State<AppState>,
    Path((id, ticket, path)): Path<(Uuid, String, String)>,
) -> Result<Response, ApiError> {
    let missing = || ApiError::NotFound("preview unavailable".into());
    if ticket.len() != 32 || !ticket.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(missing());
    }
    let permit = ARCHIVE_WORKERS.try_acquire().map_err(|_| {
        ApiError::TooManyRequests("archive preview busy".into())
    })?;
    let hash = hex::encode(Sha256::digest(ticket.as_bytes()));
    let row = state.db.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT archive FROM static_drafts WHERE id=$1 AND preview_hash=$2 AND expires_at>now() AND preview_until>now()",
        [id.into(), hash.into()])).await?.ok_or_else(missing)?;
    render_asset(row.try_get("", "archive")?, path, permit).await
}

async fn render_asset(
    bytes: Vec<u8>,
    path: String,
    permit: tokio::sync::SemaphorePermit<'static>,
) -> Result<Response, ApiError> {
    let mime = match path.rsplit('.').next().unwrap_or("") {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        _ => "text/plain; charset=utf-8",
    };
    let content = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut archive =
            ZipArchive::new(Cursor::new(bytes)).map_err(ApiError::internal)?;
        let file = archive
            .by_name(&path)
            .map_err(|_| ApiError::NotFound("file not found".into()))?;
        let mut content = Vec::new();
        file.take(MAX_EXPANDED + 1)
            .read_to_end(&mut content)
            .map_err(ApiError::internal)?;
        if content.len() as u64 > MAX_EXPANDED {
            return Err(invalid("file exceeds preview limit"));
        }
        Ok(content)
    })
    .await
    .map_err(ApiError::internal)??;
    Ok(([
        ("content-type", mime),
        ("content-security-policy", "sandbox; default-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'"),
        ("x-frame-options", "SAMEORIGIN"),
        ("x-content-type-options", "nosniff"),
        ("cache-control", "private, no-store"),
        ("referrer-policy", "no-referrer"),
    ], content).into_response())
}
