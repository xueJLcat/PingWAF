use super::*;
use crate::{
    api::{error::ApiError, state::AppState},
    auth::AuthUser,
};
use axum::{extract::State, Json};
use serde::Deserialize;
use serde_json::{json, Value as JsonValue};
use sha2::{Digest, Sha256};

fn runtime(s: &AppState) -> Result<&Service, ApiError> {
    s.syslog.as_deref().ok_or_else(|| {
        ApiError::ServiceUnavailable("Syslog unavailable".into())
    })
}
fn internal(e: anyhow::Error) -> ApiError {
    ApiError::Internal(e.to_string())
}
fn invalid(e: anyhow::Error) -> ApiError {
    ApiError::BadRequest(format!("{e:#}")).with_code("syslog.invalid")
}
fn transport_error(e: anyhow::Error) -> ApiError {
    let stage = e.to_string();
    let code = if stage.starts_with("dns") {
        "syslog.dns"
    } else if stage.starts_with("tls") {
        "syslog.tls"
    } else if stage.starts_with("connect") {
        "syslog.connect"
    } else {
        "syslog.write"
    };
    ApiError::BadGateway(format!("{e:#}")).with_code(code)
}
fn certificate(pem: &str) -> Option<JsonValue> {
    let cert = rustls_pemfile::certs(&mut std::io::Cursor::new(pem))
        .next()?
        .ok()?;
    use x509_parser::prelude::*;
    let (_, parsed) = X509Certificate::from_der(cert.as_ref()).ok()?;
    Some(
        json!({"sha256":hex::encode(Sha256::digest(cert.as_ref())),"expires":parsed.validity().not_after.to_string()}),
    )
}
fn view(s: &Stored) -> Json<JsonValue> {
    Json(
        json!({"revision":s.revision,"configured":s.config.is_some(),
    "config":s.config.clone().unwrap_or_default(),"ca_info":certificate(&s.ca),"cert_info":certificate(&s.cert),"has_key":!s.key.is_empty()}),
    )
}
pub(crate) async fn show(
    State(s): State<AppState>,
    user: AuthUser,
) -> Result<Json<JsonValue>, ApiError> {
    user.require_admin()?;
    Ok(view(&stored(&s.db, "").await.map_err(internal)?))
}
pub(crate) async fn status(
    State(s): State<AppState>,
    user: AuthUser,
) -> Result<Json<JsonValue>, ApiError> {
    user.require_admin()?;
    let service = runtime(&s)?;
    let a = service.active.load_full();
    let (count, bytes, oldest) = queue_stats(&s.db).await.map_err(internal)?;
    let stats = service.stats.lock().unwrap().clone();
    Ok(Json(
        json!({"active_revision":a.revision,"enabled":a.config.enabled,"host":a.config.host,"port":a.config.port,"transport":a.config.transport,
        "queue_count":count,"queue_bytes":bytes,"oldest":oldest,"since":service.started,"stats":stats}),
    ))
}
#[derive(Deserialize)]
pub(crate) struct Edit {
    revision: i64,
    config: Config,
    ca: Option<String>,
    cert: Option<String>,
    key: Option<String>,
    #[serde(default)]
    discard: bool,
}
fn check_revision(want: i64, have: i64) -> Result<(), ApiError> {
    if want != have {
        Err(ApiError::Conflict(format!(
            "Configuration changed (revision {have}); reload before saving"
        ))
        .with_code("syslog.revision"))
    } else {
        Ok(())
    }
}
impl Edit {
    fn prepare(
        &self,
        old: &Stored,
        testing: bool,
    ) -> Result<(Material, Tls), ApiError> {
        check_revision(self.revision, old.revision)?;
        self.config
            .validate(testing || self.config.enabled)
            .map_err(invalid)?;
        let need_old_key = self.key.is_none()
            && self.config.transport == "tls"
            && self.config.mtls
            && (testing || self.config.enabled);
        let mut m = old.material(need_old_key).map_err(invalid)?;
        for (field, update) in [
            (&mut m.ca, &self.ca),
            (&mut m.cert, &self.cert),
            (&mut m.key, &self.key),
        ] {
            if let Some(input) = update {
                if input.len() > 262144 {
                    return Err(invalid(anyhow::anyhow!(
                        "PEM: maximum size is 256 KiB"
                    )));
                }
                *field = input.clone();
            }
        }
        if !m.ca.is_empty() && certificate(&m.ca).is_none() {
            return Err(invalid(anyhow::anyhow!("ca: invalid certificate")));
        }
        if !m.cert.is_empty() && certificate(&m.cert).is_none() {
            return Err(invalid(anyhow::anyhow!("cert: invalid certificate")));
        }
        if !m.key.is_empty()
            && rustls_pemfile::private_key(&mut std::io::Cursor::new(&m.key))
                .ok()
                .flatten()
                .is_none()
        {
            return Err(invalid(anyhow::anyhow!("key: invalid PEM")));
        }
        let tls = if testing || self.config.enabled {
            transport::tls(&self.config, &m).map_err(invalid)?
        } else {
            None
        };
        Ok((m, tls))
    }
}
pub(crate) async fn test(
    State(s): State<AppState>,
    user: AuthUser,
    Json(edit): Json<Edit>,
) -> Result<Json<JsonValue>, ApiError> {
    user.require_admin()?;
    let service = runtime(&s)?;
    {
        let mut last = service.last_test.lock().unwrap();
        if last.is_some_and(|v| v.elapsed() < Duration::from_secs(2)) {
            return Err(ApiError::TooManyRequests(
                "Wait two seconds before testing again".into(),
            ));
        }
        *last = Some(Instant::now());
    }
    let old = stored(&s.db, "").await.map_err(internal)?;
    let (_, tls) = edit.prepare(&old, true)?;
    let c = &edit.config;
    let packet = wire::encode(
        c,
        0,
        &Default::default(),
        Uuid::nil(),
        None,
        Utc::now(),
        "test",
        c.severity.unwrap_or(6),
    )
    .ok_or_else(|| {
        invalid(anyhow::anyhow!("max_bytes: test event exceeds limit"))
    })?;
    let mut conn = Connection::connect(c, &tls)
        .await
        .map_err(transport_error)?;
    conn.send(c, &packet.bytes).await.map_err(transport_error)?;
    Ok(Json(
        json!({"id":packet.id,"time":Utc::now(),"stage":"written","peer":conn.peer(),"transport":c.transport}),
    ))
}
pub(crate) async fn update(
    State(s): State<AppState>,
    user: AuthUser,
    Json(edit): Json<Edit>,
) -> Result<Json<JsonValue>, ApiError> {
    user.require_admin()?;
    let service = runtime(&s)?;
    let old = stored(&s.db, "").await.map_err(internal)?;
    let (material, tls) = edit.prepare(&old, false)?;
    if edit.config.enabled && edit.config.transport != "udp" {
        Connection::connect(&edit.config, &tls)
            .await
            .map_err(transport_error)?;
    }
    let sealed = if edit.key.is_none() {
        old.key.clone()
    } else if !material.key.is_empty() {
        let sealed = crate::notify::secretbox::seal_string(&material.key);
        if !sealed.starts_with("enc:v1:") {
            return Err(invalid(anyhow::anyhow!("key: configure PINGWAF_SECRET_KEY before storing a private key")));
        }
        sealed
    } else {
        String::new()
    };
    let tx = s.db.begin().await?;
    let locked = stored(&tx, "FOR UPDATE").await.map_err(internal)?;
    check_revision(edit.revision, locked.revision)?;
    let discard = locked
        .config
        .as_ref()
        .is_some_and(|c| c.invalidates_queue(&edit.config));
    let dropped = clear_if_needed(&tx, discard, edit.discard).await?;
    let revision = locked.revision + 1;
    tx.execute(sql("UPDATE syslog_settings SET revision=$1,config=$2,ca=$3,cert=$4,sealed_key=$5 WHERE id=1",vec![
        revision.into(),json!(&edit.config).into(),material.ca.clone().into(),material.cert.clone().into(),sealed.clone().into()])).await?;
    tx.commit().await?;
    service.install(Active {
        revision,
        config: edit.config.clone(),
        tls,
    });
    service.stats.lock().unwrap().discarded += dropped;
    tracing::info!(actor=%user.id,revision,dropped,"Syslog configuration saved");
    Ok(view(&Stored {
        revision,
        config: Some(edit.config),
        ca: material.ca,
        cert: material.cert,
        key: sealed,
    }))
}
async fn clear_if_needed(
    tx: &DatabaseTransaction,
    required: bool,
    confirmed: bool,
) -> Result<u64, ApiError> {
    if !required {
        return Ok(0);
    }
    if !confirmed && queue_stats(tx).await.map_err(internal)?.0 != 0 {
        return Err(ApiError::Conflict(
            "Queued events require explicit discard".into(),
        )
        .with_code("syslog.queue_not_empty"));
    }
    Ok(tx
        .execute(sql("DELETE FROM syslog_queue", vec![]))
        .await?
        .rows_affected())
}
#[derive(Deserialize)]
pub(crate) struct Removal {
    revision: i64,
    #[serde(default)]
    discard: bool,
}
pub(crate) async fn remove(
    State(s): State<AppState>,
    user: AuthUser,
    Json(req): Json<Removal>,
) -> Result<Json<JsonValue>, ApiError> {
    user.require_admin()?;
    let service = runtime(&s)?;
    let tx = s.db.begin().await?;
    let old = stored(&tx, "FOR UPDATE").await.map_err(internal)?;
    check_revision(req.revision, old.revision)?;
    let dropped = clear_if_needed(&tx, true, req.discard).await?;
    tx.execute(sql("UPDATE syslog_settings SET revision=revision+1, config=NULL,ca='',cert='',sealed_key='' WHERE id=1",vec![])).await?;
    let result = stored(&tx, "").await.map_err(internal)?;
    tx.commit().await?;
    service.install(result.active().map_err(internal)?);
    service.stats.lock().unwrap().discarded += dropped;
    tracing::info!(actor=%user.id,revision=result.revision,dropped,"Syslog target removed");
    Ok(view(&result))
}
