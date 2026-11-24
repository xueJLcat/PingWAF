//! Syncs ACME-issued PEMs from the embedded data plane into the database.
//!
//! In all-in-one mode the data plane's lets-encrypt task is the issuer: it
//! writes the issued certificate and key into its local `acme_state.toml` (the
//! memory config manager mirrors every write there). The control plane's
//! `build_site_config` reads `site_certificates` from PostgreSQL, so before
//! this sync the row still had an empty `cert_pem`: every *other* agent was
//! told "ACME is enabled, no PEM", tried to issue its own HTTP-01 order, and
//! failed because the CA's validation request reaches whichever instance owns
//! port 80 — not necessarily the agent that saved the token.
//!
//! The sync is deliberately read-only against the data plane and only writes
//! `site_certificates` rows that are ACME-managed (`auto_renew` and an
//! `acme_email`). Uploaded/manual PEMs are never overwritten: a row without
//! ACME management is skipped, and a row whose current PEM already matches is
//! a no-op.
//!
//! A remote agent that issues a certificate is still not reported back here;
//! that needs a PEM report over the control-plane channel. The embedded data
//! plane is the designated issuer for sites whose DNS points at the control
//! plane, which is the deployment this sync fixes.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use chrono::{DateTime, Utc};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::Deserialize;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::api::ssl::cert_status;
use crate::api::state::AppState;
use crate::models::{site_certificates, site_ssl};
use crate::site_cert;

/// How often the file is checked. Issuance is rare; a 30 s delay only means
/// the other agents stop retrying a little later.
const SYNC_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Default, Deserialize)]
struct AcmeState {
    #[serde(default)]
    certificates: HashMap<String, AcmeCertificate>,
}

#[derive(Debug, Default, Deserialize)]
struct AcmeCertificate {
    #[serde(default)]
    domains: String,
    #[serde(default)]
    tls_cert: String,
    #[serde(default)]
    tls_key: String,
}

struct CertificateMeta {
    issuer: String,
    not_before: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

/// Starts the periodic sync. `path` is the embedded data plane's
/// `acme_state.toml`; a missing file is normal in server-only mode.
pub fn spawn(state: AppState, path: PathBuf) {
    tokio::spawn(async move {
        let mut last_modified: Option<SystemTime> = None;
        let mut ticker = tokio::time::interval(SYNC_INTERVAL);
        loop {
            ticker.tick().await;
            if let Err(err) = sync_once(&state, &path, &mut last_modified).await
            {
                warn!(
                    error = %err,
                    path = %path.display(),
                    "ACME state sync failed"
                );
            }
        }
    });
}

async fn sync_once(
    state: &AppState,
    path: &Path,
    last_modified: &mut Option<SystemTime>,
) -> anyhow::Result<usize> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            debug!(path = %path.display(), "no ACME state file yet");
            return Ok(0);
        },
        Err(err) => return Err(err.into()),
    };
    let modified = metadata.modified().ok();
    if modified == *last_modified {
        return Ok(0);
    }

    let text = std::fs::read_to_string(path)?;
    let parsed: AcmeState = match toml::from_str(&text) {
        Ok(parsed) => parsed,
        Err(err) => {
            // The data plane writes atomically, but a malformed file must not
            // take the control plane down or retry in a tight loop. Wait for
            // the next write before trying again.
            *last_modified = modified;
            return Err(anyhow::anyhow!(
                "cannot parse {}: {err}",
                path.display()
            ));
        },
    };

    let mut updated = 0;
    for (name, cert) in &parsed.certificates {
        let Some(site_id) = site_id_from_key(name) else {
            continue;
        };
        if cert.domains.trim().is_empty()
            || cert.tls_cert.trim().is_empty()
            || cert.tls_key.trim().is_empty()
        {
            continue;
        }
        if sync_certificate(
            state,
            site_id,
            &cert.domains,
            &cert.tls_cert,
            &cert.tls_key,
        )
        .await?
        {
            updated += 1;
        }
    }

    *last_modified = modified;
    if updated > 0 {
        // The PEM is now in the row `build_site_config` reads, so every agent
        // gets it on the next push. Without this, agents only see it on the
        // next unrelated config change.
        crate::grpc::notify_all_config_changed(state, Some("acme-state-sync"))
            .await;
    }
    Ok(updated)
}

async fn sync_certificate(
    state: &AppState,
    site_id: Uuid,
    domains: &str,
    cert_pem: &str,
    key_pem: &str,
) -> anyhow::Result<bool> {
    let row = site_certificates::Entity::find()
        .filter(site_certificates::Column::SiteId.eq(site_id))
        .filter(site_certificates::Column::Domain.eq(domains.to_string()))
        .one(&state.db)
        .await?;
    // Older rows may have the domains in another order or the alternate
    // domain as the primary string. Fall back to the site's row only when the
    // exact domain match found nothing.
    let row = match row {
        Some(row) => Some(row),
        None => {
            site_certificates::Entity::find()
                .filter(site_certificates::Column::SiteId.eq(site_id))
                .one(&state.db)
                .await?
        },
    };
    let Some(row) = row else {
        // The file can outlive a deleted certificate row. Not an error: the
        // next issuance or a site edit removes it.
        debug!(site_id = %site_id, domains, "ACME certificate has no row");
        return Ok(false);
    };

    // Only ACME-managed rows are this file's to update. A manual upload (or a
    // row whose auto-renew was turned off) must never be replaced by an old
    // ACME PEM that happens to share the site id.
    if !row.auto_renew
        || row
            .acme_email
            .as_deref()
            .map(str::trim)
            .is_none_or(str::is_empty)
    {
        return Ok(false);
    }
    if row.cert_pem.as_deref() == Some(cert_pem)
        && row.key_pem.as_deref() == Some(key_pem)
    {
        return Ok(false);
    }

    let mut active: site_certificates::ActiveModel = row.clone().into();
    active.cert_pem = Set(Some(cert_pem.to_string()));
    active.key_pem = Set(Some(key_pem.to_string()));
    active.status = Set(cert_status::ACTIVE.to_string());
    active.failure_reason = Set(None);
    active.updated_at = Set(Utc::now());
    let meta = parse_certificate_meta(cert_pem);
    if let Some(meta) = &meta {
        active.issuer = Set(Some(meta.issuer.clone()));
        active.not_before = Set(Some(meta.not_before));
        active.expires_at = Set(Some(meta.expires_at));
    }
    let certificate_id = row.id;
    active.update(&state.db).await?;

    // The issued PEM is the site's certificate now. A generated self-signed
    // leaf would otherwise keep winning — the data plane prefers an inline PEM
    // over an ACME order — so the site would serve the wrong certificate
    // forever. Point the posture at this row and drop our generated material.
    let posture_row = site_ssl::Entity::find()
        .filter(site_ssl::Column::SiteId.eq(site_id))
        .one(&state.db)
        .await?;
    if let Some(ssl) = posture_row {
        if ssl.self_signed || site_cert::is_generated(ssl.issuer.as_deref()) {
            let mut posture: site_ssl::ActiveModel = ssl.into();
            posture.self_signed = Set(false);
            posture.certificate_id = Set(Some(certificate_id));
            posture.cert_pem = Set(None);
            posture.key_pem = Set(None);
            if let Some(meta) = &meta {
                posture.issuer = Set(Some(meta.issuer.clone()));
                posture.expires_at = Set(Some(meta.expires_at));
            }
            posture.update(&state.db).await?;
            info!(
                site_id = %site_id,
                cert_id = %certificate_id,
                "ACME certificate took over from the self-signed leaf"
            );
        }
    }

    info!(
        site_id = %site_id,
        domain = %row.domain,
        cert_len = cert_pem.len(),
        key_len = key_pem.len(),
        "synced ACME certificate into the control plane"
    );
    Ok(true)
}

fn site_id_from_key(name: &str) -> Option<Uuid> {
    let site = name.strip_suffix("_cert")?;
    Uuid::parse_str(site).ok()
}

fn parse_certificate_meta(cert_pem: &str) -> Option<CertificateMeta> {
    let (_, block) =
        x509_parser::pem::parse_x509_pem(cert_pem.as_bytes()).ok()?;
    let cert = block.parse_x509().ok()?;
    let validity = cert.validity();
    let not_before = validity.not_before.to_datetime();
    let expires_at = validity.not_after.to_datetime();
    Some(CertificateMeta {
        // `site_certificates.issuer` is varchar(200); a pathological DN must
        // not make the PEM update fail.
        issuer: cert.issuer().to_string().chars().take(200).collect(),
        not_before: DateTime::<Utc>::from_timestamp(
            not_before.unix_timestamp(),
            0,
        )?,
        expires_at: DateTime::<Utc>::from_timestamp(
            expires_at.unix_timestamp(),
            0,
        )?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_issued_certificate_metadata() {
        use rcgen::{CertificateParams, KeyPair};

        let params =
            CertificateParams::new(vec!["example.com".to_string()]).unwrap();
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let meta = parse_certificate_meta(&cert.pem()).unwrap();
        assert!(!meta.issuer.is_empty());
        assert!(meta.expires_at > meta.not_before);
    }

    #[test]
    fn parses_certificate_entries_and_skips_empty_ones() {
        let state: AcmeState = toml::from_str(
            r#"
[certificates.11111111-1111-1111-1111-111111111111_cert]
domains = "example.com,www.example.com"
tls_cert = "CERT"
tls_key = "KEY"

[certificates.22222222-2222-2222-2222-222222222222_cert]
domains = "empty.example"
tls_cert = ""
tls_key = ""
"#,
        )
        .unwrap();
        let site_id =
            Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let cert = state
            .certificates
            .get("11111111-1111-1111-1111-111111111111_cert")
            .unwrap();
        assert_eq!(cert.domains, "example.com,www.example.com");
        assert_eq!(cert.tls_cert, "CERT");
        assert_eq!(cert.tls_key, "KEY");
        assert_eq!(
            site_id_from_key("11111111-1111-1111-1111-111111111111_cert"),
            Some(site_id)
        );
        assert_eq!(site_id_from_key("not-a-uuid_cert"), None);
        assert_eq!(
            site_id_from_key("11111111-1111-1111-1111-111111111111"),
            None
        );
    }
}
