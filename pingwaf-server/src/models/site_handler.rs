use reqwest::Url;
use sea_orm::{ConnectionTrait, DatabaseTransaction, DbErr, Statement};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

fn yes() -> bool {
    true
}
fn found() -> u32 {
    302
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SiteHandler {
    Zip {
        digest: String,
    },
    Static {
        directory_id: String,
        digest: String,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        rollback: bool,
    },
    Redirect {
        target: String,
        #[serde(default = "found")]
        status: u32,
        #[serde(default = "yes")]
        preserve_path: bool,
        #[serde(default = "yes")]
        preserve_query: bool,
    },
}

/// Validate the final graph in the same transaction that writes listener claims.
/// Paused sites participate so reactivation cannot introduce a latent cycle.
pub async fn check_redirects(tx: &DatabaseTransaction) -> Result<(), DbErr> {
    let rows = tx.query_all(Statement::from_string(tx.get_database_backend(),
        "SELECT id, domain, alternate_domains, site_handler, port::integer AS port, protocol
         FROM sites s CROSS JOIN LATERAL site_listener_claims(s.ingress_port, s.ingress_protocol, s.additional_ingresses)
         WHERE s.site_handler IS NOT NULL"
    )).await?;
    let mut destinations = HashMap::new();
    let mut claims = HashMap::<(String, u16), HashMap<String, Uuid>>::new();
    for row in rows {
        let id: Uuid = row.try_get("", "id")?;
        let value: serde_json::Value = row.try_get("", "site_handler")?;
        let handler: SiteHandler = serde_json::from_value(value)
            .map_err(|e| DbErr::Custom(e.to_string()))?;
        let next = handler.to_proto().map_err(DbErr::Custom)?;
        let pingwaf_proto::managed_site::Handler::Redirect(redirect) = next
        else {
            continue;
        };
        destinations.insert(
            id,
            Url::parse(&redirect.target)
                .map_err(|e| DbErr::Custom(e.to_string()))?,
        );
        let port: i32 = row.try_get("", "port")?;
        let scope = claims
            .entry((row.try_get("", "protocol")?, port as u16))
            .or_default();
        scope.insert(row.try_get("", "domain")?, id);
        for alias in row.try_get::<Vec<String>>("", "alternate_domains")? {
            scope.insert(alias, id);
        }
    }
    let mut done = HashSet::new();
    for start in destinations.keys() {
        let mut path = HashSet::new();
        let mut current = *start;
        while !done.contains(&current) {
            if !path.insert(current) {
                return Err(DbErr::Custom(
                    "redirect cycle between configured sites".into(),
                ));
            }
            let target = &destinations[&current];
            let Some(names) = claims.get(&(
                target.scheme().to_owned(),
                target.port_or_known_default().unwrap(),
            )) else {
                break;
            };
            let host = target.host_str().unwrap().trim_end_matches('.');
            let next = names.get(host).or_else(|| {
                host.match_indices('.')
                    .find_map(|(i, _)| names.get(&format!("*{}", &host[i..])))
            });
            let Some(next) = next else {
                break;
            };
            current = *next;
        }
        done.extend(path);
    }
    Ok(())
}

impl SiteHandler {
    fn redirect_target(target: &str, status: u32) -> Result<Url, String> {
        let url = Url::parse(target)
            .map_err(|_| "invalid redirect target".to_owned())?;
        if !matches!(status, 301 | 302 | 307 | 308)
            || !matches!(url.scheme(), "http" | "https")
            || url.host().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || target.len() > 4096
            || target.chars().any(char::is_control)
        {
            return Err("invalid HTTP(S) redirect target or status".into());
        }
        Ok(url)
    }

    pub fn to_proto(
        &self,
    ) -> Result<pingwaf_proto::managed_site::Handler, String> {
        match self {
            Self::Zip { digest } => {
                if digest.len() != 64
                    || !digest.bytes().all(|b| {
                        b.is_ascii_hexdigit() && !b.is_ascii_uppercase()
                    })
                {
                    return Err("invalid archive digest".into());
                }
                Ok(pingwaf_proto::managed_site::Handler::StaticRelease(
                    pingwaf_proto::StaticRelease {
                        directory_id: String::new(),
                        digest: digest.clone(),
                    },
                ))
            },
            Self::Static {
                directory_id,
                digest,
                ..
            } => {
                if directory_id.is_empty()
                    || directory_id.len() > 64
                    || !directory_id.bytes().all(|b| {
                        b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')
                    })
                    || digest.len() != 64
                    || !digest.bytes().all(|b| {
                        b.is_ascii_hexdigit() && !b.is_ascii_uppercase()
                    })
                {
                    return Err(
                        "invalid registered directory or content digest".into(),
                    );
                }
                Ok(pingwaf_proto::managed_site::Handler::StaticRelease(
                    pingwaf_proto::StaticRelease {
                        directory_id: directory_id.clone(),
                        digest: digest.clone(),
                    },
                ))
            },
            Self::Redirect {
                target,
                status,
                preserve_path,
                preserve_query,
            } => Ok(pingwaf_proto::managed_site::Handler::Redirect(
                pingwaf_proto::SiteRedirect {
                    target: Self::redirect_target(target, *status)?.to_string(),
                    status: *status,
                    preserve_path: *preserve_path,
                    preserve_query: *preserve_query,
                },
            )),
        }
    }
}
