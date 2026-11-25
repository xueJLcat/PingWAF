use std::collections::{BTreeMap, BTreeSet};

use pingwaf_proto::{PanelListeners, MAX_INGRESS_LISTENERS};
use sea_orm::{ConnectionTrait, DbBackend, DbErr, Statement};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct AddressOverride {
    pub site_id: Uuid,
    pub port: u16,
    pub addresses: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Policy {
    pub addresses: Option<Vec<String>>,
    pub overrides: Vec<AddressOverride>,
    pub revision: i64,
    #[serde(default)]
    pub updated_by: String,
}

pub(crate) async fn read(
    db: &impl ConnectionTrait,
    agent: Uuid,
) -> Result<Policy, DbErr> {
    let row = db.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT p.addresses, p.revision, p.updated_by, COALESCE((SELECT jsonb_agg(jsonb_build_object(
        'site_id', o.site_id, 'port', o.port, 'addresses', o.addresses) ORDER BY o.site_id, o.port)
        FROM node_listener_overrides o WHERE o.agent_id=p.id), '[]'::jsonb) AS overrides
        FROM node_listener_policies p WHERE p.id=$1", [agent.into()])).await?
        .ok_or_else(|| DbErr::Custom("missing node listener policy".into()))?;
    Ok(Policy {
        addresses: row.try_get("", "addresses")?,
        revision: row.try_get("", "revision")?,
        updated_by: row.try_get("", "updated_by")?,
        overrides: serde_json::from_value(row.try_get("", "overrides")?)
            .map_err(|e| DbErr::Custom(e.to_string()))?,
    })
}

impl Policy {
    pub fn normalize(&mut self) -> Result<(), String> {
        let addresses = pingwaf_proto::normalize_bind_addresses(
            self.addresses
                .as_deref()
                .ok_or("node addresses require migration review")?,
        )?;
        let mut seen = BTreeSet::new();
        for item in &mut self.overrides {
            if item.port == 0 || !seen.insert((item.site_id, item.port)) {
                return Err("invalid or duplicate site listener".into());
            }
            item.addresses =
                pingwaf_proto::normalize_bind_addresses(&item.addresses)?;
            for address in &item.addresses {
                let wildcard = if address.contains(':') {
                    "::"
                } else {
                    "0.0.0.0"
                };
                if !addresses
                    .iter()
                    .any(|allowed| allowed == address || allowed == wildcard)
                {
                    return Err(format!(
                        "site bind address {address} exceeds the node policy"
                    ));
                }
            }
        }
        self.addresses = Some(addresses);
        Ok(())
    }

    pub fn apply(&self, listeners: &mut PanelListeners) -> Result<(), String> {
        if listeners.endpoints.is_empty() {
            return Ok(());
        }
        let base = self
            .addresses
            .as_ref()
            .ok_or("node addresses require migration review")?;
        let overrides: BTreeMap<_, _> = self
            .overrides
            .iter()
            .map(|v| ((v.site_id.to_string(), u32::from(v.port)), &v.addresses))
            .collect();
        let mut count = 0;
        for endpoint in &mut listeners.endpoints {
            let port =
                endpoint.ingress.as_ref().ok_or("missing listener")?.port;
            let mut addresses = endpoint.site_ids.iter().map(|id| {
                overrides.get(&(id.clone(), port)).copied().unwrap_or(base)
            });
            let first = addresses.next().ok_or("listener has no owner")?;
            if addresses.any(|next| next != first) {
                return Err(format!("sites sharing port {port} require identical bind addresses"));
            }
            endpoint.addresses.clone_from(first);
            count += first.len();
        }
        if count > MAX_INGRESS_LISTENERS {
            return Err(format!("node requires {count} sockets; limit is {MAX_INGRESS_LISTENERS}"));
        }
        Ok(())
    }
}
