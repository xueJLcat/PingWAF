/// Generated gRPC code for PingWAF control plane protocol
#[allow(clippy::all)]
#[allow(warnings)]
pub mod control_plane {
    tonic::include_proto!("pingwaf");
}

// Re-export commonly used types at crate root for convenience
pub use control_plane::*;

impl AgentHeartbeat {
    /// Use the field numbers understood by the peer that accepted registration.
    pub fn encode_legacy_reports(&mut self, managed: bool) {
        use prost::Message;
        if managed {
            self.legacy_listener = self
                .ingress_listeners
                .take()
                .map(|m| m.encode_to_vec())
                .into_iter()
                .collect();
            self.legacy_report = self
                .managed_apply
                .take()
                .map(|m| m.encode_to_vec())
                .into_iter()
                .collect();
        } else {
            self.managed_apply = None;
            self.legacy_listener = self
                .tunnel_listener
                .take()
                .map(|m| m.encode_to_vec())
                .into_iter()
                .collect();
            self.legacy_report = self
                .tunnel_sessions
                .drain(..)
                .map(|m| m.encode_to_vec())
                .collect();
        }
    }

    /// Decode overlapping tags only once the server knows the registered peer.
    /// Older 0.32 standalone agents can report inventory without a managed lease.
    pub fn decode_legacy_reports(
        &mut self,
        managed: bool,
        pre_tunnel_agent: bool,
    ) -> Result<(), &'static str> {
        use prost::Message;
        let listeners = std::mem::take(&mut self.legacy_listener);
        let reports = std::mem::take(&mut self.legacy_report);
        if listeners.len() > 1 {
            return Err("duplicate listener report");
        }
        if managed || pre_tunnel_agent {
            if reports.len() > 1 {
                return Err("duplicate managed report");
            }
            if let Some(raw) = listeners.first() {
                self.ingress_listeners = Some(
                    IngressListeners::decode(raw.as_slice())
                        .map_err(|_| "invalid ingress inventory")?,
                );
            }
            if let Some(raw) = reports.first() {
                self.managed_apply = Some(
                    ManagedApplyReport::decode(raw.as_slice())
                        .map_err(|_| "invalid managed report")?,
                );
            }
        } else {
            if let Some(raw) = listeners.first() {
                self.tunnel_listener = Some(
                    TunnelListenerStatus::decode(raw.as_slice())
                        .map_err(|_| "invalid tunnel listener")?,
                );
            }
            self.tunnel_sessions = reports
                .iter()
                .map(|raw| {
                    TunnelSessionReport::decode(raw.as_slice())
                        .map_err(|_| "invalid tunnel session")
                })
                .collect::<Result<_, _>>()?;
        }
        if !managed {
            self.managed_apply = None;
        }
        Ok(())
    }
}

/// Per-process socket budget and upper bound for a heartbeat's inventory.
pub const MAX_INGRESS_LISTENERS: usize = 32;

/// Canonical address set for one listener. IPv6 sockets are v6-only.
pub fn normalize_bind_addresses(
    values: &[String],
) -> Result<Vec<String>, String> {
    use std::{collections::BTreeSet, net::IpAddr};
    if !(1..=MAX_INGRESS_LISTENERS).contains(&values.len()) {
        return Err(format!(
            "expected 1 to {MAX_INGRESS_LISTENERS} bind addresses"
        ));
    }
    let mut addresses = BTreeSet::new();
    for text in values {
        let ip: IpAddr = text
            .trim()
            .parse()
            .map_err(|_| format!("invalid bind address {text}"))?;
        if ip.is_multicast()
            || matches!(ip, IpAddr::V6(v) if v.to_ipv4_mapped().is_some())
            || !addresses.insert(ip)
        {
            return Err(format!("unsupported or duplicate address {ip}"));
        }
    }
    for ip in &addresses {
        if ip.is_unspecified()
            && addresses
                .iter()
                .any(|other| other != ip && other.is_ipv4() == ip.is_ipv4())
        {
            return Err(format!("wildcard {ip} overlaps another address"));
        }
    }
    Ok(addresses.into_iter().map(|ip| ip.to_string()).collect())
}

impl PanelListeners {
    /// Call only with the authorized sites belonging to one snapshot.
    pub fn for_sites(sites: &[ManagedSite]) -> Self {
        use std::collections::{BTreeMap, BTreeSet};
        let mut owners: BTreeMap<(u32, i32), BTreeSet<String>> =
            BTreeMap::new();
        for item in sites {
            let Some(site) = &item.site else { continue };
            if site.status != SiteStatusEnum::SiteStatusActive as i32 {
                continue;
            }
            if item.ingress.is_none() {
                for (port, protocol) in
                    [(80, IngressProtocol::Http), (443, IngressProtocol::Https)]
                {
                    owners
                        .entry((port, protocol as i32))
                        .or_default()
                        .insert(site.id.clone());
                }
            }
            for ingress in item.ingress.iter().chain(&item.additional_ingresses)
            {
                owners
                    .entry((ingress.port, ingress.protocol))
                    .or_default()
                    .insert(site.id.clone());
            }
        }
        Self {
            unmatched_pages: Vec::new(),
            policy_revision: 0,
            endpoints: owners
                .into_iter()
                .map(|((port, protocol), sites)| PanelEndpoint {
                    ingress: Some(SiteIngress { port, protocol }),
                    addresses: vec!["0.0.0.0".into()],
                    site_ids: sites.into_iter().collect(),
                })
                .collect(),
        }
    }
}

impl ManagedSiteConfig {
    pub fn from_sites(sites: Vec<ManagedSite>) -> Self {
        Self {
            listeners: Some(PanelListeners::for_sites(&sites)),
            sites,
        }
    }
}

pub const MANAGED_PROTOCOL_VERSION: u32 = 1;

/// Maximum time a managed snapshot can authorize forwarding without a pull.
pub const MAX_MANAGED_LEASE_SECONDS: u32 = 90;

/// Leave room for the managed envelope inside tonic's 4 MiB decoding limit.
pub const MAX_MANAGED_CONFIG_BYTES: usize = 4 * 1024 * 1024 - 1024;

#[cfg(test)]
mod heartbeat_compatibility {
    use super::*;
    use prost::Message;

    // These two published wire layouts both predate this decoder.
    #[derive(Clone, PartialEq, Message)]
    struct Local68 {
        #[prost(message, optional, tag = "25")]
        inventory: Option<IngressListeners>,
        #[prost(message, optional, tag = "26")]
        applied: Option<ManagedApplyReport>,
    }

    #[derive(Clone, PartialEq, Message)]
    struct Official33 {
        #[prost(message, optional, tag = "25")]
        listener: Option<TunnelListenerStatus>,
        #[prost(message, repeated, tag = "26")]
        sessions: Vec<TunnelSessionReport>,
    }

    #[test]
    fn registered_wire_layouts_round_trip() {
        let local = Local68 {
            inventory: Some(IngressListeners {
                dynamic_bind: true,
                ..Default::default()
            }),
            applied: Some(ManagedApplyReport {
                generation: 42,
                ..Default::default()
            }),
        };
        let official = Official33 {
            listener: Some(TunnelListenerStatus {
                active: true,
                ..Default::default()
            }),
            sessions: ["one", "two"]
                .map(|id| TunnelSessionReport {
                    tunnel_id: id.into(),
                    ..Default::default()
                })
                .to_vec(),
        };
        let decode =
            |bytes: Vec<u8>| AgentHeartbeat::decode(bytes.as_slice()).unwrap();
        let mut old = decode(local.encode_to_vec());
        old.decode_legacy_reports(true, false).unwrap();
        assert_eq!(old.ingress_listeners, local.inventory);
        assert_eq!(old.managed_apply, local.applied);
        old.tunnel_listener.clone_from(&official.listener);
        old.tunnel_sessions.clone_from(&official.sessions);
        old.encode_legacy_reports(true);
        let bytes = old.encode_to_vec();
        assert_eq!(Local68::decode(bytes.as_slice()).unwrap(), local);
        let mut mixed = decode(bytes);
        mixed.decode_legacy_reports(true, false).unwrap();
        assert_eq!(mixed.tunnel_sessions, official.sessions);

        let mut current = decode(official.encode_to_vec());
        current.decode_legacy_reports(false, false).unwrap();
        assert_eq!(current.tunnel_listener, official.listener);
        assert_eq!(current.tunnel_sessions, official.sessions);
        current.encode_legacy_reports(false);
        assert_eq!(
            Official33::decode(current.encode_to_vec().as_slice()).unwrap(),
            official
        );

        let mut standalone = decode(local.encode_to_vec());
        standalone.decode_legacy_reports(false, true).unwrap();
        assert_eq!(standalone.ingress_listeners, local.inventory);
        assert!(standalone.managed_apply.is_none());
        assert!(standalone.tunnel_listener.is_none());
    }

    #[test]
    fn malformed_and_duplicate_singular_reports_are_rejected() {
        let mut peer = AgentHeartbeat {
            legacy_listener: vec![vec![0xff]],
            ..Default::default()
        };
        assert!(peer.decode_legacy_reports(true, false).is_err());
        peer.legacy_report = vec![vec![], vec![]];
        assert!(peer.decode_legacy_reports(true, false).is_err());
    }
}
