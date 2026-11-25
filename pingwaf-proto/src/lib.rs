/// Generated gRPC code for PingWAF control plane protocol
#[allow(clippy::all)]
#[allow(warnings)]
pub mod control_plane {
    tonic::include_proto!("pingwaf");
}

// Re-export commonly used types at crate root for convenience
pub use control_plane::*;

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
