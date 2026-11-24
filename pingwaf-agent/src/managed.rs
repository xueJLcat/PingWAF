//! Validation and indexing of managed configuration candidates. A lease is
//! independent of receipt: it only permits forwarding for an applied version.

use std::collections::HashMap;

use anyhow::{ensure, Context};
use pingwaf_proto::{
    FailoverMode, IngressProtocol, ManagedSite, ManagedSiteConfig,
    ManagedSnapshot, SiteStatusEnum, MAX_MANAGED_CONFIG_BYTES,
};
use prost::Message;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::cache::{
    self, lookup_with_wildcard, CachedRules, RuleCache, SiteRules,
};
use std::sync::Arc;

#[cfg(target_os = "linux")]
mod lease;
#[cfg(target_os = "linux")]
pub use lease::{Lease, PullWindow, Received};
#[cfg(target_os = "linux")]
mod applied;
#[cfg(target_os = "linux")]
pub use applied::{AppliedState, Forwarding, Pending};

/// Trusted listener identity, supplied by the owner of the accepting socket.
/// The default pair of listeners share one hostname namespace.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Listener {
    Default,
    Custom {
        port: u16,
        protocol: IngressProtocol,
    },
}

/// A verified and indexed candidate, not evidence that any site is applied.
pub struct Candidate {
    version: Version,
    sites: HashMap<Uuid, ManagedSite>,
    routes: HashMap<Listener, HashMap<String, Uuid>>,
}

impl Candidate {
    pub fn version(&self) -> Version {
        self.version
    }

    pub fn sites(&self) -> &HashMap<Uuid, ManagedSite> {
        &self.sites
    }

    /// Project only default listeners into the existing default proxy. Its
    /// failover registry must never include aliases from a custom listener.
    pub fn default_config(&self) -> pingwaf_proto::SiteConfig {
        let mut rows: Vec<_> = self
            .sites
            .values()
            .filter(|item| item.ingress.is_none())
            .filter_map(|item| {
                Some((item.site.as_ref()?.clone(), item.failover_mode))
            })
            .collect();
        rows.sort_by(|a, b| a.0.id.cmp(&b.0.id));
        let policies = rows
            .iter()
            .map(|(site, mode)| pingwaf_proto::SitePolicy {
                domain: site.domain.clone(),
                alternate_domains: site.alternate_domains.clone(),
                mode: *mode,
            })
            .collect();
        // RuleCache reads the common registry from the first site's bundle.
        if let Some(bundle) =
            rows.first_mut().and_then(|(s, _)| s.rules.as_mut())
        {
            bundle.site_policies = policies;
        }
        pingwaf_proto::SiteConfig {
            sites: rows.into_iter().map(|(site, _)| site).collect(),
            ..Default::default()
        }
    }

    /// Compare decoded policy, not protobuf bytes or legacy fingerprints.
    #[cfg(target_os = "linux")]
    fn same_policy(&self, other: &Self) -> bool {
        self.sites == other.sites
    }

    #[cfg(target_os = "linux")]
    fn same_listener_policy(&self, other: &Self, listener: Listener) -> bool {
        let Some(routes) = self.routes.get(&listener) else {
            return false;
        };
        other.routes.get(&listener) == Some(routes)
            && routes
                .values()
                .all(|id| self.sites.get(id) == other.sites.get(id))
    }

    /// Takes the hostname only, not an HTTP authority or a forwarding header.
    /// A non-default listener cannot fall back to the default namespace.
    pub fn site_id(&self, listener: Listener, hostname: &str) -> Option<Uuid> {
        select(&self.routes, listener, hostname)
    }

    /// Compile the verified envelopes into immutable, UUID-keyed rules.
    /// Never populate or write the legacy domain-indexed cache.
    pub fn compile(&self) -> anyhow::Result<Compiled> {
        let mut compiled = HashMap::with_capacity(self.sites.len());
        for (id, envelope) in &self.sites {
            let site =
                envelope.site.as_ref().context("managed site is missing")?;
            let bundle = site
                .rules
                .as_ref()
                .context("managed rule bundle is missing")?;
            let rules = RuleCache::convert_site(site, bundle);
            compiled.insert(
                *id,
                CompiledSite {
                    rules: Arc::new(rules),
                    failover: cache::FailoverMode::from(envelope.failover_mode),
                    bundle_settings: CachedRules {
                        global_fail_open: bundle.default_fail_open,
                        global_cache: bundle.global_cache.as_ref().map(
                            |config| {
                                Arc::new(RuleCache::convert_global_cache(
                                    config,
                                ))
                            },
                        ),
                        origin_verify_cert: bundle.origin_verify_cert,
                        log_settings: bundle.log_settings.as_ref().map(
                            |config| {
                                Arc::new(RuleCache::convert_log_settings(
                                    config,
                                ))
                            },
                        ),
                        ..CachedRules::default()
                    },
                },
            );
        }
        Ok(Compiled {
            version: self.version,
            routes: self.routes.clone(),
            sites: compiled,
        })
    }
}

pub struct Compiled {
    version: Version,
    routes: HashMap<Listener, HashMap<String, Uuid>>,
    sites: HashMap<Uuid, CompiledSite>,
}

pub struct CompiledSite {
    pub rules: Arc<SiteRules>,
    pub failover: cache::FailoverMode,
    bundle_settings: CachedRules,
}

impl Compiled {
    pub fn version(&self) -> Version {
        self.version
    }

    pub fn site(&self, id: Uuid) -> Option<&CompiledSite> {
        self.sites.get(&id)
    }

    pub fn sites(&self) -> impl Iterator<Item = (Uuid, &CompiledSite)> {
        self.sites.iter().map(|(id, site)| (*id, site))
    }

    pub fn select(
        &self,
        listener: Listener,
        hostname: &str,
    ) -> Option<(Uuid, &CompiledSite)> {
        let id = select(&self.routes, listener, hostname)?;
        Some((id, self.site(id)?))
    }
}

impl CompiledSite {
    /// The proxy config converter may read only this site's rules and global
    /// settings. No legacy domain index or domain-only failover policies.
    pub fn translation_input(&self) -> CachedRules {
        CachedRules {
            sites: HashMap::from([(
                self.rules.site_id.clone(),
                self.rules.clone(),
            )]),
            ..self.bundle_settings.clone()
        }
    }
}

fn select(
    routes: &HashMap<Listener, HashMap<String, Uuid>>,
    listener: Listener,
    hostname: &str,
) -> Option<Uuid> {
    let names = routes.get(&listener)?;
    let hostname = hostname.strip_suffix('.').unwrap_or(hostname);
    let hostname = hostname.to_ascii_lowercase();
    (valid_hostname(&hostname) && !hostname.starts_with("*."))
        .then(|| lookup_with_wildcard(names, &hostname).copied())
        .flatten()
}

/// In-memory high-water mark. Carry it across registrations; an unexpected
/// authority change or generation reset must not turn into an implicit reset.
#[derive(Default)]
pub struct Receiver {
    session: Option<Uuid>,
    received: Option<Version>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Version {
    pub session: Uuid,
    pub authority: Uuid,
    pub generation: i64,
    pub hash: [u8; 32],
}

impl Receiver {
    /// `session` comes from the agreed registration, never from a snapshot.
    pub fn set_session(&mut self, session: Option<Uuid>) {
        self.session = session;
    }

    /// Returns a new candidate, or `None` for an identical retransmission.
    /// On error the previous received high-water mark is unchanged.
    pub fn receive(
        &mut self,
        snapshot: ManagedSnapshot,
    ) -> anyhow::Result<Option<Candidate>> {
        let session = parse_uuid(&snapshot.session_id)?;
        let authority = parse_uuid(&snapshot.authority_epoch)?;
        ensure!(self.session == Some(session), "managed session mismatch");
        ensure!(snapshot.generation > 0, "invalid managed generation");
        ensure!(
            snapshot.config.len() <= MAX_MANAGED_CONFIG_BYTES,
            "managed snapshot too large"
        );
        let hash = Sha256::digest(&snapshot.config);
        ensure!(
            hex::encode(hash) == snapshot.config_hash,
            "managed snapshot checksum mismatch"
        );
        let version = Version {
            session,
            authority,
            generation: snapshot.generation,
            hash: hash.into(),
        };
        if let Some(previous) = &self.received {
            ensure!(
                authority == previous.authority,
                "managed authority changed"
            );
            ensure!(
                snapshot.generation >= previous.generation,
                "stale managed generation"
            );
            if snapshot.generation == previous.generation {
                ensure!(version == *previous, "managed generation was reused");
                return Ok(None);
            }
        }
        let data = ManagedSiteConfig::decode(snapshot.config.as_slice())
            .context("invalid managed configuration")?;
        let candidate = index(data, version)?;
        self.received = Some(version);
        Ok(Some(candidate))
    }
}

pub(crate) fn parse_uuid(value: &str) -> anyhow::Result<Uuid> {
    let id = Uuid::parse_str(value).context("invalid managed UUID")?;
    ensure!(
        !id.is_nil() && id.to_string() == value,
        "invalid managed UUID"
    );
    Ok(id)
}

fn index(
    data: ManagedSiteConfig,
    version: Version,
) -> anyhow::Result<Candidate> {
    let mut candidate = Candidate {
        version,
        sites: HashMap::new(),
        routes: HashMap::new(),
    };
    let mut protocols = HashMap::new();
    for mut item in data.sites {
        let site = item.site.as_mut().context("managed site is missing")?;
        let bundle = site
            .rules
            .as_mut()
            .context("managed rule bundle is missing")?;
        let id = parse_uuid(&site.id)?;
        ensure!(
            site.id == bundle.site_id,
            "managed rule bundle belongs to a different site"
        );
        // Already verified the raw snapshot checksum. This field is a legacy
        // fingerprint of wire bytes; map iteration order can change it even
        // when the rule content is equal. Managed consumers don't read it.
        bundle.config_hash.clear();
        SiteStatusEnum::try_from(site.status)
            .context("invalid managed site status")?;
        ensure!(
            FailoverMode::try_from(item.failover_mode).is_ok(),
            "invalid managed failover policy"
        );
        let listener = match &item.ingress {
            None => Listener::Default,
            Some(ingress) => {
                let port = u16::try_from(ingress.port)
                    .context("invalid managed port")?;
                ensure!(!matches!(port, 0 | 80 | 443), "invalid managed port");
                let protocol = ingress.protocol();
                ensure!(
                    matches!(
                        protocol,
                        IngressProtocol::Http | IngressProtocol::Https
                    ),
                    "invalid managed protocol"
                );
                ensure!(
                    protocols
                        .insert(port, protocol)
                        .is_none_or(|old| old == protocol),
                    "conflicting managed listener protocols"
                );
                Listener::Custom { port, protocol }
            },
        };
        let names = candidate.routes.entry(listener).or_default();
        for hostname in
            std::iter::once(&site.domain).chain(&site.alternate_domains)
        {
            ensure!(valid_hostname(hostname), "invalid managed hostname");
            ensure!(
                names.insert(hostname.clone(), id).is_none(),
                "conflicting managed hostname"
            );
        }
        // Reserve paused names during validation, but do not route to them.
        // Custom delivery normally excludes them altogether.
        ensure!(
            candidate.sites.insert(id, item).is_none(),
            "duplicate managed site UUID"
        );
    }
    for names in candidate.routes.values_mut() {
        ensure!(
            names
                .iter()
                .all(|(name, id)| !overlaps_other_site(names, name, id)),
            "overlapping managed hostnames"
        );
        names.retain(|_, id| {
            candidate
                .sites
                .get(id)
                .and_then(|item| item.site.as_ref())
                .is_some_and(|site| {
                    site.status() == SiteStatusEnum::SiteStatusActive
                })
        });
    }
    Ok(candidate)
}

fn valid_hostname(hostname: &str) -> bool {
    if hostname.len() > 253 {
        return false;
    }
    let raw = if let Some(suffix) = hostname.strip_prefix("*.") {
        if !suffix.contains('.') {
            return false;
        }
        suffix
    } else {
        hostname
    };
    raw.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'))
    })
}

fn overlaps_other_site(
    names: &HashMap<String, Uuid>,
    name: &str,
    id: &Uuid,
) -> bool {
    let mut rest = name.strip_prefix("*.").unwrap_or(name);
    let mut wildcard = String::with_capacity(rest.len() + 2);
    while let Some((_, suffix)) = rest.split_once('.') {
        wildcard.clear();
        wildcard.push_str("*.");
        wildcard.push_str(suffix);
        if names.get(&wildcard).is_some_and(|other| other != id) {
            return true;
        }
        rest = suffix;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingwaf_proto::{RuleBundle, Site, SiteIngress};

    fn managed(
        domain: &str,
        ingress: Option<(u32, IngressProtocol)>,
    ) -> (Uuid, ManagedSite) {
        let id = Uuid::new_v4();
        let site = ManagedSite {
            site: Some(Site {
                id: id.to_string(),
                domain: domain.to_owned(),
                rules: Some(RuleBundle {
                    site_id: id.to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ingress: ingress.map(|(port, protocol)| SiteIngress {
                port,
                protocol: protocol as i32,
            }),
            ..Default::default()
        };
        (id, site)
    }

    fn seal(snapshot: &mut ManagedSnapshot) {
        snapshot.config_hash = hex::encode(Sha256::digest(&snapshot.config));
    }

    fn snapshot(
        session: Uuid,
        epoch: Uuid,
        generation: i64,
        sites: Vec<ManagedSite>,
    ) -> ManagedSnapshot {
        let mut snapshot = ManagedSnapshot {
            session_id: session.to_string(),
            authority_epoch: epoch.to_string(),
            generation,
            config: ManagedSiteConfig { sites }.encode_to_vec(),
            ..Default::default()
        };
        seal(&mut snapshot);
        snapshot
    }

    #[test]
    fn selects_uuid_by_listener_before_hostname_and_never_falls_back() {
        use IngressProtocol::{Http, Https};
        let (default_id, default) = managed("shared.example", None);
        let (http_id, http) = managed("shared.example", Some((81, Http)));
        let (https_id, mut https) =
            managed("shared.example", Some((82, Https)));
        https.site.as_mut().unwrap().alternate_domains =
            vec!["*.alias.example".into()];
        let (mtls_id, mtls) = managed("shared.example", Some((83, Https)));
        let (_, mut paused) = managed("paused.example", None);
        paused.site.as_mut().unwrap().status =
            SiteStatusEnum::SiteStatusPaused as i32;
        let session = Uuid::new_v4();
        let mut receiver = Receiver::default();
        receiver.set_session(Some(session));
        let candidate = receiver
            .receive(snapshot(
                session,
                Uuid::new_v4(),
                1,
                vec![default, http, https, mtls, paused],
            ))
            .unwrap()
            .unwrap();
        let custom = |port, protocol| Listener::Custom { port, protocol };
        for (listener, id) in [
            (Listener::Default, default_id),
            (custom(81, Http), http_id),
            (custom(82, Https), https_id),
            (custom(83, Https), mtls_id),
        ] {
            assert_eq!(
                candidate.site_id(listener, "Shared.Example."),
                Some(id)
            );
        }
        for listener in [custom(82, Http), custom(84, Https)] {
            assert_eq!(candidate.site_id(listener, "shared.example"), None);
        }
        assert_eq!(
            candidate.site_id(custom(82, Https), "a.b.alias.example"),
            Some(https_id)
        );
        for host in [
            "alias.example",
            "*.alias.example",
            "a.alias.example:82",
            "shared.example..",
        ] {
            assert_eq!(candidate.site_id(custom(82, Https), host), None);
        }
        assert_eq!(
            candidate.site_id(Listener::Default, "paused.example"),
            None
        );
    }

    #[test]
    fn same_domain_compiles_to_independent_rules_and_policy_by_port() {
        let http = IngressProtocol::Http;
        let (id81, mut site81) = managed("shared.example", Some((81, http)));
        let (id82, mut site82) = managed("shared.example", Some((82, http)));
        site81.failover_mode = 1;
        site82.failover_mode = 2;
        site81.site.as_mut().unwrap().trust_proxy_headers = true;
        site82.site.as_mut().unwrap().downstream_timeout_secs = 17;
        let session = Uuid::new_v4();
        let mut receiver = Receiver::default();
        receiver.set_session(Some(session));
        let candidate = receiver
            .receive(snapshot(session, Uuid::new_v4(), 1, vec![site81, site82]))
            .unwrap()
            .unwrap();
        let compiled = candidate.compile().unwrap();
        assert_eq!(compiled.version(), candidate.version());
        let lookup = |port| {
            compiled.select(
                Listener::Custom {
                    port,
                    protocol: http,
                },
                "Shared.Example.",
            )
        };
        let (matched81, a) = lookup(81).unwrap();
        let (matched82, b) = lookup(82).unwrap();
        assert_eq!((matched81, matched82), (id81, id82));
        assert!(a.rules.proxy_trust.enabled);
        assert!(!b.rules.proxy_trust.enabled);
        assert_eq!(b.rules.downstream_timeout_secs, 17);
        assert_eq!(a.failover, cache::FailoverMode::Open);
        assert_eq!(b.failover, cache::FailoverMode::Closed);
        assert!(lookup(83).is_none());
        assert!(compiled
            .select(Listener::Default, "shared.example")
            .is_none());
        let config = b.translation_input();
        assert_eq!(config.sites.len(), 1);
        assert!(config.sites.contains_key(id82.to_string().as_str()));
        assert!(config.domain_index.is_empty());
        assert!(config.failover_registry.is_empty());
    }

    #[test]
    fn old_sessions_and_generations_cannot_replace_new_candidates() {
        let session = Uuid::new_v4();
        let next_session = Uuid::new_v4();
        let epoch = Uuid::new_v4();
        let (_, site) =
            managed("shared.example", Some((81, IngressProtocol::Http)));
        let initial = snapshot(session, epoch, 3, vec![site.clone()]);
        let mut receiver = Receiver::default();
        assert!(receiver.receive(initial.clone()).is_err());
        receiver.set_session(Some(session));
        assert!(receiver.receive(initial.clone()).unwrap().is_some());
        assert!(receiver.receive(initial.clone()).unwrap().is_none());
        assert!(receiver
            .receive(snapshot(session, epoch, 2, vec![]))
            .is_err());
        assert!(receiver
            .receive(snapshot(session, epoch, 3, vec![]))
            .is_err());
        assert!(receiver
            .receive(snapshot(session, Uuid::new_v4(), 4, vec![]))
            .is_err());
        receiver.set_session(Some(next_session));
        assert!(receiver.receive(initial).is_err());
        assert!(receiver
            .receive(snapshot(next_session, epoch, 3, vec![site]))
            .is_err());
        let candidate = receiver
            .receive(snapshot(next_session, epoch, 4, vec![]))
            .unwrap()
            .unwrap();
        assert_eq!(candidate.version().session, next_session);
        assert_eq!(candidate.version().generation, 4);
        assert!(candidate.sites().is_empty());
    }

    #[test]
    fn validates_exact_bytes_before_decoding_and_does_not_advance_on_error() {
        let session = Uuid::new_v4();
        let epoch = Uuid::new_v4();
        let mut receiver = Receiver::default();
        receiver.set_session(Some(session));
        let valid = snapshot(session, epoch, 1, vec![]);
        let mut corrupt = valid.clone();
        corrupt.generation = 2;
        corrupt.config = vec![0xff];
        assert!(receiver.receive(corrupt.clone()).is_err());
        seal(&mut corrupt);
        assert!(receiver.receive(corrupt).is_err());
        let mut large = valid.clone();
        large.generation = 2;
        large.config.resize(MAX_MANAGED_CONFIG_BYTES + 1, 0);
        assert!(receiver.receive(large).is_err());
        let mut unknown_field = valid;
        // Field 2 (not known to this proto), varint 1. Re-encoding drops it.
        unknown_field.config = vec![0x10, 1];
        seal(&mut unknown_field);
        assert!(receiver.receive(unknown_field).unwrap().is_some());
    }

    #[test]
    fn rejects_ambiguous_or_inconsistent_sites_as_one_candidate() {
        use IngressProtocol::{Http, Https};
        let (_, wildcard) = managed("*.shared.example", Some((81, Http)));
        let (_, nested) = managed("*.a.shared.example", Some((81, Http)));
        let (_, exact) = managed("a.shared.example", Some((81, Http)));
        let (_, other_protocol) = managed("another.example", Some((81, Https)));
        let (_, bad_port) = managed("another.example", Some((443, Https)));
        let (_, mut wrong_bundle) = managed("another.example", None);
        wrong_bundle.site.as_mut().unwrap().id = Uuid::new_v4().to_string();
        let (_, mut unknown_status) = managed("another.example", None);
        unknown_status.site.as_mut().unwrap().status = i32::MAX;
        let session = Uuid::new_v4();
        let epoch = Uuid::new_v4();
        let mut receiver = Receiver::default();
        receiver.set_session(Some(session));
        for sites in [
            vec![wildcard.clone(), nested],
            vec![exact.clone(), wildcard.clone()],
            vec![exact.clone(), exact.clone()],
            vec![exact.clone(), other_protocol],
            vec![bad_port],
            vec![wrong_bundle],
            vec![unknown_status],
        ] {
            assert!(receiver
                .receive(snapshot(session, epoch, 2, sites))
                .is_err());
        }
        assert!(receiver
            .receive(snapshot(session, epoch, 1, vec![wildcard]))
            .unwrap()
            .is_some());
    }
}
