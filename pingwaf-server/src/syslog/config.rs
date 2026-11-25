use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub enabled: bool,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub transport: String,
    pub access: bool,
    pub security: bool,
    /// None means every site; an empty selection matches no rows.
    pub sites: Option<Vec<Uuid>>,
    pub facility: u8,
    pub severity: Option<u8>,
    pub threshold: u8,
    pub format: String,
    pub body: String,
    pub framing: String,
    pub hostname: String,
    pub app: String,
    pub ip_mode: String,
    pub max_bytes: usize,
    pub server_name: String,
    pub trust: String,
    pub mtls: bool,
    pub connect_seconds: u64,
    pub write_seconds: u64,
    pub retry_min: u64,
    pub retry_max: u64,
    pub retention_hours: u32,
    pub queue_mib: u32,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: false,
            name: "Syslog".into(),
            host: String::new(),
            port: 6514,
            transport: "tls".into(),
            access: false,
            security: true,
            sites: None,
            facility: 16,
            severity: None,
            threshold: 7,
            format: "5424".into(),
            body: "json".into(),
            framing: "octet".into(),
            hostname: String::new(),
            app: "pingwaf".into(),
            ip_mode: "mask".into(),
            max_bytes: 8192,
            server_name: String::new(),
            trust: "system".into(),
            mtls: false,
            connect_seconds: 5,
            write_seconds: 5,
            retry_min: 1,
            retry_max: 60,
            retention_hours: 24,
            queue_mib: 64,
        }
    }
}
fn valid_host(s: &str) -> bool {
    s.parse::<IpAddr>().is_ok()
        || (!s.is_empty()
            && s.len() <= 253
            && s.strip_suffix('.').unwrap_or(s).split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            }))
}
impl Config {
    pub fn validate(&self, active: bool) -> Result<()> {
        ensure!(
            self.name.chars().count() <= 64
                && (!active || !self.name.trim().is_empty()),
            "name: 1–64"
        );
        ensure!(
            valid_host(&self.host) || (!active && self.host.is_empty()),
            "host: invalid hostname or IP"
        );
        ensure!(self.port != 0, "port: 1–65535");
        ensure!(
            matches!(self.transport.as_str(), "udp" | "tcp" | "tls"),
            "transport"
        );
        ensure!(self.access || self.security || !active, "access/security");
        ensure!(
            self.sites.as_ref().is_none_or(|v| v.len() <= 10000),
            "sites"
        );
        ensure!(
            self.facility <= 23
                && self.severity.unwrap_or(0) <= 7
                && self.threshold <= 7,
            "facility/severity/threshold"
        );
        ensure!(
            matches!(self.ip_mode.as_str(), "omit" | "mask" | "full"),
            "ip_mode"
        );
        ensure!(matches!(self.body.as_str(), "json" | "kv"), "body");
        ensure!(matches!(self.format.as_str(), "3164" | "5424"), "format");
        ensure!(matches!(self.framing.as_str(), "octet" | "lf"), "framing");
        ensure!(
            self.transport != "tls"
                || (self.format == "5424" && self.framing == "octet"),
            "TLS requires RFC 5424 and octet framing"
        );
        ensure!(
            (480..=if self.transport == "udp" { 8192 } else { 65536 })
                .contains(&self.max_bytes),
            "max_bytes"
        );
        ensure!(
            self.app.len() <= 48
                && !self.app.is_empty()
                && self
                    .app
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
            "app"
        );
        ensure!(
            self.hostname.is_empty() || valid_host(&self.hostname),
            "hostname"
        );
        ensure!(
            self.server_name.is_empty() || valid_host(&self.server_name),
            "server_name"
        );
        ensure!(matches!(self.trust.as_str(), "system" | "custom"), "trust");
        ensure!(
            (1..=60).contains(&self.connect_seconds)
                && (1..=60).contains(&self.write_seconds),
            "timeout: 1–60 s"
        );
        ensure!(
            (1..=30).contains(&self.retry_min)
                && (self.retry_min..=300).contains(&self.retry_max),
            "retry"
        );
        ensure!(
            (1..=168).contains(&self.retention_hours)
                && (1..=512).contains(&self.queue_mib),
            "retention_hours/queue_mib"
        );
        Ok(())
    }
    pub fn target_changed(&self, other: &Self) -> bool {
        !self.host.eq_ignore_ascii_case(&other.host)
            || self.port != other.port
            || self.transport != other.transport
            || !self.server_name.eq_ignore_ascii_case(&other.server_name)
    }
    pub fn invalidates_queue(&self, next: &Self) -> bool {
        self.target_changed(next)
            || (!next.access && self.access)
            || (!next.security && self.security)
            || self.sites != next.sites
            || self.ip_mode != next.ip_mode
            || self.threshold != next.threshold
            || self.severity != next.severity
            || self.format != next.format
            || self.body != next.body
            || self.framing != next.framing
            || self.max_bytes > next.max_bytes
    }
}
