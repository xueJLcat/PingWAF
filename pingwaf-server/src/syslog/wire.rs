use super::config::Config;
use chrono::{DateTime, SecondsFormat, Utc};
use pingwaf_proto::control_plane::LogEntry;
use serde_json::{json, Map, Value};
use std::net::IpAddr;
use uuid::Uuid;

pub struct Packet {
    pub id: Uuid,
    pub revision: i64,
    pub kind: &'static str,
    pub bytes: Vec<u8>,
}

fn masked(ip: &str, mode: &str) -> Option<String> {
    let ip: IpAddr = ip.parse().ok()?;
    match (mode, ip) {
        ("full", ip) => Some(ip.to_string()),
        ("mask", IpAddr::V4(v)) => Some(format!(
            "{}.{}.{}.0/24",
            v.octets()[0],
            v.octets()[1],
            v.octets()[2]
        )),
        ("mask", IpAddr::V6(v)) => Some(format!(
            "{:x}:{:x}:{:x}::/48",
            v.segments()[0],
            v.segments()[1],
            v.segments()[2]
        )),
        _ => None,
    }
}
pub fn severity(entry: &LogEntry, security: bool) -> u8 {
    if security {
        match entry.waf_action.as_str() {
            "block" | "deny" | "challenge" | "drop" | "captcha" => 4,
            "log" | "monitor" | "observe" => 5,
            _ => 6,
        }
    } else {
        match entry.response_status {
            500..=599 => 3,
            400..=499 => 5,
            _ => 6,
        }
    }
}
pub fn encode(
    c: &Config,
    rev: i64,
    entry: &LogEntry,
    agent: Uuid,
    site: Option<Uuid>,
    time: DateTime<Utc>,
    kind: &'static str,
    sev: u8,
) -> Option<Packet> {
    static HOST: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    let hostname = if c.hostname.is_empty() {
        HOST.get_or_init(|| {
            let h = crate::hostname();
            if !h.is_empty()
                && h.len() <= 253
                && h.bytes().all(|b| b.is_ascii_graphic())
            {
                h
            } else {
                "pingwaf".into()
            }
        })
    } else {
        &c.hostname
    };
    let pri = c.facility as u16 * 8 + sev as u16;
    let ts = time.to_rfc3339_opts(SecondsFormat::Millis, true);
    let header = if c.format == "5424" {
        format!("<{pri}>1 {ts} {hostname} {} - {kind} - ", c.app)
    } else {
        format!("<{pri}>{} {hostname} {}: ", time.format("%b %e %T"), c.app)
    };
    let id = Uuid::new_v4();
    let mut body = Map::new();
    body.insert("event_id".into(), json!(id));
    body.insert("kind".into(), json!(kind));
    body.insert("time".into(), json!(ts));
    body.insert("agent_id".into(), json!(agent));
    if let Some(site) = site {
        body.insert("site_id".into(), json!(site));
    }
    for (k, val) in [
        ("request_id", entry.request_id.as_str()),
        ("method", &entry.method),
        ("host", &entry.host),
        (
            "path",
            entry.path.split(['?', '#']).next().unwrap_or_default(),
        ),
    ] {
        if !val.is_empty() {
            body.insert(
                k.into(),
                json!(val.chars().take(2048).collect::<String>()),
            );
        }
    }
    if kind == "security" {
        let rule = if entry.waf_enforced_rule_id.is_empty() {
            &entry.waf_rule_id
        } else {
            &entry.waf_enforced_rule_id
        };
        body.insert(
            "rule_id".into(),
            json!(rule.chars().take(256).collect::<String>()),
        );
        body.insert(
            "action".into(),
            json!(entry.waf_action.chars().take(64).collect::<String>()),
        );
    } else if entry.response_status != 0 {
        body.insert("status".into(), json!(entry.response_status));
    }
    if let Some(ip) = masked(&entry.client_ip, &c.ip_mode) {
        body.insert("client_ip".into(), json!(ip));
    }
    let limit = if c.format == "3164" {
        c.max_bytes.min(1024)
    } else {
        c.max_bytes
    };
    for field in [
        "path",
        "host",
        "request_id",
        "rule_id",
        "client_ip",
        "method",
        "action",
        "status",
        "",
    ] {
        let render = |fields: &Map<String, Value>| {
            if c.body == "json" {
                serde_json::to_string(fields).unwrap()
            } else {
                fields
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            }
        };
        let message = render(&body);
        if header.len() + message.len() <= limit {
            return Some(Packet {
                id,
                revision: rev,
                kind,
                bytes: [header.as_bytes(), message.as_bytes()].concat(),
            });
        }
        if let Some(Value::String(v)) = body.get_mut(field) {
            let over = header.len() + message.len() - limit;
            let n = v.floor_char_boundary(v.len().saturating_sub(over));
            if n > 0 {
                v.truncate(n);
                let txt = render(&body);
                if header.len() + txt.len() <= limit {
                    return Some(Packet {
                        id,
                        revision: rev,
                        kind,
                        bytes: [header.as_bytes(), txt.as_bytes()].concat(),
                    });
                }
            }
        }
        body.remove(field);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_preserves_identity_and_excludes_sensitive_data_after_truncation()
    {
        let mut entry = LogEntry::default();
        entry.path = format!("/{}?token=secret", "测试".repeat(500));
        entry.client_ip = "2001:db8:abcd:1234::1".into();
        entry.waf_details = "private rule details".into();
        let c = Config {
            max_bytes: 480,
            ..Default::default()
        };
        let site = Uuid::new_v4();
        let agent = Uuid::new_v4();
        let p =
            encode(&c, 4, &entry, agent, Some(site), Utc::now(), "security", 4)
                .unwrap();
        let msg = std::str::from_utf8(&p.bytes).unwrap();
        assert!(msg.starts_with("<132>1 ") && msg.len() <= 480);
        let v: Value =
            serde_json::from_str(&msg[msg.find('{').unwrap()..]).unwrap();
        assert_eq!(v["event_id"], json!(p.id));
        assert_eq!(v["agent_id"], json!(agent));
        assert_eq!(v["site_id"], json!(site));
        assert_eq!(v["client_ip"], "2001:db8:abcd::/48");
        assert!(!msg.contains("secret") && !msg.contains("private rule"));
        assert_eq!(masked("192.0.2.99", "mask").unwrap(), "192.0.2.0/24");
        assert!(masked("192.0.2.99", "omit").is_none());
    }

    #[test]
    fn legacy_frame_escapes_line_breaks_and_applies_its_own_size_limit() {
        let c = Config {
            format: "3164".into(),
            body: "kv".into(),
            ..Default::default()
        };
        let mut entry = LogEntry::default();
        entry.path = format!("/a\nb{}", "x".repeat(2000));
        let p =
            encode(&c, 1, &entry, Uuid::nil(), None, Utc::now(), "access", 6)
                .unwrap();
        let text = String::from_utf8(p.bytes).unwrap();
        assert!(
            text.len() <= 1024 && !text.contains('\n') && text.contains("\\n")
        );
        assert!(text.starts_with("<134>") && text.contains("event_id="));
    }
}
