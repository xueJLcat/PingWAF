//! Telegram Bot API delivery for control-plane alerts.

use serde_json::{json, Value};

use super::AlertEvent;

/// Message reported for any unusable `chat_id`, whatever the shape was.
const INVALID_CHAT_ID: &str =
    "config.chat_id must be a numeric chat ID or @channel username";

/// Longest slice of a Bot API description echoed back to the operator. The
/// real text ("Bad Request: chat not found") is short; the cap keeps a
/// tampered response from flooding the log or the console.
const MAX_ERROR_DETAIL: usize = 200;

/// Largest failed response body read back. A Bot API answer is a small JSON
/// object; anything bigger is not worth parsing, and reading it would let a
/// hijacked host decide how much memory the control plane spends.
const MAX_RESPONSE_BYTES: usize = 8 * 1024;

fn token(config: &Value) -> Result<&str, String> {
    let value = config
        .get("bot_token")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();

    let valid = value.split_once(':').is_some_and(|(id, secret)| {
        !id.is_empty()
            && id.bytes().all(|b| b.is_ascii_digit())
            && !secret.is_empty()
            && secret
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    });

    if !valid {
        return Err("config.bot_token is not a valid Telegram bot token".into());
    }

    Ok(value)
}

/// The chat to post into, normalised to the string form the Bot API accepts.
///
/// A `@channel` username, a numeric string, and a bare JSON number are all
/// valid: configuration written by a script (Ansible, a restored backup, the
/// REST API directly) may well carry the number unquoted, and rejecting that
/// would deny the very shape Telegram itself documents.
fn chat_id(config: &Value) -> Result<String, String> {
    if let Some(id) = config.get("chat_id").and_then(Value::as_i64) {
        return if id == 0 {
            Err(INVALID_CHAT_ID.to_string())
        } else {
            Ok(id.to_string())
        };
    }

    let value = config
        .get("chat_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();

    // A numeric string is normalised through the parsed id, not echoed back:
    // `"007"` and `"+100123"` parse locally but are not what the Bot API takes.
    if let Ok(id) = value.parse::<i64>() {
        return if id == 0 {
            Err(INVALID_CHAT_ID.to_string())
        } else {
            Ok(id.to_string())
        };
    }

    let username = value.strip_prefix('@').is_some_and(|name| {
        !name.is_empty()
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    });

    if !username {
        return Err(INVALID_CHAT_ID.to_string());
    }

    Ok(value.to_string())
}

fn thread_id(config: &Value) -> Result<Option<i32>, String> {
    match config.get("message_thread_id") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.trim().is_empty() => Ok(None),
        Some(value) => {
            let id = value
                .as_i64()
                .and_then(|n| i32::try_from(n).ok())
                .or_else(|| value.as_str().and_then(|s| s.trim().parse().ok()));

            id.filter(|n| *n > 0).map(Some).ok_or_else(|| {
                "config.message_thread_id must be a positive integer".into()
            })
        },
    }
}

pub fn validate_config(config: &Value) -> Result<(), String> {
    token(config)?;
    chat_id(config)?;
    thread_id(config)?;
    Ok(())
}

fn truncate_message(text: &str, max_units: usize) -> String {
    let mut result = String::new();
    let mut units = 0;
    // One unit is always reserved for the ellipsis, so a zero budget still
    // has to yield something no longer than the budget it was given.
    let budget = max_units.max(1);

    for ch in text.chars() {
        if units + ch.len_utf16() > budget - 1 {
            result.push('…');
            return result;
        }

        units += ch.len_utf16();
        result.push(ch);
    }

    result
}

fn payload(config: &Value, event: &AlertEvent) -> Result<Value, String> {
    let indicator = match event.severity {
        "critical" => "🔴",
        "warning" => "🟠",
        "info" => "ℹ️",
        _ => "🔔",
    };

    let text = format!(
        "{} PingWAF — {}\n\n{}\n\n\
         Severity: {}\n\
         Event: {}\n\
         Time: {}",
        indicator,
        truncate_message(&event.title, 400),
        truncate_message(&event.message, 3000),
        event.severity,
        truncate_message(&event.event_type, 100),
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
    );

    // Plain text prevents alert content from being interpreted as markup.
    let mut body = json!({
        "chat_id": chat_id(config)?,
        "text": truncate_message(&text, 4096),
        "link_preview_options": {
            "is_disabled": true
        }
    });

    if let Some(id) = thread_id(config)? {
        body["message_thread_id"] = json!(id);
    }

    Ok(body)
}

/// Flattens a Bot API `description` into text safe to log or show: no control
/// characters, no echo of the bot token, and a bounded length.
fn sanitise_detail(raw: &str, token: &str) -> String {
    let flat: String = raw
        .chars()
        .filter(|ch| !ch.is_control())
        .take(MAX_ERROR_DETAIL * 2)
        .collect();
    let redacted = if token.is_empty() {
        flat
    } else {
        flat.replace(token, "<redacted>")
    };
    redacted
        .chars()
        .take(MAX_ERROR_DETAIL)
        .collect::<String>()
        .trim()
        .to_string()
}

/// Turns a Bot API response into the outcome reported to the operator.
///
/// Telegram puts the reason for a refusal in `description` ("chat not found",
/// "message thread not found", "bot was blocked by the user"), which is the
/// difference between an operator fixing the channel and guessing. The text is
/// Telegram's own, not attacker-controlled content fetched from a configured
/// URL, and it is capped and token-scrubbed before it leaves this function.
fn interpret(
    status: reqwest::StatusCode,
    body: &[u8],
    token: &str,
) -> Result<(), String> {
    let parsed: Option<Value> = serde_json::from_slice(body).ok();
    let detail = parsed
        .as_ref()
        .and_then(|value| value.get("description"))
        .and_then(Value::as_str)
        .map(|raw| sanitise_detail(raw, token));

    if status.as_u16() == 429 {
        return Err(match detail {
            Some(detail) => {
                format!("Telegram rate limit exceeded (HTTP 429): {detail}")
            },
            None => "Telegram rate limit exceeded (HTTP 429)".to_string(),
        });
    }

    if !status.is_success() {
        return Err(match detail {
            Some(detail) => {
                format!("Telegram returned HTTP {status}: {detail}")
            },
            None => format!("Telegram returned HTTP {status}"),
        });
    }

    match (
        parsed
            .as_ref()
            .and_then(|value| value.get("ok"))
            .and_then(Value::as_bool),
        detail,
    ) {
        (Some(true), _) => Ok(()),
        (_, Some(detail)) => {
            Err(format!("Telegram rejected the notification: {detail}"))
        },
        (_, None) => Err("Invalid Telegram API response".to_string()),
    }
}

pub async fn send(
    http: &reqwest::Client,
    config: &Value,
    event: &AlertEvent,
) -> Result<(), String> {
    let token = token(config)?;
    let body = payload(config, event)?;

    // Keep the destination fixed. Never expose the request URL or the raw
    // transport error: the URL contains the token.
    let url = format!("https://api.telegram.org/bot{token}/sendMessage");

    let response = http
        .post(url)
        .json(&body)
        .send()
        .await
        .map_err(|_| "Telegram request failed".to_string())?;

    let status = response.status();
    // The refusal reason lives in the body, but the body is not ours to trust
    // with unbounded memory: skip anything claiming more than a Bot API reply.
    let oversized = response
        .content_length()
        .is_some_and(|length| length as usize > MAX_RESPONSE_BYTES);
    let body = if oversized {
        Vec::new()
    } else {
        response.bytes().await.unwrap_or_default().to_vec()
    };

    interpret(status, &body, token)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Value {
        json!({
            "bot_token": "123:abc_DEF-1",
            "chat_id": "-1001234567890"
        })
    }

    fn event() -> AlertEvent {
        AlertEvent {
            event_type: "agent.offline".into(),
            severity: "warning",
            title: "Agent offline".into(),
            message: "Agent has stopped responding.".into(),
            details: None,
            dedup_key: None,
        }
    }

    #[test]
    fn valid_configuration() {
        assert!(validate_config(&config()).is_ok());
    }

    #[test]
    fn invalid_token_is_rejected() {
        for value in ["", "__REDACTED__", "123:abc/evil", "abc:123"] {
            let mut cfg = config();
            cfg["bot_token"] = json!(value);

            assert!(validate_config(&cfg).is_err());
        }
    }

    #[test]
    fn invalid_chat_id_is_rejected() {
        let mut cfg = config();

        for value in ["", "0", "invalid", "@"] {
            cfg["chat_id"] = json!(value);
            assert!(validate_config(&cfg).is_err());
        }
    }

    #[test]
    fn channel_username_is_supported() {
        let mut cfg = config();
        cfg["chat_id"] = json!("@operations_alerts");

        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn topic_id_is_optional() {
        let body = payload(&config(), &event()).unwrap();

        assert!(body.get("message_thread_id").is_none());
    }

    #[test]
    fn topic_id_is_included() {
        let mut cfg = config();
        cfg["message_thread_id"] = json!("42");

        let body = payload(&cfg, &event()).unwrap();

        assert_eq!(body["message_thread_id"], 42);
    }

    #[test]
    fn invalid_topic_is_rejected() {
        let mut cfg = config();
        cfg["message_thread_id"] = json!(-1);

        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn message_is_plain_text() {
        let mut evt = event();
        evt.message = "<test> *test* _test_".into();

        let body = payload(&config(), &evt).unwrap();

        assert!(body.get("parse_mode").is_none());
        assert!(body["text"].as_str().unwrap().contains(&evt.message));
    }

    #[test]
    fn message_does_not_contain_token() {
        let body = payload(&config(), &event()).unwrap();

        assert!(!body.to_string().contains("123:abc_DEF-1"));
    }

    #[test]
    fn long_unicode_messages_are_truncated() {
        let mut evt = event();
        evt.message = "😀".repeat(5000);

        let body = payload(&config(), &evt).unwrap();
        let text = body["text"].as_str().unwrap();

        assert!(text.encode_utf16().count() <= 4096);
        assert!(text.contains("Severity: warning"));
    }

    #[test]
    fn numeric_chat_id_is_accepted_and_normalised() {
        let mut cfg = config();
        cfg["chat_id"] = json!(-1001234567890i64);

        assert!(validate_config(&cfg).is_ok());
        let body = payload(&cfg, &event()).unwrap();
        assert_eq!(body["chat_id"], json!("-1001234567890"));
    }

    #[test]
    fn numeric_string_chat_id_is_normalised() {
        for (input, expected) in
            [("007", "7"), ("+1001234567890", "1001234567890")]
        {
            let mut cfg = config();
            cfg["chat_id"] = json!(input);

            assert!(
                validate_config(&cfg).is_ok(),
                "{input} should be accepted"
            );
            let body = payload(&cfg, &event()).unwrap();
            assert_eq!(body["chat_id"], json!(expected));
        }
    }

    #[test]
    fn zero_budget_truncation_stays_within_budget() {
        assert!(truncate_message("abc", 0).encode_utf16().count() <= 1);
        assert_eq!(truncate_message("abc", 1), "…");
    }

    #[test]
    fn non_integer_chat_id_shapes_are_rejected() {
        for value in [json!(0), json!(1.5), json!(true), json!(["1"])] {
            let mut cfg = config();
            cfg["chat_id"] = value.clone();
            assert!(
                validate_config(&cfg).is_err(),
                "chat_id {value} should be rejected"
            );
        }
    }

    #[test]
    fn accepted_response_is_ok() {
        assert!(interpret(
            reqwest::StatusCode::OK,
            br#"{"ok":true,"result":{}}"#,
            "123:abc_DEF-1"
        )
        .is_ok());
    }

    #[test]
    fn refusal_reason_reaches_the_caller() {
        let err = interpret(
            reqwest::StatusCode::BAD_REQUEST,
            br#"{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}"#,
            "123:abc_DEF-1",
        )
        .unwrap_err();

        assert!(err.contains("chat not found"), "unexpected error: {err}");
        assert!(err.contains("400"));
    }

    #[test]
    fn refusal_reason_never_echoes_the_token() {
        let token = "123:abc_DEF-1";
        let body = format!(
            r#"{{"ok":false,"error_code":401,"description":"Unauthorized {token}"}}"#
        );
        let err = interpret(
            reqwest::StatusCode::UNAUTHORIZED,
            body.as_bytes(),
            token,
        )
        .unwrap_err();

        assert!(!err.contains(token), "token leaked: {err}");
        assert!(err.contains("<redacted>"));
    }

    #[test]
    fn rate_limit_is_reported_separately() {
        let err = interpret(
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            br#"{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 5"}"#,
            "123:abc_DEF-1",
        )
        .unwrap_err();

        assert!(err.contains("rate limit"));
        assert!(err.contains("retry after 5"));
    }

    #[test]
    fn non_json_success_body_is_reported_as_invalid() {
        let err = interpret(
            reqwest::StatusCode::OK,
            b"<html>gateway</html>",
            "123:abc_DEF-1",
        )
        .unwrap_err();

        assert_eq!(err, "Invalid Telegram API response");
    }

    #[test]
    fn error_detail_is_capped_and_flattened() {
        let raw = format!("Bad\u{7}Request: {}", "x".repeat(5000));
        let err = interpret(
            reqwest::StatusCode::BAD_REQUEST,
            format!(r#"{{"ok":false,"description":"{raw}"}}"#).as_bytes(),
            "",
        )
        .unwrap_err();

        assert!(!err.contains('\u{7}'), "control character kept");
        assert!(err.chars().count() <= MAX_ERROR_DETAIL + 40);
    }
}
