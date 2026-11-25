//! Minting of the short-lived session tokens the edges verify.
//!
//! The signing key is **derived from `jwt_secret`** with a domain-separated
//! hash, so there is no new secret to store, back up or rotate independently:
//! the key exists only in the control plane's memory and rotates with the JWT
//! secret. The public half travels in every rule bundle, which is what lets an
//! edge verify a token without ever holding the connector's credential.
//!
//! Deriving rather than storing is deliberate: a stored Ed25519 key would be a
//! second secret with its own backup/restore problem, and this one has no
//! reason to outlive the deployment's existing secret.

use std::sync::OnceLock;

use anyhow::{anyhow, Result};
use ring::signature::{Ed25519KeyPair, KeyPair};
use ring::hmac;

use pingwaf_tunnel::token::{self, SessionTokenClaims};

/// Domain separator: the same `jwt_secret` must never yield the same key for
/// two different purposes.
const SEED_CONTEXT: &[u8] = b"pingwaf-tunnel-session-token-v2";
static SIGNER: OnceLock<hmac::Key> = OnceLock::new();

/// Derives the signing key from the deployment's JWT secret.
///
/// Idempotent: the first call wins, later calls are no-ops, so a hot reload of
/// the configuration cannot silently swap the key out from under the edges.
pub fn init(jwt_secret: &str) {
    SIGNER.get_or_init(|| hmac::Key::new(hmac::HMAC_SHA256, jwt_secret.as_bytes()));
}

fn signing_key(tunnel_id: &str, credential_digest: &str) -> Result<Ed25519KeyPair> {
    let root = SIGNER.get().ok_or_else(|| anyhow!("tunnel signing key is not initialised"))?;
    let digest = hex::decode(credential_digest)?;
    anyhow::ensure!(digest.len() == 32, "invalid tunnel credential digest");
    let mut mac = hmac::Context::with_key(root);
    mac.update(SEED_CONTEXT);
    mac.update(tunnel_id.as_bytes());
    mac.update(&digest);
    Ed25519KeyPair::from_seed_unchecked(mac.sign().as_ref())
        .map_err(|_| anyhow!("cannot derive the tunnel signing key"))
}

/// Re-pairing changes the public key even when the edge missed the revocation.
pub fn public_key_hex(tunnel_id: &str, credential_digest: &str) -> Result<String> {
    Ok(token::public_key_hex(signing_key(tunnel_id, credential_digest)?.public_key().as_ref()))
}

/// Mints a token for `tunnel_id`, valid for `ttl_secs`.
///
/// Returns the token and its expiry (unix seconds), or an error when the key
/// was never initialised — the caller then refuses the pairing rather than
/// handing out a token no edge can verify.
pub fn mint(tunnel_id: &str, credential_digest: &str, ttl_secs: u64) -> Result<(String, i64)> {
    let signer = signing_key(tunnel_id, credential_digest)?;
    let now = chrono::Utc::now().timestamp();
    let ttl = ttl_secs.clamp(60, 86_400) as i64;
    let claims = SessionTokenClaims {
        tunnel_id: tunnel_id.to_string(),
        issued_at: now,
        expires_at: now + ttl,
    };
    let payload = token::payload_bytes(&claims);
    let signature = signer.sign(&payload);
    Ok((
        token::encode(&claims, signature.as_ref()),
        claims.expires_at,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_minted_token_verifies_against_the_published_key() {
        // The tests share one process-wide key; initialise it once.
        init("unit-test-jwt-secret-value");
        let digest = "ab".repeat(32);
        let key = public_key_hex("tunnel-1", &digest).unwrap();
        let (token, expires_at) = mint("tunnel-1", &digest, 600).unwrap();
        let now = chrono::Utc::now().timestamp();
        assert!(expires_at > now);
        let claims = token::verify(&token, &key, "tunnel-1", now)
            .expect("the freshly minted token must verify");
        assert_eq!(claims.expires_at, expires_at);
        // …and not for another tunnel.
        assert!(
            token::verify(&token, &key, "tunnel-2", now).is_err()
        );
        let rotated = public_key_hex("tunnel-1", &"cd".repeat(32)).unwrap();
        assert!(token::verify(&token, &rotated, "tunnel-1", now).is_err());
    }

    #[test]
    fn the_ttl_is_clamped() {
        init("unit-test-jwt-secret-value");
        let (_, expires_at) = mint("tunnel-1", &"ab".repeat(32), 1).unwrap();
        let now = chrono::Utc::now().timestamp();
        assert!(
            expires_at >= now + 60,
            "a token must live at least a minute"
        );
    }
}
