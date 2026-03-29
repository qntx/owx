//! API key file format, token generation, and hashing.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Token prefix that signals agent mode.
pub const TOKEN_PREFIX: &str = "owx_key_";

/// An API key file stored at `<vault>/keys/<id>.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ApiKeyFile {
    /// Unique key identifier (UUID v4).
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// SHA-256 hash of the raw token (hex-encoded).
    pub token_hash: String,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
    /// Wallet IDs this key can access.
    pub wallet_ids: Vec<String>,
    /// Policy IDs attached to this key (AND semantics).
    pub policy_ids: Vec<String>,
    /// Optional expiry timestamp (ISO-8601).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Per-wallet encrypted mnemonic copies, keyed by wallet ID.
    /// Each value is a [`CryptoEnvelope`](crate::CryptoEnvelope) encrypted with HKDF(token).
    pub wallet_secrets: HashMap<String, serde_json::Value>,
}

impl ApiKeyFile {
    /// Create a new API key file.
    #[must_use]
    pub const fn new(
        id: String,
        name: String,
        token_hash: String,
        created_at: String,
        wallet_ids: Vec<String>,
        policy_ids: Vec<String>,
        expires_at: Option<String>,
        wallet_secrets: HashMap<String, serde_json::Value>,
    ) -> Self {
        Self {
            id,
            name,
            token_hash,
            created_at,
            wallet_ids,
            policy_ids,
            expires_at,
            wallet_secrets,
        }
    }
}

/// Generate a random API token: `owx_key_<64 hex chars>` (256 bits of entropy).
pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    #[allow(clippy::expect_used)]
    getrandom::fill(&mut bytes).expect("system CSPRNG unavailable");
    format!("{TOKEN_PREFIX}{}", hex::encode(bytes))
}

/// SHA-256 hash of the raw token string, hex-encoded.
#[must_use]
pub fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    hex::encode(digest)
}

/// Check whether a credential string is an API token (starts with prefix).
#[must_use]
pub fn is_api_token(credential: &str) -> bool {
    credential.starts_with(TOKEN_PREFIX)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn token_format() {
        let token = generate_token();
        assert!(token.starts_with(TOKEN_PREFIX));
        assert_eq!(token.len(), 8 + 64); // prefix + 64 hex chars
    }

    #[test]
    fn token_uniqueness() {
        let t1 = generate_token();
        let t2 = generate_token();
        assert_ne!(t1, t2);
    }

    #[test]
    fn hash_deterministic() {
        let token = "owx_key_abc123";
        assert_eq!(hash_token(token), hash_token(token));
    }

    #[test]
    fn hash_differs() {
        assert_ne!(hash_token("owx_key_a"), hash_token("owx_key_b"));
    }

    #[test]
    fn is_api_token_check() {
        assert!(is_api_token("owx_key_abc"));
        assert!(!is_api_token("password123"));
        assert!(!is_api_token(""));
    }

    #[test]
    fn api_key_serde_roundtrip() {
        let key = ApiKeyFile {
            id: "test-id".into(),
            name: "test-agent".into(),
            token_hash: hash_token("owx_key_test"),
            created_at: "2026-01-01T00:00:00Z".into(),
            wallet_ids: vec!["w1".into()],
            policy_ids: vec!["p1".into()],
            expires_at: None,
            wallet_secrets: HashMap::new(),
        };
        let json = serde_json::to_string(&key).unwrap();
        let restored: ApiKeyFile = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.id, "test-id");
        assert!(!json.contains("expires_at"));
    }
}
