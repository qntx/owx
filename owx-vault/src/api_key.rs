//! API key file format (on-disk JSON).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// An API key file stored at `<vault>/keys/<id>.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Per-wallet encrypted secret copies, keyed by wallet ID.
    /// Each value is a `CryptoEnvelope` encrypted with HKDF(token).
    pub wallet_secrets: HashMap<String, serde_json::Value>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn serde_roundtrip() {
        let key = ApiKeyFile {
            id: "test-id".into(),
            name: "test-agent".into(),
            token_hash: "deadbeef".into(),
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

    #[test]
    fn with_expiry() {
        let key = ApiKeyFile {
            id: "test-id".into(),
            name: "expiring".into(),
            token_hash: "abc".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            wallet_ids: vec![],
            policy_ids: vec![],
            expires_at: Some("2026-12-31T00:00:00Z".into()),
            wallet_secrets: HashMap::new(),
        };
        let json = serde_json::to_string(&key).unwrap();
        assert!(json.contains("expires_at"));
    }
}
