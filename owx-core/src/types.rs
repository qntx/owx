//! Core shared types.

#![allow(missing_docs)]

use serde::{Deserialize, Serialize};

/// Unique wallet identifier (UUID v4).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WalletId(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    pub chain_id: String,
    pub address: String,
    pub derivation_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletInfo {
    pub id: String,
    pub name: String,
    pub accounts: Vec<AccountInfo>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyInfo {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub wallet_ids: Vec<String>,
    pub policy_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyCreateResult {
    pub token: String,
    pub key: ApiKeyInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResult {
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_id: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionSignResult {
    pub signature: String,
    pub signed_tx: String,
    pub tx_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendResult {
    pub tx_hash: String,
}

impl Default for WalletId {
    fn default() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }
}

impl WalletId {
    /// Generate a new random wallet ID.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn generates_valid_uuid() {
        let id = WalletId::new();
        assert!(!id.0.is_empty());
        assert!(uuid::Uuid::parse_str(&id.0).is_ok());
    }

    #[test]
    fn serde_transparent() {
        let id = WalletId("test-id".to_owned());
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"test-id\"");
        let restored: WalletId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, restored);
    }
}
