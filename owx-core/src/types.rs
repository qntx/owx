//! Shared DTO types for the public API surface.

use serde::{Deserialize, Serialize};

/// Unique wallet identifier (UUID v4).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WalletId(pub String);

/// A single account within a wallet (one per chain family).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    /// CAIP-2 chain identifier (e.g. `eip155:1`).
    pub chain_id: String,
    /// Address in the chain's native format.
    pub address: String,
    /// BIP-44 derivation path used (empty for imported private keys).
    pub derivation_path: String,
}

/// Public wallet information (no secret material exposed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletInfo {
    /// Unique wallet identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Derived accounts across chains.
    pub accounts: Vec<AccountInfo>,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
}

/// Public API key information (no token or secrets exposed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyInfo {
    /// Unique key identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
    /// Wallet IDs this key can access.
    pub wallet_ids: Vec<String>,
    /// Policy IDs attached to this key.
    pub policy_ids: Vec<String>,
    /// Optional expiry timestamp (ISO-8601).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// Result of creating an API key (shown once to the user).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyCreateResult {
    /// The raw API token (`owx_key_...`). Only returned at creation time.
    pub token: String,
    /// Public key metadata.
    pub key: ApiKeyInfo,
}

/// Result of a message signing operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResult {
    /// Hex-encoded signature.
    pub signature: String,
    /// ECDSA recovery ID (EVM only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_id: Option<u8>,
}

/// Result of an EVM transaction signing operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionSignResult {
    /// Hex-encoded signature.
    pub signature: String,
    /// Hex-encoded signed transaction (RLP-encoded).
    pub signed_tx: String,
    /// Transaction hash.
    pub tx_hash: String,
}

/// Result of a sign-and-send operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendResult {
    /// On-chain transaction hash.
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
