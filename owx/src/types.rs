//! Public-facing DTO types for the OWX API surface.

use serde::{Deserialize, Serialize};

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

/// Result of a signing operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResult {
    /// Hex-encoded signature.
    pub signature: String,
    /// ECDSA recovery ID (secp256k1 only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_id: Option<u8>,
}

/// Result of a sign-and-send operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendResult {
    /// On-chain transaction hash.
    pub tx_hash: String,
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
