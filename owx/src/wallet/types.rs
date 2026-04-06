//! Wallet data types — on-disk and public-facing representations.

use serde::{Deserialize, Serialize};

/// Options for importing a wallet from a single private key.
#[allow(clippy::exhaustive_structs)]
#[derive(Debug, Default)]
pub struct ImportKeyOptions<'a> {
    /// Target chain (determines which curve the primary key belongs to).
    pub chain: Option<&'a str>,
    /// Explicit secp256k1 key hex override.
    pub secp256k1_hex: Option<&'a str>,
    /// Explicit ed25519 key hex override.
    pub ed25519_hex: Option<&'a str>,
}

/// Type of key material stored in the ciphertext.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    /// BIP-39 mnemonic phrase.
    Mnemonic,
    /// Multi-curve key pair (`{"secp256k1":"hex","ed25519":"hex"}`).
    PrivateKey,
}

/// An account entry within an encrypted wallet file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAccount {
    /// CAIP-10 account identifier (e.g. `eip155:1:0xabc…`).
    pub account_id: String,
    /// Address in the chain's native format.
    pub address: String,
    /// CAIP-2 chain identifier (e.g. `eip155:1`).
    pub chain_id: String,
    /// BIP-44 derivation path (`None` for imported keys).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derivation_path: Option<String>,
}

/// The full on-disk wallet file (extended keystore v2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedWallet {
    /// Format version (always 2 for new wallets).
    #[serde(alias = "lws_version")]
    pub ows_version: u32,
    /// Unique wallet identifier (UUID v4).
    pub id: String,
    /// Human-readable wallet name.
    pub name: String,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
    /// Derived accounts across chains.
    pub accounts: Vec<WalletAccount>,
    /// Encrypted key material ([`owx_vault::CryptoEnvelope`] as JSON).
    pub crypto: serde_json::Value,
    /// Type of key material stored in the ciphertext.
    pub key_type: KeyType,
    /// Optional metadata.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub metadata: serde_json::Value,
}

impl EncryptedWallet {
    /// Create a new wallet with the current timestamp and version 2.
    #[must_use]
    pub fn new(
        id: String,
        name: String,
        accounts: Vec<WalletAccount>,
        crypto: serde_json::Value,
        key_type: KeyType,
    ) -> Self {
        Self {
            ows_version: 2,
            id,
            name,
            created_at: chrono::Utc::now().to_rfc3339(),
            accounts,
            crypto,
            key_type,
            metadata: serde_json::Value::Null,
        }
    }
}

/// Public wallet information (no secret material exposed).
#[non_exhaustive]
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

/// A single account within a wallet (one per chain family).
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    /// CAIP-2 chain identifier.
    pub chain_id: String,
    /// Address in the chain's native format.
    pub address: String,
    /// BIP-44 derivation path (`None` for imported keys).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derivation_path: Option<String>,
}

/// Convert an [`EncryptedWallet`] to the public-facing [`WalletInfo`].
pub fn to_info(w: &EncryptedWallet) -> WalletInfo {
    WalletInfo {
        id: w.id.clone(),
        name: w.name.clone(),
        accounts: w
            .accounts
            .iter()
            .map(|a| AccountInfo {
                chain_id: a.chain_id.clone(),
                address: a.address.clone(),
                derivation_path: a.derivation_path.clone(),
            })
            .collect(),
        created_at: w.created_at.clone(),
    }
}
