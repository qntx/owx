//! On-disk encrypted wallet file format.

use serde::{Deserialize, Serialize};

/// The full on-disk wallet file (JSON).
///
/// Written to `<vault>/wallets/<id>.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedWallet {
    /// Format version (`2` for current).
    pub version: u32,
    /// Unique wallet identifier (UUID v4).
    pub id: String,
    /// Human-readable wallet name.
    pub name: String,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
    /// Derived accounts across chains.
    pub accounts: Vec<WalletAccount>,
    /// Encrypted key material (a `CryptoEnvelope` as JSON value).
    pub crypto: serde_json::Value,
    /// Type of key material stored in the ciphertext.
    pub key_type: KeyType,
    /// Optional metadata.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub metadata: serde_json::Value,
}

/// An account entry within an encrypted wallet file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAccount {
    /// CAIP-10 account identifier (e.g. `eip155:1:0xabc...`).
    pub account_id: String,
    /// Address in the chain's native format.
    pub address: String,
    /// CAIP-2 chain identifier (e.g. `eip155:1`).
    pub chain_id: String,
    /// BIP-44 derivation path used.
    pub derivation_path: String,
}

/// Type of key material stored in the ciphertext.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    /// BIP-39 mnemonic phrase.
    Mnemonic,
    /// Multi-curve key pair: `{"secp256k1":"hex","ed25519":"hex"}`.
    PrivateKey,
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
            version: 2,
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn dummy_wallet() -> EncryptedWallet {
        EncryptedWallet::new(
            "test-id".to_owned(),
            "test-wallet".to_owned(),
            vec![WalletAccount {
                account_id: "eip155:1:0xabc".to_owned(),
                address: "0xabc".to_owned(),
                chain_id: "eip155:1".to_owned(),
                derivation_path: "m/44'/60'/0'/0/0".to_owned(),
            }],
            serde_json::json!({"cipher": "aes-256-gcm"}),
            KeyType::Mnemonic,
        )
    }

    #[test]
    fn serde_roundtrip() {
        let wallet = dummy_wallet();
        let json = serde_json::to_string_pretty(&wallet).unwrap();
        let restored: EncryptedWallet = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.id, "test-id");
        assert_eq!(restored.version, 2);
    }

    #[test]
    fn key_type_serde() {
        assert_eq!(
            serde_json::to_string(&KeyType::Mnemonic).unwrap(),
            "\"mnemonic\""
        );
        assert_eq!(
            serde_json::to_string(&KeyType::PrivateKey).unwrap(),
            "\"private_key\""
        );
    }

    #[test]
    fn metadata_omitted_when_null() {
        let wallet = dummy_wallet();
        let json = serde_json::to_value(&wallet).unwrap();
        assert!(json.get("metadata").is_none());
    }

    #[test]
    fn matches_required_fields() {
        let wallet = dummy_wallet();
        let json = serde_json::to_value(&wallet).unwrap();
        for key in [
            "version",
            "id",
            "name",
            "created_at",
            "accounts",
            "crypto",
            "key_type",
        ] {
            assert!(json.get(key).is_some(), "missing key: {key}");
        }
    }
}
