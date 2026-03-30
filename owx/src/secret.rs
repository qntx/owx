//! Internal wallet secret types for encryption/decryption.

use owx_core::chain::ChainType;
use owx_core::wallet_file::{EncryptedWallet, KeyType};
use owx_vault::{CryptoEnvelope, crypto};

use crate::error::OwxError;

/// Decrypted wallet secret — either a mnemonic or per-curve private keys.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WalletSecret {
    /// BIP-39 mnemonic phrase.
    Mnemonic {
        /// The mnemonic words.
        phrase: String,
    },
    /// Per-curve hex-encoded private keys.
    PrivateKeys {
        /// Secp256k1 key (EVM/Bitcoin).
        #[serde(skip_serializing_if = "Option::is_none")]
        secp256k1: Option<String>,
        /// Ed25519 key (Solana).
        #[serde(skip_serializing_if = "Option::is_none")]
        ed25519: Option<String>,
    },
}

/// Legacy format: `{"secp256k1":"hex","ed25519":"hex"}` without type tag.
#[derive(Debug, Clone, serde::Deserialize)]
struct LegacyPrivateKeys {
    /// Secp256k1 key hex.
    #[serde(default)]
    secp256k1: Option<String>,
    /// Ed25519 key hex.
    #[serde(default)]
    ed25519: Option<String>,
}

impl WalletSecret {
    /// Create a mnemonic secret.
    pub fn mnemonic(phrase: impl Into<String>) -> Self {
        Self::Mnemonic {
            phrase: phrase.into(),
        }
    }

    /// Create a private-key secret for the given chain's curve.
    pub fn private_key(chain_type: ChainType, key_hex: impl Into<String>) -> Self {
        let secret_hex = key_hex.into();
        match chain_type {
            ChainType::Evm | ChainType::Bitcoin => Self::PrivateKeys {
                secp256k1: Some(secret_hex),
                ed25519: None,
            },
            ChainType::Solana => Self::PrivateKeys {
                secp256k1: None,
                ed25519: Some(secret_hex),
            },
        }
    }

    /// Returns the [`KeyType`] for on-disk storage.
    pub const fn key_type(&self) -> KeyType {
        match self {
            Self::Mnemonic { .. } => KeyType::Mnemonic,
            Self::PrivateKeys { .. } => KeyType::PrivateKey,
        }
    }

    /// Whether this secret can sign for the given chain.
    pub const fn supports_chain(&self, chain_type: ChainType) -> bool {
        match self {
            Self::Mnemonic { .. } => true,
            Self::PrivateKeys { secp256k1, ed25519 } => match chain_type {
                ChainType::Evm | ChainType::Bitcoin => secp256k1.is_some(),
                ChainType::Solana => ed25519.is_some(),
            },
        }
    }

    /// Returns the mnemonic phrase, if this is a mnemonic secret.
    pub fn phrase(&self) -> Option<&str> {
        match self {
            Self::Mnemonic { phrase } => Some(phrase),
            Self::PrivateKeys { .. } => None,
        }
    }

    /// Returns the hex-encoded private key for the given chain's curve.
    pub fn private_key_hex(&self, chain_type: ChainType) -> Option<&str> {
        match self {
            Self::Mnemonic { .. } => None,
            Self::PrivateKeys { secp256k1, ed25519 } => match chain_type {
                ChainType::Evm | ChainType::Bitcoin => secp256k1.as_deref(),
                ChainType::Solana => ed25519.as_deref(),
            },
        }
    }

    /// Export as a human-readable string (phrase or JSON key pair).
    pub fn export_string(&self) -> Result<String, OwxError> {
        if let Some(phrase) = self.phrase() {
            Ok(phrase.to_owned())
        } else {
            serde_json::to_string_pretty(self).map_err(OwxError::from)
        }
    }

    /// Serialize to bytes for encryption.
    pub fn into_bytes(self) -> Result<Vec<u8>, OwxError> {
        serde_json::to_vec(&self).map_err(OwxError::from)
    }
}

/// Decrypt a wallet's secret using the given credential (passphrase or token).
pub fn decrypt_wallet_secret(
    wallet: &EncryptedWallet,
    credential: &str,
) -> Result<WalletSecret, OwxError> {
    let envelope: CryptoEnvelope = serde_json::from_value(wallet.crypto.clone())?;
    decrypt_wallet_secret_from_envelope(&envelope, credential, wallet.key_type)
}

/// Decrypt a wallet secret from a pre-parsed [`CryptoEnvelope`].
pub fn decrypt_wallet_secret_from_envelope(
    envelope: &CryptoEnvelope,
    credential: &str,
    key_type: KeyType,
) -> Result<WalletSecret, OwxError> {
    let plaintext = crypto::decrypt(envelope, credential)?;
    parse_wallet_secret(plaintext.expose(), key_type)
}

/// Parse decrypted bytes into a [`WalletSecret`], handling legacy formats.
fn parse_wallet_secret(bytes: &[u8], key_type: KeyType) -> Result<WalletSecret, OwxError> {
    if let Ok(secret) = serde_json::from_slice::<WalletSecret>(bytes) {
        return Ok(secret);
    }

    match key_type {
        KeyType::Mnemonic => {
            let phrase = String::from_utf8(bytes.to_vec()).map_err(|_| {
                OwxError::InvalidInput("wallet contains invalid UTF-8 mnemonic".into())
            })?;
            Ok(WalletSecret::mnemonic(phrase))
        }
        KeyType::PrivateKey => {
            let legacy = serde_json::from_slice::<LegacyPrivateKeys>(bytes).map_err(|_| {
                OwxError::InvalidInput("wallet contains invalid private key payload".into())
            })?;
            Ok(WalletSecret::PrivateKeys {
                secp256k1: legacy.secp256k1,
                ed25519: legacy.ed25519,
            })
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn serialize_roundtrip_mnemonic() {
        let secret = WalletSecret::mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        );
        let bytes = secret.into_bytes().unwrap();
        let restored: WalletSecret = serde_json::from_slice(&bytes).unwrap();
        assert!(matches!(restored, WalletSecret::Mnemonic { .. }));
    }

    #[test]
    fn supports_expected_chain() {
        let secret = WalletSecret::private_key(ChainType::Evm, "11".repeat(32));
        assert!(secret.supports_chain(ChainType::Evm));
        assert!(secret.supports_chain(ChainType::Bitcoin));
        assert!(!secret.supports_chain(ChainType::Solana));
    }

    #[test]
    fn export_private_keys_as_json() {
        let secret = WalletSecret::private_key(ChainType::Solana, "22".repeat(32));
        let exported = secret.export_string().unwrap();
        assert!(exported.contains("ed25519"));
    }
}
