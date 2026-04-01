//! Internal wallet secret types for encryption/decryption.

use owx_core::chain::ChainType;
use owx_core::wallet_file::{EncryptedWallet, KeyType};
use owx_vault::{CryptoEnvelope, crypto};

use crate::error::OwxError;

/// Whether a chain type uses the Ed25519 curve.
const fn is_ed25519_chain(ct: ChainType) -> bool {
    matches!(ct, ChainType::Solana | ChainType::Ton | ChainType::Sui)
}

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
        /// Secp256k1 key (EVM/Bitcoin/Cosmos/Tron/Spark/Filecoin).
        #[serde(skip_serializing_if = "Option::is_none")]
        secp256k1: Option<String>,
        /// Ed25519 key (Solana/TON/Sui).
        #[serde(skip_serializing_if = "Option::is_none")]
        ed25519: Option<String>,
    },
}

/// Legacy format without type tag.
#[derive(serde::Deserialize)]
struct LegacyKeys {
    /// Secp256k1 hex key.
    #[serde(default)]
    secp256k1: Option<String>,
    /// Ed25519 hex key.
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
    #[allow(dead_code)]
    pub fn private_key(chain_type: ChainType, key_hex: impl Into<String>) -> Self {
        let h = key_hex.into();
        if is_ed25519_chain(chain_type) {
            Self::PrivateKeys {
                secp256k1: None,
                ed25519: Some(h),
            }
        } else {
            Self::PrivateKeys {
                secp256k1: Some(h),
                ed25519: None,
            }
        }
    }

    /// Create from explicit dual keys.
    #[must_use]
    pub const fn dual_keys(secp256k1: String, ed25519: String) -> Self {
        Self::PrivateKeys {
            secp256k1: Some(secp256k1),
            ed25519: Some(ed25519),
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
    #[allow(dead_code)]
    pub const fn supports_chain(&self, ct: ChainType) -> bool {
        match self {
            Self::Mnemonic { .. } => true,
            Self::PrivateKeys { secp256k1, ed25519 } => {
                if is_ed25519_chain(ct) {
                    ed25519.is_some()
                } else {
                    secp256k1.is_some()
                }
            }
        }
    }

    /// Returns the mnemonic phrase if this is a mnemonic secret.
    pub fn phrase(&self) -> Option<&str> {
        match self {
            Self::Mnemonic { phrase } => Some(phrase),
            Self::PrivateKeys { .. } => None,
        }
    }

    /// Returns the hex private key for the given chain's curve.
    pub fn private_key_hex(&self, ct: ChainType) -> Option<&str> {
        match self {
            Self::Mnemonic { .. } => None,
            Self::PrivateKeys { secp256k1, ed25519 } => {
                if is_ed25519_chain(ct) {
                    ed25519.as_deref()
                } else {
                    secp256k1.as_deref()
                }
            }
        }
    }

    /// Export as a human-readable string.
    pub fn export_string(&self) -> Result<String, OwxError> {
        match self.phrase() {
            Some(p) => Ok(p.to_owned()),
            None => serde_json::to_string_pretty(self).map_err(OwxError::from),
        }
    }

    /// Serialize to bytes for encryption.
    pub fn to_bytes(&self) -> Result<Vec<u8>, OwxError> {
        serde_json::to_vec(self).map_err(OwxError::from)
    }
}

/// Decrypt a wallet's secret using the given credential.
pub fn decrypt_secret(
    wallet: &EncryptedWallet,
    credential: &str,
) -> Result<WalletSecret, OwxError> {
    let envelope: CryptoEnvelope = serde_json::from_value(wallet.crypto.clone())?;
    decrypt_from_envelope(&envelope, credential, wallet.key_type)
}

/// Decrypt from a pre-parsed envelope.
pub fn decrypt_from_envelope(
    envelope: &CryptoEnvelope,
    credential: &str,
    key_type: KeyType,
) -> Result<WalletSecret, OwxError> {
    let plaintext = crypto::decrypt(envelope, credential)?;
    parse_secret(plaintext.expose(), key_type)
}

/// Parse decrypted bytes into a [`WalletSecret`], handling legacy formats.
fn parse_secret(bytes: &[u8], key_type: KeyType) -> Result<WalletSecret, OwxError> {
    if let Ok(s) = serde_json::from_slice::<WalletSecret>(bytes) {
        return Ok(s);
    }
    match key_type {
        KeyType::Mnemonic => {
            let phrase = String::from_utf8(bytes.to_vec())
                .map_err(|_| OwxError::InvalidInput("invalid UTF-8 mnemonic".into()))?;
            Ok(WalletSecret::mnemonic(phrase))
        }
        KeyType::PrivateKey => {
            let legacy = serde_json::from_slice::<LegacyKeys>(bytes)
                .map_err(|_| OwxError::InvalidInput("invalid private key payload".into()))?;
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
    fn roundtrip_mnemonic() {
        let s = WalletSecret::mnemonic("abandon abandon about");
        let b = s.to_bytes().unwrap();
        let r: WalletSecret = serde_json::from_slice(&b).unwrap();
        assert!(matches!(r, WalletSecret::Mnemonic { .. }));
    }

    #[test]
    fn supports_chain_logic() {
        let s = WalletSecret::private_key(ChainType::Evm, "aa".repeat(32));
        assert!(s.supports_chain(ChainType::Evm));
        assert!(s.supports_chain(ChainType::Bitcoin));
        assert!(s.supports_chain(ChainType::Cosmos));
        assert!(!s.supports_chain(ChainType::Solana));
        assert!(!s.supports_chain(ChainType::Ton));
    }
}
