//! Wallet secret: decrypted key material with zeroize-on-drop.
//!
//! Encryption format (OWS-compatible):
//! - **Mnemonic**: raw UTF-8 phrase bytes
//! - **Private key pair**: `{"secp256k1":"hex","ed25519":"hex"}` JSON (no type tag)

use owx_core::chain::ChainType;
use owx_core::wallet_file::{EncryptedWallet, KeyType};
use owx_vault::{CryptoEnvelope, crypto};
use zeroize::Zeroize;

use crate::error::OwxError;

/// Whether a chain type uses the Ed25519 curve.
const fn is_ed25519(ct: ChainType) -> bool {
    matches!(ct, ChainType::Solana | ChainType::Ton | ChainType::Sui)
}

/// Decrypted wallet secret — either a mnemonic phrase or dual-curve key pair.
///
/// All secret material is zeroized on [`Drop`].
pub enum WalletSecret {
    /// BIP-39 mnemonic phrase.
    Mnemonic(String),
    /// Per-curve hex-encoded private keys.
    KeyPair {
        /// Secp256k1 key hex (EVM/Bitcoin/Cosmos/Tron/Spark/Filecoin).
        secp256k1: String,
        /// Ed25519 key hex (Solana/TON/Sui).
        ed25519: String,
    },
}

impl WalletSecret {
    /// Create a mnemonic secret.
    pub fn mnemonic(phrase: impl Into<String>) -> Self {
        Self::Mnemonic(phrase.into())
    }

    /// Create from explicit dual-curve keys.
    pub fn key_pair(secp256k1: impl Into<String>, ed25519: impl Into<String>) -> Self {
        Self::KeyPair {
            secp256k1: secp256k1.into(),
            ed25519: ed25519.into(),
        }
    }

    /// Returns the [`KeyType`] for on-disk storage.
    pub const fn key_type(&self) -> KeyType {
        match self {
            Self::Mnemonic(_) => KeyType::Mnemonic,
            Self::KeyPair { .. } => KeyType::PrivateKey,
        }
    }

    /// Returns the mnemonic phrase (if this is a mnemonic secret).
    pub fn phrase(&self) -> Option<&str> {
        match self {
            Self::Mnemonic(p) => Some(p),
            Self::KeyPair { .. } => None,
        }
    }

    /// Returns the hex private key for the given chain's curve.
    pub fn private_key_hex(&self, ct: ChainType) -> Option<&str> {
        match self {
            Self::Mnemonic(_) => None,
            Self::KeyPair { secp256k1, ed25519 } => {
                if is_ed25519(ct) {
                    Some(ed25519)
                } else {
                    Some(secp256k1)
                }
            }
        }
    }

    /// Export as a human-readable string (phrase or JSON key pair).
    pub fn export_string(&self) -> Result<String, OwxError> {
        match self {
            Self::Mnemonic(p) => Ok(p.clone()),
            Self::KeyPair { secp256k1, ed25519 } => {
                let obj = serde_json::json!({"secp256k1": secp256k1, "ed25519": ed25519});
                serde_json::to_string_pretty(&obj).map_err(OwxError::from)
            }
        }
    }

    /// Serialize to bytes for encryption (OWS-compatible format).
    pub fn to_bytes(&self) -> Result<Vec<u8>, OwxError> {
        match self {
            Self::Mnemonic(p) => Ok(p.as_bytes().to_vec()),
            Self::KeyPair { secp256k1, ed25519 } => {
                let obj = serde_json::json!({"secp256k1": secp256k1, "ed25519": ed25519});
                serde_json::to_vec(&obj).map_err(OwxError::from)
            }
        }
    }
}

impl Drop for WalletSecret {
    fn drop(&mut self) {
        match self {
            Self::Mnemonic(p) => p.zeroize(),
            Self::KeyPair { secp256k1, ed25519 } => {
                secp256k1.zeroize();
                ed25519.zeroize();
            }
        }
    }
}

impl std::fmt::Debug for WalletSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mnemonic(_) => f.write_str("WalletSecret::Mnemonic([REDACTED])"),
            Self::KeyPair { .. } => f.write_str("WalletSecret::KeyPair([REDACTED])"),
        }
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

/// Decrypt from a pre-parsed envelope with known key type.
pub fn decrypt_from_envelope(
    envelope: &CryptoEnvelope,
    credential: &str,
    key_type: KeyType,
) -> Result<WalletSecret, OwxError> {
    let plaintext = crypto::decrypt(envelope, credential)?;
    parse_secret(plaintext.expose(), key_type)
}

/// Parse decrypted bytes into a [`WalletSecret`] based on the wallet's key type.
fn parse_secret(bytes: &[u8], key_type: KeyType) -> Result<WalletSecret, OwxError> {
    match key_type {
        KeyType::Mnemonic => {
            let phrase = String::from_utf8(bytes.to_vec())
                .map_err(|_| OwxError::InvalidInput("invalid UTF-8 mnemonic".into()))?;
            Ok(WalletSecret::mnemonic(phrase))
        }
        KeyType::PrivateKey => {
            /// Untagged key pair JSON layout.
            #[derive(serde::Deserialize)]
            struct KeyPairJson {
                /// Secp256k1 hex key.
                secp256k1: String,
                /// Ed25519 hex key.
                ed25519: String,
            }
            let kp: KeyPairJson = serde_json::from_slice(bytes)
                .map_err(|_| OwxError::InvalidInput("invalid key pair payload".into()))?;
            Ok(WalletSecret::key_pair(kp.secp256k1, kp.ed25519))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn mnemonic_roundtrip() {
        let s = WalletSecret::mnemonic("abandon abandon about");
        let b = s.to_bytes().unwrap();
        assert_eq!(b, b"abandon abandon about");
        let r = parse_secret(&b, KeyType::Mnemonic).unwrap();
        assert_eq!(r.phrase(), Some("abandon abandon about"));
    }

    #[test]
    fn key_pair_roundtrip() {
        let secp = "aa".repeat(32);
        let ed = "bb".repeat(32);
        let s = WalletSecret::key_pair(&secp, &ed);
        let b = s.to_bytes().unwrap();
        let r = parse_secret(&b, KeyType::PrivateKey).unwrap();
        assert_eq!(r.private_key_hex(ChainType::Evm), Some(secp.as_str()));
        assert_eq!(r.private_key_hex(ChainType::Solana), Some(ed.as_str()));
    }

    #[test]
    fn key_pair_covers_all_chains() {
        let s = WalletSecret::key_pair("aa".repeat(32), "bb".repeat(32));
        for ct in &owx_core::chain::ALL_CHAIN_TYPES {
            assert!(s.private_key_hex(*ct).is_some(), "missing key for {ct}");
        }
    }

    #[test]
    fn debug_does_not_leak() {
        let s = WalletSecret::mnemonic("super secret words");
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("super"));
        assert!(dbg.contains("REDACTED"));
    }
}
