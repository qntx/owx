//! Wallet secret: decrypted key material with zeroize-on-drop.
//!
//! Encryption format (OWS-compatible):
//! - **Mnemonic**: raw UTF-8 phrase bytes
//! - **Private key pair**: `{"secp256k1":"hex","ed25519":"hex"}` JSON (no type tag)

use owx_vault::{CryptoEnvelope, crypto};
use zeroize::Zeroizing;

use crate::chain::ChainFamily;
use crate::error::Error;
use crate::wallet::{EncryptedWallet, KeyType};

/// Decrypted wallet secret — either a mnemonic phrase or dual-curve key pair.
///
/// All secret material is zeroized on [`Drop`].
pub enum WalletSecret {
    /// BIP-39 mnemonic phrase.
    Mnemonic(Zeroizing<String>),
    /// Per-curve hex-encoded private keys.
    KeyPair {
        /// Secp256k1 key hex (EVM/Bitcoin/Cosmos/Tron/Spark/Filecoin).
        secp256k1: Zeroizing<String>,
        /// Ed25519 key hex (Solana/TON/Sui).
        ed25519: Zeroizing<String>,
    },
}

impl WalletSecret {
    /// Create a mnemonic secret.
    pub fn mnemonic(phrase: impl Into<String>) -> Self {
        Self::Mnemonic(Zeroizing::new(phrase.into()))
    }

    /// Create from explicit dual-curve keys.
    pub fn key_pair(secp256k1: impl Into<String>, ed25519: impl Into<String>) -> Self {
        Self::KeyPair {
            secp256k1: Zeroizing::new(secp256k1.into()),
            ed25519: Zeroizing::new(ed25519.into()),
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
            Self::Mnemonic(p) => Some(p.as_str()),
            Self::KeyPair { .. } => None,
        }
    }

    /// Returns the hex private key for the given chain's curve.
    pub fn private_key_hex(&self, ct: ChainFamily) -> Option<&str> {
        match self {
            Self::Mnemonic(_) => None,
            Self::KeyPair { secp256k1, ed25519 } => {
                if ct.is_ed25519() {
                    Some(ed25519.as_str())
                } else {
                    Some(secp256k1.as_str())
                }
            }
        }
    }

    /// Export as a human-readable string (phrase or JSON key pair).
    ///
    /// Returns [`Zeroizing<String>`] so the secret is scrubbed on drop.
    pub fn export_string(&self) -> Result<Zeroizing<String>, Error> {
        match self {
            Self::Mnemonic(p) => Ok(Zeroizing::new(p.to_string())),
            Self::KeyPair { secp256k1, ed25519 } => {
                let obj = serde_json::json!({"secp256k1": secp256k1.as_str(), "ed25519": ed25519.as_str()});
                serde_json::to_string_pretty(&obj)
                    .map(Zeroizing::new)
                    .map_err(Error::from)
            }
        }
    }

    /// Serialize to bytes for encryption (OWS-compatible format).
    ///
    /// Returns [`Zeroizing<Vec<u8>>`] so the plaintext is automatically
    /// scrubbed on drop, even if the caller forgets explicit cleanup.
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        match self {
            Self::Mnemonic(p) => Ok(Zeroizing::new(p.as_bytes().to_vec())),
            Self::KeyPair { secp256k1, ed25519 } => {
                let obj = serde_json::json!({"secp256k1": secp256k1.as_str(), "ed25519": ed25519.as_str()});
                serde_json::to_vec(&obj)
                    .map(Zeroizing::new)
                    .map_err(Error::from)
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
pub fn decrypt_secret(wallet: &EncryptedWallet, credential: &str) -> Result<WalletSecret, Error> {
    let envelope: CryptoEnvelope = serde_json::from_value(wallet.crypto.clone())?;
    decrypt_from_envelope(&envelope, credential, wallet.key_type)
}

/// Decrypt from a pre-parsed envelope with known key type.
pub fn decrypt_from_envelope(
    envelope: &CryptoEnvelope,
    credential: &str,
    key_type: KeyType,
) -> Result<WalletSecret, Error> {
    let plaintext = crypto::decrypt(envelope, credential)?;
    parse_secret(plaintext.expose(), key_type)
}

/// Parse decrypted bytes into a [`WalletSecret`] based on the wallet's key type.
fn parse_secret(bytes: &[u8], key_type: KeyType) -> Result<WalletSecret, Error> {
    match key_type {
        KeyType::Mnemonic => {
            let phrase = String::from_utf8(bytes.to_vec())
                .map_err(|_| Error::InvalidInput("invalid UTF-8 mnemonic".into()))?;
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
                .map_err(|_| Error::InvalidInput("invalid key pair payload".into()))?;
            Ok(WalletSecret::key_pair(kp.secp256k1, kp.ed25519))
        }
    }
}
