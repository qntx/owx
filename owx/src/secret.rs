//! Wallet secret: decrypted key material with zeroize-on-drop.
//!
//! Encryption format (OWS-compatible):
//! - **Mnemonic**: raw UTF-8 phrase bytes
//! - **Private key pair**: `{"secp256k1":"hex","ed25519":"hex"}` JSON (no type tag)

use owx_vault::{CryptoEnvelope, crypto};
use zeroize::Zeroizing;

use crate::chain::ChainFamily;
use crate::error::OwxError as Error;
use crate::wallet::{EncryptedWallet, KeyType};

/// Decrypted wallet secret — either a mnemonic phrase or dual-curve key pair.
///
/// All secret material is zeroized on [`Drop`].
pub(crate) enum WalletSecret {
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
    pub(crate) fn mnemonic(phrase: impl Into<String>) -> Self {
        Self::Mnemonic(Zeroizing::new(phrase.into()))
    }

    /// Create from explicit dual-curve keys.
    pub(crate) fn key_pair(secp256k1: impl Into<String>, ed25519: impl Into<String>) -> Self {
        Self::KeyPair {
            secp256k1: Zeroizing::new(secp256k1.into()),
            ed25519: Zeroizing::new(ed25519.into()),
        }
    }

    /// Returns the [`KeyType`] for on-disk storage.
    pub(crate) const fn key_type(&self) -> KeyType {
        match self {
            Self::Mnemonic(_) => KeyType::Mnemonic,
            Self::KeyPair { .. } => KeyType::PrivateKey,
        }
    }

    /// Returns the mnemonic phrase (if this is a mnemonic secret).
    pub(crate) fn phrase(&self) -> Option<&str> {
        match self {
            Self::Mnemonic(p) => Some(p.as_str()),
            Self::KeyPair { .. } => None,
        }
    }

    /// Returns the hex private key for the given chain's curve.
    pub(crate) fn private_key_hex(&self, ct: ChainFamily) -> Option<&str> {
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
    pub(crate) fn export_string(&self) -> Result<Zeroizing<String>, Error> {
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
    pub(crate) fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
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
pub(crate) fn decrypt_secret(
    wallet: &EncryptedWallet,
    credential: &str,
) -> Result<WalletSecret, Error> {
    decrypt_from_envelope(&wallet.crypto, credential, wallet.key_type)
}

/// Decrypt from a pre-parsed envelope with known key type.
pub(crate) fn decrypt_from_envelope(
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
            let phrase = match String::from_utf8(bytes.to_vec()) {
                Ok(s) => Zeroizing::new(s),
                Err(e) => {
                    let mut bad = e.into_bytes();
                    zeroize::Zeroize::zeroize(&mut bad[..]);
                    return Err(Error::InvalidInput("invalid UTF-8 mnemonic".into()));
                }
            };
            Ok(WalletSecret::Mnemonic(phrase))
        }
        KeyType::PrivateKey => {
            #[derive(serde::Deserialize)]
            struct KeyPairJson {
                secp256k1: String,
                ed25519: String,
            }
            let kp: KeyPairJson = serde_json::from_slice(bytes)
                .map_err(|_| Error::InvalidInput("invalid key pair payload".into()))?;
            Ok(WalletSecret::key_pair(kp.secp256k1, kp.ed25519))
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    reason = "test panics on out-of-bounds are acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn mnemonic_key_type() {
        let s = WalletSecret::mnemonic("abandon abandon about");
        assert_eq!(s.key_type(), KeyType::Mnemonic);
    }

    #[test]
    fn keypair_key_type() {
        let s = WalletSecret::key_pair("aa".repeat(32), "bb".repeat(32));
        assert_eq!(s.key_type(), KeyType::PrivateKey);
    }

    #[test]
    fn mnemonic_phrase_returns_some() {
        let s = WalletSecret::mnemonic("test phrase");
        assert_eq!(s.phrase(), Some("test phrase"));
    }

    #[test]
    fn keypair_phrase_returns_none() {
        let s = WalletSecret::key_pair("aa", "bb");
        assert!(s.phrase().is_none());
    }

    #[test]
    fn mnemonic_private_key_hex_returns_none() {
        let s = WalletSecret::mnemonic("test");
        assert!(s.private_key_hex(ChainFamily::Evm).is_none());
    }

    #[test]
    fn keypair_returns_secp_for_evm() {
        let s = WalletSecret::key_pair("secp_hex", "ed_hex");
        assert_eq!(s.private_key_hex(ChainFamily::Evm), Some("secp_hex"));
    }

    #[test]
    fn keypair_returns_ed_for_solana() {
        let s = WalletSecret::key_pair("secp_hex", "ed_hex");
        assert_eq!(s.private_key_hex(ChainFamily::Solana), Some("ed_hex"));
    }

    #[test]
    fn export_string_mnemonic() {
        let s = WalletSecret::mnemonic("zoo zoo zoo");
        let out = s.export_string().unwrap();
        assert_eq!(&*out, "zoo zoo zoo");
    }

    #[test]
    fn export_string_keypair_is_json() {
        let s = WalletSecret::key_pair("aabb", "ccdd");
        let out = s.export_string().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["secp256k1"], "aabb");
        assert_eq!(parsed["ed25519"], "ccdd");
    }

    #[test]
    fn to_bytes_mnemonic_roundtrip() {
        let s = WalletSecret::mnemonic("hello world");
        let bytes = s.to_bytes().unwrap();
        assert_eq!(&*bytes, b"hello world");
    }

    #[test]
    fn to_bytes_keypair_roundtrip() {
        let s = WalletSecret::key_pair("aa", "bb");
        let bytes = s.to_bytes().unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["secp256k1"], "aa");
    }

    #[test]
    fn debug_redacts_secrets() {
        let m = WalletSecret::mnemonic("secret phrase");
        let kp = WalletSecret::key_pair("key1", "key2");
        assert!(format!("{m:?}").contains("REDACTED"));
        assert!(format!("{kp:?}").contains("REDACTED"));
        assert!(!format!("{m:?}").contains("secret phrase"));
    }

    #[test]
    fn parse_secret_mnemonic_valid_utf8() {
        let bytes = b"abandon abandon about";
        let s = parse_secret(bytes, KeyType::Mnemonic).unwrap();
        assert_eq!(s.phrase(), Some("abandon abandon about"));
    }

    #[test]
    fn parse_secret_mnemonic_invalid_utf8() {
        let bytes = &[0xFF, 0xFE];
        assert!(parse_secret(bytes, KeyType::Mnemonic).is_err());
    }

    #[test]
    fn parse_secret_keypair_valid_json() {
        let json = br#"{"secp256k1":"aa","ed25519":"bb"}"#;
        let s = parse_secret(json, KeyType::PrivateKey).unwrap();
        assert_eq!(s.private_key_hex(ChainFamily::Evm), Some("aa"));
        assert_eq!(s.private_key_hex(ChainFamily::Solana), Some("bb"));
    }

    #[test]
    fn parse_secret_keypair_invalid_json() {
        assert!(parse_secret(b"not json", KeyType::PrivateKey).is_err());
    }
}
