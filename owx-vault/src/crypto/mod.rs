//! Encryption envelope: scrypt + AES-256-GCM, HKDF-SHA256 + AES-256-GCM.
//!
//! Submodules:
//! - [`envelope`] — on-disk JSON-serializable types
//! - [`scrypt`] — passphrase-based encryption (wallet owner)
//! - [`hkdf`] — token-based encryption (API key agent)
//! - [`aes`] — AES-256-GCM primitives

mod aes;
pub mod envelope;
pub mod hkdf;
mod rand;
pub mod scrypt;

pub use envelope::{
    CipherParams, CryptoEnvelope, HkdfKdfParams, KdfParamsVariant, ScryptKdfParams,
};

use crate::error::VaultError;
use crate::secret::SecretBytes;

// Prevent fast-kdf from being used in release builds.
#[cfg(all(feature = "fast-kdf", not(debug_assertions)))]
compile_error!(
    "The `fast-kdf` feature reduces scrypt to 2^10 iterations and must not be used in release builds."
);

/// Encrypt plaintext with a passphrase (scrypt KDF + AES-256-GCM).
pub fn encrypt(plaintext: &[u8], passphrase: &str) -> Result<CryptoEnvelope, VaultError> {
    scrypt::encrypt(plaintext, passphrase)
}

/// Encrypt plaintext with an API token (HKDF-SHA256 + AES-256-GCM).
pub fn encrypt_hkdf(plaintext: &[u8], token: &str) -> Result<CryptoEnvelope, VaultError> {
    hkdf::encrypt(plaintext, token)
}

/// Decrypt a [`CryptoEnvelope`]. Dispatches on the `kdf` field.
pub fn decrypt(envelope: &CryptoEnvelope, credential: &str) -> Result<SecretBytes, VaultError> {
    match envelope.kdf.as_str() {
        "scrypt" => scrypt::decrypt(envelope, credential),
        "hkdf-sha256" => hkdf::decrypt(envelope, credential),
        other => Err(VaultError::InvalidParams(format!(
            "unsupported KDF: {other}"
        ))),
    }
}

/// Decode a hex string into bytes.
fn hex_decode(s: &str) -> Result<Vec<u8>, VaultError> {
    hex::decode(s).map_err(|e| VaultError::InvalidParams(e.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn scrypt_roundtrip() {
        let plaintext = b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let envelope = encrypt(plaintext, "strong-pass").unwrap();
        assert_eq!(envelope.kdf, "scrypt");
        assert_eq!(envelope.cipher, "aes-256-gcm");
        let decrypted = decrypt(&envelope, "strong-pass").unwrap();
        assert_eq!(decrypted.expose(), plaintext);
    }

    #[test]
    fn hkdf_roundtrip() {
        let plaintext = b"{\"secp256k1\":\"deadbeef\",\"ed25519\":\"cafebabe\"}";
        let token = "owx_key_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let envelope = encrypt_hkdf(plaintext, token).unwrap();
        assert_eq!(envelope.kdf, "hkdf-sha256");
        let decrypted = decrypt(&envelope, token).unwrap();
        assert_eq!(decrypted.expose(), plaintext);
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let envelope = encrypt(b"", "pass").unwrap();
        let decrypted = decrypt(&envelope, "pass").unwrap();
        assert!(decrypted.expose().is_empty());
    }

    #[test]
    fn wrong_passphrase_rejected() {
        let envelope = encrypt(b"sensitive", "correct").unwrap();
        assert!(decrypt(&envelope, "wrong").is_err());
    }

    #[test]
    fn wrong_token_rejected() {
        let envelope = encrypt_hkdf(b"sensitive", "token-a").unwrap();
        assert!(decrypt(&envelope, "token-b").is_err());
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let mut envelope = encrypt(b"data", "pass").unwrap();
        let mut ct_bytes = hex::decode(&envelope.ciphertext).unwrap();
        if let Some(b) = ct_bytes.first_mut() {
            *b ^= 0xff;
        }
        envelope.ciphertext = hex::encode(&ct_bytes);
        assert!(
            decrypt(&envelope, "pass").is_err(),
            "tampered ciphertext must be rejected"
        );
    }

    #[test]
    fn tampered_auth_tag_rejected() {
        let mut envelope = encrypt(b"data", "pass").unwrap();
        let mut tag_bytes = hex::decode(&envelope.auth_tag).unwrap();
        if let Some(b) = tag_bytes.last_mut() {
            *b ^= 0xff;
        }
        envelope.auth_tag = hex::encode(&tag_bytes);
        assert!(
            decrypt(&envelope, "pass").is_err(),
            "tampered auth tag must be rejected"
        );
    }

    #[test]
    fn unsupported_kdf_rejected() {
        let mut envelope = encrypt(b"data", "pass").unwrap();
        envelope.kdf = "argon2id".to_owned();
        assert!(decrypt(&envelope, "pass").is_err());
    }

    #[test]
    fn envelope_survives_json_serialization() {
        let original = encrypt(b"roundtrip-via-json", "pass").unwrap();
        let json = serde_json::to_string(&original).unwrap();
        let restored: CryptoEnvelope = serde_json::from_str(&json).unwrap();
        let decrypted = decrypt(&restored, "pass").unwrap();
        assert_eq!(decrypted.expose(), b"roundtrip-via-json");
    }

    #[test]
    fn two_encryptions_produce_different_envelopes() {
        let e1 = encrypt(b"same-data", "same-pass").unwrap();
        let e2 = encrypt(b"same-data", "same-pass").unwrap();
        assert_ne!(e1.ciphertext, e2.ciphertext, "random salt/IV should differ");
    }
}
