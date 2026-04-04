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
    fn scrypt_encrypt_decrypt_roundtrip() {
        let plaintext = b"secret mnemonic phrase";
        let passphrase = "test-pass";
        let envelope = encrypt(plaintext, passphrase).unwrap();
        assert_eq!(envelope.kdf, "scrypt");
        let decrypted = decrypt(&envelope, passphrase).unwrap();
        assert_eq!(decrypted.expose(), plaintext);
    }

    #[test]
    fn hkdf_encrypt_decrypt_roundtrip() {
        let plaintext = b"agent key material";
        let token = "owx_key_abc123";
        let envelope = encrypt_hkdf(plaintext, token).unwrap();
        assert_eq!(envelope.kdf, "hkdf-sha256");
        let decrypted = decrypt(&envelope, token).unwrap();
        assert_eq!(decrypted.expose(), plaintext);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let envelope = encrypt(b"data", "correct").unwrap();
        let result = decrypt(&envelope, "wrong");
        assert!(result.is_err());
    }

    #[test]
    fn wrong_token_fails() {
        let envelope = encrypt_hkdf(b"data", "token-a").unwrap();
        let result = decrypt(&envelope, "token-b");
        assert!(result.is_err());
    }

    #[test]
    fn unsupported_kdf_fails() {
        let mut envelope = encrypt(b"data", "pass").unwrap();
        envelope.kdf = "argon2".to_owned();
        let result = decrypt(&envelope, "pass");
        assert!(result.is_err());
    }

    #[test]
    fn envelope_json_roundtrip() {
        let envelope = encrypt(b"test", "pass").unwrap();
        let json = serde_json::to_string(&envelope).unwrap();
        let parsed: CryptoEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.cipher, "aes-256-gcm");
        let decrypted = decrypt(&parsed, "pass").unwrap();
        assert_eq!(decrypted.expose(), b"test");
    }
}
