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
