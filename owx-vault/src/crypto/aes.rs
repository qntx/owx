//! AES-256-GCM encrypt/decrypt primitives.

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};

use crate::error::VaultError;
use crate::secret::SecretBytes;

/// AES-256-GCM encrypt, returning `(ciphertext_hex, tag_hex)`.
pub fn encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<(String, String), VaultError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(iv);
    let combined = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| VaultError::Crypto(e.to_string()))?;

    let tag_offset = combined.len() - 16;
    Ok((
        hex::encode(&combined[..tag_offset]),
        hex::encode(&combined[tag_offset..]),
    ))
}

/// AES-256-GCM decrypt with tag verification.
pub fn decrypt(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<SecretBytes, VaultError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(iv);

    let mut combined = ciphertext.to_vec();
    combined.extend_from_slice(tag);

    let plaintext = cipher
        .decrypt(nonce, combined.as_ref())
        .map_err(|e| VaultError::Crypto(e.to_string()))?;

    Ok(SecretBytes::new(plaintext))
}
