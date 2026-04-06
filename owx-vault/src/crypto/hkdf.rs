//! HKDF-SHA256 KDF + AES-256-GCM encryption/decryption (for API key tokens).

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use super::aes;
use super::envelope::{CipherParams, CryptoEnvelope, HkdfKdfParams, KdfParamsVariant};
use super::rand::fill_random;
use crate::error::VaultError;
use crate::secret::SecretBytes;

/// HKDF info string.
const INFO: &[u8] = b"owx-api-key-v1";
/// Derived key length.
const DKLEN: u32 = 32;

/// Encrypt plaintext with an API token (HKDF-SHA256 + AES-256-GCM).
///
/// # Errors
///
/// Returns [`VaultError::Crypto`] if HKDF expansion or AES encryption fails.
pub fn encrypt(plaintext: &[u8], token: &str) -> Result<CryptoEnvelope, VaultError> {
    let mut salt = [0u8; 32];
    fill_random(&mut salt);
    let mut iv = [0u8; 12];
    fill_random(&mut iv);

    let mut dk = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(&salt), token.as_bytes());
    hk.expand(INFO, &mut dk)
        .map_err(|e| VaultError::Crypto(e.to_string()))?;

    let (ct, tag) = aes::encrypt(&dk, &iv, plaintext)?;
    dk.zeroize();

    Ok(CryptoEnvelope {
        cipher: "aes-256-gcm".to_owned(),
        cipherparams: CipherParams {
            iv: hex::encode(iv),
        },
        ciphertext: ct,
        auth_tag: tag,
        kdf: "hkdf-sha256".to_owned(),
        kdfparams: KdfParamsVariant::Hkdf(HkdfKdfParams {
            dklen: DKLEN,
            salt: hex::encode(salt),
            info: String::from_utf8_lossy(INFO).into_owned(),
        }),
    })
}

/// Decrypt an HKDF-encrypted envelope.
///
/// # Errors
///
/// Returns [`VaultError::InvalidParams`] if the derived key length is wrong,
/// or [`VaultError::Crypto`] if HKDF expansion or AES decryption fails.
pub fn decrypt(envelope: &CryptoEnvelope, token: &str) -> Result<SecretBytes, VaultError> {
    let KdfParamsVariant::Hkdf(kp) = &envelope.kdfparams else {
        return Err(VaultError::InvalidParams("expected HKDF kdfparams".into()));
    };
    if kp.dklen != DKLEN {
        return Err(VaultError::InvalidParams(format!(
            "HKDF dklen={}, expected {DKLEN}",
            kp.dklen
        )));
    }

    let salt = super::hex_decode(&kp.salt)?;
    let iv = super::hex_decode(&envelope.cipherparams.iv)?;
    let ct = super::hex_decode(&envelope.ciphertext)?;
    let tag = super::hex_decode(&envelope.auth_tag)?;

    let mut dk = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(&salt), token.as_bytes());
    hk.expand(kp.info.as_bytes(), &mut dk)
        .map_err(|e| VaultError::Crypto(e.to_string()))?;

    let result = aes::decrypt(&dk, &iv, &ct, &tag);
    dk.zeroize();
    result
}
