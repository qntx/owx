//! Scrypt KDF + AES-256-GCM encryption/decryption.

use scrypt::{Params as ScryptParams, scrypt};
use zeroize::Zeroize;

use super::aes;
use super::envelope::{CipherParams, CryptoEnvelope, KdfParamsVariant, ScryptKdfParams};
use super::rand::fill_random;
use crate::error::VaultError;
use crate::secret::SecretBytes;

/// Scrypt log2(N) for tests / fast-kdf.
#[cfg(any(test, feature = "fast-kdf"))]
const LOG_N: u8 = 10;
/// Scrypt log2(N) for production.
#[cfg(not(any(test, feature = "fast-kdf")))]
const LOG_N: u8 = 16;

/// Scrypt N = `2^log_n`.
pub(crate) const N: u32 = 1 << (LOG_N as u32);
/// Scrypt block size.
pub(crate) const R: u32 = 8;
/// Scrypt parallelism.
pub(crate) const P: u32 = 1;
/// Derived key length.
pub(crate) const DKLEN: u32 = 32;

/// Encrypt plaintext with a passphrase (scrypt KDF + AES-256-GCM).
///
/// # Errors
///
/// Returns [`VaultError::InvalidParams`] if scrypt parameters are invalid,
/// or [`VaultError::Crypto`] if key derivation or AES encryption fails.
pub fn encrypt(plaintext: &[u8], passphrase: &str) -> Result<CryptoEnvelope, VaultError> {
    let mut salt = [0u8; 32];
    fill_random(&mut salt)?;
    let mut iv = [0u8; 12];
    fill_random(&mut iv)?;

    let params = ScryptParams::new(LOG_N, R, P, DKLEN as usize)
        .map_err(|e| VaultError::InvalidParams(e.to_string()))?;
    let mut dk = [0u8; 32];
    scrypt(passphrase.as_bytes(), &salt, &params, &mut dk)
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
        kdf: "scrypt".to_owned(),
        kdfparams: KdfParamsVariant::Scrypt(ScryptKdfParams {
            dklen: DKLEN,
            n: N,
            r: R,
            p: P,
            salt: hex::encode(salt),
        }),
    })
}

/// Decrypt a scrypt-encrypted envelope.
///
/// # Errors
///
/// Returns [`VaultError::InvalidParams`] if scrypt parameters are invalid or
/// out of allowed bounds, or [`VaultError::Crypto`] if decryption fails.
pub fn decrypt(envelope: &CryptoEnvelope, passphrase: &str) -> Result<SecretBytes, VaultError> {
    let KdfParamsVariant::Scrypt(kp) = &envelope.kdfparams else {
        return Err(VaultError::InvalidParams(
            "expected scrypt kdfparams".into(),
        ));
    };
    validate_params(kp)?;

    let salt = super::hex_decode(&kp.salt)?;
    let iv = super::hex_decode(&envelope.cipherparams.iv)?;
    let ct = super::hex_decode(&envelope.ciphertext)?;
    let tag = super::hex_decode(&envelope.auth_tag)?;

    let log_n = u8::try_from(kp.n.trailing_zeros())
        .map_err(|_| VaultError::InvalidParams("scrypt log_n exceeds u8 range".into()))?;
    let params = ScryptParams::new(log_n, kp.r, kp.p, kp.dklen as usize)
        .map_err(|e| VaultError::InvalidParams(e.to_string()))?;

    let mut dk = vec![0u8; kp.dklen as usize];
    scrypt(passphrase.as_bytes(), &salt, &params, &mut dk)
        .map_err(|e| VaultError::Crypto(e.to_string()))?;

    let result = aes::decrypt(&dk, &iv, &ct, &tag);
    dk.zeroize();
    result
}

/// Validate scrypt parameters for safety bounds.
fn validate_params(kp: &ScryptKdfParams) -> Result<(), VaultError> {
    let n = kp.n;
    if n == 0 || (n & (n - 1)) != 0 {
        return Err(VaultError::InvalidParams(format!(
            "scrypt N must be power of 2, got {n}"
        )));
    }
    if n < N {
        return Err(VaultError::InvalidParams(format!(
            "scrypt N={n} below minimum {N}"
        )));
    }
    if kp.r < R {
        return Err(VaultError::InvalidParams(format!(
            "scrypt r={} below minimum {R}",
            kp.r
        )));
    }
    if kp.p < P {
        return Err(VaultError::InvalidParams(format!(
            "scrypt p={} below minimum {P}",
            kp.p
        )));
    }
    if kp.dklen != DKLEN {
        return Err(VaultError::InvalidParams(format!(
            "dklen={}, expected {DKLEN}",
            kp.dklen
        )));
    }
    Ok(())
}
