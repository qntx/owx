//! Encryption envelope: scrypt + AES-256-GCM, HKDF-SHA256 + AES-256-GCM.

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use hkdf::Hkdf;
use scrypt::{Params as ScryptParams, scrypt};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

// Prevent fast-kdf from being used in release builds.
#[cfg(all(feature = "fast-kdf", not(debug_assertions)))]
compile_error!(
    "The `fast-kdf` feature reduces scrypt to 2^10 iterations and must not be used in release builds."
);

use crate::error::VaultError;
use crate::secret::SecretBytes;

/// On-disk encrypted envelope (JSON-serializable).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoEnvelope {
    /// Cipher algorithm identifier.
    pub cipher: String,
    /// Cipher parameters (IV).
    pub cipherparams: CipherParams,
    /// Hex-encoded ciphertext.
    pub ciphertext: String,
    /// Hex-encoded AES-GCM authentication tag.
    pub auth_tag: String,
    /// KDF algorithm identifier.
    pub kdf: String,
    /// KDF parameters (variant).
    pub kdfparams: KdfParamsVariant,
}

/// Cipher parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherParams {
    /// Hex-encoded initialization vector.
    pub iv: String,
}

/// Scrypt KDF parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScryptKdfParams {
    /// Derived key length in bytes.
    pub dklen: u32,
    /// CPU/memory cost parameter.
    pub n: u32,
    /// Block size parameter.
    pub r: u32,
    /// Parallelization parameter.
    pub p: u32,
    /// Hex-encoded salt.
    pub salt: String,
}

/// HKDF-SHA256 KDF parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HkdfKdfParams {
    /// Derived key length in bytes.
    pub dklen: u32,
    /// Hex-encoded salt.
    pub salt: String,
    /// Info string for HKDF expand.
    pub info: String,
}

/// Unified KDF parameters — deserializes to whichever variant matches.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum KdfParamsVariant {
    /// Scrypt parameters.
    Scrypt(ScryptKdfParams),
    /// HKDF parameters.
    Hkdf(HkdfKdfParams),
}

/// Scrypt log2(N) for tests / fast-kdf.
#[cfg(any(test, feature = "fast-kdf"))]
const KDF_LOG_N: u8 = 10;
/// Scrypt log2(N) for production.
#[cfg(not(any(test, feature = "fast-kdf")))]
const KDF_LOG_N: u8 = 16;

/// Scrypt N = 2^log_n.
const KDF_N: u32 = 1 << (KDF_LOG_N as u32);
/// Scrypt block size.
const KDF_R: u32 = 8;
/// Scrypt parallelism.
const KDF_P: u32 = 1;
/// Derived key length for scrypt.
const KDF_DKLEN: u32 = 32;

/// HKDF info string.
const HKDF_INFO: &[u8] = b"owx-api-key-v1";
/// Derived key length for HKDF.
const HKDF_DKLEN: u32 = 32;

/// Fill a buffer with cryptographically secure random bytes.
///
/// # Panics
///
/// Panics if the system CSPRNG is unavailable.
fn fill_random(buf: &mut [u8]) {
    #[allow(clippy::expect_used)]
    getrandom::getrandom(buf).expect("system CSPRNG unavailable");
}

/// Encrypt plaintext with a passphrase (scrypt KDF + AES-256-GCM).
pub fn encrypt(plaintext: &[u8], passphrase: &str) -> Result<CryptoEnvelope, VaultError> {
    let mut salt = [0u8; 32];
    fill_random(&mut salt);

    let mut iv = [0u8; 12];
    fill_random(&mut iv);

    let params = ScryptParams::new(KDF_LOG_N, KDF_R, KDF_P, KDF_DKLEN as usize)
        .map_err(|e| VaultError::InvalidParams(e.to_string()))?;
    let mut derived_key = [0u8; 32];
    scrypt(passphrase.as_bytes(), &salt, &params, &mut derived_key)
        .map_err(|e| VaultError::Crypto(e.to_string()))?;

    let (ciphertext_hex, auth_tag_hex) = aes_gcm_encrypt(&derived_key, &iv, plaintext)?;
    derived_key.zeroize();

    Ok(CryptoEnvelope {
        cipher: "aes-256-gcm".to_owned(),
        cipherparams: CipherParams {
            iv: hex::encode(iv),
        },
        ciphertext: ciphertext_hex,
        auth_tag: auth_tag_hex,
        kdf: "scrypt".to_owned(),
        kdfparams: KdfParamsVariant::Scrypt(ScryptKdfParams {
            dklen: KDF_DKLEN,
            n: KDF_N,
            r: KDF_R,
            p: KDF_P,
            salt: hex::encode(salt),
        }),
    })
}

/// Encrypt plaintext with an API token (HKDF-SHA256 + AES-256-GCM).
pub fn encrypt_hkdf(plaintext: &[u8], token: &str) -> Result<CryptoEnvelope, VaultError> {
    let mut salt = [0u8; 32];
    fill_random(&mut salt);

    let mut iv = [0u8; 12];
    fill_random(&mut iv);

    let mut derived_key = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(&salt), token.as_bytes());
    hk.expand(HKDF_INFO, &mut derived_key)
        .map_err(|e| VaultError::Crypto(e.to_string()))?;

    let (ciphertext_hex, auth_tag_hex) = aes_gcm_encrypt(&derived_key, &iv, plaintext)?;
    derived_key.zeroize();

    Ok(CryptoEnvelope {
        cipher: "aes-256-gcm".to_owned(),
        cipherparams: CipherParams {
            iv: hex::encode(iv),
        },
        ciphertext: ciphertext_hex,
        auth_tag: auth_tag_hex,
        kdf: "hkdf-sha256".to_owned(),
        kdfparams: KdfParamsVariant::Hkdf(HkdfKdfParams {
            dklen: HKDF_DKLEN,
            salt: hex::encode(salt),
            info: String::from_utf8_lossy(HKDF_INFO).into_owned(),
        }),
    })
}

/// Decrypt a [`CryptoEnvelope`]. Dispatches on the `kdf` field.
pub fn decrypt(envelope: &CryptoEnvelope, credential: &str) -> Result<SecretBytes, VaultError> {
    match envelope.kdf.as_str() {
        "scrypt" => decrypt_scrypt(envelope, credential),
        "hkdf-sha256" => decrypt_hkdf(envelope, credential),
        other => Err(VaultError::InvalidParams(format!(
            "unsupported KDF: {other}"
        ))),
    }
}

/// Decrypt using scrypt-derived key.
fn decrypt_scrypt(envelope: &CryptoEnvelope, passphrase: &str) -> Result<SecretBytes, VaultError> {
    let KdfParamsVariant::Scrypt(kp) = &envelope.kdfparams else {
        return Err(VaultError::InvalidParams(
            "expected scrypt kdfparams".into(),
        ));
    };

    validate_scrypt_params(kp)?;

    let salt = hex_decode(&kp.salt)?;
    let iv = hex_decode(&envelope.cipherparams.iv)?;
    let ciphertext = hex_decode(&envelope.ciphertext)?;
    let auth_tag = hex_decode(&envelope.auth_tag)?;

    #[allow(clippy::cast_possible_truncation)]
    let log_n = kp.n.trailing_zeros() as u8;
    let params = ScryptParams::new(log_n, kp.r, kp.p, kp.dklen as usize)
        .map_err(|e| VaultError::InvalidParams(e.to_string()))?;

    let mut derived_key = vec![0u8; kp.dklen as usize];
    scrypt(passphrase.as_bytes(), &salt, &params, &mut derived_key)
        .map_err(|e| VaultError::Crypto(e.to_string()))?;

    let result = aes_gcm_decrypt(&derived_key, &iv, &ciphertext, &auth_tag);
    derived_key.zeroize();
    result
}

/// Decrypt using HKDF-SHA256-derived key.
fn decrypt_hkdf(envelope: &CryptoEnvelope, token: &str) -> Result<SecretBytes, VaultError> {
    let KdfParamsVariant::Hkdf(kp) = &envelope.kdfparams else {
        return Err(VaultError::InvalidParams("expected HKDF kdfparams".into()));
    };

    if kp.dklen != HKDF_DKLEN {
        return Err(VaultError::InvalidParams(format!(
            "HKDF dklen={}, expected {HKDF_DKLEN}",
            kp.dklen
        )));
    }

    let salt = hex_decode(&kp.salt)?;
    let iv = hex_decode(&envelope.cipherparams.iv)?;
    let ciphertext = hex_decode(&envelope.ciphertext)?;
    let auth_tag = hex_decode(&envelope.auth_tag)?;

    let mut derived_key = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(&salt), token.as_bytes());
    hk.expand(kp.info.as_bytes(), &mut derived_key)
        .map_err(|e| VaultError::Crypto(e.to_string()))?;

    let result = aes_gcm_decrypt(&derived_key, &iv, &ciphertext, &auth_tag);
    derived_key.zeroize();
    result
}

/// Validate scrypt parameters for safety bounds.
fn validate_scrypt_params(kp: &ScryptKdfParams) -> Result<(), VaultError> {
    let n = kp.n;
    if n == 0 || (n & (n - 1)) != 0 {
        return Err(VaultError::InvalidParams(format!(
            "scrypt N must be a power of 2, got {n}"
        )));
    }
    if n < KDF_N {
        return Err(VaultError::InvalidParams(format!(
            "scrypt N={n} below minimum {KDF_N} — possible downgrade attack"
        )));
    }
    if kp.r < KDF_R {
        return Err(VaultError::InvalidParams(format!(
            "scrypt r={} below minimum {KDF_R}",
            kp.r
        )));
    }
    if kp.p < KDF_P {
        return Err(VaultError::InvalidParams(format!(
            "scrypt p={} below minimum {KDF_P}",
            kp.p
        )));
    }
    if kp.dklen != KDF_DKLEN {
        return Err(VaultError::InvalidParams(format!(
            "dklen={}, expected {KDF_DKLEN}",
            kp.dklen
        )));
    }
    Ok(())
}

/// AES-256-GCM encrypt, returning `(ciphertext, tag)`.
fn aes_gcm_encrypt(
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
) -> Result<(String, String), VaultError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(iv);
    let ciphertext_with_tag = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| VaultError::Crypto(e.to_string()))?;

    let tag_offset = ciphertext_with_tag.len() - 16;
    let ct = &ciphertext_with_tag[..tag_offset];
    let tag = &ciphertext_with_tag[tag_offset..];
    Ok((hex::encode(ct), hex::encode(tag)))
}

/// AES-256-GCM decrypt with tag verification.
///
/// Decrypts the given ciphertext with the provided key, IV, and authentication
/// tag, returning the decrypted plaintext as a `SecretBytes` instance.
fn aes_gcm_decrypt(
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

/// Decode a hex string into bytes.
fn hex_decode(s: &str) -> Result<Vec<u8>, VaultError> {
    hex::decode(s).map_err(|e| VaultError::InvalidParams(e.to_string()))
}

/// Token prefix that signals agent mode.
pub const TOKEN_PREFIX: &str = "owx_key_";

/// Check whether a credential string is an API token.
#[must_use]
pub fn is_api_token(credential: &str) -> bool {
    credential.starts_with(TOKEN_PREFIX)
}

/// Generate a random API token: `owx_key_<64 hex chars>` (256 bits of entropy).
///
/// # Panics
///
/// Panics if the system CSPRNG is unavailable.
pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    fill_random(&mut bytes);
    format!("{TOKEN_PREFIX}{}", hex::encode(bytes))
}

/// SHA-256 hash of the raw token string, hex-encoded.
#[must_use]
pub fn hash_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(token.as_bytes()))
}
