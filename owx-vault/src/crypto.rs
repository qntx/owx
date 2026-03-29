//! Encryption envelope: scrypt + AES-256-GCM, HKDF-SHA256 + AES-256-GCM.
//!
//! HKDF-SHA256 is implemented inline to avoid version conflicts between
//! `hkdf 0.12` (which pins `sha2 0.10`) and the latest `sha2 0.11`.

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use scrypt::{Params as ScryptParams, scrypt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

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

#[cfg(any(test, feature = "fast-kdf"))]
const KDF_LOG_N: u8 = 10;
#[cfg(not(any(test, feature = "fast-kdf")))]
const KDF_LOG_N: u8 = 16;

const KDF_N: u32 = 1 << (KDF_LOG_N as u32);
const KDF_R: u32 = 8;
const KDF_P: u32 = 1;
const KDF_DKLEN: u32 = 32;

const HKDF_INFO: &[u8] = b"owx-api-key-v1";
const HKDF_DKLEN: u32 = 32;

/// Fill a buffer with cryptographically secure random bytes.
fn fill_random(buf: &mut [u8]) {
    getrandom::fill(buf).expect("system CSPRNG unavailable");
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
    hkdf_sha256(&salt, token.as_bytes(), HKDF_INFO, &mut derived_key);

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

fn decrypt_scrypt(envelope: &CryptoEnvelope, passphrase: &str) -> Result<SecretBytes, VaultError> {
    let kp = match &envelope.kdfparams {
        KdfParamsVariant::Scrypt(p) => p,
        _ => {
            return Err(VaultError::InvalidParams(
                "expected scrypt kdfparams".into(),
            ));
        }
    };

    validate_scrypt_params(kp)?;

    let salt = hex_decode(&kp.salt)?;
    let iv = hex_decode(&envelope.cipherparams.iv)?;
    let ciphertext = hex_decode(&envelope.ciphertext)?;
    let auth_tag = hex_decode(&envelope.auth_tag)?;

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

fn decrypt_hkdf(envelope: &CryptoEnvelope, token: &str) -> Result<SecretBytes, VaultError> {
    let kp = match &envelope.kdfparams {
        KdfParamsVariant::Hkdf(p) => p,
        _ => return Err(VaultError::InvalidParams("expected HKDF kdfparams".into())),
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
    hkdf_sha256(
        &salt,
        token.as_bytes(),
        kp.info.as_bytes(),
        &mut derived_key,
    );

    let result = aes_gcm_decrypt(&derived_key, &iv, &ciphertext, &auth_tag);
    derived_key.zeroize();
    result
}

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
    if kp.dklen != KDF_DKLEN {
        return Err(VaultError::InvalidParams(format!(
            "dklen={}, expected {KDF_DKLEN}",
            kp.dklen
        )));
    }
    Ok(())
}

fn aes_gcm_encrypt(
    key: &[u8; 32],
    iv: &[u8; 12],
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

fn aes_gcm_decrypt(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    auth_tag: &[u8],
) -> Result<SecretBytes, VaultError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(iv);

    let mut combined = ciphertext.to_vec();
    combined.extend_from_slice(auth_tag);

    let plaintext = cipher
        .decrypt(nonce, combined.as_ref())
        .map_err(|e| VaultError::Crypto(e.to_string()))?;

    Ok(SecretBytes::new(plaintext))
}

fn hex_decode(s: &str) -> Result<Vec<u8>, VaultError> {
    hex::decode(s).map_err(|e| VaultError::InvalidParams(e.to_string()))
}

/// HMAC-SHA256 (RFC 2104).
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;

    let mut padded_key = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let h = Sha256::digest(key);
        padded_key[..32].copy_from_slice(&h);
    } else {
        padded_key[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= padded_key[i];
        opad[i] ^= padded_key[i];
    }
    padded_key.zeroize();

    let inner = Sha256::new()
        .chain_update(ipad)
        .chain_update(data)
        .finalize();
    let outer = Sha256::new()
        .chain_update(opad)
        .chain_update(inner)
        .finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&outer);
    out
}

/// HKDF-SHA256 extract-then-expand (RFC 5869).
fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) {
    let effective_salt = if salt.is_empty() {
        &[0u8; 32][..]
    } else {
        salt
    };
    let prk = hmac_sha256(effective_salt, ikm);

    let hash_len = 32usize;
    let n = okm.len().div_ceil(hash_len);
    let mut t = Vec::new();
    let mut offset = 0;

    for i in 1..=n {
        let mut buf = Vec::with_capacity(t.len() + info.len() + 1);
        buf.extend_from_slice(&t);
        buf.extend_from_slice(info);
        #[allow(clippy::cast_possible_truncation)]
        buf.push(i as u8);
        let block = hmac_sha256(&prk, &buf);
        t = block.to_vec();
        let copy_len = std::cmp::min(hash_len, okm.len() - offset);
        okm[offset..offset + copy_len].copy_from_slice(&t[..copy_len]);
        offset += copy_len;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrypt_roundtrip() {
        let plaintext = b"hello world";
        let envelope = encrypt(plaintext, "pass").unwrap();
        let decrypted = decrypt(&envelope, "pass").unwrap();
        assert_eq!(decrypted.expose(), plaintext);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let envelope = encrypt(b"data", "correct").unwrap();
        assert!(decrypt(&envelope, "wrong").is_err());
    }

    #[test]
    fn hkdf_roundtrip() {
        let plaintext = b"agent secret";
        let token = "owx_key_abc123";
        let envelope = encrypt_hkdf(plaintext, token).unwrap();
        assert_eq!(envelope.kdf, "hkdf-sha256");
        let decrypted = decrypt(&envelope, token).unwrap();
        assert_eq!(decrypted.expose(), plaintext);
    }

    #[test]
    fn hkdf_wrong_token_fails() {
        let envelope = encrypt_hkdf(b"data", "token1").unwrap();
        assert!(decrypt(&envelope, "token2").is_err());
    }

    #[test]
    fn different_encryptions_differ() {
        let e1 = encrypt(b"same", "pass").unwrap();
        let e2 = encrypt(b"same", "pass").unwrap();
        assert_ne!(e1.ciphertext, e2.ciphertext);
    }

    #[test]
    fn envelope_serde_roundtrip() {
        let envelope = encrypt(b"serde test", "pass").unwrap();
        let json = serde_json::to_string(&envelope).unwrap();
        let restored: CryptoEnvelope = serde_json::from_str(&json).unwrap();
        let decrypted = decrypt(&restored, "pass").unwrap();
        assert_eq!(decrypted.expose(), b"serde test");
    }

    #[test]
    fn unsupported_kdf_rejected() {
        let mut envelope = encrypt(b"x", "p").unwrap();
        envelope.kdf = "argon2id".to_owned();
        assert!(decrypt(&envelope, "p").is_err());
    }

    #[test]
    fn hmac_sha256_test_vector() {
        // RFC 4231 test case 2
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
        let result = hmac_sha256(key, data);
        assert_eq!(hex::encode(result), expected);
    }
}
