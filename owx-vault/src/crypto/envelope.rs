//! On-disk encrypted envelope types (JSON-serializable).

use serde::{Deserialize, Serialize};

/// On-disk encrypted envelope.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::module_name_repetitions)]
pub struct CryptoEnvelope {
    /// Cipher algorithm identifier (always `"aes-256-gcm"`).
    pub cipher: String,
    /// Cipher parameters (IV).
    pub cipherparams: CipherParams,
    /// Hex-encoded ciphertext.
    pub ciphertext: String,
    /// Hex-encoded AES-GCM authentication tag.
    pub auth_tag: String,
    /// KDF algorithm identifier (`"scrypt"` or `"hkdf-sha256"`).
    pub kdf: String,
    /// KDF parameters (variant).
    pub kdfparams: KdfParamsVariant,
}

/// Cipher parameters.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherParams {
    /// Hex-encoded initialization vector.
    pub iv: String,
}

/// Scrypt KDF parameters.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScryptKdfParams {
    /// Derived key length in bytes.
    pub dklen: u32,
    /// CPU/memory cost parameter (power of 2).
    pub n: u32,
    /// Block size parameter.
    pub r: u32,
    /// Parallelization parameter.
    pub p: u32,
    /// Hex-encoded salt.
    pub salt: String,
}

/// HKDF-SHA256 KDF parameters.
#[non_exhaustive]
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
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum KdfParamsVariant {
    /// Scrypt parameters.
    Scrypt(ScryptKdfParams),
    /// HKDF parameters.
    Hkdf(HkdfKdfParams),
}
