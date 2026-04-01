//! Encrypted storage, crypto envelope, and file-system vault for OWX.
//!
//! This crate provides:
//! - [`crypto`] — scrypt/HKDF + AES-256-GCM encryption envelopes
//! - [`store`] — File-system vault CRUD operations
//! - [`secret`] — Zeroize-on-drop secret bytes wrapper with mlock support
//! - [`hardening`] — Process-level security hardening
//!
//! Core types ([`EncryptedWallet`], [`ApiKeyFile`], [`Config`]) live in
//! [`owx_core`] and are re-exported here for convenience.

pub mod audit;
pub mod crypto;
pub mod error;
pub mod hardening;
pub mod key_cache;
pub(crate) mod permissions;
pub mod secret;
pub mod store;

use std::sync::OnceLock;
use std::time::Duration;

pub use crypto::{
    CryptoEnvelope, TOKEN_PREFIX, decrypt, encrypt, encrypt_hkdf, generate_token, hash_token,
    is_api_token,
};
pub use error::VaultError;
pub use key_cache::KeyCache;
pub use secret::SecretBytes;
pub use store::Vault;

/// Process-wide derived-key cache (5 s TTL, max 32 entries).
static GLOBAL_KEY_CACHE: OnceLock<KeyCache> = OnceLock::new();

/// Returns the process-wide key cache.
#[must_use]
pub fn global_key_cache() -> &'static KeyCache {
    GLOBAL_KEY_CACHE.get_or_init(|| KeyCache::new(Duration::from_secs(5), 32))
}
