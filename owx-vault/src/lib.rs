//! Encrypted storage, crypto envelope, and file-system vault for OWX.
//!
//! This crate provides:
//! - [`crypto`] — scrypt/HKDF + AES-256-GCM encryption envelopes
//! - [`store::Vault`] — File-system vault CRUD operations
//! - [`secret`] — Zeroize-on-drop secret bytes wrapper with mlock support
//! - [`hardening`] — Process-level security hardening
//!
//! Storage-layer types ([`EncryptedWallet`], [`ApiKeyFile`], [`Policy`],
//! [`Config`]) also live here since they are tightly coupled with vault I/O.

pub mod api_key;
pub mod audit;
pub mod config;
pub mod crypto;
pub mod error;
pub mod hardening;
pub mod key_cache;
pub(crate) mod permissions;
pub mod policy;
pub mod secret;
pub mod store;
pub mod wallet;

use std::sync::OnceLock;
use std::time::Duration;

pub use api_key::ApiKeyFile;
pub use config::Config;
pub use crypto::{
    CryptoEnvelope, TOKEN_PREFIX, decrypt, encrypt, encrypt_hkdf, generate_token, hash_token,
    is_api_token,
};
pub use error::VaultError;
pub use key_cache::KeyCache;
pub use policy::{
    Policy, PolicyAction, PolicyContext, PolicyResult, PolicyRule, SpendingContext,
    TransactionContext,
};
pub use secret::SecretBytes;
pub use store::Vault;
pub use wallet::{EncryptedWallet, KeyType, WalletAccount};

/// Process-wide derived-key cache (5 s TTL, max 32 entries).
static GLOBAL_KEY_CACHE: OnceLock<KeyCache> = OnceLock::new();

/// Returns the process-wide key cache.
#[must_use]
pub fn global_key_cache() -> &'static KeyCache {
    GLOBAL_KEY_CACHE.get_or_init(|| KeyCache::new(Duration::from_secs(5), 32))
}
