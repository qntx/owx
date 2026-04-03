//! Crypto envelope, secret-bytes, and generic file-system store for OWX.
//!
//! This crate is **domain-agnostic** — it knows nothing about wallets,
//! chains, or policies.  It provides:
//!
//! - [`crypto`] — scrypt / HKDF-SHA256 + AES-256-GCM encryption envelopes
//! - [`secret`] — Zeroize-on-drop secret bytes wrapper with mlock support
//! - [`store`] — Generic JSON file-system store
//! - [`hardening`] — Process-level security hardening (core dumps, ptrace, signals)

pub mod crypto;
pub mod error;
pub mod hardening;
pub mod key_cache;
pub mod secret;
pub mod store;

use std::sync::OnceLock;
use std::time::Duration;

pub use crypto::CryptoEnvelope;
pub use error::VaultError;
pub use key_cache::KeyCache;
pub use secret::SecretBytes;
pub use store::Store;

/// Process-wide derived-key cache (5 s TTL, max 32 entries).
static GLOBAL_KEY_CACHE: OnceLock<KeyCache> = OnceLock::new();

/// Returns the process-wide key cache.
#[must_use]
pub fn global_key_cache() -> &'static KeyCache {
    GLOBAL_KEY_CACHE.get_or_init(|| KeyCache::new(Duration::from_secs(5), 32))
}
