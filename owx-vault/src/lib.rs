//! Crypto envelope, secret-bytes, and generic file-system store for OWX.
//!
//! - [`crypto`] — scrypt / HKDF-SHA256 + AES-256-GCM encryption envelopes
//! - [`secret`] — Zeroize-on-drop secret bytes wrapper with mlock support
//! - [`store`] — Generic JSON file-system store
//! - [`key_cache`] — TTL-based derived key cache
//! - [`hardening`] — Process-level security hardening (core dumps, ptrace, signals)

pub mod crypto;
pub mod error;
pub mod hardening;
pub mod key_cache;
pub mod secret;
pub mod store;

pub use crypto::CryptoEnvelope;
pub use error::VaultError;
pub use key_cache::KeyCache;
pub use secret::SecretBytes;
pub use store::Store;
