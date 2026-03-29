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

pub mod crypto;
pub mod error;
pub mod hardening;
pub(crate) mod permissions;
pub mod secret;
pub mod store;

pub use crypto::CryptoEnvelope;
pub use error::VaultError;
pub use owx_core::api_key::{
    self, ApiKeyFile, TOKEN_PREFIX, generate_token, hash_token, is_api_token,
};
pub use owx_core::config::Config;
pub use owx_core::wallet_file::{self, EncryptedWallet, KeyType, WalletAccount};
pub use secret::SecretBytes;
pub use store::Vault;
