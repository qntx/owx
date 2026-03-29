//! Encrypted storage, crypto envelope, and file-system vault for OWX.
//!
//! This crate provides:
//! - [`crypto`] — scrypt/HKDF + AES-256-GCM encryption envelopes
//! - [`wallet_file`] — On-disk encrypted wallet format
//! - [`api_key`] — API key file format, token generation and hashing
//! - [`store`] — File-system vault CRUD operations
//! - [`config`] — Application configuration
//! - [`secret`] — Zeroize-on-drop secret bytes wrapper

pub mod api_key;
pub mod config;
pub mod crypto;
pub mod error;
mod permissions;
pub mod secret;
pub mod store;
pub mod wallet_file;

pub use api_key::ApiKeyFile;
pub use config::Config;
pub use crypto::CryptoEnvelope;
pub use error::VaultError;
pub use secret::SecretBytes;
pub use store::Vault;
pub use wallet_file::EncryptedWallet;
