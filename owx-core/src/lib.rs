//! Core types, chain registry, and error definitions for OWX.
//!
//! This crate provides the shared type system used by all OWX crates:
//! - [`chain`] — Chain type enum, known chains registry, CAIP-2 parsing
//! - [`caip`] — Validated CAIP-2 chain identifier type
//! - [`config`] — Application configuration with RPC endpoints
//! - [`policy`] — Policy types (rules, context, result)
//! - [`wallet_file`] — On-disk encrypted wallet file format
//! - [`api_key`] — API key file format and token utilities
//! - [`error`] — Structured error types with JSON serialization

pub mod api_key;
pub mod caip;
pub mod chain;
pub mod config;
pub mod error;
pub mod policy;
pub mod types;
pub mod wallet_file;

pub use api_key::ApiKeyFile;
pub use caip::ChainId;
pub use chain::{
    ALL_CHAIN_TYPES, Chain, ChainType, KNOWN_CHAINS, default_chain_for_type, parse_chain,
};
pub use config::Config;
pub use error::{OwxError, OwxErrorCode};
pub use policy::{Policy, PolicyAction, PolicyContext, PolicyResult, PolicyRule};
pub use types::WalletId;
pub use wallet_file::{EncryptedWallet, KeyType, WalletAccount};
