//! Core types and chain registry for OWX.
//!
//! This crate contains **zero business logic** — only shared types,
//! the chain registry, configuration, policy definitions, error types,
//! and on-disk file formats.

pub mod api_key;
pub mod chain;
pub mod config;
pub mod error;
pub mod policy;
pub mod types;
pub mod wallet_file;

pub use api_key::ApiKeyFile;
pub use chain::{
    default_chain_for_type, parse_chain, Chain, ChainType, ALL_CHAIN_TYPES, KNOWN_CHAINS,
};
pub use config::Config;
pub use error::{OwxError, OwxErrorCode};
pub use policy::{
    Policy, PolicyAction, PolicyContext, PolicyResult, PolicyRule, SpendingContext,
    TransactionContext,
};
pub use types::WalletId;
pub use wallet_file::{EncryptedWallet, KeyType, WalletAccount};
