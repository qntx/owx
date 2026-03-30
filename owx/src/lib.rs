//! Agent-native, self-custodial, policy-gated, multi-chain wallet toolkit.
//!
//! `owx` is the orchestration layer that combines:
//! - [`owx_core`] for shared types and chain registry
//! - [`kobe`] for HD key derivation
//! - [`signer`] for chain-specific signing
//! - [`owx_vault`] for encrypted storage and process hardening
//! - [`owx_policy`] for policy enforcement
//! - [`owx_pay`] for x402 payments

pub mod agent;
pub mod broadcast;
pub mod derivation;
pub mod error;
pub mod key_ops;
pub mod signing;
pub mod wallet_ops;
pub(crate) mod wallet_secret;

pub use agent::AgentWallet;
pub use broadcast::SendResult;
pub use error::OwxError;
pub use signing::{SignResult, TransactionSignResult};
pub use wallet_ops::{AccountInfo, WalletInfo};
