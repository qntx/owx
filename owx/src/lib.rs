//! Agent-native, self-custodial, policy-gated, multi-chain wallet toolkit.
//!
//! `owx` is the orchestration layer that combines:
//! - [`owx_core`] for shared types and chain registry
//! - [`kobe`] for HD key derivation
//! - [`signer`] for chain-specific signing
//! - [`owx_vault`] for encrypted storage and process hardening
//! - [`owx_policy`] for policy enforcement
//! - [`owx_pay`] for x402 payments

mod agent;
mod broadcast;
mod derivation;
mod error;
mod key_ops;
mod services;
mod signing;
mod wallet_ops;
mod wallet_secret;

pub use agent::AgentWallet;
pub use error::{OwxError, OwxErrorCode};
pub use owx_core::{
    AccountInfo, ApiKeyCreateResult, ApiKeyInfo, SendResult, SignResult, TransactionSignResult,
    WalletInfo,
};
pub use services::{ApiKeyService, SigningService, WalletService, derive_address};
pub use wallet_secret::WalletSecret;
