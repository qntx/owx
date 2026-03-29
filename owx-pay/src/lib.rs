//! x402 payment client for OWX agent wallets.
//!
//! Provides the [`WalletBridge`] trait that the main `owx` crate implements,
//! and the x402 payment flow (detect 402 → parse requirements → sign → retry).
//!
//! Also includes service discovery and wallet funding via MoonPay.

pub mod discovery;
pub mod error;
pub mod fund;
pub mod types;
pub mod wallet;
pub mod x402;

pub use error::PayError;
pub use types::{DiscoverResult, FundResult, PayResult, PaymentInfo, Service};
pub use wallet::WalletBridge;
