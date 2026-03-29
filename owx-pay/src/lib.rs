//! x402 payment client for OWX agent wallets.
//!
//! Provides the [`WalletBridge`] trait that the main `owx` crate implements,
//! and the x402 payment flow (detect 402 → parse requirements → sign → retry).

pub mod error;
pub mod types;
pub mod wallet;
pub mod x402;

pub use error::PayError;
pub use types::{PayResult, PaymentInfo};
pub use wallet::WalletBridge;
