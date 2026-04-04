//! Cross-chain token swap via LiFi for OWX.
//!
//! Wraps [`lifiswap::LiFiClient`] with a simplified async API for quoting,
//! routing, and executing cross-chain swaps using OWX wallets.
//!
//! ```ignore
//! let client = owx_swap::SwapClient::new("my-integrator")?;
//! let quote = client.quote("42161", "0xUSDC", "0xWallet", "10000000", "10", "0xDAI").await?;
//! ```

#![allow(clippy::missing_docs_in_private_items)]

mod client;
mod error;

pub use client::SwapClient;
pub use error::SwapError;
pub use lifiswap;

/// Re-export key types from lifiswap for convenience.
pub mod types {
    pub use lifiswap::types::*;
}
