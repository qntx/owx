//! Cross-chain token swap via LiFi for OWX.
//!
//! This crate wraps the [`lifiswap`] SDK to provide a simple swap interface
//! that integrates with OWX vault wallets.
//!
//! ```ignore
//! let client = owx_swap::SwapClient::new("my-integrator")?;
//! let quote = client.quote(&request).await?;
//! ```

#![allow(clippy::missing_docs_in_private_items)]

pub use lifiswap;

/// Swap error.
#[derive(Debug, thiserror::Error)]
pub enum SwapError {
    /// LiFi SDK error.
    #[error("lifi: {0}")]
    LiFi(#[from] lifiswap::error::LiFiError),
    /// OWX error.
    #[error("owx: {0}")]
    Owx(#[from] owx::Error),
}

/// Re-export key types from lifiswap for convenience.
pub mod types {
    pub use lifiswap::types::*;
}
