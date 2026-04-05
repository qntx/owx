//! Backend-agnostic cross-chain token swap engine for OWX.
//!
//! `owx-swap` provides a generic [`SwapBackend`] trait so that multiple
//! aggregators (LiFi, Uniswap, Jupiter, …) can be plugged in behind a
//! unified [`SwapEngine`].
//!
//! # Agent workflow
//!
//! ```ignore
//! use owx_swap::{SwapEngine, SwapRequest};
//!
//! let mut engine = SwapEngine::new();
//! engine.add_backend(owx_swap::backends::lifi::LiFiBackend::new("owx")?);
//!
//! let req = SwapRequest { /* … */ };
//! let quotes = engine.get_quotes(&req).await?;   // JSON-serialisable
//! let receipt = engine.execute(&quotes[0], &signer).await?;
//! ```

pub mod backends;
mod engine;
mod error;
mod provider;
pub mod types;

#[cfg(feature = "evm")]
pub use backends::evm::{evm_provider_from_key, evm_provider_from_key_with_rpcs};
#[cfg(feature = "lifi")]
pub use backends::lifi::LiFiBackend;
pub use engine::SwapEngine;
pub use error::SwapError;
#[cfg(feature = "evm")]
pub use lifiswap_evm::EvmProvider;
pub use provider::{SwapBackend, SwapSigner};
pub use types::{SelectionStrategy, SwapQuote, SwapReceipt, SwapRequest, SwapStatus};
