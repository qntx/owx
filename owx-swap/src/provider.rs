//! Backend-agnostic swap provider and signer traits.
//!
//! [`SwapBackend`] is the extension point for adding new swap/bridge
//! aggregators (`LiFi`, Uniswap, Jupiter, 1inch, …).
//!
//! [`SwapSigner`] abstracts the signing capability so that `owx-swap` never
//! touches raw private keys directly.

use std::future::Future;
use std::pin::Pin;

use crate::error::SwapError;
use crate::types::{SwapQuote, SwapReceipt, SwapRequest};

/// A swap/bridge aggregator backend.
///
/// Implementations translate between the generic [`SwapRequest`]/[`SwapQuote`]
/// types and the backend's native API.
pub trait SwapBackend: Send + Sync {
    /// Unique backend identifier (e.g. `"lifi"`, `"uniswap"`, `"jupiter"`).
    fn name(&self) -> &str;

    /// Fetch quotes for a swap request.
    fn get_quotes<'a>(
        &'a self,
        req: &'a SwapRequest,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SwapQuote>, SwapError>> + Send + 'a>>;

    /// Execute a previously obtained quote.
    ///
    /// The `quote.opaque` field carries backend-specific state needed for
    /// execution (e.g. a serialised `LiFi` `Route`).
    fn execute<'a>(
        &'a self,
        quote: &'a SwapQuote,
        signer: &'a dyn SwapSigner,
    ) -> Pin<Box<dyn Future<Output = Result<SwapReceipt, SwapError>> + Send + 'a>>;
}

/// Signing abstraction injected by the caller (typically `owx` core).
///
/// The swap engine never sees raw private keys — it delegates all
/// cryptographic operations through this trait.
pub trait SwapSigner: Send + Sync {
    /// Wallet address on the relevant chain.
    fn address(&self) -> &str;

    /// Sign and broadcast a raw transaction, returning the tx hash.
    fn send_transaction<'a>(
        &'a self,
        chain_id: u64,
        tx_data: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<String, SwapError>> + Send + 'a>>;
}
