//! x402 payment protocol, service discovery, and wallet funding for OWX.
//!
//! This crate is optional — enable it via `owx-pay` in your dependencies.
//!
//! ```ignore
//! let result = owx_pay::pay(&bridge, "https://api.example.com/data", "GET", None)?;
//! let services = owx_pay::discover(None, Some(20), None)?;
//! ```

#![allow(clippy::missing_docs_in_private_items)]

mod bridge;
mod error;

#[cfg(feature = "x402")]
mod discovery;
#[cfg(feature = "x402")]
mod x402;

#[cfg(feature = "moonpay")]
mod fund;

pub use bridge::{OwxBridge, WalletBridge};
#[cfg(feature = "x402")]
pub use discovery::{DiscoverResult, Service};
pub use error::{PayError, PayErrorCode};
#[cfg(feature = "moonpay")]
pub use fund::{FundResult, TokenBalance};
#[cfg(feature = "x402")]
pub use x402::{PayResult, PaymentInfo};

/// Make an HTTP request with automatic x402 payment handling (blocking).
#[cfg(feature = "x402")]
pub fn pay(
    wallet: &dyn WalletBridge,
    url: &str,
    method: &str,
    body: Option<&str>,
) -> Result<PayResult, PayError> {
    x402::pay(wallet, url, method, body)
}

/// Discover payable services.
#[cfg(feature = "x402")]
pub fn discover(
    query: Option<&str>,
    limit: Option<u64>,
    offset: Option<u64>,
) -> Result<DiscoverResult, PayError> {
    discovery::discover_all(query, limit, offset)
}

/// Fund a wallet via MoonPay.
#[cfg(feature = "moonpay")]
pub fn fund(
    wallet_address: &str,
    chain: Option<&str>,
    token: Option<&str>,
) -> Result<FundResult, PayError> {
    fund::fund_blocking(wallet_address, chain, token)
}

/// Check token balances via MoonPay.
#[cfg(feature = "moonpay")]
pub fn get_balances(
    wallet_address: &str,
    chain: Option<&str>,
) -> Result<Vec<TokenBalance>, PayError> {
    fund::get_balances_blocking(wallet_address, chain)
}
