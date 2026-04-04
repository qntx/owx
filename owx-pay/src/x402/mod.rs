//! x402 payment protocol implementation (blocking).

mod eip3009;
pub mod http;
mod negotiate;
mod types;

pub use types::{PayResult, PaymentInfo};

use crate::bridge::WalletBridge;
use crate::error::PayError;

/// Make an HTTP request with automatic x402 payment handling.
pub fn pay(
    wallet: &dyn WalletBridge,
    url: &str,
    method: &str,
    body: Option<&str>,
) -> Result<PayResult, PayError> {
    let initial = http::send_request(url, method, body, None)?;
    if initial.status().as_u16() != 402 {
        let status = initial.status().as_u16();
        let text = initial.text().unwrap_or_default();
        return Ok(PayResult {
            status,
            body: text,
            payment: None,
        });
    }

    let headers = initial.headers().clone();
    let body_402 = initial.text().unwrap_or_default();
    negotiate::handle_402(wallet, url, method, body, &headers, &body_402)
}
