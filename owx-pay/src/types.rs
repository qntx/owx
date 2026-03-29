//! Payment type definitions.

use serde::{Deserialize, Serialize};

/// Result of a payment flow.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PayResult {
    /// HTTP status code of the final response.
    pub status: u16,
    /// Response body.
    pub body: String,
    /// Payment info if a payment was made.
    pub payment: Option<PaymentInfo>,
}

/// Information about a completed payment.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PaymentInfo {
    /// Human-readable amount (e.g. "$0.01").
    pub amount: String,
    /// Chain display name (e.g. "base").
    pub network: String,
    /// Token symbol (e.g. "USDC").
    pub token: String,
}

/// x402 payment requirements from the server's 402 response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PaymentRequirements {
    /// Payment scheme (e.g. "exact").
    pub scheme: String,
    /// CAIP-2 network or human name.
    pub network: String,
    /// Amount in the token's smallest unit.
    pub amount: String,
    /// Token contract address.
    pub asset: String,
    /// Recipient address.
    #[serde(rename = "payTo")]
    pub pay_to: String,
    /// Maximum timeout in seconds.
    #[serde(rename = "maxTimeoutSeconds", default = "default_timeout")]
    pub max_timeout_seconds: u64,
    /// Extra fields (token name, version, etc.).
    #[serde(default)]
    pub extra: serde_json::Value,
    /// Optional description.
    #[serde(default)]
    pub description: Option<String>,
}

/// Default timeout in seconds for payment requirements.
const fn default_timeout() -> u64 {
    30
}

/// x402 server response envelope.
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct X402Response {
    /// Payment options the server accepts.
    pub accepts: Vec<PaymentRequirements>,
    /// Protocol version.
    #[serde(rename = "x402Version")]
    pub x402_version: Option<u32>,
}
