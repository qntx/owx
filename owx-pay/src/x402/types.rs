//! x402 protocol types.

use serde::{Deserialize, Serialize};

/// Result of a payment flow.
#[derive(Debug, Clone, Serialize)]
pub struct PayResult {
    /// HTTP status code of the final response.
    pub status: u16,
    /// Response body.
    pub body: String,
    /// Payment info if a payment was made.
    pub payment: Option<PaymentInfo>,
}

/// Information about a completed payment.
#[derive(Debug, Clone, Serialize)]
pub struct PaymentInfo {
    /// Human-readable amount (e.g. "$0.01").
    pub amount: String,
    /// Chain display name.
    pub network: String,
    /// Token symbol.
    pub token: String,
}

/// Raw x402 protocol response (from 402 headers or body).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct X402Response {
    /// Protocol version (1 or 2).
    #[serde(default)]
    pub x402_version: Option<u32>,
    /// Payment options the server accepts.
    pub accepts: Vec<PaymentRequirements>,
    /// Resource metadata (v2 only).
    #[serde(default)]
    pub resource: Option<serde_json::Value>,
}

/// A single payment option from a 402 response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequirements {
    /// Payment scheme (e.g. "exact").
    pub scheme: String,
    /// CAIP-2 network identifier.
    pub network: String,
    /// Required payment amount in smallest token unit.
    #[serde(alias = "maxAmountRequired")]
    pub amount: String,
    /// Token contract address.
    pub asset: String,
    /// Recipient address.
    #[serde(alias = "payTo")]
    pub pay_to: String,
    /// Maximum seconds the server will wait for payment confirmation.
    #[serde(default = "default_timeout")]
    pub max_timeout_seconds: u64,
    /// Extra metadata (token name, version, decimals, etc.).
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub extra: serde_json::Value,
    /// Optional human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Default payment timeout (30 seconds).
const fn default_timeout() -> u64 {
    30
}
