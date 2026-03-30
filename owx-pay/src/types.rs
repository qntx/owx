//! Payment type definitions.

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
    /// Chain display name (e.g. "base").
    pub network: String,
    /// Token symbol (e.g. "USDC").
    pub token: String,
}

/// x402 payment requirements from the server's 402 response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequirements {
    /// Payment scheme (e.g. "exact").
    pub scheme: String,
    /// CAIP-2 network or human name.
    pub network: String,
    /// Amount in the token's smallest unit.
    #[serde(alias = "maxAmountRequired")]
    pub amount: String,
    /// Token contract address.
    pub asset: String,
    /// Recipient address.
    #[serde(alias = "payTo")]
    pub pay_to: String,
    /// Maximum timeout in seconds.
    #[serde(default = "default_timeout")]
    pub max_timeout_seconds: u64,
    /// Extra fields (token name, version, etc.).
    #[serde(default, skip_serializing_if = "is_json_null")]
    pub extra: serde_json::Value,
    /// Optional description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Optional resource identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}

/// Default timeout in seconds for payment requirements.
const fn default_timeout() -> u64 {
    30
}

/// Check if a JSON value is null.
fn is_json_null(value: &serde_json::Value) -> bool {
    value.is_null()
}

/// x402 server response envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct X402Response {
    /// Payment options the server accepts.
    #[serde(default)]
    pub x402_version: Option<u32>,
    /// Payment options.
    pub accepts: Vec<PaymentRequirements>,
    /// Optional resource metadata.
    #[serde(default)]
    pub resource: Option<serde_json::Value>,
}

/// The signed payment payload sent to the server in the payment header.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PaymentPayload {
    /// x402 v1 payment payload.
    V1(PaymentPayloadV1),
    /// x402 v2 payment payload.
    V2(PaymentPayloadV2),
}

/// x402 v1 payment payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentPayloadV1 {
    /// Protocol version.
    pub x402_version: u32,
    /// Payment scheme.
    pub scheme: String,
    /// Network identifier.
    pub network: String,
    /// Scheme-specific payload.
    pub payload: serde_json::Value,
}

/// x402 v2 payment payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentPayloadV2 {
    /// Protocol version.
    pub x402_version: u32,
    /// The accepted payment requirement.
    pub accepted: PaymentRequirements,
    /// Optional resource metadata.
    pub resource: Option<serde_json::Value>,
    /// Scheme-specific payload.
    pub payload: serde_json::Value,
}

/// EIP-3009 TransferWithAuthorization payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Eip3009Payload {
    /// Hex signature.
    pub signature: String,
    /// Authorization details.
    pub authorization: Eip3009Authorization,
}

/// EIP-3009 authorization fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Eip3009Authorization {
    /// From address.
    pub from: String,
    /// To address.
    pub to: String,
    /// Value in smallest unit.
    pub value: String,
    /// Valid-after timestamp.
    pub valid_after: String,
    /// Valid-before timestamp.
    pub valid_before: String,
    /// Random nonce.
    pub nonce: String,
}

/// A discovered payable service.
#[derive(Debug, Clone, Serialize)]
pub struct Service {
    /// Human-readable name.
    pub name: String,
    /// Full endpoint URL.
    pub url: String,
    /// Short description.
    pub description: String,
    /// Cheapest price display (e.g. "$0.01").
    pub price: String,
    /// Network or chain.
    pub network: String,
}

/// Result of a `discover()` call with pagination.
#[derive(Debug, Clone, Serialize)]
pub struct DiscoverResult {
    /// Discovered services on this page.
    pub services: Vec<Service>,
    /// Total number of services in the directory.
    pub total: u64,
    /// Limit used for this page.
    pub limit: u64,
    /// Offset used for this page.
    pub offset: u64,
}

/// Wire type for a single discovered service from the CDP API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveredService {
    /// Resource URL.
    pub resource: String,
    /// Service type.
    #[serde(default)]
    pub r#type: Option<String>,
    /// x402 version.
    #[serde(default)]
    pub x402_version: Option<u32>,
    /// Payment options.
    #[serde(default)]
    pub accepts: Vec<PaymentRequirements>,
    /// Metadata.
    #[serde(default)]
    pub metadata: Option<ServiceMetadata>,
}

/// Service metadata from discovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceMetadata {
    /// Description.
    pub description: Option<String>,
}

/// Discovery API response envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryResponse {
    /// Discovered items.
    pub items: Vec<DiscoveredService>,
    /// Pagination info.
    #[serde(default)]
    pub pagination: Option<Pagination>,
}

/// Pagination info from discovery API.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Pagination {
    /// Items per page.
    pub limit: u64,
    /// Current offset.
    pub offset: u64,
    /// Total items.
    pub total: u64,
}

/// Result of `fund()` call.
#[derive(Debug, Clone, Serialize)]
pub struct FundResult {
    /// Deposit ID.
    pub deposit_id: String,
    /// Deposit URL for the user.
    pub deposit_url: String,
    /// Available deposit wallets (chain, address).
    pub wallets: Vec<(String, String)>,
    /// User instructions.
    pub instructions: String,
}
