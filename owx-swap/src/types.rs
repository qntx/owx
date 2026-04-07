//! Backend-agnostic swap types.
//!
//! These types form the public API surface of `owx-swap`. Concrete backends
//! (`LiFi`, Uniswap, Jupiter, …) translate to and from these types internally.

use serde::{Deserialize, Serialize};

/// A cross-chain or same-chain swap request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapRequest {
    /// Source chain (CAIP-2 or numeric ID, e.g. `"eip155:42161"` or `"42161"`).
    pub from_chain: String,
    /// Source token contract address (or native identifier).
    pub from_token: String,
    /// Input amount in the token's smallest unit.
    pub from_amount: String,
    /// Sender wallet address.
    pub from_address: String,
    /// Destination chain.
    pub to_chain: String,
    /// Destination token contract address.
    pub to_token: String,
    /// Optional receiver address (defaults to `from_address`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_address: Option<String>,
    /// Slippage tolerance (0.0–1.0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slippage: Option<f64>,
}

/// Token metadata included in a quote.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    /// Contract address (or `"0x0…0"` / native identifier).
    pub address: String,
    /// Human-readable symbol (e.g. `"USDC"`).
    pub symbol: String,
    /// Decimal places.
    pub decimals: u8,
    /// Chain ID.
    pub chain_id: String,
}

/// A single swap quote returned by a backend.
///
/// Quotes are **serializable**: an agent can persist the JSON, analyse it
/// offline, and later pass the `id` back to `execute` without re-querying.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapQuote {
    /// Unique quote identifier (`<backend>:<backend-route-id>`).
    pub id: String,
    /// Backend that produced this quote.
    pub provider: String,
    /// Source token info.
    pub from_token: TokenInfo,
    /// Destination token info.
    pub to_token: TokenInfo,
    /// Input amount (smallest unit).
    pub from_amount: String,
    /// Expected output amount (smallest unit).
    pub to_amount: String,
    /// Minimum guaranteed output amount (smallest unit).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_amount_min: Option<String>,
    /// Output amount in USD.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_amount_usd: Option<String>,
    /// Total gas cost in USD.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gas_cost_usd: Option<String>,
    /// Human-readable route summary (e.g. `"stargate → 1inch"`).
    pub route_summary: String,
    /// Tags assigned by the backend (e.g. `["CHEAPEST", "FASTEST"]`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Estimated execution time in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_seconds: Option<u64>,
    /// Backend-specific opaque payload — passed back verbatim on `execute`.
    pub opaque: serde_json::Value,
}

/// Execution receipt returned after a swap completes (or fails).
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapReceipt {
    /// Transaction hash (or first tx hash for multi-step routes).
    pub tx_hash: String,
    /// Terminal execution status.
    pub status: SwapStatus,
    /// Actual input amount.
    pub from_amount: String,
    /// Actual output amount (if known).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_amount: Option<String>,
}

/// Terminal swap status.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapStatus {
    /// Transaction submitted, awaiting confirmation.
    Pending,
    /// Swap completed successfully.
    Success,
    /// Swap failed.
    Failed {
        /// Human-readable failure reason.
        reason: String,
    },
}

/// Strategy for auto-selecting a quote from multiple candidates.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionStrategy {
    /// Maximize output amount.
    #[default]
    BestOutput,
    /// Minimize gas cost.
    Cheapest,
    /// Minimize estimated execution time.
    Fastest,
}
