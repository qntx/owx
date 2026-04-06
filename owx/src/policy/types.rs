//! Policy types: rules, context, and evaluation results.

use serde::{Deserialize, Serialize};

/// A declarative policy rule evaluated in-process.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyRule {
    /// Deny if `chain_id` is not in the allowlist.
    AllowedChains {
        /// CAIP-2 chain IDs that are permitted.
        chain_ids: Vec<String>,
    },
    /// Deny if current time is past the timestamp.
    ExpiresAt {
        /// ISO-8601 expiry timestamp.
        timestamp: String,
    },
    /// Deny if the transaction value exceeds a per-transaction cap.
    MaxAmount {
        /// Maximum amount in the token's smallest unit.
        amount: String,
        /// Token contract address or native identifier.
        asset: String,
    },
    /// Deny if cumulative daily spending exceeds the limit.
    DailyLimit {
        /// Maximum daily amount in the token's smallest unit.
        amount: String,
        /// Token contract address or native identifier.
        asset: String,
    },
    /// Deny if the recipient is not in the allowlist.
    AllowedRecipients {
        /// Permitted destination addresses.
        addresses: Vec<String>,
    },
}

/// A stored policy definition.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Unique policy identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Schema version.
    pub version: u32,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
    /// Declarative rules (AND semantics).
    pub rules: Vec<PolicyRule>,
    /// Optional path to an executable policy program.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    /// Opaque configuration passed to the executable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Value>,
    /// Executable timeout in seconds (default: 5).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,
}

/// Transaction fields available for policy evaluation.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionContext {
    /// Destination address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// Native value in smallest unit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Raw transaction hex.
    pub raw_hex: String,
    /// Calldata / input data (EVM).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    /// Asset identifier (contract address or "native").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset: Option<String>,
}

/// Spending context for daily-limit policies.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendingContext {
    /// Cumulative daily spending so far (smallest unit).
    pub daily_total: String,
    /// Date string (YYYY-MM-DD).
    pub date: String,
    /// Asset identifier (must match the rule's asset).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset: Option<String>,
}

/// Context passed to policy evaluation.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyContext {
    /// CAIP-2 chain ID.
    pub chain_id: String,
    /// Wallet identifier.
    pub wallet_id: String,
    /// API key identifier.
    pub api_key_id: String,
    /// Transaction details.
    pub transaction: TransactionContext,
    /// Spending context for daily-limit policies.
    pub spending: SpendingContext,
    /// Current ISO-8601 timestamp.
    pub timestamp: String,
}

/// Result of policy evaluation.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResult {
    /// Whether the request is allowed.
    pub allow: bool,
    /// Reason for denial (if denied).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Which policy produced the denial (if denied).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
}

impl PolicyResult {
    /// Create an "allowed" result.
    #[must_use]
    pub const fn allowed() -> Self {
        Self {
            allow: true,
            reason: None,
            policy_id: None,
        }
    }

    /// Create a "denied" result.
    #[must_use]
    pub fn denied(policy_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            allow: false,
            reason: Some(reason.into()),
            policy_id: Some(policy_id.into()),
        }
    }
}
