//! Policy type definitions for agent access control.

use serde::{Deserialize, Serialize};

/// Action taken when a policy rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    /// Deny the request.
    Deny,
}

/// A declarative policy rule evaluated in-process.
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
    /// Optional path to a custom executable policy program.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    /// Opaque configuration passed to the executable (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Value>,
    /// Action to take on rule match.
    pub action: PolicyAction,
}

/// Transaction fields available for policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionContext {
    /// Destination address (if applicable).
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
}

/// Spending context for daily-limit policies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendingContext {
    /// Cumulative daily spending so far (smallest unit).
    pub daily_total: String,
    /// Date string (YYYY-MM-DD).
    pub date: String,
}

/// Context passed to policy evaluation.
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn policy_rule_serde_allowed_chains() {
        let rule = PolicyRule::AllowedChains {
            chain_ids: vec!["eip155:8453".into()],
        };
        let json = serde_json::to_value(&rule).unwrap();
        assert_eq!(json["type"], "allowed_chains");
        let restored: PolicyRule = serde_json::from_value(json).unwrap();
        assert_eq!(restored, rule);
    }

    #[test]
    fn policy_serde_roundtrip() {
        let policy = Policy {
            id: "test".into(),
            name: "Test".into(),
            version: 1,
            created_at: "2026-01-01T00:00:00Z".into(),
            rules: vec![PolicyRule::AllowedChains {
                chain_ids: vec!["eip155:8453".into()],
            }],
            executable: None,
            config: None,
            action: PolicyAction::Deny,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let restored: Policy = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.id, "test");
        assert_eq!(restored.rules.len(), 1);
    }

    #[test]
    fn policy_result_allowed() {
        let r = PolicyResult::allowed();
        assert!(r.allow);
        assert!(r.reason.is_none());
    }

    #[test]
    fn policy_result_denied() {
        let r = PolicyResult::denied("p1", "chain not allowed");
        assert!(!r.allow);
        assert_eq!(r.policy_id.as_deref(), Some("p1"));
    }
}
