//! Policy types and declarative + executable evaluation engine.

use std::io::Write as _;
use std::process::Command;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::Error;

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
    /// Optional path to an executable policy program.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    /// Opaque configuration passed to the executable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Value>,
    /// Action to take on rule match.
    pub action: PolicyAction,
    /// Executable timeout in seconds (default: 5).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,
}

/// Transaction fields available for policy evaluation.
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

/// Evaluate all policies against a context (AND semantics — first denial wins).
pub fn evaluate(policies: &[Policy], context: &PolicyContext) -> PolicyResult {
    for policy in policies {
        let result = evaluate_one(policy, context);
        if !result.allow {
            return result;
        }
    }
    PolicyResult::allowed()
}

/// Evaluate a single policy: declarative rules first, then optional executable.
fn evaluate_one(policy: &Policy, context: &PolicyContext) -> PolicyResult {
    for rule in &policy.rules {
        let result = evaluate_rule(rule, &policy.id, context);
        if !result.allow {
            return result;
        }
    }
    if let Some(ref exe) = policy.executable {
        return evaluate_executable(
            exe,
            policy.config.as_ref(),
            &policy.id,
            context,
            policy.timeout_seconds,
        );
    }
    PolicyResult::allowed()
}

/// Evaluate one declarative rule.
fn evaluate_rule(rule: &PolicyRule, pid: &str, ctx: &PolicyContext) -> PolicyResult {
    match rule {
        PolicyRule::AllowedChains { chain_ids } => {
            if chain_ids.iter().any(|c| c == &ctx.chain_id) {
                PolicyResult::allowed()
            } else {
                PolicyResult::denied(pid, format!("chain {} not in allowlist", ctx.chain_id))
            }
        }
        PolicyRule::ExpiresAt { timestamp } => {
            if ctx.timestamp.as_str() > timestamp.as_str() {
                PolicyResult::denied(pid, format!("policy expired at {timestamp}"))
            } else {
                PolicyResult::allowed()
            }
        }
        PolicyRule::MaxAmount { amount, .. } => match &ctx.transaction.value {
            Some(value) if exceeds(value, amount) => {
                PolicyResult::denied(pid, format!("amount {value} exceeds max {amount}"))
            }
            _ => PolicyResult::allowed(),
        },
        PolicyRule::DailyLimit { amount, .. } => {
            let total = &ctx.spending.daily_total;
            if exceeds(total, amount) {
                PolicyResult::denied(
                    pid,
                    format!("daily spending {total} exceeds limit {amount}"),
                )
            } else {
                PolicyResult::allowed()
            }
        }
        PolicyRule::AllowedRecipients { addresses } => match &ctx.transaction.to {
            Some(to) if !addresses.iter().any(|a| a.eq_ignore_ascii_case(to)) => {
                PolicyResult::denied(pid, format!("recipient {to} not in allowlist"))
            }
            _ => PolicyResult::allowed(),
        },
    }
}

/// Compare two decimal-string amounts (returns true if value > max).
fn exceeds(value: &str, max: &str) -> bool {
    let v: u128 = value.parse().unwrap_or(0);
    let m: u128 = max.parse().unwrap_or(u128::MAX);
    v > m
}

/// Run an executable policy subprocess and parse its JSON verdict.
fn evaluate_executable(
    exe: &str,
    config: Option<&serde_json::Value>,
    pid: &str,
    ctx: &PolicyContext,
    timeout_seconds: Option<u64>,
) -> PolicyResult {
    let mut payload = serde_json::to_value(ctx).unwrap_or_default();
    if let Some(cfg) = config
        && let Some(map) = payload.as_object_mut()
    {
        map.insert("policy_config".to_owned(), cfg.clone());
    }

    let stdin_bytes = match serde_json::to_vec(&payload) {
        Ok(b) => b,
        Err(e) => return PolicyResult::denied(pid, format!("serialize context: {e}")),
    };

    let mut child = match Command::new(exe)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return PolicyResult::denied(pid, format!("failed to start: {e}")),
    };

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(&stdin_bytes);
    }

    let timeout = Duration::from_secs(timeout_seconds.unwrap_or(5));
    let output = match wait_timeout(&mut child, timeout) {
        Ok(o) => o,
        Err(reason) => return PolicyResult::denied(pid, reason),
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return PolicyResult::denied(pid, format!("exited {}: {}", output.status, stderr.trim()));
    }

    match serde_json::from_slice::<PolicyResult>(&output.stdout) {
        Ok(r) if r.allow => PolicyResult::allowed(),
        Ok(r) => PolicyResult::denied(pid, r.reason.unwrap_or_else(|| "denied".into())),
        Err(e) => PolicyResult::denied(pid, format!("invalid JSON: {e}")),
    }
}

/// Wait for a child process with a timeout, killing it if exceeded.
fn wait_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Result<std::process::Output, String> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                if let Some(mut o) = child.stdout.take() {
                    use std::io::Read;
                    let _ = o.read_to_end(&mut stdout);
                }
                if let Some(mut e) = child.stderr.take() {
                    use std::io::Read;
                    let _ = e.read_to_end(&mut stderr);
                }
                let status = child.wait().map_err(|e| e.to_string())?;
                return Ok(std::process::Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("timed out after {}s", timeout.as_secs()));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(format!("wait failed: {e}")),
        }
    }
}

/// Load a policy from the vault store, returning a domain error on miss.
pub fn load_policy(store: &owx_vault::Store, id: &str) -> Result<Policy, Error> {
    store
        .load::<Policy>("policies", id)
        .map_err(|_| Error::PolicyNotFound(id.to_owned()))
}

/// List all policies sorted alphabetically by name.
pub fn list_policies(store: &owx_vault::Store) -> Result<Vec<Policy>, Error> {
    let mut policies: Vec<Policy> = store.list("policies")?;
    policies.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(policies)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn test_policy(id: &str, rules: Vec<PolicyRule>) -> Policy {
        Policy {
            id: id.to_owned(),
            name: id.to_owned(),
            version: 1,
            created_at: "2026-01-01T00:00:00Z".to_owned(),
            rules,
            executable: None,
            config: None,
            action: PolicyAction::Deny,
            timeout_seconds: None,
        }
    }

    fn test_ctx() -> PolicyContext {
        PolicyContext {
            chain_id: "eip155:8453".to_owned(),
            wallet_id: "w1".to_owned(),
            api_key_id: "k1".to_owned(),
            transaction: TransactionContext {
                to: Some("0xRecipient".to_owned()),
                value: Some("100000".to_owned()),
                raw_hex: "0xdead".to_owned(),
                data: None,
            },
            spending: SpendingContext {
                daily_total: "50000".to_owned(),
                date: "2026-01-01".to_owned(),
            },
            timestamp: "2026-01-01T12:00:00Z".to_owned(),
        }
    }

    #[test]
    fn allowed_chains_pass() {
        let p = test_policy(
            "p1",
            vec![PolicyRule::AllowedChains {
                chain_ids: vec!["eip155:8453".into()],
            }],
        );
        assert!(evaluate(&[p], &test_ctx()).allow);
    }

    #[test]
    fn allowed_chains_deny() {
        let p = test_policy(
            "p1",
            vec![PolicyRule::AllowedChains {
                chain_ids: vec!["eip155:1".into()],
            }],
        );
        let r = evaluate(&[p], &test_ctx());
        assert!(!r.allow);
        assert!(r.reason.unwrap().contains("not in allowlist"));
    }

    #[test]
    fn expires_at_pass() {
        let p = test_policy(
            "p1",
            vec![PolicyRule::ExpiresAt {
                timestamp: "2027-01-01T00:00:00Z".to_owned(),
            }],
        );
        assert!(evaluate(&[p], &test_ctx()).allow);
    }

    #[test]
    fn expires_at_deny() {
        let p = test_policy(
            "p1",
            vec![PolicyRule::ExpiresAt {
                timestamp: "2025-01-01T00:00:00Z".to_owned(),
            }],
        );
        assert!(!evaluate(&[p], &test_ctx()).allow);
    }

    #[test]
    fn max_amount_pass() {
        let p = test_policy(
            "p1",
            vec![PolicyRule::MaxAmount {
                amount: "200000".to_owned(),
                asset: "native".to_owned(),
            }],
        );
        assert!(evaluate(&[p], &test_ctx()).allow);
    }

    #[test]
    fn max_amount_deny() {
        let p = test_policy(
            "p1",
            vec![PolicyRule::MaxAmount {
                amount: "50000".to_owned(),
                asset: "native".to_owned(),
            }],
        );
        assert!(!evaluate(&[p], &test_ctx()).allow);
    }

    #[test]
    fn daily_limit_pass() {
        let p = test_policy(
            "p1",
            vec![PolicyRule::DailyLimit {
                amount: "100000".to_owned(),
                asset: "native".to_owned(),
            }],
        );
        assert!(evaluate(&[p], &test_ctx()).allow);
    }

    #[test]
    fn daily_limit_deny() {
        let p = test_policy(
            "p1",
            vec![PolicyRule::DailyLimit {
                amount: "10000".to_owned(),
                asset: "native".to_owned(),
            }],
        );
        assert!(!evaluate(&[p], &test_ctx()).allow);
    }

    #[test]
    fn allowed_recipients_pass() {
        let p = test_policy(
            "p1",
            vec![PolicyRule::AllowedRecipients {
                addresses: vec!["0xRecipient".into()],
            }],
        );
        assert!(evaluate(&[p], &test_ctx()).allow);
    }

    #[test]
    fn allowed_recipients_deny() {
        let p = test_policy(
            "p1",
            vec![PolicyRule::AllowedRecipients {
                addresses: vec!["0xOther".into()],
            }],
        );
        assert!(!evaluate(&[p], &test_ctx()).allow);
    }

    #[test]
    fn and_semantics_short_circuits() {
        let policies = vec![
            test_policy(
                "pass",
                vec![PolicyRule::AllowedChains {
                    chain_ids: vec!["eip155:8453".into()],
                }],
            ),
            test_policy(
                "fail",
                vec![PolicyRule::AllowedChains {
                    chain_ids: vec!["eip155:1".into()],
                }],
            ),
        ];
        let r = evaluate(&policies, &test_ctx());
        assert!(!r.allow);
        assert_eq!(r.policy_id.unwrap(), "fail");
    }

    #[test]
    fn empty_policies_allow() {
        assert!(evaluate(&[], &test_ctx()).allow);
    }

    #[test]
    fn recipients_case_insensitive() {
        let p = test_policy(
            "p1",
            vec![PolicyRule::AllowedRecipients {
                addresses: vec!["0xrecipient".into()],
            }],
        );
        assert!(evaluate(&[p], &test_ctx()).allow);
    }
}
