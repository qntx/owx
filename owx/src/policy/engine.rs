//! Declarative policy evaluation engine.

use super::executable::evaluate_executable;
use super::types::{Policy, PolicyContext, PolicyResult, PolicyRule};

/// Evaluate all policies against a context (AND semantics — first denial wins).
#[must_use]
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
            let Ok(expires) = chrono::DateTime::parse_from_rfc3339(timestamp) else {
                return PolicyResult::denied(pid, format!("invalid expires_at: '{timestamp}'"));
            };
            let Ok(now) = chrono::DateTime::parse_from_rfc3339(&ctx.timestamp) else {
                return PolicyResult::denied(
                    pid,
                    format!("invalid context timestamp: '{}'", ctx.timestamp),
                );
            };
            if now >= expires {
                PolicyResult::denied(pid, format!("policy expired at {timestamp}"))
            } else {
                PolicyResult::allowed()
            }
        }
        PolicyRule::MaxAmount { amount, asset } => {
            if !asset_matches(asset, ctx.transaction.asset.as_deref()) {
                return PolicyResult::allowed();
            }
            ctx.transaction.value.as_ref().map_or_else(
                PolicyResult::allowed,
                |value| match exceeds(value, amount) {
                    Ok(true) => {
                        PolicyResult::denied(pid, format!("amount {value} exceeds max {amount}"))
                    }
                    Err(reason) => PolicyResult::denied(pid, reason),
                    _ => PolicyResult::allowed(),
                },
            )
        }
        PolicyRule::DailyLimit { amount, asset } => {
            if !asset_matches(asset, ctx.spending.asset.as_deref()) {
                return PolicyResult::allowed();
            }
            let total = &ctx.spending.daily_total;
            match exceeds(total, amount) {
                Ok(true) => PolicyResult::denied(
                    pid,
                    format!("daily spending {total} exceeds limit {amount}"),
                ),
                Err(reason) => PolicyResult::denied(pid, reason),
                _ => PolicyResult::allowed(),
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

/// Check if a rule's asset matches the context asset.
///
/// Rules: if context has no asset, the rule always applies (conservative).
/// If both present, compare case-insensitively.
#[allow(clippy::missing_const_for_fn)]
fn asset_matches(rule_asset: &str, ctx_asset: Option<&str>) -> bool {
    ctx_asset.is_none_or(|a| a.eq_ignore_ascii_case(rule_asset))
}

/// Compare two decimal-string amounts (returns true if value > max).
///
/// Returns `Err` if either string is not a valid u128, ensuring malformed
/// amounts are never silently allowed.
fn exceeds(value: &str, max: &str) -> Result<bool, String> {
    let v: u128 = value
        .parse()
        .map_err(|_| format!("unparseable amount value: '{value}'"))?;
    let m: u128 = max
        .parse()
        .map_err(|_| format!("unparseable amount limit: '{max}'"))?;
    Ok(v > m)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::policy::{SpendingContext, TransactionContext};

    fn test_policy(id: &str, rules: Vec<PolicyRule>) -> Policy {
        Policy {
            id: id.to_owned(),
            name: id.to_owned(),
            version: 1,
            created_at: "2026-01-01T00:00:00Z".to_owned(),
            rules,
            executable: None,
            config: None,
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
                asset: Some("native".to_owned()),
            },
            spending: SpendingContext {
                daily_total: "50000".to_owned(),
                date: "2026-01-01".to_owned(),
                asset: Some("native".to_owned()),
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
