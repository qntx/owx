//! Declarative policy evaluation engine.

use owx_core::policy::{Policy, PolicyContext, PolicyResult, PolicyRule};

/// Evaluate all policies against a context (AND semantics).
///
/// Short-circuits on first denial. Returns [`PolicyResult::allowed()`] if every
/// policy passes.
pub fn evaluate(policies: &[Policy], context: &PolicyContext) -> PolicyResult {
    for policy in policies {
        let result = evaluate_one(policy, context);
        if !result.allow {
            return result;
        }
    }
    PolicyResult::allowed()
}

/// Evaluate a single policy against the context.
fn evaluate_one(policy: &Policy, context: &PolicyContext) -> PolicyResult {
    for rule in &policy.rules {
        let result = evaluate_rule(rule, &policy.id, context);
        if !result.allow {
            return result;
        }
    }

    if let Some(ref exe) = policy.executable {
        return crate::executable::evaluate_executable(
            exe,
            policy.config.as_ref(),
            &policy.id,
            context,
        );
    }

    PolicyResult::allowed()
}

/// Evaluate a single rule within a policy.
fn evaluate_rule(rule: &PolicyRule, policy_id: &str, ctx: &PolicyContext) -> PolicyResult {
    match rule {
        PolicyRule::AllowedChains { chain_ids } => {
            if chain_ids.iter().any(|c| c == &ctx.chain_id) {
                PolicyResult::allowed()
            } else {
                PolicyResult::denied(
                    policy_id,
                    format!("chain {} not in allowlist", ctx.chain_id),
                )
            }
        }
        PolicyRule::ExpiresAt { timestamp } => {
            if ctx.timestamp.as_str() > timestamp.as_str() {
                PolicyResult::denied(policy_id, format!("policy expired at {timestamp}"))
            } else {
                PolicyResult::allowed()
            }
        }
        PolicyRule::MaxAmount { amount, asset: _ } => match &ctx.transaction.value {
            Some(value) if value_exceeds(value, amount) => {
                PolicyResult::denied(policy_id, format!("amount {value} exceeds max {amount}"))
            }
            _ => PolicyResult::allowed(),
        },
        PolicyRule::DailyLimit {
            amount: _,
            asset: _,
        } => {
            // Daily limit requires external state (spending tracker). For now, pass-through.
            // The orchestration layer can inject spending totals into the context.
            PolicyResult::allowed()
        }
        PolicyRule::AllowedRecipients { addresses } => match &ctx.transaction.to {
            Some(to) if !addresses.iter().any(|a| a.eq_ignore_ascii_case(to)) => {
                PolicyResult::denied(policy_id, format!("recipient {to} not in allowlist"))
            }
            _ => PolicyResult::allowed(),
        },
    }
}

/// Compare two decimal strings as `u128`. Returns true if `value > max`.
fn value_exceeds(value: &str, max: &str) -> bool {
    let v: u128 = value.parse().unwrap_or(0);
    let m: u128 = max.parse().unwrap_or(u128::MAX);
    v > m
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use owx_core::policy::{PolicyAction, SpendingContext, TransactionContext};

    use super::*;

    fn base_context() -> PolicyContext {
        PolicyContext {
            chain_id: "eip155:8453".to_owned(),
            wallet_id: "w1".to_owned(),
            api_key_id: "k1".to_owned(),
            transaction: TransactionContext {
                to: Some("0xabc".to_owned()),
                value: Some("100000000000000000".to_owned()),
                raw_hex: "0x00".to_owned(),
                data: None,
            },
            spending: SpendingContext {
                daily_total: "0".to_owned(),
                date: "2026-03-22".to_owned(),
            },
            timestamp: "2026-03-22T10:35:22Z".to_owned(),
        }
    }

    fn policy_with_rules(id: &str, rules: Vec<PolicyRule>) -> Policy {
        Policy {
            id: id.to_owned(),
            name: id.to_owned(),
            version: 1,
            created_at: "2026-01-01T00:00:00Z".to_owned(),
            rules,
            executable: None,
            config: None,
            action: PolicyAction::Deny,
        }
    }

    #[test]
    fn allowed_chains_pass() {
        let ctx = base_context();
        let p = policy_with_rules(
            "c",
            vec![PolicyRule::AllowedChains {
                chain_ids: vec!["eip155:8453".into()],
            }],
        );
        assert!(evaluate(&[p], &ctx).allow);
    }

    #[test]
    fn allowed_chains_deny() {
        let ctx = base_context();
        let p = policy_with_rules(
            "c",
            vec![PolicyRule::AllowedChains {
                chain_ids: vec!["eip155:1".into()],
            }],
        );
        let r = evaluate(&[p], &ctx);
        assert!(!r.allow);
        assert!(r.reason.unwrap().contains("not in allowlist"));
    }

    #[test]
    fn expires_at_before() {
        let ctx = base_context();
        let p = policy_with_rules(
            "e",
            vec![PolicyRule::ExpiresAt {
                timestamp: "2027-01-01T00:00:00Z".into(),
            }],
        );
        assert!(evaluate(&[p], &ctx).allow);
    }

    #[test]
    fn expires_at_after() {
        let ctx = base_context();
        let p = policy_with_rules(
            "e",
            vec![PolicyRule::ExpiresAt {
                timestamp: "2025-01-01T00:00:00Z".into(),
            }],
        );
        assert!(!evaluate(&[p], &ctx).allow);
    }

    #[test]
    fn max_amount_pass() {
        let ctx = base_context();
        let p = policy_with_rules(
            "m",
            vec![PolicyRule::MaxAmount {
                amount: "999999999999999999".into(),
                asset: "native".into(),
            }],
        );
        assert!(evaluate(&[p], &ctx).allow);
    }

    #[test]
    fn max_amount_deny() {
        let ctx = base_context();
        let p = policy_with_rules(
            "m",
            vec![PolicyRule::MaxAmount {
                amount: "1000".into(),
                asset: "native".into(),
            }],
        );
        assert!(!evaluate(&[p], &ctx).allow);
    }

    #[test]
    fn allowed_recipients_pass() {
        let ctx = base_context();
        let p = policy_with_rules(
            "r",
            vec![PolicyRule::AllowedRecipients {
                addresses: vec!["0xabc".into()],
            }],
        );
        assert!(evaluate(&[p], &ctx).allow);
    }

    #[test]
    fn allowed_recipients_deny() {
        let ctx = base_context();
        let p = policy_with_rules(
            "r",
            vec![PolicyRule::AllowedRecipients {
                addresses: vec!["0xdef".into()],
            }],
        );
        assert!(!evaluate(&[p], &ctx).allow);
    }

    #[test]
    fn empty_policies_allow() {
        assert!(evaluate(&[], &base_context()).allow);
    }

    #[test]
    fn short_circuits_on_first_deny() {
        let ctx = base_context();
        let policies = vec![
            policy_with_rules(
                "pass",
                vec![PolicyRule::AllowedChains {
                    chain_ids: vec!["eip155:8453".into()],
                }],
            ),
            policy_with_rules(
                "fail",
                vec![PolicyRule::AllowedChains {
                    chain_ids: vec!["eip155:1".into()],
                }],
            ),
        ];
        let r = evaluate(&policies, &ctx);
        assert!(!r.allow);
        assert_eq!(r.policy_id.as_deref(), Some("fail"));
    }
}
