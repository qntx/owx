//! Policy evaluation engine (declarative rules + executable subprocess).

use std::io::Write as _;
use std::process::Command;
use std::time::{Duration, Instant};

use owx_core::policy::{Policy, PolicyContext, PolicyResult, PolicyRule};

/// Evaluate all policies against a context (AND semantics).
pub fn evaluate(policies: &[Policy], context: &PolicyContext) -> PolicyResult {
    for policy in policies {
        let result = evaluate_one(policy, context);
        if !result.allow {
            return result;
        }
    }
    PolicyResult::allowed()
}

/// Evaluate a single policy: declarative rules first, then executable.
fn evaluate_one(policy: &Policy, context: &PolicyContext) -> PolicyResult {
    for rule in &policy.rules {
        let result = evaluate_rule(rule, &policy.id, context);
        if !result.allow {
            return result;
        }
    }
    if let Some(ref exe) = policy.executable {
        return evaluate_executable(exe, policy.config.as_ref(), &policy.id, context);
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
                PolicyResult::denied(pid, format!("daily spending {total} exceeds limit {amount}"))
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

    let output = match wait_timeout(&mut child, Duration::from_secs(5)) {
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
                return Ok(std::process::Output { status, stdout, stderr });
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use owx_core::policy::{PolicyAction, SpendingContext, TransactionContext};

    use super::*;

    fn ctx() -> PolicyContext {
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

    fn pol(id: &str, rules: Vec<PolicyRule>) -> Policy {
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
        let p = pol("c", vec![PolicyRule::AllowedChains { chain_ids: vec!["eip155:8453".into()] }]);
        assert!(evaluate(&[p], &ctx()).allow);
    }

    #[test]
    fn allowed_chains_deny() {
        let p = pol("c", vec![PolicyRule::AllowedChains { chain_ids: vec!["eip155:1".into()] }]);
        assert!(!evaluate(&[p], &ctx()).allow);
    }

    #[test]
    fn empty_policies_allow() {
        assert!(evaluate(&[], &ctx()).allow);
    }

    #[test]
    fn short_circuits() {
        let policies = vec![
            pol("pass", vec![PolicyRule::AllowedChains { chain_ids: vec!["eip155:8453".into()] }]),
            pol("fail", vec![PolicyRule::AllowedChains { chain_ids: vec!["eip155:1".into()] }]),
        ];
        let r = evaluate(&policies, &ctx());
        assert!(!r.allow);
        assert_eq!(r.policy_id.as_deref(), Some("fail"));
    }

    #[test]
    fn allowed_recipients_deny() {
        let p = pol("r", vec![PolicyRule::AllowedRecipients { addresses: vec!["0xdef".into()] }]);
        assert!(!evaluate(&[p], &ctx()).allow);
    }
}
