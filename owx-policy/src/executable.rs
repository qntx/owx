//! Executable policy evaluation (subprocess with timeout).

use std::io::Write as _;
use std::process::Command;
use std::time::{Duration, Instant};

use crate::types::{PolicyContext, PolicyResult};

/// Evaluate an executable policy by spawning a subprocess.
///
/// The context (+ optional config) is serialized as JSON to stdin.
/// The executable must write a [`PolicyResult`] JSON to stdout and exit 0.
pub fn evaluate_executable(
    exe: &str,
    config: Option<&serde_json::Value>,
    policy_id: &str,
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
        Err(e) => {
            return PolicyResult::denied(policy_id, format!("failed to serialize context: {e}"));
        }
    };

    let mut child = match Command::new(exe)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return PolicyResult::denied(policy_id, format!("failed to start executable: {e}"));
        }
    };

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(&stdin_bytes);
    }

    let output = match wait_with_timeout(&mut child, Duration::from_secs(5)) {
        Ok(output) => output,
        Err(reason) => return PolicyResult::denied(policy_id, reason),
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return PolicyResult::denied(
            policy_id,
            format!(
                "executable exited with {}: {}",
                output.status,
                stderr.trim()
            ),
        );
    }

    match serde_json::from_slice::<PolicyResult>(&output.stdout) {
        Ok(result) if result.allow => PolicyResult::allowed(),
        Ok(result) => PolicyResult::denied(
            policy_id,
            result
                .reason
                .unwrap_or_else(|| "denied by executable".into()),
        ),
        Err(e) => PolicyResult::denied(policy_id, format!("invalid JSON from executable: {e}")),
    }
}

fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Result<std::process::Output, String> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                if let Some(mut out) = child.stdout.take() {
                    use std::io::Read;
                    let _ = out.read_to_end(&mut stdout);
                }
                if let Some(mut err) = child.stderr.take() {
                    use std::io::Read;
                    let _ = err.read_to_end(&mut stderr);
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
                    return Err(format!("executable timed out after {}s", timeout.as_secs()));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(format!("failed to wait on executable: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TransactionContext;

    fn test_ctx() -> PolicyContext {
        PolicyContext {
            chain_id: "eip155:8453".to_owned(),
            wallet_id: "w1".to_owned(),
            api_key_id: "k1".to_owned(),
            transaction: TransactionContext {
                to: None,
                value: None,
                raw_hex: "0x00".to_owned(),
            },
            timestamp: "2026-01-01T00:00:00Z".to_owned(),
        }
    }

    #[test]
    fn nonexistent_binary_denies() {
        let r = evaluate_executable("/nonexistent/binary", None, "bad-exe", &test_ctx());
        assert!(!r.allow);
        assert!(r.reason.unwrap().contains("failed to start"));
    }
}
