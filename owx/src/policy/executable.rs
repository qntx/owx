//! Executable (subprocess) policy evaluation.

use std::io::Write as _;
use std::process::Command;
use std::time::{Duration, Instant};

use super::types::{PolicyContext, PolicyResult};

/// Run an executable policy subprocess and parse its JSON verdict.
pub(super) fn evaluate_executable(
    exe: &str,
    config: Option<&serde_json::Value>,
    pid: &str,
    ctx: &PolicyContext,
    timeout_seconds: Option<u64>,
) -> PolicyResult {
    if let Err(reason) = validate_executable_path(exe) {
        return PolicyResult::denied(pid, reason);
    }

    let mut payload = match serde_json::to_value(ctx) {
        Ok(v) => v,
        Err(e) => return PolicyResult::denied(pid, format!("serialize context: {e}")),
    };
    if let Some(cfg) = config
        && let Some(map) = payload.as_object_mut()
    {
        map.insert("policy_config".to_owned(), cfg.clone());
    }

    let stdin_bytes = match serde_json::to_vec(&payload) {
        Ok(b) => b,
        Err(e) => return PolicyResult::denied(pid, format!("serialize payload: {e}")),
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

/// Validate an executable policy path.
///
/// Rejects empty paths, path-traversal attempts (`..`), and relative paths.
/// Only absolute paths are allowed to prevent ambient `PATH`-based attacks.
fn validate_executable_path(exe: &str) -> Result<(), String> {
    if exe.is_empty() {
        return Err("empty executable path".into());
    }
    if exe.contains("..") {
        return Err(format!("path traversal rejected: '{exe}'"));
    }
    let p = std::path::Path::new(exe);
    if !p.is_absolute() {
        return Err(format!("executable must be an absolute path, got '{exe}'"));
    }
    Ok(())
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
