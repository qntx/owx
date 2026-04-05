//! Append-only audit log for wallet operations.
//!
//! Every signing, key-creation, or wallet-mutation event is recorded to
//! `<vault>/logs/audit.jsonl` as a newline-delimited JSON stream.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// A single audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// ISO-8601 timestamp of the event.
    pub timestamp: String,
    /// The operation that was performed.
    pub operation: String,
    /// Wallet ID involved (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_id: Option<String>,
    /// API key ID used (if agent mode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key_id: Option<String>,
    /// CAIP-2 chain ID (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,
    /// Whether the operation succeeded.
    pub success: bool,
    /// Optional error message on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Append-only audit logger backed by a JSONL file.
#[derive(Debug, Clone)]
pub struct AuditLog {
    /// Path to the audit log file.
    path: PathBuf,
}

impl AuditLog {
    /// Open (or create) an audit log at `<vault_root>/logs/audit.jsonl`.
    #[must_use]
    pub fn new(vault_root: &Path) -> Self {
        let log_dir = vault_root.join("logs");
        let _ = fs::create_dir_all(&log_dir);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&log_dir, fs::Permissions::from_mode(0o700));
        }
        Self {
            path: log_dir.join("audit.jsonl"),
        }
    }

    /// Append an entry to the audit log.
    ///
    /// Failures are silently ignored — audit logging must not block
    /// the primary operation.
    pub fn log(&self, entry: &AuditEntry) {
        let Ok(json) = serde_json::to_string(entry) else {
            return;
        };
        let _ = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .and_then(|mut f| writeln!(f, "{json}"));
    }

    /// Convenience: log a successful operation.
    pub fn log_ok(&self, operation: &str, wallet_id: Option<&str>, chain_id: Option<&str>) {
        self.log(&AuditEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            operation: operation.to_owned(),
            wallet_id: wallet_id.map(ToOwned::to_owned),
            api_key_id: None,
            chain_id: chain_id.map(ToOwned::to_owned),
            success: true,
            error: None,
        });
    }

    /// Read all audit entries from the log file.
    ///
    /// Returns an empty vec if the file does not exist.
    /// Malformed lines are silently skipped.
    pub fn read_all(&self) -> Vec<AuditEntry> {
        let Ok(contents) = fs::read_to_string(&self.path) else {
            return Vec::new();
        };
        contents
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }
}
