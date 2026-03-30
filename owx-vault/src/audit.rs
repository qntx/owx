//! Append-only audit log for wallet operations.
//!
//! Every signing, key-creation, or wallet-mutation event is recorded to
//! `<vault>/audit.jsonl` as a newline-delimited JSON stream. The log is
//! append-only and never truncated by the library.

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
    pub action: AuditAction,
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

/// Auditable operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    /// Wallet created.
    WalletCreate,
    /// Wallet imported (mnemonic).
    WalletImport,
    /// Wallet imported (private key).
    WalletImportKey,
    /// Wallet deleted.
    WalletDelete,
    /// Wallet renamed.
    WalletRename,
    /// Wallet exported (mnemonic revealed).
    WalletExport,
    /// Message signed.
    SignMessage,
    /// Transaction signed.
    SignTransaction,
    /// Transaction signed and broadcast.
    SignAndSend,
    /// API key created.
    ApiKeyCreate,
    /// API key revoked.
    ApiKeyRevoke,
    /// Policy created.
    PolicyCreate,
    /// Policy deleted.
    PolicyDelete,
}

/// Append-only audit logger backed by a JSONL file.
#[derive(Debug, Clone)]
pub struct AuditLog {
    /// Path to the audit log file.
    path: PathBuf,
}

impl AuditLog {
    /// Open (or create) an audit log at `<vault_root>/audit.jsonl`.
    #[must_use]
    pub fn new(vault_root: &Path) -> Self {
        Self {
            path: vault_root.join("audit.jsonl"),
        }
    }

    /// Append an entry to the audit log.
    ///
    /// Failures are silently ignored — audit logging must not block
    /// the primary operation. In debug builds, failures are printed
    /// to stderr.
    pub fn log(&self, entry: &AuditEntry) {
        let Ok(json) = serde_json::to_string(entry) else {
            return;
        };
        let result = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .and_then(|mut f| writeln!(f, "{json}"));

        #[cfg(debug_assertions)]
        if let Err(e) = result {
            #[allow(clippy::print_stderr)]
            {
                eprintln!("warning: audit log write failed: {e}");
            }
        }
        #[cfg(not(debug_assertions))]
        let _ = result;
    }

    /// Convenience: log a successful operation.
    pub fn log_ok(&self, action: AuditAction, wallet_id: Option<&str>, chain_id: Option<&str>) {
        self.log(&AuditEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            action,
            wallet_id: wallet_id.map(ToOwned::to_owned),
            api_key_id: None,
            chain_id: chain_id.map(ToOwned::to_owned),
            success: true,
            error: None,
        });
    }

    /// Convenience: log an agent operation.
    pub fn log_agent(
        &self,
        action: AuditAction,
        wallet_id: Option<&str>,
        api_key_id: &str,
        chain_id: Option<&str>,
        success: bool,
        error: Option<&str>,
    ) {
        self.log(&AuditEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            action,
            wallet_id: wallet_id.map(ToOwned::to_owned),
            api_key_id: Some(api_key_id.to_owned()),
            chain_id: chain_id.map(ToOwned::to_owned),
            success,
            error: error.map(ToOwned::to_owned),
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn log_and_read() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path());

        log.log_ok(AuditAction::WalletCreate, Some("w1"), None);
        log.log_ok(AuditAction::SignMessage, Some("w1"), Some("eip155:1"));

        let entries = log.read_all();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].action, AuditAction::WalletCreate);
        assert!(entries[0].success);
        assert_eq!(entries[1].chain_id.as_deref(), Some("eip155:1"));
    }

    #[test]
    fn log_agent_operation() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path());

        log.log_agent(
            AuditAction::SignTransaction,
            Some("w1"),
            "key-1",
            Some("eip155:8453"),
            true,
            None,
        );

        let entries = log.read_all();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].api_key_id.as_deref(), Some("key-1"));
    }

    #[test]
    fn log_failure() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path());

        log.log(&AuditEntry {
            timestamp: "2026-01-01T00:00:00Z".to_owned(),
            action: AuditAction::WalletExport,
            wallet_id: Some("w1".to_owned()),
            api_key_id: None,
            chain_id: None,
            success: false,
            error: Some("invalid passphrase".to_owned()),
        });

        let entries = log.read_all();
        assert_eq!(entries.len(), 1);
        assert!(!entries[0].success);
        assert_eq!(entries[0].error.as_deref(), Some("invalid passphrase"));
    }

    #[test]
    fn empty_log_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path());
        assert!(log.read_all().is_empty());
    }

    #[test]
    fn serde_roundtrip() {
        let entry = AuditEntry {
            timestamp: "2026-01-01T00:00:00Z".to_owned(),
            action: AuditAction::ApiKeyCreate,
            wallet_id: Some("w1".to_owned()),
            api_key_id: Some("k1".to_owned()),
            chain_id: None,
            success: true,
            error: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("api_key_create"));
        assert!(!json.contains("chain_id"));
        assert!(!json.contains("error"));
        let restored: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.action, AuditAction::ApiKeyCreate);
    }
}
