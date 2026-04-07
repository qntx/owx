//! Append-only audit log for wallet operations.
//!
//! Every signing, key-creation, or wallet-mutation event is recorded to
//! `<vault>/logs/audit.jsonl` as a newline-delimited JSON stream.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Auditable wallet operations.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOp {
    /// A new wallet was created.
    CreateWallet,
    /// A mnemonic phrase was imported.
    ImportMnemonic,
    /// A single private key was imported.
    ImportPrivateKey,
    /// Dual-curve private keys were imported.
    ImportPrivateKeys,
    /// A wallet was deleted.
    DeleteWallet,
    /// A wallet was renamed.
    RenameWallet,
    /// A wallet secret was exported.
    ExportWallet,
    /// A message was signed.
    SignMessage,
    /// A transaction was signed.
    SignTransaction,
    /// EIP-712 typed data was signed.
    SignTypedData,
    /// A transaction was signed and broadcast.
    SignAndSend,
    /// An API key was created.
    CreateApiKey,
    /// An API key was revoked.
    RevokeApiKey,
}

/// A single audit log entry.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Timestamp of the event.
    pub timestamp: DateTime<Utc>,
    /// The operation that was performed.
    pub operation: AuditOp,
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
pub(crate) struct AuditLog {
    /// Path to the audit log file.
    path: PathBuf,
}

impl AuditLog {
    /// Open (or create) an audit log at `<vault_root>/logs/audit.jsonl`.
    #[must_use]
    pub(crate) fn new(vault_root: &Path) -> Self {
        let log_dir = vault_root.join("logs");
        let _dir = fs::create_dir_all(&log_dir);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _perm = fs::set_permissions(&log_dir, fs::Permissions::from_mode(0o700));
        }
        Self {
            path: log_dir.join("audit.jsonl"),
        }
    }

    /// Append an entry to the audit log.
    ///
    /// Failures are silently ignored — audit logging must not block
    /// the primary operation.
    pub(crate) fn log(&self, entry: &AuditEntry) {
        let Ok(json) = serde_json::to_string(entry) else {
            return;
        };
        let _write = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .and_then(|mut f| writeln!(f, "{json}"));
    }

    /// Convenience: log a successful operation.
    ///
    /// Pass `api_key_id` when the operation is performed via an agent API
    /// token so the audit trail can identify which key was used.
    pub(crate) fn log_ok(
        &self,
        operation: AuditOp,
        wallet_id: Option<&str>,
        chain_id: Option<&str>,
        api_key_id: Option<&str>,
    ) {
        self.log(&AuditEntry {
            timestamp: Utc::now(),
            operation,
            wallet_id: wallet_id.map(ToOwned::to_owned),
            api_key_id: api_key_id.map(ToOwned::to_owned),
            chain_id: chain_id.map(ToOwned::to_owned),
            success: true,
            error: None,
        });
    }

    /// Convenience: log a failed operation.
    pub(crate) fn log_err(
        &self,
        operation: AuditOp,
        wallet_id: Option<&str>,
        chain_id: Option<&str>,
        error_msg: &str,
    ) {
        self.log(&AuditEntry {
            timestamp: Utc::now(),
            operation,
            wallet_id: wallet_id.map(ToOwned::to_owned),
            api_key_id: None,
            chain_id: chain_id.map(ToOwned::to_owned),
            success: false,
            error: Some(error_msg.to_owned()),
        });
    }

    /// Read all audit entries from the log file.
    ///
    /// Returns an empty vec if the file does not exist.
    /// Malformed lines are silently skipped.
    pub(crate) fn read_all(&self) -> Vec<AuditEntry> {
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
#[allow(
    clippy::indexing_slicing,
    reason = "test panics on out-of-bounds are acceptable"
)]
mod tests {
    use super::*;

    fn tmp_log() -> (tempfile::TempDir, AuditLog) {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path());
        (dir, log)
    }

    #[test]
    fn read_all_empty_when_no_file() {
        let (_dir, log) = tmp_log();
        assert!(log.read_all().is_empty());
    }

    #[test]
    fn log_ok_roundtrip() {
        let (_dir, log) = tmp_log();
        log.log_ok(AuditOp::CreateWallet, Some("w1"), None, None);
        let entries = log.read_all();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].operation, AuditOp::CreateWallet);
        assert!(entries[0].success);
        assert_eq!(entries[0].wallet_id.as_deref(), Some("w1"));
        assert!(entries[0].error.is_none());
    }

    #[test]
    fn log_err_roundtrip() {
        let (_dir, log) = tmp_log();
        log.log_err(
            AuditOp::SignMessage,
            Some("w2"),
            Some("eip155:1"),
            "bad key",
        );
        let entries = log.read_all();
        assert_eq!(entries.len(), 1);
        assert!(!entries[0].success);
        assert_eq!(entries[0].error.as_deref(), Some("bad key"));
        assert_eq!(entries[0].chain_id.as_deref(), Some("eip155:1"));
    }

    #[test]
    fn multiple_entries_append() {
        let (_dir, log) = tmp_log();
        log.log_ok(AuditOp::CreateWallet, Some("w1"), None, None);
        log.log_ok(AuditOp::DeleteWallet, Some("w1"), None, None);
        log.log_err(AuditOp::ExportWallet, Some("w1"), None, "denied");
        assert_eq!(log.read_all().len(), 3);
    }

    #[test]
    fn malformed_lines_skipped() {
        let (_dir, log) = tmp_log();
        log.log_ok(AuditOp::CreateWallet, Some("w1"), None, None);
        // Manually append a bad line.
        let mut f = OpenOptions::new().append(true).open(&log.path).unwrap();
        writeln!(f, "{{not valid json").unwrap();
        log.log_ok(AuditOp::RenameWallet, Some("w1"), None, None);
        let entries = log.read_all();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn timestamp_is_utc() {
        let (_dir, log) = tmp_log();
        log.log_ok(AuditOp::CreateApiKey, None, None, Some("key-hash"));
        let entries = log.read_all();
        assert_eq!(entries[0].timestamp.timezone(), Utc);
        assert_eq!(entries[0].api_key_id.as_deref(), Some("key-hash"));
    }
}
