//! Vault error types.

use std::path::PathBuf;

/// Errors that can occur in vault operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VaultError {
    /// Encryption or decryption failed.
    #[error("crypto: {0}")]
    Crypto(String),

    /// Invalid KDF parameters (possible downgrade attack).
    #[error("invalid params: {0}")]
    InvalidParams(String),

    /// Wallet not found by name or ID.
    #[error("wallet not found: {0}")]
    WalletNotFound(String),

    /// Wallet name already exists.
    #[error("wallet name already exists: {0}")]
    WalletNameExists(String),

    /// Multiple wallets share the same name.
    #[error("ambiguous wallet name '{name}': {count} matches")]
    AmbiguousWallet {
        /// The ambiguous name.
        name: String,
        /// Number of matches.
        count: usize,
    },

    /// API key not found.
    #[error("API key not found")]
    ApiKeyNotFound,

    /// Policy not found.
    #[error("policy not found: {0}")]
    PolicyNotFound(String),

    /// Invalid input from the caller.
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// File-system I/O error.
    #[error("I/O error on {path}: {source}")]
    Io {
        /// The file path involved.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// JSON serialization/deserialization error.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

impl VaultError {
    /// Create an I/O error with path context.
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}
