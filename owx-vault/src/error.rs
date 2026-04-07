//! Vault-layer error types (crypto + I/O only, no domain knowledge).

use std::path::PathBuf;

/// Errors from vault-level operations (encryption, storage, I/O).
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    /// Encryption or decryption failed.
    #[error("crypto: {0}")]
    Crypto(String),

    /// Invalid KDF parameters (possible downgrade attack).
    #[error("invalid params: {0}")]
    InvalidParams(String),

    /// A stored entry was not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// Invalid input rejected at the storage layer.
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

    /// JSON serialization / deserialization error.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

impl VaultError {
    /// Machine-readable `SCREAMING_SNAKE_CASE` error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Crypto(_) => "CRYPTO",
            Self::InvalidParams(_) => "INVALID_PARAMS",
            Self::NotFound(_) => "NOT_FOUND",
            Self::InvalidInput(_) => "INVALID_INPUT",
            Self::Io { .. } => "IO",
            Self::Json(_) => "JSON",
        }
    }

    /// Create an I/O error with path context.
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}
