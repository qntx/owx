//! Unified error type for OWX.

use serde::{Serialize, Serializer};

/// Machine-readable error codes for API consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    /// Vault encryption / decryption failed.
    Crypto,
    /// Invalid KDF parameters.
    InvalidParams,
    /// Wallet not found.
    WalletNotFound,
    /// Wallet name already exists.
    WalletNameExists,
    /// Multiple wallets match the given name.
    AmbiguousWallet,
    /// API key not found.
    ApiKeyNotFound,
    /// Policy not found.
    PolicyNotFound,
    /// Invalid input.
    InvalidInput,
    /// File-system I/O error.
    Io,
    /// JSON serialization error.
    Json,
    /// Policy denied the request.
    PolicyDenied,
    /// API key expired.
    ApiKeyExpired,
    /// HD key derivation error.
    Derivation,
    /// Cryptographic signing error.
    Signing,
    /// Transaction broadcast failed.
    BroadcastFailed,
    /// x402 payment protocol error.
    Pay,
    /// HTTP request error.
    Http,
}

/// Unified error type for all `owx` operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Vault (storage / crypto) error.
    #[error(transparent)]
    Vault(#[from] owx_vault::VaultError),

    /// Wallet not found.
    #[error("wallet not found: {0}")]
    WalletNotFound(String),

    /// Wallet name already exists.
    #[error("wallet name exists: {0}")]
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
    #[error("API key not found: {0}")]
    ApiKeyNotFound(String),

    /// Policy not found.
    #[error("policy not found: {0}")]
    PolicyNotFound(String),

    /// Policy denied the request.
    #[error("denied by policy '{policy_id}': {reason}")]
    PolicyDenied {
        /// Policy that denied.
        policy_id: String,
        /// Human-readable reason.
        reason: String,
    },

    /// API key expired.
    #[error("API key expired: {0}")]
    ApiKeyExpired(String),

    /// Invalid input from the caller.
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// HD derivation error.
    #[error("derivation: {0}")]
    Derivation(String),

    /// Signing error.
    #[error("signing: {0}")]
    Signing(String),

    /// Transaction broadcast failed.
    #[error("broadcast: {0}")]
    BroadcastFailed(String),

    /// x402 payment protocol error.
    #[error("pay: {0}")]
    Pay(String),

    /// HTTP request error.
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON error.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

impl Error {
    /// Returns the machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Vault(v) => match v {
                owx_vault::VaultError::Crypto(_) => ErrorCode::Crypto,
                owx_vault::VaultError::InvalidParams(_) => ErrorCode::InvalidParams,
                owx_vault::VaultError::NotFound(_) => ErrorCode::WalletNotFound,
                owx_vault::VaultError::InvalidInput(_) => ErrorCode::InvalidInput,
                owx_vault::VaultError::Io { .. } => ErrorCode::Io,
                owx_vault::VaultError::Json(_) => ErrorCode::Json,
            },
            Self::WalletNotFound(_) => ErrorCode::WalletNotFound,
            Self::WalletNameExists(_) => ErrorCode::WalletNameExists,
            Self::AmbiguousWallet { .. } => ErrorCode::AmbiguousWallet,
            Self::ApiKeyNotFound(_) => ErrorCode::ApiKeyNotFound,
            Self::PolicyNotFound(_) => ErrorCode::PolicyNotFound,
            Self::PolicyDenied { .. } => ErrorCode::PolicyDenied,
            Self::ApiKeyExpired(_) => ErrorCode::ApiKeyExpired,
            Self::InvalidInput(_) => ErrorCode::InvalidInput,
            Self::Derivation(_) => ErrorCode::Derivation,
            Self::Signing(_) => ErrorCode::Signing,
            Self::BroadcastFailed(_) => ErrorCode::BroadcastFailed,
            Self::Pay(_) => ErrorCode::Pay,
            Self::Http(_) => ErrorCode::Http,
            Self::Json(_) => ErrorCode::Json,
        }
    }
}

/// JSON: `{"code": "...", "message": "..."}`.
#[derive(Serialize)]
struct ErrorPayload {
    /// Machine-readable code.
    code: ErrorCode,
    /// Human-readable message.
    message: String,
}

impl Serialize for Error {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        ErrorPayload {
            code: self.code(),
            message: self.to_string(),
        }
        .serialize(serializer)
    }
}
