//! Top-level error type for OWX.

use serde::{Serialize, Serializer};

/// Structured error codes for API consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OwxErrorCode {
    /// Vault encryption/decryption failed.
    VaultCrypto,
    /// Invalid KDF parameters.
    VaultInvalidParams,
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
    /// JSON error.
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
    /// Payment protocol error.
    Pay,
}

/// Unified error type for `owx` operations.
#[derive(Debug, thiserror::Error)]
pub enum OwxError {
    /// Vault (storage/crypto) error.
    #[error(transparent)]
    Vault(#[from] owx_vault::VaultError),

    /// Payment error.
    #[error(transparent)]
    Pay(#[from] owx_pay::PayError),

    /// Policy denied the request.
    #[error("denied by policy '{policy_id}': {reason}")]
    PolicyDenied {
        /// Policy that denied.
        policy_id: String,
        /// Reason for denial.
        reason: String,
    },

    /// API key expired.
    #[error("API key expired: {id}")]
    ApiKeyExpired {
        /// Key ID.
        id: String,
    },

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
    #[error("broadcast failed: {0}")]
    BroadcastFailed(String),

    /// JSON error.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

impl OwxError {
    /// Returns the structured error code.
    #[must_use]
    pub const fn code(&self) -> OwxErrorCode {
        match self {
            Self::Vault(v) => match v {
                owx_vault::VaultError::Crypto(_) => OwxErrorCode::VaultCrypto,
                owx_vault::VaultError::InvalidParams(_) => OwxErrorCode::VaultInvalidParams,
                owx_vault::VaultError::WalletNotFound(_) => OwxErrorCode::WalletNotFound,
                owx_vault::VaultError::WalletNameExists(_) => OwxErrorCode::WalletNameExists,
                owx_vault::VaultError::AmbiguousWallet { .. } => OwxErrorCode::AmbiguousWallet,
                owx_vault::VaultError::ApiKeyNotFound => OwxErrorCode::ApiKeyNotFound,
                owx_vault::VaultError::PolicyNotFound(_) => OwxErrorCode::PolicyNotFound,
                owx_vault::VaultError::InvalidInput(_) => OwxErrorCode::InvalidInput,
                owx_vault::VaultError::Io { .. } => OwxErrorCode::Io,
                owx_vault::VaultError::Json(_) => OwxErrorCode::Json,
            },
            Self::Pay(_) => OwxErrorCode::Pay,
            Self::PolicyDenied { .. } => OwxErrorCode::PolicyDenied,
            Self::ApiKeyExpired { .. } => OwxErrorCode::ApiKeyExpired,
            Self::InvalidInput(_) => OwxErrorCode::InvalidInput,
            Self::Derivation(_) => OwxErrorCode::Derivation,
            Self::Signing(_) => OwxErrorCode::Signing,
            Self::BroadcastFailed(_) => OwxErrorCode::BroadcastFailed,
            Self::Json(_) => OwxErrorCode::Json,
        }
    }
}

/// JSON: `{"code": "...", "message": "..."}`.
#[derive(Serialize)]
struct ErrorPayload {
    /// Structured error code.
    code: OwxErrorCode,
    /// Human-readable message.
    message: String,
}

impl Serialize for OwxError {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        ErrorPayload {
            code: self.code(),
            message: self.to_string(),
        }
        .serialize(serializer)
    }
}
