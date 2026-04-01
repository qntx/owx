//! Core error types with structured JSON serialization.

use serde::{Serialize, Serializer};

/// Structured error codes for API consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoreErrorCode {
    /// Wallet not found by name or ID.
    WalletNotFound,
    /// Chain not supported.
    ChainNotSupported,
    /// Invalid passphrase.
    InvalidPassphrase,
    /// Invalid input from the caller.
    InvalidInput,
    /// CAIP-2 parse error.
    CaipParseError,
    /// Policy denied the request.
    PolicyDenied,
    /// API key not found.
    ApiKeyNotFound,
    /// API key expired.
    ApiKeyExpired,
}

/// Unified error type for OWX operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum CoreError {
    /// Wallet not found by name or ID.
    #[error("wallet not found: {id}")]
    WalletNotFound {
        /// The wallet name or ID that was not found.
        id: String,
    },

    /// Chain not supported.
    #[error("chain not supported: {chain}")]
    ChainNotSupported {
        /// The chain identifier.
        chain: String,
    },

    /// Invalid passphrase.
    #[error("invalid passphrase")]
    InvalidPassphrase,

    /// Invalid input from the caller.
    #[error("invalid input: {message}")]
    InvalidInput {
        /// Description of the invalid input.
        message: String,
    },

    /// CAIP-2 parse error.
    #[error("CAIP parse error: {message}")]
    CaipParseError {
        /// Description of the parse error.
        message: String,
    },

    /// Policy denied the request.
    #[error("denied by policy '{policy_id}': {reason}")]
    PolicyDenied {
        /// Which policy produced the denial.
        policy_id: String,
        /// Human-readable reason.
        reason: String,
    },

    /// API key not found.
    #[error("API key not found")]
    ApiKeyNotFound,

    /// API key expired.
    #[error("API key expired: {id}")]
    ApiKeyExpired {
        /// The expired key ID.
        id: String,
    },
}

impl CoreError {
    /// Returns the structured error code for this error.
    #[must_use]
    pub const fn code(&self) -> CoreErrorCode {
        match self {
            Self::WalletNotFound { .. } => CoreErrorCode::WalletNotFound,
            Self::ChainNotSupported { .. } => CoreErrorCode::ChainNotSupported,
            Self::InvalidPassphrase => CoreErrorCode::InvalidPassphrase,
            Self::InvalidInput { .. } => CoreErrorCode::InvalidInput,
            Self::CaipParseError { .. } => CoreErrorCode::CaipParseError,
            Self::PolicyDenied { .. } => CoreErrorCode::PolicyDenied,
            Self::ApiKeyNotFound => CoreErrorCode::ApiKeyNotFound,
            Self::ApiKeyExpired { .. } => CoreErrorCode::ApiKeyExpired,
        }
    }
}

/// Serialization payload: `{"code": "...", "message": "..."}`.
#[derive(Serialize)]
struct ErrorPayload {
    /// Structured error code.
    code: CoreErrorCode,
    /// Human-readable message.
    message: String,
}

impl Serialize for CoreError {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let payload = ErrorPayload {
            code: self.code(),
            message: self.to_string(),
        };
        payload.serialize(serializer)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn code_mapping() {
        assert_eq!(
            CoreError::WalletNotFound { id: "x".into() }.code(),
            CoreErrorCode::WalletNotFound
        );
        assert_eq!(
            CoreError::ChainNotSupported { chain: "x".into() }.code(),
            CoreErrorCode::ChainNotSupported
        );
        assert_eq!(
            CoreError::InvalidPassphrase.code(),
            CoreErrorCode::InvalidPassphrase
        );
        assert_eq!(
            CoreError::InvalidInput {
                message: "x".into()
            }
            .code(),
            CoreErrorCode::InvalidInput
        );
        assert_eq!(
            CoreError::CaipParseError {
                message: "x".into()
            }
            .code(),
            CoreErrorCode::CaipParseError
        );
        assert_eq!(
            CoreError::PolicyDenied {
                policy_id: "x".into(),
                reason: "x".into()
            }
            .code(),
            CoreErrorCode::PolicyDenied
        );
        assert_eq!(
            CoreError::ApiKeyNotFound.code(),
            CoreErrorCode::ApiKeyNotFound
        );
        assert_eq!(
            CoreError::ApiKeyExpired { id: "x".into() }.code(),
            CoreErrorCode::ApiKeyExpired
        );
    }

    #[test]
    fn display_output() {
        let err = CoreError::WalletNotFound {
            id: "abc-123".into(),
        };
        assert_eq!(err.to_string(), "wallet not found: abc-123");
    }

    #[test]
    fn json_serialization_shape() {
        let err = CoreError::WalletNotFound {
            id: "abc-123".into(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "WALLET_NOT_FOUND");
        assert_eq!(json["message"], "wallet not found: abc-123");
    }

    #[test]
    fn policy_denied_serialization() {
        let err = CoreError::PolicyDenied {
            policy_id: "spending-limit".into(),
            reason: "exceeded daily limit".into(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "POLICY_DENIED");
        assert!(
            json["message"]
                .as_str()
                .unwrap()
                .contains("exceeded daily limit")
        );
    }
}
