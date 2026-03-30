//! Top-level error type for OWX.

use serde::{Serialize, Serializer};

/// Structured error codes for API consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OwxErrorCode {
    /// Vault encryption/decryption failed.
    VaultCrypto,
    /// Invalid KDF parameters (possible downgrade attack).
    VaultInvalidParams,
    /// Wallet not found by name or ID.
    WalletNotFound,
    /// Wallet name already exists.
    WalletNameExists,
    /// Multiple wallets match the given name.
    AmbiguousWallet,
    /// API key not found.
    ApiKeyNotFound,
    /// Policy not found.
    PolicyNotFound,
    /// Invalid input from the caller.
    InvalidInput,
    /// File-system I/O error.
    Io,
    /// JSON serialization/deserialization error.
    Json,
    /// Policy denied the request.
    PolicyDenied,
    /// Executable policy failed.
    PolicyExecutableFailed,
    /// Server did not return 402.
    PaymentNotRequired,
    /// Malformed x402 response.
    PaymentProtocolMalformed,
    /// Unsupported payment chain/scheme.
    PaymentUnsupported,
    /// Payment signing failed.
    PaymentSigningFailed,
    /// HTTP request failed.
    Http,
    /// API key expired.
    ApiKeyExpired,
    /// HD key derivation error.
    Derivation,
    /// Cryptographic signing error.
    Signing,
}

/// Unified error type for `owx` operations.
#[derive(Debug, thiserror::Error)]
pub enum OwxError {
    /// Vault (storage/crypto) error.
    #[error(transparent)]
    Vault(#[from] owx_vault::VaultError),

    /// Policy evaluation error.
    #[error(transparent)]
    Policy(#[from] owx_policy::PolicyError),

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

    /// HD derivation error from kobe.
    #[error("derivation: {0}")]
    Derivation(String),

    /// Signing error from signer.
    #[error("signing: {0}")]
    Signing(String),

    /// JSON error.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

impl OwxError {
    /// Returns the structured error code for this error.
    #[must_use]
    pub const fn code(&self) -> OwxErrorCode {
        match self {
            Self::Vault(inner) => match inner {
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
            Self::Policy(inner) => match inner {
                owx_policy::PolicyError::Denied { .. } => OwxErrorCode::PolicyDenied,
                owx_policy::PolicyError::ExecutableFailed(_) => {
                    OwxErrorCode::PolicyExecutableFailed
                }
                owx_policy::PolicyError::Json(_) => OwxErrorCode::Json,
            },
            Self::Pay(inner) => match inner {
                owx_pay::PayError::NotPaymentRequired(_) => OwxErrorCode::PaymentNotRequired,
                owx_pay::PayError::ProtocolMalformed(_) => OwxErrorCode::PaymentProtocolMalformed,
                owx_pay::PayError::Unsupported(_) => OwxErrorCode::PaymentUnsupported,
                owx_pay::PayError::SigningFailed(_) => OwxErrorCode::PaymentSigningFailed,
                owx_pay::PayError::Http(_) => OwxErrorCode::Http,
                owx_pay::PayError::Json(_) => OwxErrorCode::Json,
                owx_pay::PayError::InvalidInput(_) => OwxErrorCode::InvalidInput,
            },
            Self::PolicyDenied { .. } => OwxErrorCode::PolicyDenied,
            Self::ApiKeyExpired { .. } => OwxErrorCode::ApiKeyExpired,
            Self::InvalidInput(_) => OwxErrorCode::InvalidInput,
            Self::Derivation(_) => OwxErrorCode::Derivation,
            Self::Signing(_) => OwxErrorCode::Signing,
            Self::Json(_) => OwxErrorCode::Json,
        }
    }
}

/// Serialization payload: `{"code": "...", "message": "..."}`.
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn code_mapping_uses_concrete_nested_variants() {
        assert_eq!(
            OwxError::from(owx_vault::VaultError::WalletNotFound("wallet-1".into())).code(),
            OwxErrorCode::WalletNotFound
        );
        assert_eq!(
            OwxError::from(owx_policy::PolicyError::ExecutableFailed("boom".into())).code(),
            OwxErrorCode::PolicyExecutableFailed
        );
        assert_eq!(
            OwxError::from(owx_pay::PayError::NotPaymentRequired(401)).code(),
            OwxErrorCode::PaymentNotRequired
        );
        assert_eq!(
            OwxError::PolicyDenied {
                policy_id: "p1".into(),
                reason: "denied".into(),
            }
            .code(),
            OwxErrorCode::PolicyDenied
        );
    }

    #[test]
    fn json_serialization_shape() {
        let err = OwxError::from(owx_vault::VaultError::AmbiguousWallet {
            name: "agent".into(),
            count: 2,
        });
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "AMBIGUOUS_WALLET");
        assert!(
            json["message"]
                .as_str()
                .unwrap()
                .contains("ambiguous wallet name")
        );
        assert!(json.get("details").is_none());
    }

    #[test]
    fn policy_denied_serialization() {
        let err = OwxError::PolicyDenied {
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
