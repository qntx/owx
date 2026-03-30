//! Top-level error type for OWX.

use serde::{Serialize, Serializer};

#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OwxErrorCode {
    VaultCrypto,
    VaultInvalidParams,
    WalletNotFound,
    WalletNameExists,
    AmbiguousWallet,
    ApiKeyNotFound,
    PolicyNotFound,
    InvalidInput,
    Io,
    Json,
    PolicyDenied,
    PolicyExecutableFailed,
    PaymentNotRequired,
    PaymentProtocolMalformed,
    PaymentUnsupported,
    PaymentSigningFailed,
    Http,
    ApiKeyExpired,
    Derivation,
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

#[derive(Serialize)]
struct ErrorPayload {
    code: OwxErrorCode,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
}

impl OwxError {
    #[must_use]
    #[allow(missing_docs)]
    pub fn code(&self) -> OwxErrorCode {
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
                owx_pay::PayError::ProtocolMalformed(_) => {
                    OwxErrorCode::PaymentProtocolMalformed
                }
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

    fn details(&self) -> Option<serde_json::Value> {
        match self {
            Self::Vault(inner) => Some(match inner {
                owx_vault::VaultError::Crypto(reason)
                | owx_vault::VaultError::InvalidParams(reason)
                | owx_vault::VaultError::InvalidInput(reason)
                | owx_vault::VaultError::PolicyNotFound(reason) => {
                    serde_json::json!({ "source": "vault", "reason": reason })
                }
                owx_vault::VaultError::WalletNotFound(id)
                | owx_vault::VaultError::WalletNameExists(id) => {
                    serde_json::json!({ "source": "vault", "id": id })
                }
                owx_vault::VaultError::AmbiguousWallet { name, count } => {
                    serde_json::json!({ "source": "vault", "name": name, "count": count })
                }
                owx_vault::VaultError::ApiKeyNotFound => {
                    serde_json::json!({ "source": "vault" })
                }
                owx_vault::VaultError::Io { path, source } => serde_json::json!({
                    "source": "vault",
                    "path": path,
                    "reason": source.to_string(),
                }),
                owx_vault::VaultError::Json(inner) => {
                    serde_json::json!({ "source": "vault", "reason": inner.to_string() })
                }
            }),
            Self::Policy(inner) => Some(match inner {
                owx_policy::PolicyError::Denied { policy_id, reason } => {
                    serde_json::json!({
                        "source": "policy",
                        "policy_id": policy_id,
                        "reason": reason,
                    })
                }
                owx_policy::PolicyError::ExecutableFailed(reason) => {
                    serde_json::json!({ "source": "policy", "reason": reason })
                }
                owx_policy::PolicyError::Json(inner) => {
                    serde_json::json!({ "source": "policy", "reason": inner.to_string() })
                }
            }),
            Self::Pay(inner) => Some(match inner {
                owx_pay::PayError::NotPaymentRequired(status) => {
                    serde_json::json!({ "source": "pay", "status": status })
                }
                owx_pay::PayError::ProtocolMalformed(reason)
                | owx_pay::PayError::Unsupported(reason)
                | owx_pay::PayError::SigningFailed(reason)
                | owx_pay::PayError::InvalidInput(reason) => {
                    serde_json::json!({ "source": "pay", "reason": reason })
                }
                owx_pay::PayError::Http(inner) => {
                    serde_json::json!({ "source": "pay", "reason": inner.to_string() })
                }
                owx_pay::PayError::Json(inner) => {
                    serde_json::json!({ "source": "pay", "reason": inner.to_string() })
                }
            }),
            Self::PolicyDenied { policy_id, reason } => {
                Some(serde_json::json!({ "policy_id": policy_id, "reason": reason }))
            }
            Self::ApiKeyExpired { id } => Some(serde_json::json!({ "id": id })),
            Self::InvalidInput(reason)
            | Self::Derivation(reason)
            | Self::Signing(reason) => Some(serde_json::json!({ "reason": reason })),
            Self::Json(inner) => Some(serde_json::json!({ "reason": inner.to_string() })),
        }
    }
}

impl Serialize for OwxError {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        ErrorPayload {
            code: self.code(),
            message: self.to_string(),
            details: self.details(),
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
    fn json_serialization_exposes_code_message_and_details() {
        let err = OwxError::from(owx_vault::VaultError::AmbiguousWallet {
            name: "agent".into(),
            count: 2,
        });
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "AMBIGUOUS_WALLET");
        assert!(json["message"]
            .as_str()
            .unwrap()
            .contains("ambiguous wallet name"));
        assert_eq!(json["details"]["name"], "agent");
        assert_eq!(json["details"]["count"], 2);
    }

    #[test]
    fn top_level_policy_denied_serialization_preserves_fields() {
        let err = OwxError::PolicyDenied {
            policy_id: "spending-limit".into(),
            reason: "exceeded daily limit".into(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "POLICY_DENIED");
        assert_eq!(json["details"]["policy_id"], "spending-limit");
        assert_eq!(json["details"]["reason"], "exceeded daily limit");
    }
}
