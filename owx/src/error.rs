//! Top-level error type for OWX.

/// Unified error type for `owx` operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
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
