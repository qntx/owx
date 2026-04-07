//! Unified error type for OWX.

use serde::{Serialize, Serializer, ser::SerializeStruct};

/// Unified error type for all `owx` operations.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum OwxError {
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

    /// Unknown or unresolvable chain.
    #[error("unknown chain: {0}")]
    UnknownChain(String),

    /// No RPC URL configured for the given chain.
    #[error("no RPC URL for chain '{0}'")]
    NoRpcUrl(String),

    /// API key does not have access to the requested resource.
    #[error("access denied: {0}")]
    AccessDenied(String),

    /// Home directory cannot be determined.
    #[error("cannot determine home directory (HOME / USERPROFILE not set)")]
    HomeNotFound,

    /// HD derivation error.
    #[error("derivation: {0}")]
    Derivation(String),

    /// Signing error.
    #[error("signing: {0}")]
    Signing(String),

    /// Transaction broadcast failed.
    #[error("broadcast: {0}")]
    BroadcastFailed(String),

    /// JSON error.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

impl From<kobe::Error> for OwxError {
    fn from(e: kobe::Error) -> Self {
        Self::Derivation(e.to_string())
    }
}

impl OwxError {
    /// Machine-readable `SCREAMING_SNAKE_CASE` error code for API consumers.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Vault(v) => v.code(),
            Self::WalletNotFound(_) => "WALLET_NOT_FOUND",
            Self::WalletNameExists(_) => "WALLET_NAME_EXISTS",
            Self::AmbiguousWallet { .. } => "AMBIGUOUS_WALLET",
            Self::ApiKeyNotFound(_) => "API_KEY_NOT_FOUND",
            Self::PolicyNotFound(_) => "POLICY_NOT_FOUND",
            Self::PolicyDenied { .. } => "POLICY_DENIED",
            Self::ApiKeyExpired(_) => "API_KEY_EXPIRED",
            Self::InvalidInput(_) => "INVALID_INPUT",
            Self::UnknownChain(_) => "UNKNOWN_CHAIN",
            Self::NoRpcUrl(_) => "NO_RPC_URL",
            Self::AccessDenied(_) => "ACCESS_DENIED",
            Self::HomeNotFound => "HOME_NOT_FOUND",
            Self::Derivation(_) => "DERIVATION",
            Self::Signing(_) => "SIGNING",
            Self::BroadcastFailed(_) => "BROADCAST_FAILED",
            Self::Json(_) => "JSON",
        }
    }
}

/// Serializes as `{"code": "SCREAMING_SNAKE_CASE", "message": "..."}`.
impl Serialize for OwxError {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut s = serializer.serialize_struct("OwxError", 2)?;
        s.serialize_field("code", self.code())?;
        s.serialize_field("message", &self.to_string())?;
        s.end()
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    reason = "test panics on out-of-bounds are acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn code_returns_screaming_snake_case() {
        let cases: Vec<(OwxError, &str)> = vec![
            (OwxError::WalletNotFound("w1".into()), "WALLET_NOT_FOUND"),
            (
                OwxError::WalletNameExists("w1".into()),
                "WALLET_NAME_EXISTS",
            ),
            (
                OwxError::AmbiguousWallet {
                    name: "w".into(),
                    count: 2,
                },
                "AMBIGUOUS_WALLET",
            ),
            (OwxError::ApiKeyNotFound("k1".into()), "API_KEY_NOT_FOUND"),
            (OwxError::PolicyNotFound("p1".into()), "POLICY_NOT_FOUND"),
            (
                OwxError::PolicyDenied {
                    policy_id: "p".into(),
                    reason: "r".into(),
                },
                "POLICY_DENIED",
            ),
            (OwxError::ApiKeyExpired("k1".into()), "API_KEY_EXPIRED"),
            (OwxError::InvalidInput("bad".into()), "INVALID_INPUT"),
            (OwxError::UnknownChain("x".into()), "UNKNOWN_CHAIN"),
            (OwxError::NoRpcUrl("eip155:1".into()), "NO_RPC_URL"),
            (OwxError::AccessDenied("no".into()), "ACCESS_DENIED"),
            (OwxError::HomeNotFound, "HOME_NOT_FOUND"),
            (OwxError::Derivation("err".into()), "DERIVATION"),
            (OwxError::Signing("err".into()), "SIGNING"),
            (OwxError::BroadcastFailed("err".into()), "BROADCAST_FAILED"),
        ];
        for (err, expected) in &cases {
            assert_eq!(err.code(), *expected, "failed for {err:?}");
        }
    }

    #[test]
    fn serialize_produces_code_and_message() {
        let err = OwxError::WalletNotFound("my-wallet".into());
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "WALLET_NOT_FOUND");
        assert_eq!(json["message"], "wallet not found: my-wallet");
    }

    #[test]
    fn serialize_roundtrip_all_variants() {
        let err = OwxError::PolicyDenied {
            policy_id: "daily-limit".into(),
            reason: "exceeded $100".into(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["code"], "POLICY_DENIED");
        assert!(parsed["message"].as_str().unwrap().contains("daily-limit"));
    }
}
