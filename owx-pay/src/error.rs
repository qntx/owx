//! Error types for the payment module.

use serde::Serialize;

/// Payment error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PayErrorCode {
    /// Protocol not recognized.
    ProtocolUnknown,
    /// No compatible payment option found.
    NoPaymentOption,
    /// Signing failed.
    SigningFailed,
    /// HTTP error.
    HttpStatus,
    /// Chain not supported for funding.
    UnsupportedChain,
    /// JSON error.
    Json,
    /// Network error.
    Network,
}

/// Payment error.
#[derive(Debug, thiserror::Error)]
#[error("{code:?}: {message}")]
pub struct PayError {
    /// Error code.
    pub code: PayErrorCode,
    /// Human-readable message.
    pub message: String,
}

impl PayError {
    /// Create a new payment error.
    #[must_use]
    pub fn new(code: PayErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl From<serde_json::Error> for PayError {
    fn from(e: serde_json::Error) -> Self {
        Self::new(PayErrorCode::Json, e.to_string())
    }
}

impl From<reqwest::Error> for PayError {
    fn from(e: reqwest::Error) -> Self {
        Self::new(PayErrorCode::Network, e.to_string())
    }
}
