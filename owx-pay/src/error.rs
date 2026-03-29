//! Payment error types.

/// Errors from payment operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PayError {
    /// The server did not return a 402 response.
    #[error("not a 402 response (status {0})")]
    NotPaymentRequired(u16),

    /// The x402 protocol response was malformed.
    #[error("malformed x402 response: {0}")]
    ProtocolMalformed(String),

    /// No supported chain/scheme in the 402 response.
    #[error("unsupported chain or scheme: {0}")]
    Unsupported(String),

    /// Signing the payment payload failed.
    #[error("signing failed: {0}")]
    SigningFailed(String),

    /// HTTP request failed.
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON error.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    /// Generic input error.
    #[error("invalid input: {0}")]
    InvalidInput(String),
}
