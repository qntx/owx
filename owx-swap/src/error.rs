//! Swap error types.

/// Unified error type for all `owx-swap` operations.
#[derive(Debug, thiserror::Error)]
pub enum SwapError {
    /// No backend registered for the requested provider name.
    #[error("provider not found: {0}")]
    ProviderNotFound(String),
    /// No quotes available for the given request.
    #[error("no quotes available")]
    NoQuotes,
    /// Quote ID not recognised by any backend.
    #[error("unknown quote: {0}")]
    UnknownQuote(String),
    /// Invalid input from the caller.
    #[error("{0}")]
    InvalidInput(String),
    /// Backend-specific execution failure.
    #[error("execution failed: {0}")]
    Execution(String),
    /// `LiFi` SDK error (when the `lifi` feature is active).
    #[cfg(feature = "lifi")]
    #[error("lifi: {0}")]
    LiFi(#[from] lifiswap::error::LiFiError),
    /// OWX core error.
    #[error("owx: {0}")]
    Owx(#[from] owx::Error),
    /// Serialization error.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}
