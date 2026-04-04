//! Swap error types.

/// Swap error.
#[derive(Debug, thiserror::Error)]
pub enum SwapError {
    /// LiFi SDK error.
    #[error("lifi: {0}")]
    LiFi(#[from] lifiswap::error::LiFiError),
    /// OWX error.
    #[error("owx: {0}")]
    Owx(#[from] owx::Error),
    /// Invalid input.
    #[error("{0}")]
    InvalidInput(String),
}
