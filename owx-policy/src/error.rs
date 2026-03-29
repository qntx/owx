//! Policy error types.

/// Errors from policy operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PolicyError {
    /// Policy evaluation denied the request.
    #[error("denied by policy '{policy_id}': {reason}")]
    Denied {
        /// Which policy produced the denial.
        policy_id: String,
        /// Human-readable reason.
        reason: String,
    },

    /// Executable policy failed to run.
    #[error("executable policy failed: {0}")]
    ExecutableFailed(String),

    /// JSON error.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}
