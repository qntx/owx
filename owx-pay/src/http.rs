//! Shared blocking HTTP client for all owx-pay operations.

use std::sync::OnceLock;
use std::time::Duration;

use crate::error::{PayError, PayErrorCode};

/// Global blocking HTTP client singleton.
static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();

/// Get the shared blocking HTTP client, initializing it on first call.
///
/// # Errors
///
/// Returns [`PayError`] if the HTTP client builder fails.
pub(crate) fn client() -> Result<&'static reqwest::blocking::Client, PayError> {
    if let Some(c) = CLIENT.get() {
        return Ok(c);
    }
    let c = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| PayError::new(PayErrorCode::Network, format!("HTTP client init: {e}")))?;
    Ok(CLIENT.get_or_init(|| c))
}
