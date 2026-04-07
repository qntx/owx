//! Cryptographically secure random byte generation.

use crate::error::VaultError;

/// Fill a buffer with cryptographically secure random bytes.
///
/// # Errors
///
/// Returns [`VaultError::Crypto`] if the system CSPRNG is unavailable.
pub(crate) fn fill_random(buf: &mut [u8]) -> Result<(), VaultError> {
    getrandom::getrandom(buf)
        .map_err(|e| VaultError::Crypto(format!("system CSPRNG unavailable: {e}")))
}
