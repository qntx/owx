//! Cryptographically secure random byte generation.

/// Fill a buffer with cryptographically secure random bytes.
///
/// # Panics
///
/// Panics if the system CSPRNG is unavailable.
pub fn fill_random(buf: &mut [u8]) {
    #[allow(clippy::expect_used)]
    getrandom::getrandom(buf).expect("system CSPRNG unavailable");
}
