//! API token generation, hashing, and identification.
//!
//! These are domain-level operations (not pure crypto) — they belong in the
//! `owx` crate rather than `owx-vault`.

use sha2::{Digest, Sha256};

/// Token prefix that signals agent mode in the credential parameter.
pub const TOKEN_PREFIX: &str = "owx_key_";

/// Check whether a credential string is an API token.
#[must_use]
pub fn is_api_token(credential: &str) -> bool {
    credential.starts_with(TOKEN_PREFIX)
}

/// Generate a random API token: `owx_key_<64 hex chars>` (256 bits of entropy).
///
/// # Panics
///
/// Panics if the system CSPRNG is unavailable.
pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    #[allow(clippy::expect_used)]
    getrandom::getrandom(&mut bytes).expect("system CSPRNG unavailable");
    format!("{TOKEN_PREFIX}{}", hex::encode(bytes))
}

/// SHA-256 hash of the raw token string, hex-encoded.
#[must_use]
pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}
