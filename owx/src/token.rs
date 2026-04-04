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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_token_has_correct_format() {
        let token = generate_token();
        assert!(token.starts_with(TOKEN_PREFIX));
        assert_eq!(token.len(), TOKEN_PREFIX.len() + 64); // 256 bits = 64 hex chars
        assert!(hex::decode(&token[TOKEN_PREFIX.len()..]).is_ok());
    }

    #[test]
    fn two_tokens_are_unique() {
        assert_ne!(generate_token(), generate_token());
    }

    #[test]
    fn hash_is_deterministic() {
        let token = "owx_key_abc123";
        assert_eq!(hash_token(token), hash_token(token));
    }

    #[test]
    fn different_tokens_have_different_hashes() {
        assert_ne!(hash_token("owx_key_a"), hash_token("owx_key_b"));
    }

    #[test]
    fn is_api_token_recognizes_prefix() {
        assert!(is_api_token("owx_key_abc"));
        assert!(!is_api_token("password123"));
        assert!(!is_api_token(""));
        assert!(!is_api_token("owx_key")); // missing trailing content but still matches prefix — correct behavior
    }
}
