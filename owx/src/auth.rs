//! Authentication: credential types and API token utilities.

use sha2::{Digest, Sha256};

/// Token prefix that signals agent mode in the credential parameter.
pub(crate) const TOKEN_PREFIX: &str = "owx_key_";

/// Authentication credential for wallet operations.
///
/// Compile-time distinction between owner passphrase and agent API token,
/// eliminating runtime string-prefix checks.
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub enum Credential<'a> {
    /// Owner passphrase (scrypt-encrypted wallet).
    Passphrase(&'a str),
    /// Agent API token (`owx_key_…`, HKDF-encrypted).
    ApiToken(&'a str),
}

impl<'a> Credential<'a> {
    /// Parse a raw credential string into the appropriate variant.
    ///
    /// Strings starting with `owx_key_` are treated as API tokens;
    /// everything else is a passphrase.
    #[must_use]
    pub fn parse(raw: &'a str) -> Self {
        if is_api_token(raw) {
            Self::ApiToken(raw)
        } else {
            Self::Passphrase(raw)
        }
    }

    /// Returns the inner string regardless of variant.
    #[must_use]
    pub const fn as_str(&self) -> &'a str {
        match self {
            Self::Passphrase(s) | Self::ApiToken(s) => s,
        }
    }
}

/// Check whether a credential string is an API token.
///
/// Must start with the prefix **and** contain payload characters after it.
#[must_use]
pub(crate) fn is_api_token(credential: &str) -> bool {
    credential.len() > TOKEN_PREFIX.len() && credential.starts_with(TOKEN_PREFIX)
}

/// Generate a random API token: `owx_key_<64 hex chars>` (256 bits of entropy).
///
/// # Errors
///
/// Returns [`crate::OwxError::InvalidInput`] if the system CSPRNG is unavailable.
pub(crate) fn generate_token() -> Result<String, crate::OwxError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|e| crate::OwxError::InvalidInput(format!("system CSPRNG unavailable: {e}")))?;
    Ok(format!("{TOKEN_PREFIX}{}", hex::encode(bytes)))
}

/// SHA-256 hash of the raw token string, hex-encoded.
#[must_use]
pub(crate) fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_passphrase() {
        let cred = Credential::parse("my-password");
        assert!(matches!(cred, Credential::Passphrase("my-password")));
        assert_eq!(cred.as_str(), "my-password");
    }

    #[test]
    fn parse_api_token() {
        let token = "owx_key_0123456789abcdef";
        let cred = Credential::parse(token);
        assert!(matches!(cred, Credential::ApiToken(_)));
        assert_eq!(cred.as_str(), token);
    }

    #[test]
    fn parse_empty_is_passphrase() {
        assert!(matches!(Credential::parse(""), Credential::Passphrase("")));
    }

    #[test]
    fn generated_token_has_correct_format() {
        let token = generate_token().unwrap();
        assert!(token.starts_with(TOKEN_PREFIX));
        assert_eq!(token.len(), TOKEN_PREFIX.len() + 64);
        assert!(hex::decode(&token[TOKEN_PREFIX.len()..]).is_ok());
    }

    #[test]
    fn two_tokens_are_unique() {
        assert_ne!(generate_token().unwrap(), generate_token().unwrap());
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
        assert!(!is_api_token("owx_key"));
        assert!(!is_api_token("owx_key_"));
    }
}
