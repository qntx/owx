//! Authentication credentials.

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
        if crate::token::is_api_token(raw) {
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
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
}
