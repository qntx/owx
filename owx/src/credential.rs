//! Authentication credentials and secret key material.

use zeroize::Zeroize;

use crate::error::Error;

/// Authentication credential for wallet operations.
///
/// Compile-time distinction between owner passphrase and agent API token,
/// eliminating runtime string-prefix checks.
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

/// A private signing key that is zeroized on drop.
///
/// Wraps raw key bytes (not hex). Never exposed outside the `owx` crate
/// as a public type — callers interact only through `Owx` methods.
pub struct SecretKey(zeroize::Zeroizing<Vec<u8>>);

impl SecretKey {
    /// Create from raw bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(zeroize::Zeroizing::new(bytes))
    }

    /// Create from a hex-encoded string.
    pub fn from_hex(hex_str: &str) -> Result<Self, Error> {
        let clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes =
            hex::decode(clean).map_err(|e| Error::InvalidInput(format!("invalid hex key: {e}")))?;
        Ok(Self::new(bytes))
    }

    /// Expose the raw key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert to hex string (crate-internal only).
    #[allow(dead_code)]
    pub(crate) fn to_hex(&self) -> zeroize::Zeroizing<String> {
        zeroize::Zeroizing::new(hex::encode(&*self.0))
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey([REDACTED])")
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

    #[test]
    fn secret_key_from_hex() {
        let key =
            SecretKey::from_hex("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
                .unwrap();
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn secret_key_strips_0x_prefix() {
        let key = SecretKey::from_hex("0xaabb").unwrap();
        assert_eq!(key.as_bytes(), &[0xaa, 0xbb]);
    }

    #[test]
    fn secret_key_invalid_hex_rejected() {
        assert!(SecretKey::from_hex("not-hex").is_err());
    }

    #[test]
    fn secret_key_debug_redacted() {
        let key = SecretKey::from_hex("aabb").unwrap();
        let dbg = format!("{key:?}");
        assert_eq!(dbg, "SecretKey([REDACTED])");
        assert!(!dbg.contains("aa"));
    }
}
