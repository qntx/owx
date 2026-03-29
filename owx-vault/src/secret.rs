//! Zeroize-on-drop secret bytes wrapper.

use zeroize::Zeroize;

/// A heap-allocated byte buffer that is zeroized when dropped.
#[derive(Clone)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Wrap raw bytes. The caller should zeroize their own copy after calling this.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Create from a slice (copies into a new allocation).
    #[must_use]
    pub fn from_slice(s: &[u8]) -> Self {
        Self(s.to_vec())
    }

    /// Expose the secret bytes for reading.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the buffer is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes([REDACTED; {} bytes])", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expose_returns_original_bytes() {
        let s = SecretBytes::new(vec![1, 2, 3]);
        assert_eq!(s.expose(), &[1, 2, 3]);
    }

    #[test]
    fn from_slice_copies() {
        let data = [0xAB; 16];
        let s = SecretBytes::from_slice(&data);
        assert_eq!(s.expose(), &data);
        assert_eq!(s.len(), 16);
    }

    #[test]
    fn debug_does_not_leak() {
        let s = SecretBytes::new(b"super secret".to_vec());
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("super"));
        assert!(dbg.contains("REDACTED"));
    }
}
