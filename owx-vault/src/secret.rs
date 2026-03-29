//! Zeroize-on-drop secret bytes wrapper with mlock support.

use zeroize::Zeroize;

use crate::hardening::{mlock_slice, munlock_slice};

/// A heap-allocated byte buffer that is zeroized when dropped.
///
/// On Unix, the buffer is mlocked to prevent swapping to disk.
/// The inner key material is securely wiped from memory on [`Drop`].
#[derive(Clone)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Wrap raw bytes. On Unix, the buffer is mlocked immediately.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        if !bytes.is_empty() {
            mlock_slice(bytes.as_ptr(), bytes.len());
        }
        Self(bytes)
    }

    /// Create from a slice (copies into a new allocation, mlocked on Unix).
    #[must_use]
    pub fn from_slice(s: &[u8]) -> Self {
        Self::new(s.to_vec())
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
        let ptr = self.0.as_ptr();
        let len = self.0.len();
        self.0.zeroize();
        munlock_slice(ptr, len);
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

    #[test]
    fn clone_independence() {
        let original = SecretBytes::new(vec![1, 2, 3]);
        let cloned = original.clone();
        assert_eq!(original.expose(), cloned.expose());
        assert_ne!(original.expose().as_ptr(), cloned.expose().as_ptr());
    }
}
