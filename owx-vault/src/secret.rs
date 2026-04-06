//! Zeroize-on-drop secret bytes wrapper with mlock support.

use zeroize::Zeroize;

use crate::hardening::{mlock_slice, munlock_slice};

/// A heap-allocated byte buffer that is zeroized when dropped.
///
/// On Unix, the buffer is mlocked to prevent swapping to disk.
/// The inner key material is securely wiped from memory on [`Drop`].
#[allow(clippy::module_name_repetitions)]
pub struct SecretBytes(Vec<u8>);

impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        Self::new(self.0.clone())
    }
}

impl SecretBytes {
    /// Wrap raw bytes. On Unix, the buffer is mlocked immediately.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // calls mlock on unix
    pub fn new(bytes: Vec<u8>) -> Self {
        if !bytes.is_empty() {
            let _ = mlock_slice(bytes.as_ptr(), bytes.len());
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

impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes([REDACTED; {} bytes])", self.0.len())
    }
}
