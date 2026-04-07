//! TTL-based key cache with LRU eviction for derived signing keys.
//!
//! Caches derived private keys in memory to avoid repeated HD derivation
//! during high-frequency agent signing. All entries are zeroized on
//! eviction, expiry, or [`Drop`].

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::secret::SecretBytes;

/// A single cached key entry.
struct Entry {
    /// The cached secret key material.
    key: SecretBytes,
    /// When this entry was last accessed.
    last_accessed: Instant,
}

/// A TTL-based cache for derived signing keys with LRU eviction.
///
/// Thread-safe via internal [`Mutex`]. All entries are zeroized on
/// eviction or when the cache is dropped.
pub struct KeyCache {
    /// Cache entries keyed by a hash of derivation inputs.
    entries: Mutex<HashMap<String, Entry>>,
    /// Time-to-live for each entry.
    ttl: Duration,
    /// Maximum number of cached entries.
    max_entries: usize,
}

impl KeyCache {
    /// Create a new cache with the given TTL and capacity.
    #[must_use]
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl,
            max_entries,
        }
    }

    /// Look up a cached key. Returns `None` if absent or expired.
    ///
    /// Accessing an entry refreshes its TTL timer.
    pub fn get(&self, id: &str) -> Option<SecretBytes> {
        let mut map = self.entries.lock().ok()?;
        let entry = map.get(id)?;
        if entry.last_accessed.elapsed() > self.ttl {
            map.remove(id);
            return None;
        }
        let cloned = entry.key.clone();
        if let Some(e) = map.get_mut(id) {
            e.last_accessed = Instant::now();
        }
        drop(map);
        Some(cloned)
    }

    /// Insert a key into the cache.
    ///
    /// Evicts expired entries first, then the least-recently-used entry
    /// if the cache is at capacity.
    pub fn insert(&self, id: &str, key: SecretBytes) {
        let Ok(mut map) = self.entries.lock() else {
            return;
        };
        self.evict_expired_inner(&mut map);

        if map.len() >= self.max_entries
            && !map.contains_key(id)
            && let Some(lru_key) = map
                .iter()
                .min_by_key(|(_, e)| e.last_accessed)
                .map(|(k, _)| k.clone())
        {
            map.remove(&lru_key);
        }

        map.insert(
            id.to_owned(),
            Entry {
                key,
                last_accessed: Instant::now(),
            },
        );
    }

    /// Remove all entries (zeroizing key material).
    pub fn clear(&self) {
        if let Ok(mut map) = self.entries.lock() {
            map.clear();
        }
    }

    /// Evict all expired entries.
    pub fn evict_expired(&self) {
        if let Ok(mut map) = self.entries.lock() {
            self.evict_expired_inner(&mut map);
        }
    }

    /// Number of currently cached entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.lock().map_or(0, |m| m.len())
    }

    /// Whether the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Evict expired entries from an already-locked map.
    fn evict_expired_inner(&self, map: &mut HashMap<String, Entry>) {
        map.retain(|_, entry| entry.last_accessed.elapsed() <= self.ttl);
    }
}

impl std::fmt::Debug for KeyCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyCache")
            .field("entries", &self.len())
            .field("ttl", &self.ttl)
            .field("max_entries", &self.max_entries)
            .finish()
    }
}

impl Drop for KeyCache {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_get() {
        let cache = KeyCache::new(Duration::from_mins(1), 10);
        cache.insert("k1", SecretBytes::from_slice(b"secret"));
        let val = cache.get("k1").unwrap();
        assert_eq!(val.expose(), b"secret");
    }

    #[test]
    fn get_missing_returns_none() {
        let cache = KeyCache::new(Duration::from_mins(1), 10);
        assert!(cache.get("nonexistent").is_none());
    }

    #[test]
    fn ttl_expiry() {
        let cache = KeyCache::new(Duration::from_millis(50), 10);
        cache.insert("k1", SecretBytes::from_slice(b"data"));
        assert!(cache.get("k1").is_some());
        #[allow(
            clippy::disallowed_methods,
            reason = "sync test needs real delay for TTL expiry"
        )]
        std::thread::sleep(Duration::from_millis(80));
        assert!(cache.get("k1").is_none());
    }

    #[test]
    fn lru_eviction_at_capacity() {
        let cache = KeyCache::new(Duration::from_mins(1), 2);
        cache.insert("k1", SecretBytes::from_slice(b"a"));
        cache.insert("k2", SecretBytes::from_slice(b"b"));
        // Access k1 to make k2 the LRU
        let _ = cache.get("k1");
        // Insert k3 — should evict k2 (LRU)
        cache.insert("k3", SecretBytes::from_slice(b"c"));
        assert!(cache.get("k1").is_some());
        assert!(cache.get("k2").is_none());
        assert!(cache.get("k3").is_some());
    }

    #[test]
    fn clear_removes_all() {
        let cache = KeyCache::new(Duration::from_mins(1), 10);
        cache.insert("k1", SecretBytes::from_slice(b"a"));
        cache.insert("k2", SecretBytes::from_slice(b"b"));
        assert_eq!(cache.len(), 2);
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn overwrite_existing_key() {
        let cache = KeyCache::new(Duration::from_mins(1), 10);
        cache.insert("k1", SecretBytes::from_slice(b"old"));
        cache.insert("k1", SecretBytes::from_slice(b"new"));
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get("k1").unwrap().expose(), b"new");
    }
}
