//! Generic JSON file-system store with path-traversal protection.
//!
//! Domain-agnostic: stores any `Serialize`/`Deserialize` type as
//! pretty-printed JSON in `<root>/<subdir>/<id>.json`.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::VaultError;

/// A file-system store rooted at a directory (e.g. `~/.owx`).
///
/// Files are organized into subdirectories by kind (e.g. `wallets/`, `keys/`).
/// On Unix, directories get `0o700` and files get `0o600` permissions.
#[derive(Debug, Clone)]
pub struct Store {
    /// Root path.
    root: PathBuf,
}

impl Store {
    /// Open (or create) a store at the given path.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::Io`] if the directory cannot be created.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, VaultError> {
        let root = path.into();
        fs::create_dir_all(&root).map_err(|e| VaultError::io(&root, e))?;
        set_dir_permissions(&root);
        Ok(Self { root })
    }

    /// Root path of the store.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Save a value as `<subdir>/<id>.json` with strict file permissions.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::InvalidInput`] on path traversal, [`VaultError::Io`]
    /// on write failure, or [`VaultError::Json`] on serialization failure.
    pub fn save<T: Serialize>(&self, subdir: &str, id: &str, value: &T) -> Result<(), VaultError> {
        sanitize_segment(subdir, "subdir")?;
        sanitize_segment(id, "identifier")?;
        let dir = self.ensure_subdir(subdir)?;
        let path = dir.join(format!("{id}.json"));
        let json = serde_json::to_string_pretty(value)?;
        fs::write(&path, &json).map_err(|e| VaultError::io(&path, e))?;
        set_file_permissions(&path);
        Ok(())
    }

    /// Load a value from `<subdir>/<id>.json`.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::NotFound`] if the file does not exist,
    /// [`VaultError::Io`] on read failure, or [`VaultError::Json`] on parse failure.
    pub fn load<T: DeserializeOwned>(&self, subdir: &str, id: &str) -> Result<T, VaultError> {
        sanitize_segment(subdir, "subdir")?;
        sanitize_segment(id, "identifier")?;
        let path = self.entry_path(subdir, id);
        if !path.exists() {
            return Err(VaultError::NotFound(format!("{subdir}/{id}")));
        }
        let contents = fs::read_to_string(&path).map_err(|e| VaultError::io(&path, e))?;
        Ok(serde_json::from_str(&contents)?)
    }

    /// Load all entries from a subdirectory (skips malformed files).
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::InvalidInput`] on path traversal or
    /// [`VaultError::Io`] if the directory cannot be read.
    pub fn list<T: DeserializeOwned>(&self, subdir: &str) -> Result<Vec<T>, VaultError> {
        sanitize_segment(subdir, "subdir")?;
        let dir = self.root.join(subdir);
        let mut items = Vec::new();
        for json_str in read_json_dir(&dir)? {
            if let Ok(item) = serde_json::from_str::<T>(&json_str) {
                items.push(item);
            }
        }
        Ok(items)
    }

    /// Delete `<subdir>/<id>.json`.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::NotFound`] if the file does not exist or
    /// [`VaultError::Io`] on deletion failure.
    pub fn delete(&self, subdir: &str, id: &str) -> Result<(), VaultError> {
        sanitize_segment(subdir, "subdir")?;
        sanitize_segment(id, "identifier")?;
        let path = self.entry_path(subdir, id);
        if !path.exists() {
            return Err(VaultError::NotFound(format!("{subdir}/{id}")));
        }
        fs::remove_file(&path).map_err(|e| VaultError::io(&path, e))
    }

    /// Check whether `<subdir>/<id>.json` exists on disk.
    #[must_use]
    pub fn exists(&self, subdir: &str, id: &str) -> bool {
        sanitize_segment(subdir, "subdir").is_ok()
            && sanitize_segment(id, "identifier").is_ok()
            && self.entry_path(subdir, id).exists()
    }

    /// Save a raw JSON string as `<subdir>/<id>.json`.
    ///
    /// Validates that the input is well-formed JSON before writing.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::Json`] if the input is not valid JSON,
    /// [`VaultError::InvalidInput`] on path traversal, or [`VaultError::Io`] on write failure.
    pub fn save_raw(&self, subdir: &str, id: &str, json: &str) -> Result<(), VaultError> {
        sanitize_segment(subdir, "subdir")?;
        sanitize_segment(id, "identifier")?;
        serde_json::from_str::<serde_json::Value>(json)?;
        let dir = self.ensure_subdir(subdir)?;
        let path = dir.join(format!("{id}.json"));
        fs::write(&path, json).map_err(|e| VaultError::io(&path, e))?;
        set_file_permissions(&path);
        Ok(())
    }

    /// Load a raw JSON string from `<subdir>/<id>.json`.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::NotFound`] if the file does not exist or
    /// [`VaultError::Io`] on read failure.
    pub fn load_raw(&self, subdir: &str, id: &str) -> Result<String, VaultError> {
        sanitize_segment(subdir, "subdir")?;
        sanitize_segment(id, "identifier")?;
        let path = self.entry_path(subdir, id);
        if !path.exists() {
            return Err(VaultError::NotFound(format!("{subdir}/{id}")));
        }
        fs::read_to_string(&path).map_err(|e| VaultError::io(&path, e))
    }

    /// List all raw JSON strings from a subdirectory.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::InvalidInput`] on path traversal or
    /// [`VaultError::Io`] if the directory cannot be read.
    pub fn list_raw(&self, subdir: &str) -> Result<Vec<String>, VaultError> {
        sanitize_segment(subdir, "subdir")?;
        read_json_dir(&self.root.join(subdir))
    }

    /// Ensure a subdirectory exists and return its path.
    fn ensure_subdir(&self, subdir: &str) -> Result<PathBuf, VaultError> {
        let dir = self.root.join(subdir);
        fs::create_dir_all(&dir).map_err(|e| VaultError::io(&dir, e))?;
        set_dir_permissions(&dir);
        Ok(dir)
    }

    /// Compute the on-disk path for an entry.
    fn entry_path(&self, subdir: &str, id: &str) -> PathBuf {
        self.root.join(subdir).join(format!("{id}.json"))
    }
}

/// Reject names that could escape the intended directory.
fn sanitize_segment(name: &str, label: &str) -> Result<(), VaultError> {
    if name.is_empty()
        || name.contains('/')
        || name.contains('\\')
        || name.contains("..")
        || name == "."
    {
        return Err(VaultError::InvalidInput(format!(
            "invalid {label} (path traversal rejected): '{name}'"
        )));
    }
    Ok(())
}

/// Read all `.json` files from a directory, returning their raw contents.
fn read_json_dir(dir: &Path) -> Result<Vec<String>, VaultError> {
    let mut entries = Vec::new();
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(entries),
        Err(e) => return Err(VaultError::io(dir, e)),
    };
    for entry_result in rd {
        let entry = entry_result.map_err(|e| VaultError::io(dir, e))?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        if let Ok(contents) = fs::read_to_string(&path) {
            entries.push(contents);
        }
    }
    Ok(entries)
}

/// Set directory permissions to owner-only (`0o700` on Unix, no-op elsewhere).
#[allow(clippy::missing_const_for_fn)]
fn set_dir_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
    }
    let _ = path;
}

/// Set file permissions to owner read/write only (`0o600` on Unix, no-op elsewhere).
#[allow(clippy::missing_const_for_fn)]
fn set_file_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    let _ = path;
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestItem {
        id: String,
        value: u32,
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let item = TestItem {
            id: "abc".into(),
            value: 42,
        };
        store.save("items", "abc", &item).unwrap();
        let loaded: TestItem = store.load("items", "abc").unwrap();
        assert_eq!(loaded, item);
    }

    #[test]
    fn list_returns_all() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        store
            .save(
                "items",
                "a",
                &TestItem {
                    id: "a".into(),
                    value: 1,
                },
            )
            .unwrap();
        store
            .save(
                "items",
                "b",
                &TestItem {
                    id: "b".into(),
                    value: 2,
                },
            )
            .unwrap();
        let items: Vec<TestItem> = store.list("items").unwrap();
        assert_eq!(items.len(), 2);
    }

    #[test]
    fn delete_removes_entry() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        store
            .save(
                "items",
                "x",
                &TestItem {
                    id: "x".into(),
                    value: 1,
                },
            )
            .unwrap();
        assert!(store.exists("items", "x"));
        store.delete("items", "x").unwrap();
        assert!(!store.exists("items", "x"));
    }

    #[test]
    fn load_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let result: Result<TestItem, _> = store.load("items", "missing");
        assert!(result.is_err());
    }

    #[test]
    fn path_traversal_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        assert!(
            store
                .save(
                    "items",
                    "../escape",
                    &TestItem {
                        id: "x".into(),
                        value: 0
                    }
                )
                .is_err()
        );
        assert!(
            store
                .save(
                    "items",
                    "a/b",
                    &TestItem {
                        id: "x".into(),
                        value: 0
                    }
                )
                .is_err()
        );
        assert!(
            store
                .save(
                    "items",
                    "..",
                    &TestItem {
                        id: "x".into(),
                        value: 0
                    }
                )
                .is_err()
        );
    }

    #[test]
    fn list_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let items: Vec<TestItem> = store.list("nonexistent").unwrap();
        assert!(items.is_empty());
    }
}
