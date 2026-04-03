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
    pub fn save<T: Serialize>(&self, subdir: &str, id: &str, value: &T) -> Result<(), VaultError> {
        sanitize_id(id)?;
        let dir = self.ensure_subdir(subdir)?;
        let path = dir.join(format!("{id}.json"));
        let json = serde_json::to_string_pretty(value)?;
        fs::write(&path, &json).map_err(|e| VaultError::io(&path, e))?;
        set_file_permissions(&path);
        Ok(())
    }

    /// Load a value from `<subdir>/<id>.json`.
    pub fn load<T: DeserializeOwned>(&self, subdir: &str, id: &str) -> Result<T, VaultError> {
        sanitize_id(id)?;
        let path = self.entry_path(subdir, id);
        if !path.exists() {
            return Err(VaultError::NotFound(format!("{subdir}/{id}")));
        }
        let contents = fs::read_to_string(&path).map_err(|e| VaultError::io(&path, e))?;
        Ok(serde_json::from_str(&contents)?)
    }

    /// Load all entries from a subdirectory (skips malformed files).
    pub fn list<T: DeserializeOwned>(&self, subdir: &str) -> Result<Vec<T>, VaultError> {
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
    pub fn delete(&self, subdir: &str, id: &str) -> Result<(), VaultError> {
        sanitize_id(id)?;
        let path = self.entry_path(subdir, id);
        if !path.exists() {
            return Err(VaultError::NotFound(format!("{subdir}/{id}")));
        }
        fs::remove_file(&path).map_err(|e| VaultError::io(&path, e))
    }

    /// Check whether `<subdir>/<id>.json` exists on disk.
    #[must_use]
    pub fn exists(&self, subdir: &str, id: &str) -> bool {
        sanitize_id(id).is_ok() && self.entry_path(subdir, id).exists()
    }

    /// Save a raw JSON string as `<subdir>/<id>.json`.
    pub fn save_raw(&self, subdir: &str, id: &str, json: &str) -> Result<(), VaultError> {
        sanitize_id(id)?;
        let dir = self.ensure_subdir(subdir)?;
        let path = dir.join(format!("{id}.json"));
        fs::write(&path, json).map_err(|e| VaultError::io(&path, e))?;
        set_file_permissions(&path);
        Ok(())
    }

    /// Load a raw JSON string from `<subdir>/<id>.json`.
    pub fn load_raw(&self, subdir: &str, id: &str) -> Result<String, VaultError> {
        sanitize_id(id)?;
        let path = self.entry_path(subdir, id);
        if !path.exists() {
            return Err(VaultError::NotFound(format!("{subdir}/{id}")));
        }
        fs::read_to_string(&path).map_err(|e| VaultError::io(&path, e))
    }

    /// List all raw JSON strings from a subdirectory.
    pub fn list_raw(&self, subdir: &str) -> Result<Vec<String>, VaultError> {
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

/// Reject IDs that could escape the subdirectory.
fn sanitize_id(id: &str) -> Result<&str, VaultError> {
    if id.is_empty() || id.contains('/') || id.contains('\\') || id.contains("..") || id == "." {
        return Err(VaultError::InvalidInput(format!(
            "invalid identifier (path traversal rejected): '{id}'"
        )));
    }
    Ok(id)
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
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
    }
    let _ = path;
}

/// Set file permissions to owner read/write only (`0o600` on Unix, no-op elsewhere).
#[allow(clippy::missing_const_for_fn)]
fn set_file_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    let _ = path;
}
