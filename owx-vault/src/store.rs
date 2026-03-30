//! File-system vault: CRUD for wallets, API keys, and policies.

#![allow(missing_docs)]
#![allow(clippy::missing_docs_in_private_items)]

use std::fs;
use std::path::{Path, PathBuf};

use owx_core::api_key::ApiKeyFile;
use owx_core::config::Config;
use owx_core::policy::Policy;
use owx_core::wallet_file::EncryptedWallet;

use crate::error::VaultError;
use crate::permissions;

/// A file-system vault rooted at a directory (e.g. `~/.owx`).
#[derive(Debug, Clone)]
pub struct Vault {
    /// Root path of the vault.
    root: PathBuf,
}

#[derive(Debug, Clone, Copy)]
pub struct WalletStore<'a> {
    vault: &'a Vault,
}

#[derive(Debug, Clone, Copy)]
pub struct ApiKeyStore<'a> {
    vault: &'a Vault,
}

#[derive(Debug, Clone, Copy)]
pub struct PolicyStore<'a> {
    vault: &'a Vault,
}

/// Validate that an ID is safe for use as a filename component.
///
/// Rejects path traversal sequences (`..`, `/`, `\`) and empty strings.
fn sanitize_id(id: &str) -> Result<&str, VaultError> {
    if id.is_empty() || id.contains('/') || id.contains('\\') || id.contains("..") || id == "." {
        return Err(VaultError::InvalidInput(format!(
            "invalid identifier (path traversal rejected): '{id}'"
        )));
    }
    Ok(id)
}

impl WalletStore<'_> {
    pub fn save(self, wallet: &EncryptedWallet) -> Result<(), VaultError> {
        self.vault.save_wallet(wallet)
    }

    pub fn list(self) -> Result<Vec<EncryptedWallet>, VaultError> {
        self.vault.list_wallets()
    }

    pub fn load(self, name_or_id: &str) -> Result<EncryptedWallet, VaultError> {
        self.vault.load_wallet(name_or_id)
    }

    pub fn delete(self, id: &str) -> Result<(), VaultError> {
        self.vault.delete_wallet(id)
    }

    pub fn name_exists(self, name: &str) -> Result<bool, VaultError> {
        self.vault.wallet_name_exists(name)
    }

    pub fn rename(self, name_or_id: &str, new_name: &str) -> Result<(), VaultError> {
        self.vault.rename_wallet(name_or_id, new_name)
    }
}

impl ApiKeyStore<'_> {
    pub fn save(self, key: &ApiKeyFile) -> Result<(), VaultError> {
        self.vault.save_api_key(key)
    }

    pub fn load(self, id: &str) -> Result<ApiKeyFile, VaultError> {
        self.vault.load_api_key(id)
    }

    pub fn load_by_token_hash(self, token_hash: &str) -> Result<ApiKeyFile, VaultError> {
        self.vault.load_api_key_by_token_hash(token_hash)
    }

    pub fn list(self) -> Result<Vec<ApiKeyFile>, VaultError> {
        self.vault.list_api_keys()
    }

    pub fn delete(self, id: &str) -> Result<(), VaultError> {
        self.vault.delete_api_key(id)
    }
}

impl PolicyStore<'_> {
    pub fn save(self, policy: &Policy) -> Result<(), VaultError> {
        self.vault.save_policy(policy)
    }

    pub fn load(self, id: &str) -> Result<Policy, VaultError> {
        self.vault.load_policy(id)
    }

    pub fn list(self) -> Result<Vec<Policy>, VaultError> {
        self.vault.list_policies()
    }

    pub fn save_raw(self, id: &str, json: &str) -> Result<(), VaultError> {
        self.vault.save_policy_raw(id, json)
    }

    pub fn load_raw(self, id: &str) -> Result<String, VaultError> {
        self.vault.load_policy_raw(id)
    }

    pub fn list_raw(self) -> Result<Vec<String>, VaultError> {
        self.vault.list_policies_raw()
    }

    pub fn delete(self, id: &str) -> Result<(), VaultError> {
        self.vault.delete_policy(id)
    }
}

impl Vault {
    /// Open (or create) a vault at the given path.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, VaultError> {
        let root = path.into();
        fs::create_dir_all(&root).map_err(|e| VaultError::io(&root, e))?;
        permissions::set_dir_permissions(&root);
        Ok(Self { root })
    }

    /// Open the default vault from [`Config::default()`].
    pub fn open_default() -> Result<Self, VaultError> {
        Self::open(Config::default().vault_path)
    }

    /// Root path of the vault.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub const fn wallets(&self) -> WalletStore<'_> {
        WalletStore { vault: self }
    }

    #[must_use]
    pub const fn api_keys(&self) -> ApiKeyStore<'_> {
        ApiKeyStore { vault: self }
    }

    #[must_use]
    pub const fn policies(&self) -> PolicyStore<'_> {
        PolicyStore { vault: self }
    }

    /// Ensure and return the wallets subdirectory.
    fn wallets_dir(&self) -> Result<PathBuf, VaultError> {
        let dir = self.root.join("wallets");
        fs::create_dir_all(&dir).map_err(|e| VaultError::io(&dir, e))?;
        permissions::set_dir_permissions(&dir);
        Ok(dir)
    }

    /// Save an encrypted wallet file.
    fn save_wallet(&self, wallet: &EncryptedWallet) -> Result<(), VaultError> {
        sanitize_id(&wallet.id)?;
        let dir = self.wallets_dir()?;
        let path = dir.join(format!("{}.json", wallet.id));
        let json = serde_json::to_string_pretty(wallet)?;
        fs::write(&path, json).map_err(|e| VaultError::io(&path, e))?;
        permissions::set_file_permissions(&path);
        Ok(())
    }

    /// List all encrypted wallets, sorted by `created_at` descending (newest first).
    #[allow(clippy::print_stderr)]
    fn list_wallets(&self) -> Result<Vec<EncryptedWallet>, VaultError> {
        let dir = self.wallets_dir()?;
        let mut wallets = Vec::new();
        for file_entry in read_json_dir(&dir)? {
            match serde_json::from_str::<EncryptedWallet>(&file_entry.contents) {
                Ok(w) => wallets.push(w),
                Err(e) => {
                    #[cfg(debug_assertions)]
                    eprintln!("warning: skipping {}: {e}", file_entry.path.display());
                    let _ = e;
                }
            }
        }
        wallets.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(wallets)
    }

    /// Load a wallet by exact ID, then by name. Errors if not found or ambiguous.
    fn load_wallet(&self, name_or_id: &str) -> Result<EncryptedWallet, VaultError> {
        let wallets = self.list_wallets()?;

        if let Some(w) = wallets.iter().find(|w| w.id == name_or_id) {
            return Ok(w.clone());
        }

        let matches: Vec<&EncryptedWallet> =
            wallets.iter().filter(|w| w.name == name_or_id).collect();
        match matches.len() {
            0 => Err(VaultError::WalletNotFound(name_or_id.to_owned())),
            1 => Ok(matches[0].clone()),
            n => Err(VaultError::AmbiguousWallet {
                name: name_or_id.to_owned(),
                count: n,
            }),
        }
    }

    /// Delete a wallet file by ID.
    fn delete_wallet(&self, id: &str) -> Result<(), VaultError> {
        sanitize_id(id)?;
        let dir = self.wallets_dir()?;
        let path = dir.join(format!("{id}.json"));
        if !path.exists() {
            return Err(VaultError::WalletNotFound(id.to_owned()));
        }
        fs::remove_file(&path).map_err(|e| VaultError::io(&path, e))
    }

    /// Check whether a wallet with the given name exists.
    fn wallet_name_exists(&self, name: &str) -> Result<bool, VaultError> {
        Ok(self.list_wallets()?.iter().any(|w| w.name == name))
    }

    /// Rename a wallet. Loads, mutates, and re-saves the wallet file.
    fn rename_wallet(&self, name_or_id: &str, new_name: &str) -> Result<(), VaultError> {
        let mut wallet = self.load_wallet(name_or_id)?;
        if wallet.name == new_name {
            return Ok(());
        }
        if self.wallet_name_exists(new_name)? {
            return Err(VaultError::WalletNameExists(new_name.to_owned()));
        }
        new_name.clone_into(&mut wallet.name);
        self.save_wallet(&wallet)
    }

    /// Ensure and return the keys subdirectory.
    fn keys_dir(&self) -> Result<PathBuf, VaultError> {
        let dir = self.root.join("keys");
        fs::create_dir_all(&dir).map_err(|e| VaultError::io(&dir, e))?;
        permissions::set_dir_permissions(&dir);
        Ok(dir)
    }

    /// Save an API key file.
    fn save_api_key(&self, key: &ApiKeyFile) -> Result<(), VaultError> {
        sanitize_id(&key.id)?;
        let dir = self.keys_dir()?;
        let path = dir.join(format!("{}.json", key.id));
        let json = serde_json::to_string_pretty(key)?;
        fs::write(&path, json).map_err(|e| VaultError::io(&path, e))?;
        permissions::set_file_permissions(&path);
        Ok(())
    }

    /// Load an API key by ID.
    fn load_api_key(&self, id: &str) -> Result<ApiKeyFile, VaultError> {
        sanitize_id(id)?;
        let dir = self.keys_dir()?;
        let path = dir.join(format!("{id}.json"));
        if !path.exists() {
            return Err(VaultError::ApiKeyNotFound);
        }
        let contents = fs::read_to_string(&path).map_err(|e| VaultError::io(&path, e))?;
        Ok(serde_json::from_str(&contents)?)
    }

    /// Look up an API key by SHA-256 token hash. Scans all key files.
    fn load_api_key_by_token_hash(&self, token_hash: &str) -> Result<ApiKeyFile, VaultError> {
        self.list_api_keys()?
            .into_iter()
            .find(|k| k.token_hash == token_hash)
            .ok_or(VaultError::ApiKeyNotFound)
    }

    /// List all API keys, sorted by creation time (newest first).
    #[allow(clippy::print_stderr)]
    fn list_api_keys(&self) -> Result<Vec<ApiKeyFile>, VaultError> {
        let dir = self.keys_dir()?;
        let mut keys = Vec::new();
        for file_entry in read_json_dir(&dir)? {
            match serde_json::from_str::<ApiKeyFile>(&file_entry.contents) {
                Ok(k) => keys.push(k),
                Err(e) => {
                    #[cfg(debug_assertions)]
                    eprintln!("warning: skipping {}: {e}", file_entry.path.display());
                    let _ = e;
                }
            }
        }
        keys.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(keys)
    }

    /// Delete an API key by ID.
    fn delete_api_key(&self, id: &str) -> Result<(), VaultError> {
        sanitize_id(id)?;
        let dir = self.keys_dir()?;
        let path = dir.join(format!("{id}.json"));
        if !path.exists() {
            return Err(VaultError::ApiKeyNotFound);
        }
        fs::remove_file(&path).map_err(|e| VaultError::io(&path, e))
    }

    /// Ensure and return the policies subdirectory.
    fn policies_dir(&self) -> Result<PathBuf, VaultError> {
        let dir = self.root.join("policies");
        fs::create_dir_all(&dir).map_err(|e| VaultError::io(&dir, e))?;
        Ok(dir)
    }

    /// Save a policy.
    fn save_policy(&self, policy: &Policy) -> Result<(), VaultError> {
        sanitize_id(&policy.id)?;
        let dir = self.policies_dir()?;
        let path = dir.join(format!("{}.json", policy.id));
        let json = serde_json::to_string_pretty(policy)?;
        fs::write(&path, json).map_err(|e| VaultError::io(&path, e))
    }

    /// Load a policy by ID.
    fn load_policy(&self, id: &str) -> Result<Policy, VaultError> {
        sanitize_id(id)?;
        let dir = self.policies_dir()?;
        let path = dir.join(format!("{id}.json"));
        if !path.exists() {
            return Err(VaultError::PolicyNotFound(id.to_owned()));
        }
        let contents = fs::read_to_string(&path).map_err(|e| VaultError::io(&path, e))?;
        Ok(serde_json::from_str(&contents)?)
    }

    /// List all policies, sorted alphabetically by name.
    #[allow(clippy::print_stderr)]
    fn list_policies(&self) -> Result<Vec<Policy>, VaultError> {
        let dir = self.policies_dir()?;
        let mut policies = Vec::new();
        for entry in read_json_dir(&dir)? {
            match serde_json::from_str::<Policy>(&entry.contents) {
                Ok(p) => policies.push(p),
                Err(e) => {
                    #[cfg(debug_assertions)]
                    eprintln!("warning: skipping {}: {e}", entry.path.display());
                    let _ = e;
                }
            }
        }
        policies.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(policies)
    }

    /// Save a raw policy JSON value by ID.
    fn save_policy_raw(&self, id: &str, json: &str) -> Result<(), VaultError> {
        sanitize_id(id)?;
        let dir = self.policies_dir()?;
        let path = dir.join(format!("{id}.json"));
        fs::write(&path, json).map_err(|e| VaultError::io(&path, e))
    }

    /// Load a raw policy JSON string by ID.
    fn load_policy_raw(&self, id: &str) -> Result<String, VaultError> {
        sanitize_id(id)?;
        let dir = self.policies_dir()?;
        let path = dir.join(format!("{id}.json"));
        if !path.exists() {
            return Err(VaultError::PolicyNotFound(id.to_owned()));
        }
        fs::read_to_string(&path).map_err(|e| VaultError::io(&path, e))
    }

    /// List all raw policy JSON files.
    fn list_policies_raw(&self) -> Result<Vec<String>, VaultError> {
        let dir = self.policies_dir()?;
        let mut out = Vec::new();
        for entry in read_json_dir(&dir)? {
            out.push(entry.contents);
        }
        Ok(out)
    }

    /// Delete a policy by ID.
    fn delete_policy(&self, id: &str) -> Result<(), VaultError> {
        sanitize_id(id)?;
        let dir = self.policies_dir()?;
        let path = dir.join(format!("{id}.json"));
        if !path.exists() {
            return Err(VaultError::PolicyNotFound(id.to_owned()));
        }
        fs::remove_file(&path).map_err(|e| VaultError::io(&path, e))
    }
}

/// A JSON file read from disk.
struct JsonFileEntry {
    /// Path to the file.
    path: PathBuf,
    /// File contents.
    contents: String,
}

/// Read all `.json` files from a directory.
#[allow(clippy::print_stderr)]
fn read_json_dir(dir: &Path) -> Result<Vec<JsonFileEntry>, VaultError> {
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
        match fs::read_to_string(&path) {
            Ok(contents) => entries.push(JsonFileEntry { path, contents }),
            Err(e) => {
                #[cfg(debug_assertions)]
                eprintln!("warning: skipping {}: {e}", path.display());
                let _ = e;
            }
        }
    }
    Ok(entries)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use owx_core::wallet_file::{KeyType, WalletAccount};

    use super::*;

    fn temp_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        (dir, vault)
    }

    fn dummy_wallet(id: &str, name: &str) -> EncryptedWallet {
        EncryptedWallet::new(
            id.to_owned(),
            name.to_owned(),
            vec![WalletAccount {
                account_id: "eip155:1:0xabc".to_owned(),
                address: "0xabc".to_owned(),
                chain_id: "eip155:1".to_owned(),
                derivation_path: "m/44'/60'/0'/0/0".to_owned(),
            }],
            serde_json::json!({"cipher": "aes-256-gcm"}),
            KeyType::Mnemonic,
        )
    }

    #[test]
    fn save_and_list_wallets() {
        let (_dir, vault) = temp_vault();
        let w = dummy_wallet("id-1", "my-wallet");
        vault.wallets().save(&w).unwrap();

        let wallets = vault.wallets().list().unwrap();
        assert_eq!(wallets.len(), 1);
        assert_eq!(wallets[0].id, "id-1");
    }

    #[test]
    fn load_by_name_or_id() {
        let (_dir, vault) = temp_vault();
        vault
            .wallets()
            .save(&dummy_wallet("uuid-1", "alpha"))
            .unwrap();

        let by_id = vault.wallets().load("uuid-1").unwrap();
        assert_eq!(by_id.name, "alpha");

        let by_name = vault.wallets().load("alpha").unwrap();
        assert_eq!(by_name.id, "uuid-1");

        assert!(vault.wallets().load("missing").is_err());
    }

    #[test]
    fn delete_wallet() {
        let (_dir, vault) = temp_vault();
        vault.wallets().save(&dummy_wallet("del-1", "del")).unwrap();
        assert_eq!(vault.wallets().list().unwrap().len(), 1);
        vault.wallets().delete("del-1").unwrap();
        assert_eq!(vault.wallets().list().unwrap().len(), 0);
    }

    #[test]
    fn wallet_name_exists_check() {
        let (_dir, vault) = temp_vault();
        vault
            .wallets()
            .save(&dummy_wallet("id-x", "exists"))
            .unwrap();
        assert!(vault.wallets().name_exists("exists").unwrap());
        assert!(!vault.wallets().name_exists("nope").unwrap());
    }

    #[test]
    fn api_key_crud() {
        use std::collections::HashMap;

        use owx_core::api_key::{generate_token, hash_token};

        let (_dir, vault) = temp_vault();
        let token = generate_token();
        let key = ApiKeyFile {
            id: "k1".into(),
            name: "agent".into(),
            token_hash: hash_token(&token),
            created_at: "2026-01-01T00:00:00Z".into(),
            wallet_ids: vec!["w1".into()],
            policy_ids: vec![],
            expires_at: None,
            wallet_secrets: HashMap::new(),
        };

        vault.api_keys().save(&key).unwrap();
        let loaded = vault.api_keys().load("k1").unwrap();
        assert_eq!(loaded.name, "agent");

        let by_hash = vault
            .api_keys()
            .load_by_token_hash(&hash_token(&token))
            .unwrap();
        assert_eq!(by_hash.id, "k1");

        vault.api_keys().delete("k1").unwrap();
        assert!(vault.api_keys().load("k1").is_err());
    }

    #[test]
    fn path_traversal_in_save_rejected() {
        let (_dir, vault) = temp_vault();
        let wallet = dummy_wallet("../../../etc/passwd", "evil");
        assert!(vault.wallets().save(&wallet).is_err());
    }

    #[test]
    fn path_traversal_in_delete_rejected() {
        let (_dir, vault) = temp_vault();
        vault
            .wallets()
            .save(&dummy_wallet("legit", "legit"))
            .unwrap();
        assert!(vault.wallets().delete("../../../etc/passwd").is_err());
        assert_eq!(vault.wallets().list().unwrap().len(), 1);
    }

    #[test]
    fn path_traversal_in_api_key_rejected() {
        let (_dir, vault) = temp_vault();
        assert!(vault.api_keys().load("../secret").is_err());
        assert!(vault.api_keys().delete("../secret").is_err());
    }

    #[test]
    fn path_traversal_in_policy_rejected() {
        let (_dir, vault) = temp_vault();
        assert!(vault.policies().save_raw("../evil", "{}").is_err());
        assert!(vault.policies().load_raw("../evil").is_err());
        assert!(vault.policies().delete("../evil").is_err());
    }

    #[test]
    fn empty_id_rejected() {
        let (_dir, vault) = temp_vault();
        assert!(vault.wallets().delete("").is_err());
        assert!(vault.api_keys().load("").is_err());
    }

    #[test]
    fn policy_raw_crud() {
        let (_dir, vault) = temp_vault();
        let json = r#"{"id":"p1","name":"test"}"#;
        vault.policies().save_raw("p1", json).unwrap();

        let loaded = vault.policies().load_raw("p1").unwrap();
        assert_eq!(loaded, json);

        let all = vault.policies().list_raw().unwrap();
        assert_eq!(all.len(), 1);

        vault.policies().delete("p1").unwrap();
        assert!(vault.policies().load_raw("p1").is_err());
    }
}
