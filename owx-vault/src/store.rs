//! File-system vault: CRUD for wallets, API keys, and policies.

use std::fs;
use std::path::{Path, PathBuf};

use crate::api_key::ApiKeyFile;
use crate::config::Config;
use crate::error::VaultError;
use crate::permissions;
use crate::wallet_file::EncryptedWallet;

/// A file-system vault rooted at a directory (e.g. `~/.owx`).
#[derive(Debug, Clone)]
pub struct Vault {
    /// Root path of the vault.
    root: PathBuf,
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


    /// Ensure and return the wallets subdirectory.
    fn wallets_dir(&self) -> Result<PathBuf, VaultError> {
        let dir = self.root.join("wallets");
        fs::create_dir_all(&dir).map_err(|e| VaultError::io(&dir, e))?;
        permissions::set_dir_permissions(&dir);
        Ok(dir)
    }

    /// Save an encrypted wallet file.
    pub fn save_wallet(&self, wallet: &EncryptedWallet) -> Result<(), VaultError> {
        let dir = self.wallets_dir()?;
        let path = dir.join(format!("{}.json", wallet.id));
        let json = serde_json::to_string_pretty(wallet)?;
        fs::write(&path, json).map_err(|e| VaultError::io(&path, e))?;
        permissions::set_file_permissions(&path);
        Ok(())
    }

    /// List all encrypted wallets, sorted by `created_at` descending (newest first).
    #[allow(clippy::print_stderr)]
    pub fn list_wallets(&self) -> Result<Vec<EncryptedWallet>, VaultError> {
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
    pub fn load_wallet(&self, name_or_id: &str) -> Result<EncryptedWallet, VaultError> {
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
    pub fn delete_wallet(&self, id: &str) -> Result<(), VaultError> {
        let dir = self.wallets_dir()?;
        let path = dir.join(format!("{id}.json"));
        if !path.exists() {
            return Err(VaultError::WalletNotFound(id.to_owned()));
        }
        fs::remove_file(&path).map_err(|e| VaultError::io(&path, e))
    }

    /// Check whether a wallet with the given name exists.
    pub fn wallet_name_exists(&self, name: &str) -> Result<bool, VaultError> {
        Ok(self.list_wallets()?.iter().any(|w| w.name == name))
    }

    /// Rename a wallet. Loads, mutates, and re-saves the wallet file.
    pub fn rename_wallet(&self, name_or_id: &str, new_name: &str) -> Result<(), VaultError> {
        let mut wallet = self.load_wallet(name_or_id)?;
        if wallet.name == new_name {
            return Ok(());
        }
        if self.wallet_name_exists(new_name)? {
            return Err(VaultError::WalletNameExists(new_name.to_owned()));
        }
        wallet.name = new_name.to_owned();
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
    pub fn save_api_key(&self, key: &ApiKeyFile) -> Result<(), VaultError> {
        let dir = self.keys_dir()?;
        let path = dir.join(format!("{}.json", key.id));
        let json = serde_json::to_string_pretty(key)?;
        fs::write(&path, json).map_err(|e| VaultError::io(&path, e))?;
        permissions::set_file_permissions(&path);
        Ok(())
    }

    /// Load an API key by ID.
    pub fn load_api_key(&self, id: &str) -> Result<ApiKeyFile, VaultError> {
        let dir = self.keys_dir()?;
        let path = dir.join(format!("{id}.json"));
        if !path.exists() {
            return Err(VaultError::ApiKeyNotFound);
        }
        let contents = fs::read_to_string(&path).map_err(|e| VaultError::io(&path, e))?;
        Ok(serde_json::from_str(&contents)?)
    }

    /// Look up an API key by SHA-256 token hash. Scans all key files.
    pub fn load_api_key_by_token_hash(&self, token_hash: &str) -> Result<ApiKeyFile, VaultError> {
        self.list_api_keys()?
            .into_iter()
            .find(|k| k.token_hash == token_hash)
            .ok_or(VaultError::ApiKeyNotFound)
    }

    /// List all API keys, sorted by creation time (newest first).
    #[allow(clippy::print_stderr)]
    pub fn list_api_keys(&self) -> Result<Vec<ApiKeyFile>, VaultError> {
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
    pub fn delete_api_key(&self, id: &str) -> Result<(), VaultError> {
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

    /// Save a raw policy JSON value by ID.
    pub fn save_policy_raw(&self, id: &str, json: &str) -> Result<(), VaultError> {
        let dir = self.policies_dir()?;
        let path = dir.join(format!("{id}.json"));
        fs::write(&path, json).map_err(|e| VaultError::io(&path, e))
    }

    /// Load a raw policy JSON string by ID.
    pub fn load_policy_raw(&self, id: &str) -> Result<String, VaultError> {
        let dir = self.policies_dir()?;
        let path = dir.join(format!("{id}.json"));
        if !path.exists() {
            return Err(VaultError::PolicyNotFound(id.to_owned()));
        }
        fs::read_to_string(&path).map_err(|e| VaultError::io(&path, e))
    }

    /// List all raw policy JSON files.
    pub fn list_policies_raw(&self) -> Result<Vec<String>, VaultError> {
        let dir = self.policies_dir()?;
        let mut out = Vec::new();
        for entry in read_json_dir(&dir)? {
            out.push(entry.contents);
        }
        Ok(out)
    }

    /// Delete a policy by ID.
    pub fn delete_policy(&self, id: &str) -> Result<(), VaultError> {
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
    use super::*;
    use crate::wallet_file::{KeyType, WalletAccount};

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
        vault.save_wallet(&w).unwrap();

        let wallets = vault.list_wallets().unwrap();
        assert_eq!(wallets.len(), 1);
        assert_eq!(wallets[0].id, "id-1");
    }

    #[test]
    fn load_by_name_or_id() {
        let (_dir, vault) = temp_vault();
        vault.save_wallet(&dummy_wallet("uuid-1", "alpha")).unwrap();

        let by_id = vault.load_wallet("uuid-1").unwrap();
        assert_eq!(by_id.name, "alpha");

        let by_name = vault.load_wallet("alpha").unwrap();
        assert_eq!(by_name.id, "uuid-1");

        assert!(vault.load_wallet("missing").is_err());
    }

    #[test]
    fn delete_wallet() {
        let (_dir, vault) = temp_vault();
        vault.save_wallet(&dummy_wallet("del-1", "del")).unwrap();
        assert_eq!(vault.list_wallets().unwrap().len(), 1);
        vault.delete_wallet("del-1").unwrap();
        assert_eq!(vault.list_wallets().unwrap().len(), 0);
    }

    #[test]
    fn wallet_name_exists_check() {
        let (_dir, vault) = temp_vault();
        vault.save_wallet(&dummy_wallet("id-x", "exists")).unwrap();
        assert!(vault.wallet_name_exists("exists").unwrap());
        assert!(!vault.wallet_name_exists("nope").unwrap());
    }

    #[test]
    fn api_key_crud() {
        use std::collections::HashMap;

        use crate::api_key::{generate_token, hash_token};

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

        vault.save_api_key(&key).unwrap();
        let loaded = vault.load_api_key("k1").unwrap();
        assert_eq!(loaded.name, "agent");

        let by_hash = vault
            .load_api_key_by_token_hash(&hash_token(&token))
            .unwrap();
        assert_eq!(by_hash.id, "k1");

        vault.delete_api_key("k1").unwrap();
        assert!(vault.load_api_key("k1").is_err());
    }

    #[test]
    fn policy_raw_crud() {
        let (_dir, vault) = temp_vault();
        let json = r#"{"id":"p1","name":"test"}"#;
        vault.save_policy_raw("p1", json).unwrap();

        let loaded = vault.load_policy_raw("p1").unwrap();
        assert_eq!(loaded, json);

        let all = vault.list_policies_raw().unwrap();
        assert_eq!(all.len(), 1);

        vault.delete_policy("p1").unwrap();
        assert!(vault.load_policy_raw("p1").is_err());
    }
}
