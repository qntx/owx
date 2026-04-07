//! Application configuration with RPC endpoint registry.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

/// Backup configuration.
#[non_exhaustive]
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    /// Backup directory path.
    pub path: PathBuf,
    /// Whether to auto-backup on wallet mutations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_backup: Option<bool>,
    /// Maximum number of backup snapshots to retain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_backups: Option<u32>,
}

/// Application configuration.
#[non_exhaustive]
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Path to the vault directory.
    #[serde(default)]
    pub vault_path: PathBuf,
    /// RPC endpoints keyed by CAIP-2 chain ID.
    #[serde(default)]
    pub rpc: HashMap<String, String>,
    /// Plugin configuration (opaque JSON per plugin name).
    #[serde(default)]
    pub plugins: HashMap<String, serde_json::Value>,
    /// Optional backup configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup: Option<BackupConfig>,
}

impl Config {
    /// Built-in default RPC endpoints for well-known chains (lazily initialized).
    #[must_use]
    pub fn default_rpc() -> &'static HashMap<String, String> {
        static RPC: LazyLock<HashMap<String, String>> = LazyLock::new(|| {
            HashMap::from([
                ("eip155:1".into(), "https://eth.llamarpc.com".into()),
                ("eip155:137".into(), "https://polygon-rpc.com".into()),
                ("eip155:42161".into(), "https://arb1.arbitrum.io/rpc".into()),
                ("eip155:10".into(), "https://mainnet.optimism.io".into()),
                ("eip155:8453".into(), "https://mainnet.base.org".into()),
                (
                    "eip155:56".into(),
                    "https://bsc-dataseed.binance.org".into(),
                ),
                ("eip155:9745".into(), "https://rpc.plasma.to".into()),
                (
                    "eip155:43114".into(),
                    "https://api.avax.network/ext/bc/C/rpc".into(),
                ),
                (
                    "eip155:42793".into(),
                    "https://node.mainnet.etherlink.com".into(),
                ),
                (
                    "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".into(),
                    "https://api.mainnet-beta.solana.com".into(),
                ),
                (
                    "bip122:000000000019d6689c085ae165831e93".into(),
                    "https://mempool.space/api".into(),
                ),
                (
                    "cosmos:cosmoshub-4".into(),
                    "https://cosmos-rest.publicnode.com".into(),
                ),
                ("tron:mainnet".into(), "https://api.trongrid.io".into()),
                ("ton:mainnet".into(), "https://toncenter.com/api/v2".into()),
                (
                    "fil:mainnet".into(),
                    "https://api.node.glif.io/rpc/v1".into(),
                ),
                (
                    "sui:mainnet".into(),
                    "https://fullnode.mainnet.sui.io:443".into(),
                ),
                ("xrpl:mainnet".into(), "https://s1.ripple.com:51234".into()),
                (
                    "xrpl:testnet".into(),
                    "https://s.altnet.rippletest.net:51234".into(),
                ),
                (
                    "xrpl:devnet".into(),
                    "https://s.devnet.rippletest.net:51234".into(),
                ),
            ])
        });
        &RPC
    }

    /// Look up an RPC URL by CAIP-2 chain ID.
    #[must_use]
    pub fn rpc_url(&self, chain_id: &str) -> Option<&str> {
        self.rpc.get(chain_id).map(String::as_str)
    }

    /// Load config from a specific path, merging user overrides on top of defaults.
    ///
    /// Returns `Ok(defaults)` if the file does not exist. Returns `Err` if the
    /// file exists but cannot be read or contains invalid JSON — this ensures a
    /// corrupted config is never silently ignored.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInput`] on I/O failure, or [`Error::Json`] on
    /// parse failure.
    pub fn load_or_default_from(path: &Path) -> Result<Self, crate::Error> {
        let mut config = Self::default();
        if !path.exists() {
            return Ok(config);
        }
        let contents = std::fs::read_to_string(path).map_err(|e| {
            crate::Error::InvalidInput(format!("read config {}: {e}", path.display()))
        })?;
        let user_config: Self = serde_json::from_str(&contents)?;
        for (k, v) in user_config.rpc {
            config.rpc.insert(k, v);
        }
        config.plugins = user_config.plugins;
        config.backup = user_config.backup;
        if !user_config.vault_path.as_os_str().is_empty() {
            config.vault_path = user_config.vault_path;
        }
        Ok(config)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            vault_path: PathBuf::new(),
            rpc: Self::default_rpc().clone(),
            plugins: HashMap::new(),
            backup: None,
        }
    }
}

/// Default vault path derived from the user's home directory.
///
/// Returns an error if neither `HOME` nor `USERPROFILE` is set, rather than
/// falling back to `/tmp` which would be world-readable.
///
/// # Errors
///
/// Returns [`Error::HomeNotFound`] if the home directory cannot be determined.
pub fn default_vault_path() -> Result<PathBuf, crate::Error> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| crate::Error::HomeNotFound)?;
    Ok(PathBuf::from(home).join(".owx"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn default_rpc_contains_ethereum() {
        let rpc = Config::default_rpc();
        assert!(rpc.contains_key("eip155:1"));
    }

    #[test]
    fn default_config_has_all_default_rpcs() {
        let config = Config::default();
        assert_eq!(config.rpc.len(), Config::default_rpc().len());
    }

    #[test]
    fn rpc_url_returns_matching_entry() {
        let config = Config::default();
        assert!(config.rpc_url("eip155:1").is_some());
        assert!(config.rpc_url("nonexistent:chain").is_none());
    }

    #[test]
    fn load_or_default_from_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.json");
        let config = Config::load_or_default_from(&path).unwrap();
        assert_eq!(config.rpc.len(), Config::default_rpc().len());
    }

    #[test]
    fn load_or_default_from_valid_file_merges_rpc() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(&path, r#"{"rpc":{"custom:chain":"https://custom.rpc"}}"#).unwrap();
        let config = Config::load_or_default_from(&path).unwrap();
        assert_eq!(config.rpc_url("custom:chain"), Some("https://custom.rpc"));
        // Default RPCs are still present.
        assert!(config.rpc_url("eip155:1").is_some());
    }

    #[test]
    fn load_or_default_from_invalid_json_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, "not json").unwrap();
        assert!(Config::load_or_default_from(&path).is_err());
    }

    #[test]
    fn load_or_default_from_overrides_vault_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(&path, r#"{"vault_path":"/custom/vault"}"#).unwrap();
        let config = Config::load_or_default_from(&path).unwrap();
        assert_eq!(config.vault_path, PathBuf::from("/custom/vault"));
    }

    #[test]
    fn load_or_default_from_empty_vault_path_keeps_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(&path, r#"{"vault_path":""}"#).unwrap();
        let config = Config::load_or_default_from(&path).unwrap();
        assert!(config.vault_path.as_os_str().is_empty());
    }
}
