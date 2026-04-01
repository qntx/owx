//! Application configuration with RPC endpoint registry.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Backup configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    /// Directory to store backups.
    pub path: PathBuf,
    /// Whether to create backups automatically on wallet mutation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_backup: Option<bool>,
    /// Maximum number of backup snapshots to retain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_backups: Option<u32>,
}

/// Application configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Path to the vault directory.
    #[serde(default = "default_vault_path")]
    pub vault_path: PathBuf,
    /// RPC endpoints keyed by CAIP-2 chain ID.
    #[serde(default)]
    pub rpc: HashMap<String, String>,
    /// Optional backup configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup: Option<BackupConfig>,
}

impl Config {
    /// Built-in default RPC endpoints for well-known chains.
    #[must_use]
    pub fn default_rpc() -> HashMap<String, String> {
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
        ])
    }

    /// Look up an RPC URL by CAIP-2 chain ID.
    #[must_use]
    pub fn rpc_url(&self, chain_id: &str) -> Option<&str> {
        self.rpc.get(chain_id).map(String::as_str)
    }

    /// Load `~/.owx/config.json`, merging user overrides on top of defaults.
    /// Returns built-in defaults if the file doesn't exist.
    #[must_use]
    pub fn load_or_default() -> Self {
        let default = Self::default();
        let config_path = default.vault_path.join("config.json");
        Self::load_or_default_from(&config_path)
    }

    /// Load config from a specific path, merging user overrides on top of defaults.
    #[must_use]
    pub fn load_or_default_from(path: &std::path::Path) -> Self {
        let mut config = Self::default();
        if path.exists()
            && let Ok(contents) = std::fs::read_to_string(path)
            && let Ok(user_config) = serde_json::from_str::<Self>(&contents)
        {
            for (k, v) in user_config.rpc {
                config.rpc.insert(k, v);
            }
            if !user_config.vault_path.as_os_str().is_empty() {
                config.vault_path = user_config.vault_path;
            }
            if user_config.backup.is_some() {
                config.backup = user_config.backup;
            }
        }
        config
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            vault_path: default_vault_path(),
            rpc: Self::default_rpc(),
            backup: None,
        }
    }
}

#[allow(clippy::missing_docs_in_private_items)]
fn default_vault_path() -> PathBuf {
    PathBuf::from(dirs_home()).join(".owx")
}

/// Best-effort home directory resolution.
fn dirs_home() -> String {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| "/tmp".to_owned())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn default_has_rpc_entries() {
        let cfg = Config::default();
        assert!(cfg.rpc_url("eip155:1").is_some());
        assert!(cfg.rpc_url("eip155:8453").is_some());
        assert!(
            cfg.rpc_url("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp")
                .is_some()
        );
        assert!(
            cfg.rpc_url("bip122:000000000019d6689c085ae165831e93")
                .is_some()
        );
    }

    #[test]
    fn rpc_miss_returns_none() {
        let cfg = Config::default();
        assert!(cfg.rpc_url("eip155:99999").is_none());
    }

    #[test]
    fn serde_roundtrip() {
        let cfg = Config::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let restored: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg.vault_path, restored.vault_path);
        assert_eq!(cfg.rpc.len(), restored.rpc.len());
    }

    #[test]
    fn load_nonexistent_returns_default() {
        let cfg = Config::load_or_default_from(std::path::Path::new("/nonexistent/config.json"));
        assert_eq!(cfg.rpc.len(), Config::default_rpc().len());
    }

    #[test]
    fn load_merges_overrides() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        let user_config = serde_json::json!({
            "vault_path": "/tmp/custom-vault",
            "rpc": {
                "eip155:1": "https://custom-eth.rpc",
                "eip155:11155111": "https://sepolia.rpc"
            }
        });
        std::fs::write(&config_path, serde_json::to_string(&user_config).unwrap()).unwrap();

        let cfg = Config::load_or_default_from(&config_path);
        assert_eq!(cfg.rpc_url("eip155:1"), Some("https://custom-eth.rpc"));
        assert_eq!(cfg.rpc_url("eip155:11155111"), Some("https://sepolia.rpc"));
        assert_eq!(cfg.rpc_url("eip155:137"), Some("https://polygon-rpc.com"));
        assert_eq!(cfg.vault_path, PathBuf::from("/tmp/custom-vault"));
    }

    #[test]
    fn load_partial_config_without_vault_path() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        let user_config = serde_json::json!({
            "rpc": {
                "eip155:1": "https://partial-eth.rpc"
            }
        });
        std::fs::write(&config_path, serde_json::to_string(&user_config).unwrap()).unwrap();

        let cfg = Config::load_or_default_from(&config_path);
        assert_eq!(cfg.rpc_url("eip155:1"), Some("https://partial-eth.rpc"));
        assert_eq!(cfg.rpc_url("eip155:137"), Some("https://polygon-rpc.com"));
    }
}
