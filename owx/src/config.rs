//! Application configuration with RPC endpoint registry.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Backup configuration.
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Path to the vault directory.
    #[serde(default = "default_vault_path")]
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
    }

    /// Look up an RPC URL by CAIP-2 chain ID.
    #[must_use]
    pub fn rpc_url(&self, chain_id: &str) -> Option<&str> {
        self.rpc.get(chain_id).map(String::as_str)
    }

    /// Load config from a specific path, merging user overrides on top of defaults.
    #[must_use]
    pub fn load_or_default_from(path: &Path) -> Self {
        let mut config = Self::default();
        if path.exists()
            && let Ok(contents) = std::fs::read_to_string(path)
            && let Ok(user_config) = serde_json::from_str::<Self>(&contents)
        {
            for (k, v) in user_config.rpc {
                config.rpc.insert(k, v);
            }
            config.plugins = user_config.plugins;
            config.backup = user_config.backup;
            if !user_config.vault_path.as_os_str().is_empty() {
                config.vault_path = user_config.vault_path;
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
            plugins: HashMap::new(),
            backup: None,
        }
    }
}

/// Best-effort default vault path.
pub fn default_vault_path() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| "/tmp".to_owned());
    PathBuf::from(home).join(".owx")
}
