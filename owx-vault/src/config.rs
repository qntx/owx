//! Application configuration.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Application configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Config {
    /// Path to the vault directory.
    pub vault_path: PathBuf,
    /// RPC endpoints keyed by CAIP-2 chain ID.
    #[serde(default)]
    pub rpc: HashMap<String, String>,
}

impl Config {
    /// Built-in default RPC endpoints for well-known chains.
    #[must_use]
    pub fn default_rpc() -> HashMap<String, String> {
        let mut rpc = HashMap::new();
        rpc.insert("eip155:1".into(), "https://eth.llamarpc.com".into());
        rpc.insert("eip155:137".into(), "https://polygon-rpc.com".into());
        rpc.insert("eip155:42161".into(), "https://arb1.arbitrum.io/rpc".into());
        rpc.insert("eip155:10".into(), "https://mainnet.optimism.io".into());
        rpc.insert("eip155:8453".into(), "https://mainnet.base.org".into());
        rpc.insert(
            "eip155:56".into(),
            "https://bsc-dataseed.binance.org".into(),
        );
        rpc.insert(
            "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".into(),
            "https://api.mainnet-beta.solana.com".into(),
        );
        rpc.insert(
            "bip122:000000000019d6689c085ae165831e93".into(),
            "https://mempool.space/api".into(),
        );
        rpc
    }

    /// Look up an RPC URL by CAIP-2 chain ID.
    #[must_use]
    pub fn rpc_url(&self, chain_id: &str) -> Option<&str> {
        self.rpc.get(chain_id).map(String::as_str)
    }
}

impl Default for Config {
    fn default() -> Self {
        let home = dirs_home();
        Self {
            vault_path: PathBuf::from(home).join(".owx"),
            rpc: Self::default_rpc(),
        }
    }
}

/// Best-effort home directory resolution (HOME on Unix, USERPROFILE on Windows).
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
    }
}
