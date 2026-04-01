//! Chain registry and CAIP-2 helpers.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Supported chain families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainType {
    /// EVM-compatible chains (Ethereum, Base, Arbitrum, …).
    Evm,
    /// Solana.
    Solana,
    /// Cosmos Hub.
    Cosmos,
    /// Bitcoin.
    Bitcoin,
    /// TRON.
    Tron,
    /// TON.
    Ton,
    /// Spark (Lightning).
    Spark,
    /// Filecoin.
    Filecoin,
    /// Sui.
    Sui,
}

/// All supported chain families for universal wallet derivation.
pub const ALL_CHAIN_TYPES: [ChainType; 9] = [
    ChainType::Evm,
    ChainType::Solana,
    ChainType::Bitcoin,
    ChainType::Cosmos,
    ChainType::Tron,
    ChainType::Ton,
    ChainType::Filecoin,
    ChainType::Spark,
    ChainType::Sui,
];

/// A specific chain (e.g. "ethereum", "arbitrum") with its family type and CAIP-2 ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chain {
    /// Human-readable name (e.g. "ethereum", "base").
    pub name: &'static str,
    /// Chain family.
    pub chain_type: ChainType,
    /// CAIP-2 chain ID (e.g. "eip155:1").
    pub chain_id: &'static str,
}

/// Known chains registry.
pub const KNOWN_CHAINS: &[Chain] = &[
    Chain {
        name: "ethereum",
        chain_type: ChainType::Evm,
        chain_id: "eip155:1",
    },
    Chain {
        name: "polygon",
        chain_type: ChainType::Evm,
        chain_id: "eip155:137",
    },
    Chain {
        name: "arbitrum",
        chain_type: ChainType::Evm,
        chain_id: "eip155:42161",
    },
    Chain {
        name: "optimism",
        chain_type: ChainType::Evm,
        chain_id: "eip155:10",
    },
    Chain {
        name: "base",
        chain_type: ChainType::Evm,
        chain_id: "eip155:8453",
    },
    Chain {
        name: "plasma",
        chain_type: ChainType::Evm,
        chain_id: "eip155:9745",
    },
    Chain {
        name: "bsc",
        chain_type: ChainType::Evm,
        chain_id: "eip155:56",
    },
    Chain {
        name: "avalanche",
        chain_type: ChainType::Evm,
        chain_id: "eip155:43114",
    },
    Chain {
        name: "solana",
        chain_type: ChainType::Solana,
        chain_id: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    },
    Chain {
        name: "bitcoin",
        chain_type: ChainType::Bitcoin,
        chain_id: "bip122:000000000019d6689c085ae165831e93",
    },
    Chain {
        name: "cosmos",
        chain_type: ChainType::Cosmos,
        chain_id: "cosmos:cosmoshub-4",
    },
    Chain {
        name: "tron",
        chain_type: ChainType::Tron,
        chain_id: "tron:mainnet",
    },
    Chain {
        name: "ton",
        chain_type: ChainType::Ton,
        chain_id: "ton:mainnet",
    },
    Chain {
        name: "spark",
        chain_type: ChainType::Spark,
        chain_id: "spark:mainnet",
    },
    Chain {
        name: "filecoin",
        chain_type: ChainType::Filecoin,
        chain_id: "fil:mainnet",
    },
    Chain {
        name: "sui",
        chain_type: ChainType::Sui,
        chain_id: "sui:mainnet",
    },
];

/// Parse a chain string into a [`Chain`].
///
/// Accepts friendly names ("ethereum", "base"), legacy family names ("evm"),
/// or CAIP-2 IDs ("eip155:1"). Unknown CAIP-2 IDs with a recognized namespace
/// are accepted and mapped to the appropriate chain type.
pub fn parse_chain(s: &str) -> Result<Chain, String> {
    let lower = s.to_lowercase();

    let lookup = match lower.as_str() {
        "evm" => "ethereum",
        _ => &lower,
    };

    if let Some(chain) = KNOWN_CHAINS.iter().find(|c| c.name == lookup) {
        return Ok(*chain);
    }

    if let Some(chain) = KNOWN_CHAINS.iter().find(|c| c.chain_id == s) {
        return Ok(*chain);
    }

    if let Some((namespace, _reference)) = s.split_once(':')
        && let Some(ct) = ChainType::from_namespace(namespace)
    {
        let leaked: &'static str = Box::leak(s.to_string().into_boxed_str());
        return Ok(Chain {
            name: leaked,
            chain_type: ct,
            chain_id: leaked,
        });
    }

    Err(format!(
        "unknown chain: '{s}'. Use a chain name (ethereum, solana, bitcoin, ...) or CAIP-2 ID (eip155:1, ...)"
    ))
}

/// Returns the default [`Chain`] for a given [`ChainType`] (first match in registry).
///
/// # Panics
///
/// Panics if no known chain exists for the given type.
#[must_use]
pub fn default_chain_for_type(ct: ChainType) -> Chain {
    #[allow(clippy::expect_used)]
    *KNOWN_CHAINS
        .iter()
        .find(|c| c.chain_type == ct)
        .expect("all chain types have a default chain")
}

impl ChainType {
    /// Returns the CAIP-2 namespace for this chain type.
    #[must_use]
    pub const fn namespace(self) -> &'static str {
        match self {
            Self::Evm => "eip155",
            Self::Solana => "solana",
            Self::Cosmos => "cosmos",
            Self::Bitcoin => "bip122",
            Self::Tron => "tron",
            Self::Ton => "ton",
            Self::Spark => "spark",
            Self::Filecoin => "fil",
            Self::Sui => "sui",
        }
    }

    /// Returns the BIP-44 coin type for this chain type.
    #[must_use]
    pub const fn default_coin_type(self) -> u32 {
        match self {
            Self::Evm => 60,
            Self::Solana => 501,
            Self::Cosmos => 118,
            Self::Bitcoin | Self::Spark => 0,
            Self::Tron => 195,
            Self::Ton => 607,
            Self::Filecoin => 461,
            Self::Sui => 784,
        }
    }

    /// Returns the [`ChainType`] for a given CAIP-2 namespace.
    #[must_use]
    pub fn from_namespace(ns: &str) -> Option<Self> {
        match ns {
            "eip155" => Some(Self::Evm),
            "solana" => Some(Self::Solana),
            "cosmos" => Some(Self::Cosmos),
            "bip122" => Some(Self::Bitcoin),
            "tron" => Some(Self::Tron),
            "ton" => Some(Self::Ton),
            "spark" => Some(Self::Spark),
            "fil" => Some(Self::Filecoin),
            "sui" => Some(Self::Sui),
            _ => None,
        }
    }
}

impl fmt::Display for ChainType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Evm => "evm",
            Self::Solana => "solana",
            Self::Cosmos => "cosmos",
            Self::Bitcoin => "bitcoin",
            Self::Tron => "tron",
            Self::Ton => "ton",
            Self::Spark => "spark",
            Self::Filecoin => "filecoin",
            Self::Sui => "sui",
        };
        f.write_str(s)
    }
}

impl FromStr for ChainType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "evm" => Ok(Self::Evm),
            "solana" => Ok(Self::Solana),
            "cosmos" => Ok(Self::Cosmos),
            "bitcoin" => Ok(Self::Bitcoin),
            "tron" => Ok(Self::Tron),
            "ton" => Ok(Self::Ton),
            "spark" => Ok(Self::Spark),
            "filecoin" => Ok(Self::Filecoin),
            "sui" => Ok(Self::Sui),
            _ => Err(format!("unknown chain type: {s}")),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn serde_roundtrip() {
        let ct = ChainType::Evm;
        let json = serde_json::to_string(&ct).unwrap();
        assert_eq!(json, "\"evm\"");
        let restored: ChainType = serde_json::from_str(&json).unwrap();
        assert_eq!(ct, restored);
    }

    #[test]
    fn serde_all_variants() {
        for (ct, expected) in [
            (ChainType::Evm, "\"evm\""),
            (ChainType::Solana, "\"solana\""),
            (ChainType::Bitcoin, "\"bitcoin\""),
            (ChainType::Cosmos, "\"cosmos\""),
            (ChainType::Tron, "\"tron\""),
            (ChainType::Ton, "\"ton\""),
            (ChainType::Spark, "\"spark\""),
            (ChainType::Filecoin, "\"filecoin\""),
            (ChainType::Sui, "\"sui\""),
        ] {
            let json = serde_json::to_string(&ct).unwrap();
            assert_eq!(json, expected);
            let restored: ChainType = serde_json::from_str(&json).unwrap();
            assert_eq!(ct, restored);
        }
    }

    #[test]
    fn namespace_mapping() {
        assert_eq!(ChainType::Evm.namespace(), "eip155");
        assert_eq!(ChainType::Solana.namespace(), "solana");
        assert_eq!(ChainType::Cosmos.namespace(), "cosmos");
        assert_eq!(ChainType::Bitcoin.namespace(), "bip122");
        assert_eq!(ChainType::Tron.namespace(), "tron");
        assert_eq!(ChainType::Ton.namespace(), "ton");
        assert_eq!(ChainType::Spark.namespace(), "spark");
        assert_eq!(ChainType::Filecoin.namespace(), "fil");
        assert_eq!(ChainType::Sui.namespace(), "sui");
    }

    #[test]
    fn coin_type_mapping() {
        assert_eq!(ChainType::Evm.default_coin_type(), 60);
        assert_eq!(ChainType::Solana.default_coin_type(), 501);
        assert_eq!(ChainType::Cosmos.default_coin_type(), 118);
        assert_eq!(ChainType::Bitcoin.default_coin_type(), 0);
        assert_eq!(ChainType::Tron.default_coin_type(), 195);
        assert_eq!(ChainType::Ton.default_coin_type(), 607);
        assert_eq!(ChainType::Filecoin.default_coin_type(), 461);
        assert_eq!(ChainType::Sui.default_coin_type(), 784);
    }

    #[test]
    fn from_namespace_all() {
        assert_eq!(ChainType::from_namespace("eip155"), Some(ChainType::Evm));
        assert_eq!(ChainType::from_namespace("solana"), Some(ChainType::Solana));
        assert_eq!(ChainType::from_namespace("cosmos"), Some(ChainType::Cosmos));
        assert_eq!(
            ChainType::from_namespace("bip122"),
            Some(ChainType::Bitcoin)
        );
        assert_eq!(ChainType::from_namespace("tron"), Some(ChainType::Tron));
        assert_eq!(ChainType::from_namespace("ton"), Some(ChainType::Ton));
        assert_eq!(ChainType::from_namespace("spark"), Some(ChainType::Spark));
        assert_eq!(ChainType::from_namespace("fil"), Some(ChainType::Filecoin));
        assert_eq!(ChainType::from_namespace("sui"), Some(ChainType::Sui));
        assert_eq!(ChainType::from_namespace("unknown"), None);
    }

    #[test]
    fn from_str_all() {
        assert_eq!("evm".parse::<ChainType>().unwrap(), ChainType::Evm);
        assert_eq!("Solana".parse::<ChainType>().unwrap(), ChainType::Solana);
        assert_eq!("BITCOIN".parse::<ChainType>().unwrap(), ChainType::Bitcoin);
        assert!("unknown".parse::<ChainType>().is_err());
    }

    #[test]
    fn display() {
        assert_eq!(ChainType::Evm.to_string(), "evm");
        assert_eq!(ChainType::Bitcoin.to_string(), "bitcoin");
        assert_eq!(ChainType::Sui.to_string(), "sui");
    }

    #[test]
    fn parse_chain_friendly_name() {
        let c = parse_chain("ethereum").unwrap();
        assert_eq!(c.name, "ethereum");
        assert_eq!(c.chain_type, ChainType::Evm);
        assert_eq!(c.chain_id, "eip155:1");
    }

    #[test]
    fn parse_chain_caip2() {
        let c = parse_chain("eip155:42161").unwrap();
        assert_eq!(c.name, "arbitrum");
        assert_eq!(c.chain_type, ChainType::Evm);
    }

    #[test]
    fn parse_chain_unknown_evm_caip2() {
        let c = parse_chain("eip155:99999").unwrap();
        assert_eq!(c.chain_type, ChainType::Evm);
        assert_eq!(c.chain_id, "eip155:99999");
    }

    #[test]
    fn parse_chain_legacy_evm() {
        let c = parse_chain("evm").unwrap();
        assert_eq!(c.name, "ethereum");
    }

    #[test]
    fn parse_chain_solana() {
        let c = parse_chain("solana").unwrap();
        assert_eq!(c.chain_type, ChainType::Solana);
    }

    #[test]
    fn parse_chain_unknown_fails() {
        assert!(parse_chain("foobar").is_err());
    }

    #[test]
    fn default_chain_for_type_works() {
        let c = default_chain_for_type(ChainType::Evm);
        assert_eq!(c.name, "ethereum");
        assert_eq!(c.chain_id, "eip155:1");
    }

    #[test]
    fn all_chain_types_count() {
        assert_eq!(ALL_CHAIN_TYPES.len(), 9);
    }
}
