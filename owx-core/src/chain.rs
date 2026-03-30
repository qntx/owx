//! Chain registry and CAIP-2 helpers.

use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::caip::ChainId;

/// Supported chain families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainType {
    /// EVM-compatible chains (Ethereum, Base, Arbitrum, …).
    Evm,
    /// Bitcoin.
    Bitcoin,
    /// Solana.
    Solana,
}

/// All supported chain types for universal wallet derivation.
pub const ALL_CHAIN_TYPES: [ChainType; 3] = [ChainType::Evm, ChainType::Bitcoin, ChainType::Solana];

/// A specific chain with its family type and CAIP-2 identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {
    /// Human-readable name (e.g. "ethereum", "base").
    pub name: Cow<'static, str>,
    /// Chain family.
    pub chain_type: ChainType,
    /// CAIP-2 chain ID (e.g. "eip155:1").
    pub chain_id: Cow<'static, str>,
}

#[allow(clippy::missing_docs_in_private_items)]
impl Chain {
    const fn known(name: &'static str, chain_type: ChainType, chain_id: &'static str) -> Self {
        Self {
            name: Cow::Borrowed(name),
            chain_type,
            chain_id: Cow::Borrowed(chain_id),
        }
    }

    fn custom(chain_type: ChainType, chain_id: &ChainId) -> Self {
        let chain_id_text = chain_id.to_string();
        Self {
            name: Cow::Owned(chain_id_text.clone()),
            chain_type,
            chain_id: Cow::Owned(chain_id_text),
        }
    }
}

/// Known chains registry.
pub const KNOWN_CHAINS: &[Chain] = &[
    Chain::known("ethereum", ChainType::Evm, "eip155:1"),
    Chain::known("polygon", ChainType::Evm, "eip155:137"),
    Chain::known("arbitrum", ChainType::Evm, "eip155:42161"),
    Chain::known("optimism", ChainType::Evm, "eip155:10"),
    Chain::known("base", ChainType::Evm, "eip155:8453"),
    Chain::known("bsc", ChainType::Evm, "eip155:56"),
    Chain::known("plasma", ChainType::Evm, "eip155:9745"),
    Chain::known("avalanche", ChainType::Evm, "eip155:43114"),
    Chain::known(
        "solana",
        ChainType::Solana,
        "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    ),
    Chain::known(
        "bitcoin",
        ChainType::Bitcoin,
        "bip122:000000000019d6689c085ae165831e93",
    ),
];

/// Parse a chain string into a [`Chain`].
///
/// Accepts friendly names ("ethereum", "base"), legacy family names ("evm"),
/// or CAIP-2 IDs ("eip155:1"). Unknown CAIP-2 IDs with a recognized namespace
/// are accepted and mapped to the appropriate chain type.
pub fn parse_chain(s: &str) -> Result<Chain, String> {
    let lower = s.to_ascii_lowercase();

    let lookup = match lower.as_str() {
        "evm" => "ethereum",
        _ => &lower,
    };

    if let Some(chain) = KNOWN_CHAINS.iter().find(|c| c.name == lookup) {
        return Ok(chain.clone());
    }

    if let Some(chain) = KNOWN_CHAINS.iter().find(|c| c.chain_id == s) {
        return Ok(chain.clone());
    }

    let chain_id = ChainId::from_str(s).map_err(|error| error.to_string())?;
    if let Some(chain_type) = ChainType::from_namespace(&chain_id.namespace) {
        return Ok(Chain::custom(chain_type, &chain_id));
    }

    Err(format!(
        "unknown chain: '{s}'. Use a chain name (ethereum, solana, bitcoin, ...) or CAIP-2 ID (eip155:1, ...)"
    ))
}

/// Returns the default [`Chain`] for a given [`ChainType`].
///
/// # Panics
///
/// Panics if no known chain exists for the given type (should never happen).
#[must_use]
pub fn default_chain_for_type(ct: ChainType) -> Chain {
    #[allow(clippy::expect_used)]
    KNOWN_CHAINS
        .iter()
        .find(|c| c.chain_type == ct)
        .cloned()
        .expect("all chain types have a default chain")
}

impl ChainType {
    /// Returns the CAIP-2 namespace for this chain type.
    #[must_use]
    pub const fn namespace(self) -> &'static str {
        match self {
            Self::Evm => "eip155",
            Self::Solana => "solana",
            Self::Bitcoin => "bip122",
        }
    }

    /// Returns the BIP-44 coin type for this chain type.
    #[must_use]
    pub const fn default_coin_type(self) -> u32 {
        match self {
            Self::Evm => 60,
            Self::Solana => 501,
            Self::Bitcoin => 0,
        }
    }

    /// Returns the [`ChainType`] for a given CAIP-2 namespace.
    #[must_use]
    pub fn from_namespace(ns: &str) -> Option<Self> {
        match ns {
            "eip155" => Some(Self::Evm),
            "solana" => Some(Self::Solana),
            "bip122" => Some(Self::Bitcoin),
            _ => None,
        }
    }
}

impl fmt::Display for ChainType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Evm => "evm",
            Self::Solana => "solana",
            Self::Bitcoin => "bitcoin",
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
            "bitcoin" => Ok(Self::Bitcoin),
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
        ] {
            let json = serde_json::to_string(&ct).unwrap();
            assert_eq!(json, expected);
        }
    }

    #[test]
    fn namespace_mapping() {
        assert_eq!(ChainType::Evm.namespace(), "eip155");
        assert_eq!(ChainType::Solana.namespace(), "solana");
        assert_eq!(ChainType::Bitcoin.namespace(), "bip122");
    }

    #[test]
    fn coin_type_mapping() {
        assert_eq!(ChainType::Evm.default_coin_type(), 60);
        assert_eq!(ChainType::Solana.default_coin_type(), 501);
        assert_eq!(ChainType::Bitcoin.default_coin_type(), 0);
    }

    #[test]
    fn from_namespace() {
        assert_eq!(ChainType::from_namespace("eip155"), Some(ChainType::Evm));
        assert_eq!(ChainType::from_namespace("solana"), Some(ChainType::Solana));
        assert_eq!(ChainType::from_namespace("unknown"), None);
    }

    #[test]
    fn from_str() {
        assert_eq!("evm".parse::<ChainType>().unwrap(), ChainType::Evm);
        assert_eq!("Solana".parse::<ChainType>().unwrap(), ChainType::Solana);
        assert!("unknown".parse::<ChainType>().is_err());
    }

    #[test]
    fn display() {
        assert_eq!(ChainType::Evm.to_string(), "evm");
        assert_eq!(ChainType::Bitcoin.to_string(), "bitcoin");
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
        assert_eq!(ALL_CHAIN_TYPES.len(), 3);
    }
}
