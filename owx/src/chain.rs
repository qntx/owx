//! Chain registry, family classification, and CAIP-2 resolution.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Supported chain families (curve grouping).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainFamily {
    /// EVM-compatible (Ethereum, Base, Arbitrum, …).
    Evm,
    /// Bitcoin.
    Bitcoin,
    /// Solana.
    Solana,
    /// Cosmos Hub.
    Cosmos,
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

/// All supported chain families in canonical order.
pub const ALL_FAMILIES: [ChainFamily; 9] = [
    ChainFamily::Evm,
    ChainFamily::Bitcoin,
    ChainFamily::Solana,
    ChainFamily::Cosmos,
    ChainFamily::Tron,
    ChainFamily::Ton,
    ChainFamily::Spark,
    ChainFamily::Filecoin,
    ChainFamily::Sui,
];

/// A known chain with its family and CAIP-2 identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {
    /// Human-readable name (e.g. "ethereum", "base").
    pub name: String,
    /// Chain family.
    pub family: ChainFamily,
    /// CAIP-2 chain ID (e.g. "eip155:1").
    pub chain_id: String,
}

/// Known chains registry.
const KNOWN: &[(&str, ChainFamily, &str)] = &[
    ("ethereum", ChainFamily::Evm, "eip155:1"),
    ("polygon", ChainFamily::Evm, "eip155:137"),
    ("arbitrum", ChainFamily::Evm, "eip155:42161"),
    ("optimism", ChainFamily::Evm, "eip155:10"),
    ("base", ChainFamily::Evm, "eip155:8453"),
    ("plasma", ChainFamily::Evm, "eip155:9745"),
    ("bsc", ChainFamily::Evm, "eip155:56"),
    ("avalanche", ChainFamily::Evm, "eip155:43114"),
    (
        "solana",
        ChainFamily::Solana,
        "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    ),
    (
        "bitcoin",
        ChainFamily::Bitcoin,
        "bip122:000000000019d6689c085ae165831e93",
    ),
    ("cosmos", ChainFamily::Cosmos, "cosmos:cosmoshub-4"),
    ("tron", ChainFamily::Tron, "tron:mainnet"),
    ("ton", ChainFamily::Ton, "ton:mainnet"),
    ("spark", ChainFamily::Spark, "spark:mainnet"),
    ("filecoin", ChainFamily::Filecoin, "fil:mainnet"),
    ("sui", ChainFamily::Sui, "sui:mainnet"),
];

/// Resolve a chain string into a [`Chain`].
///
/// Accepts friendly names ("ethereum", "base"), legacy family names ("evm"),
/// or CAIP-2 IDs ("eip155:1"). Unknown CAIP-2 IDs with a recognized namespace
/// are accepted and mapped to the appropriate family.
pub fn resolve_chain(s: &str) -> Result<Chain, crate::Error> {
    let lower = s.to_lowercase();
    let lookup = if lower == "evm" { "ethereum" } else { &lower };

    if let Some(&(name, family, chain_id)) = KNOWN.iter().find(|(n, _, _)| *n == lookup) {
        return Ok(Chain {
            name: name.to_owned(),
            family,
            chain_id: chain_id.to_owned(),
        });
    }

    if let Some(&(name, family, chain_id)) = KNOWN.iter().find(|(_, _, id)| *id == s) {
        return Ok(Chain {
            name: name.to_owned(),
            family,
            chain_id: chain_id.to_owned(),
        });
    }

    if let Some((namespace, _reference)) = s.split_once(':')
        && let Some(family) = ChainFamily::from_namespace(namespace)
    {
        return Ok(Chain {
            name: s.to_owned(),
            family,
            chain_id: s.to_owned(),
        });
    }

    Err(crate::Error::InvalidInput(format!(
        "unknown chain: '{s}'. Use a chain name (ethereum, solana, …) or CAIP-2 ID (eip155:1, …)"
    )))
}

/// Returns the default [`Chain`] for a given [`ChainFamily`].
#[must_use]
#[allow(clippy::expect_used)]
pub fn default_chain(family: ChainFamily) -> Chain {
    let &(name, fam, chain_id) = KNOWN
        .iter()
        .find(|(_, f, _)| *f == family)
        .expect("all families have a default chain");
    Chain {
        name: name.to_owned(),
        family: fam,
        chain_id: chain_id.to_owned(),
    }
}

impl ChainFamily {
    /// Whether this family uses Ed25519 (vs secp256k1).
    #[must_use]
    pub const fn is_ed25519(self) -> bool {
        matches!(self, Self::Solana | Self::Ton | Self::Sui)
    }

    /// CAIP-2 namespace for this family.
    #[must_use]
    pub const fn namespace(self) -> &'static str {
        match self {
            Self::Evm => "eip155",
            Self::Bitcoin => "bip122",
            Self::Solana => "solana",
            Self::Cosmos => "cosmos",
            Self::Tron => "tron",
            Self::Ton => "ton",
            Self::Spark => "spark",
            Self::Filecoin => "fil",
            Self::Sui => "sui",
        }
    }

    /// Resolve a CAIP-2 namespace to a [`ChainFamily`].
    #[must_use]
    pub fn from_namespace(ns: &str) -> Option<Self> {
        match ns {
            "eip155" => Some(Self::Evm),
            "bip122" => Some(Self::Bitcoin),
            "solana" => Some(Self::Solana),
            "cosmos" => Some(Self::Cosmos),
            "tron" => Some(Self::Tron),
            "ton" => Some(Self::Ton),
            "spark" => Some(Self::Spark),
            "fil" => Some(Self::Filecoin),
            "sui" => Some(Self::Sui),
            _ => None,
        }
    }
}

impl fmt::Display for ChainFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Evm => "evm",
            Self::Bitcoin => "bitcoin",
            Self::Solana => "solana",
            Self::Cosmos => "cosmos",
            Self::Tron => "tron",
            Self::Ton => "ton",
            Self::Spark => "spark",
            Self::Filecoin => "filecoin",
            Self::Sui => "sui",
        })
    }
}

impl FromStr for ChainFamily {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "evm" => Ok(Self::Evm),
            "bitcoin" => Ok(Self::Bitcoin),
            "solana" => Ok(Self::Solana),
            "cosmos" => Ok(Self::Cosmos),
            "tron" => Ok(Self::Tron),
            "ton" => Ok(Self::Ton),
            "spark" => Ok(Self::Spark),
            "filecoin" => Ok(Self::Filecoin),
            "sui" => Ok(Self::Sui),
            _ => Err(format!("unknown chain family: {s}")),
        }
    }
}
