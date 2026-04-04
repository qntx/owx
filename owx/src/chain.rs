//! Chain registry, family classification, CAIP-2 resolution, and chain ID types.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize, de};

/// Supported chain families grouped by elliptic curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainFamily {
    /// EVM-compatible (Ethereum, Base, Arbitrum, …).
    Evm,
    /// Bitcoin (BIP-84 native SegWit).
    Bitcoin,
    /// Solana.
    Solana,
    /// Cosmos Hub.
    Cosmos,
    /// TRON.
    Tron,
    /// TON.
    Ton,
    /// Spark (Lightning on Bitcoin).
    Spark,
    /// Filecoin.
    Filecoin,
    /// Sui.
    Sui,
    /// XRP Ledger.
    Xrpl,
}

/// All supported chain families in canonical order.
pub const ALL_FAMILIES: [ChainFamily; 10] = [
    ChainFamily::Evm,
    ChainFamily::Bitcoin,
    ChainFamily::Solana,
    ChainFamily::Cosmos,
    ChainFamily::Tron,
    ChainFamily::Ton,
    ChainFamily::Spark,
    ChainFamily::Filecoin,
    ChainFamily::Sui,
    ChainFamily::Xrpl,
];

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
            Self::Xrpl => "xrpl",
        }
    }

    /// BIP-44 coin type for this chain family.
    #[must_use]
    pub const fn coin_type(self) -> u32 {
        match self {
            Self::Evm => 60,
            Self::Bitcoin => 0,
            Self::Solana => 501,
            Self::Cosmos => 118,
            Self::Tron => 195,
            Self::Ton => 607,
            Self::Spark => 8_797_555,
            Self::Filecoin => 461,
            Self::Sui => 784,
            Self::Xrpl => 144,
        }
    }

    /// Resolve a CAIP-2 namespace string to a [`ChainFamily`].
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
            "xrpl" => Some(Self::Xrpl),
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
            Self::Xrpl => "xrpl",
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
            "xrpl" => Ok(Self::Xrpl),
            _ => Err(format!("unknown chain family: {s}")),
        }
    }
}

/// CAIP-2 chain identifier (`namespace:reference`).
///
/// Validates namespace (3–8 lowercase alphanumeric) and reference (1–64 alphanumeric + dash/underscore)
/// per the [CAIP-2 specification](https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-2.md).
#[derive(Debug, Clone, Eq)]
pub struct ChainId {
    /// CAIP-2 namespace (e.g. "eip155", "solana").
    pub namespace: String,
    /// CAIP-2 reference (e.g. "1", "mainnet").
    pub reference: String,
}

impl ChainId {
    /// Validate a CAIP-2 namespace: 3–8 chars, `[a-z0-9]` only.
    fn validate_namespace(ns: &str) -> Result<(), String> {
        if ns.len() < 3 || ns.len() > 8 {
            return Err(format!(
                "namespace must be 3–8 chars, got {} ('{ns}')",
                ns.len()
            ));
        }
        if !ns
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        {
            return Err(format!("namespace must be [a-z0-9], got '{ns}'"));
        }
        Ok(())
    }

    /// Validate a CAIP-2 reference: 1–64 chars, `[a-zA-Z0-9-_]` only.
    fn validate_reference(r: &str) -> Result<(), String> {
        if r.is_empty() || r.len() > 64 {
            return Err(format!(
                "reference must be 1–64 chars, got {} ('{r}')",
                r.len()
            ));
        }
        if !r
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(format!("reference contains invalid chars: '{r}'"));
        }
        Ok(())
    }
}

impl FromStr for ChainId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (namespace, reference) = s
            .split_once(':')
            .ok_or_else(|| format!("expected 'namespace:reference', got '{s}'"))?;
        Self::validate_namespace(namespace)?;
        Self::validate_reference(reference)?;
        Ok(Self {
            namespace: namespace.to_owned(),
            reference: reference.to_owned(),
        })
    }
}

impl fmt::Display for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.namespace, self.reference)
    }
}

impl PartialEq for ChainId {
    fn eq(&self, other: &Self) -> bool {
        self.namespace == other.namespace && self.reference == other.reference
    }
}

impl std::hash::Hash for ChainId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.namespace.hash(state);
        self.reference.hash(state);
    }
}

impl Serialize for ChainId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ChainId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(de::Error::custom)
    }
}

/// A resolved chain with its family and CAIP-2 identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {
    /// Human-readable name (e.g. "ethereum", "base").
    pub name: String,
    /// Chain family (curve grouping).
    pub family: ChainFamily,
    /// CAIP-2 chain ID (e.g. "eip155:1").
    pub chain_id: String,
}

/// Known chains registry (name, family, CAIP-2 ID).
const KNOWN: &[(&str, ChainFamily, &str)] = &[
    ("ethereum", ChainFamily::Evm, "eip155:1"),
    ("polygon", ChainFamily::Evm, "eip155:137"),
    ("arbitrum", ChainFamily::Evm, "eip155:42161"),
    ("optimism", ChainFamily::Evm, "eip155:10"),
    ("base", ChainFamily::Evm, "eip155:8453"),
    ("plasma", ChainFamily::Evm, "eip155:9745"),
    ("bsc", ChainFamily::Evm, "eip155:56"),
    ("avalanche", ChainFamily::Evm, "eip155:43114"),
    ("etherlink", ChainFamily::Evm, "eip155:42793"),
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
    ("xrpl", ChainFamily::Xrpl, "xrpl:mainnet"),
    ("xrpl-testnet", ChainFamily::Xrpl, "xrpl:testnet"),
    ("xrpl-devnet", ChainFamily::Xrpl, "xrpl:devnet"),
];

/// Resolve a chain string into a [`Chain`].
///
/// Accepts:
/// - Friendly names: `"ethereum"`, `"base"`, `"xrpl-testnet"`
/// - Legacy family name: `"evm"` → resolves to `"ethereum"`
/// - CAIP-2 IDs: `"eip155:1"`, `"eip155:42161"`
/// - Unknown CAIP-2 IDs with a recognized namespace: `"eip155:9999"` → `ChainFamily::Evm`
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

    if let Some((namespace, _)) = s.split_once(':')
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
