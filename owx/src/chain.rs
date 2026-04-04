//! Chain registry, family classification, and CAIP-2 resolution.
//!
//! The central `for_each_chain!` macro defines the chain ↔ crate mapping once.
//! All dispatch (derivation, signing, address) is generated from it — adding a
//! new chain family requires only extending that single table.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize, de};

/// Master chain table. Every row is:
///
/// ```text
/// (Variant, display, namespace, coin_type, is_ed25519, signer_path)
/// ```
///
/// Derivation logic lives in `signer::derive_account` (Bitcoin needs special
/// error handling), but signing/address dispatch uses this table via macros.
macro_rules! for_each_chain {
    ($macro:ident) => {
        $macro! {
            [ Evm,       "evm",      "eip155",  60,        false, signer::evm::Signer     ],
            [ Bitcoin,   "bitcoin",  "bip122",  0,         false, signer::btc::Signer     ],
            [ Solana,    "solana",   "solana",  501,       true,  signer::svm::Signer     ],
            [ Cosmos,    "cosmos",   "cosmos",  118,       false, signer::cosmos::Signer  ],
            [ Tron,      "tron",     "tron",    195,       false, signer::tron::Signer    ],
            [ Ton,       "ton",      "ton",     607,       true,  signer::ton::Signer     ],
            [ Spark,     "spark",    "spark",   8_797_555, false, signer::spark::Signer   ],
            [ Filecoin,  "filecoin", "fil",     461,       false, signer::fil::Signer     ],
            [ Sui,       "sui",      "sui",     784,       true,  signer::sui::Signer     ],
            [ Xrpl,      "xrpl",     "xrpl",    144,       false, signer::xrpl::Signer    ],
        }
    };
}
pub(crate) use for_each_chain;

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

/// Implement `ChainFamily` methods, `Display`, and `FromStr` from the chain table.
macro_rules! impl_chain_family_methods {
    ( $( [ $variant:ident, $display:expr, $ns:expr, $coin:expr, $ed:expr, $signer:path ] ),+ $(,)? ) => {
        impl ChainFamily {
            /// Whether this family uses Ed25519 (vs secp256k1).
            #[must_use]
            pub const fn is_ed25519(self) -> bool {
                match self { $( Self::$variant => $ed, )+ }
            }

            /// CAIP-2 namespace.
            #[must_use]
            pub const fn namespace(self) -> &'static str {
                match self { $( Self::$variant => $ns, )+ }
            }

            /// BIP-44 coin type.
            #[must_use]
            pub const fn coin_type(self) -> u32 {
                match self { $( Self::$variant => $coin, )+ }
            }

            /// Resolve a CAIP-2 namespace to a [`ChainFamily`].
            #[must_use]
            pub fn from_namespace(ns: &str) -> Option<Self> {
                match ns { $( $ns => Some(Self::$variant), )+ _ => None }
            }
        }

        impl fmt::Display for ChainFamily {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(match self { $( Self::$variant => $display, )+ })
            }
        }

        impl FromStr for ChainFamily {
            type Err = String;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s.to_lowercase().as_str() {
                    $( $display => Ok(Self::$variant), )+
                    _ => Err(format!("unknown chain family: {s}")),
                }
            }
        }
    };
}
for_each_chain!(impl_chain_family_methods);

/// CAIP-2 chain identifier (`namespace:reference`).
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
        if !(3..=8).contains(&ns.len()) {
            return Err(format!(
                "namespace must be 3–8 chars, got {} ('{ns}')",
                ns.len()
            ));
        }
        if !ns
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
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
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(format!("reference contains invalid chars: '{r}'"));
        }
        Ok(())
    }
}

impl FromStr for ChainId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ns, reference) = s
            .split_once(':')
            .ok_or_else(|| format!("expected 'namespace:reference', got '{s}'"))?;
        Self::validate_namespace(ns)?;
        Self::validate_reference(reference)?;
        Ok(Self {
            namespace: ns.to_owned(),
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

/// A resolved chain: name + family + CAIP-2 identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chain {
    /// Human-readable name (e.g. "ethereum", "base").
    pub name: &'static str,
    /// Chain family (curve grouping).
    pub family: ChainFamily,
    /// CAIP-2 chain ID (e.g. "eip155:1").
    pub chain_id: &'static str,
}

/// Known chains registry.
pub const KNOWN: &[Chain] = &[
    Chain {
        name: "ethereum",
        family: ChainFamily::Evm,
        chain_id: "eip155:1",
    },
    Chain {
        name: "polygon",
        family: ChainFamily::Evm,
        chain_id: "eip155:137",
    },
    Chain {
        name: "arbitrum",
        family: ChainFamily::Evm,
        chain_id: "eip155:42161",
    },
    Chain {
        name: "optimism",
        family: ChainFamily::Evm,
        chain_id: "eip155:10",
    },
    Chain {
        name: "base",
        family: ChainFamily::Evm,
        chain_id: "eip155:8453",
    },
    Chain {
        name: "plasma",
        family: ChainFamily::Evm,
        chain_id: "eip155:9745",
    },
    Chain {
        name: "bsc",
        family: ChainFamily::Evm,
        chain_id: "eip155:56",
    },
    Chain {
        name: "avalanche",
        family: ChainFamily::Evm,
        chain_id: "eip155:43114",
    },
    Chain {
        name: "etherlink",
        family: ChainFamily::Evm,
        chain_id: "eip155:42793",
    },
    Chain {
        name: "solana",
        family: ChainFamily::Solana,
        chain_id: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    },
    Chain {
        name: "bitcoin",
        family: ChainFamily::Bitcoin,
        chain_id: "bip122:000000000019d6689c085ae165831e93",
    },
    Chain {
        name: "cosmos",
        family: ChainFamily::Cosmos,
        chain_id: "cosmos:cosmoshub-4",
    },
    Chain {
        name: "tron",
        family: ChainFamily::Tron,
        chain_id: "tron:mainnet",
    },
    Chain {
        name: "ton",
        family: ChainFamily::Ton,
        chain_id: "ton:mainnet",
    },
    Chain {
        name: "spark",
        family: ChainFamily::Spark,
        chain_id: "spark:mainnet",
    },
    Chain {
        name: "filecoin",
        family: ChainFamily::Filecoin,
        chain_id: "fil:mainnet",
    },
    Chain {
        name: "sui",
        family: ChainFamily::Sui,
        chain_id: "sui:mainnet",
    },
    Chain {
        name: "xrpl",
        family: ChainFamily::Xrpl,
        chain_id: "xrpl:mainnet",
    },
    Chain {
        name: "xrpl-testnet",
        family: ChainFamily::Xrpl,
        chain_id: "xrpl:testnet",
    },
    Chain {
        name: "xrpl-devnet",
        family: ChainFamily::Xrpl,
        chain_id: "xrpl:devnet",
    },
];

/// Resolve a chain string into a known [`Chain`], or synthesize one for
/// unregistered CAIP-2 IDs with a recognized namespace.
pub fn resolve(s: &str) -> Result<ResolvedChain, crate::Error> {
    let lower = s.to_lowercase();
    let lookup = if lower == "evm" { "ethereum" } else { &lower };

    if let Some(chain) = KNOWN.iter().find(|c| c.name == lookup) {
        return Ok(ResolvedChain::Known(chain));
    }
    if let Some(chain) = KNOWN.iter().find(|c| c.chain_id == s) {
        return Ok(ResolvedChain::Known(chain));
    }
    if let Some((namespace, _)) = s.split_once(':')
        && let Some(family) = ChainFamily::from_namespace(namespace)
    {
        return Ok(ResolvedChain::Dynamic {
            family,
            chain_id: s.to_owned(),
        });
    }
    Err(crate::Error::InvalidInput(format!(
        "unknown chain: '{s}'. Use a chain name (ethereum, solana, …) or CAIP-2 ID (eip155:1, …)"
    )))
}

/// Result of chain resolution — either a static reference or a dynamic CAIP-2 chain.
#[derive(Debug, Clone)]
pub enum ResolvedChain {
    /// A known chain from the static registry.
    Known(&'static Chain),
    /// A dynamically resolved chain (unknown CAIP-2 ID but recognized namespace).
    Dynamic {
        /// Chain family derived from the namespace.
        family: ChainFamily,
        /// The original CAIP-2 chain ID string.
        chain_id: String,
    },
}

impl ResolvedChain {
    /// Chain family.
    #[must_use]
    pub const fn family(&self) -> ChainFamily {
        match self {
            Self::Known(c) => c.family,
            Self::Dynamic { family, .. } => *family,
        }
    }

    /// CAIP-2 chain ID.
    #[must_use]
    pub fn chain_id(&self) -> &str {
        match self {
            Self::Known(c) => c.chain_id,
            Self::Dynamic { chain_id, .. } => chain_id,
        }
    }

    /// Human-readable name (chain ID for dynamic chains).
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Known(c) => c.name,
            Self::Dynamic { chain_id, .. } => chain_id,
        }
    }
}

/// Returns the default [`Chain`] for a given [`ChainFamily`].
#[must_use]
#[allow(clippy::expect_used)]
pub fn default_chain(family: ChainFamily) -> &'static Chain {
    KNOWN
        .iter()
        .find(|c| c.family == family)
        .expect("all families have a default chain")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn resolve_known_by_name() {
        let r = resolve("ethereum").unwrap();
        assert_eq!(r.family(), ChainFamily::Evm);
        assert_eq!(r.chain_id(), "eip155:1");
    }

    #[test]
    fn resolve_evm_alias() {
        let r = resolve("evm").unwrap();
        assert_eq!(r.name(), "ethereum");
    }

    #[test]
    fn resolve_caip2() {
        let r = resolve("eip155:42161").unwrap();
        assert_eq!(r.name(), "arbitrum");
    }

    #[test]
    fn resolve_dynamic_caip2() {
        let r = resolve("eip155:99999").unwrap();
        assert_eq!(r.family(), ChainFamily::Evm);
        assert_eq!(r.chain_id(), "eip155:99999");
    }

    #[test]
    fn resolve_all_known_chains() {
        for chain in KNOWN {
            let r = resolve(chain.name).unwrap();
            assert_eq!(r.family(), chain.family);
            assert_eq!(r.chain_id(), chain.chain_id);
        }
    }

    #[test]
    fn resolve_unknown_fails() {
        assert!(resolve("unknown_chain").is_err());
    }

    #[test]
    fn chain_family_from_namespace_roundtrip() {
        for &fam in &ALL_FAMILIES {
            let ns = fam.namespace();
            assert_eq!(ChainFamily::from_namespace(ns), Some(fam));
        }
    }

    #[test]
    fn chain_family_display_parse_roundtrip() {
        for &fam in &ALL_FAMILIES {
            let s = fam.to_string();
            let parsed: ChainFamily = s.parse().unwrap();
            assert_eq!(parsed, fam);
        }
    }

    #[test]
    fn chain_id_parse_valid() {
        let id: ChainId = "eip155:1".parse().unwrap();
        assert_eq!(id.namespace, "eip155");
        assert_eq!(id.reference, "1");
        assert_eq!(id.to_string(), "eip155:1");
    }

    #[test]
    fn chain_id_reject_invalid() {
        assert!("".parse::<ChainId>().is_err());
        assert!("ab:1".parse::<ChainId>().is_err());
        assert!("eip1551".parse::<ChainId>().is_err());
        assert!("EIP155:1".parse::<ChainId>().is_err());
    }

    #[test]
    fn default_chain_all_families() {
        for &fam in &ALL_FAMILIES {
            let chain = default_chain(fam);
            assert_eq!(chain.family, fam);
        }
    }
}
