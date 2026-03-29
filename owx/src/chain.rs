//! Chain registry and CAIP-2 helpers.

/// Supported chain families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ChainFamily {
    /// EVM-compatible chains (Ethereum, Base, Arbitrum, …).
    Evm,
    /// Bitcoin.
    Bitcoin,
    /// Solana.
    Solana,
}

/// A known chain with its CAIP-2 identifier.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Chain {
    /// Human-readable name (e.g. "ethereum", "base").
    pub name: &'static str,
    /// Chain family.
    pub family: ChainFamily,
    /// CAIP-2 chain ID (e.g. "eip155:1").
    pub chain_id: &'static str,
}

/// Known chains registry.
pub const KNOWN_CHAINS: &[Chain] = &[
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
        name: "bsc",
        family: ChainFamily::Evm,
        chain_id: "eip155:56",
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
];

/// All supported chain families for universal wallet derivation.
pub const ALL_FAMILIES: [ChainFamily; 3] =
    [ChainFamily::Evm, ChainFamily::Bitcoin, ChainFamily::Solana];

/// Parse a chain string into a [`Chain`].
///
/// Accepts friendly names ("ethereum", "base") or CAIP-2 IDs ("eip155:1").
pub fn parse_chain(s: &str) -> Result<Chain, String> {
    let lower = s.to_lowercase();

    if let Some(chain) = KNOWN_CHAINS.iter().find(|c| c.name == lower) {
        return Ok(*chain);
    }

    if let Some(chain) = KNOWN_CHAINS.iter().find(|c| c.chain_id == s) {
        return Ok(*chain);
    }

    if let Some(family) = family_from_namespace(s) {
        let leaked: &'static str = Box::leak(s.to_owned().into_boxed_str());
        return Ok(Chain {
            name: leaked,
            family,
            chain_id: leaked,
        });
    }

    Err(format!("unknown chain: '{s}'"))
}

/// Default chain for a family.
///
/// # Panics
///
/// Panics if no known chain exists for the given family.
#[must_use]
pub fn default_chain(family: ChainFamily) -> Chain {
    #[allow(clippy::expect_used)]
    *KNOWN_CHAINS
        .iter()
        .find(|c| c.family == family)
        .expect("all families have a default")
}

/// Extract the CAIP-2 namespace from a chain ID and map to a [`ChainFamily`].
fn family_from_namespace(s: &str) -> Option<ChainFamily> {
    let (ns, _) = s.split_once(':')?;
    match ns {
        "eip155" => Some(ChainFamily::Evm),
        "solana" => Some(ChainFamily::Solana),
        "bip122" => Some(ChainFamily::Bitcoin),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_by_name() {
        let c = parse_chain("ethereum").unwrap();
        assert_eq!(c.chain_id, "eip155:1");
        assert_eq!(c.family, ChainFamily::Evm);
    }

    #[test]
    fn parse_by_caip2() {
        let c = parse_chain("eip155:8453").unwrap();
        assert_eq!(c.name, "base");
    }

    #[test]
    fn parse_unknown_evm() {
        let c = parse_chain("eip155:99999").unwrap();
        assert_eq!(c.family, ChainFamily::Evm);
    }

    #[test]
    fn parse_unknown_fails() {
        assert!(parse_chain("foobar").is_err());
    }

    #[test]
    fn default_chain_works() {
        assert_eq!(default_chain(ChainFamily::Evm).name, "ethereum");
        assert_eq!(default_chain(ChainFamily::Bitcoin).name, "bitcoin");
        assert_eq!(default_chain(ChainFamily::Solana).name, "solana");
    }
}
