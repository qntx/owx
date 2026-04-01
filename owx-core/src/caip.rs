//! CAIP-2 Chain ID parsing and validation.

use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::error::OwxError;

/// CAIP-2 Chain ID: `namespace:reference`.
///
/// Validates per the CAIP-2 spec:
/// - namespace: 3–8 lowercase alphanumeric characters
/// - reference: 1–64 alphanumeric / hyphen / underscore characters
#[derive(Debug, Clone, Eq)]
pub struct ChainId {
    /// CAIP-2 namespace (e.g. `eip155`, `solana`, `bip122`).
    pub namespace: String,
    /// CAIP-2 reference (e.g. `1`, `cosmoshub-4`).
    pub reference: String,
}

impl ChainId {
    /// Validate that a namespace conforms to CAIP-2 (3-8 lowercase alphanumeric).
    fn validate_namespace(ns: &str) -> Result<(), OwxError> {
        if ns.len() < 3 || ns.len() > 8 {
            return Err(OwxError::CaipParseError {
                message: format!(
                    "namespace must be 3-8 characters, got {} ('{ns}')",
                    ns.len(),
                ),
            });
        }
        if !ns
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        {
            return Err(OwxError::CaipParseError {
                message: format!("namespace must be [a-z0-9], got '{ns}'"),
            });
        }
        Ok(())
    }

    /// Validate that a reference conforms to CAIP-2 (1-64 alphanumeric/hyphen/underscore).
    fn validate_reference(reference: &str) -> Result<(), OwxError> {
        if reference.is_empty() || reference.len() > 64 {
            return Err(OwxError::CaipParseError {
                message: format!(
                    "reference must be 1-64 characters, got {} ('{reference}')",
                    reference.len(),
                ),
            });
        }
        if !reference
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(OwxError::CaipParseError {
                message: format!("reference contains invalid characters: '{reference}'"),
            });
        }
        Ok(())
    }
}

impl FromStr for ChainId {
    type Err = OwxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ns, ref_part) = s.split_once(':').ok_or_else(|| OwxError::CaipParseError {
            message: format!("expected 'namespace:reference', got '{s}'"),
        })?;
        Self::validate_namespace(ns)?;
        Self::validate_reference(ref_part)?;
        Ok(Self {
            namespace: ns.to_owned(),
            reference: ref_part.to_owned(),
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

impl Hash for ChainId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.namespace.hash(state);
        self.reference.hash(state);
    }
}

impl Serialize for ChainId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ChainId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(de::Error::custom)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_evm() {
        let id: ChainId = "eip155:1".parse().unwrap();
        assert_eq!(id.namespace, "eip155");
        assert_eq!(id.reference, "1");
    }

    #[test]
    fn parse_solana() {
        let id: ChainId = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".parse().unwrap();
        assert_eq!(id.namespace, "solana");
    }

    #[test]
    fn parse_cosmos() {
        let id: ChainId = "cosmos:cosmoshub-4".parse().unwrap();
        assert_eq!(id.namespace, "cosmos");
        assert_eq!(id.reference, "cosmoshub-4");
    }

    #[test]
    fn parse_bitcoin() {
        let id: ChainId = "bip122:000000000019d6689c085ae165831e93"
            .parse()
            .unwrap();
        assert_eq!(id.namespace, "bip122");
    }

    #[test]
    fn reject_no_colon() {
        assert!("eip1551".parse::<ChainId>().is_err());
    }

    #[test]
    fn reject_short_namespace() {
        assert!("ab:1".parse::<ChainId>().is_err());
    }

    #[test]
    fn reject_long_namespace() {
        assert!("abcdefghi:1".parse::<ChainId>().is_err());
    }

    #[test]
    fn reject_uppercase_namespace() {
        assert!("EIP155:1".parse::<ChainId>().is_err());
    }

    #[test]
    fn display_roundtrip() {
        let id: ChainId = "eip155:1".parse().unwrap();
        assert_eq!(id.to_string(), "eip155:1");
        let id2: ChainId = id.to_string().parse().unwrap();
        assert_eq!(id, id2);
    }

    #[test]
    fn serde_roundtrip() {
        let id: ChainId = "eip155:1".parse().unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"eip155:1\"");
        let id2: ChainId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, id2);
    }

    #[test]
    fn hash_equality() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        let id1: ChainId = "eip155:1".parse().unwrap();
        let id2: ChainId = "eip155:1".parse().unwrap();
        set.insert(id1);
        assert!(set.contains(&id2));
    }
}
