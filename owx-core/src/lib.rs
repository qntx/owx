//! Minimal core types for OWX: chain registry and CAIP-2 identifiers.
//!
//! This crate is intentionally **zero-logic** and **dependency-minimal**.
//! All storage formats, configuration, and policy types live in [`owx_vault`].

pub mod caip;
pub mod chain;

pub use caip::{CaipParseError, ChainId};
pub use chain::{
    ALL_CHAIN_TYPES, Chain, ChainType, KNOWN_CHAINS, default_chain_for_type, parse_chain,
};
