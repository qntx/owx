//! EVM provider bridge: OWX wallet → `lifiswap-evm` execution.
//!
//! Creates an [`EvmProvider`] from a raw secp256k1 private key hex string,
//! enabling end-to-end swap execution through the `LiFi` engine.

use std::collections::HashMap;

use alloy::signers::local::PrivateKeySigner;
use lifiswap_evm::{EvmProvider, LocalSigner};

use crate::error::SwapError;

/// Build an [`EvmProvider`] from a raw private key hex and default RPC URL.
///
/// # Errors
///
/// Returns [`SwapError::InvalidInput`] if the key or URL is malformed.
#[allow(clippy::module_name_repetitions)]
pub fn evm_provider_from_key(
    private_key_hex: &str,
    rpc_url: &str,
) -> Result<EvmProvider, SwapError> {
    let key_hex = private_key_hex
        .strip_prefix("0x")
        .unwrap_or(private_key_hex);
    let signer: PrivateKeySigner = key_hex
        .parse()
        .map_err(|e| SwapError::InvalidInput(format!("invalid private key: {e}")))?;
    let rpc: url::Url = rpc_url
        .parse()
        .map_err(|e| SwapError::InvalidInput(format!("invalid RPC URL: {e}")))?;
    let local = LocalSigner::new(signer, rpc.clone());
    Ok(EvmProvider::new(local, rpc))
}

/// Build an [`EvmProvider`] with multi-chain RPC resolution.
///
/// # Errors
///
/// Returns [`SwapError::InvalidInput`] if the key or URL is malformed.
#[allow(clippy::module_name_repetitions, clippy::implicit_hasher)]
pub fn evm_provider_from_key_with_rpcs(
    private_key_hex: &str,
    default_rpc_url: &str,
    rpc_map: HashMap<u64, String>,
) -> Result<EvmProvider, SwapError> {
    let provider = evm_provider_from_key(private_key_hex, default_rpc_url)?;
    Ok(provider.with_rpc_resolver(OwxRpcResolver(rpc_map)))
}

/// Maps `LiFi` numeric chain IDs to OWX RPC URLs.
#[derive(Debug, Clone)]
struct OwxRpcResolver(HashMap<u64, String>);

impl lifiswap_evm::rpc::RpcUrlResolver for OwxRpcResolver {
    fn resolve(&self, chain_id: u64) -> Option<url::Url> {
        self.0.get(&chain_id).and_then(|s| s.parse().ok())
    }
}
