//! Wallet bridge trait for payment signing.

use crate::error::PayError;

/// Trait abstracting wallet access for payment operations.
///
/// The main `owx` crate implements this for [`AgentWallet`]. The private key
/// NEVER leaves the implementation — all signing happens inside the wallet.
pub trait WalletBridge: Send + Sync {
    /// CAIP-2 chain IDs this wallet supports (e.g. `["eip155:8453"]`).
    fn supported_chains(&self) -> Vec<String>;

    /// Get the address for a CAIP-2 chain ID.
    fn address(&self, chain_id: &str) -> Result<String, PayError>;

    /// Sign a payment payload for the given scheme and chain.
    ///
    /// For `"exact"` scheme: `payload` is EIP-712 typed data JSON.
    /// Returns the signature as a hex string with `0x` prefix.
    fn sign_typed_data(&self, chain_id: &str, payload: &str) -> Result<String, PayError>;
}
