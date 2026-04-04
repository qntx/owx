//! Wallet bridge trait and vault-backed implementation.

use owx::Vault;
use owx::chain::ChainFamily;

/// Trait abstracting wallet access for payment operations.
///
/// The private key NEVER leaves the implementation — all signing happens
/// inside the wallet.
pub trait WalletBridge: Send + Sync {
    /// Chain families this wallet supports.
    fn supported_families(&self) -> Vec<ChainFamily>;
    /// Get the address for a CAIP-2 network string.
    fn address(&self, network: &str) -> Result<String, owx::Error>;
    /// Sign a payment payload for a scheme/network. Returns hex signature.
    fn sign_payload(
        &self,
        scheme: &str,
        network: &str,
        payload: &str,
    ) -> Result<String, owx::Error>;
}

/// Concrete [`WalletBridge`] backed by an OWX vault wallet.
pub struct VaultBridge<'v> {
    vault: &'v Vault,
    wallet: String,
    credential: String,
    index: u32,
}

impl std::fmt::Debug for VaultBridge<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultBridge")
            .field("wallet", &self.wallet)
            .field("credential", &"[REDACTED]")
            .field("index", &self.index)
            .finish()
    }
}

impl<'v> VaultBridge<'v> {
    /// Create a new bridge.
    pub fn new(
        vault: &'v Vault,
        wallet: impl Into<String>,
        credential: impl Into<String>,
        index: u32,
    ) -> Self {
        Self {
            vault,
            wallet: wallet.into(),
            credential: credential.into(),
            index,
        }
    }
}

impl WalletBridge for VaultBridge<'_> {
    fn supported_families(&self) -> Vec<ChainFamily> {
        owx::list_wallets(self.vault)
            .ok()
            .and_then(|ws| {
                ws.into_iter()
                    .find(|w| w.id == self.wallet || w.name == self.wallet)
            })
            .map(|w| {
                w.accounts
                    .iter()
                    .filter_map(|a| {
                        a.chain_id
                            .split_once(':')
                            .and_then(|(ns, _)| ChainFamily::from_namespace(ns))
                    })
                    .collect::<std::collections::HashSet<_>>()
                    .into_iter()
                    .collect()
            })
            .unwrap_or_default()
    }

    fn address(&self, network: &str) -> Result<String, owx::Error> {
        let info = owx::get_wallet(self.vault, &self.wallet)?;
        info.accounts
            .iter()
            .find(|a| a.chain_id == network)
            .map(|a| a.address.clone())
            .ok_or_else(|| owx::Error::InvalidInput(format!("no account for chain {network}")))
    }

    fn sign_payload(
        &self,
        _scheme: &str,
        network: &str,
        payload: &str,
    ) -> Result<String, owx::Error> {
        let result = owx::sign_typed_data(
            self.vault,
            &self.wallet,
            network,
            payload,
            &self.credential,
            Some(self.index),
        )?;
        let sig_bytes = hex::decode(&result.signature)
            .map_err(|e| owx::Error::Signing(format!("invalid sig hex: {e}")))?;
        let full = if sig_bytes.len() == 64 {
            let mut buf = sig_bytes;
            buf.push(27 + result.recovery_id.unwrap_or(0));
            buf
        } else {
            sig_bytes
        };
        Ok(format!("0x{}", hex::encode(&full)))
    }
}
