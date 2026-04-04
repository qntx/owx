//! [`VaultBridge`] — connects OWX vault signing to the payment layer.

use crate::Vault;
use crate::chain::ChainFamily;
use crate::error::Error;
use crate::pay::WalletBridge;

/// Concrete [`WalletBridge`] backed by an OWX vault wallet.
pub struct VaultBridge<'v> {
    /// Vault handle.
    vault: &'v Vault,
    /// Wallet name or ID.
    wallet: String,
    /// Credential (passphrase or API token).
    credential: String,
    /// Account index for derivation.
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
        crate::list_wallets(self.vault)
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

    fn address(&self, network: &str) -> Result<String, Error> {
        let info = crate::get_wallet(self.vault, &self.wallet)?;
        info.accounts
            .iter()
            .find(|a| a.chain_id == network)
            .map(|a| a.address.clone())
            .ok_or_else(|| Error::InvalidInput(format!("no account for chain {network}")))
    }

    fn sign_payload(&self, _scheme: &str, network: &str, payload: &str) -> Result<String, Error> {
        let result = crate::sign_typed_data(
            self.vault,
            &self.wallet,
            network,
            payload,
            &self.credential,
            Some(self.index),
        )?;

        let sig_bytes = hex::decode(&result.signature)
            .map_err(|e| Error::Signing(format!("invalid sig hex: {e}")))?;

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
