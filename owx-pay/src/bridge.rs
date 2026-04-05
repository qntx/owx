//! Wallet bridge trait and OWX-backed implementation.

use owx::Owx;
use owx::chain::ChainFamily;
use zeroize::Zeroizing;

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

/// Concrete [`WalletBridge`] backed by an [`Owx`] instance.
pub struct OwxBridge<'a> {
    owx: &'a Owx,
    wallet: String,
    credential: Zeroizing<String>,
    index: u32,
}

impl std::fmt::Debug for OwxBridge<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwxBridge")
            .field("wallet", &self.wallet)
            .field("index", &self.index)
            .finish()
    }
}

impl<'a> OwxBridge<'a> {
    /// Create a new bridge.
    pub fn new(
        owx: &'a Owx,
        wallet: impl Into<String>,
        credential: impl Into<String>,
        index: u32,
    ) -> Self {
        Self {
            owx,
            wallet: wallet.into(),
            credential: Zeroizing::new(credential.into()),
            index,
        }
    }
}

impl WalletBridge for OwxBridge<'_> {
    fn supported_families(&self) -> Vec<ChainFamily> {
        self.owx
            .get_wallet(&self.wallet)
            .ok()
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
        let info = self.owx.get_wallet(&self.wallet)?;
        if let Some(a) = info.accounts.iter().find(|a| a.chain_id == network) {
            return Ok(a.address.clone());
        }
        let ns = network.split_once(':').map_or(network, |(ns, _)| ns);
        info.accounts
            .iter()
            .find(|a| a.chain_id.starts_with(ns))
            .map(|a| a.address.clone())
            .ok_or_else(|| owx::Error::InvalidInput(format!("no account for chain {network}")))
    }

    fn sign_payload(
        &self,
        _scheme: &str,
        network: &str,
        payload: &str,
    ) -> Result<String, owx::Error> {
        let cred = owx::Credential::parse(&self.credential);
        let result = self
            .owx
            .sign_typed_data(&self.wallet, network, payload, cred)?;
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
