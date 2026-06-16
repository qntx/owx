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
    ///
    /// # Errors
    ///
    /// Returns [`owx::OwxError`] if the network is unsupported or wallet lookup fails.
    fn address(&self, network: &str) -> Result<String, owx::OwxError>;
    /// Sign a payment payload for a scheme/network. Returns hex signature.
    ///
    /// # Errors
    ///
    /// Returns [`owx::OwxError`] if signing fails.
    fn sign_payload(
        &self,
        scheme: &str,
        network: &str,
        payload: &str,
    ) -> Result<String, owx::OwxError>;
}

/// Concrete [`WalletBridge`] backed by an [`Owx`] instance.
pub struct OwxBridge<'a> {
    /// Reference to the OWX orchestrator.
    owx: &'a Owx,
    /// Wallet name or ID.
    wallet: String,
    /// API token or passphrase (zeroized on drop).
    credential: Zeroizing<String>,
    /// HD derivation index.
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

    fn address(&self, network: &str) -> Result<String, owx::OwxError> {
        let info = self.owx.get_wallet(&self.wallet)?;
        if let Some(a) = info.accounts.iter().find(|a| a.chain_id == network) {
            return Ok(a.address.clone());
        }
        let ns = network.split_once(':').map_or(network, |(ns, _)| ns);
        info.accounts
            .iter()
            .find(|a| a.chain_id.starts_with(ns))
            .map(|a| a.address.clone())
            .ok_or_else(|| owx::OwxError::InvalidInput(format!("no account for chain {network}")))
    }

    fn sign_payload(
        &self,
        _scheme: &str,
        network: &str,
        payload: &str,
    ) -> Result<String, owx::OwxError> {
        let cred = owx::Credential::parse(&self.credential);
        let result = self
            .owx
            .sign_typed_data(&self.wallet, network, payload, cred)?;
        Ok(format!("0x{}", result.signature))
    }
}
