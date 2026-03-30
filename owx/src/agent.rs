//! The main [`AgentWallet`] orchestration type.

#![allow(missing_docs)]
#![allow(clippy::missing_docs_in_private_items)]

use owx_vault::store::Vault;

use crate::error::OwxError;
use crate::services::{ApiKeyService, SigningService, WalletService};

/// Agent-native, self-custodial, policy-gated, multi-chain wallet.
///
/// This is the primary entry point for the OWX library. It wraps a [`Vault`]
/// and provides high-level operations for wallet management, signing, and
/// API key delegation.
#[derive(Debug)]
pub struct AgentWallet {
    /// Underlying vault for encrypted storage.
    vault: Vault,
}

impl AgentWallet {
    /// Open an agent wallet backed by a vault at the given path.
    pub fn open(vault_path: impl Into<std::path::PathBuf>) -> Result<Self, OwxError> {
        let vault = Vault::open(vault_path)?;
        Ok(Self { vault })
    }

    /// Open the default agent wallet (`~/.owx`).
    pub fn open_default() -> Result<Self, OwxError> {
        let vault = Vault::open_default()?;
        Ok(Self { vault })
    }

    /// Get a reference to the underlying vault.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) const fn vault(&self) -> &Vault {
        &self.vault
    }

    #[must_use]
    pub const fn wallets(&self) -> WalletService<'_> {
        WalletService::new(&self.vault)
    }

    #[must_use]
    pub const fn api_keys(&self) -> ApiKeyService<'_> {
        ApiKeyService::new(&self.vault)
    }

    #[must_use]
    pub const fn signing(&self) -> SigningService<'_> {
        SigningService::new(&self.vault)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn temp_agent() -> (tempfile::TempDir, AgentWallet) {
        let dir = tempfile::tempdir().unwrap();
        let agent = AgentWallet::open(dir.path()).unwrap();
        (dir, agent)
    }

    #[test]
    fn full_lifecycle() {
        let (_dir, agent) = temp_agent();

        let info = agent.wallets().create("my-wallet", "pass", 12).unwrap();
        assert_eq!(info.name, "my-wallet");
        assert_eq!(info.accounts.len(), 3);

        let wallets = agent.wallets().list().unwrap();
        assert_eq!(wallets.len(), 1);

        agent.wallets().delete("my-wallet").unwrap();
        assert!(agent.wallets().list().unwrap().is_empty());
    }

    #[test]
    fn import_sign_export() {
        let (_dir, agent) = temp_agent();

        agent
            .wallets()
            .import_mnemonic("w", TEST_MNEMONIC, "pass", 0)
            .unwrap();

        let sig = agent
            .signing()
            .sign_message("w", "ethereum", b"hello", "pass", None)
            .unwrap();
        assert!(!sig.signature.is_empty());

        let exported = agent.wallets().export("w", "pass").unwrap();
        assert_eq!(exported.phrase(), Some(TEST_MNEMONIC));
    }

    #[test]
    fn api_key_flow() {
        let (_dir, agent) = temp_agent();

        let info = agent
            .wallets()
            .import_mnemonic("w", TEST_MNEMONIC, "pass", 0)
            .unwrap();
        let wallet_id = info.id;

        let result = agent
            .api_keys()
            .create("agent-key", &[wallet_id], &[], "pass", None)
            .unwrap();
        assert!(result.token.starts_with("owx_key_"));
        assert!(
            !serde_json::to_string(&result.key)
                .unwrap()
                .contains("wallet_secrets")
        );

        let sig = agent
            .signing()
            .sign_message("w", "ethereum", b"hello", &result.token, None)
            .unwrap();
        assert!(!sig.signature.is_empty());

        agent.api_keys().revoke(&result.key.id).unwrap();
    }

    #[test]
    fn private_key_wallet_signs_messages() {
        let (_dir, agent) = temp_agent();

        agent
            .wallets()
            .import_private_key(
                "pk",
                "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
                "ethereum",
                "pass",
            )
            .unwrap();

        let sig = agent
            .signing()
            .sign_message("pk", "ethereum", b"hello", "pass", None)
            .unwrap();
        assert!(!sig.signature.is_empty());
    }

    #[test]
    fn transaction_signing_returns_signed_tx() {
        let (_dir, agent) = temp_agent();

        agent
            .wallets()
            .import_mnemonic("w", TEST_MNEMONIC, "pass", 0)
            .unwrap();

        let result = agent
            .signing()
            .sign_transaction(
                "w",
                "ethereum",
                "02df018001018252089400000000000000000000000000000000000000008080c0",
                "pass",
                None,
            )
            .unwrap();
        assert!(!result.signature.is_empty());
        assert!(!result.signed_tx.is_empty());
        assert!(result.tx_hash.starts_with("0x"));
    }
}
