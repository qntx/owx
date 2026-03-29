//! The main [`AgentWallet`] orchestration type.

use owx_vault::store::Vault;

use crate::error::OwxError;
use crate::key_ops;
use crate::signing::{self, SignResult};
use crate::wallet_ops::{self, WalletInfo};

/// Agent-native, self-custodial, policy-gated, multi-chain wallet.
///
/// This is the primary entry point for the OWX library. It wraps a [`Vault`]
/// and provides high-level operations for wallet management, signing, and
/// API key delegation.
#[derive(Debug)]
#[non_exhaustive]
pub struct AgentWallet {
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
    #[must_use]
    pub const fn vault(&self) -> &Vault {
        &self.vault
    }

    // ── Wallet Management ──

    /// Create a new wallet with a randomly generated mnemonic.
    pub fn create_wallet(
        &self,
        name: &str,
        passphrase: &str,
        words: usize,
    ) -> Result<WalletInfo, OwxError> {
        wallet_ops::create_wallet(&self.vault, name, passphrase, words)
    }

    /// Import a wallet from an existing mnemonic phrase.
    pub fn import_mnemonic(
        &self,
        name: &str,
        mnemonic_phrase: &str,
        passphrase: &str,
        index: u32,
    ) -> Result<WalletInfo, OwxError> {
        wallet_ops::import_mnemonic(&self.vault, name, mnemonic_phrase, passphrase, index)
    }

    /// List all wallets.
    pub fn list_wallets(&self) -> Result<Vec<WalletInfo>, OwxError> {
        wallet_ops::list_wallets(&self.vault)
    }

    /// Get a single wallet by name or ID.
    pub fn get_wallet(&self, name_or_id: &str) -> Result<WalletInfo, OwxError> {
        wallet_ops::get_wallet(&self.vault, name_or_id)
    }

    /// Delete a wallet by name or ID.
    pub fn delete_wallet(&self, name_or_id: &str) -> Result<(), OwxError> {
        wallet_ops::delete_wallet(&self.vault, name_or_id)
    }

    /// Export a wallet's mnemonic (requires owner passphrase).
    pub fn export_wallet(&self, name_or_id: &str, passphrase: &str) -> Result<String, OwxError> {
        wallet_ops::export_wallet(&self.vault, name_or_id, passphrase)
    }

    // ── API Key Management ──

    /// Create an API key for agent access to wallets.
    ///
    /// Returns `(token, key_file)`. The token is shown once to the user.
    pub fn create_api_key(
        &self,
        name: &str,
        wallet_ids: &[String],
        policy_ids: &[String],
        passphrase: &str,
        expires_at: Option<&str>,
    ) -> Result<(String, owx_vault::ApiKeyFile), OwxError> {
        key_ops::create_api_key(
            &self.vault,
            name,
            wallet_ids,
            policy_ids,
            passphrase,
            expires_at,
        )
    }

    /// Revoke (delete) an API key by ID.
    pub fn revoke_api_key(&self, id: &str) -> Result<(), OwxError> {
        self.vault.delete_api_key(id)?;
        Ok(())
    }

    /// List all API keys.
    pub fn list_api_keys(&self) -> Result<Vec<owx_vault::ApiKeyFile>, OwxError> {
        let keys = self.vault.list_api_keys()?;
        Ok(keys)
    }

    // ── Signing ──

    /// Sign a message. `credential` is either a passphrase or an API token.
    pub fn sign_message(
        &self,
        wallet: &str,
        chain: &str,
        message: &[u8],
        credential: &str,
        index: Option<u32>,
    ) -> Result<SignResult, OwxError> {
        signing::sign_message(&self.vault, wallet, chain, message, credential, index)
    }

    /// Sign a hex-encoded transaction. `credential` is either a passphrase or an API token.
    pub fn sign_transaction(
        &self,
        wallet: &str,
        chain: &str,
        tx_hex: &str,
        credential: &str,
        index: Option<u32>,
    ) -> Result<SignResult, OwxError> {
        signing::sign_transaction(&self.vault, wallet, chain, tx_hex, credential, index)
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

        let info = agent.create_wallet("my-wallet", "pass", 12).unwrap();
        assert_eq!(info.name, "my-wallet");
        assert_eq!(info.accounts.len(), 3);

        let wallets = agent.list_wallets().unwrap();
        assert_eq!(wallets.len(), 1);

        agent.delete_wallet("my-wallet").unwrap();
        assert!(agent.list_wallets().unwrap().is_empty());
    }

    #[test]
    fn import_sign_export() {
        let (_dir, agent) = temp_agent();

        agent
            .import_mnemonic("w", TEST_MNEMONIC, "pass", 0)
            .unwrap();

        let sig = agent
            .sign_message("w", "ethereum", b"hello", "pass", None)
            .unwrap();
        assert!(!sig.signature.is_empty());

        let exported = agent.export_wallet("w", "pass").unwrap();
        assert_eq!(exported, TEST_MNEMONIC);
    }

    #[test]
    fn api_key_flow() {
        let (_dir, agent) = temp_agent();

        let info = agent
            .import_mnemonic("w", TEST_MNEMONIC, "pass", 0)
            .unwrap();
        let wallet_id = info.id;

        let (token, key) = agent
            .create_api_key("agent-key", &[wallet_id], &[], "pass", None)
            .unwrap();
        assert!(token.starts_with("owx_key_"));

        let sig = agent
            .sign_message("w", "ethereum", b"hello", &token, None)
            .unwrap();
        assert!(!sig.signature.is_empty());

        agent.revoke_api_key(&key.id).unwrap();
    }
}
