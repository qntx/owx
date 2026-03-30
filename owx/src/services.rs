#![allow(missing_docs)]
#![allow(clippy::missing_docs_in_private_items)]

use owx_core::{
    ApiKeyCreateResult, ApiKeyInfo, SendResult, SignResult, TransactionSignResult, WalletInfo,
};
use owx_vault::store::Vault;

use crate::broadcast;
use crate::error::OwxError;
use crate::key_ops;
use crate::signing;
use crate::wallet_ops;
use crate::wallet_secret::WalletSecret;

#[derive(Debug, Clone, Copy)]
pub struct WalletService<'a> {
    vault: &'a Vault,
}

impl<'a> WalletService<'a> {
    pub(crate) const fn new(vault: &'a Vault) -> Self {
        Self { vault }
    }

    pub fn create(
        self,
        name: &str,
        passphrase: &str,
        words: usize,
    ) -> Result<WalletInfo, OwxError> {
        wallet_ops::create_wallet(self.vault, name, passphrase, words)
    }

    pub fn import_mnemonic(
        self,
        name: &str,
        mnemonic_phrase: &str,
        passphrase: &str,
        index: u32,
    ) -> Result<WalletInfo, OwxError> {
        wallet_ops::import_mnemonic(self.vault, name, mnemonic_phrase, passphrase, index)
    }

    pub fn list(self) -> Result<Vec<WalletInfo>, OwxError> {
        wallet_ops::list_wallets(self.vault)
    }

    pub fn get(self, name_or_id: &str) -> Result<WalletInfo, OwxError> {
        wallet_ops::get_wallet(self.vault, name_or_id)
    }

    pub fn delete(self, name_or_id: &str) -> Result<(), OwxError> {
        wallet_ops::delete_wallet(self.vault, name_or_id)
    }

    pub fn export(self, name_or_id: &str, passphrase: &str) -> Result<WalletSecret, OwxError> {
        wallet_ops::export_wallet(self.vault, name_or_id, passphrase)
    }

    pub fn import_private_key(
        self,
        name: &str,
        private_key_hex: &str,
        chain: &str,
        passphrase: &str,
    ) -> Result<WalletInfo, OwxError> {
        wallet_ops::import_private_key(self.vault, name, private_key_hex, chain, passphrase)
    }

    pub fn rename(self, name_or_id: &str, new_name: &str) -> Result<(), OwxError> {
        wallet_ops::rename_wallet(self.vault, name_or_id, new_name)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ApiKeyService<'a> {
    vault: &'a Vault,
}

impl<'a> ApiKeyService<'a> {
    pub(crate) const fn new(vault: &'a Vault) -> Self {
        Self { vault }
    }

    pub fn create(
        self,
        name: &str,
        wallet_ids: &[String],
        policy_ids: &[String],
        passphrase: &str,
        expires_at: Option<&str>,
    ) -> Result<ApiKeyCreateResult, OwxError> {
        key_ops::create_api_key(
            self.vault, name, wallet_ids, policy_ids, passphrase, expires_at,
        )
    }

    pub fn revoke(self, id: &str) -> Result<(), OwxError> {
        self.vault.api_keys().delete(id)?;
        Ok(())
    }

    pub fn list(self) -> Result<Vec<ApiKeyInfo>, OwxError> {
        key_ops::list_api_keys(self.vault)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SigningService<'a> {
    vault: &'a Vault,
}

impl<'a> SigningService<'a> {
    pub(crate) const fn new(vault: &'a Vault) -> Self {
        Self { vault }
    }

    pub fn sign_message(
        self,
        wallet: &str,
        chain: &str,
        message: &[u8],
        credential: &str,
        index: Option<u32>,
    ) -> Result<SignResult, OwxError> {
        signing::sign_message(self.vault, wallet, chain, message, credential, index)
    }

    pub fn sign_transaction(
        self,
        wallet: &str,
        chain: &str,
        tx_hex: &str,
        credential: &str,
        index: Option<u32>,
    ) -> Result<TransactionSignResult, OwxError> {
        signing::sign_transaction(self.vault, wallet, chain, tx_hex, credential, index)
    }

    pub async fn sign_and_send(
        self,
        wallet: &str,
        chain: &str,
        tx_hex: &str,
        credential: &str,
        index: Option<u32>,
        rpc_url: Option<&str>,
    ) -> Result<SendResult, OwxError> {
        broadcast::sign_and_send(
            self.vault, wallet, chain, tx_hex, credential, index, rpc_url,
        )
        .await
    }
}

pub fn derive_address(
    mnemonic_phrase: &str,
    chain: &str,
    index: Option<u32>,
) -> Result<String, OwxError> {
    wallet_ops::derive_address(mnemonic_phrase, chain, index)
}
