//! Wallet CRUD operations: create, import, export, delete.

use owx_vault::crypto;
use owx_vault::store::Vault;
use owx_vault::wallet_file::{EncryptedWallet, KeyType};

use crate::derivation;
use crate::error::OwxError;

/// Public wallet info (no secrets).
#[derive(Debug, Clone, serde::Serialize)]
pub struct WalletInfo {
    /// Wallet ID.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Derived accounts.
    pub accounts: Vec<AccountInfo>,
    /// Creation timestamp.
    pub created_at: String,
}

/// Public account info.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AccountInfo {
    /// CAIP-2 chain ID.
    pub chain_id: String,
    /// On-chain address.
    pub address: String,
    /// Derivation path used.
    pub derivation_path: String,
}

fn wallet_to_info(w: &EncryptedWallet) -> WalletInfo {
    WalletInfo {
        id: w.id.clone(),
        name: w.name.clone(),
        accounts: w
            .accounts
            .iter()
            .map(|a| AccountInfo {
                chain_id: a.chain_id.clone(),
                address: a.address.clone(),
                derivation_path: a.derivation_path.clone(),
            })
            .collect(),
        created_at: w.created_at.clone(),
    }
}

/// Create a new wallet: generate mnemonic, derive all-chain accounts, encrypt, store.
pub fn create_wallet(
    vault: &Vault,
    name: &str,
    passphrase: &str,
    words: usize,
) -> Result<WalletInfo, OwxError> {
    if vault.wallet_name_exists(name)? {
        return Err(OwxError::Vault(owx_vault::VaultError::WalletNameExists(
            name.to_owned(),
        )));
    }

    let kobe_wallet =
        kobe::Wallet::generate(words, None).map_err(|e| OwxError::Derivation(e.to_string()))?;
    let phrase = kobe_wallet.mnemonic();

    let accounts = derivation::derive_all_accounts(phrase, 0)?;
    let envelope = crypto::encrypt(phrase.as_bytes(), passphrase)?;
    let crypto_json = serde_json::to_value(&envelope)?;

    let wallet = EncryptedWallet::new(
        uuid::Uuid::new_v4().to_string(),
        name.to_owned(),
        accounts,
        crypto_json,
        KeyType::Mnemonic,
    );

    vault.save_wallet(&wallet)?;
    Ok(wallet_to_info(&wallet))
}

/// Import a wallet from an existing mnemonic phrase.
pub fn import_mnemonic(
    vault: &Vault,
    name: &str,
    mnemonic_phrase: &str,
    passphrase: &str,
    index: u32,
) -> Result<WalletInfo, OwxError> {
    if vault.wallet_name_exists(name)? {
        return Err(OwxError::Vault(owx_vault::VaultError::WalletNameExists(
            name.to_owned(),
        )));
    }

    // Validate the mnemonic by attempting derivation
    let accounts = derivation::derive_all_accounts(mnemonic_phrase, index)?;
    let envelope = crypto::encrypt(mnemonic_phrase.as_bytes(), passphrase)?;
    let crypto_json = serde_json::to_value(&envelope)?;

    let wallet = EncryptedWallet::new(
        uuid::Uuid::new_v4().to_string(),
        name.to_owned(),
        accounts,
        crypto_json,
        KeyType::Mnemonic,
    );

    vault.save_wallet(&wallet)?;
    Ok(wallet_to_info(&wallet))
}

/// List all wallets.
pub fn list_wallets(vault: &Vault) -> Result<Vec<WalletInfo>, OwxError> {
    let wallets = vault.list_wallets()?;
    Ok(wallets.iter().map(wallet_to_info).collect())
}

/// Get a single wallet by name or ID.
pub fn get_wallet(vault: &Vault, name_or_id: &str) -> Result<WalletInfo, OwxError> {
    let wallet = vault.load_wallet(name_or_id)?;
    Ok(wallet_to_info(&wallet))
}

/// Delete a wallet.
pub fn delete_wallet(vault: &Vault, name_or_id: &str) -> Result<(), OwxError> {
    let wallet = vault.load_wallet(name_or_id)?;
    vault.delete_wallet(&wallet.id)?;
    Ok(())
}

/// Export a wallet's mnemonic phrase (requires passphrase).
pub fn export_wallet(
    vault: &Vault,
    name_or_id: &str,
    passphrase: &str,
) -> Result<String, OwxError> {
    let wallet = vault.load_wallet(name_or_id)?;
    let envelope: owx_vault::CryptoEnvelope = serde_json::from_value(wallet.crypto)?;
    let secret = crypto::decrypt(&envelope, passphrase)?;

    String::from_utf8(secret.expose().to_vec())
        .map_err(|_| OwxError::InvalidInput("wallet contains invalid UTF-8".into()))
}

/// Decrypt the mnemonic from an encrypted wallet.
pub(crate) fn decrypt_mnemonic(
    wallet: &EncryptedWallet,
    credential: &str,
) -> Result<String, OwxError> {
    let envelope: owx_vault::CryptoEnvelope = serde_json::from_value(wallet.crypto.clone())?;
    let secret = crypto::decrypt(&envelope, credential)?;
    String::from_utf8(secret.expose().to_vec())
        .map_err(|_| OwxError::InvalidInput("wallet contains invalid UTF-8 mnemonic".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn temp_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        (dir, vault)
    }

    #[test]
    fn create_and_list() {
        let (_dir, vault) = temp_vault();
        let info = create_wallet(&vault, "test", "pass", 12).unwrap();
        assert_eq!(info.name, "test");
        assert_eq!(info.accounts.len(), 3);

        let wallets = list_wallets(&vault).unwrap();
        assert_eq!(wallets.len(), 1);
    }

    #[test]
    fn import_and_export() {
        let (_dir, vault) = temp_vault();
        let info = import_mnemonic(&vault, "imported", TEST_MNEMONIC, "pass", 0).unwrap();
        assert_eq!(info.accounts.len(), 3);

        let exported = export_wallet(&vault, "imported", "pass").unwrap();
        assert_eq!(exported, TEST_MNEMONIC);
    }

    #[test]
    fn export_wrong_passphrase_fails() {
        let (_dir, vault) = temp_vault();
        import_mnemonic(&vault, "w", TEST_MNEMONIC, "correct", 0).unwrap();
        assert!(export_wallet(&vault, "w", "wrong").is_err());
    }

    #[test]
    fn duplicate_name_rejected() {
        let (_dir, vault) = temp_vault();
        create_wallet(&vault, "dup", "p", 12).unwrap();
        assert!(create_wallet(&vault, "dup", "p", 12).is_err());
    }

    #[test]
    fn delete_works() {
        let (_dir, vault) = temp_vault();
        create_wallet(&vault, "del", "p", 12).unwrap();
        delete_wallet(&vault, "del").unwrap();
        assert!(list_wallets(&vault).unwrap().is_empty());
    }
}
