#![allow(clippy::missing_docs_in_private_items)]

//! Wallet CRUD operations: create, import, export, delete.

use owx_core::chain::{ALL_CHAIN_TYPES, default_chain_for_type};
use owx_core::wallet_file::{EncryptedWallet, WalletAccount};
use owx_vault::crypto;
use owx_vault::store::Vault;
use zeroize::Zeroize;

use crate::derivation;
use crate::error::OwxError;
use crate::wallet_secret::{WalletSecret, decrypt_wallet_secret};

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

/// Convert an encrypted wallet to a public-facing info struct.
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

fn encrypt_wallet_secret(
    secret: WalletSecret,
    passphrase: &str,
) -> Result<serde_json::Value, OwxError> {
    let mut secret_bytes = secret.into_bytes()?;
    let envelope = crypto::encrypt(&secret_bytes, passphrase)?;
    secret_bytes.zeroize();
    serde_json::to_value(&envelope).map_err(OwxError::from)
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
    let secret = WalletSecret::mnemonic(phrase.to_owned());
    let key_type = secret.key_type();
    let crypto_json = encrypt_wallet_secret(secret, passphrase)?;

    let wallet = EncryptedWallet::new(
        uuid::Uuid::new_v4().to_string(),
        name.to_owned(),
        accounts,
        crypto_json,
        key_type,
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
    let secret = WalletSecret::mnemonic(mnemonic_phrase.to_owned());
    let key_type = secret.key_type();
    let crypto_json = encrypt_wallet_secret(secret, passphrase)?;

    let wallet = EncryptedWallet::new(
        uuid::Uuid::new_v4().to_string(),
        name.to_owned(),
        accounts,
        crypto_json,
        key_type,
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

/// Import a wallet from a hex-encoded private key.
///
/// Stores a dual-curve key pair: the provided key for its curve, plus a random
/// key for the other curve so all chain families are addressable.
pub fn import_private_key(
    vault: &Vault,
    name: &str,
    private_key_hex: &str,
    chain: &str,
    passphrase: &str,
) -> Result<WalletInfo, OwxError> {
    if vault.wallet_name_exists(name)? {
        return Err(OwxError::Vault(owx_vault::VaultError::WalletNameExists(
            name.to_owned(),
        )));
    }

    let chain_info = owx_core::parse_chain(chain).map_err(OwxError::InvalidInput)?;
    let trimmed = private_key_hex
        .strip_prefix("0x")
        .unwrap_or(private_key_hex);
    let key_bytes = hex::decode(trimmed)
        .map_err(|e| OwxError::InvalidInput(format!("invalid hex private key: {e}")))?;

    let secret = WalletSecret::private_key(chain_info.chain_type, hex::encode(&key_bytes));
    let key_type = secret.key_type();

    let mut accounts = Vec::new();
    for ct in &ALL_CHAIN_TYPES {
        if secret.supports_chain(*ct) {
            let default = default_chain_for_type(*ct);
            let address = derivation::derive_address_from_key(*ct, &key_bytes)?;
            accounts.push(WalletAccount {
                account_id: format!("{}:{address}", default.chain_id),
                address,
                chain_id: default.chain_id.to_owned(),
                derivation_path: String::new(),
            });
        }
    }

    let crypto_json = encrypt_wallet_secret(secret, passphrase)?;

    let wallet = EncryptedWallet::new(
        uuid::Uuid::new_v4().to_string(),
        name.to_owned(),
        accounts,
        crypto_json,
        key_type,
    );

    vault.save_wallet(&wallet)?;
    Ok(wallet_to_info(&wallet))
}

/// Rename a wallet.
pub fn rename_wallet(vault: &Vault, name_or_id: &str, new_name: &str) -> Result<(), OwxError> {
    vault.rename_wallet(name_or_id, new_name)?;
    Ok(())
}

/// Derive an address from a mnemonic for a specific chain.
pub fn derive_address(
    mnemonic_phrase: &str,
    chain: &str,
    index: Option<u32>,
) -> Result<String, OwxError> {
    let chain_info = owx_core::parse_chain(chain).map_err(OwxError::InvalidInput)?;
    let accounts = derivation::derive_all_accounts(mnemonic_phrase, index.unwrap_or(0))?;
    accounts
        .iter()
        .find(|a| a.chain_id == chain_info.chain_id)
        .map(|a| a.address.clone())
        .ok_or_else(|| {
            OwxError::InvalidInput(format!("no account for chain {}", chain_info.chain_id))
        })
}

/// Export a wallet's secret.
///
/// Mnemonic wallets return the phrase. Private key wallets return JSON with both keys.
pub fn export_wallet(
    vault: &Vault,
    name_or_id: &str,
    passphrase: &str,
) -> Result<WalletSecret, OwxError> {
    let wallet = vault.load_wallet(name_or_id)?;
    decrypt_wallet_secret(&wallet, passphrase)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
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
        assert_eq!(exported.phrase(), Some(TEST_MNEMONIC));
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

    #[test]
    fn import_private_key_evm() {
        let (_dir, vault) = temp_vault();
        let key_hex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let info = import_private_key(&vault, "pk-wallet", key_hex, "ethereum", "pass").unwrap();
        assert_eq!(info.name, "pk-wallet");
        assert_eq!(info.accounts.len(), 2);

        let evm = info
            .accounts
            .iter()
            .find(|a| a.chain_id.starts_with("eip155:"))
            .unwrap();
        assert!(evm.address.starts_with("0x"));
        assert!(evm.derivation_path.is_empty());
        assert!(
            info.accounts
                .iter()
                .all(|a| !a.chain_id.starts_with("solana:"))
        );

        let exported = export_wallet(&vault, "pk-wallet", "pass").unwrap();
        assert!(matches!(
            exported,
            WalletSecret::PrivateKeys {
                secp256k1: Some(_),
                ed25519: None,
            }
        ));
    }

    #[test]
    fn rename_wallet_works() {
        let (_dir, vault) = temp_vault();
        create_wallet(&vault, "old-name", "p", 12).unwrap();
        rename_wallet(&vault, "old-name", "new-name").unwrap();

        assert!(get_wallet(&vault, "new-name").is_ok());
        assert!(get_wallet(&vault, "old-name").is_err());
    }

    #[test]
    fn rename_to_existing_name_fails() {
        let (_dir, vault) = temp_vault();
        create_wallet(&vault, "a", "p", 12).unwrap();
        create_wallet(&vault, "b", "p", 12).unwrap();
        assert!(rename_wallet(&vault, "a", "b").is_err());
    }

    #[test]
    fn derive_address_works() {
        let addr = derive_address(TEST_MNEMONIC, "ethereum", Some(0)).unwrap();
        assert!(addr.starts_with("0x"));
        assert_eq!(addr.len(), 42);
    }
}
