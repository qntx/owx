//! Wallet CRUD operations: create, import, export, delete, derive.

use owx_core::chain::{ALL_CHAIN_TYPES, ChainType, default_chain_for_type};
use owx_core::wallet_file::{EncryptedWallet, WalletAccount};
use owx_core::{AccountInfo, WalletInfo};
use owx_vault::Vault;
use owx_vault::crypto;
use zeroize::Zeroize;

use crate::derivation;
use crate::error::OwxError;
use crate::secret::{WalletSecret, decrypt_wallet_secret};

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

/// Encrypt a wallet secret with a passphrase and return the JSON envelope.
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
            let chain_id = default.chain_id.into_owned();
            let address = derivation::derive_address_from_key(*ct, &key_bytes)?;
            accounts.push(WalletAccount {
                account_id: format!("{chain_id}:{address}"),
                address,
                chain_id,
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

/// Import a wallet from explicit per-curve hex-encoded private keys.
///
/// Both keys are stored so all chain families are addressable.
/// Either key may be `None`, in which case the corresponding chains are unavailable.
pub fn import_private_keys(
    vault: &Vault,
    name: &str,
    secp256k1_hex: Option<&str>,
    ed25519_hex: Option<&str>,
    passphrase: &str,
) -> Result<WalletInfo, OwxError> {
    fn decode_hex_key(hex_str: &str) -> Result<Vec<u8>, OwxError> {
        let trimmed = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        hex::decode(trimmed)
            .map_err(|e| OwxError::InvalidInput(format!("invalid hex private key: {e}")))
    }

    if secp256k1_hex.is_none() && ed25519_hex.is_none() {
        return Err(OwxError::InvalidInput(
            "at least one private key must be provided".into(),
        ));
    }
    if vault.wallet_name_exists(name)? {
        return Err(OwxError::Vault(owx_vault::VaultError::WalletNameExists(
            name.to_owned(),
        )));
    }

    let secp = secp256k1_hex.map(decode_hex_key).transpose()?;
    let ed = ed25519_hex.map(decode_hex_key).transpose()?;

    let secret = WalletSecret::PrivateKeys {
        secp256k1: secp.as_ref().map(hex::encode),
        ed25519: ed.as_ref().map(hex::encode),
    };
    let key_type = secret.key_type();

    let mut accounts = Vec::new();
    for ct in &ALL_CHAIN_TYPES {
        if secret.supports_chain(*ct) {
            let default = default_chain_for_type(*ct);
            let chain_id = default.chain_id.into_owned();
            let key_bytes = match ct {
                ChainType::Evm | ChainType::Bitcoin => secp.as_deref(),
                ChainType::Solana => ed.as_deref(),
            };
            if let Some(kb) = key_bytes {
                let address = derivation::derive_address_from_key(*ct, kb)?;
                accounts.push(WalletAccount {
                    account_id: format!("{chain_id}:{address}"),
                    address,
                    chain_id,
                    derivation_path: String::new(),
                });
            }
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

/// Generate a new BIP-39 mnemonic phrase.
pub fn generate_mnemonic(words: u32) -> Result<String, OwxError> {
    let w = match words {
        12 | 24 => words as usize,
        _ => return Err(OwxError::InvalidInput("words must be 12 or 24".into())),
    };
    let wallet =
        kobe::Wallet::generate(w, None).map_err(|e| OwxError::Derivation(e.to_string()))?;
    Ok(wallet.mnemonic().to_owned())
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

/// Export a wallet's secret as a string.
///
/// Mnemonic wallets return the phrase. Private key wallets return JSON `{"secp256k1":"hex","ed25519":"hex"}`.
pub fn export_wallet(
    vault: &Vault,
    name_or_id: &str,
    passphrase: &str,
) -> Result<String, OwxError> {
    let wallet = vault.load_wallet(name_or_id)?;
    let secret = decrypt_wallet_secret(&wallet, passphrase)?;
    secret.export_string()
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
        assert!(exported.contains("secp256k1"));
        assert!(!exported.contains("ed25519"));
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

    #[test]
    fn generate_mnemonic_12_words() {
        let phrase = generate_mnemonic(12).unwrap();
        assert_eq!(phrase.split_whitespace().count(), 12);
    }

    #[test]
    fn generate_mnemonic_24_words() {
        let phrase = generate_mnemonic(24).unwrap();
        assert_eq!(phrase.split_whitespace().count(), 24);
    }

    #[test]
    fn generate_mnemonic_invalid_words() {
        assert!(generate_mnemonic(15).is_err());
    }

    #[test]
    fn import_dual_keys_all_chains() {
        let (_dir, vault) = temp_vault();
        let secp = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let ed = "1".repeat(64);
        let info = import_private_keys(&vault, "dual", Some(secp), Some(&ed), "pass").unwrap();
        assert_eq!(info.accounts.len(), 3);
        assert!(
            info.accounts
                .iter()
                .any(|a| a.chain_id.starts_with("eip155:"))
        );
        assert!(
            info.accounts
                .iter()
                .any(|a| a.chain_id.starts_with("solana:"))
        );
        assert!(
            info.accounts
                .iter()
                .any(|a| a.chain_id.starts_with("bip122:"))
        );
    }

    #[test]
    fn import_keys_secp_only() {
        let (_dir, vault) = temp_vault();
        let secp = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let info = import_private_keys(&vault, "secp-only", Some(secp), None, "pass").unwrap();
        assert_eq!(info.accounts.len(), 2);
        assert!(
            info.accounts
                .iter()
                .all(|a| !a.chain_id.starts_with("solana:"))
        );
    }

    #[test]
    fn import_keys_no_keys_fails() {
        let (_dir, vault) = temp_vault();
        assert!(import_private_keys(&vault, "none", None, None, "pass").is_err());
    }
}
