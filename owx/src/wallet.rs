//! Wallet types and CRUD operations.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::Vault;
use crate::chain::{ALL_FAMILIES, default_chain, resolve_chain};
use crate::error::Error;
use crate::secret::{WalletSecret, decrypt_secret};
use crate::signer;

/// The full on-disk wallet file (JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedWallet {
    /// Format version.
    #[serde(alias = "lws_version")]
    pub ows_version: u32,
    /// Unique wallet identifier (UUID v4).
    pub id: String,
    /// Human-readable wallet name.
    pub name: String,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
    /// Derived accounts across chains.
    pub accounts: Vec<WalletAccount>,
    /// Encrypted key material (a `CryptoEnvelope` as JSON value).
    pub crypto: serde_json::Value,
    /// Type of key material stored in the ciphertext.
    pub key_type: KeyType,
    /// Optional metadata.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub metadata: serde_json::Value,
}

/// An account entry within an encrypted wallet file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAccount {
    /// CAIP-10 account identifier (e.g. `eip155:1:0xabc…`).
    pub account_id: String,
    /// Address in the chain's native format.
    pub address: String,
    /// CAIP-2 chain identifier (e.g. `eip155:1`).
    pub chain_id: String,
    /// BIP-44 derivation path used.
    pub derivation_path: String,
}

/// Type of key material stored in the ciphertext.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    /// BIP-39 mnemonic phrase.
    Mnemonic,
    /// Multi-curve key pair.
    PrivateKey,
}

impl EncryptedWallet {
    /// Create a new wallet with the current timestamp and version 2.
    #[must_use]
    pub fn new(
        id: String,
        name: String,
        accounts: Vec<WalletAccount>,
        crypto: serde_json::Value,
        key_type: KeyType,
    ) -> Self {
        Self {
            ows_version: 2,
            id,
            name,
            created_at: chrono::Utc::now().to_rfc3339(),
            accounts,
            crypto,
            key_type,
            metadata: serde_json::Value::Null,
        }
    }
}

/// Public wallet information (no secret material).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletInfo {
    /// Unique wallet identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Derived accounts across chains.
    pub accounts: Vec<AccountInfo>,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
}

/// A single account within a wallet (one per chain family).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    /// CAIP-2 chain identifier.
    pub chain_id: String,
    /// Address in the chain's native format.
    pub address: String,
    /// BIP-44 derivation path used (empty for imported keys).
    pub derivation_path: String,
}

/// Convert an [`EncryptedWallet`] to the public-facing [`WalletInfo`].
fn to_info(w: &EncryptedWallet) -> WalletInfo {
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

/// Encrypt a wallet secret and return the envelope as a JSON value.
fn encrypt_secret(secret: &WalletSecret, passphrase: &str) -> Result<serde_json::Value, Error> {
    let mut bytes = secret.to_bytes()?;
    let envelope = owx_vault::crypto::encrypt(&bytes, passphrase)?;
    bytes.zeroize();
    serde_json::to_value(&envelope).map_err(Error::from)
}

/// Validate that a hex string decodes to exactly 32 bytes.
fn validate_hex_key(hex_str: &str, label: &str) -> Result<(), Error> {
    let clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes =
        hex::decode(clean).map_err(|e| Error::InvalidInput(format!("invalid {label} hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(Error::InvalidInput(format!(
            "{label} key must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(())
}

/// Generate a new BIP-39 mnemonic phrase.
pub fn generate_mnemonic(words: usize) -> Result<String, Error> {
    let wallet =
        kobe::Wallet::generate(words, None).map_err(|e| Error::Derivation(e.to_string()))?;
    Ok(wallet.mnemonic().to_owned())
}

/// Create a new wallet: generate mnemonic, derive all-chain accounts, encrypt, store.
pub fn create_wallet(
    vault: &Vault,
    name: &str,
    passphrase: &str,
    words: usize,
) -> Result<WalletInfo, Error> {
    ensure_name_available(vault, name)?;

    let kobe_wallet =
        kobe::Wallet::generate(words, None).map_err(|e| Error::Derivation(e.to_string()))?;
    let phrase = kobe_wallet.mnemonic();
    let accounts = signer::derive_all_accounts(phrase, 0)?;
    let secret = WalletSecret::mnemonic(phrase);
    let crypto_json = encrypt_secret(&secret, passphrase)?;

    let wallet = EncryptedWallet::new(
        uuid::Uuid::new_v4().to_string(),
        name.to_owned(),
        accounts,
        crypto_json,
        secret.key_type(),
    );
    vault.store().save("wallets", &wallet.id, &wallet)?;
    Ok(to_info(&wallet))
}

/// Import a wallet from an existing mnemonic phrase.
pub fn import_mnemonic(
    vault: &Vault,
    name: &str,
    mnemonic_phrase: &str,
    passphrase: &str,
    index: u32,
) -> Result<WalletInfo, Error> {
    ensure_name_available(vault, name)?;
    let accounts = signer::derive_all_accounts(mnemonic_phrase, index)?;
    let secret = WalletSecret::mnemonic(mnemonic_phrase);
    let crypto_json = encrypt_secret(&secret, passphrase)?;

    let wallet = EncryptedWallet::new(
        uuid::Uuid::new_v4().to_string(),
        name.to_owned(),
        accounts,
        crypto_json,
        secret.key_type(),
    );
    vault.store().save("wallets", &wallet.id, &wallet)?;
    Ok(to_info(&wallet))
}

/// Import a wallet from explicit dual-curve private keys.
pub fn import_private_keys(
    vault: &Vault,
    name: &str,
    secp256k1_hex: &str,
    ed25519_hex: &str,
    passphrase: &str,
) -> Result<WalletInfo, Error> {
    ensure_name_available(vault, name)?;
    validate_hex_key(secp256k1_hex, "secp256k1")?;
    validate_hex_key(ed25519_hex, "ed25519")?;
    let secret = WalletSecret::key_pair(secp256k1_hex, ed25519_hex);

    let mut accounts = Vec::new();
    for fam in &ALL_FAMILIES {
        let Some(key_hex) = secret.private_key_hex(*fam) else {
            continue;
        };
        let chain = default_chain(*fam);
        if let Ok(addr) = signer::address_from_hex(*fam, key_hex) {
            accounts.push(WalletAccount {
                account_id: format!("{}:{addr}", chain.chain_id),
                address: addr,
                chain_id: chain.chain_id,
                derivation_path: String::new(),
            });
        }
    }

    let crypto_json = encrypt_secret(&secret, passphrase)?;
    let wallet = EncryptedWallet::new(
        uuid::Uuid::new_v4().to_string(),
        name.to_owned(),
        accounts,
        crypto_json,
        secret.key_type(),
    );
    vault.store().save("wallets", &wallet.id, &wallet)?;
    Ok(to_info(&wallet))
}

/// List all wallets.
pub fn list_wallets(vault: &Vault) -> Result<Vec<WalletInfo>, Error> {
    let mut wallets: Vec<EncryptedWallet> = vault.store().list("wallets")?;
    wallets.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(wallets.iter().map(to_info).collect())
}

/// Get a wallet by name or ID.
pub fn get_wallet(vault: &Vault, name_or_id: &str) -> Result<WalletInfo, Error> {
    Ok(to_info(&load_wallet(vault, name_or_id)?))
}

/// Delete a wallet.
pub fn delete_wallet(vault: &Vault, name_or_id: &str) -> Result<(), Error> {
    let w = load_wallet(vault, name_or_id)?;
    vault.store().delete("wallets", &w.id)?;
    Ok(())
}

/// Rename a wallet.
pub fn rename_wallet(vault: &Vault, name_or_id: &str, new_name: &str) -> Result<(), Error> {
    let mut wallet = load_wallet(vault, name_or_id)?;
    if wallet.name == new_name {
        return Ok(());
    }
    ensure_name_available(vault, new_name)?;
    new_name.clone_into(&mut wallet.name);
    vault.store().save("wallets", &wallet.id, &wallet)?;
    Ok(())
}

/// Export a wallet's secret.
pub fn export_wallet(vault: &Vault, name_or_id: &str, passphrase: &str) -> Result<String, Error> {
    let wallet = load_wallet(vault, name_or_id)?;
    let secret = decrypt_secret(&wallet, passphrase)?;
    secret.export_string()
}

/// Derive an address for a specific chain from a wallet.
pub fn derive_address(
    vault: &Vault,
    wallet_name_or_id: &str,
    chain: &str,
    passphrase: &str,
    index: Option<u32>,
) -> Result<String, Error> {
    let chain_info = resolve_chain(chain)?;
    let wallet = load_wallet(vault, wallet_name_or_id)?;
    let secret = decrypt_secret(&wallet, passphrase)?;
    let idx = index.unwrap_or(0);

    if let Some(phrase) = secret.phrase() {
        let kw = kobe::Wallet::from_mnemonic(phrase, None)
            .map_err(|e| Error::Derivation(e.to_string()))?;
        let key_hex = signer::derive_private_key_hex(&kw, chain_info.family, idx)?;
        signer::address_from_hex(chain_info.family, &key_hex).or_else(|_| {
            let accounts = signer::derive_all_accounts(phrase, idx)?;
            accounts
                .iter()
                .find(|a| a.chain_id == chain_info.chain_id)
                .map(|a| a.address.clone())
                .ok_or_else(|| {
                    Error::InvalidInput(format!("no account for chain {}", chain_info.chain_id))
                })
        })
    } else {
        let h = secret.private_key_hex(chain_info.family).ok_or_else(|| {
            Error::InvalidInput(format!(
                "no private key for chain family {}",
                chain_info.family
            ))
        })?;
        signer::address_from_hex(chain_info.family, h)
    }
}

/// Load an encrypted wallet by name or ID (internal).
pub(crate) fn load_wallet(vault: &Vault, name_or_id: &str) -> Result<EncryptedWallet, Error> {
    let wallets: Vec<EncryptedWallet> = vault.store().list("wallets")?;

    if let Some(w) = wallets.iter().find(|w| w.id == name_or_id) {
        return Ok(w.clone());
    }

    let matches: Vec<&EncryptedWallet> = wallets.iter().filter(|w| w.name == name_or_id).collect();
    match matches.len() {
        0 => Err(Error::WalletNotFound(name_or_id.to_owned())),
        1 => Ok(matches[0].clone()),
        n => Err(Error::AmbiguousWallet {
            name: name_or_id.to_owned(),
            count: n,
        }),
    }
}

/// Ensure no wallet with this name already exists.
fn ensure_name_available(vault: &Vault, name: &str) -> Result<(), Error> {
    let wallets: Vec<EncryptedWallet> = vault.store().list("wallets")?;
    if wallets.iter().any(|w| w.name == name) {
        return Err(Error::WalletNameExists(name.to_owned()));
    }
    Ok(())
}
