//! Wallet types and CRUD operations.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::Owx;
use crate::chain::{ALL_FAMILIES, default_chain};
use crate::error::Error;
use crate::secret::{WalletSecret, decrypt_secret};
use crate::signer;

/// Type of key material stored in the ciphertext.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    /// BIP-39 mnemonic phrase.
    Mnemonic,
    /// Multi-curve key pair (`{"secp256k1":"hex","ed25519":"hex"}`).
    PrivateKey,
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
    /// BIP-44 derivation path (`None` for imported keys).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derivation_path: Option<String>,
}

/// The full on-disk wallet file (extended keystore v2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedWallet {
    /// Format version (always 2 for new wallets).
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
    /// Encrypted key material ([`owx_vault::CryptoEnvelope`] as JSON).
    pub crypto: serde_json::Value,
    /// Type of key material stored in the ciphertext.
    pub key_type: KeyType,
    /// Optional metadata.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub metadata: serde_json::Value,
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

/// Public wallet information (no secret material exposed).
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
    /// BIP-44 derivation path (`None` for imported keys).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derivation_path: Option<String>,
}

/// Generate a new BIP-39 mnemonic phrase.
pub fn generate_mnemonic(words: usize) -> Result<String, Error> {
    let wallet =
        kobe::Wallet::generate(words, None).map_err(|e| Error::Derivation(e.to_string()))?;
    Ok(wallet.mnemonic().to_owned())
}

/// Create a new wallet: generate mnemonic, derive all-chain accounts, encrypt, store.
pub fn create_wallet(
    owx: &Owx,
    name: &str,
    passphrase: &str,
    words: usize,
) -> Result<WalletInfo, Error> {
    ensure_name_available(owx, name)?;
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
    owx.store().save("wallets", &wallet.id, &wallet)?;
    Ok(to_info(&wallet))
}

/// Import a wallet from an existing mnemonic phrase.
pub fn import_mnemonic(
    owx: &Owx,
    name: &str,
    mnemonic_phrase: &str,
    passphrase: &str,
    index: u32,
) -> Result<WalletInfo, Error> {
    ensure_name_available(owx, name)?;
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
    owx.store().save("wallets", &wallet.id, &wallet)?;
    Ok(to_info(&wallet))
}

/// Import a wallet from a single hex-encoded private key.
///
/// The `chain` parameter determines which curve the key belongs to
/// (default: secp256k1). A random 32-byte key is generated for the other
/// curve so all chain families get an address.
pub fn import_private_key(
    owx: &Owx,
    name: &str,
    private_key_hex: &str,
    chain: Option<&str>,
    passphrase: &str,
    secp256k1_hex: Option<&str>,
    ed25519_hex: Option<&str>,
) -> Result<WalletInfo, Error> {
    ensure_name_available(owx, name)?;

    let (secp_bytes, ed_bytes) =
        resolve_key_pair(private_key_hex, chain, secp256k1_hex, ed25519_hex)?;
    validate_key_len(&secp_bytes, "secp256k1")?;
    validate_key_len(&ed_bytes, "ed25519")?;

    let secret = WalletSecret::key_pair(hex::encode(&secp_bytes), hex::encode(&ed_bytes));
    let accounts = derive_accounts_from_secret(&secret)?;
    let crypto_json = encrypt_secret(&secret, passphrase)?;
    let wallet = EncryptedWallet::new(
        uuid::Uuid::new_v4().to_string(),
        name.to_owned(),
        accounts,
        crypto_json,
        secret.key_type(),
    );
    owx.store().save("wallets", &wallet.id, &wallet)?;
    Ok(to_info(&wallet))
}

/// Import a wallet from explicit dual-curve private keys.
pub fn import_private_keys(
    owx: &Owx,
    name: &str,
    secp256k1_hex: &str,
    ed25519_hex: &str,
    passphrase: &str,
) -> Result<WalletInfo, Error> {
    ensure_name_available(owx, name)?;

    let secp_bytes = decode_hex_key(secp256k1_hex)?;
    let ed_bytes = decode_hex_key(ed25519_hex)?;
    validate_key_len(&secp_bytes, "secp256k1")?;
    validate_key_len(&ed_bytes, "ed25519")?;

    let secret = WalletSecret::key_pair(hex::encode(&secp_bytes), hex::encode(&ed_bytes));
    let accounts = derive_accounts_from_secret(&secret)?;
    let crypto_json = encrypt_secret(&secret, passphrase)?;
    let wallet = EncryptedWallet::new(
        uuid::Uuid::new_v4().to_string(),
        name.to_owned(),
        accounts,
        crypto_json,
        secret.key_type(),
    );
    owx.store().save("wallets", &wallet.id, &wallet)?;
    Ok(to_info(&wallet))
}

/// List all wallets (newest first).
pub fn list_wallets(owx: &Owx) -> Result<Vec<WalletInfo>, Error> {
    let mut wallets: Vec<EncryptedWallet> = owx.store().list("wallets")?;
    wallets.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(wallets.iter().map(to_info).collect())
}

/// Get a wallet by name or ID.
pub fn get_wallet(owx: &Owx, name_or_id: &str) -> Result<WalletInfo, Error> {
    Ok(to_info(&load_wallet(owx, name_or_id)?))
}

/// Delete a wallet.
pub fn delete_wallet(owx: &Owx, name_or_id: &str) -> Result<(), Error> {
    let w = load_wallet(owx, name_or_id)?;
    owx.store().delete("wallets", &w.id)?;
    Ok(())
}

/// Rename a wallet.
pub fn rename_wallet(owx: &Owx, name_or_id: &str, new_name: &str) -> Result<(), Error> {
    let mut wallet = load_wallet(owx, name_or_id)?;
    if wallet.name == new_name {
        return Ok(());
    }
    ensure_name_available(owx, new_name)?;
    new_name.clone_into(&mut wallet.name);
    owx.store().save("wallets", &wallet.id, &wallet)?;
    Ok(())
}

/// Export a wallet's secret (mnemonic phrase or JSON key pair).
pub fn export_wallet(owx: &Owx, name_or_id: &str, passphrase: &str) -> Result<String, Error> {
    let wallet = load_wallet(owx, name_or_id)?;
    let secret = decrypt_secret(&wallet, passphrase)?;
    secret.export_string()
}

/// Derive an address for a specific chain from a wallet.
pub fn derive_address(
    owx: &Owx,
    wallet_name_or_id: &str,
    chain: &str,
    passphrase: &str,
    index: Option<u32>,
) -> Result<String, Error> {
    let resolved = crate::chain::resolve(chain)?;
    let family = resolved.family();
    let chain_id = resolved.chain_id();
    let wallet = load_wallet(owx, wallet_name_or_id)?;
    let secret = decrypt_secret(&wallet, passphrase)?;
    let idx = index.unwrap_or(0);

    if let Some(phrase) = secret.phrase() {
        let kw = kobe::Wallet::from_mnemonic(phrase, None)
            .map_err(|e| Error::Derivation(e.to_string()))?;
        let key_hex = signer::derive_private_key_hex(&kw, family, idx)?;
        signer::address_from_hex(family, &key_hex).or_else(|_| {
            let accounts = signer::derive_all_accounts(phrase, idx)?;
            accounts
                .iter()
                .find(|a| a.chain_id == chain_id)
                .map(|a| a.address.clone())
                .ok_or_else(|| Error::InvalidInput(format!("no account for chain {chain_id}")))
        })
    } else {
        let h = secret.private_key_hex(family).ok_or_else(|| {
            Error::InvalidInput(format!("no private key for chain family {family}"))
        })?;
        signer::address_from_hex(family, h)
    }
}

/// Load an encrypted wallet by name or ID (internal).
///
/// Optimized: tries direct ID lookup first (single file read), falls back
/// to listing all wallets only for name-based lookup.
pub(crate) fn load_wallet(owx: &Owx, name_or_id: &str) -> Result<EncryptedWallet, Error> {
    if let Ok(w) = owx.store().load::<EncryptedWallet>("wallets", name_or_id) {
        return Ok(w);
    }
    let wallets: Vec<EncryptedWallet> = owx.store().list("wallets")?;
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
    let bytes = secret.to_bytes()?;
    let envelope = owx_vault::crypto::encrypt(&bytes, passphrase)?;
    serde_json::to_value(&envelope).map_err(Error::from)
}

/// Derive accounts for all chain families from a [`WalletSecret`] key pair.
fn derive_accounts_from_secret(secret: &WalletSecret) -> Result<Vec<WalletAccount>, Error> {
    let mut accounts = Vec::new();
    for &fam in &ALL_FAMILIES {
        let Some(key_hex) = secret.private_key_hex(fam) else {
            continue;
        };
        let chain = default_chain(fam);
        let addr = signer::address_from_hex(fam, key_hex)?;
        accounts.push(WalletAccount {
            account_id: format!("{}:{addr}", chain.chain_id),
            address: addr,
            chain_id: chain.chain_id.to_owned(),
            derivation_path: None,
        });
    }
    Ok(accounts)
}

/// Resolve the dual-curve key pair from import parameters.
fn resolve_key_pair(
    primary_hex: &str,
    chain: Option<&str>,
    secp_override: Option<&str>,
    ed_override: Option<&str>,
) -> Result<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>), Error> {
    if let (Some(s), Some(e)) = (secp_override, ed_override) {
        return Ok((decode_hex_key(s)?, decode_hex_key(e)?));
    }

    let key_bytes = decode_hex_key(primary_hex)?;
    let is_ed25519 =
        chain.is_some_and(|c| crate::chain::resolve(c).is_ok_and(|r| r.family().is_ed25519()));

    let mut random = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(&mut *random)
        .map_err(|e| Error::InvalidInput(format!("CSPRNG failed: {e}")))?;

    if is_ed25519 {
        let secp = secp_override
            .map(decode_hex_key)
            .transpose()?
            .unwrap_or_else(|| Zeroizing::new(random.to_vec()));
        Ok((secp, key_bytes))
    } else {
        let ed = ed_override
            .map(decode_hex_key)
            .transpose()?
            .unwrap_or_else(|| Zeroizing::new(random.to_vec()));
        Ok((key_bytes, ed))
    }
}

/// Decode a hex private key (strips optional `0x` prefix).
fn decode_hex_key(hex_str: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    let clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    hex::decode(clean)
        .map(Zeroizing::new)
        .map_err(|e| Error::InvalidInput(format!("invalid hex key: {e}")))
}

/// Validate that a decoded key is exactly 32 bytes.
fn validate_key_len(bytes: &[u8], label: &str) -> Result<(), Error> {
    if bytes.len() != 32 {
        return Err(Error::InvalidInput(format!(
            "{label} key must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(())
}

/// Ensure no wallet with this name already exists.
fn ensure_name_available(owx: &Owx, name: &str) -> Result<(), Error> {
    let wallets: Vec<EncryptedWallet> = owx.store().list("wallets")?;
    if wallets.iter().any(|w| w.name == name) {
        return Err(Error::WalletNameExists(name.to_owned()));
    }
    Ok(())
}
