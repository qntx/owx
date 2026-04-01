//! Core wallet operations: create, import, sign, send, derive.
//!
//! All functions take a `&Vault` handle — no facade structs.

use owx_core::chain::ChainType;
use owx_core::parse_chain;
use owx_core::wallet_file::EncryptedWallet;
use owx_vault::Vault;
use owx_vault::crypto;
use zeroize::Zeroize;

use crate::chains;
use crate::error::OwxError;
use crate::secret::{WalletSecret, decrypt_secret};
use crate::types::{AccountInfo, SendResult, SignResult, WalletInfo};

fn wallet_to_info(w: &EncryptedWallet) -> WalletInfo {
    WalletInfo {
        id: w.id.clone(),
        name: w.name.clone(),
        accounts: w.accounts.iter().map(|a| AccountInfo {
            chain_id: a.chain_id.clone(),
            address: a.address.clone(),
            derivation_path: a.derivation_path.clone(),
        }).collect(),
        created_at: w.created_at.clone(),
    }
}

fn encrypt_secret(secret: &WalletSecret, passphrase: &str) -> Result<serde_json::Value, OwxError> {
    let mut bytes = secret.to_bytes()?;
    let envelope = crypto::encrypt(&bytes, passphrase)?;
    bytes.zeroize();
    serde_json::to_value(&envelope).map_err(OwxError::from)
}

/// Generate a new BIP-39 mnemonic phrase.
pub fn generate_mnemonic(words: usize) -> Result<String, OwxError> {
    let wallet = kobe::Wallet::generate(words, None)
        .map_err(|e| OwxError::Derivation(e.to_string()))?;
    Ok(wallet.mnemonic().to_owned())
}

/// Create a new wallet: generate mnemonic, derive all-chain accounts, encrypt, store.
pub fn create_wallet(
    vault: &Vault,
    name: &str,
    passphrase: &str,
    words: usize,
) -> Result<WalletInfo, OwxError> {
    if vault.wallet_name_exists(name)? {
        return Err(OwxError::Vault(owx_vault::VaultError::WalletNameExists(name.to_owned())));
    }

    let kobe_wallet = kobe::Wallet::generate(words, None)
        .map_err(|e| OwxError::Derivation(e.to_string()))?;
    let phrase = kobe_wallet.mnemonic();
    let accounts = chains::derive_all_accounts(phrase, 0)?;
    let secret = WalletSecret::mnemonic(phrase);
    let crypto_json = encrypt_secret(&secret, passphrase)?;

    let wallet = EncryptedWallet::new(
        uuid::Uuid::new_v4().to_string(),
        name.to_owned(),
        accounts,
        crypto_json,
        secret.key_type(),
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
        return Err(OwxError::Vault(owx_vault::VaultError::WalletNameExists(name.to_owned())));
    }
    let accounts = chains::derive_all_accounts(mnemonic_phrase, index)?;
    let secret = WalletSecret::mnemonic(mnemonic_phrase);
    let crypto_json = encrypt_secret(&secret, passphrase)?;

    let wallet = EncryptedWallet::new(
        uuid::Uuid::new_v4().to_string(),
        name.to_owned(),
        accounts,
        crypto_json,
        secret.key_type(),
    );
    vault.save_wallet(&wallet)?;
    Ok(wallet_to_info(&wallet))
}

/// Import a wallet from explicit dual-curve private keys.
pub fn import_private_keys(
    vault: &Vault,
    name: &str,
    secp256k1_hex: &str,
    ed25519_hex: &str,
    passphrase: &str,
) -> Result<WalletInfo, OwxError> {
    if vault.wallet_name_exists(name)? {
        return Err(OwxError::Vault(owx_vault::VaultError::WalletNameExists(name.to_owned())));
    }
    let secret = WalletSecret::dual_keys(secp256k1_hex.to_owned(), ed25519_hex.to_owned());

    let mut accounts = Vec::new();
    for ct in &owx_core::chain::ALL_CHAIN_TYPES {
        if let Some(key_hex) = secret.private_key_hex(*ct) {
            let chain = owx_core::chain::default_chain_for_type(*ct);
            let addr = derive_address_from_hex(*ct, key_hex)?;
            accounts.push(owx_core::wallet_file::WalletAccount {
                account_id: format!("{}:{addr}", chain.chain_id),
                address: addr,
                chain_id: chain.chain_id.to_owned(),
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
    vault.save_wallet(&wallet)?;
    Ok(wallet_to_info(&wallet))
}

/// Derive an address from a hex private key for a given chain type.
fn derive_address_from_hex(ct: ChainType, key_hex: &str) -> Result<String, OwxError> {
    match ct {
        ChainType::Evm => {
            let s = signer::evm::Signer::from_hex(key_hex)
                .map_err(|e| OwxError::Derivation(e.to_string()))?;
            Ok(s.address())
        }
        ChainType::Solana => {
            let s = signer::svm::Signer::from_hex(key_hex)
                .map_err(|e| OwxError::Derivation(e.to_string()))?;
            Ok(s.address())
        }
        ChainType::Sui => {
            let s = signer::sui::Signer::from_hex(key_hex)
                .map_err(|e| OwxError::Derivation(e.to_string()))?;
            Ok(s.address())
        }
        _ => Err(OwxError::InvalidInput(format!(
            "address derivation from private key not supported for {ct} — use mnemonic import"
        ))),
    }
}

/// List all wallets.
pub fn list_wallets(vault: &Vault) -> Result<Vec<WalletInfo>, OwxError> {
    Ok(vault.list_wallets()?.iter().map(wallet_to_info).collect())
}

/// Get a wallet by name or ID.
pub fn get_wallet(vault: &Vault, name_or_id: &str) -> Result<WalletInfo, OwxError> {
    Ok(wallet_to_info(&vault.load_wallet(name_or_id)?))
}

/// Delete a wallet.
pub fn delete_wallet(vault: &Vault, name_or_id: &str) -> Result<(), OwxError> {
    let w = vault.load_wallet(name_or_id)?;
    vault.delete_wallet(&w.id)?;
    Ok(())
}

/// Rename a wallet.
pub fn rename_wallet(vault: &Vault, name_or_id: &str, new_name: &str) -> Result<(), OwxError> {
    vault.rename_wallet(name_or_id, new_name)?;
    Ok(())
}

/// Export a wallet's secret.
pub fn export_wallet(vault: &Vault, name_or_id: &str, passphrase: &str) -> Result<String, OwxError> {
    let wallet = vault.load_wallet(name_or_id)?;
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
) -> Result<String, OwxError> {
    let chain_info = parse_chain(chain).map_err(OwxError::InvalidInput)?;
    let wallet = vault.load_wallet(wallet_name_or_id)?;
    let secret = decrypt_secret(&wallet, passphrase)?;
    let idx = index.unwrap_or(0);

    match secret.phrase() {
        Some(phrase) => {
            let kw = kobe::Wallet::from_mnemonic(phrase, None)
                .map_err(|e| OwxError::Derivation(e.to_string()))?;
            let key_hex = chains::derive_private_key_hex(&kw, chain_info.chain_type, idx)?;
            derive_address_from_hex(chain_info.chain_type, &key_hex)
                .or_else(|_| {
                    let accounts = chains::derive_all_accounts(phrase, idx)?;
                    accounts.iter()
                        .find(|a| a.chain_id == chain_info.chain_id)
                        .map(|a| a.address.clone())
                        .ok_or_else(|| OwxError::InvalidInput(format!("no account for chain {}", chain_info.chain_id)))
                })
        }
        None => {
            let h = secret.private_key_hex(chain_info.chain_type)
                .ok_or_else(|| OwxError::InvalidInput(format!(
                    "no private key for chain type {}", chain_info.chain_type
                )))?;
            derive_address_from_hex(chain_info.chain_type, h)
        }
    }
}

/// Sign a message.
pub fn sign_message(
    vault: &Vault,
    wallet_name_or_id: &str,
    chain: &str,
    message: &[u8],
    credential: &str,
    index: Option<u32>,
) -> Result<SignResult, OwxError> {
    let chain_info = parse_chain(chain).map_err(OwxError::InvalidInput)?;
    let idx = index.unwrap_or(0);
    let key_hex = resolve_signing_key(vault, wallet_name_or_id, credential, chain_info.chain_type, idx)?;
    chains::sign_message_hex(chain_info.chain_type, &key_hex, message)
}

/// Sign a transaction (hex-encoded).
pub fn sign_transaction(
    vault: &Vault,
    wallet_name_or_id: &str,
    chain: &str,
    tx_hex: &str,
    credential: &str,
    index: Option<u32>,
) -> Result<SignResult, OwxError> {
    let chain_info = parse_chain(chain).map_err(OwxError::InvalidInput)?;
    let tx_hex_clean = tx_hex.strip_prefix("0x").unwrap_or(tx_hex);
    let tx_bytes = hex::decode(tx_hex_clean)
        .map_err(|e| OwxError::InvalidInput(format!("invalid hex: {e}")))?;
    let idx = index.unwrap_or(0);
    let key_hex = resolve_signing_key(vault, wallet_name_or_id, credential, chain_info.chain_type, idx)?;
    chains::sign_transaction_hex(chain_info.chain_type, &key_hex, &tx_bytes)
}

/// Sign a transaction and broadcast it.
pub fn sign_and_send(
    vault: &Vault,
    wallet_name_or_id: &str,
    chain: &str,
    tx_hex: &str,
    credential: &str,
    index: Option<u32>,
    rpc_url: Option<&str>,
) -> Result<SendResult, OwxError> {
    let chain_info = parse_chain(chain).map_err(OwxError::InvalidInput)?;
    let tx_hex_clean = tx_hex.strip_prefix("0x").unwrap_or(tx_hex);
    let tx_bytes = hex::decode(tx_hex_clean)
        .map_err(|e| OwxError::InvalidInput(format!("invalid hex: {e}")))?;
    let idx = index.unwrap_or(0);
    let key_hex = resolve_signing_key(vault, wallet_name_or_id, credential, chain_info.chain_type, idx)?;

    let sig_result = chains::sign_transaction_hex(chain_info.chain_type, &key_hex, &tx_bytes)?;
    let sig_bytes = hex::decode(&sig_result.signature)
        .map_err(|e| OwxError::Signing(format!("invalid sig hex: {e}")))?;

    let rpc = resolve_rpc(chain_info.chain_id, chain_info.chain_type, rpc_url)?;

    match chain_info.chain_type {
        ChainType::Evm => {
            let signed_tx = chains::encode_signed_evm_tx(&tx_bytes, &sig_bytes)?;
            let hex_tx = format!("0x{}", hex::encode(&signed_tx));
            let body = serde_json::json!({
                "jsonrpc": "2.0", "method": "eth_sendRawTransaction",
                "params": [hex_tx], "id": 1
            });
            let resp = curl_post_json(&rpc, &body.to_string())?;
            extract_json_field(&resp, "result").map(|h| SendResult { tx_hash: h })
        }
        _ => Err(OwxError::BroadcastFailed(format!(
            "broadcast not yet implemented for {}", chain_info.chain_type
        ))),
    }
}

/// Resolve the hex private key for signing from a vault wallet + credential.
fn resolve_signing_key(
    vault: &Vault,
    wallet_name_or_id: &str,
    credential: &str,
    ct: ChainType,
    index: u32,
) -> Result<String, OwxError> {
    // TODO: API token (owx_key_...) path with policy evaluation
    let wallet = vault.load_wallet(wallet_name_or_id)?;
    let secret = decrypt_secret(&wallet, credential)?;

    match secret.phrase() {
        Some(phrase) => {
            let kw = kobe::Wallet::from_mnemonic(phrase, None)
                .map_err(|e| OwxError::Derivation(e.to_string()))?;
            chains::derive_private_key_hex(&kw, ct, index)
        }
        None => {
            secret.private_key_hex(ct)
                .map(|h| h.to_owned())
                .ok_or_else(|| OwxError::InvalidInput(format!(
                    "no private key for chain type {ct}"
                )))
        }
    }
}

fn resolve_rpc(chain_id: &str, ct: ChainType, explicit: Option<&str>) -> Result<String, OwxError> {
    if let Some(url) = explicit {
        return Ok(url.to_owned());
    }
    let config = owx_core::Config::load_or_default();
    if let Some(url) = config.rpc_url(chain_id) {
        return Ok(url.to_owned());
    }
    let defaults = owx_core::Config::default_rpc();
    if let Some(url) = defaults.get(chain_id) {
        return Ok(url.clone());
    }
    let ns = ct.namespace();
    for (k, v) in &config.rpc {
        if k.starts_with(ns) { return Ok(v.clone()); }
    }
    for (k, v) in &defaults {
        if k.starts_with(ns) { return Ok(v.clone()); }
    }
    Err(OwxError::InvalidInput(format!("no RPC URL for chain '{chain_id}'")))
}

fn curl_post_json(url: &str, body: &str) -> Result<String, OwxError> {
    let output = std::process::Command::new("curl")
        .args(["-fsSL", "-X", "POST", "-H", "Content-Type: application/json", "-d", body, url])
        .output()
        .map_err(|e| OwxError::BroadcastFailed(format!("curl: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(OwxError::BroadcastFailed(format!("curl failed: {stderr}")));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn extract_json_field(json_str: &str, field: &str) -> Result<String, OwxError> {
    let parsed: serde_json::Value = serde_json::from_str(json_str)?;
    if let Some(error) = parsed.get("error") {
        return Err(OwxError::BroadcastFailed(format!("RPC error: {error}")));
    }
    parsed[field].as_str().map(|s| s.to_owned())
        .ok_or_else(|| OwxError::BroadcastFailed(format!("no '{field}' in response")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn generate_mnemonic_12() {
        let phrase = generate_mnemonic(12).unwrap();
        assert_eq!(phrase.split_whitespace().count(), 12);
    }

    #[test]
    fn generate_mnemonic_24() {
        let phrase = generate_mnemonic(24).unwrap();
        assert_eq!(phrase.split_whitespace().count(), 24);
    }

    #[test]
    fn create_and_list_wallets() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        let info = create_wallet(&vault, "test", "", 12).unwrap();
        assert_eq!(info.name, "test");
        assert_eq!(info.accounts.len(), 9);

        let wallets = list_wallets(&vault).unwrap();
        assert_eq!(wallets.len(), 1);
    }

    #[test]
    fn create_duplicate_name_fails() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        create_wallet(&vault, "dup", "", 12).unwrap();
        assert!(create_wallet(&vault, "dup", "", 12).is_err());
    }

    #[test]
    fn import_and_export_mnemonic() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let info = import_mnemonic(&vault, "imported", phrase, "pass", 0).unwrap();
        assert_eq!(info.accounts.len(), 9);

        let exported = export_wallet(&vault, "imported", "pass").unwrap();
        assert_eq!(exported, phrase);
    }

    #[test]
    fn sign_evm_message() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        import_mnemonic(&vault, "signer", phrase, "", 0).unwrap();

        let result = sign_message(&vault, "signer", "ethereum", b"hello", "", None).unwrap();
        assert!(!result.signature.is_empty());
    }

    #[test]
    fn delete_wallet_works() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        create_wallet(&vault, "del", "", 12).unwrap();
        assert_eq!(list_wallets(&vault).unwrap().len(), 1);
        delete_wallet(&vault, "del").unwrap();
        assert_eq!(list_wallets(&vault).unwrap().len(), 0);
    }

    #[test]
    fn rename_wallet_works() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        create_wallet(&vault, "old", "", 12).unwrap();
        rename_wallet(&vault, "old", "new").unwrap();
        assert!(get_wallet(&vault, "new").is_ok());
        assert!(get_wallet(&vault, "old").is_err());
    }
}
