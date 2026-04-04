//! Agent-native, self-custodial, policy-gated, multi-chain wallet toolkit.
//!
//! ```ignore
//! let vault = owx::Vault::open("~/.owx")?;
//! let info  = owx::create_wallet(&vault, "my-wallet", "pass", 12)?;
//! let sig   = owx::sign_message(&vault, "my-wallet", "ethereum", b"hello", "pass", None)?;
//! ```

pub mod audit;
pub mod broadcast;
pub mod chain;
pub mod config;
mod error;
pub mod key;
pub mod policy;
pub mod secret;
pub mod signer;
pub mod wallet;

use std::path::PathBuf;

pub use error::{Error, ErrorCode};
pub use key::{ApiKeyCreateResult, ApiKeyInfo, create_api_key, list_api_keys, revoke_api_key};
pub use signer::{SendResult, SignResult};
pub use wallet::{
    AccountInfo, WalletInfo, create_wallet, delete_wallet, derive_address, export_wallet,
    generate_mnemonic, get_wallet, import_mnemonic, import_private_key, import_private_keys,
    list_wallets, rename_wallet,
};

/// Domain-aware vault wrapping [`owx_vault::Store`].
#[derive(Debug, Clone)]
pub struct Vault {
    /// Underlying generic store.
    store: owx_vault::Store,
}

impl Vault {
    /// Open (or create) a vault at the given path.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, Error> {
        Ok(Self {
            store: owx_vault::Store::open(path)?,
        })
    }

    /// Open the default vault at `~/.owx`.
    pub fn open_default() -> Result<Self, Error> {
        Self::open(default_vault_path())
    }

    /// Access the underlying generic store.
    #[must_use]
    pub const fn store(&self) -> &owx_vault::Store {
        &self.store
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
) -> Result<SignResult, Error> {
    let resolved = chain::resolve(chain)?;
    let family = resolved.family();
    let idx = index.unwrap_or(0);
    let key_hex = key::resolve_signing_key(vault, wallet_name_or_id, credential, family, idx)?;
    let out = signer::sign_message(family, &key_hex, message)?;
    Ok(signer::to_sign_result(&out))
}

/// Sign a transaction (hex-encoded).
pub fn sign_transaction(
    vault: &Vault,
    wallet_name_or_id: &str,
    chain: &str,
    tx_hex: &str,
    credential: &str,
    index: Option<u32>,
) -> Result<SignResult, Error> {
    let resolved = chain::resolve(chain)?;
    let family = resolved.family();
    let tx_hex_clean = tx_hex.strip_prefix("0x").unwrap_or(tx_hex);
    let tx_bytes =
        hex::decode(tx_hex_clean).map_err(|e| Error::InvalidInput(format!("invalid hex: {e}")))?;
    let idx = index.unwrap_or(0);
    let key_hex = key::resolve_signing_key(vault, wallet_name_or_id, credential, family, idx)?;
    let out = signer::sign_transaction(family, &key_hex, &tx_bytes)?;
    Ok(signer::to_sign_result(&out))
}

/// Sign EIP-712 typed data (EVM only).
pub fn sign_typed_data(
    vault: &Vault,
    wallet_name_or_id: &str,
    chain: &str,
    typed_data_json: &str,
    credential: &str,
    index: Option<u32>,
) -> Result<SignResult, Error> {
    let resolved = chain::resolve(chain)?;
    let family = resolved.family();
    if family != chain::ChainFamily::Evm {
        return Err(Error::InvalidInput(
            "EIP-712 typed data signing is only supported for EVM chains".into(),
        ));
    }
    let idx = index.unwrap_or(0);
    let key_hex = key::resolve_signing_key(vault, wallet_name_or_id, credential, family, idx)?;
    let out = signer::sign_typed_data(&key_hex, typed_data_json)?;
    Ok(signer::to_sign_result(&out))
}

/// Sign a transaction and broadcast it to the network.
pub fn sign_and_send(
    vault: &Vault,
    wallet_name_or_id: &str,
    chain: &str,
    tx_hex: &str,
    credential: &str,
    index: Option<u32>,
    rpc_url: Option<&str>,
) -> Result<SendResult, Error> {
    let resolved = chain::resolve(chain)?;
    let family = resolved.family();
    let chain_id = resolved.chain_id();
    let tx_hex_clean = tx_hex.strip_prefix("0x").unwrap_or(tx_hex);
    let tx_bytes =
        hex::decode(tx_hex_clean).map_err(|e| Error::InvalidInput(format!("invalid hex: {e}")))?;
    let idx = index.unwrap_or(0);
    let key_hex = key::resolve_signing_key(vault, wallet_name_or_id, credential, family, idx)?;
    let sig = signer::sign_transaction(family, &key_hex, &tx_bytes)?;
    let payload = signer::encode_signed_tx(family, &tx_bytes, &sig)?;
    let rpc = broadcast::resolve_rpc(chain_id, family, rpc_url)?;
    let tx_hash = broadcast::broadcast(family, &rpc, &payload)?;
    Ok(SendResult { tx_hash })
}

/// Best-effort default vault path.
fn default_vault_path() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| "/tmp".to_owned());
    PathBuf::from(home).join(".owx")
}
