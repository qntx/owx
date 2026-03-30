//! Transaction and message signing operations.

use owx_core::parse_chain;
use owx_vault::store::Vault;

use crate::derivation;
use crate::error::OwxError;
use crate::key_ops;
use crate::wallet_ops;

/// Signature result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SignResult {
    /// Hex-encoded signature bytes.
    pub signature: String,
}

/// Sign a message. The `credential` is either a passphrase or an API token (`owx_key_...`).
pub fn sign_message(
    vault: &Vault,
    wallet_name_or_id: &str,
    chain: &str,
    message: &[u8],
    credential: &str,
    index: Option<u32>,
) -> Result<SignResult, OwxError> {
    let chain_info = parse_chain(chain).map_err(OwxError::InvalidInput)?;
    let account_index = index.unwrap_or(0);

    let mnemonic = resolve_mnemonic(vault, wallet_name_or_id, credential, chain_info.chain_id)?;
    let sig_bytes =
        derivation::sign_with_mnemonic(&mnemonic, chain_info.chain_type, account_index, message)?;

    Ok(SignResult {
        signature: hex::encode(&sig_bytes),
    })
}

/// Sign a raw transaction (hex-encoded). Returns hex signature.
pub fn sign_transaction(
    vault: &Vault,
    wallet_name_or_id: &str,
    chain: &str,
    tx_hex: &str,
    credential: &str,
    index: Option<u32>,
) -> Result<SignResult, OwxError> {
    let tx_hex_clean = tx_hex.strip_prefix("0x").unwrap_or(tx_hex);
    let tx_bytes = hex::decode(tx_hex_clean)
        .map_err(|e| OwxError::InvalidInput(format!("invalid hex transaction: {e}")))?;

    sign_message(
        vault,
        wallet_name_or_id,
        chain,
        &tx_bytes,
        credential,
        index,
    )
}

/// Resolve the mnemonic from either a passphrase or an API token credential.
fn resolve_mnemonic(
    vault: &Vault,
    wallet_name_or_id: &str,
    credential: &str,
    chain_id: &str,
) -> Result<String, OwxError> {
    if owx_vault::api_key::is_api_token(credential) {
        key_ops::resolve_mnemonic_from_token(vault, credential, wallet_name_or_id, chain_id)
    } else {
        let wallet = vault.load_wallet(wallet_name_or_id)?;
        wallet_ops::decrypt_mnemonic(&wallet, credential)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn temp_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let v = Vault::open(dir.path()).unwrap();
        (dir, v)
    }

    #[test]
    fn sign_message_with_passphrase() {
        let (_dir, vault) = temp_vault();
        wallet_ops::import_mnemonic(&vault, "w", TEST_MNEMONIC, "pass", 0).unwrap();

        let result = sign_message(&vault, "w", "ethereum", b"hello", "pass", None).unwrap();
        assert!(!result.signature.is_empty());
    }
}
