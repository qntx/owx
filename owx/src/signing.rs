//! Transaction and message signing operations.

use owx_core::chain::ChainType;
use owx_core::parse_chain;
use owx_core::policy::TransactionContext;
use owx_core::{SignResult, TransactionSignResult};
use owx_vault::Vault;

use crate::derivation;
use crate::error::OwxError;
use crate::key;
use crate::key::AccessRequest;
use crate::secret::{WalletSecret, decrypt_wallet_secret};

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
    let chain_id = chain_info.chain_id.to_string();
    let request = AccessRequest::message(&chain_id);

    let secret = resolve_wallet_secret(vault, wallet_name_or_id, credential, &request)?;
    let sig_bytes =
        sign_message_with_secret(&secret, chain_info.chain_type, account_index, message)?;

    Ok(SignResult {
        signature: hex::encode(&sig_bytes),
        recovery_id: None,
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
) -> Result<TransactionSignResult, OwxError> {
    let chain_info = parse_chain(chain).map_err(OwxError::InvalidInput)?;
    if chain_info.chain_type != ChainType::Evm {
        return Err(OwxError::InvalidInput(
            "transaction signing is only implemented for EVM chains".into(),
        ));
    }

    let tx_hex_clean = tx_hex.strip_prefix("0x").unwrap_or(tx_hex);
    let tx_bytes = hex::decode(tx_hex_clean)
        .map_err(|e| OwxError::InvalidInput(format!("invalid hex transaction: {e}")))?;
    let account_index = index.unwrap_or(0);
    let chain_id = chain_info.chain_id.to_string();
    let request = AccessRequest::for_transaction(
        &chain_id,
        evm_transaction_context(&tx_bytes, tx_hex_clean)?,
    );
    let secret = resolve_wallet_secret(vault, wallet_name_or_id, credential, &request)?;
    let (signature, signed_tx, tx_hash) =
        sign_evm_transaction_with_secret(&secret, account_index, &tx_bytes)?;

    Ok(TransactionSignResult {
        signature,
        signed_tx: hex::encode(signed_tx),
        tx_hash,
    })
}

/// Sign EIP-712 typed structured data. Only supported for EVM chains.
pub fn sign_typed_data(
    vault: &Vault,
    wallet_name_or_id: &str,
    chain: &str,
    typed_data_json: &str,
    credential: &str,
    index: Option<u32>,
) -> Result<SignResult, OwxError> {
    let chain_info = parse_chain(chain).map_err(OwxError::InvalidInput)?;
    if chain_info.chain_type != ChainType::Evm {
        return Err(OwxError::InvalidInput(
            "EIP-712 typed data signing is only supported for EVM chains".into(),
        ));
    }
    if owx_vault::api_key::is_api_token(credential) {
        return Err(OwxError::InvalidInput(
            "EIP-712 typed data signing via API key is not yet supported".into(),
        ));
    }
    let account_index = index.unwrap_or(0);
    let secret = {
        let wallet = vault.load_wallet(wallet_name_or_id)?;
        decrypt_wallet_secret(&wallet, credential)?
    };
    let sig_bytes = sign_typed_data_with_secret(&secret, account_index, typed_data_json)?;
    Ok(SignResult {
        signature: hex::encode(&sig_bytes),
        recovery_id: None,
    })
}

/// Dispatch typed-data signing based on secret type.
fn sign_typed_data_with_secret(
    secret: &WalletSecret,
    index: u32,
    typed_data_json: &str,
) -> Result<Vec<u8>, OwxError> {
    match secret {
        WalletSecret::Mnemonic { phrase } => {
            derivation::sign_typed_data_with_mnemonic(phrase, index, typed_data_json)
        }
        WalletSecret::PrivateKeys { .. } => {
            let key_hex = secret.private_key_hex(ChainType::Evm).ok_or_else(|| {
                OwxError::InvalidInput("wallet does not contain an EVM private key".into())
            })?;
            derivation::sign_typed_data_with_private_key(key_hex, typed_data_json)
        }
    }
}

/// Resolve a wallet secret from either a passphrase or API token.
fn resolve_wallet_secret(
    vault: &Vault,
    wallet_name_or_id: &str,
    credential: &str,
    request: &AccessRequest,
) -> Result<WalletSecret, OwxError> {
    if owx_vault::api_key::is_api_token(credential) {
        key::resolve_wallet_secret_from_token(vault, credential, wallet_name_or_id, request)
    } else {
        let wallet = vault.load_wallet(wallet_name_or_id)?;
        decrypt_wallet_secret(&wallet, credential)
    }
}

/// Decode an unsigned EVM transaction into a [`TransactionContext`] for policy evaluation.
fn evm_transaction_context(tx_bytes: &[u8], raw_hex: &str) -> Result<TransactionContext, OwxError> {
    use signer_evm::alloy_consensus::{Transaction as _, TypedTransaction};

    let typed_tx = TypedTransaction::decode_unsigned(&mut &tx_bytes[..])
        .map_err(|e| OwxError::InvalidInput(format!("failed to decode EVM transaction: {e}")))?;
    let data_hex = hex::encode(typed_tx.input());

    Ok(TransactionContext {
        to: typed_tx.to().map(|address| format!("{address}")),
        value: Some(typed_tx.value().to_string()),
        raw_hex: format!("0x{raw_hex}"),
        data: (!data_hex.is_empty()).then(|| format!("0x{data_hex}")),
    })
}

/// Dispatch message signing based on secret type.
fn sign_message_with_secret(
    secret: &WalletSecret,
    chain_type: ChainType,
    index: u32,
    message: &[u8],
) -> Result<Vec<u8>, OwxError> {
    match secret {
        WalletSecret::Mnemonic { phrase } => {
            derivation::sign_with_mnemonic(phrase, chain_type, index, message)
        }
        WalletSecret::PrivateKeys { .. } => {
            let private_key_hex = secret.private_key_hex(chain_type).ok_or_else(|| {
                OwxError::InvalidInput(format!(
                    "wallet secret does not support {chain_type} signing"
                ))
            })?;
            derivation::sign_with_private_key(chain_type, private_key_hex, message)
        }
    }
}

/// Dispatch EVM transaction signing based on secret type.
fn sign_evm_transaction_with_secret(
    secret: &WalletSecret,
    index: u32,
    tx_bytes: &[u8],
) -> Result<(String, Vec<u8>, String), OwxError> {
    match secret {
        WalletSecret::Mnemonic { phrase } => {
            derivation::sign_evm_transaction_with_mnemonic(phrase, index, tx_bytes)
        }
        WalletSecret::PrivateKeys { .. } => {
            let private_key_hex = secret.private_key_hex(ChainType::Evm).ok_or_else(|| {
                OwxError::InvalidInput("wallet secret does not contain an EVM private key".into())
            })?;
            derivation::sign_evm_transaction_with_private_key(private_key_hex, tx_bytes)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::key;
    use crate::wallet;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn temp_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let v = Vault::open(dir.path()).unwrap();
        (dir, v)
    }

    #[test]
    fn sign_message_with_passphrase() {
        let (_dir, vault) = temp_vault();
        wallet::import_mnemonic(&vault, "w", TEST_MNEMONIC, "pass", 0).unwrap();

        let result = sign_message(&vault, "w", "ethereum", b"hello", "pass", None).unwrap();
        assert!(!result.signature.is_empty());
    }

    #[test]
    fn sign_message_with_private_key_wallet() {
        let (_dir, vault) = temp_vault();
        wallet::import_private_key(
            &vault,
            "w",
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
            "ethereum",
            "pass",
        )
        .unwrap();

        let result = sign_message(&vault, "w", "ethereum", b"hello", "pass", None).unwrap();
        assert!(!result.signature.is_empty());
    }

    #[test]
    fn sign_evm_transaction_with_passphrase() {
        let (_dir, vault) = temp_vault();
        wallet::import_mnemonic(&vault, "w", TEST_MNEMONIC, "pass", 0).unwrap();

        let result = sign_transaction(
            &vault,
            "w",
            "ethereum",
            "02df018001018252089400000000000000000000000000000000000000008080c0",
            "pass",
            None,
        )
        .unwrap();
        assert!(!result.signature.is_empty());
        assert!(!result.signed_tx.is_empty());
        assert!(result.tx_hash.starts_with("0x"));
    }

    #[test]
    fn sign_transaction_rejects_non_evm_chain() {
        let (_dir, vault) = temp_vault();
        wallet::import_mnemonic(&vault, "w", TEST_MNEMONIC, "pass", 0).unwrap();

        let result = sign_transaction(&vault, "w", "solana", "00", "pass", None);
        assert!(result.is_err());
    }

    #[test]
    fn sign_transaction_with_api_key_respects_recipient_policy() {
        let (_dir, vault) = temp_vault();
        let w = wallet::import_mnemonic(&vault, "w", TEST_MNEMONIC, "pass", 0).unwrap();
        let policy = serde_json::json!({
            "id": "recipient-policy",
            "name": "Recipient Policy",
            "version": 1,
            "created_at": "2026-01-01T00:00:00Z",
            "rules": [{
                "type": "allowed_recipients",
                "addresses": ["0x1111111111111111111111111111111111111111"]
            }],
            "action": "deny"
        });
        vault
            .save_policy_raw("recipient-policy", &policy.to_string())
            .unwrap();

        let wallet_id = w.id;
        let result = key::create_api_key(
            &vault,
            "agent",
            &[wallet_id],
            &["recipient-policy".to_owned()],
            "pass",
            None,
        )
        .unwrap();

        let signing_result = sign_transaction(
            &vault,
            "w",
            "ethereum",
            "02df018001018252089400000000000000000000000000000000000000008080c0",
            &result.token,
            None,
        );
        assert!(matches!(signing_result, Err(OwxError::PolicyDenied { .. })));
    }
}
