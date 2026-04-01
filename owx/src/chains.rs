//! Unified 9-chain HD derivation and signing bridges to kobe/signer.

use owx_core::chain::{ALL_CHAIN_TYPES, ChainType, default_chain_for_type};
use owx_core::wallet_file::WalletAccount;

use crate::error::OwxError;
use crate::types::SignResult;

fn d_err<E: std::fmt::Display>(e: E) -> OwxError {
    OwxError::Derivation(e.to_string())
}

fn s_err<E: std::fmt::Display>(e: E) -> OwxError {
    OwxError::Signing(e.to_string())
}

fn make_account(chain_id: &str, address: &str, path: &str) -> WalletAccount {
    WalletAccount {
        account_id: format!("{chain_id}:{address}"),
        address: address.to_owned(),
        chain_id: chain_id.to_owned(),
        derivation_path: path.to_owned(),
    }
}

/// Derive accounts for all 9 chain families from a mnemonic.
pub fn derive_all_accounts(
    mnemonic: &str,
    index: u32,
) -> Result<Vec<WalletAccount>, OwxError> {
    let wallet = kobe::Wallet::from_mnemonic(mnemonic, None).map_err(d_err)?;
    let mut accounts = Vec::with_capacity(ALL_CHAIN_TYPES.len());
    for ct in &ALL_CHAIN_TYPES {
        let chain = default_chain_for_type(*ct);
        accounts.push(derive_one(&wallet, *ct, chain.chain_id, index)?);
    }
    Ok(accounts)
}

/// Derive a single account for one chain type.
fn derive_one(
    wallet: &kobe::Wallet,
    ct: ChainType,
    chain_id: &str,
    index: u32,
) -> Result<WalletAccount, OwxError> {
    use kobe::Derive;

    match ct {
        ChainType::Evm => {
            let d = Derive::derive(&kobe_evm::Deriver::new(wallet), index).map_err(d_err)?;
            Ok(make_account(chain_id, &d.address, &d.path))
        }
        ChainType::Bitcoin => {
            let deriver = kobe_btc::Deriver::new(wallet, kobe_btc::Network::Mainnet).map_err(d_err)?;
            let d = Derive::derive(&deriver, index).map_err(d_err)?;
            Ok(make_account(chain_id, &d.address, &d.path))
        }
        ChainType::Solana => {
            let d = Derive::derive(&kobe_svm::Deriver::new(wallet), index).map_err(d_err)?;
            Ok(make_account(chain_id, &d.address, &d.path))
        }
        ChainType::Cosmos => {
            let d = Derive::derive(&kobe_cosmos::Deriver::new(wallet), index).map_err(d_err)?;
            Ok(make_account(chain_id, &d.address, &d.path))
        }
        ChainType::Tron => {
            let d = Derive::derive(&kobe_tron::Deriver::new(wallet), index).map_err(d_err)?;
            Ok(make_account(chain_id, &d.address, &d.path))
        }
        ChainType::Ton => {
            let d = Derive::derive(&kobe_ton::Deriver::new(wallet), index).map_err(d_err)?;
            Ok(make_account(chain_id, &d.address, &d.path))
        }
        ChainType::Spark => {
            let d = Derive::derive(&kobe_spark::Deriver::new(wallet), index).map_err(d_err)?;
            Ok(make_account(chain_id, &d.address, &d.path))
        }
        ChainType::Filecoin => {
            let d = Derive::derive(&kobe_fil::Deriver::new(wallet), index).map_err(d_err)?;
            Ok(make_account(chain_id, &d.address, &d.path))
        }
        ChainType::Sui => {
            let d = Derive::derive(&kobe_sui::Deriver::new(wallet), index).map_err(d_err)?;
            Ok(make_account(chain_id, &d.address, &d.path))
        }
    }
}

/// Sign a message with a mnemonic-derived key.
pub fn sign_message_mnemonic(
    mnemonic: &str,
    ct: ChainType,
    index: u32,
    message: &[u8],
) -> Result<SignResult, OwxError> {
    let wallet = kobe::Wallet::from_mnemonic(mnemonic, None).map_err(d_err)?;
    let key_hex = derive_private_key_hex(&wallet, ct, index)?;
    sign_message_hex(ct, &key_hex, message)
}

/// Sign a message with a hex private key.
pub fn sign_message_hex(
    ct: ChainType,
    key_hex: &str,
    message: &[u8],
) -> Result<SignResult, OwxError> {
    match ct {
        ChainType::Evm => {
            let s = signer::evm::Signer::from_hex(key_hex).map_err(s_err)?;
            to_sign_result(s.sign_message(message).map_err(s_err)?)
        }
        ChainType::Bitcoin => {
            let s = signer::btc::Signer::from_hex(key_hex).map_err(s_err)?;
            to_sign_result(s.sign_message(message).map_err(s_err)?)
        }
        ChainType::Cosmos => {
            let s = signer::cosmos::Signer::from_hex(key_hex).map_err(s_err)?;
            to_sign_result(s.sign_message(message).map_err(s_err)?)
        }
        ChainType::Tron => {
            let s = signer::tron::Signer::from_hex(key_hex).map_err(s_err)?;
            to_sign_result(s.sign_message(message).map_err(s_err)?)
        }
        ChainType::Spark => {
            let s = signer::spark::Signer::from_hex(key_hex).map_err(s_err)?;
            to_sign_result(s.sign_message(message).map_err(s_err)?)
        }
        ChainType::Filecoin => {
            let s = signer::fil::Signer::from_hex(key_hex).map_err(s_err)?;
            to_sign_result(s.sign_message(message).map_err(s_err)?)
        }
        ChainType::Solana => {
            let s = signer::svm::Signer::from_hex(key_hex).map_err(s_err)?;
            let sig = s.sign_transaction_message(message);
            Ok(SignResult {
                signature: hex::encode(sig.to_bytes()),
                recovery_id: None,
            })
        }
        ChainType::Ton => {
            let s = signer::ton::Signer::from_hex(key_hex).map_err(s_err)?;
            let sig = s.sign_transaction(message);
            Ok(SignResult {
                signature: hex::encode(sig.to_bytes()),
                recovery_id: None,
            })
        }
        ChainType::Sui => {
            let s = signer::sui::Signer::from_hex(key_hex).map_err(s_err)?;
            let sig = s.sign_message(message);
            Ok(SignResult {
                signature: hex::encode(sig.to_bytes()),
                recovery_id: None,
            })
        }
    }
}

/// Sign a transaction with a hex private key.
pub fn sign_transaction_hex(
    ct: ChainType,
    key_hex: &str,
    tx_bytes: &[u8],
) -> Result<SignResult, OwxError> {
    match ct {
        ChainType::Evm => {
            let s = signer::evm::Signer::from_hex(key_hex).map_err(s_err)?;
            to_sign_result(s.sign_transaction(tx_bytes).map_err(s_err)?)
        }
        ChainType::Bitcoin => {
            let s = signer::btc::Signer::from_hex(key_hex).map_err(s_err)?;
            to_sign_result(s.sign_transaction(tx_bytes).map_err(s_err)?)
        }
        ChainType::Cosmos => {
            let s = signer::cosmos::Signer::from_hex(key_hex).map_err(s_err)?;
            to_sign_result(s.sign_transaction(tx_bytes).map_err(s_err)?)
        }
        ChainType::Tron => {
            let s = signer::tron::Signer::from_hex(key_hex).map_err(s_err)?;
            to_sign_result(s.sign_transaction(tx_bytes).map_err(s_err)?)
        }
        ChainType::Spark => {
            let s = signer::spark::Signer::from_hex(key_hex).map_err(s_err)?;
            to_sign_result(s.sign_transaction(tx_bytes).map_err(s_err)?)
        }
        ChainType::Filecoin => {
            let s = signer::fil::Signer::from_hex(key_hex).map_err(s_err)?;
            to_sign_result(s.sign_transaction(tx_bytes).map_err(s_err)?)
        }
        ChainType::Solana => {
            let s = signer::svm::Signer::from_hex(key_hex).map_err(s_err)?;
            let sig = s.sign_transaction_message(tx_bytes);
            Ok(SignResult {
                signature: hex::encode(sig.to_bytes()),
                recovery_id: None,
            })
        }
        ChainType::Ton => {
            let s = signer::ton::Signer::from_hex(key_hex).map_err(s_err)?;
            let sig = s.sign_transaction(tx_bytes);
            Ok(SignResult {
                signature: hex::encode(sig.to_bytes()),
                recovery_id: None,
            })
        }
        ChainType::Sui => {
            let s = signer::sui::Signer::from_hex(key_hex).map_err(s_err)?;
            let sig = s.sign_transaction(tx_bytes);
            Ok(SignResult {
                signature: hex::encode(sig.to_bytes()),
                recovery_id: None,
            })
        }
    }
}

/// Encode a signed EVM transaction for broadcasting.
pub fn encode_signed_evm_tx(unsigned_tx: &[u8], signature: &[u8]) -> Result<Vec<u8>, OwxError> {
    signer::evm::Signer::encode_signed_transaction(unsigned_tx, signature).map_err(s_err)
}

/// Derive the hex private key for a chain type from a kobe wallet.
pub fn derive_private_key_hex(
    wallet: &kobe::Wallet,
    ct: ChainType,
    index: u32,
) -> Result<String, OwxError> {
    use kobe::Derive;

    match ct {
        ChainType::Evm => {
            let d = Derive::derive(&kobe_evm::Deriver::new(wallet), index).map_err(d_err)?;
            Ok(d.private_key.to_string())
        }
        ChainType::Bitcoin => {
            let deriver = kobe_btc::Deriver::new(wallet, kobe_btc::Network::Mainnet).map_err(d_err)?;
            let d = deriver.derive(index).map_err(d_err)?;
            Ok(d.private_key_hex.to_string())
        }
        ChainType::Solana => {
            let d = Derive::derive(&kobe_svm::Deriver::new(wallet), index).map_err(d_err)?;
            Ok(d.private_key.to_string())
        }
        ChainType::Cosmos => {
            let d = Derive::derive(&kobe_cosmos::Deriver::new(wallet), index).map_err(d_err)?;
            Ok(d.private_key.to_string())
        }
        ChainType::Tron => {
            let d = Derive::derive(&kobe_tron::Deriver::new(wallet), index).map_err(d_err)?;
            Ok(d.private_key.to_string())
        }
        ChainType::Ton => {
            let d = Derive::derive(&kobe_ton::Deriver::new(wallet), index).map_err(d_err)?;
            Ok(d.private_key.to_string())
        }
        ChainType::Spark => {
            let d = Derive::derive(&kobe_spark::Deriver::new(wallet), index).map_err(d_err)?;
            Ok(d.private_key.to_string())
        }
        ChainType::Filecoin => {
            let d = Derive::derive(&kobe_fil::Deriver::new(wallet), index).map_err(d_err)?;
            Ok(d.private_key.to_string())
        }
        ChainType::Sui => {
            let d = Derive::derive(&kobe_sui::Deriver::new(wallet), index).map_err(d_err)?;
            Ok(d.private_key.to_string())
        }
    }
}

/// Convert a signer `SignOutput` to our `SignResult`.
fn to_sign_result(out: signer::SignOutput) -> Result<SignResult, OwxError> {
    Ok(SignResult {
        signature: hex::encode(&out.signature),
        recovery_id: out.recovery_id,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn derive_all_produces_9_accounts() {
        let accounts = derive_all_accounts(MNEMONIC, 0).unwrap();
        assert_eq!(accounts.len(), 9);

        let evm = accounts.iter().find(|a| a.chain_id.starts_with("eip155:")).unwrap();
        assert!(evm.address.starts_with("0x"));

        let btc = accounts.iter().find(|a| a.chain_id.starts_with("bip122:")).unwrap();
        assert!(!btc.address.is_empty());

        let sol = accounts.iter().find(|a| a.chain_id.starts_with("solana:")).unwrap();
        assert!(!sol.address.is_empty());
    }

    #[test]
    fn deterministic_derivation() {
        let a1 = derive_all_accounts(MNEMONIC, 0).unwrap();
        let a2 = derive_all_accounts(MNEMONIC, 0).unwrap();
        for (x, y) in a1.iter().zip(a2.iter()) {
            assert_eq!(x.address, y.address);
        }
    }

    #[test]
    fn different_indices() {
        let a0 = derive_all_accounts(MNEMONIC, 0).unwrap();
        let a1 = derive_all_accounts(MNEMONIC, 1).unwrap();
        assert_ne!(a0[0].address, a1[0].address);
    }

    #[test]
    fn sign_evm_message() {
        let r = sign_message_mnemonic(MNEMONIC, ChainType::Evm, 0, b"hello").unwrap();
        assert!(!r.signature.is_empty());
        assert!(r.recovery_id.is_some());
    }

    #[test]
    fn sign_solana_message() {
        let r = sign_message_mnemonic(MNEMONIC, ChainType::Solana, 0, b"hello").unwrap();
        assert!(!r.signature.is_empty());
        assert!(r.recovery_id.is_none());
    }
}
