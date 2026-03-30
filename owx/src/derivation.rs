#![allow(clippy::missing_docs_in_private_items)]

//! HD key derivation bridging kobe ecosystem.

use owx_core::chain::{ALL_CHAIN_TYPES, ChainType, default_chain_for_type};
use owx_core::wallet_file::WalletAccount;

use crate::error::OwxError;

/// Derive accounts for all chain types from a mnemonic at the given index.
pub fn derive_all_accounts(
    mnemonic_phrase: &str,
    index: u32,
) -> Result<Vec<WalletAccount>, OwxError> {
    let wallet = kobe::Wallet::from_mnemonic(mnemonic_phrase, None)
        .map_err(|e| OwxError::Derivation(e.to_string()))?;

    let mut accounts = Vec::with_capacity(ALL_CHAIN_TYPES.len());
    for ct in &ALL_CHAIN_TYPES {
        let chain = default_chain_for_type(*ct);
        let acct = derive_account_for_chain(&wallet, *ct, chain.chain_id.as_ref(), index)?;
        accounts.push(acct);
    }
    Ok(accounts)
}

/// Derive a single account for a specific chain type.
fn derive_account_for_chain(
    wallet: &kobe::Wallet,
    chain_type: ChainType,
    chain_id: &str,
    index: u32,
) -> Result<WalletAccount, OwxError> {
    match chain_type {
        ChainType::Evm => {
            let deriver = kobe_evm::Deriver::new(wallet);
            let d = deriver
                .derive(index)
                .map_err(|e| OwxError::Derivation(e.to_string()))?;
            Ok(WalletAccount {
                account_id: format!("{chain_id}:{}", d.address),
                address: d.address.clone(),
                chain_id: chain_id.to_owned(),
                derivation_path: d.path,
            })
        }
        ChainType::Bitcoin => {
            let deriver = kobe_btc::Deriver::new(wallet, kobe_btc::Network::Mainnet)
                .map_err(|e| OwxError::Derivation(e.to_string()))?;
            let d = deriver
                .derive(index)
                .map_err(|e| OwxError::Derivation(e.to_string()))?;
            Ok(WalletAccount {
                account_id: format!("{chain_id}:{}", d.address),
                address: d.address.clone(),
                chain_id: chain_id.to_owned(),
                derivation_path: d.path.to_string(),
            })
        }
        ChainType::Solana => {
            let deriver = kobe_svm::Deriver::new(wallet);
            let d = deriver
                .derive(index)
                .map_err(|e| OwxError::Derivation(e.to_string()))?;
            Ok(WalletAccount {
                account_id: format!("{chain_id}:{}", d.address),
                address: d.address.clone(),
                chain_id: chain_id.to_owned(),
                derivation_path: d.path,
            })
        }
    }
}

/// Derive an address from a raw private key for a given chain type.
pub fn derive_address_from_key(
    chain_type: ChainType,
    private_key: &[u8],
) -> Result<String, OwxError> {
    let key32: [u8; 32] = private_key.try_into().map_err(|_| {
        OwxError::InvalidInput(format!(
            "private key must be 32 bytes, got {}",
            private_key.len()
        ))
    })?;

    match chain_type {
        ChainType::Evm => {
            let s = signer::evm::Signer::from_bytes(&key32.into())
                .map_err(|e| OwxError::Derivation(e.to_string()))?;
            Ok(format!("{}", s.address()))
        }
        ChainType::Bitcoin => {
            let s = signer::btc::Signer::from_bytes(&key32, signer::btc::Network::Bitcoin)
                .map_err(|e| OwxError::Derivation(e.to_string()))?;
            Ok(s.p2wpkh_address(signer::btc::Network::Bitcoin).to_string())
        }
        ChainType::Solana => {
            let s = signer::svm::Signer::from_bytes(&key32);
            Ok(s.address())
        }
    }
}

/// Sign a message with a mnemonic-derived key for the given chain type.
pub fn sign_with_mnemonic(
    mnemonic_phrase: &str,
    chain_type: ChainType,
    index: u32,
    message: &[u8],
) -> Result<Vec<u8>, OwxError> {
    use signer::evm::SignerSync;
    use signer::svm::ed25519_dalek::Signer as _;
    let wallet = kobe::Wallet::from_mnemonic(mnemonic_phrase, None)
        .map_err(|e| OwxError::Derivation(e.to_string()))?;

    match chain_type {
        ChainType::Evm => {
            let deriver = kobe_evm::Deriver::new(&wallet);
            let derived = deriver
                .derive(index)
                .map_err(|e| OwxError::Derivation(e.to_string()))?;
            let s = signer::evm::Signer::from_derived(&derived)
                .map_err(|e| OwxError::Signing(e.to_string()))?;
            let sig = s
                .sign_message_sync(message)
                .map_err(|e| OwxError::Signing(e.to_string()))?;
            Ok(sig.as_bytes().to_vec())
        }
        ChainType::Bitcoin => {
            let deriver = kobe_btc::Deriver::new(&wallet, kobe_btc::Network::Mainnet)
                .map_err(|e| OwxError::Derivation(e.to_string()))?;
            let derived = deriver
                .derive(index)
                .map_err(|e| OwxError::Derivation(e.to_string()))?;
            let s = signer::btc::Signer::from_derived(&derived, signer::btc::Network::Bitcoin)
                .map_err(|e| OwxError::Signing(e.to_string()))?;
            let msg = std::str::from_utf8(message).map_err(|_| {
                OwxError::InvalidInput("bitcoin message must be valid UTF-8".into())
            })?;
            let sig_b64 = s
                .sign_message(msg)
                .map_err(|e| OwxError::Signing(e.to_string()))?;
            Ok(sig_b64.into_bytes())
        }
        ChainType::Solana => {
            let deriver = kobe_svm::Deriver::new(&wallet);
            let derived = deriver
                .derive(index)
                .map_err(|e| OwxError::Derivation(e.to_string()))?;
            let s = signer::svm::Signer::from_derived(&derived)
                .map_err(|e| OwxError::Signing(e.to_string()))?;
            let sig = s.sign(message);
            Ok(sig.to_bytes().to_vec())
        }
    }
}

pub fn sign_with_private_key(
    chain_type: ChainType,
    private_key_hex: &str,
    message: &[u8],
) -> Result<Vec<u8>, OwxError> {
    use signer::evm::SignerSync;
    use signer::svm::ed25519_dalek::Signer as _;

    match chain_type {
        ChainType::Evm => {
            let signer = signer::evm::Signer::from_hex(private_key_hex)
                .map_err(|e| OwxError::Signing(e.to_string()))?;
            let sig = signer
                .sign_message_sync(message)
                .map_err(|e| OwxError::Signing(e.to_string()))?;
            Ok(sig.as_bytes().to_vec())
        }
        ChainType::Bitcoin => {
            let signer =
                signer::btc::Signer::from_hex(private_key_hex, signer::btc::Network::Bitcoin)
                    .map_err(|e| OwxError::Signing(e.to_string()))?;
            let msg = std::str::from_utf8(message).map_err(|_| {
                OwxError::InvalidInput("bitcoin message must be valid UTF-8".into())
            })?;
            let sig_b64 = signer
                .sign_message(msg)
                .map_err(|e| OwxError::Signing(e.to_string()))?;
            Ok(sig_b64.into_bytes())
        }
        ChainType::Solana => {
            let signer = signer::svm::Signer::from_hex(private_key_hex)
                .map_err(|e| OwxError::Signing(e.to_string()))?;
            let sig = signer.sign(message);
            Ok(sig.to_bytes().to_vec())
        }
    }
}

pub fn sign_evm_transaction_with_mnemonic(
    mnemonic_phrase: &str,
    index: u32,
    tx_bytes: &[u8],
) -> Result<(String, Vec<u8>, String), OwxError> {
    let wallet = kobe::Wallet::from_mnemonic(mnemonic_phrase, None)
        .map_err(|e| OwxError::Derivation(e.to_string()))?;
    let deriver = kobe_evm::Deriver::new(&wallet);
    let derived = deriver
        .derive(index)
        .map_err(|e| OwxError::Derivation(e.to_string()))?;
    let signer = signer::evm::Signer::from_derived(&derived)
        .map_err(|e| OwxError::Signing(e.to_string()))?;
    sign_evm_transaction_with_signer(&signer, tx_bytes)
}

pub fn sign_evm_transaction_with_private_key(
    private_key_hex: &str,
    tx_bytes: &[u8],
) -> Result<(String, Vec<u8>, String), OwxError> {
    let signer = signer::evm::Signer::from_hex(private_key_hex)
        .map_err(|e| OwxError::Signing(e.to_string()))?;
    sign_evm_transaction_with_signer(&signer, tx_bytes)
}

pub fn sign_evm_transaction_with_signer(
    signer: &signer::evm::Signer,
    tx_bytes: &[u8],
) -> Result<(String, Vec<u8>, String), OwxError> {
    use signer::evm::TxSignerSync;
    use signer_evm::alloy_consensus::{Signed, TxEnvelope, TypedTransaction};
    use signer_evm::alloy_network::eip2718::Encodable2718;

    let mut typed_tx = TypedTransaction::decode_unsigned(&mut &tx_bytes[..])
        .map_err(|e| OwxError::InvalidInput(format!("failed to decode EVM transaction: {e}")))?;

    let sig = signer
        .sign_transaction_sync(&mut typed_tx)
        .map_err(|e| OwxError::Signing(e.to_string()))?;

    let tx_hash = typed_tx.tx_hash(&sig);
    let envelope = match typed_tx {
        TypedTransaction::Legacy(tx) => TxEnvelope::Legacy(Signed::new_unchecked(tx, sig, tx_hash)),
        TypedTransaction::Eip2930(tx) => {
            TxEnvelope::Eip2930(Signed::new_unchecked(tx, sig, tx_hash))
        }
        TypedTransaction::Eip1559(tx) => {
            TxEnvelope::Eip1559(Signed::new_unchecked(tx, sig, tx_hash))
        }
        TypedTransaction::Eip4844(tx) => {
            TxEnvelope::Eip4844(Signed::new_unchecked(tx, sig, tx_hash))
        }
        TypedTransaction::Eip7702(tx) => {
            TxEnvelope::Eip7702(Signed::new_unchecked(tx, sig, tx_hash))
        }
    };

    Ok((
        format!("{sig}"),
        envelope.encoded_2718(),
        format!("{tx_hash}"),
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn derive_all_produces_three_accounts() {
        let accounts = derive_all_accounts(TEST_MNEMONIC, 0).unwrap();
        assert_eq!(accounts.len(), 3);

        let evm = accounts
            .iter()
            .find(|a| a.chain_id.starts_with("eip155:"))
            .unwrap();
        assert!(evm.address.starts_with("0x"));

        let btc = accounts
            .iter()
            .find(|a| a.chain_id.starts_with("bip122:"))
            .unwrap();
        assert!(!btc.address.is_empty());

        let sol = accounts
            .iter()
            .find(|a| a.chain_id.starts_with("solana:"))
            .unwrap();
        assert!(!sol.address.is_empty());
    }

    #[test]
    fn derive_deterministic() {
        let a1 = derive_all_accounts(TEST_MNEMONIC, 0).unwrap();
        let a2 = derive_all_accounts(TEST_MNEMONIC, 0).unwrap();
        for (x, y) in a1.iter().zip(a2.iter()) {
            assert_eq!(x.address, y.address);
        }
    }

    #[test]
    fn different_indices_different_addresses() {
        let a0 = derive_all_accounts(TEST_MNEMONIC, 0).unwrap();
        let a1 = derive_all_accounts(TEST_MNEMONIC, 1).unwrap();
        assert_ne!(a0[0].address, a1[0].address);
    }

    #[test]
    fn sign_evm_message() {
        let sig = sign_with_mnemonic(TEST_MNEMONIC, ChainType::Evm, 0, b"hello").unwrap();
        assert_eq!(sig.len(), 65);
    }

    #[test]
    fn sign_solana_message() {
        let sig = sign_with_mnemonic(TEST_MNEMONIC, ChainType::Solana, 0, b"hello").unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn sign_private_key_evm_message() {
        let sig = sign_with_private_key(
            ChainType::Evm,
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
            b"hello",
        )
        .unwrap();
        assert_eq!(sig.len(), 65);
    }

    #[test]
    fn sign_evm_transaction_from_private_key() {
        let unsigned_tx =
            hex::decode("02df018001018252089400000000000000000000000000000000000000008080c0")
                .unwrap();
        let (signature, signed_tx, tx_hash) = sign_evm_transaction_with_private_key(
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
            &unsigned_tx,
        )
        .unwrap();
        assert!(!signature.is_empty());
        assert!(!signed_tx.is_empty());
        assert!(tx_hash.starts_with("0x"));
    }
}
