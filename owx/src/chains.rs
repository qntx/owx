//! Unified 9-chain HD derivation and signing via kobe + signer.
//!
//! Uses macros to eliminate per-chain match-arm repetition while keeping
//! static dispatch for zero-cost abstraction.

use owx_core::chain::{ALL_CHAIN_TYPES, ChainType, default_chain_for_type};
use owx_core::wallet_file::WalletAccount;
use signer::Sign;

use crate::error::OwxError;
use crate::types::SignResult;

/// Dispatch to a chain-specific signer constructed from a hex key.
/// All 9 signers implement the `Sign` trait so the body is uniform.
macro_rules! with_signer {
    ($ct:expr, $key_hex:expr, $s:ident => $body:expr) => {
        match $ct {
            ChainType::Evm      => { let $s = signer::evm::Signer::from_hex($key_hex).map_err(s_err)?; $body }
            ChainType::Bitcoin   => { let $s = signer::btc::Signer::from_hex($key_hex).map_err(s_err)?; $body }
            ChainType::Solana    => { let $s = signer::svm::Signer::from_hex($key_hex).map_err(s_err)?; $body }
            ChainType::Cosmos    => { let $s = signer::cosmos::Signer::from_hex($key_hex).map_err(s_err)?; $body }
            ChainType::Tron      => { let $s = signer::tron::Signer::from_hex($key_hex).map_err(s_err)?; $body }
            ChainType::Ton       => { let $s = signer::ton::Signer::from_hex($key_hex).map_err(s_err)?; $body }
            ChainType::Spark     => { let $s = signer::spark::Signer::from_hex($key_hex).map_err(s_err)?; $body }
            ChainType::Filecoin  => { let $s = signer::fil::Signer::from_hex($key_hex).map_err(s_err)?; $body }
            ChainType::Sui       => { let $s = signer::sui::Signer::from_hex($key_hex).map_err(s_err)?; $body }
        }
    };
}

/// Convert a derivation error into [`OwxError::Derivation`].
fn d_err(e: impl std::fmt::Display) -> OwxError { OwxError::Derivation(e.to_string()) }

/// Convert a signing error into [`OwxError::Signing`].
fn s_err(e: impl std::fmt::Display) -> OwxError { OwxError::Signing(e.to_string()) }

/// Build a [`WalletAccount`] from chain ID, address, and derivation path.
fn make_account(chain_id: &str, address: &str, path: &str) -> WalletAccount {
    WalletAccount {
        account_id: format!("{chain_id}:{address}"),
        address: address.to_owned(),
        chain_id: chain_id.to_owned(),
        derivation_path: path.to_owned(),
    }
}

/// Convert a signer [`SignOutput`](signer::SignOutput) into our [`SignResult`].
#[allow(clippy::needless_pass_by_value)]
fn to_sign_result(out: signer::SignOutput) -> SignResult {
    SignResult { signature: hex::encode(&out.signature), recovery_id: out.recovery_id }
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

/// Sign a message with a hex private key. Uses the `Sign` trait uniformly.
pub fn sign_message_hex(ct: ChainType, key_hex: &str, message: &[u8]) -> Result<SignResult, OwxError> {
    with_signer!(ct, key_hex, s => Ok(to_sign_result(Sign::sign_message(&s, message).map_err(s_err)?)))
}

/// Sign a transaction with a hex private key. Uses the `Sign` trait uniformly.
pub fn sign_transaction_hex(ct: ChainType, key_hex: &str, tx_bytes: &[u8]) -> Result<SignResult, OwxError> {
    with_signer!(ct, key_hex, s => Ok(to_sign_result(Sign::sign_transaction(&s, tx_bytes).map_err(s_err)?)))
}

/// Encode a signed EVM transaction for broadcasting.
pub fn encode_signed_evm_tx(unsigned_tx: &[u8], signature: &[u8]) -> Result<Vec<u8>, OwxError> {
    signer::evm::Signer::encode_signed_transaction(unsigned_tx, signature).map_err(s_err)
}

/// Derive an address from a hex private key (EVM/Solana/Sui only).
pub fn derive_address_from_hex(ct: ChainType, key_hex: &str) -> Result<String, OwxError> {
    match ct {
        ChainType::Evm => Ok(signer::evm::Signer::from_hex(key_hex).map_err(s_err)?.address()),
        ChainType::Solana => Ok(signer::svm::Signer::from_hex(key_hex).map_err(s_err)?.address()),
        ChainType::Sui => Ok(signer::sui::Signer::from_hex(key_hex).map_err(s_err)?.address()),
        _ => Err(OwxError::InvalidInput(format!(
            "address derivation from private key not supported for {ct} — use mnemonic import"
        ))),
    }
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
    fn sign_evm_message_via_trait() {
        let wallet = kobe::Wallet::from_mnemonic(MNEMONIC, None).unwrap();
        let key_hex = derive_private_key_hex(&wallet, ChainType::Evm, 0).unwrap();
        let r = sign_message_hex(ChainType::Evm, &key_hex, b"hello").unwrap();
        assert!(!r.signature.is_empty());
        assert!(r.recovery_id.is_some());
    }

    #[test]
    fn sign_solana_message_via_trait() {
        let wallet = kobe::Wallet::from_mnemonic(MNEMONIC, None).unwrap();
        let key_hex = derive_private_key_hex(&wallet, ChainType::Solana, 0).unwrap();
        let r = sign_message_hex(ChainType::Solana, &key_hex, b"hello").unwrap();
        assert!(!r.signature.is_empty());
        assert!(r.recovery_id.is_none());
    }

    #[test]
    fn sign_all_chains_message() {
        let wallet = kobe::Wallet::from_mnemonic(MNEMONIC, None).unwrap();
        for ct in &ALL_CHAIN_TYPES {
            let key_hex = derive_private_key_hex(&wallet, *ct, 0).unwrap();
            let r = sign_message_hex(*ct, &key_hex, b"test").unwrap();
            assert!(!r.signature.is_empty(), "empty sig for {ct}");
        }
    }

    #[test]
    fn sign_all_chains_transaction() {
        let wallet = kobe::Wallet::from_mnemonic(MNEMONIC, None).unwrap();
        let tx = [0u8; 32];
        for ct in &ALL_CHAIN_TYPES {
            let key_hex = derive_private_key_hex(&wallet, *ct, 0).unwrap();
            let r = sign_transaction_hex(*ct, &key_hex, &tx).unwrap();
            assert!(!r.signature.is_empty(), "empty sig for {ct}");
        }
    }

    #[test]
    fn derive_address_evm() {
        let wallet = kobe::Wallet::from_mnemonic(MNEMONIC, None).unwrap();
        let key_hex = derive_private_key_hex(&wallet, ChainType::Evm, 0).unwrap();
        let addr = derive_address_from_hex(ChainType::Evm, &key_hex).unwrap();
        assert!(addr.starts_with("0x"));
        assert_eq!(addr.len(), 42);
    }
}
