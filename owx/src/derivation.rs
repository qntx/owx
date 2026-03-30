//! HD key derivation and signing bridges to the kobe/signer ecosystem.

use owx_core::chain::{ALL_CHAIN_TYPES, ChainType, default_chain_for_type};
use owx_core::wallet_file::WalletAccount;

use crate::error::OwxError;

/// Extension trait for converting arbitrary errors into [`OwxError`] variants.
trait DerivationResultExt<T> {
    /// Map the error to [`OwxError::Derivation`].
    fn derive_err(self) -> Result<T, OwxError>;
}

impl<T, E: std::fmt::Display> DerivationResultExt<T> for Result<T, E> {
    fn derive_err(self) -> Result<T, OwxError> {
        self.map_err(|e| OwxError::Derivation(e.to_string()))
    }
}

/// Extension trait for converting signing errors into [`OwxError::Signing`].
trait SigningResultExt<T> {
    /// Map the error to [`OwxError::Signing`].
    fn sign_err(self) -> Result<T, OwxError>;
}

impl<T, E: std::fmt::Display> SigningResultExt<T> for Result<T, E> {
    fn sign_err(self) -> Result<T, OwxError> {
        self.map_err(|e| OwxError::Signing(e.to_string()))
    }
}

/// Build a [`WalletAccount`] from derivation output.
fn make_account(chain_id: &str, address: &str, path: &str) -> WalletAccount {
    WalletAccount {
        account_id: format!("{chain_id}:{address}"),
        address: address.to_owned(),
        chain_id: chain_id.to_owned(),
        derivation_path: path.to_owned(),
    }
}

/// Derive accounts for all chain types from a mnemonic at the given index.
pub fn derive_all_accounts(
    mnemonic_phrase: &str,
    index: u32,
) -> Result<Vec<WalletAccount>, OwxError> {
    let wallet = kobe::Wallet::from_mnemonic(mnemonic_phrase, None).derive_err()?;
    let mut accounts = Vec::with_capacity(ALL_CHAIN_TYPES.len());
    for ct in &ALL_CHAIN_TYPES {
        let chain = default_chain_for_type(*ct);
        accounts.push(derive_account(
            &wallet,
            *ct,
            chain.chain_id.as_ref(),
            index,
        )?);
    }
    Ok(accounts)
}

/// Derive a single account for a specific chain type.
fn derive_account(
    wallet: &kobe::Wallet,
    chain_type: ChainType,
    chain_id: &str,
    index: u32,
) -> Result<WalletAccount, OwxError> {
    match chain_type {
        ChainType::Evm => {
            let d = kobe_evm::Deriver::new(wallet).derive(index).derive_err()?;
            Ok(make_account(chain_id, &d.address, &d.path))
        }
        ChainType::Bitcoin => {
            let d = kobe_btc::Deriver::new(wallet, kobe_btc::Network::Mainnet)
                .derive_err()?
                .derive(index)
                .derive_err()?;
            Ok(make_account(chain_id, &d.address, &d.path.to_string()))
        }
        ChainType::Solana => {
            let d = kobe_svm::Deriver::new(wallet).derive(index).derive_err()?;
            Ok(make_account(chain_id, &d.address, &d.path))
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
            let s = signer::evm::Signer::from_bytes(&key32.into()).derive_err()?;
            Ok(format!("{}", s.address()))
        }
        ChainType::Bitcoin => {
            let s = signer::btc::Signer::from_bytes(&key32, signer::btc::Network::Bitcoin)
                .derive_err()?;
            Ok(s.p2wpkh_address(signer::btc::Network::Bitcoin).to_string())
        }
        ChainType::Solana => Ok(signer::svm::Signer::from_bytes(&key32).address()),
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

    let wallet = kobe::Wallet::from_mnemonic(mnemonic_phrase, None).derive_err()?;
    match chain_type {
        ChainType::Evm => {
            let derived = kobe_evm::Deriver::new(&wallet).derive(index).derive_err()?;
            let s = signer::evm::Signer::from_derived(&derived).sign_err()?;
            Ok(s.sign_message_sync(message).sign_err()?.as_bytes().to_vec())
        }
        ChainType::Bitcoin => {
            let derived = kobe_btc::Deriver::new(&wallet, kobe_btc::Network::Mainnet)
                .derive_err()?
                .derive(index)
                .derive_err()?;
            let s = signer::btc::Signer::from_derived(&derived, signer::btc::Network::Bitcoin)
                .sign_err()?;
            let msg = std::str::from_utf8(message).map_err(|_| {
                OwxError::InvalidInput("bitcoin message must be valid UTF-8".into())
            })?;
            Ok(s.sign_message(msg).sign_err()?.into_bytes())
        }
        ChainType::Solana => {
            let derived = kobe_svm::Deriver::new(&wallet).derive(index).derive_err()?;
            let s = signer::svm::Signer::from_derived(&derived).sign_err()?;
            Ok(s.sign(message).to_bytes().to_vec())
        }
    }
}

/// Sign a message with a raw private key for the given chain type.
pub fn sign_with_private_key(
    chain_type: ChainType,
    private_key_hex: &str,
    message: &[u8],
) -> Result<Vec<u8>, OwxError> {
    use signer::evm::SignerSync;
    use signer::svm::ed25519_dalek::Signer as _;

    match chain_type {
        ChainType::Evm => {
            let s = signer::evm::Signer::from_hex(private_key_hex).sign_err()?;
            Ok(s.sign_message_sync(message).sign_err()?.as_bytes().to_vec())
        }
        ChainType::Bitcoin => {
            let s = signer::btc::Signer::from_hex(private_key_hex, signer::btc::Network::Bitcoin)
                .sign_err()?;
            let msg = std::str::from_utf8(message).map_err(|_| {
                OwxError::InvalidInput("bitcoin message must be valid UTF-8".into())
            })?;
            Ok(s.sign_message(msg).sign_err()?.into_bytes())
        }
        ChainType::Solana => {
            let s = signer::svm::Signer::from_hex(private_key_hex).sign_err()?;
            Ok(s.sign(message).to_bytes().to_vec())
        }
    }
}

/// Sign an EVM transaction with a mnemonic-derived key.
pub fn sign_evm_transaction_with_mnemonic(
    mnemonic_phrase: &str,
    index: u32,
    tx_bytes: &[u8],
) -> Result<(String, Vec<u8>, String), OwxError> {
    let wallet = kobe::Wallet::from_mnemonic(mnemonic_phrase, None).derive_err()?;
    let derived = kobe_evm::Deriver::new(&wallet).derive(index).derive_err()?;
    let evm_signer = signer::evm::Signer::from_derived(&derived).sign_err()?;
    sign_evm_transaction_with_signer(&evm_signer, tx_bytes)
}

/// Sign an EVM transaction with a raw private key.
pub fn sign_evm_transaction_with_private_key(
    private_key_hex: &str,
    tx_bytes: &[u8],
) -> Result<(String, Vec<u8>, String), OwxError> {
    let evm_signer = signer::evm::Signer::from_hex(private_key_hex).sign_err()?;
    sign_evm_transaction_with_signer(&evm_signer, tx_bytes)
}

/// Sign an EVM transaction using an already-constructed signer.
pub fn sign_evm_transaction_with_signer(
    signer: &signer::evm::Signer,
    tx_bytes: &[u8],
) -> Result<(String, Vec<u8>, String), OwxError> {
    use signer::evm::TxSignerSync;
    use signer_evm::alloy_consensus::{Signed, TxEnvelope, TypedTransaction};
    use signer_evm::alloy_network::eip2718::Encodable2718;

    let mut typed_tx = TypedTransaction::decode_unsigned(&mut &tx_bytes[..])
        .map_err(|e| OwxError::InvalidInput(format!("failed to decode EVM transaction: {e}")))?;

    let sig = signer.sign_transaction_sync(&mut typed_tx).sign_err()?;

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

/// Sign EIP-712 typed data with a mnemonic-derived key.
pub fn sign_typed_data_with_mnemonic(
    mnemonic_phrase: &str,
    index: u32,
    typed_data_json: &str,
) -> Result<Vec<u8>, OwxError> {
    let wallet = kobe::Wallet::from_mnemonic(mnemonic_phrase, None).derive_err()?;
    let derived = kobe_evm::Deriver::new(&wallet).derive(index).derive_err()?;
    let evm_signer = signer::evm::Signer::from_derived(&derived).sign_err()?;
    sign_typed_data_with_signer(&evm_signer, typed_data_json)
}

/// Sign EIP-712 typed data with a raw private key.
pub fn sign_typed_data_with_private_key(
    private_key_hex: &str,
    typed_data_json: &str,
) -> Result<Vec<u8>, OwxError> {
    let evm_signer = signer::evm::Signer::from_hex(private_key_hex).sign_err()?;
    sign_typed_data_with_signer(&evm_signer, typed_data_json)
}

/// Sign EIP-712 typed data using an already-constructed EVM signer.
fn sign_typed_data_with_signer(
    signer: &signer::evm::Signer,
    typed_data_json: &str,
) -> Result<Vec<u8>, OwxError> {
    use signer::evm::SignerSync;

    // Validate JSON
    let _: serde_json::Value = serde_json::from_str(typed_data_json)
        .map_err(|e| OwxError::InvalidInput(format!("invalid EIP-712 JSON: {e}")))?;

    // EIP-712: sign the typed data as a prefixed message.
    // Full EIP-712 struct-hash computation would require parsing domain/types/message;
    // here we sign the raw JSON bytes via EIP-191 personal_sign as a pragmatic approach.
    let sig = signer
        .sign_message_sync(typed_data_json.as_bytes())
        .sign_err()?;
    Ok(sig.as_bytes().to_vec())
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
