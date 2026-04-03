//! Multi-chain signing dispatch via match + local macros (zero trait objects).

use kobe::DerivedAccount;
use signer::{Sign, SignOutput};

use crate::chain::{ALL_FAMILIES, ChainFamily, default_chain};
use crate::error::Error;
use crate::wallet::WalletAccount;

/// Convert a derivation error.
fn d_err(e: impl std::fmt::Display) -> Error {
    Error::Derivation(e.to_string())
}

/// Convert a signing error.
fn s_err(e: impl std::fmt::Display) -> Error {
    Error::Signing(e.to_string())
}

/// Derive an HD account for a chain family.
pub fn derive_account(
    family: ChainFamily,
    wallet: &kobe::Wallet,
    index: u32,
) -> Result<DerivedAccount, Error> {
    match family {
        ChainFamily::Evm => {
            kobe::Derive::derive(&kobe_evm::Deriver::new(wallet), index).map_err(d_err)
        }
        ChainFamily::Bitcoin => {
            let deriver =
                kobe_btc::Deriver::new(wallet, kobe_btc::Network::Mainnet).map_err(d_err)?;
            kobe::Derive::derive(&deriver, index).map_err(d_err)
        }
        ChainFamily::Solana => {
            kobe::Derive::derive(&kobe_svm::Deriver::new(wallet), index).map_err(d_err)
        }
        ChainFamily::Cosmos => {
            kobe::Derive::derive(&kobe_cosmos::Deriver::new(wallet), index).map_err(d_err)
        }
        ChainFamily::Tron => {
            kobe::Derive::derive(&kobe_tron::Deriver::new(wallet), index).map_err(d_err)
        }
        ChainFamily::Ton => {
            kobe::Derive::derive(&kobe_ton::Deriver::new(wallet), index).map_err(d_err)
        }
        ChainFamily::Spark => {
            kobe::Derive::derive(&kobe_spark::Deriver::new(wallet), index).map_err(d_err)
        }
        ChainFamily::Filecoin => {
            kobe::Derive::derive(&kobe_fil::Deriver::new(wallet), index).map_err(d_err)
        }
        ChainFamily::Sui => {
            kobe::Derive::derive(&kobe_sui::Deriver::new(wallet), index).map_err(d_err)
        }
    }
}

/// Sign a message with a hex private key.
pub fn sign_message(
    family: ChainFamily,
    key_hex: &str,
    message: &[u8],
) -> Result<SignOutput, Error> {
    macro_rules! sign {
        ($signer:path) => {{
            let s = <$signer>::from_hex(key_hex).map_err(s_err)?;
            Sign::sign_message(&s, message).map_err(s_err)
        }};
    }
    match family {
        ChainFamily::Evm => sign!(signer::evm::Signer),
        ChainFamily::Bitcoin => sign!(signer::btc::Signer),
        ChainFamily::Solana => sign!(signer::svm::Signer),
        ChainFamily::Cosmos => sign!(signer::cosmos::Signer),
        ChainFamily::Tron => sign!(signer::tron::Signer),
        ChainFamily::Ton => sign!(signer::ton::Signer),
        ChainFamily::Spark => sign!(signer::spark::Signer),
        ChainFamily::Filecoin => sign!(signer::fil::Signer),
        ChainFamily::Sui => sign!(signer::sui::Signer),
    }
}

/// Sign a transaction with a hex private key.
pub fn sign_transaction(
    family: ChainFamily,
    key_hex: &str,
    tx_bytes: &[u8],
) -> Result<SignOutput, Error> {
    macro_rules! sign {
        ($signer:path) => {{
            let s = <$signer>::from_hex(key_hex).map_err(s_err)?;
            Sign::sign_transaction(&s, tx_bytes).map_err(s_err)
        }};
    }
    match family {
        ChainFamily::Evm => sign!(signer::evm::Signer),
        ChainFamily::Bitcoin => sign!(signer::btc::Signer),
        ChainFamily::Solana => sign!(signer::svm::Signer),
        ChainFamily::Cosmos => sign!(signer::cosmos::Signer),
        ChainFamily::Tron => sign!(signer::tron::Signer),
        ChainFamily::Ton => sign!(signer::ton::Signer),
        ChainFamily::Spark => sign!(signer::spark::Signer),
        ChainFamily::Filecoin => sign!(signer::fil::Signer),
        ChainFamily::Sui => sign!(signer::sui::Signer),
    }
}

/// Sign EIP-712 typed data (EVM only).
pub fn sign_typed_data(key_hex: &str, typed_data_json: &str) -> Result<SignOutput, Error> {
    let s = signer::evm::Signer::from_hex(key_hex).map_err(s_err)?;
    s.sign_typed_data(typed_data_json).map_err(s_err)
}

/// Encode a signed transaction for broadcasting.
///
/// EVM: RLP-encodes the full signed tx. Other chains: returns the raw
/// signature bytes (most non-EVM chains embed the signature directly).
pub fn encode_signed_tx(
    family: ChainFamily,
    tx_bytes: &[u8],
    sig: &SignOutput,
) -> Result<Vec<u8>, Error> {
    match family {
        ChainFamily::Evm => {
            signer::evm::Signer::encode_signed_transaction(tx_bytes, &sig.signature).map_err(s_err)
        }
        _ => Ok(sig.signature.clone()),
    }
}

/// Derive an address from a hex private key (not all families support this).
pub fn address_from_hex(family: ChainFamily, key_hex: &str) -> Result<String, Error> {
    match family {
        ChainFamily::Evm => Ok(signer::evm::Signer::from_hex(key_hex)
            .map_err(s_err)?
            .address()),
        ChainFamily::Solana => Ok(signer::svm::Signer::from_hex(key_hex)
            .map_err(s_err)?
            .address()),
        ChainFamily::Sui => Ok(signer::sui::Signer::from_hex(key_hex)
            .map_err(s_err)?
            .address()),
        _ => Err(Error::InvalidInput(format!(
            "address derivation from private key not supported for {family}"
        ))),
    }
}

/// Derive the hex private key for a chain family from a kobe wallet.
pub fn derive_private_key_hex(
    wallet: &kobe::Wallet,
    family: ChainFamily,
    index: u32,
) -> Result<String, Error> {
    let d = derive_account(family, wallet, index)?;
    Ok(d.private_key.to_string())
}

/// Derive accounts for all 9 chain families from a mnemonic.
pub fn derive_all_accounts(mnemonic: &str, index: u32) -> Result<Vec<WalletAccount>, Error> {
    let wallet = kobe::Wallet::from_mnemonic(mnemonic, None).map_err(d_err)?;
    let mut accounts = Vec::with_capacity(ALL_FAMILIES.len());
    for fam in &ALL_FAMILIES {
        let chain = default_chain(*fam);
        let d = derive_account(*fam, &wallet, index)?;
        accounts.push(WalletAccount {
            account_id: format!("{}:{}", chain.chain_id, d.address),
            address: d.address,
            chain_id: chain.chain_id,
            derivation_path: d.path,
        });
    }
    Ok(accounts)
}

/// Result of a signing operation (public DTO).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignResult {
    /// Hex-encoded signature.
    pub signature: String,
    /// ECDSA recovery ID (secp256k1 only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_id: Option<u8>,
}

/// Result of a sign-and-send operation (public DTO).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SendResult {
    /// On-chain transaction hash.
    pub tx_hash: String,
}

/// Convert a [`SignOutput`] to the public [`SignResult`].
#[allow(clippy::needless_pass_by_value)]
pub fn to_sign_result(out: SignOutput) -> SignResult {
    SignResult {
        signature: hex::encode(&out.signature),
        recovery_id: out.recovery_id,
    }
}
