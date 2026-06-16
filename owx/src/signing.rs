//! Multi-chain signing dispatch.
//!
//! Signing and address derivation use the `for_each_chain!` macro so adding
//! a chain only requires extending the table in `chain.rs`. HD derivation
//! stays as a manual match because `kobe_btc::Deriver::new` has a different
//! signature (returns `Result` with its own error type).

use kobe::DerivedAccount;
use signer::{SignMessage, SignOutput};
use zeroize::Zeroizing;

use crate::chain::{ChainFamily, for_each_chain};
use crate::error::OwxError as Error;

/// Result of a signing operation.
#[non_exhaustive]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignResult {
    /// Hex-encoded signature.
    pub signature: String,
    /// ECDSA recovery ID (secp256k1 only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_id: Option<u8>,
}

/// Result of a sign-and-send operation.
#[non_exhaustive]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SendResult {
    /// On-chain transaction hash.
    pub tx_hash: String,
}

/// Convert a [`SignOutput`] to the public [`SignResult`].
#[must_use]
pub(crate) fn to_sign_result(out: &SignOutput) -> SignResult {
    SignResult {
        signature: out.to_hex(),
        recovery_id: out.v(),
    }
}

/// Wrap a derivation error.
fn d_err(e: impl std::fmt::Display) -> Error {
    Error::Derivation(e.to_string())
}

/// Wrap a signing error.
fn s_err(e: impl std::fmt::Display) -> Error {
    Error::Signing(e.to_string())
}

/// Derive an HD account for a chain family from a kobe wallet.
///
/// This is a manual match because `kobe_btc::Deriver::new` returns a `Result`
/// with its own error type, while all other chains' constructors are infallible.
///
/// # Errors
///
/// Returns [`Error::Derivation`] if HD derivation fails.
pub(crate) fn derive_account(
    family: ChainFamily,
    wallet: &kobe::Wallet,
    index: u32,
) -> Result<DerivedAccount, Error> {
    match family {
        ChainFamily::Evm => {
            kobe::Derive::derive(&kobe_evm::Deriver::new(wallet), index).map_err(d_err)
        }
        ChainFamily::Bitcoin => {
            let d = kobe_btc::Deriver::new(wallet, kobe_btc::Network::Mainnet).map_err(d_err)?;
            kobe::Derive::derive(&d, index)
                .map(|a| (*a).clone())
                .map_err(d_err)
        }
        ChainFamily::Solana => kobe::Derive::derive(&kobe_svm::Deriver::new(wallet), index)
            .map(|a| (*a).clone())
            .map_err(d_err),
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
        ChainFamily::Xrpl => {
            kobe::Derive::derive(&kobe_xrpl::Deriver::new(wallet), index).map_err(d_err)
        }
    }
}

/// Derive the hex private key for a chain family.
///
/// # Errors
///
/// Returns [`Error::Derivation`] if HD derivation fails.
pub(crate) fn derive_private_key_hex(
    wallet: &kobe::Wallet,
    family: ChainFamily,
    index: u32,
) -> Result<Zeroizing<String>, Error> {
    Ok(derive_account(family, wallet, index)?.private_key_hex())
}

/// Sign a message with a hex private key.
///
/// # Errors
///
/// Returns [`Error::Signing`] if key parsing or signing fails.
pub(crate) fn sign_message(
    family: ChainFamily,
    key_hex: &str,
    message: &[u8],
) -> Result<SignOutput, Error> {
    match family {
        ChainFamily::Evm => signer::evm::Signer::from_hex(key_hex)
            .map_err(s_err)?
            .sign_message(message)
            .map_err(s_err),
        ChainFamily::Bitcoin => signer::btc::Signer::from_hex(key_hex)
            .map_err(s_err)?
            .sign_message(message)
            .map_err(s_err),
        ChainFamily::Solana => signer::svm::Signer::from_hex(key_hex)
            .map_err(s_err)?
            .sign_message(message)
            .map_err(s_err),
        ChainFamily::Tron => signer::tron::Signer::from_hex(key_hex)
            .map_err(s_err)?
            .sign_message(message)
            .map_err(s_err),
        ChainFamily::Spark => signer::spark::Signer::from_hex(key_hex)
            .map_err(s_err)?
            .sign_message(message)
            .map_err(s_err),
        ChainFamily::Sui => signer::sui::Signer::from_hex(key_hex)
            .map_err(s_err)?
            .sign_message(message)
            .map_err(s_err),
        ChainFamily::Cosmos | ChainFamily::Ton | ChainFamily::Filecoin | ChainFamily::Xrpl => Err(
            Error::InvalidInput(format!("message signing is not supported for {family}")),
        ),
    }
}

/// Sign a transaction with a hex private key.
///
/// # Errors
///
/// Returns [`Error::Signing`] if key parsing or signing fails.
pub(crate) fn sign_transaction(
    family: ChainFamily,
    key_hex: &str,
    tx_bytes: &[u8],
) -> Result<SignOutput, Error> {
    macro_rules! dispatch {
        ( $( [ $var:ident, $disp:expr, $ns:expr, $coin:expr, $ed:expr, $signer:path ] ),+ $(,)? ) => {
            match family {
                $( ChainFamily::$var => {
                    let s = <$signer>::from_hex(key_hex).map_err(s_err)?;
                    s.sign_transaction(tx_bytes).map_err(s_err)
                } )+
            }
        };
    }
    for_each_chain!(dispatch)
}

/// Sign EIP-712 typed data (EVM only).
///
/// # Errors
///
/// Returns [`Error::Signing`] if key parsing or signing fails.
pub(crate) fn sign_typed_data(key_hex: &str, typed_data_json: &str) -> Result<SignOutput, Error> {
    let s = signer::evm::Signer::from_hex(key_hex).map_err(s_err)?;
    s.sign_typed_data(typed_data_json).map_err(s_err)
}

/// Encode a signed transaction for broadcasting.
///
/// # Errors
///
/// Returns [`Error::Signing`] if encoding fails (EVM only).
pub(crate) fn encode_signed_tx(
    family: ChainFamily,
    key_hex: &str,
    tx_bytes: &[u8],
    sig: &SignOutput,
) -> Result<Vec<u8>, Error> {
    match family {
        ChainFamily::Evm => signer::evm::Signer::from_hex(key_hex)
            .map_err(s_err)?
            .encode_signed_transaction(tx_bytes, sig)
            .map_err(s_err),
        ChainFamily::Bitcoin
        | ChainFamily::Solana
        | ChainFamily::Cosmos
        | ChainFamily::Tron
        | ChainFamily::Ton
        | ChainFamily::Spark
        | ChainFamily::Filecoin
        | ChainFamily::Sui
        | ChainFamily::Xrpl => Ok(sig.to_bytes()),
    }
}

/// Derive an on-chain address from a hex private key.
///
/// # Errors
///
/// Returns [`Error::Signing`] if the hex key is invalid.
pub fn address_from_hex(family: ChainFamily, key_hex: &str) -> Result<String, Error> {
    let address = match family {
        ChainFamily::Evm => signer::evm::Signer::from_hex(key_hex)
            .map_err(s_err)?
            .address(),
        ChainFamily::Bitcoin => signer::btc::Signer::from_hex(key_hex)
            .map_err(s_err)?
            .address(),
        ChainFamily::Solana => signer::svm::Signer::from_hex(key_hex)
            .map_err(s_err)?
            .address(),
        ChainFamily::Cosmos => signer::cosmos::Signer::from_hex(key_hex)
            .map_err(s_err)?
            .address(),
        ChainFamily::Tron => signer::tron::Signer::from_hex(key_hex)
            .map_err(s_err)?
            .address(),
        ChainFamily::Ton => signer::ton::Signer::from_hex(key_hex)
            .map_err(s_err)?
            .identity(),
        ChainFamily::Spark => signer::spark::Signer::from_hex(key_hex)
            .map_err(s_err)?
            .address(),
        ChainFamily::Filecoin => signer::fil::Signer::from_hex(key_hex)
            .map_err(s_err)?
            .address(),
        ChainFamily::Sui => signer::sui::Signer::from_hex(key_hex)
            .map_err(s_err)?
            .address(),
        ChainFamily::Xrpl => signer::xrpl::Signer::from_hex(key_hex)
            .map_err(s_err)?
            .address(),
    };
    Ok(address)
}
