//! Trait-based chain dispatch for HD derivation and signing.
//!
//! Each chain family implements [`ChainHandler`] as a zero-size struct,
//! replacing the previous macro-based dispatch with clean trait objects.

use kobe::DerivedAccount;
use owx_core::ChainType;
use signer::{Sign, SignOutput};

use crate::error::OwxError;
use crate::types::SignResult;

/// Unified per-chain handler for derivation, signing, and address derivation.
pub trait ChainHandler: Send + Sync {
    /// Derive an account (address + path + key) from an HD wallet.
    fn derive(&self, wallet: &kobe::Wallet, index: u32) -> Result<DerivedAccount, OwxError>;

    /// Sign a message with a hex-encoded private key.
    fn sign_message(&self, key_hex: &str, message: &[u8]) -> Result<SignOutput, OwxError>;

    /// Sign a transaction with a hex-encoded private key.
    fn sign_transaction(&self, key_hex: &str, tx_bytes: &[u8]) -> Result<SignOutput, OwxError>;

    /// Derive an address from a hex private key (not all chains support this).
    fn address_from_hex(&self, _key_hex: &str) -> Result<String, OwxError> {
        Err(OwxError::InvalidInput(
            "address derivation from private key not supported for this chain".into(),
        ))
    }

    /// Encode a signed transaction for broadcasting (chain-specific wire format).
    fn encode_signed_tx(&self, _tx_bytes: &[u8], _sig: &SignOutput) -> Result<Vec<u8>, OwxError> {
        Err(OwxError::InvalidInput(
            "transaction encoding not supported for this chain".into(),
        ))
    }
}

/// Look up the handler for a chain family.
pub fn handler(ct: ChainType) -> &'static dyn ChainHandler {
    match ct {
        ChainType::Evm => &EvmHandler,
        ChainType::Bitcoin => &BtcHandler,
        ChainType::Solana => &SvmHandler,
        ChainType::Cosmos => &CosmosHandler,
        ChainType::Tron => &TronHandler,
        ChainType::Ton => &TonHandler,
        ChainType::Spark => &SparkHandler,
        ChainType::Filecoin => &FilHandler,
        ChainType::Sui => &SuiHandler,
    }
}

// ── Helper conversions ──────────────────────────────────────────────

/// Convert a derivation error.
fn d_err(e: impl std::fmt::Display) -> OwxError {
    OwxError::Derivation(e.to_string())
}

/// Convert a signing error.
fn s_err(e: impl std::fmt::Display) -> OwxError {
    OwxError::Signing(e.to_string())
}

/// Convert a [`SignOutput`] to our public [`SignResult`].
#[allow(clippy::needless_pass_by_value)]
pub fn to_sign_result(out: SignOutput) -> SignResult {
    SignResult {
        signature: hex::encode(&out.signature),
        recovery_id: out.recovery_id,
    }
}

// ── Per-chain handler implementations ───────────────────────────────

/// EVM (Ethereum, Base, Arbitrum, …).
struct EvmHandler;

impl ChainHandler for EvmHandler {
    fn derive(&self, wallet: &kobe::Wallet, index: u32) -> Result<DerivedAccount, OwxError> {
        kobe::Derive::derive(&kobe_evm::Deriver::new(wallet), index).map_err(d_err)
    }

    fn sign_message(&self, key_hex: &str, message: &[u8]) -> Result<SignOutput, OwxError> {
        let s = signer::evm::Signer::from_hex(key_hex).map_err(s_err)?;
        Sign::sign_message(&s, message).map_err(s_err)
    }

    fn sign_transaction(&self, key_hex: &str, tx_bytes: &[u8]) -> Result<SignOutput, OwxError> {
        let s = signer::evm::Signer::from_hex(key_hex).map_err(s_err)?;
        Sign::sign_transaction(&s, tx_bytes).map_err(s_err)
    }

    fn address_from_hex(&self, key_hex: &str) -> Result<String, OwxError> {
        Ok(signer::evm::Signer::from_hex(key_hex)
            .map_err(s_err)?
            .address())
    }

    fn encode_signed_tx(&self, tx_bytes: &[u8], sig: &SignOutput) -> Result<Vec<u8>, OwxError> {
        signer::evm::Signer::encode_signed_transaction(tx_bytes, &sig.signature).map_err(s_err)
    }
}

/// Bitcoin.
struct BtcHandler;

impl ChainHandler for BtcHandler {
    fn derive(&self, wallet: &kobe::Wallet, index: u32) -> Result<DerivedAccount, OwxError> {
        let deriver = kobe_btc::Deriver::new(wallet, kobe_btc::Network::Mainnet).map_err(d_err)?;
        kobe::Derive::derive(&deriver, index).map_err(d_err)
    }

    fn sign_message(&self, key_hex: &str, message: &[u8]) -> Result<SignOutput, OwxError> {
        let s = signer::btc::Signer::from_hex(key_hex).map_err(s_err)?;
        Sign::sign_message(&s, message).map_err(s_err)
    }

    fn sign_transaction(&self, key_hex: &str, tx_bytes: &[u8]) -> Result<SignOutput, OwxError> {
        let s = signer::btc::Signer::from_hex(key_hex).map_err(s_err)?;
        Sign::sign_transaction(&s, tx_bytes).map_err(s_err)
    }
}

/// Solana.
struct SvmHandler;

impl ChainHandler for SvmHandler {
    fn derive(&self, wallet: &kobe::Wallet, index: u32) -> Result<DerivedAccount, OwxError> {
        kobe::Derive::derive(&kobe_svm::Deriver::new(wallet), index).map_err(d_err)
    }

    fn sign_message(&self, key_hex: &str, message: &[u8]) -> Result<SignOutput, OwxError> {
        let s = signer::svm::Signer::from_hex(key_hex).map_err(s_err)?;
        Sign::sign_message(&s, message).map_err(s_err)
    }

    fn sign_transaction(&self, key_hex: &str, tx_bytes: &[u8]) -> Result<SignOutput, OwxError> {
        let s = signer::svm::Signer::from_hex(key_hex).map_err(s_err)?;
        Sign::sign_transaction(&s, tx_bytes).map_err(s_err)
    }

    fn address_from_hex(&self, key_hex: &str) -> Result<String, OwxError> {
        Ok(signer::svm::Signer::from_hex(key_hex)
            .map_err(s_err)?
            .address())
    }
}

/// Cosmos.
struct CosmosHandler;

impl ChainHandler for CosmosHandler {
    fn derive(&self, wallet: &kobe::Wallet, index: u32) -> Result<DerivedAccount, OwxError> {
        kobe::Derive::derive(&kobe_cosmos::Deriver::new(wallet), index).map_err(d_err)
    }

    fn sign_message(&self, key_hex: &str, message: &[u8]) -> Result<SignOutput, OwxError> {
        let s = signer::cosmos::Signer::from_hex(key_hex).map_err(s_err)?;
        Sign::sign_message(&s, message).map_err(s_err)
    }

    fn sign_transaction(&self, key_hex: &str, tx_bytes: &[u8]) -> Result<SignOutput, OwxError> {
        let s = signer::cosmos::Signer::from_hex(key_hex).map_err(s_err)?;
        Sign::sign_transaction(&s, tx_bytes).map_err(s_err)
    }
}

/// TRON.
struct TronHandler;

impl ChainHandler for TronHandler {
    fn derive(&self, wallet: &kobe::Wallet, index: u32) -> Result<DerivedAccount, OwxError> {
        kobe::Derive::derive(&kobe_tron::Deriver::new(wallet), index).map_err(d_err)
    }

    fn sign_message(&self, key_hex: &str, message: &[u8]) -> Result<SignOutput, OwxError> {
        let s = signer::tron::Signer::from_hex(key_hex).map_err(s_err)?;
        Sign::sign_message(&s, message).map_err(s_err)
    }

    fn sign_transaction(&self, key_hex: &str, tx_bytes: &[u8]) -> Result<SignOutput, OwxError> {
        let s = signer::tron::Signer::from_hex(key_hex).map_err(s_err)?;
        Sign::sign_transaction(&s, tx_bytes).map_err(s_err)
    }
}

/// TON.
struct TonHandler;

impl ChainHandler for TonHandler {
    fn derive(&self, wallet: &kobe::Wallet, index: u32) -> Result<DerivedAccount, OwxError> {
        kobe::Derive::derive(&kobe_ton::Deriver::new(wallet), index).map_err(d_err)
    }

    fn sign_message(&self, key_hex: &str, message: &[u8]) -> Result<SignOutput, OwxError> {
        let s = signer::ton::Signer::from_hex(key_hex).map_err(s_err)?;
        Sign::sign_message(&s, message).map_err(s_err)
    }

    fn sign_transaction(&self, key_hex: &str, tx_bytes: &[u8]) -> Result<SignOutput, OwxError> {
        let s = signer::ton::Signer::from_hex(key_hex).map_err(s_err)?;
        Sign::sign_transaction(&s, tx_bytes).map_err(s_err)
    }
}

/// Spark (Lightning).
struct SparkHandler;

impl ChainHandler for SparkHandler {
    fn derive(&self, wallet: &kobe::Wallet, index: u32) -> Result<DerivedAccount, OwxError> {
        kobe::Derive::derive(&kobe_spark::Deriver::new(wallet), index).map_err(d_err)
    }

    fn sign_message(&self, key_hex: &str, message: &[u8]) -> Result<SignOutput, OwxError> {
        let s = signer::spark::Signer::from_hex(key_hex).map_err(s_err)?;
        Sign::sign_message(&s, message).map_err(s_err)
    }

    fn sign_transaction(&self, key_hex: &str, tx_bytes: &[u8]) -> Result<SignOutput, OwxError> {
        let s = signer::spark::Signer::from_hex(key_hex).map_err(s_err)?;
        Sign::sign_transaction(&s, tx_bytes).map_err(s_err)
    }
}

/// Filecoin.
struct FilHandler;

impl ChainHandler for FilHandler {
    fn derive(&self, wallet: &kobe::Wallet, index: u32) -> Result<DerivedAccount, OwxError> {
        kobe::Derive::derive(&kobe_fil::Deriver::new(wallet), index).map_err(d_err)
    }

    fn sign_message(&self, key_hex: &str, message: &[u8]) -> Result<SignOutput, OwxError> {
        let s = signer::fil::Signer::from_hex(key_hex).map_err(s_err)?;
        Sign::sign_message(&s, message).map_err(s_err)
    }

    fn sign_transaction(&self, key_hex: &str, tx_bytes: &[u8]) -> Result<SignOutput, OwxError> {
        let s = signer::fil::Signer::from_hex(key_hex).map_err(s_err)?;
        Sign::sign_transaction(&s, tx_bytes).map_err(s_err)
    }
}

/// Sui.
struct SuiHandler;

impl ChainHandler for SuiHandler {
    fn derive(&self, wallet: &kobe::Wallet, index: u32) -> Result<DerivedAccount, OwxError> {
        kobe::Derive::derive(&kobe_sui::Deriver::new(wallet), index).map_err(d_err)
    }

    fn sign_message(&self, key_hex: &str, message: &[u8]) -> Result<SignOutput, OwxError> {
        let s = signer::sui::Signer::from_hex(key_hex).map_err(s_err)?;
        Sign::sign_message(&s, message).map_err(s_err)
    }

    fn sign_transaction(&self, key_hex: &str, tx_bytes: &[u8]) -> Result<SignOutput, OwxError> {
        let s = signer::sui::Signer::from_hex(key_hex).map_err(s_err)?;
        Sign::sign_transaction(&s, tx_bytes).map_err(s_err)
    }

    fn address_from_hex(&self, key_hex: &str) -> Result<String, OwxError> {
        Ok(signer::sui::Signer::from_hex(key_hex)
            .map_err(s_err)?
            .address())
    }
}

// ── Public convenience functions ────────────────────────────────────

/// Derive accounts for all 9 chain families from a mnemonic.
pub fn derive_all_accounts(
    mnemonic: &str,
    index: u32,
) -> Result<Vec<owx_vault::WalletAccount>, OwxError> {
    let wallet = kobe::Wallet::from_mnemonic(mnemonic, None).map_err(d_err)?;
    let mut accounts = Vec::with_capacity(owx_core::ALL_CHAIN_TYPES.len());
    for ct in &owx_core::ALL_CHAIN_TYPES {
        let chain = owx_core::default_chain_for_type(*ct);
        let h = handler(*ct);
        let d = h.derive(&wallet, index)?;
        accounts.push(owx_vault::WalletAccount {
            account_id: format!("{}:{}", chain.chain_id, d.address),
            address: d.address,
            chain_id: chain.chain_id.to_owned(),
            derivation_path: d.path,
        });
    }
    Ok(accounts)
}

/// Derive the hex private key for a chain type from a kobe wallet.
pub fn derive_private_key_hex(
    wallet: &kobe::Wallet,
    ct: ChainType,
    index: u32,
) -> Result<String, OwxError> {
    let d = handler(ct).derive(wallet, index)?;
    Ok(d.private_key.to_string())
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
    fn sign_all_chains_message() {
        let wallet = kobe::Wallet::from_mnemonic(MNEMONIC, None).unwrap();
        for ct in &owx_core::ALL_CHAIN_TYPES {
            let key_hex = derive_private_key_hex(&wallet, *ct, 0).unwrap();
            let h = handler(*ct);
            let sig = h.sign_message(&key_hex, b"test").unwrap();
            assert!(!sig.signature.is_empty(), "empty sig for {ct}");
        }
    }

    #[test]
    fn sign_all_chains_transaction() {
        let wallet = kobe::Wallet::from_mnemonic(MNEMONIC, None).unwrap();
        let tx = [0u8; 32];
        for ct in &owx_core::ALL_CHAIN_TYPES {
            let key_hex = derive_private_key_hex(&wallet, *ct, 0).unwrap();
            let h = handler(*ct);
            let sig = h.sign_transaction(&key_hex, &tx).unwrap();
            assert!(!sig.signature.is_empty(), "empty sig for {ct}");
        }
    }

    #[test]
    fn evm_address_from_hex() {
        let wallet = kobe::Wallet::from_mnemonic(MNEMONIC, None).unwrap();
        let key_hex = derive_private_key_hex(&wallet, ChainType::Evm, 0).unwrap();
        let addr = handler(ChainType::Evm).address_from_hex(&key_hex).unwrap();
        assert!(addr.starts_with("0x"));
        assert_eq!(addr.len(), 42);
    }
}
