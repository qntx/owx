//! HD key derivation bridging kobe ecosystem.

use owx_vault::wallet_file::WalletAccount;

use crate::chain::{ALL_FAMILIES, ChainFamily, default_chain};
use crate::error::OwxError;

/// Derive accounts for all chain families from a mnemonic at the given index.
pub fn derive_all_accounts(
    mnemonic_phrase: &str,
    index: u32,
) -> Result<Vec<WalletAccount>, OwxError> {
    let wallet = kobe::Wallet::from_mnemonic(mnemonic_phrase, None)
        .map_err(|e| OwxError::Derivation(e.to_string()))?;

    let mut accounts = Vec::with_capacity(ALL_FAMILIES.len());
    for family in &ALL_FAMILIES {
        let chain = default_chain(*family);
        let acct = derive_account_for_family(&wallet, *family, chain.chain_id, index)?;
        accounts.push(acct);
    }
    Ok(accounts)
}

/// Derive a single account for a specific chain family.
fn derive_account_for_family(
    wallet: &kobe::Wallet,
    family: ChainFamily,
    chain_id: &str,
    index: u32,
) -> Result<WalletAccount, OwxError> {
    match family {
        ChainFamily::Evm => {
            let deriver = kobe_evm::Deriver::new(wallet);
            let d = deriver
                .derive(index)
                .map_err(|e| OwxError::Derivation(e.to_string()))?;
            Ok(WalletAccount::new(
                format!("{chain_id}:{}", d.address),
                d.address.clone(),
                chain_id.to_owned(),
                d.path,
            ))
        }
        ChainFamily::Bitcoin => {
            let deriver = kobe_btc::Deriver::new(wallet, kobe_btc::Network::Mainnet)
                .map_err(|e| OwxError::Derivation(e.to_string()))?;
            let d = deriver
                .derive(index)
                .map_err(|e| OwxError::Derivation(e.to_string()))?;
            Ok(WalletAccount::new(
                format!("{chain_id}:{}", d.address),
                d.address.clone(),
                chain_id.to_owned(),
                d.path.to_string(),
            ))
        }
        ChainFamily::Solana => {
            let deriver = kobe_svm::Deriver::new(wallet);
            let d = deriver
                .derive(index)
                .map_err(|e| OwxError::Derivation(e.to_string()))?;
            Ok(WalletAccount::new(
                format!("{chain_id}:{}", d.address),
                d.address.clone(),
                chain_id.to_owned(),
                d.path,
            ))
        }
    }
}

/// Sign a message with a mnemonic-derived key for the given chain family.
pub fn sign_with_mnemonic(
    mnemonic_phrase: &str,
    family: ChainFamily,
    index: u32,
    message: &[u8],
) -> Result<Vec<u8>, OwxError> {
    let wallet = kobe::Wallet::from_mnemonic(mnemonic_phrase, None)
        .map_err(|e| OwxError::Derivation(e.to_string()))?;

    match family {
        ChainFamily::Evm => {
            let deriver = kobe_evm::Deriver::new(&wallet);
            let derived = deriver
                .derive(index)
                .map_err(|e| OwxError::Derivation(e.to_string()))?;
            let s = signer::evm::Signer::from_derived(&derived)
                .map_err(|e| OwxError::Signing(e.to_string()))?;
            use signer::evm::SignerSync;
            let sig = s
                .sign_message_sync(message)
                .map_err(|e| OwxError::Signing(e.to_string()))?;
            Ok(sig.as_bytes().to_vec())
        }
        ChainFamily::Bitcoin => {
            let deriver = kobe_btc::Deriver::new(&wallet, kobe_btc::Network::Mainnet)
                .map_err(|e| OwxError::Derivation(e.to_string()))?;
            let derived = deriver
                .derive(index)
                .map_err(|e| OwxError::Derivation(e.to_string()))?;
            let s = signer::btc::Signer::from_derived(&derived, signer::btc::Network::Bitcoin)
                .map_err(|e| OwxError::Signing(e.to_string()))?;
            let msg = std::str::from_utf8(message).unwrap_or("");
            let sig_b64 = s
                .sign_message(msg)
                .map_err(|e| OwxError::Signing(e.to_string()))?;
            Ok(sig_b64.into_bytes())
        }
        ChainFamily::Solana => {
            let deriver = kobe_svm::Deriver::new(&wallet);
            let derived = deriver
                .derive(index)
                .map_err(|e| OwxError::Derivation(e.to_string()))?;
            let s = signer::svm::Signer::from_derived(&derived)
                .map_err(|e| OwxError::Signing(e.to_string()))?;
            use signer::svm::ed25519_dalek::Signer as _;
            let sig = s.sign(message);
            Ok(sig.to_bytes().to_vec())
        }
    }
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
        let sig = sign_with_mnemonic(TEST_MNEMONIC, ChainFamily::Evm, 0, b"hello").unwrap();
        assert_eq!(sig.len(), 65);
    }

    #[test]
    fn sign_solana_message() {
        let sig = sign_with_mnemonic(TEST_MNEMONIC, ChainFamily::Solana, 0, b"hello").unwrap();
        assert_eq!(sig.len(), 64);
    }
}
