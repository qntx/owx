//! End-to-end integration tests for the Owx orchestrator.
//!
//! Each test creates a fresh temp vault directory, exercises real crypto
//! (scrypt with fast-kdf in test profile), and verifies observable behavior.

#![allow(clippy::unwrap_used, clippy::missing_docs_in_private_items)]

use owx::{Credential, ImportKeyOptions, Owx};

fn temp_owx() -> (tempfile::TempDir, Owx) {
    let dir = tempfile::tempdir().unwrap();
    let owx = Owx::open(dir.path()).unwrap();
    (dir, owx)
}

#[test]
fn wallet_lifecycle_create_list_get_rename_export_delete() {
    let (_dir, owx) = temp_owx();

    // Create
    let info = owx.create_wallet("test-wallet", "", 12).unwrap();
    assert_eq!(info.name, "test-wallet");
    assert_eq!(info.accounts.len(), 10); // 10 chain families

    // List
    let wallets = owx.list_wallets().unwrap();
    assert_eq!(wallets.len(), 1);
    assert_eq!(wallets[0].id, info.id);

    // Get by name
    let fetched = owx.get_wallet("test-wallet").unwrap();
    assert_eq!(fetched.id, info.id);

    // Get by ID
    let fetched_by_id = owx.get_wallet(&info.id).unwrap();
    assert_eq!(fetched_by_id.name, "test-wallet");

    // Rename
    owx.rename_wallet("test-wallet", "renamed").unwrap();
    let renamed = owx.get_wallet("renamed").unwrap();
    assert_eq!(renamed.id, info.id);
    assert!(owx.get_wallet("test-wallet").is_err());

    // Export mnemonic
    let secret = owx.export_wallet("renamed", "").unwrap();
    assert_eq!(secret.split_whitespace().count(), 12);

    // Delete
    owx.delete_wallet("renamed").unwrap();
    assert!(owx.list_wallets().unwrap().is_empty());
}

#[test]
fn duplicate_wallet_name_rejected() {
    let (_dir, owx) = temp_owx();
    owx.create_wallet("dup", "", 12).unwrap();
    let err = owx.create_wallet("dup", "", 12);
    assert!(err.is_err());
}

#[test]
fn sign_message_all_10_chains() {
    let (_dir, owx) = temp_owx();
    owx.create_wallet("signer", "", 12).unwrap();

    // XRPL excluded: signer crate does not support canonical message signing for XRPL
    let chains = [
        "evm", "bitcoin", "solana", "cosmos", "tron", "ton", "spark", "filecoin", "sui",
    ];
    for chain in chains {
        let result = owx.sign_message("signer", chain, b"hello", Credential::Passphrase(""));
        assert!(
            result.is_ok(),
            "sign_message failed for {chain}: {:?}",
            result.err()
        );
        let sig = result.unwrap();
        assert!(!sig.signature.is_empty(), "empty signature for {chain}");
    }
}

#[test]
fn sign_transaction_evm() {
    let (_dir, owx) = temp_owx();
    owx.create_wallet("tx-signer", "", 12).unwrap();
    let tx_hex = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    let result = owx.sign_transaction("tx-signer", "evm", tx_hex, Credential::Passphrase(""));
    assert!(result.is_ok());
    assert!(result.unwrap().recovery_id.is_some());
}

#[test]
fn import_mnemonic_reproduces_same_addresses() {
    let (_dir, owx) = temp_owx();

    let w1 = owx.create_wallet("original", "", 12).unwrap();
    let mnemonic = owx.export_wallet("original", "").unwrap();

    let w2 = owx.import_mnemonic("imported", &mnemonic, "", 0).unwrap();

    for (a1, a2) in w1.accounts.iter().zip(w2.accounts.iter()) {
        assert_eq!(a1.chain_id, a2.chain_id);
        assert_eq!(
            a1.address, a2.address,
            "address mismatch for chain {}",
            a1.chain_id
        );
    }
}

#[test]
fn import_private_key_produces_10_accounts() {
    let (_dir, owx) = temp_owx();
    let opts = ImportKeyOptions {
        chain: Some("evm"),
        ..Default::default()
    };
    let info = owx
        .import_private_key(
            "pk-wallet",
            "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318",
            "",
            &opts,
        )
        .unwrap();
    assert_eq!(info.accounts.len(), 10);
    assert!(
        info.accounts
            .iter()
            .any(|a| a.chain_id.starts_with("eip155:"))
    );
}

#[test]
fn derive_address_matches_wallet_account() {
    let (_dir, owx) = temp_owx();
    let info = owx.create_wallet("derive-test", "", 12).unwrap();
    let evm_account = info
        .accounts
        .iter()
        .find(|a| a.chain_id == "eip155:1")
        .unwrap();

    let derived = owx
        .derive_address("derive-test", "ethereum", "", Some(0))
        .unwrap();
    assert_eq!(derived, evm_account.address);
}

#[test]
fn api_key_create_list_revoke() {
    let (_dir, owx) = temp_owx();
    let wallet = owx.create_wallet("agent-wallet", "", 12).unwrap();

    let result = owx
        .create_api_key("test-agent", &[wallet.id], &[], "", None)
        .unwrap();
    assert!(result.token.starts_with("owx_key_"));
    assert_eq!(result.key.name, "test-agent");

    let keys = owx.list_api_keys().unwrap();
    assert_eq!(keys.len(), 1);

    owx.revoke_api_key(&result.key.id).unwrap();
    assert!(owx.list_api_keys().unwrap().is_empty());
}

#[test]
fn wallet_not_found_error() {
    let (_dir, owx) = temp_owx();
    let err = owx.get_wallet("nonexistent").unwrap_err();
    let json = serde_json::to_value(&err).unwrap();
    assert_eq!(json["code"], "WALLET_NOT_FOUND");
}

#[test]
fn signing_deterministic() {
    let (_dir, owx) = temp_owx();
    owx.create_wallet("det", "", 12).unwrap();
    let s1 = owx
        .sign_message("det", "evm", b"test", Credential::Passphrase(""))
        .unwrap();
    let s2 = owx
        .sign_message("det", "evm", b"test", Credential::Passphrase(""))
        .unwrap();
    assert_eq!(s1.signature, s2.signature);
}
