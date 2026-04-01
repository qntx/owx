//! API key creation, listing, revocation, and token-based access.

use std::collections::HashMap;

use owx_core::api_key::ApiKeyFile;
use owx_vault::Vault;
use owx_vault::crypto;

use crate::error::OwxError;
use crate::secret::decrypt_secret;
use crate::types::{ApiKeyCreateResult, ApiKeyInfo};

/// Convert an [`ApiKeyFile`] to the public-facing [`ApiKeyInfo`].
fn key_to_info(k: &ApiKeyFile) -> ApiKeyInfo {
    ApiKeyInfo {
        id: k.id.clone(),
        name: k.name.clone(),
        created_at: k.created_at.clone(),
        wallet_ids: k.wallet_ids.clone(),
        policy_ids: k.policy_ids.clone(),
        expires_at: k.expires_at.clone(),
    }
}

/// Create an API key for agent access to one or more wallets.
pub fn create_api_key(
    vault: &Vault,
    name: &str,
    wallet_ids: &[String],
    policy_ids: &[String],
    passphrase: &str,
    expires_at: Option<&str>,
) -> Result<ApiKeyCreateResult, OwxError> {
    let token = crypto::generate_token();
    let mut wallet_secrets = HashMap::new();
    let mut resolved_ids = Vec::with_capacity(wallet_ids.len());

    for wid in wallet_ids {
        let wallet = vault.load_wallet(wid)?;
        let secret = decrypt_secret(&wallet, passphrase)?;
        let secret_bytes = secret.to_bytes()?;
        let hkdf_envelope = crypto::encrypt_hkdf(&secret_bytes, &token)?;
        let envelope_json = serde_json::to_value(&hkdf_envelope)?;
        wallet_secrets.insert(wallet.id.clone(), envelope_json);
        resolved_ids.push(wallet.id.clone());
    }

    for pid in policy_ids {
        vault.load_policy(pid)?;
    }

    let key_file = ApiKeyFile {
        id: uuid::Uuid::new_v4().to_string(),
        name: name.to_owned(),
        token_hash: crypto::hash_token(&token),
        created_at: chrono::Utc::now().to_rfc3339(),
        wallet_ids: resolved_ids,
        policy_ids: policy_ids.to_vec(),
        expires_at: expires_at.map(String::from),
        wallet_secrets,
    };

    vault.save_api_key(&key_file)?;

    Ok(ApiKeyCreateResult {
        token,
        key: key_to_info(&key_file),
    })
}

/// List all API keys (public info only).
pub fn list_api_keys(vault: &Vault) -> Result<Vec<ApiKeyInfo>, OwxError> {
    Ok(vault.list_api_keys()?.iter().map(key_to_info).collect())
}

/// Revoke (delete) an API key by ID.
pub fn revoke_api_key(vault: &Vault, id: &str) -> Result<(), OwxError> {
    vault.delete_api_key(id)?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use owx_core::policy::{Policy, PolicyAction, PolicyRule};
    use owx_core::wallet_file::{EncryptedWallet, KeyType, WalletAccount};

    use super::*;

    fn setup_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path()).unwrap();

        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let secret = crate::secret::WalletSecret::mnemonic(phrase);
        let secret_bytes = secret.to_bytes().unwrap();
        let envelope = crypto::encrypt(&secret_bytes, "pass").unwrap();
        let crypto_json = serde_json::to_value(&envelope).unwrap();

        let wallet = EncryptedWallet::new(
            "w1".to_owned(),
            "test-wallet".to_owned(),
            vec![WalletAccount {
                account_id: "eip155:1:0xabc".to_owned(),
                address: "0xabc".to_owned(),
                chain_id: "eip155:1".to_owned(),
                derivation_path: "m/44'/60'/0'/0/0".to_owned(),
            }],
            crypto_json,
            KeyType::Mnemonic,
        );
        vault.save_wallet(&wallet).unwrap();

        let policy = Policy {
            id: "p1".to_owned(),
            name: "Test".to_owned(),
            version: 1,
            created_at: "2026-01-01T00:00:00Z".to_owned(),
            rules: vec![PolicyRule::AllowedChains { chain_ids: vec!["eip155:8453".into()] }],
            executable: None,
            config: None,
            action: PolicyAction::Deny,
        };
        vault.save_policy(&policy).unwrap();

        (dir, vault)
    }

    #[test]
    fn create_and_list() {
        let (_dir, vault) = setup_vault();
        let result = create_api_key(
            &vault, "agent", &["w1".into()], &["p1".into()], "pass", None,
        ).unwrap();

        assert!(result.token.starts_with("owx_key_"));
        assert_eq!(result.key.name, "agent");

        let keys = list_api_keys(&vault).unwrap();
        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn revoke_works() {
        let (_dir, vault) = setup_vault();
        let result = create_api_key(
            &vault, "agent", &["w1".into()], &["p1".into()], "pass", None,
        ).unwrap();

        revoke_api_key(&vault, &result.key.id).unwrap();
        assert_eq!(list_api_keys(&vault).unwrap().len(), 0);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let (_dir, vault) = setup_vault();
        let result = create_api_key(
            &vault, "agent", &["w1".into()], &["p1".into()], "wrong", None,
        );
        assert!(result.is_err());
    }
}
