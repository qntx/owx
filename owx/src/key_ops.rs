//! API key creation and token-based signing flows.

use std::collections::HashMap;

use owx_vault::api_key::{self, ApiKeyFile};
use owx_vault::crypto;
use owx_vault::store::Vault;

use crate::error::OwxError;
use crate::wallet_ops;

/// Create an API key for agent access to one or more wallets.
///
/// 1. Authenticates with the owner's passphrase
/// 2. Decrypts the mnemonic for each wallet
/// 3. Generates a random token (`owx_key_...`)
/// 4. Re-encrypts each mnemonic under HKDF(token)
/// 5. Stores the key file
/// 6. Returns the raw token (shown once)
pub fn create_api_key(
    vault: &Vault,
    name: &str,
    wallet_ids: &[String],
    policy_ids: &[String],
    passphrase: &str,
    expires_at: Option<&str>,
) -> Result<(String, ApiKeyFile), OwxError> {
    let mut wallet_secrets = HashMap::new();
    let mut resolved_ids = Vec::with_capacity(wallet_ids.len());
    let token = api_key::generate_token();

    for wid in wallet_ids {
        let wallet = vault.load_wallet(wid)?;
        let mnemonic = wallet_ops::decrypt_mnemonic(&wallet, passphrase)?;

        let hkdf_envelope = crypto::encrypt_hkdf(mnemonic.as_bytes(), &token)?;
        let envelope_json = serde_json::to_value(&hkdf_envelope)?;

        wallet_secrets.insert(wallet.id.clone(), envelope_json);
        resolved_ids.push(wallet.id.clone());
    }

    for pid in policy_ids {
        vault.load_policy_raw(pid)?;
    }

    let id = uuid::Uuid::new_v4().to_string();
    let key_file = ApiKeyFile::new(
        id,
        name.to_owned(),
        api_key::hash_token(&token),
        chrono::Utc::now().to_rfc3339(),
        resolved_ids,
        policy_ids.to_vec(),
        expires_at.map(String::from),
        wallet_secrets,
    );

    vault.save_api_key(&key_file)?;
    Ok((token, key_file))
}

/// Resolve a mnemonic from an API token (agent mode).
///
/// 1. Look up key file by SHA256(token)
/// 2. Check expiry
/// 3. Check wallet scope
/// 4. Load and evaluate policies
/// 5. HKDF(token) → decrypt mnemonic
pub(crate) fn resolve_mnemonic_from_token(
    vault: &Vault,
    token: &str,
    wallet_name_or_id: &str,
    chain_id: &str,
) -> Result<String, OwxError> {
    let token_hash = api_key::hash_token(token);
    let key_file = vault.load_api_key_by_token_hash(&token_hash)?;

    check_expiry(&key_file)?;

    let wallet = vault.load_wallet(wallet_name_or_id)?;
    if !key_file.wallet_ids.contains(&wallet.id) {
        return Err(OwxError::InvalidInput(format!(
            "API key '{}' does not have access to wallet '{}'",
            key_file.name, wallet.id,
        )));
    }

    let policies = load_policies(vault, &key_file)?;
    if !policies.is_empty() {
        let context = owx_policy::PolicyContext::new(
            chain_id.to_owned(),
            wallet.id.clone(),
            key_file.id.clone(),
            owx_policy::types::TransactionContext::new(None, None, String::new()),
            chrono::Utc::now().to_rfc3339(),
        );
        let result = owx_policy::evaluate(&policies, &context);
        if !result.allow {
            return Err(OwxError::PolicyDenied {
                policy_id: result.policy_id.unwrap_or_default(),
                reason: result.reason.unwrap_or_else(|| "denied".into()),
            });
        }
    }

    let envelope_value = key_file.wallet_secrets.get(&wallet.id).ok_or_else(|| {
        OwxError::InvalidInput(format!(
            "API key has no encrypted secret for wallet {}",
            wallet.id
        ))
    })?;

    let envelope: owx_vault::CryptoEnvelope = serde_json::from_value(envelope_value.clone())?;
    let secret = crypto::decrypt(&envelope, token)?;

    String::from_utf8(secret.expose().to_vec())
        .map_err(|_| OwxError::InvalidInput("wallet contains invalid UTF-8 mnemonic".into()))
}

/// Check whether an API key has expired.
fn check_expiry(key_file: &ApiKeyFile) -> Result<(), OwxError> {
    if let Some(ref expires) = key_file.expires_at {
        let now = chrono::Utc::now().to_rfc3339();
        if now.as_str() > expires.as_str() {
            return Err(OwxError::ApiKeyExpired {
                id: key_file.id.clone(),
            });
        }
    }
    Ok(())
}

/// Load all policies referenced by an API key file.
fn load_policies(
    vault: &Vault,
    key_file: &ApiKeyFile,
) -> Result<Vec<owx_policy::Policy>, OwxError> {
    let mut policies = Vec::with_capacity(key_file.policy_ids.len());
    for pid in &key_file.policy_ids {
        let json = vault.load_policy_raw(pid)?;
        let policy: owx_policy::Policy = serde_json::from_str(&json)?;
        policies.push(policy);
    }
    Ok(policies)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn setup(vault: &Vault) -> String {
        wallet_ops::import_mnemonic(vault, "test-wallet", TEST_MNEMONIC, "pass", 0)
            .unwrap()
            .id
    }

    fn setup_policy(vault: &Vault) {
        let policy = serde_json::json!({
            "id": "test-policy",
            "name": "Test",
            "version": 1,
            "created_at": "2026-01-01T00:00:00Z",
            "rules": [{"type": "allowed_chains", "chain_ids": ["eip155:8453"]}],
            "action": "deny"
        });
        vault
            .save_policy_raw("test-policy", &policy.to_string())
            .unwrap();
    }

    #[test]
    fn create_api_key_and_resolve() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        let wallet_id = setup(&vault);
        setup_policy(&vault);

        let (token, key_file) = create_api_key(
            &vault,
            "agent",
            &[wallet_id.clone()],
            &["test-policy".to_owned()],
            "pass",
            None,
        )
        .unwrap();

        assert!(token.starts_with("owx_key_"));
        assert_eq!(key_file.wallet_ids, vec![wallet_id]);

        let mnemonic =
            resolve_mnemonic_from_token(&vault, &token, "test-wallet", "eip155:8453").unwrap();
        assert_eq!(mnemonic, TEST_MNEMONIC);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        let wallet_id = setup(&vault);

        let result = create_api_key(&vault, "a", &[wallet_id], &[], "wrong", None);
        assert!(result.is_err());
    }

    #[test]
    fn expired_key_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        let wallet_id = setup(&vault);

        let (token, _) = create_api_key(
            &vault,
            "a",
            &[wallet_id],
            &[],
            "pass",
            Some("2020-01-01T00:00:00Z"),
        )
        .unwrap();

        let result = resolve_mnemonic_from_token(&vault, &token, "test-wallet", "eip155:1");
        assert!(matches!(result, Err(OwxError::ApiKeyExpired { .. })));
    }

    #[test]
    fn policy_denies_wrong_chain() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        let wallet_id = setup(&vault);
        setup_policy(&vault);

        let (token, _) = create_api_key(
            &vault,
            "a",
            &[wallet_id],
            &["test-policy".to_owned()],
            "pass",
            None,
        )
        .unwrap();

        let result = resolve_mnemonic_from_token(&vault, &token, "test-wallet", "eip155:1");
        assert!(matches!(result, Err(OwxError::PolicyDenied { .. })));
    }
}
