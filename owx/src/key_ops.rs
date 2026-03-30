#![allow(clippy::missing_docs_in_private_items, missing_docs)]

//! API key creation and token-based signing flows.

use std::collections::HashMap;

use owx_core::policy::{PolicyContext, SpendingContext, TransactionContext};
use owx_vault::api_key::{self, ApiKeyFile};
use owx_vault::crypto;
use owx_vault::store::Vault;
use zeroize::Zeroize;

use crate::error::OwxError;
use crate::wallet_secret::{
    WalletSecret, decrypt_wallet_secret, decrypt_wallet_secret_from_envelope,
};

#[derive(Debug, Clone)]
pub struct AccessRequest {
    pub chain_id: String,
    pub transaction: TransactionContext,
}

impl AccessRequest {
    pub fn message(chain_id: &str) -> Self {
        Self {
            chain_id: chain_id.to_owned(),
            transaction: TransactionContext {
                to: None,
                value: None,
                raw_hex: String::new(),
                data: None,
            },
        }
    }

    pub fn for_transaction(chain_id: &str, tx_context: TransactionContext) -> Self {
        Self {
            chain_id: chain_id.to_owned(),
            transaction: tx_context,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ApiKeyInfo {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub wallet_ids: Vec<String>,
    pub policy_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ApiKeyCreateResult {
    pub token: String,
    pub key: ApiKeyInfo,
}

fn api_key_to_info(key_file: &ApiKeyFile) -> ApiKeyInfo {
    ApiKeyInfo {
        id: key_file.id.clone(),
        name: key_file.name.clone(),
        created_at: key_file.created_at.clone(),
        wallet_ids: key_file.wallet_ids.clone(),
        policy_ids: key_file.policy_ids.clone(),
        expires_at: key_file.expires_at.clone(),
    }
}

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
) -> Result<ApiKeyCreateResult, OwxError> {
    let mut wallet_secrets = HashMap::new();
    let mut resolved_ids = Vec::with_capacity(wallet_ids.len());
    let token = api_key::generate_token();

    for wid in wallet_ids {
        let wallet = vault.load_wallet(wid)?;
        let secret = decrypt_wallet_secret(&wallet, passphrase)?;
        let mut secret_bytes = secret.into_bytes()?;
        let encrypted_secret = crypto::encrypt_hkdf(&secret_bytes, &token);
        secret_bytes.zeroize();
        let hkdf_envelope = encrypted_secret?;
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
        token_hash: api_key::hash_token(&token),
        created_at: chrono::Utc::now().to_rfc3339(),
        wallet_ids: resolved_ids,
        policy_ids: policy_ids.to_vec(),
        expires_at: expires_at.map(String::from),
        wallet_secrets,
    };

    vault.save_api_key(&key_file)?;
    Ok(ApiKeyCreateResult {
        token,
        key: api_key_to_info(&key_file),
    })
}

pub fn list_api_keys(vault: &Vault) -> Result<Vec<ApiKeyInfo>, OwxError> {
    Ok(vault.list_api_keys()?.iter().map(api_key_to_info).collect())
}

/// Resolve a mnemonic from an API token (agent mode).
///
/// 1. Look up key file by SHA256(token)
/// 2. Check expiry
/// 3. Check wallet scope
/// 4. Load and evaluate policies
/// 5. HKDF(token) → decrypt wallet secret
pub fn resolve_wallet_secret_from_token(
    vault: &Vault,
    token: &str,
    wallet_name_or_id: &str,
    request: &AccessRequest,
) -> Result<WalletSecret, OwxError> {
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
        let context = PolicyContext {
            chain_id: request.chain_id.clone(),
            wallet_id: wallet.id.clone(),
            api_key_id: key_file.id.clone(),
            transaction: request.transaction.clone(),
            spending: SpendingContext {
                daily_total: "0".to_owned(),
                date: chrono::Utc::now().format("%Y-%m-%d").to_string(),
            },
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
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
    decrypt_wallet_secret_from_envelope(&envelope, token, wallet.key_type)
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
        let policy = vault.load_policy(pid)?;
        policies.push(policy);
    }
    Ok(policies)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::wallet_ops;

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

        let result = create_api_key(
            &vault,
            "agent",
            std::slice::from_ref(&wallet_id),
            &["test-policy".to_owned()],
            "pass",
            None,
        )
        .unwrap();

        assert!(result.token.starts_with("owx_key_"));
        assert_eq!(result.key.wallet_ids, vec![wallet_id]);
        assert!(
            serde_json::to_string(&result.key)
                .unwrap()
                .contains("test-policy")
        );

        let listed = list_api_keys(&vault).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, result.key.id);

        let secret = resolve_wallet_secret_from_token(
            &vault,
            &result.token,
            "test-wallet",
            &AccessRequest::message("eip155:8453"),
        )
        .unwrap();
        assert_eq!(secret.phrase(), Some(TEST_MNEMONIC));
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

        let result = create_api_key(
            &vault,
            "a",
            &[wallet_id],
            &[],
            "pass",
            Some("2020-01-01T00:00:00Z"),
        )
        .unwrap();

        let resolution = resolve_wallet_secret_from_token(
            &vault,
            &result.token,
            "test-wallet",
            &AccessRequest::message("eip155:1"),
        );
        assert!(matches!(resolution, Err(OwxError::ApiKeyExpired { .. })));
    }

    #[test]
    fn policy_denies_wrong_chain() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        let wallet_id = setup(&vault);
        setup_policy(&vault);

        let result = create_api_key(
            &vault,
            "a",
            &[wallet_id],
            &["test-policy".to_owned()],
            "pass",
            None,
        )
        .unwrap();

        let resolution = resolve_wallet_secret_from_token(
            &vault,
            &result.token,
            "test-wallet",
            &AccessRequest::message("eip155:1"),
        );
        assert!(matches!(resolution, Err(OwxError::PolicyDenied { .. })));
    }
}
