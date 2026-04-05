//! API key types, creation, listing, revocation, and token-based access.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::Owx;
use crate::chain::{ChainFamily, default_chain};
use crate::error::Error;
use crate::policy::{self, Policy, PolicyContext, SpendingContext, TransactionContext};
use crate::secret::{WalletSecret, decrypt_from_envelope, decrypt_secret};
use crate::signer;

/// On-disk API key file stored at `<vault>/keys/<id>.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyFile {
    /// Unique key identifier (UUID v4).
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// SHA-256 hash of the raw token (hex-encoded).
    pub token_hash: String,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
    /// Wallet IDs this key can access.
    pub wallet_ids: Vec<String>,
    /// Policy IDs attached to this key (AND semantics).
    pub policy_ids: Vec<String>,
    /// Optional expiry timestamp (ISO-8601).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Per-wallet encrypted secret copies, keyed by wallet ID.
    pub wallet_secrets: HashMap<String, serde_json::Value>,
}

/// Public API key information (no token or secrets exposed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyInfo {
    /// Unique key identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
    /// Wallet IDs this key can access.
    pub wallet_ids: Vec<String>,
    /// Policy IDs attached to this key.
    pub policy_ids: Vec<String>,
    /// Optional expiry timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// Result of creating an API key (shown once to the user).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyCreateResult {
    /// The raw API token (`owx_key_…`). Only returned at creation time.
    pub token: String,
    /// Public key metadata.
    pub key: ApiKeyInfo,
}

/// Convert an [`ApiKeyFile`] to the public-facing [`ApiKeyInfo`].
fn to_info(k: &ApiKeyFile) -> ApiKeyInfo {
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
    vault: &Owx,
    name: &str,
    wallet_ids: &[String],
    policy_ids: &[String],
    passphrase: &str,
    expires_at: Option<&str>,
) -> Result<ApiKeyCreateResult, Error> {
    let token = crate::token::generate_token();
    let mut wallet_secrets = HashMap::new();
    let mut resolved_ids = Vec::with_capacity(wallet_ids.len());

    for wid in wallet_ids {
        let wallet = crate::wallet::load_wallet(vault, wid)?;
        let secret = decrypt_secret(&wallet, passphrase)?;
        let mut secret_bytes = secret.to_bytes()?;
        let hkdf_envelope = owx_vault::crypto::encrypt_hkdf(&secret_bytes, &token)?;
        secret_bytes.zeroize();
        let envelope_json = serde_json::to_value(&hkdf_envelope)?;
        wallet_secrets.insert(wallet.id.clone(), envelope_json);
        resolved_ids.push(wallet.id.clone());
    }

    for pid in policy_ids {
        policy::load_policy(vault.store(), pid)?;
    }

    let key_file = ApiKeyFile {
        id: uuid::Uuid::new_v4().to_string(),
        name: name.to_owned(),
        token_hash: crate::token::hash_token(&token),
        created_at: chrono::Utc::now().to_rfc3339(),
        wallet_ids: resolved_ids,
        policy_ids: policy_ids.to_vec(),
        expires_at: expires_at.map(String::from),
        wallet_secrets,
    };

    vault.store().save("keys", &key_file.id, &key_file)?;

    Ok(ApiKeyCreateResult {
        token,
        key: to_info(&key_file),
    })
}

/// List all API keys (public info only).
pub fn list_api_keys(vault: &Owx) -> Result<Vec<ApiKeyInfo>, Error> {
    let mut keys: Vec<ApiKeyFile> = vault.store().list("keys")?;
    keys.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(keys.iter().map(to_info).collect())
}

/// Revoke (delete) an API key by ID.
pub fn revoke_api_key(vault: &Owx, id: &str) -> Result<(), Error> {
    vault
        .store()
        .delete("keys", id)
        .map_err(|_| Error::ApiKeyNotFound(id.to_owned()))
}

/// Resolve the hex private key for signing via an API token (agent mode).
///
/// Validates token → checks expiry → loads wallet → enforces policies → decrypts.
/// Returns a [`Zeroizing<String>`] that is automatically scrubbed on drop.
pub fn resolve_agent_key(
    vault: &Owx,
    wallet_name_or_id: &str,
    token: &str,
    family: ChainFamily,
    index: u32,
) -> Result<Zeroizing<String>, Error> {
    let token_hash = crate::token::hash_token(token);
    let api_key = find_key_by_hash(vault, &token_hash)?;

    if let Some(ref exp) = api_key.expires_at {
        let expires = chrono::DateTime::parse_from_rfc3339(exp)
            .map_err(|e| Error::InvalidInput(format!("invalid expires_at '{exp}': {e}")))?;
        if chrono::Utc::now() >= expires {
            return Err(Error::ApiKeyExpired(api_key.id));
        }
    }

    let wallet = crate::wallet::load_wallet(vault, wallet_name_or_id)?;
    if !api_key.wallet_ids.contains(&wallet.id) {
        return Err(Error::InvalidInput(format!(
            "API key '{}' does not have access to wallet '{}'",
            api_key.id, wallet.id
        )));
    }

    let chain = default_chain(family);
    let policies: Vec<Policy> = api_key
        .policy_ids
        .iter()
        .filter_map(|pid| policy::load_policy(vault.store(), pid).ok())
        .collect();

    if !policies.is_empty() {
        let ctx = PolicyContext {
            chain_id: chain.chain_id.to_owned(),
            wallet_id: wallet.id.clone(),
            api_key_id: api_key.id.clone(),
            transaction: TransactionContext {
                to: None,
                value: None,
                raw_hex: String::new(),
                data: None,
            },
            spending: SpendingContext {
                daily_total: "0".to_owned(),
                date: chrono::Utc::now().format("%Y-%m-%d").to_string(),
            },
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        let result = policy::evaluate(&policies, &ctx);
        if !result.allow {
            return Err(Error::PolicyDenied {
                policy_id: result.policy_id.unwrap_or_default(),
                reason: result.reason.unwrap_or_default(),
            });
        }
    }

    let envelope_value = api_key.wallet_secrets.get(&wallet.id).ok_or_else(|| {
        Error::InvalidInput(format!(
            "API key has no encrypted secret for wallet '{}'",
            wallet.id
        ))
    })?;
    let envelope: owx_vault::CryptoEnvelope = serde_json::from_value(envelope_value.clone())?;
    let secret = decrypt_from_envelope(&envelope, token, wallet.key_type)?;
    extract_key_hex(&secret, family, index).map(Zeroizing::new)
}

/// Resolve signing key: passphrase (owner) or API token (agent).
///
/// Returns a [`Zeroizing<String>`] that is automatically scrubbed on drop.
pub fn resolve_signing_key(
    vault: &Owx,
    wallet_name_or_id: &str,
    credential: &str,
    family: ChainFamily,
    index: u32,
) -> Result<Zeroizing<String>, Error> {
    if crate::token::is_api_token(credential) {
        return resolve_agent_key(vault, wallet_name_or_id, credential, family, index);
    }
    let wallet = crate::wallet::load_wallet(vault, wallet_name_or_id)?;
    let secret = decrypt_secret(&wallet, credential)?;
    extract_key_hex(&secret, family, index).map(Zeroizing::new)
}

/// Extract the hex private key from a decrypted wallet secret.
fn extract_key_hex(
    secret: &WalletSecret,
    family: ChainFamily,
    index: u32,
) -> Result<String, Error> {
    if let Some(phrase) = secret.phrase() {
        let kw = kobe::Wallet::from_mnemonic(phrase, None)
            .map_err(|e| Error::Derivation(e.to_string()))?;
        signer::derive_private_key_hex(&kw, family, index)
    } else {
        secret
            .private_key_hex(family)
            .map(ToOwned::to_owned)
            .ok_or_else(|| Error::InvalidInput(format!("no private key for chain family {family}")))
    }
}

/// Look up an API key by token hash (constant-time comparison).
fn find_key_by_hash(vault: &Owx, token_hash: &str) -> Result<ApiKeyFile, Error> {
    let keys: Vec<ApiKeyFile> = vault.store().list("keys")?;
    keys.into_iter()
        .find(|k| k.token_hash.as_bytes().ct_eq(token_hash.as_bytes()).into())
        .ok_or_else(|| Error::ApiKeyNotFound("<redacted>".to_owned()))
}
