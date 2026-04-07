//! API key types, creation, listing, revocation, and token-based access.

use std::collections::HashMap;

use owx_vault::CryptoEnvelope;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::Owx;
use crate::chain::{ChainFamily, default_chain};
use crate::error::OwxError as Error;
use crate::policy::{self, Policy, PolicyContext, SpendingContext, TransactionContext};
use crate::secret::{WalletSecret, decrypt_from_envelope, decrypt_secret};
use crate::signing;

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
    pub wallet_secrets: HashMap<String, CryptoEnvelope>,
}

/// Public API key information (no token or secrets exposed).
#[non_exhaustive]
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
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct ApiKeyCreateResult {
    /// The raw API token (`owx_key_…`). Only returned at creation time.
    /// Wrapped in [`Zeroizing`] so it is scrubbed when this struct is dropped.
    pub token: Zeroizing<String>,
    /// Public key metadata.
    pub key: ApiKeyInfo,
}

impl Serialize for ApiKeyCreateResult {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("ApiKeyCreateResult", 2)?;
        s.serialize_field("token", self.token.as_str())?;
        s.serialize_field("key", &self.key)?;
        s.end()
    }
}

impl From<&ApiKeyFile> for ApiKeyInfo {
    fn from(k: &ApiKeyFile) -> Self {
        Self {
            id: k.id.clone(),
            name: k.name.clone(),
            created_at: k.created_at.clone(),
            wallet_ids: k.wallet_ids.clone(),
            policy_ids: k.policy_ids.clone(),
            expires_at: k.expires_at.clone(),
        }
    }
}

/// Create an API key for agent access to one or more wallets.
pub(crate) fn create_api_key(
    vault: &Owx,
    name: &str,
    wallet_ids: &[String],
    policy_ids: &[String],
    passphrase: &str,
    expires_at: Option<&str>,
) -> Result<ApiKeyCreateResult, Error> {
    let token = crate::auth::generate_token()?;
    let mut wallet_secrets = HashMap::new();
    let mut resolved_ids = Vec::with_capacity(wallet_ids.len());

    for wid in wallet_ids {
        let wallet = crate::wallet::load_wallet(vault, wid)?;
        let secret = decrypt_secret(&wallet, passphrase)?;
        let secret_bytes = secret.to_bytes()?;
        let hkdf_envelope = owx_vault::crypto::encrypt_hkdf(&secret_bytes, &token)?;
        wallet_secrets.insert(wallet.id.clone(), hkdf_envelope);
        resolved_ids.push(wallet.id.clone());
    }

    for pid in policy_ids {
        policy::load_policy(vault.store(), pid)?;
    }

    if let Some(exp) = expires_at {
        chrono::DateTime::parse_from_rfc3339(exp)
            .map_err(|e| Error::InvalidInput(format!("invalid expires_at '{exp}': {e}")))?;
    }

    let key_file = ApiKeyFile {
        id: uuid::Uuid::new_v4().to_string(),
        name: name.to_owned(),
        token_hash: crate::auth::hash_token(&token),
        created_at: chrono::Utc::now().to_rfc3339(),
        wallet_ids: resolved_ids,
        policy_ids: policy_ids.to_vec(),
        expires_at: expires_at.map(String::from),
        wallet_secrets,
    };

    vault.store().save("keys", &key_file.id, &key_file)?;

    Ok(ApiKeyCreateResult {
        token: Zeroizing::new(token),
        key: ApiKeyInfo::from(&key_file),
    })
}

/// List all API keys (public info only).
pub(crate) fn list_api_keys(vault: &Owx) -> Result<Vec<ApiKeyInfo>, Error> {
    let mut keys: Vec<ApiKeyFile> = vault.store().list("keys")?;
    keys.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(keys.iter().map(ApiKeyInfo::from).collect())
}

/// Revoke (delete) an API key by ID.
pub(crate) fn revoke_api_key(vault: &Owx, id: &str) -> Result<(), Error> {
    vault
        .store()
        .delete("keys", id)
        .map_err(|_| Error::ApiKeyNotFound(id.to_owned()))
}

/// Resolve the hex private key for signing via an API token (agent mode).
///
/// Validates token → checks expiry → loads wallet → enforces policies → decrypts.
/// Returns a [`Zeroizing<String>`] that is automatically scrubbed on drop.
pub(crate) fn resolve_agent_key(
    vault: &Owx,
    wallet_name_or_id: &str,
    token: &str,
    family: ChainFamily,
    index: u32,
) -> Result<Zeroizing<String>, Error> {
    let token_hash = crate::auth::hash_token(token);
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
        return Err(Error::AccessDenied(format!(
            "API key '{}' does not have access to wallet '{}'",
            api_key.id, wallet.id
        )));
    }

    let chain = default_chain(family).ok_or_else(|| Error::UnknownChain(family.to_string()))?;
    let policies: Vec<Policy> = api_key
        .policy_ids
        .iter()
        .map(|pid| policy::load_policy(vault.store(), pid))
        .collect::<Result<Vec<_>, _>>()?;

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
                asset: None,
            },
            spending: SpendingContext {
                daily_total: "0".to_owned(),
                date: chrono::Utc::now().format("%Y-%m-%d").to_string(),
                asset: None,
            },
            timestamp: chrono::Utc::now(),
        };
        let result = policy::evaluate(&policies, &ctx);
        if !result.allow {
            return Err(Error::PolicyDenied {
                policy_id: result.policy_id.unwrap_or_default(),
                reason: result.reason.unwrap_or_default(),
            });
        }
    }

    let envelope = api_key.wallet_secrets.get(&wallet.id).ok_or_else(|| {
        Error::AccessDenied(format!(
            "API key has no encrypted secret for wallet '{}'",
            wallet.id
        ))
    })?;
    let secret = decrypt_from_envelope(envelope, token, wallet.key_type)?;
    extract_key_hex(&secret, family, index)
}

/// Resolve signing key: passphrase (owner) or API token (agent).
///
/// Returns a [`Zeroizing<String>`] that is automatically scrubbed on drop.
pub(crate) fn resolve_signing_key(
    vault: &Owx,
    wallet_name_or_id: &str,
    credential: &str,
    family: ChainFamily,
    index: u32,
) -> Result<Zeroizing<String>, Error> {
    if crate::auth::is_api_token(credential) {
        return resolve_agent_key(vault, wallet_name_or_id, credential, family, index);
    }
    let wallet = crate::wallet::load_wallet(vault, wallet_name_or_id)?;
    let secret = decrypt_secret(&wallet, credential)?;
    extract_key_hex(&secret, family, index)
}

/// Extract the hex private key from a decrypted wallet secret.
fn extract_key_hex(
    secret: &WalletSecret,
    family: ChainFamily,
    index: u32,
) -> Result<Zeroizing<String>, Error> {
    if let Some(phrase) = secret.phrase() {
        let kw = kobe::Wallet::from_mnemonic(phrase, None)?;
        signing::derive_private_key_hex(&kw, family, index)
    } else {
        secret
            .private_key_hex(family)
            .map(|s| Zeroizing::new(s.to_owned()))
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
