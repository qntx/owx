//! Agent-native, self-custodial, policy-gated, multi-chain wallet toolkit.
//!
//! All public operations are methods on [`Owx`], the stateful orchestrator
//! that owns the vault store, config, audit log, and HTTP client.
//!
//! ```ignore
//! let owx = Owx::open("~/.owx")?;
//! let info = owx.create_wallet("my-wallet", "pass", 12)?;
//! let sig  = owx.sign_message("my-wallet", "evm", b"hello",
//!     Credential::Passphrase("pass")).await?;
//! ```

mod audit;
mod auth;
pub(crate) mod broadcast;
pub mod chain;
pub mod config;
mod error;
pub(crate) mod key;
pub mod policy;
pub(crate) mod secret;
pub(crate) mod signing;
pub(crate) mod wallet;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

pub use audit::{AuditEntry, AuditOp};
pub use auth::Credential;
pub use error::OwxError;
use error::OwxError as Error;
pub use key::{ApiKeyCreateResult, ApiKeyInfo};
pub use signing::{SendResult, SignResult, address_from_hex};
pub use wallet::{AccountInfo, ImportKeyOptions, WalletInfo};

/// The OWX orchestrator — stateful entry point for all operations.
///
/// Owns the vault store, cached config, audit log, and shared HTTP client.
/// Clone is cheap (`Arc`-backed config).
#[derive(Debug)]
pub struct Owx {
    /// Underlying file-system store.
    pub(crate) store: owx_vault::Store,
    /// Cached configuration.
    pub(crate) config: Arc<config::Config>,
    /// Append-only audit log.
    pub(crate) audit: audit::AuditLog,
    /// Shared async HTTP client for broadcast/pay/swap.
    pub(crate) http: reqwest::Client,
}

impl Owx {
    /// Open (or create) an OWX instance at the given vault path.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Vault`] if the store cannot be opened, or [`Error::Json`]
    /// if the config file is malformed.
    pub fn open(vault_path: impl Into<PathBuf>) -> Result<Self, Error> {
        let path = vault_path.into();
        let store = owx_vault::Store::open(&path)?;
        let config = config::Config::load_or_default_from(&path.join("config.json"))?;
        let audit = audit::AuditLog::new(&path);
        let http = build_http_client()?;
        Ok(Self {
            store,
            config: Arc::new(config),
            audit,
            http,
        })
    }

    /// Open the default vault at `~/.owx`.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the default path cannot be resolved or the vault
    /// cannot be opened.
    pub fn open_default() -> Result<Self, Error> {
        Self::open(config::default_vault_path()?)
    }

    /// Access the underlying generic store.
    #[must_use]
    pub const fn store(&self) -> &owx_vault::Store {
        &self.store
    }

    /// Access the cached config.
    #[must_use]
    pub fn config(&self) -> &config::Config {
        &self.config
    }

    /// Access the shared HTTP client.
    #[must_use]
    pub const fn http(&self) -> &reqwest::Client {
        &self.http
    }

    /// Generate a new BIP-39 mnemonic phrase.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInput`] if `words` is not 12 or 24.
    pub fn generate_mnemonic(&self, words: usize) -> Result<String, Error> {
        wallet::generate_mnemonic(words)
    }

    /// Create a new wallet.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if mnemonic generation, encryption, or storage fails.
    pub fn create_wallet(
        &self,
        name: &str,
        passphrase: &str,
        words: usize,
    ) -> Result<WalletInfo, Error> {
        let info = wallet::create_wallet(self, name, passphrase, words)?;
        self.audit
            .log_ok(AuditOp::CreateWallet, Some(&info.id), None, None);
        Ok(info)
    }

    /// Import from mnemonic.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the mnemonic is invalid or encryption/storage fails.
    pub fn import_mnemonic(
        &self,
        name: &str,
        phrase: &str,
        passphrase: &str,
        index: u32,
    ) -> Result<WalletInfo, Error> {
        let info = wallet::import_mnemonic(self, name, phrase, passphrase, index)?;
        self.audit
            .log_ok(AuditOp::ImportMnemonic, Some(&info.id), None, None);
        Ok(info)
    }

    /// Import from private key.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the key is invalid or encryption/storage fails.
    pub fn import_private_key(
        &self,
        name: &str,
        key_hex: &str,
        passphrase: &str,
        opts: &ImportKeyOptions<'_>,
    ) -> Result<WalletInfo, Error> {
        let info = wallet::import_private_key(self, name, key_hex, passphrase, opts)?;
        self.audit
            .log_ok(AuditOp::ImportPrivateKey, Some(&info.id), None, None);
        Ok(info)
    }

    /// Import from dual-curve keys.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if either key is invalid or encryption/storage fails.
    pub fn import_private_keys(
        &self,
        name: &str,
        secp: &str,
        ed: &str,
        passphrase: &str,
    ) -> Result<WalletInfo, Error> {
        let info = wallet::import_private_keys(self, name, secp, ed, passphrase)?;
        self.audit
            .log_ok(AuditOp::ImportPrivateKeys, Some(&info.id), None, None);
        Ok(info)
    }

    /// List all wallets (newest first).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Vault`] if the store cannot be read.
    pub fn list_wallets(&self) -> Result<Vec<WalletInfo>, Error> {
        wallet::list_wallets(self)
    }

    /// Get a wallet by name or ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::WalletNotFound`] or [`Error::AmbiguousWallet`] on lookup failure.
    pub fn get_wallet(&self, name_or_id: &str) -> Result<WalletInfo, Error> {
        wallet::get_wallet(self, name_or_id)
    }

    /// Delete a wallet.
    ///
    /// # Errors
    ///
    /// Returns [`Error::WalletNotFound`] if the wallet does not exist.
    pub fn delete_wallet(&self, name_or_id: &str) -> Result<(), Error> {
        wallet::delete_wallet(self, name_or_id)?;
        self.audit
            .log_ok(AuditOp::DeleteWallet, Some(name_or_id), None, None);
        Ok(())
    }

    /// Rename a wallet.
    ///
    /// # Errors
    ///
    /// Returns [`Error::WalletNotFound`] or [`Error::WalletNameExists`] on conflict.
    pub fn rename_wallet(&self, name_or_id: &str, new_name: &str) -> Result<(), Error> {
        wallet::rename_wallet(self, name_or_id, new_name)?;
        self.audit
            .log_ok(AuditOp::RenameWallet, Some(name_or_id), None, None);
        Ok(())
    }

    /// Export a wallet secret.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the wallet is not found or decryption fails.
    pub fn export_wallet(
        &self,
        name_or_id: &str,
        passphrase: &str,
    ) -> Result<zeroize::Zeroizing<String>, Error> {
        match wallet::export_wallet(self, name_or_id, passphrase) {
            Ok(secret) => {
                self.audit
                    .log_ok(AuditOp::ExportWallet, Some(name_or_id), None, None);
                Ok(secret)
            }
            Err(e) => {
                self.audit.log_err(
                    AuditOp::ExportWallet,
                    Some(name_or_id),
                    None,
                    &e.to_string(),
                );
                Err(e)
            }
        }
    }

    /// Derive an address for a chain.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the chain is unknown, wallet not found, or derivation fails.
    pub fn derive_address(
        &self,
        wallet: &str,
        chain: &str,
        passphrase: &str,
        index: Option<u32>,
    ) -> Result<String, Error> {
        wallet::derive_address(self, wallet, chain, passphrase, index)
    }

    /// Sign a message.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if key resolution, policy check, or signing fails.
    pub fn sign_message(
        &self,
        wallet: &str,
        chain: &str,
        message: &[u8],
        cred: Credential<'_>,
    ) -> Result<SignResult, Error> {
        let resolved = chain::resolve(chain)?;
        let key = self.resolve_key_audited(AuditOp::SignMessage, wallet, &resolved, &cred)?;
        let out = signing::sign_message(resolved.family(), &key, message)?;
        self.audit_sign_ok(AuditOp::SignMessage, wallet, &resolved, &cred);
        Ok(signing::to_sign_result(&out))
    }

    /// Sign a transaction (hex-encoded).
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the hex is invalid, key resolution, or signing fails.
    pub fn sign_transaction(
        &self,
        wallet: &str,
        chain: &str,
        tx_hex: &str,
        cred: Credential<'_>,
    ) -> Result<SignResult, Error> {
        let resolved = chain::resolve(chain)?;
        let clean = tx_hex.strip_prefix("0x").unwrap_or(tx_hex);
        let tx_bytes =
            hex::decode(clean).map_err(|e| Error::InvalidInput(format!("invalid hex: {e}")))?;
        let key = self.resolve_key_audited(AuditOp::SignTransaction, wallet, &resolved, &cred)?;
        let out = signing::sign_transaction(resolved.family(), &key, &tx_bytes)?;
        self.audit_sign_ok(AuditOp::SignTransaction, wallet, &resolved, &cred);
        Ok(signing::to_sign_result(&out))
    }

    /// Sign EIP-712 typed data (EVM only).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInput`] for non-EVM chains, or [`Error`] if
    /// key resolution or signing fails.
    pub fn sign_typed_data(
        &self,
        wallet: &str,
        chain: &str,
        typed_data: &str,
        cred: Credential<'_>,
    ) -> Result<SignResult, Error> {
        let resolved = chain::resolve(chain)?;
        if resolved.family() != chain::ChainFamily::Evm {
            return Err(Error::InvalidInput("EIP-712 is EVM-only".into()));
        }
        let key = self.resolve_key_audited(AuditOp::SignTypedData, wallet, &resolved, &cred)?;
        let out = signing::sign_typed_data(&key, typed_data)?;
        self.audit_sign_ok(AuditOp::SignTypedData, wallet, &resolved, &cred);
        Ok(signing::to_sign_result(&out))
    }

    /// Sign and broadcast a transaction.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if signing, RPC resolution, or broadcast fails.
    pub async fn sign_and_send(
        &self,
        wallet: &str,
        chain: &str,
        tx_hex: &str,
        cred: Credential<'_>,
        rpc_url: Option<&str>,
    ) -> Result<SendResult, Error> {
        let resolved = chain::resolve(chain)?;
        let family = resolved.family();
        let chain_id = resolved.chain_id();
        let clean = tx_hex.strip_prefix("0x").unwrap_or(tx_hex);
        let tx_bytes =
            hex::decode(clean).map_err(|e| Error::InvalidInput(format!("invalid hex: {e}")))?;
        let key = key::resolve_signing_key(self, wallet, cred.as_str(), family, 0)?;
        let sig = signing::sign_transaction(family, &key, &tx_bytes)?;
        let payload = signing::encode_signed_tx(family, &key, &tx_bytes, &sig)?;
        let rpc = broadcast::resolve_rpc(chain_id, rpc_url, &self.config)?;
        let tx_hash = broadcast::broadcast(&self.http, family, &rpc, &payload).await?;
        let audit_id = credential_audit_id(&cred);
        self.audit.log_ok(
            AuditOp::SignAndSend,
            Some(wallet),
            Some(chain_id),
            audit_id.as_deref(),
        );
        Ok(SendResult { tx_hash })
    }

    /// Execute a closure with temporary access to a wallet's signing key.
    ///
    /// The raw hex key is passed by reference to the closure and **zeroized
    /// immediately** after the closure returns. The key never escapes as an
    /// owned `String`, so callers cannot accidentally retain it.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if key resolution fails or the closure returns an error.
    pub fn with_signing_key<F, R>(
        &self,
        wallet: &str,
        cred: Credential<'_>,
        family: chain::ChainFamily,
        index: u32,
        f: F,
    ) -> Result<R, Error>
    where
        F: FnOnce(&str) -> Result<R, Error>,
    {
        let key = key::resolve_signing_key(self, wallet, cred.as_str(), family, index)?;
        f(&key)
    }

    /// Create an API key.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if encryption or storage fails.
    pub fn create_api_key(
        &self,
        name: &str,
        wallet_ids: &[String],
        policy_ids: &[String],
        passphrase: &str,
        expires_at: Option<&str>,
    ) -> Result<ApiKeyCreateResult, Error> {
        let result =
            key::create_api_key(self, name, wallet_ids, policy_ids, passphrase, expires_at)?;
        self.audit.log_ok(AuditOp::CreateApiKey, None, None, None);
        Ok(result)
    }

    /// List all API keys.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Vault`] if the store cannot be read.
    pub fn list_api_keys(&self) -> Result<Vec<ApiKeyInfo>, Error> {
        key::list_api_keys(self)
    }

    /// Revoke an API key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ApiKeyNotFound`] if the key does not exist.
    pub fn revoke_api_key(&self, id: &str) -> Result<(), Error> {
        key::revoke_api_key(self, id)?;
        self.audit.log_ok(AuditOp::RevokeApiKey, None, None, None);
        Ok(())
    }

    /// Read all audit log entries.
    ///
    /// Returns an empty vec if the log file does not exist.
    /// Malformed lines are silently skipped.
    #[must_use]
    pub fn audit_log(&self) -> Vec<AuditEntry> {
        self.audit.read_all()
    }

    /// Create (or overwrite) a policy from a JSON string.
    ///
    /// The JSON is validated before persisting.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInput`] if the JSON is not a valid [`policy::Policy`],
    /// or [`Error::Vault`] if storage fails.
    pub fn create_policy(&self, id: &str, json: &str) -> Result<(), Error> {
        serde_json::from_str::<policy::Policy>(json)
            .map_err(|e| Error::InvalidInput(format!("invalid policy JSON: {e}")))?;
        self.store.save_raw("policies", id, json)?;
        Ok(())
    }

    /// List all policies sorted alphabetically by name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Vault`] if the store cannot be read.
    pub fn list_policies(&self) -> Result<Vec<policy::Policy>, Error> {
        policy::list_policies(&self.store)
    }

    /// Load a single policy by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PolicyNotFound`] if the policy does not exist.
    pub fn get_policy(&self, id: &str) -> Result<policy::Policy, Error> {
        policy::load_policy(&self.store, id)
    }

    /// Delete a policy by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Vault`] if the policy does not exist or deletion fails.
    pub fn delete_policy(&self, id: &str) -> Result<(), Error> {
        self.store.delete("policies", id)?;
        Ok(())
    }

    /// Resolve a signing key with audit logging on failure.
    fn resolve_key_audited(
        &self,
        op: AuditOp,
        wallet: &str,
        resolved: &chain::ResolvedChain,
        cred: &Credential<'_>,
    ) -> Result<zeroize::Zeroizing<String>, Error> {
        key::resolve_signing_key(self, wallet, cred.as_str(), resolved.family(), 0).inspect_err(
            |e| {
                self.audit
                    .log_err(op, Some(wallet), Some(resolved.chain_id()), &e.to_string());
            },
        )
    }

    /// Record a successful signing audit entry.
    fn audit_sign_ok(
        &self,
        op: AuditOp,
        wallet: &str,
        resolved: &chain::ResolvedChain,
        cred: &Credential<'_>,
    ) {
        let audit_id = credential_audit_id(cred);
        self.audit.log_ok(
            op,
            Some(wallet),
            Some(resolved.chain_id()),
            audit_id.as_deref(),
        );
    }
}

/// Extract an audit-safe identifier from a credential.
fn credential_audit_id(cred: &Credential<'_>) -> Option<String> {
    match cred {
        Credential::ApiToken(t) => Some(auth::hash_token(t)),
        Credential::Passphrase(_) => None,
    }
}

/// Build the shared async HTTP client.
///
/// # Errors
///
/// Returns [`Error::InvalidInput`] if the HTTP client builder fails.
fn build_http_client() -> Result<reqwest::Client, Error> {
    reqwest::Client::builder()
        .pool_max_idle_per_host(20)
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| Error::InvalidInput(format!("failed to build HTTP client: {e}")))
}
