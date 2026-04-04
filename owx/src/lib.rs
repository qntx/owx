//! Agent-native, self-custodial, policy-gated, multi-chain wallet toolkit.
//!
//! All public operations are `async` methods on [`Owx`], the stateful
//! orchestrator that owns the vault store, config, audit log, and HTTP client.
//!
//! ```ignore
//! let owx = Owx::open("~/.owx")?;
//! let info = owx.create_wallet("my-wallet", "pass", 12)?;
//! let sig  = owx.sign_message("my-wallet", "evm", b"hello",
//!     Credential::Passphrase("pass")).await?;
//! ```

pub mod audit;
pub mod broadcast;
pub mod chain;
pub mod config;
pub mod credential;
mod error;
pub mod key;
pub mod policy;
pub mod secret;
pub mod signer;
pub mod token;
pub mod wallet;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

pub use credential::{Credential, SecretKey};
pub use error::{Error, ErrorCode};
pub use key::{ApiKeyCreateResult, ApiKeyInfo};
pub use signer::{SendResult, SignResult};
pub use wallet::{AccountInfo, WalletInfo};

/// The OWX orchestrator — stateful entry point for all operations.
///
/// Owns the vault store, cached config, audit log, and shared HTTP client.
/// All methods are `async`-ready. Clone is cheap (`Arc`-backed config).
#[derive(Debug)]
pub struct Owx {
    /// Underlying file-system store.
    store: owx_vault::Store,
    /// Cached configuration.
    config: Arc<config::Config>,
    /// Append-only audit log.
    audit: audit::AuditLog,
    /// Shared async HTTP client for broadcast/pay/swap.
    http: reqwest::Client,
    /// Derived-key cache (instance-owned, not global).
    #[allow(dead_code)]
    key_cache: owx_vault::KeyCache,
}

impl Owx {
    /// Open (or create) an OWX instance at the given vault path.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, Error> {
        let path = path.into();
        let store = owx_vault::Store::open(&path)?;
        let config = config::Config::load_or_default_from(&path.join("config.json"));
        let audit = audit::AuditLog::new(&path);
        let http = build_http_client();
        let key_cache = owx_vault::KeyCache::new(Duration::from_secs(5), 32);
        Ok(Self {
            store,
            config: Arc::new(config),
            audit,
            http,
            key_cache,
        })
    }

    /// Open the default vault at `~/.owx`.
    pub fn open_default() -> Result<Self, Error> {
        Self::open(default_vault_path())
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
    pub fn generate_mnemonic(&self, words: usize) -> Result<String, Error> {
        wallet::generate_mnemonic(words)
    }

    /// Create a new wallet.
    pub fn create_wallet(
        &self,
        name: &str,
        passphrase: &str,
        words: usize,
    ) -> Result<WalletInfo, Error> {
        let info = wallet::create_wallet(self, name, passphrase, words)?;
        self.audit.log_ok("create_wallet", Some(&info.id), None);
        Ok(info)
    }

    /// Import from mnemonic.
    pub fn import_mnemonic(
        &self,
        name: &str,
        phrase: &str,
        passphrase: &str,
        index: u32,
    ) -> Result<WalletInfo, Error> {
        let info = wallet::import_mnemonic(self, name, phrase, passphrase, index)?;
        self.audit.log_ok("import_mnemonic", Some(&info.id), None);
        Ok(info)
    }

    /// Import from private key.
    pub fn import_private_key(
        &self,
        name: &str,
        key_hex: &str,
        chain: Option<&str>,
        passphrase: &str,
        secp256k1_hex: Option<&str>,
        ed25519_hex: Option<&str>,
    ) -> Result<WalletInfo, Error> {
        let info = wallet::import_private_key(
            self,
            name,
            key_hex,
            chain,
            passphrase,
            secp256k1_hex,
            ed25519_hex,
        )?;
        self.audit
            .log_ok("import_private_key", Some(&info.id), None);
        Ok(info)
    }

    /// Import from dual-curve keys.
    pub fn import_private_keys(
        &self,
        name: &str,
        secp: &str,
        ed: &str,
        passphrase: &str,
    ) -> Result<WalletInfo, Error> {
        self.import_private_key(name, "", None, passphrase, Some(secp), Some(ed))
    }

    /// List all wallets (newest first).
    pub fn list_wallets(&self) -> Result<Vec<WalletInfo>, Error> {
        wallet::list_wallets(self)
    }

    /// Get a wallet by name or ID.
    pub fn get_wallet(&self, name_or_id: &str) -> Result<WalletInfo, Error> {
        wallet::get_wallet(self, name_or_id)
    }

    /// Delete a wallet.
    pub fn delete_wallet(&self, name_or_id: &str) -> Result<(), Error> {
        wallet::delete_wallet(self, name_or_id)?;
        self.audit.log_ok("delete_wallet", Some(name_or_id), None);
        Ok(())
    }

    /// Rename a wallet.
    pub fn rename_wallet(&self, name_or_id: &str, new_name: &str) -> Result<(), Error> {
        wallet::rename_wallet(self, name_or_id, new_name)?;
        self.audit.log_ok("rename_wallet", Some(name_or_id), None);
        Ok(())
    }

    /// Export a wallet secret.
    pub fn export_wallet(&self, name_or_id: &str, passphrase: &str) -> Result<String, Error> {
        wallet::export_wallet(self, name_or_id, passphrase)
    }

    /// Derive an address for a chain.
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
    pub fn sign_message(
        &self,
        wallet: &str,
        chain: &str,
        message: &[u8],
        cred: Credential<'_>,
    ) -> Result<SignResult, Error> {
        let resolved = chain::resolve(chain)?;
        let family = resolved.family();
        let key_hex = key::resolve_signing_key(self, wallet, cred.as_str(), family, 0)?;
        let out = signer::sign_message(family, &key_hex, message)?;
        self.audit
            .log_ok("sign_message", Some(wallet), Some(resolved.chain_id()));
        Ok(signer::to_sign_result(&out))
    }

    /// Sign a transaction (hex-encoded).
    pub fn sign_transaction(
        &self,
        wallet: &str,
        chain: &str,
        tx_hex: &str,
        cred: Credential<'_>,
    ) -> Result<SignResult, Error> {
        let resolved = chain::resolve(chain)?;
        let family = resolved.family();
        let clean = tx_hex.strip_prefix("0x").unwrap_or(tx_hex);
        let tx_bytes =
            hex::decode(clean).map_err(|e| Error::InvalidInput(format!("invalid hex: {e}")))?;
        let key_hex = key::resolve_signing_key(self, wallet, cred.as_str(), family, 0)?;
        let out = signer::sign_transaction(family, &key_hex, &tx_bytes)?;
        self.audit
            .log_ok("sign_transaction", Some(wallet), Some(resolved.chain_id()));
        Ok(signer::to_sign_result(&out))
    }

    /// Sign EIP-712 typed data (EVM only).
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
        let key_hex = key::resolve_signing_key(self, wallet, cred.as_str(), resolved.family(), 0)?;
        let out = signer::sign_typed_data(&key_hex, typed_data)?;
        self.audit
            .log_ok("sign_typed_data", Some(wallet), Some(resolved.chain_id()));
        Ok(signer::to_sign_result(&out))
    }

    /// Sign and broadcast a transaction.
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
        let key_hex = key::resolve_signing_key(self, wallet, cred.as_str(), family, 0)?;
        let sig = signer::sign_transaction(family, &key_hex, &tx_bytes)?;
        let payload = signer::encode_signed_tx(family, &tx_bytes, &sig)?;
        let rpc = broadcast::resolve_rpc(chain_id, family, rpc_url, &self.config)?;
        let tx_hash = broadcast::broadcast(&self.http, family, &rpc, &payload).await?;
        self.audit
            .log_ok("sign_and_send", Some(wallet), Some(chain_id));
        Ok(SendResult { tx_hash })
    }

    /// Create an API key.
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
        self.audit.log_ok("create_api_key", None, None);
        Ok(result)
    }

    /// List all API keys.
    pub fn list_api_keys(&self) -> Result<Vec<ApiKeyInfo>, Error> {
        key::list_api_keys(self)
    }

    /// Revoke an API key.
    pub fn revoke_api_key(&self, id: &str) -> Result<(), Error> {
        key::revoke_api_key(self, id)?;
        self.audit.log_ok("revoke_api_key", None, None);
        Ok(())
    }
}

/// Build the shared async HTTP client.
fn build_http_client() -> reqwest::Client {
    #[allow(clippy::expect_used)]
    reqwest::Client::builder()
        .pool_max_idle_per_host(20)
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .build()
        .expect("failed to build HTTP client")
}

/// Best-effort default vault path.
fn default_vault_path() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| "/tmp".to_owned());
    PathBuf::from(home).join(".owx")
}
