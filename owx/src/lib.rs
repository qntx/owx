//! Agent-native, self-custodial, policy-gated, multi-chain wallet toolkit.
//!
//! Flat public API over [`owx_vault::Vault`].
//!
//! ```ignore
//! let vault = owx::Vault::open("~/.owx")?;
//! let info  = owx::create_wallet(&vault, "my-wallet", "pass", 12)?;
//! let sig   = owx::sign_message(&vault, "my-wallet", "ethereum", b"hello", "pass", None)?;
//! ```

mod broadcast;
mod error;
mod handler;
mod key_ops;
mod ops;
mod policy_engine;
mod secret;
pub mod types;

pub use error::{OwxError, OwxErrorCode};
pub use key_ops::{create_api_key, list_api_keys, revoke_api_key};
pub use ops::{
    create_wallet, delete_wallet, derive_address, export_wallet, generate_mnemonic, get_wallet,
    import_mnemonic, import_private_keys, list_wallets, rename_wallet, sign_and_send, sign_message,
    sign_transaction,
};
pub use owx_vault::Vault;
pub use types::{AccountInfo, ApiKeyCreateResult, ApiKeyInfo, SendResult, SignResult, WalletInfo};
