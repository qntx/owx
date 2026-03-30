//! Agent-native, self-custodial, policy-gated, multi-chain wallet toolkit.
//!
//! Flat public API over [`owx_vault::Vault`]. All operations take a `&Vault` handle.
//!
//! ```ignore
//! let vault = owx::Vault::open("~/.owx")?;
//! let info  = owx::create_wallet(&vault, "my-wallet", "pass", 12)?;
//! let sig   = owx::sign_message(&vault, "my-wallet", "ethereum", b"hello", "pass", None)?;
//! ```

mod broadcast;
mod derivation;
mod error;
mod key;
mod secret;
mod signing;
mod wallet;

pub use broadcast::sign_and_send;
pub use error::{OwxError, OwxErrorCode};
pub use key::{create_api_key, list_api_keys, revoke_api_key};
pub use owx_core::{
    AccountInfo, ApiKeyCreateResult, ApiKeyInfo, SendResult, SignResult, TransactionSignResult,
    WalletInfo,
};
pub use owx_vault::Vault;
pub use signing::{sign_message, sign_transaction, sign_typed_data};
pub use wallet::{
    create_wallet, delete_wallet, derive_address, export_wallet, generate_mnemonic, get_wallet,
    import_mnemonic, import_private_key, list_wallets, rename_wallet,
};
