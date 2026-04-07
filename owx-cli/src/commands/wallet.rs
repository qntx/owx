//! Wallet subcommands — agent-friendly, zero stdin interaction.

use clap::Subcommand;
use owx::Owx;

use crate::output::print_json;

/// Wallet actions.
#[derive(Subcommand)]
pub(crate) enum WalletAction {
    /// Create a new wallet.
    Create {
        name: String,
        /// Encryption passphrase.
        #[arg(long, env = "OWX_PASSPHRASE")]
        passphrase: String,
        #[arg(long, default_value = "12")]
        words: usize,
    },
    /// Import from mnemonic.
    Import {
        name: String,
        #[arg(long)]
        mnemonic: String,
        /// Encryption passphrase.
        #[arg(long, env = "OWX_PASSPHRASE")]
        passphrase: String,
    },
    /// Import a single private key.
    ImportKey {
        name: String,
        #[arg(long)]
        key: String,
        #[arg(long)]
        chain: Option<String>,
        /// Encryption passphrase.
        #[arg(long, env = "OWX_PASSPHRASE")]
        passphrase: String,
    },
    /// Import dual-curve private keys.
    ImportKeys {
        name: String,
        #[arg(long)]
        secp256k1: String,
        #[arg(long)]
        ed25519: String,
        /// Encryption passphrase.
        #[arg(long, env = "OWX_PASSPHRASE")]
        passphrase: String,
    },
    /// List all wallets.
    List,
    /// Get wallet info.
    Info { name: String },
    /// Export wallet secret.
    Export {
        name: String,
        /// Decryption passphrase.
        #[arg(long, env = "OWX_PASSPHRASE")]
        passphrase: String,
    },
    /// Rename a wallet.
    Rename {
        name: String,
        #[arg(long)]
        new_name: String,
    },
    /// Delete a wallet.
    Delete { name: String },
}

pub(crate) fn run(action: WalletAction, owx: &Owx) -> Result<(), owx::OwxError> {
    match action {
        WalletAction::Create {
            name,
            passphrase,
            words,
        } => print_json(&owx.create_wallet(&name, &passphrase, words)?),
        WalletAction::Import {
            name,
            mnemonic,
            passphrase,
        } => print_json(&owx.import_mnemonic(&name, &mnemonic, &passphrase, 0)?),
        WalletAction::ImportKey {
            name,
            key,
            chain,
            passphrase,
        } => {
            let opts = owx::ImportKeyOptions {
                chain: chain.as_deref(),
                ..Default::default()
            };
            print_json(&owx.import_private_key(&name, &key, &passphrase, &opts)?)
        }
        WalletAction::ImportKeys {
            name,
            secp256k1,
            ed25519,
            passphrase,
        } => print_json(&owx.import_private_keys(&name, &secp256k1, &ed25519, &passphrase)?),
        WalletAction::List => print_json(&owx.list_wallets()?),
        WalletAction::Info { name } => print_json(&owx.get_wallet(&name)?),
        WalletAction::Export { name, passphrase } => {
            let secret = owx.export_wallet(&name, &passphrase)?;
            print_json(&*secret)
        }
        WalletAction::Rename { name, new_name } => {
            owx.rename_wallet(&name, &new_name)?;
            print_json(&serde_json::json!({ "status": "renamed", "name": new_name }))
        }
        WalletAction::Delete { name } => {
            owx.delete_wallet(&name)?;
            print_json(&serde_json::json!({ "status": "deleted", "name": name }))
        }
    }
}
