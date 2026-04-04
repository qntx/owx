//! Wallet subcommands.

use clap::Subcommand;
use owx::Owx;

use crate::output::{print_json, read_line};

#[derive(Subcommand)]
pub enum WalletAction {
    Create {
        name: String,
        #[arg(long, default_value = "12")]
        words: usize,
    },
    Import {
        name: String,
        #[arg(long)]
        mnemonic: String,
    },
    ImportKey {
        name: String,
        #[arg(long)]
        key: String,
        #[arg(long)]
        chain: Option<String>,
    },
    ImportKeys {
        name: String,
        #[arg(long)]
        secp256k1: String,
        #[arg(long)]
        ed25519: String,
    },
    List,
    Info {
        name: String,
    },
    Export {
        name: String,
    },
    Rename {
        name: String,
        #[arg(long)]
        new_name: String,
    },
    Delete {
        name: String,
    },
}

#[allow(clippy::print_stdout)]
pub fn run(action: WalletAction, owx: &Owx) -> Result<(), owx::Error> {
    match action {
        WalletAction::Create { name, words } => {
            let pass = read_line("Passphrase: ");
            print_json(&owx.create_wallet(&name, &pass, words)?)
        }
        WalletAction::Import { name, mnemonic } => {
            let pass = read_line("Passphrase: ");
            print_json(&owx.import_mnemonic(&name, &mnemonic, &pass, 0)?)
        }
        WalletAction::ImportKey { name, key, chain } => {
            let pass = read_line("Passphrase: ");
            print_json(&owx.import_private_key(&name, &key, chain.as_deref(), &pass, None, None)?)
        }
        WalletAction::ImportKeys {
            name,
            secp256k1,
            ed25519,
        } => {
            let pass = read_line("Passphrase: ");
            print_json(&owx.import_private_keys(&name, &secp256k1, &ed25519, &pass)?)
        }
        WalletAction::List => print_json(&owx.list_wallets()?),
        WalletAction::Info { name } => print_json(&owx.get_wallet(&name)?),
        WalletAction::Export { name } => {
            let pass = read_line("Passphrase: ");
            print_json(&owx.export_wallet(&name, &pass)?)
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
