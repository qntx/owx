//! API key subcommands.

use clap::Subcommand;
use owx::Owx;

use crate::output::{print_json, read_line};

#[derive(Subcommand)]
pub enum KeyAction {
    Create {
        name: String,
        #[arg(long)]
        wallet: Vec<String>,
        #[arg(long)]
        policy: Vec<String>,
        #[arg(long)]
        expires: Option<String>,
    },
    List,
    Revoke {
        id: String,
    },
}

#[allow(clippy::print_stdout)]
pub fn run(action: KeyAction, owx: &Owx) -> Result<(), owx::Error> {
    match action {
        KeyAction::Create {
            name,
            wallet,
            policy,
            expires,
        } => {
            let pass = read_line("Owner passphrase: ");
            print_json(&owx.create_api_key(&name, &wallet, &policy, &pass, expires.as_deref())?)
        }
        KeyAction::List => print_json(&owx.list_api_keys()?),
        KeyAction::Revoke { id } => {
            owx.revoke_api_key(&id)?;
            print_json(&serde_json::json!({ "status": "revoked", "id": id }))
        }
    }
}
