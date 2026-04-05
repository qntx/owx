//! API key subcommands — agent-friendly, zero stdin interaction.

use clap::Subcommand;
use owx::Owx;

use crate::output::print_json;

/// API key actions.
#[derive(Subcommand)]
pub enum KeyAction {
    /// Create an API key for agent access.
    Create {
        name: String,
        /// Owner passphrase (required to re-encrypt wallet secrets for the agent).
        #[arg(long, env = "OWX_PASSPHRASE")]
        passphrase: String,
        #[arg(long)]
        wallet: Vec<String>,
        #[arg(long)]
        policy: Vec<String>,
        #[arg(long)]
        expires: Option<String>,
    },
    /// List all API keys.
    List,
    /// Revoke an API key by ID.
    Revoke { id: String },
}

#[allow(clippy::print_stdout)]
pub fn run(action: KeyAction, owx: &Owx) -> Result<(), owx::Error> {
    match action {
        KeyAction::Create {
            name,
            passphrase,
            wallet,
            policy,
            expires,
        } => print_json(&owx.create_api_key(
            &name,
            &wallet,
            &policy,
            &passphrase,
            expires.as_deref(),
        )?),
        KeyAction::List => print_json(&owx.list_api_keys()?),
        KeyAction::Revoke { id } => {
            owx.revoke_api_key(&id)?;
            print_json(&serde_json::json!({ "status": "revoked", "id": id }))
        }
    }
}
