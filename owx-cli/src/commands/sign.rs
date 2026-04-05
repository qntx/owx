//! Signing subcommands — agent-friendly, zero stdin interaction.

use clap::Subcommand;
use owx::Owx;

use crate::output::print_json;

/// Signing actions.
#[derive(Subcommand)]
pub enum SignAction {
    /// Sign a message.
    #[command(name = "msg")]
    Message {
        wallet: String,
        chain: String,
        message: String,
        /// Passphrase or API token.
        #[arg(long, env = "OWX_CREDENTIAL")]
        credential: String,
        #[arg(long, default_value = "utf8")]
        encoding: String,
    },
    /// Sign a transaction.
    #[command(name = "tx")]
    Transaction {
        wallet: String,
        chain: String,
        tx_hex: String,
        /// Passphrase or API token.
        #[arg(long, env = "OWX_CREDENTIAL")]
        credential: String,
    },
}

#[allow(clippy::print_stdout)]
pub fn run(action: SignAction, owx: &Owx) -> Result<(), owx::Error> {
    match action {
        SignAction::Message {
            wallet,
            chain,
            message,
            credential,
            encoding,
        } => {
            let cred = owx::Credential::parse(&credential);
            let msg_bytes = match encoding.as_str() {
                "hex" => hex::decode(&message)
                    .map_err(|e| owx::Error::InvalidInput(format!("invalid hex: {e}")))?,
                _ => message.into_bytes(),
            };
            print_json(&owx.sign_message(&wallet, &chain, &msg_bytes, cred)?)
        }
        SignAction::Transaction {
            wallet,
            chain,
            tx_hex,
            credential,
        } => {
            let cred = owx::Credential::parse(&credential);
            print_json(&owx.sign_transaction(&wallet, &chain, &tx_hex, cred)?)
        }
    }
}
