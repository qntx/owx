//! Signing subcommands.

use clap::Subcommand;
use owx::Owx;

use crate::output::{print_json, read_line};

#[derive(Subcommand)]
pub enum SignAction {
    #[command(name = "msg")]
    Message {
        wallet: String,
        chain: String,
        message: String,
        #[arg(long, default_value = "utf8")]
        encoding: String,
    },
    #[command(name = "tx")]
    Transaction {
        wallet: String,
        chain: String,
        tx_hex: String,
    },
}

#[allow(clippy::print_stdout)]
pub fn run(action: SignAction, owx: &Owx) -> Result<(), owx::Error> {
    let cred_str = read_line("Passphrase or API token: ");
    let cred = owx::Credential::parse(&cred_str);
    match action {
        SignAction::Message {
            wallet,
            chain,
            message,
            encoding,
        } => {
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
        } => print_json(&owx.sign_transaction(&wallet, &chain, &tx_hex, cred)?),
    }
}
