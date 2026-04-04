//! CLI for OWX agent wallet toolkit.

#![allow(clippy::missing_docs_in_private_items, missing_docs)]

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use owx::Vault;

#[derive(Parser)]
#[command(
    name = "owx",
    about = "Agent-native, self-custodial, policy-gated, multi-chain wallet toolkit."
)]
struct Cli {
    #[arg(long, global = true)]
    vault: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Wallet management.
    Wallet {
        #[command(subcommand)]
        action: WalletAction,
    },
    /// API key management.
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },
    /// Signing operations.
    Sign {
        #[command(subcommand)]
        action: SignAction,
    },
    /// Derive an address for a chain.
    Derive {
        chain: String,
        #[arg(long, default_value = "0")]
        index: u32,
    },
    /// Generate a BIP-39 mnemonic phrase.
    Generate {
        #[arg(long, default_value = "12")]
        words: u32,
    },
    /// Send a signed transaction to the chain RPC.
    Send {
        wallet: String,
        chain: String,
        tx_hex: String,
        #[arg(long)]
        rpc: Option<String>,
    },
    /// Make an HTTP request with automatic x402 payment.
    Pay {
        url: String,
        #[arg(long, default_value = "GET")]
        method: String,
        #[arg(long)]
        body: Option<String>,
    },
    /// Discover payable services.
    Discover {
        #[arg(long)]
        query: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: u64,
    },
    /// Fund a wallet via MoonPay.
    Fund {
        #[arg(long, default_value = "base")]
        chain: String,
        #[arg(long, default_value = "USDC")]
        token: String,
    },
    /// Check token balances via MoonPay.
    Balance {
        #[arg(long, default_value = "base")]
        chain: String,
    },
    /// Policy management.
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
}

#[derive(Subcommand)]
enum WalletAction {
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

#[derive(Subcommand)]
enum KeyAction {
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

#[derive(Subcommand)]
enum SignAction {
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

#[derive(Subcommand)]
enum PolicyAction {
    Create {
        id: String,
        #[arg(long)]
        json: String,
    },
    List,
    Info {
        id: String,
    },
    Delete {
        id: String,
    },
}

#[allow(clippy::print_stderr)]
fn main() {
    let cli = Cli::parse();
    let vault = match &cli.vault {
        Some(path) => Vault::open(path),
        None => Vault::open_default(),
    };
    let vault = match vault {
        Ok(v) => v,
        Err(e) => exit_with_error(&e),
    };
    if let Err(e) = run(cli.command, &vault) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

#[allow(clippy::print_stdout)]
fn run(cmd: Commands, vault: &Vault) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        Commands::Wallet { action } => run_wallet(action, vault)?,
        Commands::Key { action } => run_key(action, vault)?,
        Commands::Sign { action } => run_sign(action, vault)?,
        Commands::Derive { chain, index } => {
            let wallet_name = read_line("Wallet name or ID: ");
            let pass = read_line("Passphrase: ");
            let address = owx::derive_address(vault, &wallet_name, &chain, &pass, Some(index))?;
            print_json(&serde_json::json!({ "chain": chain, "index": index, "address": address }))?;
        }
        Commands::Generate { words } => {
            let phrase = owx::generate_mnemonic(words as usize)?;
            print_json(&serde_json::json!({ "mnemonic": phrase }))?;
        }
        Commands::Send {
            wallet,
            chain,
            tx_hex,
            rpc,
        } => {
            let cred = read_line("Passphrase or API token: ");
            let result =
                owx::sign_and_send(vault, &wallet, &chain, &tx_hex, &cred, None, rpc.as_deref())?;
            print_json(&result)?;
        }
        Commands::Pay { url, method, body } => {
            let wallet_name = read_line("Wallet name or ID: ");
            let cred = read_line("Passphrase or API token: ");
            let bridge = owx_pay::VaultBridge::new(vault, &wallet_name, &cred, 0);
            let result = owx_pay::pay(&bridge, &url, &method, body.as_deref())?;
            print_json(&result)?;
        }
        Commands::Discover { query, limit } => {
            let result = owx_pay::discover(query.as_deref(), Some(limit), None)?;
            print_json(&result)?;
        }
        Commands::Fund { chain, token } => {
            let evm_addr = first_evm_address(vault)?;
            let result = owx_pay::fund(&evm_addr, Some(&chain), Some(&token))?;
            print_json(&result)?;
        }
        Commands::Balance { chain } => {
            let evm_addr = first_evm_address(vault)?;
            let balances = owx_pay::get_balances(&evm_addr, Some(&chain))?;
            print_json(&balances)?;
        }
        Commands::Policy { action } => run_policy(action, vault)?,
    }
    Ok(())
}

fn first_evm_address(vault: &Vault) -> Result<String, owx::Error> {
    let wallets = owx::list_wallets(vault)?;
    let w = wallets
        .first()
        .ok_or_else(|| owx::Error::InvalidInput("no wallets found".into()))?;
    w.accounts
        .iter()
        .find(|a| a.chain_id.starts_with("eip155:"))
        .map(|a| a.address.clone())
        .ok_or_else(|| owx::Error::InvalidInput("no EVM account found".into()))
}

#[allow(clippy::print_stdout)]
fn run_wallet(action: WalletAction, vault: &Vault) -> Result<(), owx::Error> {
    match action {
        WalletAction::Create { name, words } => {
            let pass = read_line("Passphrase: ");
            print_json(&owx::create_wallet(vault, &name, &pass, words)?)
        }
        WalletAction::Import { name, mnemonic } => {
            let pass = read_line("Passphrase: ");
            print_json(&owx::import_mnemonic(vault, &name, &mnemonic, &pass, 0)?)
        }
        WalletAction::ImportKey { name, key, chain } => {
            let pass = read_line("Passphrase: ");
            print_json(&owx::import_private_key(
                vault,
                &name,
                &key,
                chain.as_deref(),
                &pass,
                None,
                None,
            )?)
        }
        WalletAction::ImportKeys {
            name,
            secp256k1,
            ed25519,
        } => {
            let pass = read_line("Passphrase: ");
            print_json(&owx::import_private_keys(
                vault, &name, &secp256k1, &ed25519, &pass,
            )?)
        }
        WalletAction::List => print_json(&owx::list_wallets(vault)?),
        WalletAction::Info { name } => print_json(&owx::get_wallet(vault, &name)?),
        WalletAction::Export { name } => {
            let pass = read_line("Passphrase: ");
            print_json(&owx::export_wallet(vault, &name, &pass)?)
        }
        WalletAction::Rename { name, new_name } => {
            owx::rename_wallet(vault, &name, &new_name)?;
            print_json(&serde_json::json!({ "status": "renamed", "name": new_name }))
        }
        WalletAction::Delete { name } => {
            owx::delete_wallet(vault, &name)?;
            print_json(&serde_json::json!({ "status": "deleted", "name": name }))
        }
    }
}

#[allow(clippy::print_stdout)]
fn run_key(action: KeyAction, vault: &Vault) -> Result<(), owx::Error> {
    match action {
        KeyAction::Create {
            name,
            wallet,
            policy,
            expires,
        } => {
            let pass = read_line("Owner passphrase: ");
            print_json(&owx::create_api_key(
                vault,
                &name,
                &wallet,
                &policy,
                &pass,
                expires.as_deref(),
            )?)
        }
        KeyAction::List => print_json(&owx::list_api_keys(vault)?),
        KeyAction::Revoke { id } => {
            owx::revoke_api_key(vault, &id)?;
            print_json(&serde_json::json!({ "status": "revoked", "id": id }))
        }
    }
}

#[allow(clippy::print_stdout)]
fn run_sign(action: SignAction, vault: &Vault) -> Result<(), owx::Error> {
    let cred = read_line("Passphrase or API token: ");
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
            print_json(&owx::sign_message(
                vault, &wallet, &chain, &msg_bytes, &cred, None,
            )?)
        }
        SignAction::Transaction {
            wallet,
            chain,
            tx_hex,
        } => print_json(&owx::sign_transaction(
            vault, &wallet, &chain, &tx_hex, &cred, None,
        )?),
    }
}

#[allow(clippy::print_stdout)]
fn run_policy(action: PolicyAction, vault: &Vault) -> Result<(), owx::Error> {
    let store = vault.store();
    match action {
        PolicyAction::Create { id, json } => {
            store.save_raw("policies", &id, &json)?;
            print_json(&serde_json::json!({ "status": "created", "id": id }))
        }
        PolicyAction::List => {
            let policies = owx::policy::list_policies(store)?;
            print_json(&policies)
        }
        PolicyAction::Info { id } => {
            let raw = store.load_raw("policies", &id)?;
            let value: serde_json::Value = serde_json::from_str(&raw)?;
            print_json(&value)
        }
        PolicyAction::Delete { id } => {
            store.delete("policies", &id)?;
            print_json(&serde_json::json!({ "status": "deleted", "id": id }))
        }
    }
}

#[allow(clippy::print_stdout)]
fn print_json<T: serde::Serialize>(value: &T) -> Result<(), owx::Error> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

#[derive(serde::Serialize)]
struct ErrorEnvelope<'a> {
    success: bool,
    error: &'a owx::Error,
}

#[allow(clippy::print_stderr)]
fn exit_with_error(error: &owx::Error) -> ! {
    let payload = ErrorEnvelope {
        success: false,
        error,
    };
    match serde_json::to_string_pretty(&payload) {
        Ok(json) => eprintln!("{json}"),
        Err(_) => eprintln!(
            r#"{{"success":false,"error":{{"code":"JSON","message":"serialization failed"}}}}"#
        ),
    }
    std::process::exit(1)
}

#[allow(clippy::print_stderr, clippy::expect_used)]
fn read_line(prompt: &str) -> String {
    eprint!("{prompt}");
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .expect("failed to read input");
    input.trim().to_owned()
}
