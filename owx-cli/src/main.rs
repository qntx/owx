//! CLI for OWX agent wallet toolkit.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use owx::AgentWallet;

#[derive(Parser)]
#[command(
    name = "owx",
    about = "Agent-native, self-custodial, policy-gated, multi-chain wallet toolkit."
)]
struct Cli {
    /// Path to the vault directory (default: ~/.owx).
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
}

#[derive(Subcommand)]
enum WalletAction {
    /// Create a new wallet.
    Create {
        /// Wallet name.
        name: String,
        /// Number of mnemonic words (12 or 24).
        #[arg(long, default_value = "12")]
        words: usize,
    },
    /// Import a wallet from a mnemonic phrase.
    Import {
        /// Wallet name.
        name: String,
        /// Mnemonic phrase.
        #[arg(long)]
        mnemonic: String,
    },
    /// List all wallets.
    List,
    /// Show wallet details.
    Info {
        /// Wallet name or ID.
        name: String,
    },
    /// Export wallet mnemonic.
    Export {
        /// Wallet name or ID.
        name: String,
    },
    /// Delete a wallet.
    Delete {
        /// Wallet name or ID.
        name: String,
    },
}

#[derive(Subcommand)]
enum KeyAction {
    /// Create an API key.
    Create {
        /// Key name.
        name: String,
        /// Wallet name or ID to grant access to.
        #[arg(long)]
        wallet: Vec<String>,
        /// Policy ID to attach.
        #[arg(long)]
        policy: Vec<String>,
        /// Expiry timestamp (ISO-8601).
        #[arg(long)]
        expires: Option<String>,
    },
    /// List all API keys.
    List,
    /// Revoke an API key.
    Revoke {
        /// Key ID.
        id: String,
    },
}

#[derive(Subcommand)]
enum SignAction {
    /// Sign a message.
    #[command(name = "msg")]
    Message {
        /// Wallet name or ID.
        wallet: String,
        /// Chain name or CAIP-2 ID.
        chain: String,
        /// Message to sign.
        message: String,
    },
    /// Sign a transaction (hex-encoded).
    #[command(name = "tx")]
    Transaction {
        /// Wallet name or ID.
        wallet: String,
        /// Chain name or CAIP-2 ID.
        chain: String,
        /// Hex-encoded transaction.
        tx_hex: String,
    },
}

fn main() {
    let cli = Cli::parse();

    let agent = match &cli.vault {
        Some(path) => AgentWallet::open(path),
        None => AgentWallet::open_default(),
    };

    let agent = match agent {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = run(cli.command, &agent) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(cmd: Commands, agent: &AgentWallet) -> Result<(), owx::OwxError> {
    match cmd {
        Commands::Wallet { action } => run_wallet(action, agent),
        Commands::Key { action } => run_key(action, agent),
        Commands::Sign { action } => run_sign(action, agent),
    }
}

fn run_wallet(action: WalletAction, agent: &AgentWallet) -> Result<(), owx::OwxError> {
    match action {
        WalletAction::Create { name, words } => {
            let pass = read_passphrase("Passphrase: ");
            let info = agent.create_wallet(&name, &pass, words)?;
            println!("{}", serde_json::to_string_pretty(&info).expect("json"));
        }
        WalletAction::Import { name, mnemonic } => {
            let pass = read_passphrase("Passphrase: ");
            let info = agent.import_mnemonic(&name, &mnemonic, &pass, 0)?;
            println!("{}", serde_json::to_string_pretty(&info).expect("json"));
        }
        WalletAction::List => {
            let wallets = agent.list_wallets()?;
            println!("{}", serde_json::to_string_pretty(&wallets).expect("json"));
        }
        WalletAction::Info { name } => {
            let info = agent.get_wallet(&name)?;
            println!("{}", serde_json::to_string_pretty(&info).expect("json"));
        }
        WalletAction::Export { name } => {
            let pass = read_passphrase("Passphrase: ");
            let mnemonic = agent.export_wallet(&name, &pass)?;
            println!("{mnemonic}");
        }
        WalletAction::Delete { name } => {
            agent.delete_wallet(&name)?;
            println!("deleted");
        }
    }
    Ok(())
}

fn run_key(action: KeyAction, agent: &AgentWallet) -> Result<(), owx::OwxError> {
    match action {
        KeyAction::Create {
            name,
            wallet,
            policy,
            expires,
        } => {
            let pass = read_passphrase("Owner passphrase: ");
            let (token, key) =
                agent.create_api_key(&name, &wallet, &policy, &pass, expires.as_deref())?;
            println!("token: {token}");
            println!("id: {}", key.id);
        }
        KeyAction::List => {
            let keys = agent.list_api_keys()?;
            for k in &keys {
                println!("{} {} (wallets: {})", k.id, k.name, k.wallet_ids.join(", "));
            }
        }
        KeyAction::Revoke { id } => {
            agent.revoke_api_key(&id)?;
            println!("revoked");
        }
    }
    Ok(())
}

fn run_sign(action: SignAction, agent: &AgentWallet) -> Result<(), owx::OwxError> {
    let cred = read_passphrase("Passphrase or API token: ");
    match action {
        SignAction::Message {
            wallet,
            chain,
            message,
        } => {
            let result = agent.sign_message(&wallet, &chain, message.as_bytes(), &cred, None)?;
            println!("{}", result.signature);
        }
        SignAction::Transaction {
            wallet,
            chain,
            tx_hex,
        } => {
            let result = agent.sign_transaction(&wallet, &chain, &tx_hex, &cred, None)?;
            println!("{}", result.signature);
        }
    }
    Ok(())
}

fn read_passphrase(prompt: &str) -> String {
    eprint!("{prompt}");
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .expect("failed to read input");
    input.trim().to_owned()
}
