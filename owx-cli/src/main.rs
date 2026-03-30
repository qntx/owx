//! CLI for OWX agent wallet toolkit.

#![allow(clippy::missing_docs_in_private_items)]

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
    /// Send a signed transaction to the chain RPC.
    Send {
        /// Wallet name or ID.
        wallet: String,
        /// Chain name or CAIP-2 ID.
        chain: String,
        /// Hex-encoded transaction.
        tx_hex: String,
        /// RPC URL override.
        #[arg(long)]
        rpc: Option<String>,
    },
    /// Make an HTTP request with automatic x402 payment.
    Pay {
        /// URL to request.
        url: String,
        /// HTTP method.
        #[arg(long, default_value = "GET")]
        method: String,
        /// Request body (JSON).
        #[arg(long)]
        body: Option<String>,
    },
    /// Discover payable services.
    Discover {
        /// Search query.
        #[arg(long)]
        query: Option<String>,
        /// Max results.
        #[arg(long, default_value = "20")]
        limit: u64,
    },
    /// Fund a wallet via MoonPay.
    Fund {
        /// Chain name (default: base).
        #[arg(long, default_value = "base")]
        chain: String,
        /// Token (default: USDC).
        #[arg(long, default_value = "USDC")]
        token: String,
    },
    /// Derive an address from a mnemonic.
    Derive {
        /// Chain name or CAIP-2 ID.
        chain: String,
        /// Account index.
        #[arg(long, default_value = "0")]
        index: u32,
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
    /// Import a wallet from a hex private key.
    ImportKey {
        /// Wallet name.
        name: String,
        /// Hex-encoded private key.
        #[arg(long)]
        key: String,
        /// Source chain (evm, bitcoin, solana).
        #[arg(long, default_value = "ethereum")]
        chain: String,
    },
    /// List all wallets.
    List,
    /// Show wallet details.
    Info {
        /// Wallet name or ID.
        name: String,
    },
    /// Export wallet secret.
    Export {
        /// Wallet name or ID.
        name: String,
    },
    /// Rename a wallet.
    Rename {
        /// Current wallet name or ID.
        name: String,
        /// New name.
        #[arg(long)]
        new_name: String,
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

#[allow(clippy::print_stderr)]
fn main() {
    let cli = Cli::parse();

    let agent_result = match &cli.vault {
        Some(path) => AgentWallet::open(path),
        None => AgentWallet::open_default(),
    };

    let agent = match agent_result {
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

/// Dispatch CLI commands.
#[allow(clippy::print_stdout, clippy::expect_used, clippy::unwrap_in_result)]
fn run(cmd: Commands, agent: &AgentWallet) -> Result<(), owx::OwxError> {
    match cmd {
        Commands::Wallet { action } => run_wallet(action, agent),
        Commands::Key { action } => run_key(action, agent),
        Commands::Sign { action } => run_sign(action, agent),
        Commands::Send {
            wallet,
            chain,
            tx_hex,
            rpc,
        } => {
            let cred = read_passphrase("Passphrase or API token: ");
            let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
            let result = rt.block_on(agent.sign_and_send(
                &wallet,
                &chain,
                &tx_hex,
                &cred,
                None,
                rpc.as_deref(),
            ))?;
            println!("{}", result.tx_hash);
            Ok(())
        }
        Commands::Pay { url, method, body } => {
            println!("x402 pay: {method} {url}");
            println!("(WalletBridge implementation required — use as library)");
            if let Some(b) = &body {
                println!("body: {b}");
            }
            Ok(())
        }
        Commands::Discover { query, limit } => {
            let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
            let result = rt.block_on(owx_pay::discovery::discover(
                query.as_deref(),
                Some(limit),
                None,
            ))?;
            println!(
                "Found {} services (total: {})",
                result.services.len(),
                result.total
            );
            for svc in &result.services {
                println!("  {} {} — {}", svc.price, svc.network, svc.url);
            }
            Ok(())
        }
        Commands::Fund { chain, token } => {
            let wallets = agent.list_wallets()?;
            let wallet_info = wallets.first().ok_or_else(|| {
                owx::OwxError::InvalidInput("no wallets found; create one first".into())
            })?;
            let evm_account = wallet_info
                .accounts
                .iter()
                .find(|a| a.chain_id.starts_with("eip155:"))
                .ok_or_else(|| owx::OwxError::InvalidInput("no EVM account found".into()))?;

            let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
            let result = rt.block_on(owx_pay::fund::fund(
                &evm_account.address,
                Some(&chain),
                Some(&token),
            ))?;
            println!("Deposit URL: {}", result.deposit_url);
            println!("Deposit ID: {}", result.deposit_id);
            for (wchain, addr) in &result.wallets {
                println!("  {wchain}: {addr}");
            }
            println!("{}", result.instructions);
            Ok(())
        }
        Commands::Derive { chain, index } => {
            let mnemonic = read_passphrase("Mnemonic: ");
            let addr = owx::wallet_ops::derive_address(&mnemonic, &chain, Some(index))?;
            println!("{addr}");
            Ok(())
        }
    }
}

/// Execute wallet subcommands.
#[allow(clippy::print_stdout, clippy::expect_used, clippy::unwrap_in_result)]
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
        WalletAction::ImportKey { name, key, chain } => {
            let pass = read_passphrase("Passphrase: ");
            let info = agent.import_private_key(&name, &key, &chain, &pass)?;
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
            let secret = agent.export_wallet(&name, &pass)?;
            println!("{secret}");
        }
        WalletAction::Rename { name, new_name } => {
            agent.rename_wallet(&name, &new_name)?;
            println!("renamed to {new_name}");
        }
        WalletAction::Delete { name } => {
            agent.delete_wallet(&name)?;
            println!("deleted");
        }
    }
    Ok(())
}

/// Execute API key subcommands.
#[allow(clippy::print_stdout)]
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

/// Execute signing subcommands.
#[allow(clippy::print_stdout)]
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
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
    }
    Ok(())
}

/// Read a passphrase from stdin (with a prompt on stderr).
#[allow(clippy::print_stderr, clippy::expect_used)]
fn read_passphrase(prompt: &str) -> String {
    eprint!("{prompt}");
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .expect("failed to read input");
    input.trim().to_owned()
}
