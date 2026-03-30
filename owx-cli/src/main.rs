//! CLI for OWX agent wallet toolkit.

use std::future::Future;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use owx::Vault;

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
    /// Wallet management commands.
    Wallet {
        #[command(subcommand)]
        action: WalletAction,
    },
    /// API key management commands.
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },
    /// Signing operation commands.
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

    let vault_result = match &cli.vault {
        Some(path) => Vault::open(path),
        None => Vault::open_default(),
    };

    let vault = match vault_result {
        Ok(v) => v,
        Err(e) => exit_with_error(&owx::OwxError::from(e)),
    };

    if let Err(e) = run(cli.command, &vault) {
        exit_with_error(&e);
    }
}

/// Dispatch CLI commands.
#[allow(clippy::print_stdout)]
fn run(cmd: Commands, vault: &Vault) -> Result<(), owx::OwxError> {
    match cmd {
        Commands::Wallet { action } => run_wallet(action, vault),
        Commands::Key { action } => run_key(action, vault),
        Commands::Sign { action } => run_sign(action, vault),
        Commands::Send {
            wallet,
            chain,
            tx_hex,
            rpc,
        } => {
            let cred = read_passphrase("Passphrase or API token: ");
            let result = block_on(owx::sign_and_send(
                vault,
                &wallet,
                &chain,
                &tx_hex,
                &cred,
                None,
                rpc.as_deref(),
            ))?;
            print_json(&result)
        }
        Commands::Pay { url, method, body } => print_json(&serde_json::json!({
            "implemented": false,
            "message": "CLI pay requires a WalletBridge implementation; use the library API",
            "method": method,
            "url": url,
            "body": body,
        })),
        Commands::Discover { query, limit } => {
            let result = block_on(owx_pay::discovery::discover(
                query.as_deref(),
                Some(limit),
                None,
            ))?;
            print_json(&result)
        }
        Commands::Fund { chain, token } => {
            let wallets = owx::list_wallets(vault)?;
            let wallet_info = wallets.first().ok_or_else(|| {
                owx::OwxError::InvalidInput("no wallets found; create one first".into())
            })?;
            let evm_account = wallet_info
                .accounts
                .iter()
                .find(|a| a.chain_id.starts_with("eip155:"))
                .ok_or_else(|| owx::OwxError::InvalidInput("no EVM account found".into()))?;

            let result = block_on(owx_pay::fund::fund(
                &evm_account.address,
                Some(&chain),
                Some(&token),
            ))?;
            print_json(&result)
        }
        Commands::Derive { chain, index } => {
            let mnemonic = read_passphrase("Mnemonic: ");
            let address = owx::derive_address(&mnemonic, &chain, Some(index))?;
            print_json(&serde_json::json!({
                "chain": chain,
                "index": index,
                "address": address,
            }))
        }
    }
}

/// Execute wallet subcommands.
#[allow(clippy::print_stdout)]
fn run_wallet(action: WalletAction, vault: &Vault) -> Result<(), owx::OwxError> {
    match action {
        WalletAction::Create { name, words } => {
            let pass = read_passphrase("Passphrase: ");
            let info = owx::create_wallet(vault, &name, &pass, words)?;
            print_json(&info)?;
        }
        WalletAction::Import { name, mnemonic } => {
            let pass = read_passphrase("Passphrase: ");
            let info = owx::import_mnemonic(vault, &name, &mnemonic, &pass, 0)?;
            print_json(&info)?;
        }
        WalletAction::ImportKey { name, key, chain } => {
            let pass = read_passphrase("Passphrase: ");
            let info = owx::import_private_key(vault, &name, &key, &chain, &pass)?;
            print_json(&info)?;
        }
        WalletAction::List => {
            let wallets = owx::list_wallets(vault)?;
            print_json(&wallets)?;
        }
        WalletAction::Info { name } => {
            let info = owx::get_wallet(vault, &name)?;
            print_json(&info)?;
        }
        WalletAction::Export { name } => {
            let pass = read_passphrase("Passphrase: ");
            let secret = owx::export_wallet(vault, &name, &pass)?;
            print_json(&secret)?;
        }
        WalletAction::Rename { name, new_name } => {
            owx::rename_wallet(vault, &name, &new_name)?;
            print_json(&serde_json::json!({
                "status": "renamed",
                "name": new_name,
            }))?;
        }
        WalletAction::Delete { name } => {
            owx::delete_wallet(vault, &name)?;
            print_json(&serde_json::json!({
                "status": "deleted",
                "name": name,
            }))?;
        }
    }
    Ok(())
}

/// Execute API key subcommands.
#[allow(clippy::print_stdout)]
fn run_key(action: KeyAction, vault: &Vault) -> Result<(), owx::OwxError> {
    match action {
        KeyAction::Create {
            name,
            wallet,
            policy,
            expires,
        } => {
            let pass = read_passphrase("Owner passphrase: ");
            let result =
                owx::create_api_key(vault, &name, &wallet, &policy, &pass, expires.as_deref())?;
            print_json(&result)?;
        }
        KeyAction::List => {
            let keys = owx::list_api_keys(vault)?;
            print_json(&keys)?;
        }
        KeyAction::Revoke { id } => {
            owx::revoke_api_key(vault, &id)?;
            print_json(&serde_json::json!({
                "status": "revoked",
                "id": id,
            }))?;
        }
    }
    Ok(())
}

/// Execute signing subcommands.
#[allow(clippy::print_stdout)]
fn run_sign(action: SignAction, vault: &Vault) -> Result<(), owx::OwxError> {
    let cred = read_passphrase("Passphrase or API token: ");
    match action {
        SignAction::Message {
            wallet,
            chain,
            message,
        } => {
            let result =
                owx::sign_message(vault, &wallet, &chain, message.as_bytes(), &cred, None)?;
            print_json(&result)?;
        }
        SignAction::Transaction {
            wallet,
            chain,
            tx_hex,
        } => {
            let result = owx::sign_transaction(vault, &wallet, &chain, &tx_hex, &cred, None)?;
            print_json(&result)?;
        }
    }
    Ok(())
}

/// Block on an async future using a one-shot tokio runtime.
fn block_on<T, E, F>(future: F) -> Result<T, owx::OwxError>
where
    F: Future<Output = Result<T, E>>,
    E: Into<owx::OwxError>,
{
    let runtime = tokio::runtime::Runtime::new().map_err(|e| {
        owx::OwxError::InvalidInput(format!("failed to initialize tokio runtime: {e}"))
    })?;
    runtime.block_on(async move { future.await.map_err(Into::into) })
}

#[allow(clippy::print_stdout)]
/// Pretty-print a value as JSON to stdout.
fn print_json<T: serde::Serialize>(value: &T) -> Result<(), owx::OwxError> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

/// JSON envelope for structured CLI error output.
#[derive(serde::Serialize)]
struct ErrorEnvelope<'a> {
    /// Always `false` for error responses.
    success: bool,
    /// The serialized error.
    error: &'a owx::OwxError,
}

#[allow(clippy::print_stderr)]
/// Print a structured JSON error to stderr and exit with code 1.
fn exit_with_error(error: &owx::OwxError) -> ! {
    let payload = ErrorEnvelope {
        success: false,
        error,
    };
    match serde_json::to_string_pretty(&payload) {
        Ok(json) => eprintln!("{json}"),
        Err(_) => eprintln!(
            "{{\n  \"success\": false,\n  \"error\": {{\n    \"kind\": \"serialization\",\n    \"message\": \"failed to serialize CLI error output\"\n  }}\n}}"
        ),
    }
    std::process::exit(1)
}

/// Read a line from stdin with a prompt on stderr.
#[allow(clippy::print_stderr, clippy::expect_used)]
fn read_passphrase(prompt: &str) -> String {
    eprint!("{prompt}");
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .expect("failed to read input");
    input.trim().to_owned()
}
