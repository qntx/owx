//! CLI subcommand definitions and dispatch.

pub mod key;
pub mod policy;
pub mod sign;
#[cfg(feature = "swap")]
pub mod swap;
pub mod wallet;

use clap::Subcommand;
use owx::Owx;

use crate::output::{print_json, read_line};

/// Top-level CLI commands.
#[derive(Subcommand)]
pub enum Commands {
    /// Wallet management.
    Wallet {
        #[command(subcommand)]
        action: wallet::WalletAction,
    },
    /// API key management.
    Key {
        #[command(subcommand)]
        action: key::KeyAction,
    },
    /// Signing operations.
    Sign {
        #[command(subcommand)]
        action: sign::SignAction,
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
    #[cfg(feature = "pay")]
    Pay {
        url: String,
        #[arg(long, default_value = "GET")]
        method: String,
        #[arg(long)]
        body: Option<String>,
    },
    /// Discover payable services.
    #[cfg(feature = "pay")]
    Discover {
        #[arg(long)]
        query: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: u64,
    },
    /// Fund a wallet via MoonPay.
    #[cfg(feature = "moonpay")]
    Fund {
        #[arg(long, default_value = "base")]
        chain: String,
        #[arg(long, default_value = "USDC")]
        token: String,
    },
    /// Check token balances via MoonPay.
    #[cfg(feature = "moonpay")]
    Balance {
        #[arg(long, default_value = "base")]
        chain: String,
    },
    /// Cross-chain token swap via LiFi.
    #[cfg(feature = "swap")]
    Swap {
        #[command(subcommand)]
        action: swap::SwapAction,
    },
    /// Policy management.
    Policy {
        #[command(subcommand)]
        action: policy::PolicyAction,
    },
}

/// Dispatch a top-level command.
#[allow(clippy::print_stdout)]
pub fn dispatch(cmd: Commands, owx: &Owx) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        Commands::Wallet { action } => wallet::run(action, owx)?,
        Commands::Key { action } => key::run(action, owx)?,
        Commands::Sign { action } => sign::run(action, owx)?,
        Commands::Derive { chain, index } => {
            let wn = read_line("Wallet name or ID: ");
            let pass = read_line("Passphrase: ");
            let addr = owx.derive_address(&wn, &chain, &pass, Some(index))?;
            print_json(&serde_json::json!({ "chain": chain, "index": index, "address": addr }))?;
        }
        Commands::Generate { words } => {
            let phrase = owx.generate_mnemonic(words as usize)?;
            print_json(&serde_json::json!({ "mnemonic": phrase }))?;
        }
        Commands::Send {
            wallet,
            chain,
            tx_hex,
            rpc,
        } => {
            let cred_str = read_line("Passphrase or API token: ");
            let cred = owx::Credential::parse(&cred_str);
            let rt = tokio::runtime::Runtime::new()?;
            let result =
                rt.block_on(owx.sign_and_send(&wallet, &chain, &tx_hex, cred, rpc.as_deref()))?;
            print_json(&result)?;
        }
        #[cfg(feature = "pay")]
        Commands::Pay { url, method, body } => {
            let wn = read_line("Wallet name or ID: ");
            let cred = read_line("Passphrase or API token: ");
            let bridge = owx_pay::OwxBridge::new(owx, &wn, &cred, 0);
            let result = owx_pay::pay(&bridge, &url, &method, body.as_deref())?;
            print_json(&result)?;
        }
        #[cfg(feature = "pay")]
        Commands::Discover { query, limit } => {
            let result = owx_pay::discover(query.as_deref(), Some(limit), None)?;
            print_json(&result)?;
        }
        #[cfg(feature = "moonpay")]
        Commands::Fund { chain, token } => {
            let evm_addr = crate::output::first_evm_address(owx)?;
            let result = owx_pay::fund(&evm_addr, Some(&chain), Some(&token))?;
            print_json(&result)?;
        }
        #[cfg(feature = "moonpay")]
        Commands::Balance { chain } => {
            let evm_addr = crate::output::first_evm_address(owx)?;
            let balances = owx_pay::get_balances(&evm_addr, Some(&chain))?;
            print_json(&balances)?;
        }
        #[cfg(feature = "swap")]
        Commands::Swap { action } => swap::run(action, owx)?,
        Commands::Policy { action } => policy::run(action, owx)?,
    }
    Ok(())
}
