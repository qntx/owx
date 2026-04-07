//! CLI subcommand definitions and dispatch — agent-friendly, zero stdin interaction.

pub(crate) mod key;
pub(crate) mod policy;
pub(crate) mod sign;
#[cfg(feature = "swap")]
pub(crate) mod swap;
pub(crate) mod wallet;

use clap::Subcommand;
use owx::Owx;

use crate::output::print_json;

/// Top-level CLI commands.
#[derive(Subcommand)]
pub(crate) enum Commands {
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
        wallet: String,
        chain: String,
        /// Owner passphrase.
        #[arg(long, env = "OWX_PASSPHRASE")]
        passphrase: String,
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
        /// Passphrase or API token.
        #[arg(long, env = "OWX_CREDENTIAL")]
        credential: String,
        #[arg(long)]
        rpc: Option<String>,
    },
    /// Make an HTTP request with automatic x402 payment.
    #[cfg(feature = "pay")]
    Pay {
        /// Wallet name or ID.
        #[arg(long)]
        wallet: String,
        /// Passphrase or API token.
        #[arg(long, env = "OWX_CREDENTIAL")]
        credential: String,
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
    /// Fund a wallet via `MoonPay`.
    #[cfg(feature = "moonpay")]
    Fund {
        #[arg(long, default_value = "base")]
        chain: String,
        #[arg(long, default_value = "USDC")]
        token: String,
    },
    /// Check token balances via `MoonPay`.
    #[cfg(feature = "moonpay")]
    Balance {
        #[arg(long, default_value = "base")]
        chain: String,
    },
    /// Cross-chain token swap.
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
pub(crate) fn dispatch(cmd: Commands, owx: &Owx) -> Result<(), owx::OwxError> {
    match cmd {
        Commands::Wallet { action } => wallet::run(action, owx)?,
        Commands::Key { action } => key::run(action, owx)?,
        Commands::Sign { action } => sign::run(action, owx)?,
        Commands::Derive {
            wallet,
            chain,
            passphrase,
            index,
        } => {
            let addr = owx.derive_address(&wallet, &chain, &passphrase, Some(index))?;
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
            credential,
            rpc,
        } => {
            let cred = owx::Credential::parse(&credential);
            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| owx::OwxError::InvalidInput(format!("tokio runtime: {e}")))?;
            let result =
                rt.block_on(owx.sign_and_send(&wallet, &chain, &tx_hex, cred, rpc.as_deref()))?;
            print_json(&result)?;
        }
        #[cfg(feature = "pay")]
        Commands::Pay {
            wallet,
            credential,
            url,
            method,
            body,
        } => {
            let bridge = owx_pay::OwxBridge::new(owx, &wallet, &credential, 0);
            let result = owx_pay::pay(&bridge, &url, &method, body.as_deref())
                .map_err(|e| owx::OwxError::InvalidInput(e.to_string()))?;
            print_json(&result)?;
        }
        #[cfg(feature = "pay")]
        Commands::Discover { query, limit } => {
            let result = owx_pay::discover(query.as_deref(), Some(limit), None)
                .map_err(|e| owx::OwxError::InvalidInput(e.to_string()))?;
            print_json(&result)?;
        }
        #[cfg(feature = "moonpay")]
        Commands::Fund { chain, token } => {
            let evm_addr = crate::output::first_evm_address(owx)?;
            let result = owx_pay::fund(&evm_addr, Some(&chain), Some(&token))
                .map_err(|e| owx::OwxError::InvalidInput(e.to_string()))?;
            print_json(&result)?;
        }
        #[cfg(feature = "moonpay")]
        Commands::Balance { chain } => {
            let evm_addr = crate::output::first_evm_address(owx)?;
            let balances = owx_pay::get_balances(&evm_addr, Some(&chain))
                .map_err(|e| owx::OwxError::InvalidInput(e.to_string()))?;
            print_json(&balances)?;
        }
        #[cfg(feature = "swap")]
        Commands::Swap { action } => swap::run(action, owx)?,
        Commands::Policy { action } => policy::run(action, owx)?,
    }
    Ok(())
}
