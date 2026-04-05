//! Swap subcommands — agent-friendly, zero stdin interaction.

use std::collections::HashMap;
use std::future::Future;

use clap::Subcommand;
use owx::Owx;
use owx::chain::ChainFamily;

use crate::output::print_json;

/// Swap actions.
#[derive(Subcommand)]
pub enum SwapAction {
    /// Get quotes for a cross-chain swap (read-only, no credential needed).
    Quotes {
        #[arg(long)]
        from_chain: String,
        #[arg(long)]
        from_token: String,
        #[arg(long)]
        from_address: String,
        #[arg(long)]
        from_amount: String,
        #[arg(long)]
        to_chain: String,
        #[arg(long)]
        to_token: String,
        /// Sort strategy: best-output (default), cheapest, fastest.
        #[arg(long, default_value = "best-output")]
        strategy: String,
    },
    /// Execute a previously obtained quote by ID.
    Execute {
        /// Wallet name or ID.
        #[arg(long)]
        wallet: String,
        /// Passphrase or API token (`OWX_CREDENTIAL` env var also accepted).
        #[arg(long, env = "OWX_CREDENTIAL")]
        credential: String,
        /// Quote ID from a prior `quotes` call (e.g. `"lifi:route-abc"`).
        /// If omitted, fetches fresh quotes and auto-selects per `--strategy`.
        #[arg(long)]
        quote_id: Option<String>,
        #[arg(long)]
        from_chain: String,
        #[arg(long)]
        from_token: String,
        #[arg(long)]
        from_amount: String,
        #[arg(long)]
        to_chain: String,
        #[arg(long)]
        to_token: String,
        /// Optional RPC URL override.
        #[arg(long)]
        rpc: Option<String>,
        /// Sort strategy for auto-selection: best-output (default), cheapest, fastest.
        #[arg(long, default_value = "best-output")]
        strategy: String,
    },
}

pub fn run(action: SwapAction, owx: &Owx) -> Result<(), owx::Error> {
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| owx::Error::InvalidInput(format!("tokio runtime: {e}")))?;

    match action {
        SwapAction::Quotes {
            from_chain,
            from_token,
            from_address,
            from_amount,
            to_chain,
            to_token,
            strategy,
        } => {
            let engine = build_engine().map_err(swap_err)?;
            let req = owx_swap::SwapRequest {
                from_chain,
                from_token,
                from_amount,
                from_address,
                to_chain,
                to_token,
                to_address: None,
                slippage: None,
            };
            let strat = parse_strategy(&strategy)?;
            let quotes = rt
                .block_on(engine.get_quotes_sorted(&req, strat))
                .map_err(swap_err)?;
            print_json(&quotes)?;
        }
        SwapAction::Execute {
            wallet,
            credential,
            quote_id: _,
            from_chain,
            from_token,
            from_amount,
            to_chain,
            to_token,
            rpc,
            strategy,
        } => {
            let cred = owx::Credential::parse(&credential);
            let default_rpc = resolve_evm_rpc(owx, &from_chain, rpc.as_deref())?;
            let rpc_map = build_rpc_map(owx, rpc.as_deref());

            let (provider, from_addr) =
                owx.with_signing_key(&wallet, cred, ChainFamily::Evm, 0, |key_hex| {
                    let addr = owx::signer::address_from_hex(ChainFamily::Evm, key_hex)?;
                    let p =
                        owx_swap::evm_provider_from_key_with_rpcs(key_hex, &default_rpc, rpc_map)
                            .map_err(|e| owx::Error::InvalidInput(e.to_string()))?;
                    Ok((p, addr))
                })?;

            let engine = build_engine_with_provider(provider).map_err(swap_err)?;

            let req = owx_swap::SwapRequest {
                from_chain,
                from_token,
                from_amount,
                from_address: from_addr,
                to_chain,
                to_token,
                to_address: None,
                slippage: None,
            };

            let strat = parse_strategy(&strategy)?;
            let quotes = rt
                .block_on(engine.get_quotes_sorted(&req, strat))
                .map_err(swap_err)?;
            let best = quotes
                .first()
                .ok_or_else(|| swap_err(owx_swap::SwapError::NoQuotes))?;

            let receipt = rt
                .block_on(engine.execute(best, &NoopSigner))
                .map_err(swap_err)?;
            print_json(&receipt)?;
        }
    }
    Ok(())
}

/// Map a [`owx_swap::SwapError`] to [`owx::Error`].
#[allow(clippy::needless_pass_by_value)]
fn swap_err(e: owx_swap::SwapError) -> owx::Error {
    owx::Error::InvalidInput(e.to_string())
}

/// Placeholder signer — actual signing is handled inside `EvmProvider`
/// registered on the underlying `LiFiClient`. The generic `SwapSigner`
/// trait is satisfied but not called for the LiFi path.
struct NoopSigner;

impl owx_swap::SwapSigner for NoopSigner {
    fn address(&self) -> &'static str {
        ""
    }

    fn send_transaction<'a>(
        &'a self,
        _chain_id: u64,
        _tx_data: &'a [u8],
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<String, owx_swap::SwapError>> + Send + 'a>>
    {
        Box::pin(async {
            Err(owx_swap::SwapError::Execution(
                "noop signer: signing delegated to EvmProvider".into(),
            ))
        })
    }
}

fn build_engine() -> Result<owx_swap::SwapEngine, owx_swap::SwapError> {
    let mut engine = owx_swap::SwapEngine::new();
    engine.add_backend(owx_swap::LiFiBackend::new("owx")?);
    Ok(engine)
}

fn build_engine_with_provider(
    provider: owx_swap::EvmProvider,
) -> Result<owx_swap::SwapEngine, owx_swap::SwapError> {
    let backend = owx_swap::LiFiBackend::new("owx")?;
    backend.add_provider(provider);
    let mut engine = owx_swap::SwapEngine::new();
    engine.add_backend(backend);
    Ok(engine)
}

fn parse_strategy(s: &str) -> Result<owx_swap::SelectionStrategy, owx::Error> {
    match s {
        "best-output" | "best_output" => Ok(owx_swap::SelectionStrategy::BestOutput),
        "cheapest" => Ok(owx_swap::SelectionStrategy::Cheapest),
        "fastest" => Ok(owx_swap::SelectionStrategy::Fastest),
        _ => Err(owx::Error::InvalidInput(format!(
            "unknown strategy '{s}'; expected best-output|cheapest|fastest"
        ))),
    }
}

/// Resolve the default EVM RPC URL for a LiFi chain ID.
fn resolve_evm_rpc(
    owx: &Owx,
    lifi_chain_id: &str,
    rpc_override: Option<&str>,
) -> Result<String, owx::Error> {
    if let Some(url) = rpc_override {
        return Ok(url.to_owned());
    }
    let numeric = lifi_chain_id
        .strip_prefix("eip155:")
        .unwrap_or(lifi_chain_id);
    let caip2 = format!("eip155:{numeric}");
    if let Some(url) = owx.config().rpc_url(&caip2) {
        return Ok(url.to_owned());
    }
    let defaults = owx::config::Config::default_rpc();
    if let Some(url) = defaults.get(&caip2) {
        return Ok(url.clone());
    }
    Err(owx::Error::InvalidInput(format!(
        "no RPC URL for chain {lifi_chain_id}; use --rpc to specify"
    )))
}

/// Build a numeric chain_id → RPC URL map from OWX config.
fn build_rpc_map(owx: &Owx, rpc_override: Option<&str>) -> HashMap<u64, String> {
    let mut map = HashMap::new();
    let defaults = owx::config::Config::default_rpc();
    for (caip2, url) in defaults.iter().chain(owx.config().rpc.iter()) {
        if let Some(id_str) = caip2.strip_prefix("eip155:")
            && let Ok(id) = id_str.parse::<u64>()
        {
            map.insert(id, url.clone());
        }
    }
    if let Some(url) = rpc_override {
        for v in map.values_mut() {
            url.clone_into(v);
        }
    }
    map
}
