//! Swap subcommands — agent-friendly, zero stdin interaction.

use std::collections::HashMap;
use std::future::Future;

use clap::Subcommand;
use owx::Owx;
use owx::chain::ChainFamily;

use crate::output::print_json;

/// Swap actions.
#[derive(Subcommand)]
pub(crate) enum SwapAction {
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
    /// Auto-select the best quote and execute a swap.
    Execute {
        /// Wallet name or ID.
        #[arg(long)]
        wallet: String,
        /// Passphrase or API token (`OWX_CREDENTIAL` env var also accepted).
        #[arg(long, env = "OWX_CREDENTIAL")]
        credential: String,
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
        /// Optional RPC URL override for the source chain.
        #[arg(long)]
        rpc: Option<String>,
        /// Sort strategy for auto-selection: best-output (default), cheapest, fastest.
        #[arg(long, default_value = "best-output")]
        strategy: String,
    },
}

pub(crate) fn run(action: SwapAction, owx: &Owx) -> Result<(), owx::OwxError> {
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| owx::OwxError::InvalidInput(format!("tokio runtime: {e}")))?;

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
            let engine = build_engine().map_err(|e| owx::OwxError::InvalidInput(e.to_string()))?;
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
                .map_err(|e| owx::OwxError::InvalidInput(e.to_string()))?;
            print_json(&quotes)?;
        }
        SwapAction::Execute {
            wallet,
            credential,
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
            let rpc_map = build_rpc_map(owx, &from_chain, rpc.as_deref());

            let (provider, from_addr) =
                owx.with_signing_key(&wallet, cred, ChainFamily::Evm, 0, |key_hex| {
                    let addr = owx::address_from_hex(ChainFamily::Evm, key_hex)?;
                    let p =
                        owx_swap::evm_provider_from_key_with_rpcs(key_hex, &default_rpc, rpc_map)
                            .map_err(|e| owx::OwxError::InvalidInput(e.to_string()))?;
                    Ok((p, addr))
                })?;

            let engine = build_engine_with_provider(provider)
                .map_err(|e| owx::OwxError::InvalidInput(e.to_string()))?;

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
            let receipt = rt
                .block_on(engine.auto_execute(&req, strat, &NoopSigner))
                .map_err(|e| owx::OwxError::InvalidInput(e.to_string()))?;
            print_json(&receipt)?;
        }
    }
    Ok(())
}

/// Placeholder signer — actual signing is handled inside `EvmProvider`
/// registered on the underlying `LiFiClient`. The generic `SwapSigner`
/// trait is satisfied but not called for the `LiFi` path.
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

fn parse_strategy(s: &str) -> Result<owx_swap::SelectionStrategy, owx::OwxError> {
    match s {
        "best-output" | "best_output" => Ok(owx_swap::SelectionStrategy::BestOutput),
        "cheapest" => Ok(owx_swap::SelectionStrategy::Cheapest),
        "fastest" => Ok(owx_swap::SelectionStrategy::Fastest),
        _ => Err(owx::OwxError::InvalidInput(format!(
            "unknown strategy '{s}'; expected best-output|cheapest|fastest"
        ))),
    }
}

/// Resolve the default EVM RPC URL for a `LiFi` chain ID.
fn resolve_evm_rpc(
    owx: &Owx,
    lifi_chain_id: &str,
    rpc_override: Option<&str>,
) -> Result<String, owx::OwxError> {
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
    Err(owx::OwxError::InvalidInput(format!(
        "no RPC URL for chain {lifi_chain_id}; use --rpc to specify"
    )))
}

/// Build a numeric `chain_id` → RPC URL map from OWX config.
///
/// If `rpc_override` is provided, it only applies to `from_chain_id` (the
/// source chain), not all chains — otherwise multi-hop cross-chain swaps
/// would send every hop to the same RPC.
fn build_rpc_map(
    owx: &Owx,
    from_chain_id: &str,
    rpc_override: Option<&str>,
) -> HashMap<u64, String> {
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
        let numeric = from_chain_id
            .strip_prefix("eip155:")
            .unwrap_or(from_chain_id);
        if let Ok(id) = numeric.parse::<u64>() {
            map.insert(id, url.to_owned());
        }
    }
    map
}
