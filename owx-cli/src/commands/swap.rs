//! Swap subcommands.

use std::collections::HashMap;

use clap::Subcommand;
use owx::Owx;
use owx::chain::ChainFamily;
use owx_swap::types::{ChainId, ExecutionOptions, Route, RoutesRequest};

use crate::output::{print_json, read_line};

/// Swap actions.
#[derive(Subcommand)]
pub enum SwapAction {
    /// Get a quote for a cross-chain swap.
    Quote {
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
    },
    /// Get available routes for a swap.
    Routes {
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
    },
    /// Execute a token swap using an OWX wallet.
    ///
    /// Queries available routes, lets you pick one (or auto-select the best),
    /// then signs and broadcasts via the internal wallet.
    Execute {
        /// Wallet name or ID.
        #[arg(long)]
        wallet: String,
        /// Source chain (LiFi numeric ID, e.g. 8453 for Base).
        #[arg(long)]
        from_chain: String,
        /// Source token contract address.
        #[arg(long)]
        from_token: String,
        /// Amount in base units (e.g. "1000000" for 1 USDC).
        #[arg(long)]
        from_amount: String,
        /// Destination chain (LiFi numeric ID).
        #[arg(long)]
        to_chain: String,
        /// Destination token contract address.
        #[arg(long)]
        to_token: String,
        /// Optional RPC URL override.
        #[arg(long)]
        rpc: Option<String>,
        /// Auto-select the best route without prompting.
        #[arg(long, default_value_t = false)]
        auto: bool,
    },
}

pub fn run(action: SwapAction, owx: &Owx) -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Runtime::new()?;

    match action {
        SwapAction::Quote {
            from_chain,
            from_token,
            from_address,
            from_amount,
            to_chain,
            to_token,
        } => {
            let client = owx_swap::SwapClient::new("owx")?;
            let req = owx_swap::types::QuoteRequest::builder()
                .from_chain(&from_chain)
                .from_token(&from_token)
                .from_address(&from_address)
                .from_amount(&from_amount)
                .to_chain(&to_chain)
                .to_token(&to_token)
                .build();
            let quote = rt.block_on(client.quote(&req))?;
            print_json(&quote)?;
        }
        SwapAction::Routes {
            from_chain,
            from_token,
            from_amount,
            to_chain,
            to_token,
        } => {
            let client = owx_swap::SwapClient::new("owx")?;
            let from_id: u64 = from_chain.parse()?;
            let to_id: u64 = to_chain.parse()?;
            let req = RoutesRequest::builder()
                .from_chain_id(ChainId(from_id))
                .to_chain_id(ChainId(to_id))
                .from_token_address(&from_token)
                .to_token_address(&to_token)
                .from_amount(&from_amount)
                .build();
            let routes = rt.block_on(client.routes(&req))?;
            print_json(&routes)?;
        }
        SwapAction::Execute {
            wallet,
            from_chain,
            from_token,
            from_amount,
            to_chain,
            to_token,
            rpc,
            auto,
        } => {
            run_execute(
                owx, &rt, &wallet, &from_chain, &from_token, &from_amount, &to_chain, &to_token,
                rpc.as_deref(), auto,
            )?;
        }
    }
    Ok(())
}

/// Execute a swap: decrypt wallet → build provider → query routes → pick → execute.
///
/// The private key **never** leaves the `with_signing_key` closure — it is
/// consumed to build the `EvmProvider` signer and then immediately zeroized.
#[allow(clippy::too_many_arguments)]
fn run_execute(
    owx: &Owx,
    rt: &tokio::runtime::Runtime,
    wallet: &str,
    from_chain: &str,
    from_token: &str,
    from_amount: &str,
    to_chain: &str,
    to_token: &str,
    rpc_override: Option<&str>,
    auto_select: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let cred_str = read_line("Passphrase or API token: ");
    let cred = owx::Credential::parse(&cred_str);

    let default_rpc = resolve_evm_rpc(owx, from_chain, rpc_override)?;
    let rpc_map = build_rpc_map(owx, rpc_override);

    // Key is passed by reference to the closure and zeroized immediately after.
    // It lives only inside EvmProvider's PrivateKeySigner (k256, which zeroizes on drop).
    let (provider, from_addr) = owx.with_signing_key(
        wallet,
        cred,
        ChainFamily::Evm,
        0,
        |key_hex| {
            let addr = owx::signer::address_from_hex(ChainFamily::Evm, key_hex)?;
            let p = owx_swap::evm_provider_from_key_with_rpcs(key_hex, &default_rpc, rpc_map)
                .map_err(|e| owx::Error::InvalidInput(e.to_string()))?;
            Ok((p, addr))
        },
    )?;

    let client = owx_swap::SwapClient::new("owx")?;
    client.add_provider(provider);

    let from_id: u64 = from_chain
        .parse()
        .map_err(|e| owx::Error::InvalidInput(format!("invalid from_chain: {e}")))?;
    let to_id: u64 = to_chain
        .parse()
        .map_err(|e| owx::Error::InvalidInput(format!("invalid to_chain: {e}")))?;

    let routes_req = RoutesRequest::builder()
        .from_chain_id(ChainId(from_id))
        .to_chain_id(ChainId(to_id))
        .from_token_address(from_token)
        .to_token_address(to_token)
        .from_amount(from_amount)
        .from_address(&from_addr)
        .build();

    let resp = rt.block_on(client.routes(&routes_req))?;
    if resp.routes.is_empty() {
        return Err("no routes available for this swap".into());
    }

    let route = select_route(&resp.routes, auto_select)?;

    let result = rt.block_on(client.execute_route(route, ExecutionOptions::default()))?;
    print_json(&result)?;

    Ok(())
}

/// Display available routes and let the user pick one (or auto-select the best).
#[allow(clippy::print_stderr)]
fn select_route(routes: &[Route], auto_select: bool) -> Result<Route, Box<dyn std::error::Error>> {
    if auto_select || routes.len() == 1 {
        return Ok(routes[0].clone());
    }

    eprintln!("\nAvailable routes:\n");
    for (i, r) in routes.iter().enumerate() {
        let tags = r.tags.as_deref().unwrap_or_default().join(", ");
        let gas = r.gas_cost_usd.as_deref().unwrap_or("?");
        let to_usd = r.to_amount_usd.as_deref().unwrap_or("?");
        let steps: Vec<&str> = r.steps.iter().filter_map(|s| s.tool.as_deref()).collect();
        eprintln!(
            "  [{i}] {from_sym} → {to_sym}  out≈${to_usd}  gas≈${gas}  via {tools}{tag_str}",
            from_sym = r.from_token.symbol,
            to_sym = r.to_token.symbol,
            tools = steps.join(" → "),
            tag_str = if tags.is_empty() {
                String::new()
            } else {
                format!("  [{tags}]")
            },
        );
    }
    eprintln!();

    loop {
        let input = read_line(&format!("Select route [0-{}]: ", routes.len() - 1));
        if let Ok(idx) = input.trim().parse::<usize>()
            && idx < routes.len()
        {
            return Ok(routes[idx].clone());
        }
        eprintln!("Invalid selection, try again.");
    }
}

/// Resolve the default EVM RPC URL for a LiFi chain ID.
fn resolve_evm_rpc(
    owx: &Owx,
    lifi_chain_id: &str,
    rpc_override: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(url) = rpc_override {
        return Ok(url.to_owned());
    }
    let caip2 = format!("eip155:{lifi_chain_id}");
    if let Some(url) = owx.config().rpc_url(&caip2) {
        return Ok(url.to_owned());
    }
    let defaults = owx::config::Config::default_rpc();
    if let Some(url) = defaults.get(&caip2) {
        return Ok(url.clone());
    }
    Err(format!("no RPC URL for chain {lifi_chain_id}; use --rpc to specify").into())
}

/// Build a numeric chain_id → RPC URL map from OWX config for multi-chain resolution.
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
