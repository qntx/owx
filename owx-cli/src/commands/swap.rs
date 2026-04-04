//! Swap subcommands.

use clap::Subcommand;

use crate::output::print_json;

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
}

pub fn run(action: SwapAction) -> Result<(), Box<dyn std::error::Error>> {
    let client = owx_swap::SwapClient::new("owx")?;
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
            let from_id: u64 = from_chain.parse()?;
            let to_id: u64 = to_chain.parse()?;
            let req = owx_swap::types::RoutesRequest::builder()
                .from_chain_id(owx_swap::types::ChainId(from_id))
                .to_chain_id(owx_swap::types::ChainId(to_id))
                .from_token_address(&from_token)
                .to_token_address(&to_token)
                .from_amount(&from_amount)
                .build();
            let routes = rt.block_on(client.routes(&req))?;
            print_json(&routes)?;
        }
    }
    Ok(())
}
