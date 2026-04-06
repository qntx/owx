//! `LiFi` swap/bridge backend.
//!
//! Translates between the generic `owx-swap` types and the `lifiswap` SDK.

use std::future::Future;
use std::pin::Pin;

use lifiswap::types::{ChainId, ExecutionOptions, RoutesRequest};
use lifiswap::{LiFiClient, LiFiConfig};

use crate::error::SwapError;
use crate::provider::{SwapBackend, SwapSigner};
use crate::types::{SwapQuote, SwapReceipt, SwapRequest, SwapStatus, TokenInfo};

/// `LiFi` aggregator backend.
#[derive(Debug, Clone)]
pub struct LiFiBackend {
    /// Underlying `LiFi` SDK client.
    client: LiFiClient,
}

impl LiFiBackend {
    /// Create a new `LiFi` backend with the given integrator name.
    ///
    /// # Errors
    ///
    /// Returns [`SwapError::LiFi`] if the client cannot be initialized.
    pub fn new(integrator: &str) -> Result<Self, SwapError> {
        let config = LiFiConfig::builder().integrator(integrator).build();
        let client = LiFiClient::new(config)?;
        Ok(Self { client })
    }

    /// Create from an existing [`LiFiConfig`].
    ///
    /// # Errors
    ///
    /// Returns [`SwapError::LiFi`] if the client cannot be initialized.
    pub fn with_config(config: LiFiConfig) -> Result<Self, SwapError> {
        let client = LiFiClient::new(config)?;
        Ok(Self { client })
    }

    /// Access the underlying [`LiFiClient`] for advanced operations.
    #[must_use]
    pub const fn client(&self) -> &LiFiClient {
        &self.client
    }

    /// Register a chain provider on the underlying client (e.g. EVM).
    pub fn add_provider(&self, provider: impl lifiswap::provider::Provider) {
        self.client.add_provider(provider);
    }
}

impl SwapBackend for LiFiBackend {
    fn name(&self) -> &'static str {
        "lifi"
    }

    fn get_quotes<'a>(
        &'a self,
        req: &'a SwapRequest,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SwapQuote>, SwapError>> + Send + 'a>> {
        Box::pin(async move {
            let from_id = parse_chain_id(&req.from_chain)?;
            let to_id = parse_chain_id(&req.to_chain)?;

            let routes_req = RoutesRequest::builder()
                .from_chain_id(ChainId(from_id))
                .to_chain_id(ChainId(to_id))
                .from_token_address(&req.from_token)
                .to_token_address(&req.to_token)
                .from_amount(&req.from_amount)
                .from_address(&req.from_address)
                .maybe_to_address(req.to_address.as_deref())
                .build();

            let resp = self.client.get_routes(&routes_req).await?;

            let quotes: Vec<SwapQuote> = resp
                .routes
                .iter()
                .map(route_to_quote)
                .collect::<Result<Vec<_>, _>>()?;

            Ok(quotes)
        })
    }

    fn execute<'a>(
        &'a self,
        quote: &'a SwapQuote,
        _signer: &'a dyn SwapSigner,
    ) -> Pin<Box<dyn Future<Output = Result<SwapReceipt, SwapError>> + Send + 'a>> {
        Box::pin(async move {
            let route: lifiswap::types::Route = serde_json::from_value(quote.opaque.clone())
                .map_err(|e| {
                    SwapError::InvalidInput(format!("failed to deserialise LiFi route: {e}"))
                })?;

            let extended = self
                .client
                .execute_route(route, ExecutionOptions::default())
                .await?;

            let tx_hash = extended
                .steps
                .first()
                .and_then(|s| s.execution.as_ref())
                .and_then(|e| e.actions.iter().find_map(|a| a.tx_hash.clone()))
                .unwrap_or_default();

            let status = if extended.steps.iter().all(|s| {
                s.execution
                    .as_ref()
                    .is_some_and(|e| e.status == lifiswap::types::ExecutionStatus::Done)
            }) {
                SwapStatus::Success
            } else {
                SwapStatus::Failed {
                    reason: "one or more steps did not complete".into(),
                }
            };

            let to_amount = extended
                .steps
                .last()
                .and_then(|s| s.execution.as_ref())
                .and_then(|e| e.to_amount.clone());

            Ok(SwapReceipt {
                tx_hash,
                status,
                from_amount: quote.from_amount.clone(),
                to_amount,
            })
        })
    }
}

/// Convert a `LiFi` `Route` into a generic `SwapQuote`.
fn route_to_quote(route: &lifiswap::types::Route) -> Result<SwapQuote, SwapError> {
    let tools: Vec<&str> = route
        .steps
        .iter()
        .filter_map(|s| s.tool.as_deref())
        .collect();

    Ok(SwapQuote {
        id: format!("lifi:{}", route.id),
        provider: "lifi".into(),
        from_token: TokenInfo {
            address: route.from_token.address.clone(),
            symbol: route.from_token.symbol.clone(),
            decimals: route.from_token.decimals,
            chain_id: route.from_chain_id.0.to_string(),
        },
        to_token: TokenInfo {
            address: route.to_token.address.clone(),
            symbol: route.to_token.symbol.clone(),
            decimals: route.to_token.decimals,
            chain_id: route.to_chain_id.0.to_string(),
        },
        from_amount: route.from_amount.clone(),
        to_amount: route.to_amount.clone(),
        to_amount_min: route.to_amount_min.clone(),
        to_amount_usd: route.to_amount_usd.clone(),
        gas_cost_usd: route.gas_cost_usd.clone(),
        route_summary: tools.join(" → "),
        tags: route.tags.clone().unwrap_or_default(),
        estimated_seconds: None,
        opaque: serde_json::to_value(route)?,
    })
}

/// Parse a chain ID string (supports both numeric `"42161"` and CAIP-2 `"eip155:42161"`).
fn parse_chain_id(s: &str) -> Result<u64, SwapError> {
    let numeric = s.strip_prefix("eip155:").unwrap_or(s);
    numeric
        .parse()
        .map_err(|e| SwapError::InvalidInput(format!("invalid chain ID '{s}': {e}")))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_numeric() {
        assert_eq!(parse_chain_id("42161").expect("valid"), 42161);
    }

    #[test]
    fn parse_caip2() {
        assert_eq!(parse_chain_id("eip155:8453").expect("valid"), 8453);
    }

    #[test]
    fn parse_invalid() {
        assert!(parse_chain_id("solana").is_err());
    }
}
