//! SwapClient — simplified async wrapper around [`lifiswap::LiFiClient`].

use std::sync::Arc;

use lifiswap::provider::Provider;
use lifiswap::types::{
    ExecutionOptions, LiFiStep, QuoteRequest, Route, RouteExtended, RoutesRequest, RoutesResponse,
};
use lifiswap::{LiFiClient, LiFiConfig};

use crate::error::SwapError;

/// High-level async swap client backed by [`LiFiClient`].
///
/// Provides simplified methods for common swap operations while exposing
/// the underlying [`LiFiClient`] for advanced use cases.
#[derive(Debug, Clone)]
pub struct SwapClient {
    inner: LiFiClient,
}

impl SwapClient {
    /// Create a new swap client with the given integrator name.
    pub fn new(integrator: &str) -> Result<Self, SwapError> {
        let config = LiFiConfig::builder().integrator(integrator).build();
        let inner = LiFiClient::new(config)?;
        Ok(Self { inner })
    }

    /// Create a swap client from an existing [`LiFiConfig`].
    pub fn with_config(config: LiFiConfig) -> Result<Self, SwapError> {
        let inner = LiFiClient::new(config)?;
        Ok(Self { inner })
    }

    /// Create a swap client with a pre-built [`reqwest::Client`].
    #[must_use]
    pub fn with_http_client(config: LiFiConfig, http: reqwest::Client) -> Self {
        Self {
            inner: LiFiClient::with_http_client(config, http),
        }
    }

    /// Register a chain provider (e.g. EVM, SVM).
    pub fn add_provider(&self, provider: impl Provider) {
        self.inner.add_provider(provider);
    }

    /// Register multiple chain providers at once.
    pub fn set_providers(&self, providers: Vec<Arc<dyn Provider>>) {
        self.inner.set_providers(providers);
    }

    /// Access the underlying [`LiFiClient`] for advanced operations.
    #[must_use]
    pub const fn lifi(&self) -> &LiFiClient {
        &self.inner
    }

    /// Get a quote for a token swap.
    pub async fn quote(&self, request: &QuoteRequest) -> Result<LiFiStep, SwapError> {
        Ok(self.inner.get_quote(request).await?)
    }

    /// Get available routes for a swap.
    pub async fn routes(&self, request: &RoutesRequest) -> Result<RoutesResponse, SwapError> {
        Ok(self.inner.get_routes(request).await?)
    }

    /// Execute a quote end-to-end (requires registered providers).
    pub async fn execute_quote(
        &self,
        quote: LiFiStep,
        options: ExecutionOptions,
    ) -> Result<RouteExtended, SwapError> {
        Ok(self.inner.execute_quote(quote, options).await?)
    }

    /// Execute a specific route (requires registered providers).
    pub async fn execute_route(
        &self,
        route: Route,
        options: ExecutionOptions,
    ) -> Result<RouteExtended, SwapError> {
        Ok(self.inner.execute_route(route, options).await?)
    }

    /// One-shot swap: quote → execute in a single call.
    pub async fn swap(
        &self,
        request: &QuoteRequest,
        options: ExecutionOptions,
    ) -> Result<RouteExtended, SwapError> {
        Ok(self.inner.swap(request, options).await?)
    }
}
