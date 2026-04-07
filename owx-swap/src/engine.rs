//! Multi-backend swap engine.
//!
//! [`SwapEngine`] aggregates quotes from all registered backends and
//! dispatches execution to the correct one based on the quote's `provider`
//! field. This is the primary entry point for library consumers.

use crate::error::SwapError;
use crate::provider::{SwapBackend, SwapSigner};
use crate::types::{SelectionStrategy, SwapQuote, SwapReceipt, SwapRequest};

/// Multi-backend swap aggregator.
///
/// Register one or more [`SwapBackend`] implementations, then call
/// [`get_quotes`](Self::get_quotes) to fan out across all backends and
/// [`execute`](Self::execute) to run a specific quote.
#[derive(Default)]
pub struct SwapEngine {
    /// Registered swap backends.
    backends: Vec<Box<dyn SwapBackend>>,
}

impl std::fmt::Debug for SwapEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SwapEngine")
            .field(
                "backends",
                &self.backends.iter().map(|b| b.name()).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl SwapEngine {
    /// Create an engine with no backends.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a swap backend.
    pub fn add_backend(&mut self, backend: impl SwapBackend + 'static) {
        self.backends.push(Box::new(backend));
    }

    /// Fan out a request to **all** backends and collect quotes.
    ///
    /// Backends that return errors are silently skipped — only quotes from
    /// responsive backends are included. Returns the last backend error if
    /// every backend fails, or [`SwapError::NoQuotes`] if all succeed but
    /// return zero results.
    ///
    /// # Errors
    ///
    /// Returns [`SwapError`] if all backends fail or no quotes are returned.
    pub async fn get_quotes(&self, req: &SwapRequest) -> Result<Vec<SwapQuote>, SwapError> {
        let mut all = Vec::new();
        let mut last_err: Option<SwapError> = None;
        for backend in &self.backends {
            match backend.get_quotes(req).await {
                Ok(quotes) => all.extend(quotes),
                Err(e) => last_err = Some(e),
            }
        }
        if all.is_empty() {
            return Err(last_err.unwrap_or(SwapError::NoQuotes));
        }
        Ok(all)
    }

    /// Fan out and sort using a specific strategy.
    ///
    /// # Errors
    ///
    /// Returns [`SwapError`] if quote retrieval fails.
    pub async fn get_quotes_sorted(
        &self,
        req: &SwapRequest,
        strategy: SelectionStrategy,
    ) -> Result<Vec<SwapQuote>, SwapError> {
        let mut quotes = self.get_quotes(req).await?;
        sort_quotes(&mut quotes, strategy);
        Ok(quotes)
    }

    /// Auto-select the best quote according to `strategy` and execute it.
    ///
    /// # Errors
    ///
    /// Returns [`SwapError`] if quote retrieval or execution fails.
    pub async fn auto_execute(
        &self,
        req: &SwapRequest,
        strategy: SelectionStrategy,
        signer: &dyn SwapSigner,
    ) -> Result<SwapReceipt, SwapError> {
        let quotes = self.get_quotes_sorted(req, strategy).await?;
        let best = quotes.first().ok_or(SwapError::NoQuotes)?;
        self.execute(best, signer).await
    }

    /// Execute a specific quote.
    ///
    /// The quote's `provider` field determines which backend handles execution.
    ///
    /// # Errors
    ///
    /// Returns [`SwapError::ProviderNotFound`] if no matching backend, or
    /// backend-specific errors on execution failure.
    pub async fn execute(
        &self,
        quote: &SwapQuote,
        signer: &dyn SwapSigner,
    ) -> Result<SwapReceipt, SwapError> {
        let backend = self
            .backends
            .iter()
            .find(|b| b.name() == quote.provider)
            .ok_or_else(|| SwapError::ProviderNotFound(quote.provider.clone()))?;
        backend.execute(quote, signer).await
    }
}

/// Sort quotes in-place according to the chosen strategy.
fn sort_quotes(quotes: &mut [SwapQuote], strategy: SelectionStrategy) {
    match strategy {
        SelectionStrategy::BestOutput => {
            quotes.sort_by(|a, b| cmp_decimal_desc(&a.to_amount, &b.to_amount));
        }
        SelectionStrategy::Cheapest => {
            quotes.sort_by(|a, b| {
                let ga = a.gas_cost_usd.as_deref().unwrap_or("999999");
                let gb = b.gas_cost_usd.as_deref().unwrap_or("999999");
                cmp_decimal_asc(ga, gb)
            });
        }
        SelectionStrategy::Fastest => {
            quotes.sort_by_key(|q| q.estimated_seconds.unwrap_or(u64::MAX));
        }
    }
}

/// Compare two decimal strings in descending order (higher first).
fn cmp_decimal_desc(a: &str, b: &str) -> std::cmp::Ordering {
    let va: f64 = a.parse().unwrap_or(0.0);
    let vb: f64 = b.parse().unwrap_or(0.0);
    vb.partial_cmp(&va).unwrap_or(std::cmp::Ordering::Equal)
}

/// Compare two decimal strings in ascending order (lower first).
fn cmp_decimal_asc(a: &str, b: &str) -> std::cmp::Ordering {
    let va: f64 = a.parse().unwrap_or(f64::MAX);
    let vb: f64 = b.parse().unwrap_or(f64::MAX);
    va.partial_cmp(&vb).unwrap_or(std::cmp::Ordering::Equal)
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    reason = "test panics on out-of-bounds are acceptable"
)]
mod tests {
    use super::*;

    fn make_quote(to_amount: &str, gas: &str, secs: u64) -> SwapQuote {
        SwapQuote {
            id: String::new(),
            provider: String::new(),
            from_token: crate::types::TokenInfo {
                address: String::new(),
                symbol: "A".into(),
                decimals: 6,
                chain_id: "1".into(),
            },
            to_token: crate::types::TokenInfo {
                address: String::new(),
                symbol: "B".into(),
                decimals: 6,
                chain_id: "1".into(),
            },
            from_amount: "1000".into(),
            to_amount: to_amount.into(),
            to_amount_min: None,
            to_amount_usd: None,
            gas_cost_usd: Some(gas.into()),
            route_summary: String::new(),
            tags: Vec::new(),
            estimated_seconds: Some(secs),
            opaque: serde_json::Value::Null,
        }
    }

    #[test]
    fn sort_best_output() {
        let mut q = vec![make_quote("100", "1", 10), make_quote("200", "2", 20)];
        sort_quotes(&mut q, SelectionStrategy::BestOutput);
        assert_eq!(q[0].to_amount, "200");
    }

    #[test]
    fn sort_cheapest() {
        let mut q = vec![make_quote("100", "5", 10), make_quote("200", "1", 20)];
        sort_quotes(&mut q, SelectionStrategy::Cheapest);
        assert_eq!(q[0].gas_cost_usd.as_deref(), Some("1"));
    }

    #[test]
    fn sort_fastest() {
        let mut q = vec![make_quote("100", "1", 30), make_quote("200", "2", 5)];
        sort_quotes(&mut q, SelectionStrategy::Fastest);
        assert_eq!(q[0].estimated_seconds, Some(5));
    }
}
