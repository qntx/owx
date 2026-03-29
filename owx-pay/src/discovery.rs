//! Service discovery via the CDP x402 directory.

use crate::error::PayError;
use crate::types::{DiscoverResult, DiscoveryResponse, Service};
use crate::x402::format_usdc;

/// CDP discovery API endpoint.
const CDP_DISCOVERY_URL: &str = "https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources";

/// Known testnet identifiers to filter out.
const TESTNETS: &[&str] = &[
    "base-sepolia",
    "eip155:84532",
    "eip155:11155111",
    "solana-devnet",
];

/// Discover payable services from the x402 directory.
///
/// Fetches the directory with pagination, filters testnets, and optionally
/// searches by query string (client-side).
pub async fn discover(
    query: Option<&str>,
    limit: Option<u64>,
    offset: Option<u64>,
) -> Result<DiscoverResult, PayError> {
    let limit = limit.unwrap_or(100);
    let offset = offset.unwrap_or(0);

    if let Some(q) = query {
        return discover_with_query(q, limit, offset).await;
    }

    let resp = fetch_page(limit, offset).await?;
    let total = resp.total;
    let services = filter_services(resp.items, None);

    Ok(DiscoverResult {
        services,
        total,
        limit,
        offset,
    })
}

/// Paginate through the directory collecting services matching a query.
async fn discover_with_query(
    query: &str,
    limit: u64,
    offset: u64,
) -> Result<DiscoverResult, PayError> {
    const PAGE_SIZE: u64 = 500;
    const MAX_PAGES: u64 = 30;

    let mut collected: Vec<Service> = Vec::new();
    let mut skipped: u64 = 0;
    let mut api_offset: u64 = 0;
    let mut total: u64 = 0;

    for _ in 0..MAX_PAGES {
        let resp = fetch_page(PAGE_SIZE, api_offset).await?;
        total = resp.total;
        let page_len = resp.items.len() as u64;

        let matches = filter_services(resp.items, Some(query));
        for svc in matches {
            if skipped < offset {
                skipped += 1;
                continue;
            }
            collected.push(svc);
            if collected.len() as u64 >= limit {
                break;
            }
        }

        if collected.len() as u64 >= limit {
            break;
        }
        api_offset += page_len;
        if api_offset >= total {
            break;
        }
    }

    Ok(DiscoverResult {
        services: collected,
        total,
        limit,
        offset,
    })
}

/// Internal fetch result.
struct FetchResult {
    /// Discovered items.
    items: Vec<crate::types::DiscoveredService>,
    /// Total count.
    total: u64,
}

/// Fetch a single page from the CDP discovery API.
async fn fetch_page(limit: u64, offset: u64) -> Result<FetchResult, PayError> {
    let url = format!("{CDP_DISCOVERY_URL}?limit={limit}&offset={offset}");
    let client = reqwest::Client::new();
    let resp = client.get(&url).send().await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(PayError::ProtocolMalformed(format!(
            "discovery returned {status}: {body}"
        )));
    }

    let text = resp.text().await.unwrap_or_default();
    let body: DiscoveryResponse = serde_json::from_str(&text)
        .map_err(|e| PayError::ProtocolMalformed(format!("failed to parse discovery: {e}")))?;

    let total = body.pagination.map_or(0, |p| p.total);
    Ok(FetchResult {
        items: body.items,
        total,
    })
}

/// Filter and convert raw discovered services, optionally matching a query.
fn filter_services(
    items: Vec<crate::types::DiscoveredService>,
    query: Option<&str>,
) -> Vec<Service> {
    let q = query.map(str::to_lowercase);
    let mut services = Vec::new();

    for svc in items {
        let accept = match svc.accepts.first() {
            Some(a) => a,
            None => continue,
        };

        if TESTNETS.iter().any(|t| accept.network.contains(t)) {
            continue;
        }

        if let Some(ref q) = q {
            let url_match = svc.resource.to_lowercase().contains(q);
            let desc_match = accept
                .description
                .as_ref()
                .is_some_and(|d| d.to_lowercase().contains(q));
            let meta_match = svc
                .metadata
                .as_ref()
                .and_then(|m| m.description.as_ref())
                .is_some_and(|d| d.to_lowercase().contains(q));
            if !url_match && !desc_match && !meta_match {
                continue;
            }
        }

        let desc = accept
            .description
            .as_deref()
            .or_else(|| svc.metadata.as_ref().and_then(|m| m.description.as_deref()))
            .unwrap_or("");

        services.push(Service {
            name: svc.resource.clone(),
            url: svc.resource,
            description: truncate(desc, 80),
            price: format_usdc(&accept.amount),
            network: accept.network.clone(),
        });
    }

    services
}

/// Truncate a string to max chars, adding "..." if needed.
fn truncate(s: &str, max: usize) -> String {
    let first_line = s.lines().next().unwrap_or("");
    if first_line.len() <= max {
        return first_line.to_owned();
    }
    let cutoff = first_line
        .char_indices()
        .map(|(idx, _)| idx)
        .chain(std::iter::once(first_line.len()))
        .take_while(|&idx| idx <= max.saturating_sub(3))
        .last()
        .unwrap_or(0);
    format!("{}...", &first_line[..cutoff])
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn truncate_short() {
        assert_eq!(truncate("hello", 80), "hello");
    }

    #[test]
    fn truncate_long() {
        let long = "a".repeat(100);
        let result = truncate(&long, 20);
        assert!(result.len() <= 20);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn truncate_multiline() {
        assert_eq!(truncate("first\nsecond", 80), "first");
    }

    #[test]
    fn testnet_filter() {
        assert!(TESTNETS.contains(&"base-sepolia"));
        assert!(TESTNETS.contains(&"eip155:84532"));
    }
}
