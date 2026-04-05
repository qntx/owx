//! x402 service discovery via CDP directory API.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::error::{PayError, PayErrorCode};
use crate::http::CLIENT as HTTP;

const DIRECTORY_URL: &str = "https://x402.org/api/services";

/// A discovered payable service.
#[derive(Debug, Clone, Serialize)]
pub struct Service {
    /// Human-readable name.
    pub name: String,
    /// Full endpoint URL.
    pub url: String,
    /// Short description.
    pub description: String,
    /// Cheapest price display.
    pub price: String,
    /// Network or chain.
    pub network: String,
    /// Tags.
    pub tags: Vec<String>,
}

/// Result of a discover call with pagination.
#[derive(Debug, Clone, Serialize)]
pub struct DiscoverResult {
    /// Discovered services.
    pub services: Vec<Service>,
    /// Total services available.
    pub total: u64,
    /// Limit used.
    pub limit: u64,
    /// Offset used.
    pub offset: u64,
}

#[derive(Deserialize)]
struct DirectoryResponse {
    #[serde(default)]
    items: Vec<DirectoryItem>,
    #[serde(default)]
    pagination: Option<Pagination>,
}

#[derive(Deserialize)]
struct DirectoryItem {
    resource: String,
    #[serde(default)]
    accepts: Vec<Accept>,
    #[serde(default)]
    metadata: Option<Metadata>,
}

#[derive(Deserialize)]
struct Accept {
    #[serde(default)]
    network: String,
    #[serde(default)]
    amount: String,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Deserialize)]
struct Metadata {
    description: Option<String>,
}

#[derive(Deserialize)]
struct Pagination {
    limit: u64,
    offset: u64,
    total: u64,
}

/// Discover payable services with optional search and pagination.
pub fn discover_all(
    query: Option<&str>,
    limit: Option<u64>,
    offset: Option<u64>,
) -> Result<DiscoverResult, PayError> {
    let limit = limit.unwrap_or(20);
    let offset = offset.unwrap_or(0);

    let mut url = format!("{DIRECTORY_URL}?limit={limit}&offset={offset}");
    if let Some(q) = query {
        let _ = write!(url, "&q={}", urlencoding(q));
    }

    let resp = HTTP.get(&url).send()?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        return Err(PayError::new(
            PayErrorCode::HttpStatus,
            format!("directory returned {status}: {body}"),
        ));
    }

    let dir: DirectoryResponse = resp.json()?;
    let pagination = dir.pagination.unwrap_or(Pagination {
        limit,
        offset,
        total: dir.items.len() as u64,
    });

    let services = dir
        .items
        .into_iter()
        .map(|item| {
            let desc = item
                .metadata
                .as_ref()
                .and_then(|m| m.description.as_deref())
                .or_else(|| item.accepts.first().and_then(|a| a.description.as_deref()))
                .unwrap_or("")
                .to_owned();
            let (price, network) = item.accepts.first().map_or_else(
                || ("free".to_owned(), String::new()),
                |a| (format_price(&a.amount), a.network.clone()),
            );
            let name = item
                .resource
                .split('/')
                .next_back()
                .unwrap_or(&item.resource)
                .to_owned();
            Service {
                name,
                url: item.resource,
                description: truncate(&desc, 80),
                price,
                network,
                tags: Vec::new(),
            }
        })
        .collect();

    Ok(DiscoverResult {
        services,
        total: pagination.total,
        limit: pagination.limit,
        offset: pagination.offset,
    })
}

fn format_price(raw: &str) -> String {
    let n: u128 = raw.parse().unwrap_or(0);
    if n == 0 {
        return "free".to_owned();
    }
    let cents = n / 10_000;
    let frac = (n % 10_000) / 100;
    format!("${cents}.{frac:02}")
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        let end = s.char_indices().nth(max - 1).map_or(s.len(), |(i, _)| i);
        format!("{}…", &s[..end])
    }
}

fn urlencoding(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}
