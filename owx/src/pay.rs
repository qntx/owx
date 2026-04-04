//! x402 payment protocol (blocking), service discovery, and wallet funding.

#![allow(clippy::missing_docs_in_private_items)]

use std::sync::LazyLock;
use std::time::Duration;

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::chain::ChainFamily;
use crate::error::Error;

/// Shared blocking HTTP client for payment operations.
static HTTP: LazyLock<reqwest::blocking::Client> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("failed to build HTTP client")
});

/// Trait abstracting wallet access for payment operations.
///
/// The private key NEVER leaves the implementation — all signing happens
/// inside the wallet.
pub trait WalletBridge: Send + Sync {
    /// Chain families this wallet supports.
    fn supported_families(&self) -> Vec<ChainFamily>;
    /// Get the address for a CAIP-2 network string.
    fn address(&self, network: &str) -> Result<String, Error>;
    /// Sign a payment payload for a scheme/network. Returns hex signature.
    fn sign_payload(&self, scheme: &str, network: &str, payload: &str) -> Result<String, Error>;
}

/// Result of a payment flow.
#[derive(Debug, Clone, Serialize)]
pub struct PayResult {
    /// HTTP status code of the final response.
    pub status: u16,
    /// Response body.
    pub body: String,
    /// Payment info if a payment was made.
    pub payment: Option<PaymentInfo>,
}

/// Information about a completed payment.
#[derive(Debug, Clone, Serialize)]
pub struct PaymentInfo {
    /// Human-readable amount (e.g. "$0.01").
    pub amount: String,
    /// Chain display name.
    pub network: String,
    /// Token symbol.
    pub token: String,
}

/// Make an HTTP request with automatic x402 payment handling (blocking).
pub fn pay(
    wallet: &dyn WalletBridge,
    url: &str,
    method: &str,
    body: Option<&str>,
) -> Result<PayResult, Error> {
    let initial = send_request(url, method, body, None)?;
    if initial.status().as_u16() != 402 {
        let status = initial.status().as_u16();
        let text = initial.text().unwrap_or_default();
        return Ok(PayResult {
            status,
            body: text,
            payment: None,
        });
    }

    let headers = initial.headers().clone();
    let body_402 = initial.text().unwrap_or_default();
    handle_402(wallet, url, method, body, &headers, &body_402)
}

/// x402 server response envelope.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct X402Response {
    #[serde(default)]
    x402_version: Option<u32>,
    accepts: Vec<PaymentRequirements>,
    #[serde(default)]
    resource: Option<serde_json::Value>,
}

/// x402 payment requirements from the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PaymentRequirements {
    scheme: String,
    network: String,
    #[serde(alias = "maxAmountRequired")]
    amount: String,
    asset: String,
    #[serde(alias = "payTo")]
    pay_to: String,
    #[serde(default = "default_timeout")]
    max_timeout_seconds: u64,
    #[serde(default)]
    extra: serde_json::Value,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    resource: Option<serde_json::Value>,
}

const fn default_timeout() -> u64 {
    30
}

/// Supported payment schemes.
const SUPPORTED_SCHEMES: &[&str] = &["exact"];

/// Process a 402 response.
fn handle_402(
    wallet: &dyn WalletBridge,
    url: &str,
    method: &str,
    req_body: Option<&str>,
    resp_headers: &reqwest::header::HeaderMap,
    body_402: &str,
) -> Result<PayResult, Error> {
    let (x402_version, resource, requirements) = parse_requirements(resp_headers, body_402)?;
    let (req, network) = pick_payment_option(wallet, &requirements)?;
    let (payload_json, payment_info) =
        build_signed_payment(wallet, req, &network, x402_version, resource.as_ref())?;

    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(payload_json.as_bytes());

    let retry = send_request(url, method, req_body, Some(&payload_b64))?;
    let status = retry.status().as_u16();
    let response_body = retry.text().unwrap_or_default();

    Ok(PayResult {
        status,
        body: response_body,
        payment: Some(payment_info),
    })
}

/// Parse payment requirements from response headers (v2 then v1) or body.
fn parse_requirements(
    headers: &reqwest::header::HeaderMap,
    body_text: &str,
) -> Result<(u32, Option<serde_json::Value>, Vec<PaymentRequirements>), Error> {
    for header_name in &["payment-required", "x-payment-required"] {
        if let Some(val) = headers.get(*header_name)
            && let Ok(s) = val.to_str()
            && let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(s)
            && let Ok(parsed) = serde_json::from_slice::<X402Response>(&decoded)
            && !parsed.accepts.is_empty()
        {
            let version = if *header_name == "payment-required" {
                parsed.x402_version.unwrap_or(2)
            } else {
                parsed.x402_version.unwrap_or(1)
            };
            return Ok((version, parsed.resource, parsed.accepts));
        }
    }
    let parsed: X402Response = serde_json::from_str(body_text)
        .map_err(|e| Error::Pay(format!("failed to parse x402 response: {e}")))?;
    if parsed.accepts.is_empty() {
        return Err(Error::Pay("empty accepts in 402 response".into()));
    }
    Ok((
        parsed.x402_version.unwrap_or(1),
        parsed.resource,
        parsed.accepts,
    ))
}

/// Whether a requirement uses the `GatewayWalletBatched` scheme (requires a
/// pre-funded gateway wallet this client does not manage).
fn is_gateway_batched(req: &PaymentRequirements) -> bool {
    req.extra
        .get("name")
        .and_then(|v| v.as_str())
        .is_some_and(|name| name == "GatewayWalletBatched")
}

/// Resolve a network string's [`ChainFamily`].
fn resolve_family(network: &str) -> Option<ChainFamily> {
    let ns = network.split_once(':').map(|(ns, _)| ns)?;
    ChainFamily::from_namespace(ns)
}

/// Parse a string as a u128 amount (for cheapest-option comparison).
fn parsed_amount(req: &PaymentRequirements) -> Option<u128> {
    req.amount.parse().ok()
}

/// Pick the best payment option: first supported network, then cheapest amount.
/// Skips unsupported schemes and `GatewayWalletBatched` offers.
fn pick_payment_option<'a>(
    wallet: &dyn WalletBridge,
    requirements: &'a [PaymentRequirements],
) -> Result<(&'a PaymentRequirements, String), Error> {
    let supported = wallet.supported_families();
    let mut candidates: Vec<(&PaymentRequirements, String)> = Vec::new();

    for req in requirements {
        if !SUPPORTED_SCHEMES.contains(&req.scheme.as_str()) {
            continue;
        }
        if is_gateway_batched(req) {
            continue;
        }
        let Some(family) = resolve_family(&req.network) else {
            continue;
        };
        if !supported.contains(&family) {
            continue;
        }
        let network = crate::chain::resolve_chain(&req.network)
            .map_or_else(|_| req.network.clone(), |c| c.chain_id);
        candidates.push((req, network));
    }

    if let Some((_, first_network)) = candidates.first() {
        let mut best = &candidates[0];
        for candidate in candidates.iter().skip(1) {
            if candidate.1 != *first_network {
                break;
            }
            if parsed_amount(candidate.0)
                .zip(parsed_amount(best.0))
                .is_some_and(|(a, b)| a < b)
            {
                best = candidate;
            }
        }
        return Ok((best.0, best.1.clone()));
    }

    let networks: Vec<_> = requirements.iter().map(|r| r.network.as_str()).collect();
    Err(Error::Pay(format!(
        "no supported chain in 402 response (networks: {networks:?}, wallet supports: {supported:?})"
    )))
}

/// Build a signed payment payload, dispatching on scheme.
fn build_signed_payment(
    wallet: &dyn WalletBridge,
    req: &PaymentRequirements,
    network: &str,
    x402_version: u32,
    resource: Option<&serde_json::Value>,
) -> Result<(String, PaymentInfo), Error> {
    match req.scheme.as_str() {
        "exact" => build_evm_exact(wallet, req, network, x402_version, resource),
        scheme => Err(Error::Pay(format!("unsupported payment scheme: {scheme}"))),
    }
}

/// Build an EVM "exact" (EIP-3009 `TransferWithAuthorization`) payment.
fn build_evm_exact(
    wallet: &dyn WalletBridge,
    req: &PaymentRequirements,
    network: &str,
    x402_version: u32,
    resource: Option<&serde_json::Value>,
) -> Result<(String, PaymentInfo), Error> {
    let address = wallet.address(network)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| Error::Pay(e.to_string()))?
        .as_secs();
    let valid_after = now.saturating_sub(5);
    let valid_before = now + req.max_timeout_seconds;

    let mut nonce_bytes = [0u8; 32];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| Error::Pay(format!("rng: {e}")))?;
    let nonce_hex = format!("0x{}", hex::encode(nonce_bytes));

    let token_name = req
        .extra
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("USD Coin");
    let token_version = req
        .extra
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("2");
    let chain_id_num: u64 = caip2_reference(network)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error::Pay(format!("cannot extract numeric chain ID from: {network}")))?;

    let typed_data = serde_json::json!({
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"}
            ],
            "TransferWithAuthorization": [
                {"name": "from", "type": "address"},
                {"name": "to", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "validAfter", "type": "uint256"},
                {"name": "validBefore", "type": "uint256"},
                {"name": "nonce", "type": "bytes32"}
            ]
        },
        "primaryType": "TransferWithAuthorization",
        "domain": {
            "name": token_name,
            "version": token_version,
            "chainId": chain_id_num.to_string(),
            "verifyingContract": req.asset
        },
        "message": {
            "from": address,
            "to": req.pay_to,
            "value": req.amount,
            "validAfter": valid_after.to_string(),
            "validBefore": valid_before.to_string(),
            "nonce": &nonce_hex
        }
    })
    .to_string();

    let signature = wallet.sign_payload(&req.scheme, network, &typed_data)?;

    let authorization = serde_json::json!({
        "from": address,
        "to": req.pay_to,
        "value": req.amount,
        "validAfter": valid_after.to_string(),
        "validBefore": valid_before.to_string(),
        "nonce": nonce_hex
    });
    let inner = serde_json::json!({
        "signature": signature,
        "authorization": authorization,
    });

    let payload = if x402_version >= 2 {
        serde_json::json!({
            "x402Version": x402_version,
            "accepted": req,
            "resource": resource,
            "payload": inner,
        })
    } else {
        serde_json::json!({
            "x402Version": x402_version,
            "scheme": req.scheme,
            "network": req.network,
            "payload": inner,
        })
    };

    let amount_display = format_usdc(&req.amount);
    let info = PaymentInfo {
        amount: amount_display,
        network: display_name(network).to_owned(),
        token: "USDC".to_owned(),
    };
    Ok((payload.to_string(), info))
}

/// Extract the CAIP-2 reference from a network string (e.g. "eip155:8453" → "8453").
fn caip2_reference(network: &str) -> Option<&str> {
    network.split_once(':').map(|(_, r)| r)
}

/// Human-readable display name for a CAIP-2 network.
fn display_name(network: &str) -> &str {
    crate::chain::resolve_chain(network)
        .ok()
        .map_or(network, |c| match c.name.as_str() {
            "ethereum" => "Ethereum",
            "polygon" => "Polygon",
            "arbitrum" => "Arbitrum",
            "optimism" => "Optimism",
            "base" => "Base",
            "bsc" => "BNB Chain",
            _ => network,
        })
}

/// Format a USDC amount (6-decimal) as a dollar string.
fn format_usdc(amount_str: &str) -> String {
    let amount: u128 = amount_str.parse().unwrap_or(0);
    let whole = amount / 1_000_000;
    let frac = amount % 1_000_000;
    let frac_str = format!("{frac:06}");
    let frac_trimmed = frac_str.trim_end_matches('0');
    let frac_display = if frac_trimmed.is_empty() {
        "00"
    } else {
        frac_trimmed
    };
    format!("${whole}.{frac_display}")
}

/// Truncate a string to `max` chars, appending "..." if truncated.
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

/// Build and send an HTTP request.
fn send_request(
    url: &str,
    method: &str,
    body: Option<&str>,
    payment_header: Option<&str>,
) -> Result<reqwest::blocking::Response, Error> {
    let mut req = match method.to_uppercase().as_str() {
        "GET" => HTTP.get(url),
        "POST" => HTTP.post(url),
        "PUT" => HTTP.put(url),
        "DELETE" => HTTP.delete(url),
        "PATCH" => HTTP.patch(url),
        other => {
            return Err(Error::InvalidInput(format!(
                "unsupported HTTP method: {other}"
            )));
        }
    };
    if let Some(b) = body {
        req = req
            .header("content-type", "application/json")
            .body(b.to_owned());
    }
    if let Some(payment) = payment_header {
        req = req
            .header("X-PAYMENT", payment)
            .header("payment-signature", payment);
    }
    req.send().map_err(Error::from)
}

/// CDP discovery API endpoint.
const CDP_DISCOVERY_URL: &str = "https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources";

/// Known testnet identifiers to filter out.
const TESTNETS: &[&str] = &[
    "base-sepolia",
    "eip155:84532",
    "eip155:11155111",
    "solana-devnet",
];

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
}

/// Result of a `discover()` call.
#[derive(Debug, Clone, Serialize)]
pub struct DiscoverResult {
    /// Discovered services.
    pub services: Vec<Service>,
    /// Total count from the directory.
    pub total: u64,
    /// Limit used.
    pub limit: u64,
    /// Offset used.
    pub offset: u64,
}

#[derive(Debug, Deserialize)]
struct DiscoveryResponse {
    items: Vec<DiscoveredService>,
    #[serde(default)]
    pagination: Option<Pagination>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DiscoveredService {
    resource: String,
    #[serde(default)]
    accepts: Vec<PaymentRequirements>,
    #[serde(default)]
    metadata: Option<ServiceMetadata>,
}

#[derive(Debug, Deserialize)]
struct ServiceMetadata {
    description: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct Pagination {
    total: u64,
}

/// Discover payable services from the x402 directory (blocking).
///
/// When a `query` is provided, paginates through the upstream API to collect
/// matching results (the upstream API does not support server-side filtering).
pub fn discover(
    query: Option<&str>,
    limit: Option<u64>,
    offset: Option<u64>,
) -> Result<DiscoverResult, Error> {
    let page_limit = limit.unwrap_or(100);
    let page_offset = offset.unwrap_or(0);

    if let Some(q) = query {
        return discover_with_query(q, page_limit, page_offset);
    }

    let resp = fetch_discovery_page(page_limit, page_offset)?;
    let services = filter_services(resp.items, None);
    Ok(DiscoverResult {
        services,
        total: resp.total,
        limit: page_limit,
        offset: page_offset,
    })
}

/// Paginate through the directory collecting query-matching services.
fn discover_with_query(query: &str, limit: u64, offset: u64) -> Result<DiscoverResult, Error> {
    const PAGE_SIZE: u64 = 500;
    const MAX_PAGES: u64 = 30;

    let mut collected: Vec<Service> = Vec::new();
    let mut skipped: u64 = 0;
    let mut api_offset: u64 = 0;
    let mut total: u64 = 0;

    for _ in 0..MAX_PAGES {
        let resp = fetch_discovery_page(PAGE_SIZE, api_offset)?;
        total = resp.total;
        let page_len = resp.items.len() as u64;

        for svc in filter_services(resp.items, Some(query)) {
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

/// Intermediate result from a single discovery page fetch.
struct DiscoveryPage {
    items: Vec<DiscoveredService>,
    total: u64,
}

/// Fetch a single page from the CDP discovery API.
fn fetch_discovery_page(limit: u64, offset: u64) -> Result<DiscoveryPage, Error> {
    let url = format!("{CDP_DISCOVERY_URL}?limit={limit}&offset={offset}");
    let resp = HTTP.get(&url).send()?;
    if !resp.status().is_success() {
        return Err(Error::Pay(format!("discovery returned {}", resp.status())));
    }
    let body: DiscoveryResponse = resp
        .json()
        .map_err(|e| Error::Pay(format!("failed to parse discovery: {e}")))?;
    let total = body.pagination.map_or(0, |p| p.total);
    Ok(DiscoveryPage {
        items: body.items,
        total,
    })
}

/// Filter and convert raw discovered services, optionally matching a query.
fn filter_services(items: Vec<DiscoveredService>, query: Option<&str>) -> Vec<Service> {
    let query_lower = query.map(str::to_lowercase);
    let mut services = Vec::new();

    for svc in items {
        let Some(accept) = svc.accepts.first() else {
            continue;
        };
        if TESTNETS.iter().any(|t| accept.network.contains(t)) {
            continue;
        }
        if let Some(ref ql) = query_lower {
            let url_match = svc.resource.to_lowercase().contains(ql);
            let accepts_desc = accept
                .description
                .as_ref()
                .is_some_and(|d| d.to_lowercase().contains(ql));
            let meta_desc = svc
                .metadata
                .as_ref()
                .and_then(|m| m.description.as_ref())
                .is_some_and(|d| d.to_lowercase().contains(ql));
            if !url_match && !accepts_desc && !meta_desc {
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

/// MoonPay API base URL.
const MOONPAY_API: &str = "https://agents.moonpay.com";

/// MoonPay chain mapping (OWX name → MoonPay slug).
const MOONPAY_CHAINS: &[(&str, &str, &str)] = &[
    ("base", "Base", "base"),
    ("ethereum", "Ethereum", "ethereum"),
    ("polygon", "Polygon", "polygon"),
    ("arbitrum", "Arbitrum", "arbitrum"),
    ("optimism", "Optimism", "optimism"),
    ("bsc", "BNB Chain", "bnb"),
    ("bnb", "BNB Chain", "bnb"),
    ("base-sepolia", "Base Sepolia", "base-sepolia"),
    ("solana", "Solana", "solana"),
];

/// Resolve a chain name to the MoonPay (display_name, moonpay_slug) pair.
fn resolve_moonpay_chain(chain: Option<&str>) -> Result<(&'static str, &'static str), Error> {
    match chain {
        Some(name) => {
            let lower = name.to_lowercase();
            MOONPAY_CHAINS
                .iter()
                .find(|(k, _, _)| *k == lower)
                .map(|(_, display, slug)| (*display, *slug))
                .ok_or_else(|| Error::Pay(format!("unknown chain for funding: {name}")))
        }
        None => Ok(("Base", "base")),
    }
}

/// Result of a `fund()` call.
#[derive(Debug, Clone, Serialize)]
pub struct FundResult {
    /// Deposit ID.
    pub deposit_id: String,
    /// Deposit URL for the user to send crypto to.
    pub deposit_url: String,
    /// Available deposit wallets `(chain, address)`.
    pub wallets: Vec<(String, String)>,
    /// User instructions.
    pub instructions: String,
}

/// Create a MoonPay deposit that auto-converts incoming crypto to USDC (blocking).
pub fn fund(
    wallet_address: &str,
    chain: Option<&str>,
    token: Option<&str>,
) -> Result<FundResult, Error> {
    let (display_name, moonpay_slug) = resolve_moonpay_chain(chain)?;
    let token_name = token.unwrap_or("USDC");

    let req_body = serde_json::json!({
        "name": format!("OWX deposit ({token_name} on {display_name})"),
        "wallet": wallet_address,
        "chain": moonpay_slug,
        "token": token_name,
    });

    let resp = HTTP
        .post(format!("{MOONPAY_API}/api/tools/deposit_create"))
        .json(&req_body)
        .send()?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        return Err(Error::Pay(format!("MoonPay returned {status}: {body}")));
    }

    let deposit: MoonPayDeposit = resp
        .json()
        .map_err(|e| Error::Pay(format!("failed to parse MoonPay response: {e}")))?;

    Ok(FundResult {
        deposit_id: deposit.id,
        deposit_url: deposit.deposit_url,
        wallets: deposit
            .wallets
            .iter()
            .map(|w| (w.chain.clone(), w.address.clone()))
            .collect(),
        instructions: deposit.instructions,
    })
}

/// A token balance from MoonPay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBalance {
    /// Token symbol (e.g. "USDC").
    pub token: String,
    /// Balance in human-readable form.
    pub balance: String,
    /// Chain the balance is on.
    pub chain: String,
}

/// Check token balances for a wallet address via MoonPay (blocking).
pub fn get_balances(wallet_address: &str, chain: Option<&str>) -> Result<Vec<TokenBalance>, Error> {
    let (_, moonpay_slug) = resolve_moonpay_chain(chain)?;

    let req_body = serde_json::json!({
        "wallet": wallet_address,
        "chain": moonpay_slug,
    });

    let resp = HTTP
        .post(format!("{MOONPAY_API}/api/tools/token_balance_list"))
        .json(&req_body)
        .send()?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        return Err(Error::Pay(format!(
            "MoonPay balance returned {status}: {body}"
        )));
    }

    let balance_resp: BalanceListResponse = resp
        .json()
        .map_err(|e| Error::Pay(format!("failed to parse balance response: {e}")))?;
    Ok(balance_resp.items)
}

#[derive(Deserialize)]
struct BalanceListResponse {
    items: Vec<TokenBalance>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MoonPayDeposit {
    id: String,
    deposit_url: String,
    wallets: Vec<DepositWallet>,
    instructions: String,
}

#[derive(Deserialize)]
struct DepositWallet {
    address: String,
    chain: String,
}
