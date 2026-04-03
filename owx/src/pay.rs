//! x402 payment protocol (blocking), service discovery, and wallet funding.

#![allow(clippy::missing_docs_in_private_items)]

use std::sync::LazyLock;
use std::time::Duration;

use base64::Engine as _;
use serde::{Deserialize, Serialize};

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
    /// CAIP-2 chain IDs this wallet supports.
    fn supported_chains(&self) -> Vec<String>;
    /// Get the address for a CAIP-2 chain ID.
    fn address(&self, chain_id: &str) -> Result<String, Error>;
    /// Sign EIP-712 typed data for a chain. Returns hex with `0x` prefix.
    fn sign_typed_data(&self, chain_id: &str, payload: &str) -> Result<String, Error>;
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
    let initial = build_request(url, method, body, None)?;
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
#[allow(dead_code)]
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
}

/// Default timeout.
const fn default_timeout() -> u64 {
    30
}

/// Process a 402 response.
fn handle_402(
    wallet: &dyn WalletBridge,
    url: &str,
    method: &str,
    req_body: Option<&str>,
    resp_headers: &reqwest::header::HeaderMap,
    body_402: &str,
) -> Result<PayResult, Error> {
    let (x402_version, requirements) = parse_requirements(resp_headers, body_402)?;
    let (req, network) = pick_option(wallet, &requirements)?;
    let (payload_json, payment_info) = build_evm_exact(wallet, req, &network, x402_version)?;

    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(payload_json.as_bytes());

    let retry = build_request_with_payment(url, method, req_body, &payload_b64)?;
    let status = retry.status().as_u16();
    let response_body = retry.text().unwrap_or_default();

    Ok(PayResult {
        status,
        body: response_body,
        payment: Some(payment_info),
    })
}

/// Parse payment requirements from response headers or body.
fn parse_requirements(
    headers: &reqwest::header::HeaderMap,
    body_text: &str,
) -> Result<(u32, Vec<PaymentRequirements>), Error> {
    use base64::Engine as _;
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
            return Ok((version, parsed.accepts));
        }
    }
    let parsed: X402Response = serde_json::from_str(body_text)
        .map_err(|e| Error::Pay(format!("failed to parse x402 response: {e}")))?;
    if parsed.accepts.is_empty() {
        return Err(Error::Pay("empty accepts in 402 response".into()));
    }
    Ok((parsed.x402_version.unwrap_or(1), parsed.accepts))
}

/// Select the first compatible payment option.
fn pick_option<'a>(
    wallet: &dyn WalletBridge,
    requirements: &'a [PaymentRequirements],
) -> Result<(&'a PaymentRequirements, String), Error> {
    let supported = wallet.supported_chains();
    for req in requirements {
        if req.scheme != "exact" {
            continue;
        }
        if supported.iter().any(|s| s == &req.network) {
            return Ok((req, req.network.clone()));
        }
    }
    Err(Error::Pay(format!(
        "no supported chain in 402 response (wallet supports: {supported:?})"
    )))
}

/// Build an EVM "exact" (EIP-3009) payment.
fn build_evm_exact(
    wallet: &dyn WalletBridge,
    req: &PaymentRequirements,
    network: &str,
    _x402_version: u32,
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
    let chain_id_num: u64 = network
        .strip_prefix("eip155:")
        .and_then(|r| r.parse().ok())
        .ok_or_else(|| Error::Pay(format!("cannot extract chain ID from: {network}")))?;

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

    let signature = wallet.sign_typed_data(network, &typed_data)?;

    let payload = serde_json::json!({
        "x402Version": 1,
        "scheme": "exact",
        "network": network,
        "payload": {
            "signature": signature,
            "authorization": {
                "from": address,
                "to": req.pay_to,
                "value": req.amount,
                "validAfter": valid_after.to_string(),
                "validBefore": valid_before.to_string(),
                "nonce": nonce_hex
            }
        }
    });

    let amount_display = format_usdc(&req.amount);
    let info = PaymentInfo {
        amount: amount_display,
        network: network.to_owned(),
        token: "USDC".to_owned(),
    };
    Ok((payload.to_string(), info))
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

/// Build an HTTP request.
fn build_request(
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

/// Build request with payment header.
fn build_request_with_payment(
    url: &str,
    method: &str,
    body: Option<&str>,
    payment_b64: &str,
) -> Result<reqwest::blocking::Response, Error> {
    build_request(url, method, body, Some(payment_b64))
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
    /// Total count.
    pub total: u64,
    /// Limit used.
    pub limit: u64,
    /// Offset used.
    pub offset: u64,
}

/// Wire types for discovery API.
#[derive(Debug, Deserialize)]
struct DiscoveryResponse {
    items: Vec<DiscoveredService>,
    #[serde(default)]
    pagination: Option<Pagination>,
}

/// A discovered service wire type.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DiscoveredService {
    resource: String,
    #[serde(default)]
    accepts: Vec<PaymentRequirements>,
    #[serde(default)]
    metadata: Option<ServiceMetadata>,
}

/// Service metadata.
#[derive(Debug, Deserialize)]
struct ServiceMetadata {
    description: Option<String>,
}

/// Pagination info.
#[derive(Debug, Clone, Copy, Deserialize)]
struct Pagination {
    total: u64,
}

/// Discover payable services from the x402 directory (blocking).
pub fn discover(
    query: Option<&str>,
    limit: Option<u64>,
    offset: Option<u64>,
) -> Result<DiscoverResult, Error> {
    let page_limit = limit.unwrap_or(100);
    let page_offset = offset.unwrap_or(0);

    let url = format!("{CDP_DISCOVERY_URL}?limit={page_limit}&offset={page_offset}");
    let resp = HTTP.get(&url).send()?;
    if !resp.status().is_success() {
        return Err(Error::Pay(format!("discovery returned {}", resp.status())));
    }
    let text = resp.text().unwrap_or_default();
    let body: DiscoveryResponse = serde_json::from_str(&text)
        .map_err(|e| Error::Pay(format!("failed to parse discovery: {e}")))?;

    let total = body.pagination.map_or(0, |p| p.total);
    let query_lower = query.map(str::to_lowercase);
    let mut services = Vec::new();

    for svc in body.items {
        let Some(accept) = svc.accepts.first() else {
            continue;
        };
        if TESTNETS.iter().any(|t| accept.network.contains(t)) {
            continue;
        }

        if let Some(ref q) = query_lower {
            let url_match = svc.resource.to_lowercase().contains(q);
            let desc_match = svc
                .metadata
                .as_ref()
                .and_then(|m| m.description.as_ref())
                .is_some_and(|d| d.to_lowercase().contains(q));
            if !url_match && !desc_match {
                continue;
            }
        }

        let desc = svc
            .metadata
            .as_ref()
            .and_then(|m| m.description.as_deref())
            .unwrap_or("");

        services.push(Service {
            name: svc.resource.clone(),
            url: svc.resource,
            description: desc.to_owned(),
            price: format_usdc(&accept.amount),
            network: accept.network.clone(),
        });
    }

    Ok(DiscoverResult {
        services,
        total,
        limit: page_limit,
        offset: page_offset,
    })
}

/// MoonPay API base URL.
const MOONPAY_API: &str = "https://agents.moonpay.com";

/// Result of `fund()` call.
#[derive(Debug, Clone, Serialize)]
pub struct FundResult {
    /// Deposit ID.
    pub deposit_id: String,
    /// Deposit URL.
    pub deposit_url: String,
    /// Available deposit wallets (chain, address).
    pub wallets: Vec<(String, String)>,
    /// User instructions.
    pub instructions: String,
}

/// Create a MoonPay deposit (blocking).
pub fn fund(
    wallet_address: &str,
    chain: Option<&str>,
    token: Option<&str>,
) -> Result<FundResult, Error> {
    let chain_name = match chain.map(str::to_lowercase).as_deref() {
        Some("ethereum" | "eip155:1") => "ethereum",
        Some("polygon" | "eip155:137") => "polygon",
        Some("arbitrum" | "eip155:42161") => "arbitrum",
        Some("optimism" | "eip155:10") => "optimism",
        Some("solana") => "solana",
        _ => "base",
    };
    let token_name = token.unwrap_or("USDC");

    let req_body = serde_json::json!({
        "name": format!("OWX deposit ({token_name} on {chain_name})"),
        "wallet": wallet_address,
        "chain": chain_name,
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

/// MoonPay deposit response.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MoonPayDeposit {
    id: String,
    deposit_url: String,
    wallets: Vec<DepositWallet>,
    instructions: String,
}

/// A deposit wallet from MoonPay.
#[derive(Deserialize)]
struct DepositWallet {
    address: String,
    chain: String,
}
