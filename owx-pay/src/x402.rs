//! x402 payment protocol implementation (blocking).

use std::sync::LazyLock;
use std::time::Duration;

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::bridge::WalletBridge;
use crate::error::{PayError, PayErrorCode};

static HTTP: LazyLock<reqwest::blocking::Client> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("failed to build HTTP client")
});

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

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct X402Response {
    #[serde(default)]
    x402_version: Option<u32>,
    accepts: Vec<PaymentRequirements>,
    #[serde(default)]
    resource: Option<serde_json::Value>,
}

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
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    extra: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<String>,
}

const fn default_timeout() -> u64 {
    30
}

/// Make an HTTP request with automatic x402 payment handling.
pub fn pay(
    wallet: &dyn WalletBridge,
    url: &str,
    method: &str,
    body: Option<&str>,
) -> Result<PayResult, PayError> {
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

fn send_request(
    url: &str,
    method: &str,
    body: Option<&str>,
    payment_header: Option<&str>,
) -> Result<reqwest::blocking::Response, PayError> {
    let mut req = match method.to_uppercase().as_str() {
        "POST" => HTTP.post(url),
        "PUT" => HTTP.put(url),
        "DELETE" => HTTP.delete(url),
        "PATCH" => HTTP.patch(url),
        _ => HTTP.get(url),
    };
    if let Some(b) = body {
        req = req
            .header("Content-Type", "application/json")
            .body(b.to_owned());
    }
    if let Some(ph) = payment_header {
        req = req.header("X-PAYMENT", ph);
    }
    Ok(req.send()?)
}

fn handle_402(
    wallet: &dyn WalletBridge,
    url: &str,
    method: &str,
    req_body: Option<&str>,
    resp_headers: &reqwest::header::HeaderMap,
    body_402: &str,
) -> Result<PayResult, PayError> {
    let x402_resp = parse_requirements(resp_headers, body_402)?;
    let version = x402_resp.x402_version.unwrap_or(1);

    let families = wallet.supported_families();
    let req = x402_resp
        .accepts
        .iter()
        .find(|r| {
            r.scheme == "exact"
                && families
                    .iter()
                    .any(|f| r.network.starts_with(f.namespace()))
        })
        .ok_or_else(|| {
            PayError::new(
                PayErrorCode::NoPaymentOption,
                "no compatible payment option",
            )
        })?;

    let account_address = wallet
        .address(&req.network)
        .map_err(|e| PayError::new(PayErrorCode::SigningFailed, e.to_string()))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let valid_after = now.saturating_sub(5);
    let valid_before = now + req.max_timeout_seconds;

    let mut nonce_bytes = [0u8; 32];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| PayError::new(PayErrorCode::SigningFailed, format!("rng: {e}")))?;
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
    let chain_id_num = req.network.split(':').nth(1).unwrap_or("8453");

    let typed_data = build_eip3009_typed_data(
        token_name,
        token_version,
        chain_id_num,
        &req.asset,
        &account_address,
        &req.pay_to,
        &req.amount,
        &format!("0x{valid_after:064x}"),
        &format!("0x{valid_before:064x}"),
        &nonce_hex,
    );

    let sig = wallet
        .sign_payload("exact", &req.network, &typed_data)
        .map_err(|e| PayError::new(PayErrorCode::SigningFailed, e.to_string()))?;

    let authorization = serde_json::json!({
        "from": account_address,
        "to": req.pay_to,
        "value": req.amount,
        "validAfter": format!("0x{valid_after:064x}"),
        "validBefore": format!("0x{valid_before:064x}"),
        "nonce": nonce_hex,
    });

    let inner_payload = serde_json::json!({
        "signature": sig,
        "authorization": authorization,
    });

    let payment_payload = if version >= 2 {
        serde_json::json!({
            "x402Version": version,
            "accepted": req,
            "resource": x402_resp.resource,
            "payload": inner_payload,
        })
    } else {
        serde_json::json!({
            "x402Version": 1,
            "scheme": "exact",
            "network": req.network,
            "payload": inner_payload,
        })
    };

    let payload_json = serde_json::to_string(&payment_payload)?;
    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(payload_json.as_bytes());

    let retry = send_request(url, method, req_body, Some(&payload_b64))?;
    let status = retry.status().as_u16();
    let response_body = retry.text().unwrap_or_default();

    let amount_decimal = format_amount(&req.amount, 6);

    Ok(PayResult {
        status,
        body: response_body,
        payment: Some(PaymentInfo {
            amount: format!("${amount_decimal}"),
            network: display_network(&req.network),
            token: "USDC".to_owned(),
        }),
    })
}

fn parse_requirements(
    headers: &reqwest::header::HeaderMap,
    body: &str,
) -> Result<X402Response, PayError> {
    if let Some(hdr) = headers
        .get("x-payment-required")
        .or_else(|| headers.get("payment-required"))
    {
        let hdr_str = hdr
            .to_str()
            .map_err(|e| PayError::new(PayErrorCode::ProtocolUnknown, e.to_string()))?;
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(hdr_str)
            && let Ok(resp) = serde_json::from_slice::<X402Response>(&decoded)
        {
            return Ok(resp);
        }
        if let Ok(resp) = serde_json::from_str::<X402Response>(hdr_str) {
            return Ok(resp);
        }
    }
    serde_json::from_str::<X402Response>(body).map_err(|e| {
        PayError::new(
            PayErrorCode::ProtocolUnknown,
            format!("cannot parse 402 response: {e}"),
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn build_eip3009_typed_data(
    token_name: &str,
    token_version: &str,
    chain_id: &str,
    verifying_contract: &str,
    from: &str,
    to: &str,
    value: &str,
    valid_after: &str,
    valid_before: &str,
    nonce: &str,
) -> String {
    serde_json::json!({
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
            "chainId": chain_id,
            "verifyingContract": verifying_contract
        },
        "message": {
            "from": from, "to": to, "value": value,
            "validAfter": valid_after, "validBefore": valid_before, "nonce": nonce
        }
    })
    .to_string()
}

fn format_amount(raw: &str, decimals: u32) -> String {
    let n: u128 = raw.parse().unwrap_or(0);
    let divisor = 10u128.pow(decimals);
    let whole = n / divisor;
    let frac = n % divisor;
    format!("{whole}.{frac:0>width$}", width = decimals as usize)
}

fn display_network(network: &str) -> String {
    match network {
        "eip155:8453" => "Base".to_owned(),
        "eip155:1" => "Ethereum".to_owned(),
        "eip155:137" => "Polygon".to_owned(),
        "eip155:42161" => "Arbitrum".to_owned(),
        "eip155:10" => "Optimism".to_owned(),
        other => other.to_owned(),
    }
}
