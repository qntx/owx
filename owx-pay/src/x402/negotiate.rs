//! x402 protocol negotiation — parsing 402 responses and building payment payloads.

use base64::Engine as _;

use super::eip3009;
use super::types::{PayResult, PaymentInfo, PaymentRequirements, X402Response};
use crate::bridge::WalletBridge;
use crate::error::{PayError, PayErrorCode};
use crate::http::client;

/// Parse payment requirements from a 402 response (headers or body).
pub(super) fn parse_requirements(
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

/// Handle a 402 response: negotiate payment, sign, and retry the original request.
pub(super) fn handle_402(
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

    let authorization = build_authorization(wallet, req)?;
    let payload = build_payment_payload(version, &x402_resp, req, &authorization);

    let payload_json = serde_json::to_string(&payload)?;
    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(payload_json.as_bytes());

    let retry = send_request(url, method, req_body, Some(&payload_b64))?;
    let status = retry.status().as_u16();
    let response_body = retry.text().unwrap_or_default();

    let token_symbol = req
        .extra
        .get("symbol")
        .and_then(|v| v.as_str())
        .unwrap_or("USDC")
        .to_owned();

    let decimals = req
        .extra
        .get("decimals")
        .and_then(serde_json::Value::as_u64)
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(6);

    Ok(PayResult {
        status,
        body: response_body,
        payment: Some(PaymentInfo {
            amount: format!("${}", format_amount(&req.amount, decimals)),
            network: display_network(&req.network),
            token: token_symbol,
        }),
    })
}

/// Build the EIP-3009 authorization payload and sign it via the wallet bridge.
fn build_authorization(
    wallet: &dyn WalletBridge,
    req: &PaymentRequirements,
) -> Result<serde_json::Value, PayError> {
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

    let valid_after_hex = format!("0x{valid_after:064x}");
    let valid_before_hex = format!("0x{valid_before:064x}");

    let typed_data = eip3009::build_typed_data(
        token_name,
        token_version,
        chain_id_num,
        &req.asset,
        &account_address,
        &req.pay_to,
        &req.amount,
        &valid_after_hex,
        &valid_before_hex,
        &nonce_hex,
    );

    let sig = wallet
        .sign_payload("exact", &req.network, &typed_data)
        .map_err(|e| PayError::new(PayErrorCode::SigningFailed, e.to_string()))?;

    Ok(serde_json::json!({
        "signature": sig,
        "authorization": {
            "from": account_address,
            "to": req.pay_to,
            "value": req.amount,
            "validAfter": valid_after_hex,
            "validBefore": valid_before_hex,
            "nonce": nonce_hex,
        },
    }))
}

/// Assemble the x402 payment payload (v1 or v2 format).
fn build_payment_payload(
    version: u32,
    x402_resp: &X402Response,
    req: &PaymentRequirements,
    inner_payload: &serde_json::Value,
) -> serde_json::Value {
    if version >= 2 {
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
    }
}

/// Format a raw integer amount with the given decimal precision.
fn format_amount(raw: &str, decimals: u32) -> String {
    let n: u128 = raw.parse().unwrap_or(0);
    let divisor = 10u128.pow(decimals);
    let whole = n / divisor;
    let frac = n % divisor;
    format!("{whole}.{frac:0>width$}", width = decimals as usize)
}

/// Map a CAIP-2 network ID to a human-readable name.
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

/// Send an HTTP request with an optional x402 payment header.
pub(super) fn send_request(
    url: &str,
    method: &str,
    body: Option<&str>,
    payment_header: Option<&str>,
) -> Result<reqwest::blocking::Response, PayError> {
    let upper = method.to_uppercase();
    let http = client()?;
    let mut req = match upper.as_str() {
        "GET" => http.get(url),
        "POST" => http.post(url),
        "PUT" => http.put(url),
        "DELETE" => http.delete(url),
        "PATCH" => http.patch(url),
        "HEAD" => http.head(url),
        _ => {
            return Err(PayError::new(
                PayErrorCode::HttpStatus,
                format!("unsupported HTTP method: {method}"),
            ));
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_amount_usdc() {
        assert_eq!(format_amount("1000000", 6), "1.000000");
        assert_eq!(format_amount("10000", 6), "0.010000");
        assert_eq!(format_amount("0", 6), "0.000000");
    }

    #[test]
    fn display_network_known() {
        assert_eq!(display_network("eip155:8453"), "Base");
        assert_eq!(display_network("eip155:1"), "Ethereum");
    }

    #[test]
    fn display_network_unknown_passthrough() {
        assert_eq!(display_network("eip155:999"), "eip155:999");
    }
}
