//! x402 payment protocol flow.
//!
//! Detects 402 responses, parses payment requirements, delegates signing
//! to the [`WalletBridge`], and retries with the signed payment header.
//! Supports both x402 v1 and v2 protocols.

use base64::{Engine, engine::general_purpose::STANDARD as B64};

use crate::error::PayError;
use crate::types::{
    Eip3009Authorization, Eip3009Payload, PayResult, PaymentInfo, PaymentPayload, PaymentPayloadV1,
    PaymentPayloadV2, PaymentRequirements, X402Response,
};
use crate::wallet::WalletBridge;

/// Legacy payment header name.
const HEADER_PAYMENT: &str = "X-PAYMENT";
/// V2 payment header name.
const HEADER_PAYMENT_V2: &str = "payment-signature";
/// Legacy payment-required header.
const HEADER_PAYMENT_REQUIRED: &str = "x-payment-required";
/// V2 payment-required header.
const HEADER_PAYMENT_REQUIRED_V2: &str = "payment-required";

/// Make an HTTP request with automatic x402 payment handling.
///
/// 1. Fires the initial request.
/// 2. If 402, parses requirements, signs payment, retries.
/// 3. Returns the final response.
pub async fn pay(
    wallet: &dyn WalletBridge,
    url: &str,
    method: &str,
    body: Option<&str>,
) -> Result<PayResult, PayError> {
    let client = reqwest::Client::new();

    let initial = build_request(&client, url, method, body, None)?
        .send()
        .await?;

    if initial.status().as_u16() != 402 {
        let status = initial.status().as_u16();
        let text = initial.text().await.unwrap_or_default();
        return Ok(PayResult {
            status,
            body: text,
            payment: None,
        });
    }

    let headers = initial.headers().clone();
    let body_402 = initial.text().await.unwrap_or_default();

    handle_402(wallet, url, method, body, &headers, &body_402).await
}

/// Process a 402 response: parse requirements, sign, retry.
async fn handle_402(
    wallet: &dyn WalletBridge,
    url: &str,
    method: &str,
    req_body: Option<&str>,
    resp_headers: &reqwest::header::HeaderMap,
    body_402: &str,
) -> Result<PayResult, PayError> {
    let (x402_version, resource, requirements) = parse_requirements(resp_headers, body_402)?;
    let (req, network) = pick_option(wallet, &requirements)?;

    let (payload, payment_info) =
        build_signed_payment(wallet, req, &network, x402_version, resource)?;

    let payload_json = serde_json::to_string(&payload)?;
    let payload_b64 = B64.encode(payload_json.as_bytes());

    let client = reqwest::Client::new();
    let retry = build_request(&client, url, method, req_body, Some(&payload_b64))?
        .send()
        .await?;

    let status = retry.status().as_u16();
    let response_body = retry.text().await.unwrap_or_default();

    Ok(PayResult {
        status,
        body: response_body,
        payment: Some(payment_info),
    })
}

/// Build a signed payment payload, dispatching on the scheme.
fn build_signed_payment(
    wallet: &dyn WalletBridge,
    req: &PaymentRequirements,
    network: &str,
    x402_version: u32,
    resource: Option<serde_json::Value>,
) -> Result<(PaymentPayload, PaymentInfo), PayError> {
    match req.scheme.as_str() {
        "exact" => build_evm_exact(wallet, req, network, x402_version, resource),
        scheme => Err(PayError::Unsupported(format!(
            "unsupported payment scheme: {scheme}"
        ))),
    }
}

/// Build an EVM "exact" (EIP-3009 TransferWithAuthorization) payment.
fn build_evm_exact(
    wallet: &dyn WalletBridge,
    req: &PaymentRequirements,
    network: &str,
    x402_version: u32,
    resource: Option<serde_json::Value>,
) -> Result<(PaymentPayload, PaymentInfo), PayError> {
    let address = wallet.address(network)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| PayError::InvalidInput(e.to_string()))?
        .as_secs();
    let valid_after = now.saturating_sub(5);
    let valid_before = now + req.max_timeout_seconds;

    let mut nonce_bytes = [0u8; 32];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| PayError::SigningFailed(format!("rng: {e}")))?;
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

    let chain_id_num: u64 = extract_evm_chain_id(network).ok_or_else(|| {
        PayError::ProtocolMalformed(format!("cannot extract numeric chain ID from: {network}"))
    })?;

    let typed_data_json = serde_json::json!({
        "types": {
            "EIP712Domain": [
                { "name": "name", "type": "string" },
                { "name": "version", "type": "string" },
                { "name": "chainId", "type": "uint256" },
                { "name": "verifyingContract", "type": "address" }
            ],
            "TransferWithAuthorization": [
                { "name": "from", "type": "address" },
                { "name": "to", "type": "address" },
                { "name": "value", "type": "uint256" },
                { "name": "validAfter", "type": "uint256" },
                { "name": "validBefore", "type": "uint256" },
                { "name": "nonce", "type": "bytes32" }
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

    let signature = wallet.sign_typed_data(network, &typed_data_json)?;

    let eip3009 = Eip3009Payload {
        signature,
        authorization: Eip3009Authorization {
            from: address,
            to: req.pay_to.clone(),
            value: req.amount.clone(),
            valid_after: valid_after.to_string(),
            valid_before: valid_before.to_string(),
            nonce: nonce_hex,
        },
    };

    let inner = serde_json::to_value(&eip3009)?;
    let payload = if x402_version >= 2 {
        PaymentPayload::V2(PaymentPayloadV2 {
            x402_version,
            accepted: req.clone(),
            resource,
            payload: inner,
        })
    } else {
        PaymentPayload::V1(PaymentPayloadV1 {
            x402_version,
            scheme: req.scheme.clone(),
            network: network.to_owned(),
            payload: inner,
        })
    };

    let amount_display = format_usdc(&req.amount);
    let payment_info = PaymentInfo {
        amount: amount_display,
        network: network.to_owned(),
        token: "USDC".to_owned(),
    };

    Ok((payload, payment_info))
}

/// Parse payment requirements from response headers or body.
///
/// Returns `(x402_version, resource, requirements)`.
fn parse_requirements(
    headers: &reqwest::header::HeaderMap,
    body_text: &str,
) -> Result<(u32, Option<serde_json::Value>, Vec<PaymentRequirements>), PayError> {
    for header_name in &[HEADER_PAYMENT_REQUIRED_V2, HEADER_PAYMENT_REQUIRED] {
        if let Some(val) = headers.get(*header_name)
            && let Ok(s) = val.to_str()
            && let Ok(decoded) = B64.decode(s)
            && let Ok(parsed) = serde_json::from_slice::<X402Response>(&decoded)
            && !parsed.accepts.is_empty()
        {
            let version = match *header_name {
                HEADER_PAYMENT_REQUIRED_V2 => parsed.x402_version.unwrap_or(2),
                _ => parsed.x402_version.unwrap_or(1),
            };
            return Ok((version, parsed.resource, parsed.accepts));
        }
    }

    let parsed: X402Response = serde_json::from_str(body_text)
        .map_err(|e| PayError::ProtocolMalformed(format!("failed to parse x402 response: {e}")))?;

    if parsed.accepts.is_empty() {
        return Err(PayError::ProtocolMalformed("empty accepts".into()));
    }

    Ok((
        parsed.x402_version.unwrap_or(1),
        parsed.resource,
        parsed.accepts,
    ))
}

/// Select the first compatible payment option from requirements.
fn pick_option<'a>(
    wallet: &dyn WalletBridge,
    requirements: &'a [PaymentRequirements],
) -> Result<(&'a PaymentRequirements, String), PayError> {
    let supported = wallet.supported_chains();

    for req in requirements {
        if req.scheme != "exact" {
            continue;
        }
        let chain_id = &req.network;
        if supported.iter().any(|s| s == chain_id) {
            return Ok((req, chain_id.clone()));
        }
    }

    Err(PayError::Unsupported(format!(
        "no supported chain in 402 response (wallet supports: {supported:?})"
    )))
}

/// Extract the numeric EVM chain ID from a CAIP-2 string (e.g. `eip155:8453` → `8453`).
fn extract_evm_chain_id(caip2: &str) -> Option<u64> {
    let reference = caip2.strip_prefix("eip155:")?;
    reference.parse().ok()
}

/// Build an HTTP request with optional payment header.
pub(crate) fn build_request(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    body: Option<&str>,
    payment_header: Option<&str>,
) -> Result<reqwest::RequestBuilder, PayError> {
    let mut req = match method.to_uppercase().as_str() {
        "GET" => client.get(url),
        "POST" => client.post(url),
        "PUT" => client.put(url),
        "DELETE" => client.delete(url),
        "PATCH" => client.patch(url),
        other => {
            return Err(PayError::InvalidInput(format!(
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
            .header(HEADER_PAYMENT, payment)
            .header(HEADER_PAYMENT_V2, payment);
    }

    Ok(req)
}

/// Format a USDC amount (6-decimal smallest unit) as a human-readable dollar string.
pub(crate) fn format_usdc(amount_str: &str) -> String {
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn extract_evm_chain_id_works() {
        assert_eq!(extract_evm_chain_id("eip155:8453"), Some(8453));
        assert_eq!(extract_evm_chain_id("eip155:1"), Some(1));
        assert_eq!(extract_evm_chain_id("solana:mainnet"), None);
    }

    #[test]
    fn format_usdc_cases() {
        assert_eq!(format_usdc("0"), "$0.00");
        assert_eq!(format_usdc("10000"), "$0.01");
        assert_eq!(format_usdc("1000000"), "$1.00");
        assert_eq!(format_usdc("1500000"), "$1.5");
    }

    #[test]
    fn parse_requirements_from_body() {
        let headers = reqwest::header::HeaderMap::new();
        let body = serde_json::json!({
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "10000",
                "asset": "0xUSDC",
                "payTo": "0xabc"
            }]
        })
        .to_string();

        let (version, _, reqs) = parse_requirements(&headers, &body).unwrap();
        assert_eq!(version, 1);
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].scheme, "exact");
    }

    #[test]
    fn parse_requirements_from_v2_header() {
        let x402 = serde_json::json!({
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "5000",
                "asset": "0xUSDC",
                "payTo": "0xv2"
            }]
        });
        let encoded = B64.encode(serde_json::to_string(&x402).unwrap().as_bytes());
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("payment-required", encoded.parse().unwrap());

        let (version, _, reqs) = parse_requirements(&headers, "not json").unwrap();
        assert_eq!(version, 2);
        assert_eq!(reqs[0].pay_to, "0xv2");
    }

    #[test]
    fn build_request_valid_methods() {
        let client = reqwest::Client::new();
        for method in &["GET", "POST", "PUT", "DELETE", "PATCH"] {
            assert!(build_request(&client, "https://example.com", method, None, None).is_ok());
        }
    }

    #[test]
    fn build_request_invalid_method() {
        let client = reqwest::Client::new();
        assert!(build_request(&client, "https://example.com", "FOOBAR", None, None).is_err());
    }
}
