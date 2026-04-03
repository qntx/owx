//! RPC broadcast via `reqwest::blocking` (replaces curl subprocess).

use owx_core::ChainType;

use crate::error::OwxError;

/// POST JSON to an RPC endpoint, return the response body.
fn post_json(url: &str, body: &serde_json::Value) -> Result<String, OwxError> {
    let resp = reqwest::blocking::Client::new()
        .post(url)
        .json(body)
        .send()
        .map_err(|e| OwxError::BroadcastFailed(format!("HTTP: {e}")))?;
    if !resp.status().is_success() {
        return Err(OwxError::BroadcastFailed(format!("HTTP {}", resp.status())));
    }
    resp.text()
        .map_err(|e| OwxError::BroadcastFailed(format!("read body: {e}")))
}

/// POST plain text to an endpoint, return the trimmed response body.
fn post_text(url: &str, body: &str) -> Result<String, OwxError> {
    let resp = reqwest::blocking::Client::new()
        .post(url)
        .header("Content-Type", "text/plain")
        .body(body.to_owned())
        .send()
        .map_err(|e| OwxError::BroadcastFailed(format!("HTTP: {e}")))?;
    if !resp.status().is_success() {
        return Err(OwxError::BroadcastFailed(format!("HTTP {}", resp.status())));
    }
    resp.text()
        .map_err(|e| OwxError::BroadcastFailed(format!("read body: {e}")))
        .map(|s| s.trim().to_owned())
}

/// Extract a string field from a JSON-RPC response.
fn extract_json_field(json_str: &str, field: &str) -> Result<String, OwxError> {
    let parsed: serde_json::Value = serde_json::from_str(json_str)?;
    if let Some(error) = parsed.get("error") {
        return Err(OwxError::BroadcastFailed(format!("RPC error: {error}")));
    }
    parsed[field]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| OwxError::BroadcastFailed(format!("no '{field}' in response")))
}

/// Broadcast a signed transaction payload to the appropriate RPC endpoint.
///
/// For EVM, `payload` must be the RLP-encoded signed transaction.
/// For other chains, `payload` is the raw signature / signed-tx bytes from the signer.
pub fn broadcast(ct: ChainType, rpc_url: &str, payload: &[u8]) -> Result<String, OwxError> {
    match ct {
        ChainType::Evm => {
            let hex_tx = format!("0x{}", hex::encode(payload));
            let body = serde_json::json!({
                "jsonrpc": "2.0", "method": "eth_sendRawTransaction",
                "params": [hex_tx], "id": 1
            });
            let resp = post_json(rpc_url, &body)?;
            extract_json_field(&resp, "result")
        }
        ChainType::Solana => {
            use base64::Engine as _;
            let b64 = base64::engine::general_purpose::STANDARD.encode(payload);
            let body = serde_json::json!({
                "jsonrpc": "2.0", "method": "sendTransaction",
                "params": [b64, {"encoding": "base64"}], "id": 1
            });
            let resp = post_json(rpc_url, &body)?;
            extract_json_field(&resp, "result")
        }
        ChainType::Bitcoin => {
            let url = format!("{}/tx", rpc_url.trim_end_matches('/'));
            let resp = post_text(&url, &hex::encode(payload))?;
            if resp.is_empty() {
                return Err(OwxError::BroadcastFailed("empty response".into()));
            }
            Ok(resp)
        }
        ChainType::Cosmos => {
            use base64::Engine as _;
            let b64 = base64::engine::general_purpose::STANDARD.encode(payload);
            let url = format!("{}/cosmos/tx/v1beta1/txs", rpc_url.trim_end_matches('/'));
            let body = serde_json::json!({"tx_bytes": b64, "mode": "BROADCAST_MODE_SYNC"});
            let resp = post_json(&url, &body)?;
            let parsed: serde_json::Value = serde_json::from_str(&resp)?;
            parsed["tx_response"]["txhash"]
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| OwxError::BroadcastFailed(format!("no txhash: {resp}")))
        }
        ChainType::Tron => {
            let url = format!("{}/wallet/broadcasthex", rpc_url.trim_end_matches('/'));
            let body = serde_json::json!({"transaction": hex::encode(payload)});
            let resp = post_json(&url, &body)?;
            extract_json_field(&resp, "txid")
        }
        ChainType::Ton => {
            use base64::Engine as _;
            let b64 = base64::engine::general_purpose::STANDARD.encode(payload);
            let url = format!("{}/sendBoc", rpc_url.trim_end_matches('/'));
            let body = serde_json::json!({"boc": b64});
            let resp = post_json(&url, &body)?;
            let parsed: serde_json::Value = serde_json::from_str(&resp)?;
            parsed["result"]["hash"]
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| OwxError::BroadcastFailed(format!("no hash: {resp}")))
        }
        _ => Err(OwxError::BroadcastFailed(format!(
            "broadcast not yet supported for {ct}"
        ))),
    }
}

/// Resolve the RPC URL: explicit > user config > built-in default.
pub fn resolve_rpc(
    chain_id: &str,
    ct: ChainType,
    explicit: Option<&str>,
) -> Result<String, OwxError> {
    if let Some(url) = explicit {
        return Ok(url.to_owned());
    }
    let config = owx_vault::Config::load_or_default();
    if let Some(url) = config.rpc_url(chain_id) {
        return Ok(url.to_owned());
    }
    let defaults = owx_vault::Config::default_rpc();
    if let Some(url) = defaults.get(chain_id) {
        return Ok(url.clone());
    }
    let ns = ct.namespace();
    for (k, v) in &config.rpc {
        if k.starts_with(ns) {
            return Ok(v.clone());
        }
    }
    for (k, v) in &defaults {
        if k.starts_with(ns) {
            return Ok(v.clone());
        }
    }
    Err(OwxError::InvalidInput(format!(
        "no RPC URL for chain '{chain_id}'"
    )))
}
