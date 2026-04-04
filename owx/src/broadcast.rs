//! Transaction broadcast via `reqwest::blocking` with shared client and timeout.

use std::sync::LazyLock;
use std::time::Duration;

use crate::chain::ChainFamily;
use crate::config::Config;
use crate::error::Error;

/// Default HTTP timeout for RPC requests.
const RPC_TIMEOUT: Duration = Duration::from_secs(30);

/// Shared HTTP client with connection pooling and timeout.
static HTTP: LazyLock<reqwest::blocking::Client> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    reqwest::blocking::Client::builder()
        .timeout(RPC_TIMEOUT)
        .build()
        .expect("failed to build HTTP client")
});

/// POST JSON to an RPC endpoint, return the response body.
fn post_json(url: &str, body: &serde_json::Value) -> Result<String, Error> {
    let resp = HTTP
        .post(url)
        .json(body)
        .send()
        .map_err(|e| Error::BroadcastFailed(format!("HTTP: {e}")))?;
    if !resp.status().is_success() {
        return Err(Error::BroadcastFailed(format!("HTTP {}", resp.status())));
    }
    resp.text()
        .map_err(|e| Error::BroadcastFailed(format!("read body: {e}")))
}

/// POST plain text to an endpoint, return the trimmed response body.
fn post_text(url: &str, body: &str) -> Result<String, Error> {
    let resp = HTTP
        .post(url)
        .header("Content-Type", "text/plain")
        .body(body.to_owned())
        .send()
        .map_err(|e| Error::BroadcastFailed(format!("HTTP: {e}")))?;
    if !resp.status().is_success() {
        return Err(Error::BroadcastFailed(format!("HTTP {}", resp.status())));
    }
    resp.text()
        .map_err(|e| Error::BroadcastFailed(format!("read body: {e}")))
        .map(|s| s.trim().to_owned())
}

/// Extract a string field from a JSON-RPC response.
fn extract_json_field(json_str: &str, field: &str) -> Result<String, Error> {
    let parsed: serde_json::Value = serde_json::from_str(json_str)?;
    if let Some(error) = parsed.get("error") {
        return Err(Error::BroadcastFailed(format!("RPC error: {error}")));
    }
    parsed[field]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| Error::BroadcastFailed(format!("no '{field}' in response")))
}

/// Broadcast a signed transaction payload to the appropriate RPC endpoint.
pub fn broadcast(family: ChainFamily, rpc_url: &str, payload: &[u8]) -> Result<String, Error> {
    match family {
        ChainFamily::Evm => {
            let hex_tx = format!("0x{}", hex::encode(payload));
            let body = serde_json::json!({
                "jsonrpc": "2.0", "method": "eth_sendRawTransaction",
                "params": [hex_tx], "id": 1
            });
            let resp = post_json(rpc_url, &body)?;
            extract_json_field(&resp, "result")
        }
        ChainFamily::Solana => {
            use base64::Engine as _;
            let b64 = base64::engine::general_purpose::STANDARD.encode(payload);
            let body = serde_json::json!({
                "jsonrpc": "2.0", "method": "sendTransaction",
                "params": [b64, {"encoding": "base64"}], "id": 1
            });
            let resp = post_json(rpc_url, &body)?;
            extract_json_field(&resp, "result")
        }
        ChainFamily::Bitcoin => {
            let url = format!("{}/tx", rpc_url.trim_end_matches('/'));
            let resp = post_text(&url, &hex::encode(payload))?;
            if resp.is_empty() {
                return Err(Error::BroadcastFailed("empty response".into()));
            }
            Ok(resp)
        }
        ChainFamily::Cosmos => {
            use base64::Engine as _;
            let b64 = base64::engine::general_purpose::STANDARD.encode(payload);
            let url = format!("{}/cosmos/tx/v1beta1/txs", rpc_url.trim_end_matches('/'));
            let body = serde_json::json!({"tx_bytes": b64, "mode": "BROADCAST_MODE_SYNC"});
            let resp = post_json(&url, &body)?;
            let parsed: serde_json::Value = serde_json::from_str(&resp)?;
            parsed["tx_response"]["txhash"]
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| Error::BroadcastFailed(format!("no txhash: {resp}")))
        }
        ChainFamily::Tron => {
            let url = format!("{}/wallet/broadcasthex", rpc_url.trim_end_matches('/'));
            let body = serde_json::json!({"transaction": hex::encode(payload)});
            let resp = post_json(&url, &body)?;
            extract_json_field(&resp, "txid")
        }
        ChainFamily::Ton => {
            use base64::Engine as _;
            let b64 = base64::engine::general_purpose::STANDARD.encode(payload);
            let url = format!("{}/sendBoc", rpc_url.trim_end_matches('/'));
            let body = serde_json::json!({"boc": b64});
            let resp = post_json(&url, &body)?;
            let parsed: serde_json::Value = serde_json::from_str(&resp)?;
            parsed["result"]["hash"]
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| Error::BroadcastFailed(format!("no hash: {resp}")))
        }
        ChainFamily::Sui => {
            use base64::Engine as _;
            let b64 = base64::engine::general_purpose::STANDARD.encode(payload);
            let body = serde_json::json!({
                "jsonrpc": "2.0", "method": "sui_executeTransactionBlock",
                "params": [b64, [], null, null], "id": 1
            });
            let resp = post_json(rpc_url, &body)?;
            extract_json_field(&resp, "result")
        }
        ChainFamily::Xrpl => {
            let hex_tx = hex::encode(payload);
            let body = serde_json::json!({
                "method": "submit",
                "params": [{ "tx_blob": hex_tx }]
            });
            let resp = post_json(rpc_url, &body)?;
            let parsed: serde_json::Value = serde_json::from_str(&resp)?;
            if let Some(hash) = parsed["result"]["tx_json"]["hash"].as_str() {
                Ok(hash.to_owned())
            } else {
                Err(Error::BroadcastFailed(format!(
                    "no tx hash in XRPL response: {resp}"
                )))
            }
        }
        _ => Err(Error::BroadcastFailed(format!(
            "broadcast not yet supported for {family}"
        ))),
    }
}

/// Resolve the RPC URL: explicit > user config > built-in default.
pub fn resolve_rpc(
    chain_id: &str,
    family: ChainFamily,
    explicit: Option<&str>,
) -> Result<String, Error> {
    if let Some(url) = explicit {
        return Ok(url.to_owned());
    }
    let config = Config::load_or_default();
    if let Some(url) = config.rpc_url(chain_id) {
        return Ok(url.to_owned());
    }
    let defaults = Config::default_rpc();
    if let Some(url) = defaults.get(chain_id) {
        return Ok(url.clone());
    }
    let ns = family.namespace();
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
    Err(Error::InvalidInput(format!(
        "no RPC URL for chain '{chain_id}'"
    )))
}
