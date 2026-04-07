//! Async transaction broadcast to chain RPC endpoints.

use base64::Engine as _;

use crate::chain::ChainFamily;
use crate::config::Config;
use crate::error::OwxError as Error;

/// Shorthand constructor for [`Error::BroadcastFailed`].
fn broadcast_err(msg: impl Into<String>) -> Error {
    Error::BroadcastFailed(msg.into())
}

/// POST JSON to an RPC endpoint, return the response body.
async fn post_json(
    client: &reqwest::Client,
    url: &str,
    body: &serde_json::Value,
) -> Result<String, Error> {
    let resp = client
        .post(url)
        .json(body)
        .send()
        .await
        .map_err(|e| broadcast_err(format!("HTTP: {e}")))?;
    if !resp.status().is_success() {
        return Err(broadcast_err(format!("HTTP {}", resp.status())));
    }
    resp.text()
        .await
        .map_err(|e| broadcast_err(format!("read body: {e}")))
}

/// POST plain text to an endpoint, return the trimmed response body.
async fn post_text(client: &reqwest::Client, url: &str, body: &str) -> Result<String, Error> {
    let resp = client
        .post(url)
        .header("Content-Type", "text/plain")
        .body(body.to_owned())
        .send()
        .await
        .map_err(|e| broadcast_err(format!("HTTP: {e}")))?;
    if !resp.status().is_success() {
        return Err(broadcast_err(format!("HTTP {}", resp.status())));
    }
    resp.text()
        .await
        .map_err(|e| broadcast_err(format!("read body: {e}")))
        .map(|s| s.trim().to_owned())
}

/// Send a JSON-RPC request and extract the `"result"` field.
async fn json_rpc(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let body = serde_json::json!({"jsonrpc": "2.0", "method": method, "params": params, "id": 1});
    let text = post_json(client, url, &body).await?;
    let parsed: serde_json::Value = serde_json::from_str(&text)?;
    if let Some(error) = parsed.get("error") {
        return Err(broadcast_err(format!("RPC error: {error}")));
    }
    Ok(parsed)
}

/// Extract a string at a JSON pointer path, or return a broadcast error.
fn extract_str(value: &serde_json::Value, pointer: &str, raw: &str) -> Result<String, Error> {
    value
        .pointer(pointer)
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| broadcast_err(format!("no '{pointer}' in response: {raw}")))
}

/// Base64-encode payload bytes.
fn b64(payload: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(payload)
}

/// Append a path segment to a base URL.
fn rpc_path(base: &str, path: &str) -> String {
    format!("{}{path}", base.trim_end_matches('/'))
}

/// Broadcast a signed transaction to the appropriate chain RPC.
pub(crate) async fn broadcast(
    client: &reqwest::Client,
    family: ChainFamily,
    rpc_url: &str,
    payload: &[u8],
) -> Result<String, Error> {
    match family {
        ChainFamily::Evm => broadcast_evm(client, rpc_url, payload).await,
        ChainFamily::Bitcoin => broadcast_bitcoin(client, rpc_url, payload).await,
        ChainFamily::Solana => broadcast_solana(client, rpc_url, payload).await,
        ChainFamily::Cosmos => broadcast_cosmos(client, rpc_url, payload).await,
        ChainFamily::Tron => broadcast_tron(client, rpc_url, payload).await,
        ChainFamily::Ton => broadcast_ton(client, rpc_url, payload).await,
        ChainFamily::Sui => broadcast_sui(client, rpc_url, payload).await,
        ChainFamily::Xrpl => broadcast_xrpl(client, rpc_url, payload).await,
        ChainFamily::Spark | ChainFamily::Filecoin => Err(broadcast_err(format!(
            "broadcast not yet supported for {family}"
        ))),
    }
}

/// Broadcast a signed EVM transaction via `eth_sendRawTransaction`.
async fn broadcast_evm(
    client: &reqwest::Client,
    url: &str,
    payload: &[u8],
) -> Result<String, Error> {
    let hex_tx = format!("0x{}", hex::encode(payload));
    let resp = json_rpc(
        client,
        url,
        "eth_sendRawTransaction",
        serde_json::json!([hex_tx]),
    )
    .await?;
    extract_str(&resp, "/result", &resp.to_string())
}

/// Broadcast a signed Solana transaction via `sendTransaction`.
async fn broadcast_solana(
    client: &reqwest::Client,
    url: &str,
    payload: &[u8],
) -> Result<String, Error> {
    let params = serde_json::json!([b64(payload), {"encoding": "base64"}]);
    let resp = json_rpc(client, url, "sendTransaction", params).await?;
    extract_str(&resp, "/result", &resp.to_string())
}

/// Broadcast a signed Bitcoin transaction via blockstream-style REST API.
async fn broadcast_bitcoin(
    client: &reqwest::Client,
    rpc_url: &str,
    payload: &[u8],
) -> Result<String, Error> {
    let url = rpc_path(rpc_url, "/tx");
    let resp = post_text(client, &url, &hex::encode(payload)).await?;
    if resp.is_empty() {
        return Err(broadcast_err("empty response"));
    }
    Ok(resp)
}

/// Broadcast a signed Cosmos transaction via REST `txs` endpoint.
async fn broadcast_cosmos(
    client: &reqwest::Client,
    rpc_url: &str,
    payload: &[u8],
) -> Result<String, Error> {
    let url = rpc_path(rpc_url, "/cosmos/tx/v1beta1/txs");
    let body = serde_json::json!({"tx_bytes": b64(payload), "mode": "BROADCAST_MODE_SYNC"});
    let text = post_json(client, &url, &body).await?;
    let parsed: serde_json::Value = serde_json::from_str(&text)?;
    let null = serde_json::Value::Null;
    let tx_resp = parsed.get("tx_response").unwrap_or(&null);
    if let Some(code) = tx_resp.get("code").and_then(serde_json::Value::as_u64)
        && code != 0
    {
        let log = tx_resp
            .get("raw_log")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        return Err(broadcast_err(format!(
            "cosmos tx failed (code {code}): {log}"
        )));
    }
    extract_str(&parsed, "/tx_response/txhash", &text)
}

/// Broadcast a signed Tron transaction via `broadcasthex`.
async fn broadcast_tron(
    client: &reqwest::Client,
    rpc_url: &str,
    payload: &[u8],
) -> Result<String, Error> {
    let url = rpc_path(rpc_url, "/wallet/broadcasthex");
    let body = serde_json::json!({"transaction": hex::encode(payload)});
    let text = post_json(client, &url, &body).await?;
    let parsed: serde_json::Value = serde_json::from_str(&text)?;
    if parsed.get("result").and_then(serde_json::Value::as_bool) == Some(false) {
        let code = parsed
            .get("code")
            .and_then(|v| v.as_str())
            .unwrap_or("UNKNOWN");
        let msg = parsed.get("message").and_then(|v| v.as_str()).unwrap_or("");
        return Err(broadcast_err(format!(
            "tron broadcast failed ({code}): {msg}"
        )));
    }
    extract_str(&parsed, "/txid", &text)
}

/// Broadcast a signed TON transaction via `sendBoc`.
async fn broadcast_ton(
    client: &reqwest::Client,
    rpc_url: &str,
    payload: &[u8],
) -> Result<String, Error> {
    let url = rpc_path(rpc_url, "/sendBoc");
    let body = serde_json::json!({"boc": b64(payload)});
    let text = post_json(client, &url, &body).await?;
    let parsed: serde_json::Value = serde_json::from_str(&text)?;
    extract_str(&parsed, "/result/hash", &text)
}

/// Broadcast a signed Sui transaction via `sui_executeTransactionBlock`.
async fn broadcast_sui(
    client: &reqwest::Client,
    url: &str,
    payload: &[u8],
) -> Result<String, Error> {
    let params = serde_json::json!([b64(payload), [], null, null]);
    let resp = json_rpc(client, url, "sui_executeTransactionBlock", params).await?;
    extract_str(&resp, "/result/digest", &resp.to_string())
}

/// Broadcast a signed XRPL transaction via `submit`.
async fn broadcast_xrpl(
    client: &reqwest::Client,
    url: &str,
    payload: &[u8],
) -> Result<String, Error> {
    let body =
        serde_json::json!({"method": "submit", "params": [{"tx_blob": hex::encode(payload)}]});
    let text = post_json(client, url, &body).await?;
    let parsed: serde_json::Value = serde_json::from_str(&text)?;
    extract_str(&parsed, "/result/tx_json/hash", &text)
}

/// Resolve the RPC URL: explicit > user config > built-in default.
pub(crate) fn resolve_rpc(
    chain_id: &str,
    explicit: Option<&str>,
    config: &Config,
) -> Result<String, Error> {
    if let Some(url) = explicit {
        return Ok(url.to_owned());
    }
    if let Some(url) = config.rpc_url(chain_id) {
        return Ok(url.to_owned());
    }
    let defaults = Config::default_rpc();
    if let Some(url) = defaults.get(chain_id) {
        return Ok(url.clone());
    }
    Err(Error::NoRpcUrl(chain_id.to_owned()))
}
