//! Async transaction broadcast to chain RPC endpoints.

use crate::chain::ChainFamily;
use crate::config::Config;
use crate::error::Error;

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
        .map_err(|e| Error::BroadcastFailed(format!("HTTP: {e}")))?;
    if !resp.status().is_success() {
        return Err(Error::BroadcastFailed(format!("HTTP {}", resp.status())));
    }
    resp.text()
        .await
        .map_err(|e| Error::BroadcastFailed(format!("read body: {e}")))
}

/// POST plain text to an endpoint, return the trimmed response body.
async fn post_text(client: &reqwest::Client, url: &str, body: &str) -> Result<String, Error> {
    let resp = client
        .post(url)
        .header("Content-Type", "text/plain")
        .body(body.to_owned())
        .send()
        .await
        .map_err(|e| Error::BroadcastFailed(format!("HTTP: {e}")))?;
    if !resp.status().is_success() {
        return Err(Error::BroadcastFailed(format!("HTTP {}", resp.status())));
    }
    resp.text()
        .await
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

/// Broadcast a signed transaction to the appropriate chain RPC.
#[allow(clippy::too_many_lines)]
pub async fn broadcast(
    client: &reqwest::Client,
    family: ChainFamily,
    rpc_url: &str,
    payload: &[u8],
) -> Result<String, Error> {
    match family {
        ChainFamily::Evm => {
            let hex_tx = format!("0x{}", hex::encode(payload));
            let body = serde_json::json!({
                "jsonrpc": "2.0", "method": "eth_sendRawTransaction",
                "params": [hex_tx], "id": 1
            });
            let resp = post_json(client, rpc_url, &body).await?;
            extract_json_field(&resp, "result")
        }
        ChainFamily::Solana => {
            use base64::Engine as _;
            let b64 = base64::engine::general_purpose::STANDARD.encode(payload);
            let body = serde_json::json!({
                "jsonrpc": "2.0", "method": "sendTransaction",
                "params": [b64, {"encoding": "base64"}], "id": 1
            });
            let resp = post_json(client, rpc_url, &body).await?;
            extract_json_field(&resp, "result")
        }
        ChainFamily::Bitcoin => {
            let url = format!("{}/tx", rpc_url.trim_end_matches('/'));
            let resp = post_text(client, &url, &hex::encode(payload)).await?;
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
            let resp = post_json(client, &url, &body).await?;
            let parsed: serde_json::Value = serde_json::from_str(&resp)?;
            let tx_resp = &parsed["tx_response"];
            if let Some(code) = tx_resp["code"].as_u64()
                && code != 0
            {
                let log = tx_resp["raw_log"].as_str().unwrap_or("unknown error");
                return Err(Error::BroadcastFailed(format!(
                    "cosmos tx failed (code {code}): {log}"
                )));
            }
            tx_resp["txhash"]
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| Error::BroadcastFailed(format!("no txhash: {resp}")))
        }
        ChainFamily::Tron => {
            let url = format!("{}/wallet/broadcasthex", rpc_url.trim_end_matches('/'));
            let body = serde_json::json!({"transaction": hex::encode(payload)});
            let resp = post_json(client, &url, &body).await?;
            let parsed: serde_json::Value = serde_json::from_str(&resp)?;
            if parsed["result"].as_bool() == Some(false) {
                let code = parsed["code"].as_str().unwrap_or("UNKNOWN");
                let msg = parsed["message"].as_str().unwrap_or("");
                return Err(Error::BroadcastFailed(format!(
                    "tron broadcast failed ({code}): {msg}"
                )));
            }
            parsed["txid"]
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| Error::BroadcastFailed(format!("no txid in Tron response: {resp}")))
        }
        ChainFamily::Ton => {
            use base64::Engine as _;
            let b64 = base64::engine::general_purpose::STANDARD.encode(payload);
            let url = format!("{}/sendBoc", rpc_url.trim_end_matches('/'));
            let body = serde_json::json!({"boc": b64});
            let resp = post_json(client, &url, &body).await?;
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
            let resp = post_json(client, rpc_url, &body).await?;
            let parsed: serde_json::Value = serde_json::from_str(&resp)?;
            if let Some(error) = parsed.get("error") {
                return Err(Error::BroadcastFailed(format!("RPC error: {error}")));
            }
            parsed["result"]["digest"]
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| Error::BroadcastFailed(format!("no digest in Sui response: {resp}")))
        }
        ChainFamily::Xrpl => {
            let hex_tx = hex::encode(payload);
            let body = serde_json::json!({
                "method": "submit",
                "params": [{ "tx_blob": hex_tx }]
            });
            let resp = post_json(client, rpc_url, &body).await?;
            let parsed: serde_json::Value = serde_json::from_str(&resp)?;
            parsed["result"]["tx_json"]["hash"]
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| {
                    Error::BroadcastFailed(format!("no tx hash in XRPL response: {resp}"))
                })
        }
        ChainFamily::Spark | ChainFamily::Filecoin => Err(Error::BroadcastFailed(format!(
            "broadcast not yet supported for {family}"
        ))),
    }
}

/// Resolve the RPC URL: explicit > user config > built-in default.
pub fn resolve_rpc(
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
    Err(Error::InvalidInput(format!(
        "no RPC URL for chain '{chain_id}'"
    )))
}
