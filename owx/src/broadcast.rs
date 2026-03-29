//! Sign and broadcast transactions to chain RPCs.

use owx_vault::store::Vault;

use crate::chain::{ChainFamily, parse_chain};
use crate::error::OwxError;
use crate::signing;

/// Result of a sign-and-send operation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SendResult {
    /// Transaction hash returned by the RPC.
    pub tx_hash: String,
}

/// Sign a transaction and broadcast it to the chain's RPC endpoint.
///
/// `credential` is either the owner's passphrase or an API token (`owx_key_...`).
/// If `rpc_url` is `None`, resolves from config or built-in defaults.
pub async fn sign_and_send(
    vault: &Vault,
    wallet_name_or_id: &str,
    chain: &str,
    tx_hex: &str,
    credential: &str,
    index: Option<u32>,
    rpc_url: Option<&str>,
) -> Result<SendResult, OwxError> {
    let chain_info = parse_chain(chain).map_err(OwxError::InvalidInput)?;

    let tx_hex_clean = tx_hex.strip_prefix("0x").unwrap_or(tx_hex);
    let tx_bytes = hex::decode(tx_hex_clean)
        .map_err(|e| OwxError::InvalidInput(format!("invalid hex transaction: {e}")))?;

    let sign_result =
        signing::sign_message(vault, wallet_name_or_id, chain, &tx_bytes, credential, index)?;

    let rpc = resolve_rpc_url(chain_info.chain_id, chain_info.family, rpc_url)?;
    let tx_hash = broadcast(chain_info.family, &rpc, &tx_bytes, &sign_result.signature).await?;

    Ok(SendResult { tx_hash })
}

/// Resolve the RPC URL: explicit > config > built-in default.
fn resolve_rpc_url(
    chain_id: &str,
    family: ChainFamily,
    explicit: Option<&str>,
) -> Result<String, OwxError> {
    if let Some(url) = explicit {
        return Ok(url.to_owned());
    }

    let config = owx_vault::Config::default();
    if let Some(url) = config.rpc_url(chain_id) {
        return Ok(url.to_owned());
    }

    let namespace = match family {
        ChainFamily::Evm => "eip155",
        ChainFamily::Bitcoin => "bip122",
        ChainFamily::Solana => "solana",
    };
    for (key, url) in &config.rpc {
        if key.starts_with(namespace) {
            return Ok(url.clone());
        }
    }

    Err(OwxError::InvalidInput(format!(
        "no RPC URL configured for chain '{chain_id}'"
    )))
}

/// Dispatch broadcast to the correct chain handler.
async fn broadcast(
    family: ChainFamily,
    rpc_url: &str,
    _tx_bytes: &[u8],
    signature_hex: &str,
) -> Result<String, OwxError> {
    match family {
        ChainFamily::Evm => broadcast_evm(rpc_url, signature_hex).await,
        ChainFamily::Bitcoin => broadcast_bitcoin(rpc_url, signature_hex).await,
        ChainFamily::Solana => broadcast_solana(rpc_url, signature_hex).await,
    }
}

/// Broadcast a signed EVM transaction via `eth_sendRawTransaction`.
async fn broadcast_evm(rpc_url: &str, signed_hex: &str) -> Result<String, OwxError> {
    let hex_tx = format!("0x{signed_hex}");
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_sendRawTransaction",
        "params": [hex_tx],
        "id": 1
    });

    let resp = rpc_post_json(rpc_url, &body).await?;
    extract_json_result(&resp)
}

/// Broadcast a signed Bitcoin transaction via Blockstream/Mempool REST API.
async fn broadcast_bitcoin(rpc_url: &str, signed_hex: &str) -> Result<String, OwxError> {
    let url = format!("{}/tx", rpc_url.trim_end_matches('/'));
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .header("content-type", "text/plain")
        .body(signed_hex.to_owned())
        .send()
        .await
        .map_err(|e| OwxError::InvalidInput(format!("broadcast failed: {e}")))?;

    let body = resp.text().await.unwrap_or_default();
    if body.is_empty() {
        return Err(OwxError::InvalidInput(
            "empty response from broadcast".into(),
        ));
    }
    Ok(body.trim().to_owned())
}

/// Broadcast a signed Solana transaction via `sendTransaction` JSON-RPC.
async fn broadcast_solana(rpc_url: &str, signed_hex: &str) -> Result<String, OwxError> {
    use base64::Engine;
    let signed_bytes = hex::decode(signed_hex)
        .map_err(|e| OwxError::InvalidInput(format!("invalid signed tx hex: {e}")))?;
    let b64_tx = base64::engine::general_purpose::STANDARD.encode(&signed_bytes);

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "sendTransaction",
        "params": [b64_tx, {"encoding": "base64"}],
        "id": 1
    });

    let resp = rpc_post_json(rpc_url, &body).await?;
    extract_json_result(&resp)
}

/// POST JSON to an RPC endpoint and return the response body.
async fn rpc_post_json(url: &str, body: &serde_json::Value) -> Result<String, OwxError> {
    let client = reqwest::Client::new();
    let resp = client
        .post(url)
        .json(body)
        .send()
        .await
        .map_err(|e| OwxError::InvalidInput(format!("RPC request failed: {e}")))?;

    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(OwxError::InvalidInput(format!(
            "RPC returned {status}: {text}"
        )));
    }
    Ok(text)
}

/// Extract the `result` field from a JSON-RPC response.
fn extract_json_result(json_str: &str) -> Result<String, OwxError> {
    let parsed: serde_json::Value = serde_json::from_str(json_str)?;
    if let Some(error) = parsed.get("error") {
        return Err(OwxError::InvalidInput(format!("RPC error: {error}")));
    }
    parsed["result"]
        .as_str()
        .map(|s| s.to_owned())
        .ok_or_else(|| OwxError::InvalidInput(format!("no 'result' in RPC response: {json_str}")))
}
