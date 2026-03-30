//! Sign and broadcast transactions to chain RPCs.

use owx_core::parse_chain;
use owx_vault::store::Vault;

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

    if chain_info.chain_type != owx_core::chain::ChainType::Evm {
        return Err(OwxError::InvalidInput(
            "sign_and_send is only implemented for EVM chains".into(),
        ));
    }

    let sign_result =
        signing::sign_transaction(vault, wallet_name_or_id, chain, tx_hex, credential, index)?;

    let rpc = resolve_rpc_url(vault, chain_info.chain_id, rpc_url)?;
    let tx_hash = broadcast_evm(&rpc, &sign_result.signed_tx).await?;

    Ok(SendResult { tx_hash })
}

/// Resolve the RPC URL: explicit > config > built-in default.
fn resolve_rpc_url(
    vault: &Vault,
    chain_id: &str,
    explicit: Option<&str>,
) -> Result<String, OwxError> {
    if let Some(url) = explicit {
        return Ok(url.to_owned());
    }

    let config_path = vault.root().join("config.json");
    let config = owx_core::Config::load_or_default_from(&config_path);
    if let Some(url) = config.rpc_url(chain_id) {
        return Ok(url.to_owned());
    }

    Err(OwxError::InvalidInput(format!(
        "no RPC URL configured for chain '{chain_id}'"
    )))
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
        .map(ToOwned::to_owned)
        .ok_or_else(|| OwxError::InvalidInput(format!("no 'result' in RPC response: {json_str}")))
}
