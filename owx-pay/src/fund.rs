//! Wallet funding via MoonPay.

use crate::error::PayError;
use crate::types::FundResult;

/// MoonPay API base URL.
const MOONPAY_API: &str = "https://agents.moonpay.com";

/// Create a MoonPay deposit that auto-converts incoming crypto to USDC.
pub async fn fund(
    wallet_address: &str,
    chain: Option<&str>,
    token: Option<&str>,
) -> Result<FundResult, PayError> {
    let chain_name = resolve_chain(chain);
    let token = token.unwrap_or("USDC");

    let client = reqwest::Client::new();
    let req_body = serde_json::json!({
        "name": format!("OWX deposit ({token} on {chain_name})"),
        "wallet": wallet_address,
        "chain": chain_name,
        "token": token,
    });

    let resp = client
        .post(format!("{MOONPAY_API}/api/tools/deposit_create"))
        .json(&req_body)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(PayError::InvalidInput(format!(
            "MoonPay returned {status}: {body}"
        )));
    }

    let deposit: MoonPayDepositResponse = resp.json().await.map_err(|e| {
        PayError::ProtocolMalformed(format!("failed to parse MoonPay response: {e}"))
    })?;

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

/// Resolve a chain name to MoonPay's format.
fn resolve_chain(chain: Option<&str>) -> &str {
    match chain {
        Some(c) => match c.to_lowercase().as_str() {
            "base" | "eip155:8453" => "base",
            "ethereum" | "eip155:1" => "ethereum",
            "polygon" | "eip155:137" => "polygon",
            "arbitrum" | "eip155:42161" => "arbitrum",
            "optimism" | "eip155:10" => "optimism",
            "solana" => "solana",
            _ => "base",
        },
        None => "base",
    }
}

/// MoonPay deposit response.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct MoonPayDepositResponse {
    /// Deposit ID.
    id: String,
    /// Deposit URL.
    deposit_url: String,
    /// Available wallets.
    wallets: Vec<DepositWallet>,
    /// Instructions for the user.
    instructions: String,
}

/// A deposit wallet from MoonPay.
#[derive(serde::Deserialize)]
struct DepositWallet {
    /// Address.
    address: String,
    /// Chain.
    chain: String,
}
