//! MoonPay wallet funding and balance queries.

use std::sync::LazyLock;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{PayError, PayErrorCode};

static HTTP: LazyLock<reqwest::blocking::Client> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("failed to build HTTP client")
});

const MOONPAY_API: &str = "https://agents.moonpay.com";

struct MoonPayChain {
    display_name: &'static str,
    moonpay_name: &'static str,
}

const MOONPAY_CHAINS: &[(&str, MoonPayChain)] = &[
    (
        "base",
        MoonPayChain {
            display_name: "Base",
            moonpay_name: "base",
        },
    ),
    (
        "ethereum",
        MoonPayChain {
            display_name: "Ethereum",
            moonpay_name: "ethereum",
        },
    ),
    (
        "polygon",
        MoonPayChain {
            display_name: "Polygon",
            moonpay_name: "polygon",
        },
    ),
    (
        "arbitrum",
        MoonPayChain {
            display_name: "Arbitrum",
            moonpay_name: "arbitrum",
        },
    ),
    (
        "optimism",
        MoonPayChain {
            display_name: "Optimism",
            moonpay_name: "optimism",
        },
    ),
    (
        "bsc",
        MoonPayChain {
            display_name: "BNB Chain",
            moonpay_name: "bnb",
        },
    ),
    (
        "bnb",
        MoonPayChain {
            display_name: "BNB Chain",
            moonpay_name: "bnb",
        },
    ),
    (
        "base-sepolia",
        MoonPayChain {
            display_name: "Base Sepolia",
            moonpay_name: "base-sepolia",
        },
    ),
    (
        "solana",
        MoonPayChain {
            display_name: "Solana",
            moonpay_name: "solana",
        },
    ),
];

fn resolve_moonpay_chain(chain: Option<&str>) -> Result<&'static MoonPayChain, PayError> {
    match chain {
        Some(name) => {
            let lower = name.to_lowercase();
            MOONPAY_CHAINS
                .iter()
                .find(|(k, _)| *k == lower)
                .map(|(_, v)| v)
                .ok_or_else(|| {
                    PayError::new(
                        PayErrorCode::UnsupportedChain,
                        format!("unknown chain: {name}"),
                    )
                })
        }
        None => Ok(&MOONPAY_CHAINS[0].1),
    }
}

/// Result of a fund operation.
#[derive(Debug, Clone, Serialize)]
pub struct FundResult {
    /// MoonPay deposit ID.
    pub deposit_id: String,
    /// URL for the user to complete the deposit.
    pub deposit_url: String,
    /// Deposit wallet addresses by chain.
    pub wallets: Vec<(String, String)>,
    /// Human-readable instructions.
    pub instructions: String,
}

/// Token balance entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBalance {
    /// Token contract address.
    pub address: String,
    /// Token name.
    pub name: String,
    /// Token symbol.
    pub symbol: String,
    /// Chain name.
    pub chain: String,
    /// Token decimals.
    pub decimals: u32,
    /// Balance info.
    pub balance: BalanceInfo,
}

/// Balance details.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BalanceInfo {
    /// Raw amount.
    pub amount: f64,
    /// USD value.
    pub value: f64,
    /// Token price.
    pub price: f64,
}

#[derive(Serialize)]
struct DepositRequest {
    name: String,
    wallet: String,
    chain: String,
    token: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DepositResponse {
    id: String,
    deposit_url: String,
    wallets: Vec<DepositWallet>,
    instructions: String,
}

#[derive(Deserialize)]
struct DepositWallet {
    address: String,
    chain: String,
}

#[derive(Serialize)]
struct BalanceRequest {
    wallet: String,
    chain: String,
}

#[derive(Deserialize)]
struct BalanceResponse {
    items: Vec<TokenBalance>,
}

/// Create a MoonPay deposit (blocking).
pub fn fund_blocking(
    wallet_address: &str,
    chain: Option<&str>,
    token: Option<&str>,
) -> Result<FundResult, PayError> {
    let mapping = resolve_moonpay_chain(chain)?;
    let token = token.unwrap_or("USDC");

    let req = DepositRequest {
        name: format!("OWX deposit ({token} on {})", mapping.display_name),
        wallet: wallet_address.to_owned(),
        chain: mapping.moonpay_name.to_owned(),
        token: token.to_owned(),
    };

    let resp = HTTP
        .post(format!("{MOONPAY_API}/api/tools/deposit_create"))
        .json(&req)
        .send()?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        return Err(PayError::new(
            PayErrorCode::HttpStatus,
            format!("MoonPay returned {status}: {body}"),
        ));
    }

    let deposit: DepositResponse = resp.json()?;
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

/// Check token balances via MoonPay (blocking).
pub fn get_balances_blocking(
    wallet_address: &str,
    chain: Option<&str>,
) -> Result<Vec<TokenBalance>, PayError> {
    let mapping = resolve_moonpay_chain(chain)?;

    let req = BalanceRequest {
        wallet: wallet_address.to_owned(),
        chain: mapping.moonpay_name.to_owned(),
    };

    let resp = HTTP
        .post(format!("{MOONPAY_API}/api/tools/token_balance_list"))
        .json(&req)
        .send()?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        return Err(PayError::new(
            PayErrorCode::HttpStatus,
            format!("MoonPay returned {status}: {body}"),
        ));
    }

    let balance: BalanceResponse = resp.json()?;
    Ok(balance.items)
}
