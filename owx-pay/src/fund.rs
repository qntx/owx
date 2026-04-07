//! `MoonPay` wallet funding and balance queries.

use serde::{Deserialize, Serialize};

use crate::error::{PayError, PayErrorCode};
use crate::http::client;

/// `MoonPay` agent API base URL.
const MOONPAY_API: &str = "https://agents.moonpay.com";

/// Mapping entry for a MoonPay-supported chain.
struct MoonPayChain {
    /// Human-readable chain name.
    display_name: &'static str,
    /// `MoonPay` API chain identifier.
    moonpay_name: &'static str,
}

/// Known chain mappings for the `MoonPay` API.
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

/// Resolve a user-facing chain name to a `MoonPay` chain entry.
fn resolve_moonpay_chain(chain: Option<&str>) -> Result<&'static MoonPayChain, PayError> {
    chain.map_or_else(
        || {
            MOONPAY_CHAINS.first().map(|(_, v)| v).ok_or_else(|| {
                PayError::new(
                    PayErrorCode::UnsupportedChain,
                    String::from("no MoonPay chains configured"),
                )
            })
        },
        |name| {
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
        },
    )
}

/// Result of a fund operation.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct FundResult {
    /// `MoonPay` deposit ID.
    pub deposit_id: String,
    /// URL for the user to complete the deposit.
    pub deposit_url: String,
    /// Deposit wallet addresses by chain.
    pub wallets: Vec<(String, String)>,
    /// Human-readable instructions.
    pub instructions: String,
}

/// Token balance entry.
#[non_exhaustive]
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

/// `MoonPay` deposit creation request body.
#[derive(Serialize)]
struct DepositRequest {
    /// Human-readable deposit name.
    name: String,
    /// Wallet address to fund.
    wallet: String,
    /// `MoonPay` chain name.
    chain: String,
    /// Token symbol (e.g. "USDC").
    token: String,
}

/// `MoonPay` deposit creation response.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DepositResponse {
    /// Unique deposit identifier.
    id: String,
    /// URL for the user to complete the deposit.
    deposit_url: String,
    /// Deposit wallet addresses.
    wallets: Vec<DepositWallet>,
    /// Human-readable instructions.
    instructions: String,
}

/// A deposit wallet address entry.
#[derive(Deserialize)]
struct DepositWallet {
    /// On-chain address.
    address: String,
    /// Chain name.
    chain: String,
}

/// `MoonPay` balance query request body.
#[derive(Serialize)]
struct BalanceRequest {
    /// Wallet address to query.
    wallet: String,
    /// `MoonPay` chain name.
    chain: String,
}

/// `MoonPay` balance query response.
#[derive(Deserialize)]
struct BalanceResponse {
    /// Token balance entries.
    items: Vec<TokenBalance>,
}

/// Create a `MoonPay` deposit (blocking).
pub(crate) fn fund_blocking(
    wallet_address: &str,
    chain: Option<&str>,
    token: Option<&str>,
) -> Result<FundResult, PayError> {
    let mapping = resolve_moonpay_chain(chain)?;
    let token_sym = token.unwrap_or("USDC");

    let req = DepositRequest {
        name: format!("OWX deposit ({token_sym} on {})", mapping.display_name),
        wallet: wallet_address.to_owned(),
        chain: mapping.moonpay_name.to_owned(),
        token: token_sym.to_owned(),
    };

    let resp = client()?
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

/// Check token balances via `MoonPay` (blocking).
pub(crate) fn get_balances_blocking(
    wallet_address: &str,
    chain: Option<&str>,
) -> Result<Vec<TokenBalance>, PayError> {
    let mapping = resolve_moonpay_chain(chain)?;

    let req = BalanceRequest {
        wallet: wallet_address.to_owned(),
        chain: mapping.moonpay_name.to_owned(),
    };

    let resp = client()?
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
