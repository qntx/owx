//! Shared CLI output utilities.

use owx::Owx;

/// Print a value as pretty-printed JSON to stdout.
pub(crate) fn print_json<T: serde::Serialize>(value: &T) -> Result<(), owx::OwxError> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

/// JSON error envelope for structured error output.
#[derive(serde::Serialize)]
pub(crate) struct ErrorEnvelope<'a> {
    /// Always `false`.
    pub success: bool,
    /// The error.
    pub error: &'a owx::OwxError,
}

/// Print a structured JSON error to stderr.
pub(crate) fn print_error(error: &owx::OwxError) {
    let payload = ErrorEnvelope {
        success: false,
        error,
    };
    match serde_json::to_string_pretty(&payload) {
        Ok(json) => eprintln!("{json}"),
        Err(_) => eprintln!(
            r#"{{"success":false,"error":{{"code":"JSON","message":"serialization failed"}}}}"#
        ),
    }
}

/// Find the first EVM address from the first wallet.
pub(crate) fn first_evm_address(owx: &Owx) -> Result<String, owx::OwxError> {
    let wallets = owx.list_wallets()?;
    let w = wallets
        .first()
        .ok_or_else(|| owx::OwxError::InvalidInput("no wallets found".into()))?;
    w.accounts
        .iter()
        .find(|a| a.chain_id.starts_with("eip155:"))
        .map(|a| a.address.clone())
        .ok_or_else(|| owx::OwxError::InvalidInput("no EVM account found".into()))
}
