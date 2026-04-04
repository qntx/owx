//! Shared CLI output utilities.

use owx::Owx;

/// Print a value as pretty-printed JSON to stdout.
#[allow(clippy::print_stdout)]
pub fn print_json<T: serde::Serialize>(value: &T) -> Result<(), owx::Error> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

/// JSON error envelope for structured error output.
#[derive(serde::Serialize)]
pub struct ErrorEnvelope<'a> {
    /// Always `false`.
    pub success: bool,
    /// The error.
    pub error: &'a owx::Error,
}

/// Print a structured JSON error and exit.
#[allow(clippy::print_stderr)]
pub fn exit_with_error(error: &owx::Error) -> ! {
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
    std::process::exit(1)
}

/// Prompt for user input on stderr, read from stdin.
#[allow(clippy::print_stderr, clippy::expect_used)]
pub fn read_line(prompt: &str) -> String {
    eprint!("{prompt}");
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .expect("failed to read input");
    input.trim().to_owned()
}

/// Find the first EVM address from the first wallet.
pub fn first_evm_address(owx: &Owx) -> Result<String, owx::Error> {
    let wallets = owx.list_wallets()?;
    let w = wallets
        .first()
        .ok_or_else(|| owx::Error::InvalidInput("no wallets found".into()))?;
    w.accounts
        .iter()
        .find(|a| a.chain_id.starts_with("eip155:"))
        .map(|a| a.address.clone())
        .ok_or_else(|| owx::Error::InvalidInput("no EVM account found".into()))
}
