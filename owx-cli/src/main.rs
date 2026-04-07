//! CLI for OWX agent wallet toolkit.

#![allow(
    clippy::print_stdout,
    reason = "CLI binary uses stdout for normal output"
)]
#![allow(
    clippy::print_stderr,
    reason = "CLI binary uses stderr for error output"
)]
#![allow(missing_docs, reason = "CLI binary internals need no public docs")]
#![allow(
    clippy::missing_docs_in_private_items,
    reason = "CLI binary internals need no docs"
)]

mod commands;
mod output;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use owx::Owx;

use crate::output::print_error;

#[derive(Parser)]
#[command(
    name = "owx",
    about = "Agent-native, self-custodial, policy-gated, multi-chain wallet toolkit."
)]
struct Cli {
    /// Path to the vault directory (default: ~/.owx).
    #[arg(long, global = true)]
    vault: Option<PathBuf>,

    #[command(subcommand)]
    command: commands::Commands,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let owx = match cli.vault.as_ref().map_or_else(Owx::open_default, Owx::open) {
        Ok(v) => v,
        Err(e) => {
            print_error(&e);
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = commands::dispatch(cli.command, &owx) {
        print_error(&e);
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
