//! CLI for OWX agent wallet toolkit.

#![allow(clippy::missing_docs_in_private_items, missing_docs)]

mod commands;
mod output;

use std::path::PathBuf;

use clap::Parser;
use owx::Owx;

use crate::output::exit_with_error;

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

#[allow(clippy::print_stderr)]
fn main() {
    let cli = Cli::parse();
    let owx_result = cli.vault.as_ref().map_or_else(Owx::open_default, Owx::open);
    let owx = match owx_result {
        Ok(v) => v,
        Err(e) => exit_with_error(&e),
    };
    if let Err(e) = commands::dispatch(cli.command, &owx) {
        exit_with_error(&e);
    }
}
