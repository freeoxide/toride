//! Binary entry point for the `toride-audit` CLI.
//!
//! Built only when the `cli` feature is enabled. Parses arguments with
//! [`clap`] and dispatches to [`toride_audit::cli::AuditCli::run`].

use clap::Parser;
use toride_audit::cli::AuditCli;

fn main() {
    let cli = AuditCli::parse();
    if let Err(e) = cli.run() {
        eprintln!("{e:?}");
        std::process::exit(1);
    }
}
