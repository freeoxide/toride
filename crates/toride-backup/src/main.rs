//! Binary entry point for the `toride-backup` CLI.
//!
//! Parses the command line with [`clap`] and dispatches to the real
//! [`BackupClient`] methods via [`Cli::run`](toride_backup::cli::Cli::run).
//! Only compiled when the `cli` feature is enabled (see `[[bin]]` in
//! `Cargo.toml`).

use clap::Parser;

use toride_backup::cli::Cli;

fn main() {
    let cli = Cli::parse();

    if let Err(e) = cli.run() {
        eprintln!("{e:?}");
        std::process::exit(1);
    }
}
