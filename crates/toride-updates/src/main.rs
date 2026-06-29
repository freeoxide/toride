//! Binary entry point for the `toride-updates` CLI.
//!
//! Parses the command line with [`clap`] and dispatches to the real
//! [`UpdatesClient`] / [`Doctor`](toride_updates::doctor::Doctor) /
//! [`ScheduleManager`](toride_updates::schedule::ScheduleManager) methods via
//! [`UpdatesCli::run`](toride_updates::cli::UpdatesCli::run). Only compiled when
//! the `cli` feature is enabled (see `[[bin]]` in `Cargo.toml`).

use clap::Parser;

use toride_updates::cli::UpdatesCli;

fn main() {
    let cli = UpdatesCli::parse();

    if let Err(e) = cli.run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
