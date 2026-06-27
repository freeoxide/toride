//! Binary entry point for the `toride-harden` CLI.
//!
//! Only compiled when the `cli` feature is enabled (see `Cargo.toml`'s
//! `[[bin]] required-features`). Parses arguments via `clap` and dispatches
//! to the real client through [`Cli::run`].

use clap::Parser;
use toride_harden::cli::Cli;

fn main() {
    let cli = Cli::parse();
    if let Err(e) = cli.run() {
        eprintln!("{e:?}");
        std::process::exit(1);
    }
}
