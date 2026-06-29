//! Binary entry point for the `toride-cloud` CLI.
//!
//! Only compiled when the `cli` feature is enabled (see the `[[bin]]` table's
//! `required-features` in `Cargo.toml`). Parses argv via clap and dispatches
//! through [`toride_cloud::cli::Cli::run`], printing any error to stderr before
//! exiting non-zero.
//!
//! `--verbose` is accepted and stored on [`Cli`]; structured-log wiring is left
//! to a future task so this binary stays free of extra dependencies.

use clap::Parser;

use toride_cloud::cli::Cli;

fn main() {
    let cli = Cli::parse();

    if let Err(e) = cli.run() {
        // Display, not Debug: the crate's `Error` types deliberately scrub
        // raw stderr / tokens out of their Display rendering, so `{e}` keeps
        // secrets and noisy provider output out of the user-facing message.
        eprintln!("{e}");
        std::process::exit(1);
    }
}
