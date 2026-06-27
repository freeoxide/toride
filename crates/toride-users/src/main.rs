//! Binary entry point for the `toride-users` CLI.
//!
//! Dispatches to the real [`UsersClient`] methods through
//! [`Cli::run`](toride_users::cli::Cli::run), which parses `std::env::args()`
//! via clap and routes the subcommand. Only compiled when the `cli` feature is
//! enabled (see `[[bin]]` in `Cargo.toml`).

use toride_users::cli::Cli;

fn main() {
    if let Err(e) = Cli::run() {
        eprintln!("{e:?}");
        std::process::exit(1);
    }
}
