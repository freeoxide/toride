//! Binary entry point for the `toride-proxy` CLI.
//!
//! Only compiled when the `cli` feature is enabled (see the `[[bin]]` table's
//! `required-features` in `Cargo.toml`). Parses argv via clap, constructs a
//! production [`ProxyClient`](toride_proxy::client::ProxyClient), and dispatches
//! through [`ProxyCli::run`](toride_proxy::cli::ProxyCli::run). Any error is
//! printed to stderr as a debug rendering before exiting non-zero, matching the
//! other `toride-*` binaries.

use clap::Parser;

use toride_proxy::cli::ProxyCli;
use toride_proxy::client::ProxyClient;

fn main() {
    let cli = ProxyCli::parse();

    // `ProxyClient::system()` only builds the runner and resolves default
    // paths; it never shells out, so a missing `nginx` binary is surfaced
    // later by the relevant subcommand rather than failing here.
    let mut client = match ProxyClient::system() {
        Ok(client) => client,
        Err(e) => {
            eprintln!("{e:?}");
            std::process::exit(1);
        }
    };

    if let Err(e) = cli.run(&mut client) {
        eprintln!("{e:?}");
        std::process::exit(1);
    }
}
