//! Binary entry point for the `toride-wireguard` CLI.
//!
//! Parses arguments with clap, dispatches to the real client calls via
//! [`WireguardCli::run`], and exits non-zero on any error.
//!
//! Only compiled when the `cli` feature is enabled (see `Cargo.toml`'s
//! `[[bin]]` `required-features`).

#[cfg(feature = "cli")]
fn main() {
    use clap::Parser;
    use toride_wireguard::cli::WireguardCli;

    let cli = WireguardCli::parse();
    if let Err(e) = cli.run() {
        eprintln!("{e:?}");
        std::process::exit(1);
    }
}

// When the `cli` feature is disabled the `[[bin]]` target is not built anyway
// (`required-features = ["cli"]`), but `cargo` still type-checks this file
// during a bare `cargo check` without features. Provide a no-op so it compiles
// cleanly in that configuration.
#[cfg(not(feature = "cli"))]
fn main() {}
