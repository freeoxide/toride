//! Binary entry point for the `toride-tailscale` CLI.
//!
//! Built only when the `cli` feature is enabled (see `Cargo.toml`'s `[[bin]]`
//! `required-features`). Parses [`TailscaleArgs`] and dispatches to the real
//! [`TailscaleClient`] / [`TailscaleService`] / [`Doctor`] calls.
//!
//! Errors are printed to stderr in `Debug` form (which includes the full
//! [`Error`](toride_tailscale::Error) context) and the process exits non-zero,
//! matching the convention used by the other toride CLI binaries.

use toride_tailscale::cli::TailscaleArgs;

fn main() {
    if let Err(err) = TailscaleArgs::run() {
        eprintln!("{err:?}");
        std::process::exit(1);
    }
}
