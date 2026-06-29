//! WireGuard client wrapping `wg` CLI commands.
//!
//! [`WireguardClient`] provides methods for interacting with the WireGuard
//! kernel module via the `wg` CLI tool. It handles command execution, output
//! parsing, and error translation.
//!
//! All commands are built as [`CommandSpec`](toride_runner::CommandSpec)s and
//! executed through a [`Runner`](toride_runner::Runner), so the entire client
//! is testable via [`FakeRunner`](toride_runner::FakeRunner) without a real
//! `wg` binary or root privileges.

use std::time::Duration;

use toride_runner::{CommandSpec, Runner};

use crate::error::Result;
use crate::parse::{WgShowEntry, parse_wg_show};

/// Default wall-clock timeout for `wg` commands (seconds).
const WG_TIMEOUT_SECS: u64 = 15;

// ---------------------------------------------------------------------------
// WireguardClient
// ---------------------------------------------------------------------------

/// Client for interacting with WireGuard via the `wg` CLI.
///
/// Wraps `wg show`, `wg showconf`, and `wg set` commands with proper error
/// handling and output parsing.
///
/// # Construction
///
/// - [`WireguardClient::new`] -- production defaults using a [`DuctRunner`](toride_runner::DuctRunner),
///   verifying `wg` is on `$PATH`.
/// - [`WireguardClient::with_runner`] -- inject a custom command runner (for testing).
pub struct WireguardClient<R: Runner> {
    runner: R,
}

impl WireguardClient<toride_runner::DuctRunner> {
    /// Create a new client using the default command runner.
    ///
    /// Construction is intentionally **lazy**: it does *not* probe for the
    /// `wg` binary. Binary availability is surfaced separately — by the
    /// caller's own `which::which("wg")` probe and by the doctor suite — so
    /// that a handle can be built on any host (e.g. to inspect config/paths)
    /// and operations fail with a clear [`Error::Runner`] only if `wg` is
    /// actually invoked while absent. Probing here would short-circuit the
    /// app's "cheap probes run on every poll, even cache-hit" design.
    pub fn new() -> Result<Self> {
        tracing::debug!("creating WireguardClient");
        Ok(Self {
            runner: toride_runner::DuctRunner,
        })
    }
}

impl<R: Runner> WireguardClient<R> {
    /// Create a client with a custom command runner (for testing).
    #[must_use]
    pub fn with_runner(runner: R) -> Self {
        Self { runner }
    }

    /// Build the `wg show all dump` command spec.
    ///
    /// Uses the machine-readable `dump` subcommand documented in `wg`(8)
    /// rather than the human-oriented default `wg show` output (which emits
    /// verbose multi-line `interface:`/`peer:` blocks that are awkward to
    /// parse). `wg show all dump` prints one tab-separated row per interface
    /// followed by one row per peer, with the interface name as the leading
    /// field of every row.
    ///
    /// [`wg`(8)]: https://www.mankier.com/8/wg
    fn show_spec() -> CommandSpec {
        CommandSpec::new("wg")
            .args(["show", "all", "dump"])
            .timeout(Duration::from_secs(WG_TIMEOUT_SECS))
    }

    /// Show all WireGuard interfaces.
    ///
    /// Executes `wg show all dump` and parses the output into [`WgShowEntry`]
    /// interface summaries (one per configured interface).
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the command fails.
    pub fn show(&self) -> Result<Vec<WgShowEntry>> {
        tracing::debug!("running `wg show all dump`");
        let output = self.runner.run_checked(&Self::show_spec())?;
        parse_wg_show(&output.stdout)
    }

    /// Build the `wg showconf <interface>` command spec.
    fn showconf_spec(interface: &str) -> CommandSpec {
        CommandSpec::new("wg")
            .args(["showconf", interface])
            .timeout(Duration::from_secs(WG_TIMEOUT_SECS))
    }

    /// Show the configuration for a specific interface.
    ///
    /// Executes `wg showconf <interface>`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the command fails (including when
    /// the interface does not exist).
    pub fn showconf(&self, interface: &str) -> Result<String> {
        tracing::debug!("running `wg showconf {interface}`");
        let output = self.runner.run_checked(&Self::showconf_spec(interface))?;
        Ok(output.stdout)
    }

    /// Build the `wg setconf <interface>` command spec.
    ///
    /// `wg setconf` reads its configuration from stdin, so the config text is
    /// passed via [`CommandSpec::stdin`]. The spec is marked `redact(true)` so
    /// any embedded private keys are scrubbed from error messages and logs.
    fn setconf_spec(interface: &str, config: &str) -> CommandSpec {
        CommandSpec::new("wg")
            .args(["setconf", interface, "/dev/stdin"])
            .stdin(config)
            .redact(true)
            .timeout(Duration::from_secs(WG_TIMEOUT_SECS))
    }

    /// Set a configuration on a running interface.
    ///
    /// Executes `wg setconf <interface>` with the config piped via stdin
    /// (`/dev/stdin`). Redaction is enabled because config commonly embeds a
    /// private key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the command fails.
    pub fn setconf(&self, interface: &str, config: &str) -> Result<()> {
        tracing::debug!("running `wg setconf {interface}`");
        let _ = self
            .runner
            .run_checked(&Self::setconf_spec(interface, config))?;
        Ok(())
    }

    /// Build the `wg syncconf <interface>` command spec.
    ///
    /// As with `setconf`, the config is supplied via stdin and redaction is
    /// enabled because it may contain a private key.
    fn syncconf_spec(interface: &str, config: &str) -> CommandSpec {
        CommandSpec::new("wg")
            .args(["syncconf", interface, "/dev/stdin"])
            .stdin(config)
            .redact(true)
            .timeout(Duration::from_secs(WG_TIMEOUT_SECS))
    }

    /// Sync a configuration to a running interface without tearing down the
    /// existing tunnel.
    ///
    /// Executes `wg syncconf <interface> /dev/stdin` with the config text piped
    /// via stdin. Redaction is enabled for the same reason as [`setconf`](Self::setconf).
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the command fails.
    pub fn syncconf(&self, interface: &str, config: &str) -> Result<()> {
        tracing::debug!("running `wg syncconf {interface}`");
        let _ = self
            .runner
            .run_checked(&Self::syncconf_spec(interface, config))?;
        Ok(())
    }

    /// Return a reference to the underlying runner.
    #[must_use]
    pub fn runner(&self) -> &R {
        &self.runner
    }
}

impl<R: Runner + Default> Default for WireguardClient<R> {
    fn default() -> Self {
        Self {
            runner: R::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use toride_runner::fake::FakeRunner;

    #[test]
    fn show_parses_real_wg_show_all_dump() {
        // Real `wg show all dump` output reproduced from the man-page-corroborated
        // Pro Custodibus monitoring guide:
        // https://www.procustodibus.com/blog/2021/01/how-to-monitor-wireguard-activity/
        // Layout documented in wg(8): interface row then one row per peer,
        // interface name leading each row, tab-separated.
        let canned = "\
wg1\tAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEE=\t/TOE4TKtAqVsePRVR+5AA43HkAK5DSntkOCO7nYq5xU=\t51821\toff\n\
wg1\tfE/wdxzl0klVp/IR8UcaoGUMjqaWi3jAd7KzHKFS6Ds=\t(none)\t172.19.0.8:51822\t10.0.0.2/32\t1617235493\t3481633\t33460136\toff\n\
";
        let runner =
            FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(canned));
        let client = WireguardClient::with_runner(runner);
        let entries = client.show().unwrap();
        // One interface row surfaced; the peer row is skipped.
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].interface, "wg1");
        assert_eq!(
            entries[0].public_key,
            "/TOE4TKtAqVsePRVR+5AA43HkAK5DSntkOCO7nYq5xU="
        );
        assert_eq!(entries[0].listen_port, 51821);
    }

    #[test]
    fn show_builds_exact_command() {
        let runner = FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(""));
        let client = WireguardClient::with_runner(runner);
        let _ = client.show();
        // The exact command shape that must be sent to the runner. Using the
        // machine-readable `dump` format documented in wg(8).
        let expected = CommandSpec::new("wg").args(["show", "all", "dump"]);
        client.runner().assert_called_with(&expected);
    }

    #[test]
    fn show_propagates_command_failure() {
        let runner =
            FakeRunner::new().push_response(toride_runner::CommandOutput::from_stderr("exit 1", 1));
        let client = WireguardClient::with_runner(runner);
        let err = client.show().unwrap_err();
        assert!(matches!(err, Error::Runner(_)), "got {err:?}");
    }

    #[test]
    fn showconf_returns_config_text() {
        let conf = "[Interface]\nListenPort = 51820\n";
        let runner =
            FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(conf));
        let client = WireguardClient::with_runner(runner);
        let out = client.showconf("wg0").unwrap();
        assert_eq!(out, conf);
        client
            .runner()
            .assert_called_with(&CommandSpec::new("wg").args(["showconf", "wg0"]));
    }

    #[test]
    fn setconf_passes_config_via_stdin_and_redacts() {
        let runner = FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(""));
        let client = WireguardClient::with_runner(runner);
        let config = "[Interface]\nPrivateKey = secret==\n";
        client.setconf("wg0", config).unwrap();

        let calls = client.runner().calls();
        let setconf_call = calls
            .iter()
            .find(|c| c.program == "wg" && c.args.first().is_some_and(|a| a == "setconf"))
            .expect("wg setconf was called");
        assert_eq!(setconf_call.args, vec!["setconf", "wg0", "/dev/stdin"]);
        assert_eq!(setconf_call.stdin.as_deref(), Some(config));
        assert!(
            setconf_call.redact,
            "config carrying a private key must be redacted"
        );
    }

    #[test]
    fn syncconf_passes_config_via_stdin_and_redacts() {
        let runner = FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(""));
        let client = WireguardClient::with_runner(runner);
        let config = "[Interface]\nPrivateKey = secret==\n";
        client.syncconf("wg0", config).unwrap();

        let calls = client.runner().calls();
        let sync_call = calls
            .iter()
            .find(|c| c.program == "wg" && c.args.first().is_some_and(|a| a == "syncconf"))
            .expect("wg syncconf was called");
        assert_eq!(sync_call.args, vec!["syncconf", "wg0", "/dev/stdin"]);
        assert_eq!(sync_call.stdin.as_deref(), Some(config));
        assert!(sync_call.redact);
    }

    #[test]
    fn runner_accessor_exposes_underlying_runner() {
        let runner = FakeRunner::new();
        let client = WireguardClient::with_runner(runner);
        // Sanity: the accessor returns the injected runner.
        let _ = client.runner();
    }
}
