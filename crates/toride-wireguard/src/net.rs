//! Network interface helpers for WireGuard.
//!
//! Provides utilities for querying and managing WireGuard network interfaces,
//! including listing interfaces, checking interface status, and reading
//! transfer statistics. All commands go through the
//! [`Runner`](toride_runner::Runner) trait, so the helpers are testable with
//! [`FakeRunner`](toride_runner::FakeRunner) without root or a real `wg`.

use std::time::Duration;

use toride_runner::{CommandSpec, Runner};

use crate::error::{Error, Result};
use crate::validate::validate_interface_name;

/// Timeout for `ip` / `wg` queries.
const NET_TIMEOUT_SECS: u64 = 10;

// ---------------------------------------------------------------------------
// InterfaceStatus
// ---------------------------------------------------------------------------

/// Status of a WireGuard network interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterfaceStatus {
    /// Interface exists and is up.
    Up,
    /// Interface exists but is down.
    Down,
    /// Interface does not exist.
    NotFound,
}

// ---------------------------------------------------------------------------
// NetworkInterface helpers
// ---------------------------------------------------------------------------

/// Check whether a network interface exists on the system.
///
/// Uses `ip link show <name>` to determine presence. Returns `Ok(false)` when
/// the command exits non-zero with a "Device not found" message (i.e. the
/// interface genuinely does not exist) and `Ok(true)` when it exits zero.
///
/// # Errors
///
/// Returns [`Error::InvalidAddress`] if the name fails validation, or
/// [`Error::Runner`] if the command cannot be run.
pub fn interface_exists(name: &str) -> Result<bool> {
    let runner = toride_runner::DuctRunner;
    interface_exists_with(&runner, name)
}

/// Like [`interface_exists`] but using an explicit runner (for testing).
///
/// # Errors
///
/// Returns [`Error::InvalidAddress`] or [`Error::Runner`] as above.
pub fn interface_exists_with<R: Runner>(runner: &R, name: &str) -> Result<bool> {
    validate_interface_name(name)?;
    tracing::debug!("checking existence of interface: {name}");
    let spec = ip_link_show_spec(name);
    let output = runner.run(&spec)?;
    if output.success {
        return Ok(true);
    }
    // `ip link show` on a missing device exits non-zero and prints
    // "Device \"<name>\" does not exist." on stderr.
    let stderr = output.stderr.to_lowercase();
    if stderr.contains("does not exist") || stderr.contains("not found") {
        Ok(false)
    } else {
        Err(Error::Runner(toride_runner::Error::CommandFailed {
            program: spec.program.clone(),
            args: toride_runner::display::redacted_args_display(&spec),
            exit_code: output.exit_code,
            stderr: toride_runner::display::scrub_stderr(&spec, &output.stderr),
        }))
    }
}

/// Get the current status (up/down/missing) of a WireGuard interface.
///
/// Uses `ip link show <name>` to determine presence, then inspects the
/// returned line for the `UP` flag.
///
/// # Errors
///
/// Returns [`Error::InvalidAddress`] if the name fails validation, or
/// [`Error::Runner`] if the command cannot be run.
pub fn interface_status(name: &str) -> Result<InterfaceStatus> {
    let runner = toride_runner::DuctRunner;
    interface_status_with(&runner, name)
}

/// Like [`interface_status`] but using an explicit runner (for testing).
///
/// # Errors
///
/// Returns [`Error::InvalidAddress`] or [`Error::Runner`] as above.
pub fn interface_status_with<R: Runner>(runner: &R, name: &str) -> Result<InterfaceStatus> {
    validate_interface_name(name)?;
    tracing::debug!("querying status of interface: {name}");
    let spec = ip_link_show_spec(name);
    let output = runner.run(&spec)?;
    if !output.success {
        let stderr = output.stderr.to_lowercase();
        if stderr.contains("does not exist") || stderr.contains("not found") {
            return Ok(InterfaceStatus::NotFound);
        }
        return Err(Error::Runner(toride_runner::Error::CommandFailed {
            program: spec.program.clone(),
            args: toride_runner::display::redacted_args_display(&spec),
            exit_code: output.exit_code,
            stderr: toride_runner::display::scrub_stderr(&spec, &output.stderr),
        }));
    }
    // `ip link show` prints a line like:
    //   "2: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 ..."
    // The presence of `UP` in the `<...>` flag set indicates the link is up.
    if output.stdout.contains("UP") {
        Ok(InterfaceStatus::Up)
    } else {
        Ok(InterfaceStatus::Down)
    }
}

/// List all WireGuard interfaces currently on the system.
///
/// Runs `wg show interfaces`, which prints a space-separated list of
/// interface names on a single line.
///
/// # Errors
///
/// Returns [`Error::Runner`] if the command fails.
pub fn list_wireguard_interfaces() -> Result<Vec<String>> {
    let runner = toride_runner::DuctRunner;
    list_wireguard_interfaces_with(&runner)
}

/// Like [`list_wireguard_interfaces`] but using an explicit runner.
///
/// # Errors
///
/// Returns [`Error::Runner`] if the command fails.
pub fn list_wireguard_interfaces_with<R: Runner>(runner: &R) -> Result<Vec<String>> {
    tracing::debug!("listing WireGuard interfaces");
    let spec = CommandSpec::new("wg")
        .args(["show", "interfaces"])
        .timeout(Duration::from_secs(NET_TIMEOUT_SECS));
    let output = runner.run_checked(&spec)?;
    let ifaces = output
        .stdout
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    Ok(ifaces)
}

/// Get the transfer statistics (bytes sent/received) for an interface.
///
/// Runs `wg show <name> transfer`, which prints `<rx_bytes> <tx_bytes>` per
/// peer line. The totals are summed across all peers.
///
/// # Errors
///
/// Returns [`Error::InvalidAddress`] if the name fails validation, or
/// [`Error::Runner`] if the command fails. Returns zero stats for an
/// interface with no transfer counters yet (still a valid result).
pub fn interface_stats(name: &str) -> Result<InterfaceStats> {
    let runner = toride_runner::DuctRunner;
    interface_stats_with(&runner, name)
}

/// Like [`interface_stats`] but using an explicit runner.
///
/// # Errors
///
/// Returns [`Error::InvalidAddress`] or [`Error::Runner`] as above.
pub fn interface_stats_with<R: Runner>(runner: &R, name: &str) -> Result<InterfaceStats> {
    validate_interface_name(name)?;
    tracing::debug!("querying transfer stats for interface: {name}");
    let spec = CommandSpec::new("wg")
        .args(["show", name, "transfer"])
        .timeout(Duration::from_secs(NET_TIMEOUT_SECS));
    let output = runner.run_checked(&spec)?;

    let mut stats = InterfaceStats::default();
    // Each line is "<peer_pubkey>\t<rx_bytes>\t<tx_bytes>".
    for line in output.stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        if let Ok(rx) = parts[1].parse::<u64>() {
            stats.bytes_received += rx;
        }
        if let Ok(tx) = parts[2].parse::<u64>() {
            stats.bytes_sent += tx;
        }
    }
    Ok(stats)
}

/// Build the `ip link show <name>` command spec.
fn ip_link_show_spec(name: &str) -> CommandSpec {
    CommandSpec::new("ip")
        .args(["link", "show", name])
        .timeout(Duration::from_secs(NET_TIMEOUT_SECS))
}

/// Transfer statistics for a WireGuard interface.
#[derive(Debug, Clone, Default)]
pub struct InterfaceStats {
    /// Total bytes received.
    pub bytes_received: u64,
    /// Total bytes sent.
    pub bytes_sent: u64,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use toride_runner::fake::FakeRunner;

    #[test]
    fn validate_name_before_checking() {
        // Should fail validation, not reach the implementation.
        let runner = FakeRunner::new();
        let result = interface_exists_with(&runner, "eth0");
        assert!(result.is_err());
    }

    #[test]
    fn stats_default() {
        let stats = InterfaceStats::default();
        assert_eq!(stats.bytes_received, 0);
        assert_eq!(stats.bytes_sent, 0);
    }

    #[test]
    fn interface_exists_true_when_ip_link_succeeds() {
        let runner = FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(
            "2: wg0: <UP> mtu 1420",
        ));
        let exists = interface_exists_with(&runner, "wg0").unwrap();
        assert!(exists);
        runner.assert_called_with(&CommandSpec::new("ip").args(["link", "show", "wg0"]));
    }

    #[test]
    fn interface_exists_false_when_device_missing() {
        let runner = FakeRunner::new().push_response(toride_runner::CommandOutput::from_stderr(
            "Device \"wg0\" does not exist.",
            1,
        ));
        let exists = interface_exists_with(&runner, "wg0").unwrap();
        assert!(!exists);
    }

    #[test]
    fn interface_exists_propagates_other_errors() {
        let runner = FakeRunner::new().push_response(toride_runner::CommandOutput::from_stderr(
            "permission denied",
            1,
        ));
        let result = interface_exists_with(&runner, "wg0");
        assert!(result.is_err());
    }

    #[test]
    fn interface_status_up_when_flag_present() {
        let runner = FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(
            "2: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420",
        ));
        let status = interface_status_with(&runner, "wg0").unwrap();
        assert_eq!(status, InterfaceStatus::Up);
    }

    #[test]
    fn interface_status_down_when_no_up_flag() {
        let runner = FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(
            "2: wg0: <POINTOPOINT,NOARP> mtu 1420",
        ));
        let status = interface_status_with(&runner, "wg0").unwrap();
        assert_eq!(status, InterfaceStatus::Down);
    }

    #[test]
    fn interface_status_not_found_when_missing() {
        let runner = FakeRunner::new().push_response(toride_runner::CommandOutput::from_stderr(
            "Device \"wg0\" does not exist.",
            1,
        ));
        let status = interface_status_with(&runner, "wg0").unwrap();
        assert_eq!(status, InterfaceStatus::NotFound);
    }

    #[test]
    fn list_wireguard_interfaces_parses_space_separated() {
        let canned = "wg0 wg1 wg2\n";
        let runner =
            FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(canned));
        let ifaces = list_wireguard_interfaces_with(&runner).unwrap();
        assert_eq!(ifaces, vec!["wg0", "wg1", "wg2"]);
        runner.assert_called_with(&CommandSpec::new("wg").args(["show", "interfaces"]));
    }

    #[test]
    fn list_wireguard_interfaces_empty_when_none() {
        let runner = FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(""));
        let ifaces = list_wireguard_interfaces_with(&runner).unwrap();
        assert!(ifaces.is_empty());
    }

    #[test]
    fn interface_stats_sums_per_peer_counters() {
        // Two peers, each with rx/tx columns.
        let canned = "AAAkey==\t1024\t2048\nBBBkey==\t512\t128\n";
        let runner =
            FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(canned));
        let stats = interface_stats_with(&runner, "wg0").unwrap();
        assert_eq!(stats.bytes_received, 1024 + 512);
        assert_eq!(stats.bytes_sent, 2048 + 128);
        runner.assert_called_with(&CommandSpec::new("wg").args(["show", "wg0", "transfer"]));
    }

    #[test]
    fn interface_stats_zero_when_no_peers() {
        let runner = FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(""));
        let stats = interface_stats_with(&runner, "wg0").unwrap();
        assert_eq!(stats.bytes_received, 0);
        assert_eq!(stats.bytes_sent, 0);
    }

    #[test]
    fn interface_stats_skips_malformed_lines() {
        let canned = "garbage line\nAAAkey==\t100\t200\n";
        let runner =
            FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(canned));
        let stats = interface_stats_with(&runner, "wg0").unwrap();
        assert_eq!(stats.bytes_received, 100);
        assert_eq!(stats.bytes_sent, 200);
    }
}
