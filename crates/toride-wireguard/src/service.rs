//! `wg-quick` service management via `toride-service`.
//!
//! Provides start/stop/restart operations for WireGuard tunnels using
//! `wg-quick` and integrates with `toride-service::ServiceManager` for
//! systemd service lifecycle (enable/disable/is-active) on the
//! `wg-quick@<interface>` unit.
//!
//! `up`/`down`/`restart` run `wg-quick` directly through the
//! [`Runner`](toride_runner::Runner) trait; `is_active`/`enable`/`disable`
//! delegate to [`ServiceManager`](toride_service::ServiceManager) (which in
//! turn shells out to `systemctl` through the same runner).

use std::time::Duration;

use toride_runner::{CommandSpec, Runner};
use toride_service::ServiceManager;

use crate::error::{Error, Result};

/// Timeout for `wg-quick` operations (they can take a few seconds to bring
/// an interface up, including address assignment and route setup).
const WG_QUICK_TIMEOUT_SECS: u64 = 30;

// ---------------------------------------------------------------------------
// WireguardService
// ---------------------------------------------------------------------------

/// Manages `wg-quick` service operations for a WireGuard interface.
///
/// Wraps `wg-quick up/down` commands and delegates systemd queries
/// (`is-active`, `enable`, `disable`) to [`ServiceManager`] for the
/// `wg-quick@<interface>` unit.
///
/// # Construction
///
/// - [`WireguardService::new`] -- production runner (`DuctRunner`).
/// - [`WireguardService::with_runner`] -- inject a custom runner (for testing).
pub struct WireguardService<R>
where
    R: Runner + Send + Sync + 'static,
{
    interface: String,
    runner: std::sync::Arc<R>,
}

impl WireguardService<toride_runner::DuctRunner> {
    /// Create a new service manager for the given interface using the default
    /// production runner.
    #[must_use]
    pub fn new(interface: &str) -> Self {
        Self {
            interface: interface.to_owned(),
            runner: std::sync::Arc::new(toride_runner::DuctRunner),
        }
    }
}

impl<R> WireguardService<R>
where
    R: Runner + Send + Sync + 'static,
{
    /// Create a service manager with a custom command runner (for testing).
    #[must_use]
    pub fn with_runner(interface: &str, runner: R) -> Self {
        Self {
            interface: interface.to_owned(),
            runner: std::sync::Arc::new(runner),
        }
    }

    /// Returns the interface name.
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Returns the systemd service name (`wg-quick@<interface>`).
    pub fn service_name(&self) -> String {
        format!("wg-quick@{}", self.interface)
    }

    /// Build the `wg-quick <verb> <interface>` command spec.
    fn wg_quick_spec(&self, verb: &str) -> CommandSpec {
        CommandSpec::new("wg-quick")
            .args([verb, self.interface.as_str()])
            .timeout(Duration::from_secs(WG_QUICK_TIMEOUT_SECS))
    }

    /// Bring the interface up using `wg-quick up <interface>`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the command fails.
    pub fn up(&self) -> Result<()> {
        tracing::info!("bringing up WireGuard interface {}", self.interface);
        let spec = self.wg_quick_spec("up");
        let output = self.runner.run(&spec)?;
        if output.success {
            Ok(())
        } else {
            Err(command_failed(
                "wg-quick up",
                &self.interface,
                &spec,
                &output,
            ))
        }
    }

    /// Bring the interface down using `wg-quick down <interface>`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the command fails.
    pub fn down(&self) -> Result<()> {
        tracing::info!("bringing down WireGuard interface {}", self.interface);
        let spec = self.wg_quick_spec("down");
        let output = self.runner.run(&spec)?;
        if output.success {
            Ok(())
        } else {
            Err(command_failed(
                "wg-quick down",
                &self.interface,
                &spec,
                &output,
            ))
        }
    }

    /// Restart the interface (down then up).
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if either command fails.
    pub fn restart(&self) -> Result<()> {
        tracing::info!("restarting WireGuard interface {}", self.interface);
        self.down()?;
        self.up()
    }

    /// Build a `ServiceManager` backed by a reference-counted clone of this
    /// service's runner, via the [`RunnerRef`] adapter. This lets a single
    /// injected `Runner` (e.g. a `FakeRunner`) service both `wg-quick` and
    /// `systemctl` calls.
    fn service_manager(&self) -> ServiceManager {
        ServiceManager::new(Box::new(RunnerRef(self.runner.clone())))
    }

    /// Check if the interface is currently up by querying `systemctl is-active`.
    ///
    /// Delegates to [`ServiceManager::is_active`] for the
    /// `wg-quick@<interface>` unit. A non-active unit returns `Ok(false)` --
    /// only a system error (e.g. `systemctl` cannot run) is surfaced.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the status cannot be determined.
    pub fn is_active(&self) -> Result<bool> {
        tracing::debug!("checking if interface {} is active", self.interface);
        let mgr = self.service_manager();
        mgr.is_active(&self.service_name())
            .map_err(|e| service_error_to_crate(&e))
    }

    /// Enable the service to start on boot via systemd.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the command fails.
    pub fn enable(&self) -> Result<()> {
        tracing::info!("enabling WireGuard service {}", self.service_name());
        let mgr = self.service_manager();
        mgr.enable(&self.service_name())
            .map_err(|e| service_error_to_crate(&e))
    }

    /// Disable the service from starting on boot.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the command fails.
    pub fn disable(&self) -> Result<()> {
        tracing::info!("disabling WireGuard service {}", self.service_name());
        let mgr = self.service_manager();
        mgr.disable(&self.service_name())
            .map_err(|e| service_error_to_crate(&e))
    }

    /// Return a reference to the underlying runner.
    /// Return a reference to the underlying runner.
    #[must_use]
    pub fn runner(&self) -> &R {
        &self.runner
    }
}

// NOTE: `self.runner` is an `Arc<R>`; `&self.runner` derefs to `&R` via
// deref-coercion through `Arc`'s `Deref` impl.

// ---------------------------------------------------------------------------
// RunnerRef -- adapter that lets ServiceManager share an Arc'd runner.
// ---------------------------------------------------------------------------

/// A `Runner` wrapper holding a reference-counted clone of an underlying
/// runner, so the same runner (e.g. a `FakeRunner`) can back both
/// `WireguardService`'s `wg-quick` calls and the `ServiceManager`'s
/// `systemctl` calls.
///
/// `ServiceManager::new` requires a `Box<dyn Runner + 'static>`; an `Arc`
/// satisfies that lifetime while still sharing state.
struct RunnerRef<R: Runner + Send + Sync>(std::sync::Arc<R>);

impl<R: Runner + Send + Sync> Clone for RunnerRef<R> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<R: Runner + Send + Sync> Runner for RunnerRef<R> {
    fn run(
        &self,
        spec: &CommandSpec,
    ) -> std::result::Result<toride_runner::CommandOutput, toride_runner::Error> {
        self.0.run(spec)
    }
}

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

/// Build an [`Error::CommandFailed`] from a failed command's output.
///
/// The captured stderr is routed through
/// [`toride_runner::display::scrub_stderr`](toride_runner::display::scrub_stderr)
/// for consistency with [`net`](crate::net): it applies the canonical length
/// cap and, when the spec carries `redact(true)`, scrubs any secret values that
/// the failed command may have echoed to stderr.
fn command_failed(
    label: &str,
    interface: &str,
    spec: &CommandSpec,
    output: &toride_runner::CommandOutput,
) -> Error {
    let code = output
        .exit_code
        .map_or("signal".to_owned(), |c| c.to_string());
    // Scrub (cap + redact-when-needed) the raw stderr before embedding it in
    // the error detail string. This mirrors net.rs and keeps error variants
    // bounded in size and free of accidental secret leaks.
    let stderr = toride_runner::display::scrub_stderr(spec, output.stderr.trim());
    let detail = if stderr.is_empty() {
        format!("{label} {interface} failed (exit {code})")
    } else {
        format!("{label} {interface} failed (exit {code}): {stderr}")
    };
    Error::CommandFailed(detail)
}

/// Map a `toride_service::Error` into the crate error type.
fn service_error_to_crate(err: &toride_service::Error) -> Error {
    Error::CommandFailed(err.to_string())
}

impl<R> Default for WireguardService<R>
where
    R: Runner + Default + Send + Sync + 'static,
{
    fn default() -> Self {
        Self {
            interface: "wg0".to_owned(),
            runner: std::sync::Arc::new(R::default()),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use toride_runner::fake::FakeRunner;

    #[test]
    fn service_name_format() {
        let svc = WireguardService::new("wg0");
        assert_eq!(svc.service_name(), "wg-quick@wg0");
        assert_eq!(svc.interface(), "wg0");
    }

    #[test]
    fn up_builds_wg_quick_up_command() {
        let runner = FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(""));
        let svc = WireguardService::with_runner("wg0", runner);
        svc.up().unwrap();
        svc.runner()
            .assert_called_with(&CommandSpec::new("wg-quick").args(["up", "wg0"]));
    }

    #[test]
    fn down_builds_wg_quick_down_command() {
        let runner = FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(""));
        let svc = WireguardService::with_runner("wg1", runner);
        svc.down().unwrap();
        svc.runner()
            .assert_called_with(&CommandSpec::new("wg-quick").args(["down", "wg1"]));
    }

    #[test]
    fn up_propagates_failure() {
        let runner = FakeRunner::new().push_response(toride_runner::CommandOutput::from_stderr(
            "no such interface",
            1,
        ));
        let svc = WireguardService::with_runner("wg0", runner);
        let err = svc.up().unwrap_err();
        assert!(matches!(err, Error::CommandFailed(_)), "got {err:?}");
    }

    #[test]
    fn up_failure_stderr_is_scrubbed() {
        // Real `wg-quick up` failure stderr (from a missing-config / missing-
        // module host), reproduced from community reports:
        //   wg-quick: '/etc/wireguard/wg0.conf' does not exist
        //   RTNETLINK answers: No such device
        // Refs: https://forum.yunohost.org/t/...wg-quick@wg0-is-failed.../20147
        //       https://github.com/wg-easy/wg-easy/issues/1931
        // The point of this test: the error detail is built via
        // toride_runner::display::scrub_stderr (consistency with net.rs), so a
        // bounded real-world stderr round-trips into the error message.
        let stderr = "wg-quick: '/etc/wireguard/wg0.conf' does not exist\n\
                      RTNETLINK answers: No such device\n";
        let runner =
            FakeRunner::new().push_response(toride_runner::CommandOutput::from_stderr(stderr, 1));
        let svc = WireguardService::with_runner("wg0", runner);
        let err = svc.up().unwrap_err();
        match err {
            Error::CommandFailed(msg) => {
                assert!(msg.contains("wg-quick up wg0 failed"), "got: {msg}");
                assert!(msg.contains("does not exist"), "stderr preserved: {msg}");
                assert!(msg.contains("No such device"), "stderr preserved: {msg}");
            }
            other => panic!("expected CommandFailed, got {other:?}"),
        }
    }

    #[test]
    fn up_failure_stderr_capped() {
        // scrub_stderr caps stderr at STDERR_CAP_BYTES (4 KiB) so an unbounded
        // failure burst cannot blow up the error variant. This is the
        // consistency guarantee net.rs already relied on.
        let big = "x".repeat(toride_runner::display::STDERR_CAP_BYTES + 5_000);
        let runner =
            FakeRunner::new().push_response(toride_runner::CommandOutput::from_stderr(&big, 1));
        let svc = WireguardService::with_runner("wg0", runner);
        let err = svc.up().unwrap_err();
        match err {
            Error::CommandFailed(msg) => {
                // Marker appended by scrub_stderr when it truncates.
                assert!(
                    msg.contains(toride_runner::display::STDERR_TRUNCATION_MARKER),
                    "got: {msg}"
                );
                assert!(msg.len() < big.len(), "must be capped");
            }
            other => panic!("expected CommandFailed, got {other:?}"),
        }
    }

    #[test]
    fn restart_runs_down_then_up() {
        let runner = FakeRunner::new()
            .push_response(toride_runner::CommandOutput::from_stdout("")) // down
            .push_response(toride_runner::CommandOutput::from_stdout("")); // up
        let svc = WireguardService::with_runner("wg0", runner);
        svc.restart().unwrap();
        let calls = svc.runner().calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].args, vec!["down", "wg0"]);
        assert_eq!(calls[1].args, vec!["up", "wg0"]);
    }

    #[test]
    fn is_active_queries_systemctl_via_service_manager() {
        // `systemctl is-active` returns exit 0 with "active" on stdout when active.
        // The same injected runner backs both wg-quick and the ServiceManager.
        let runner =
            FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout("active"));
        let svc = WireguardService::with_runner("wg0", runner);
        let active = svc.is_active().unwrap();
        assert!(active);
        svc.runner()
            .assert_called_with(&CommandSpec::new("systemctl").args(["is-active", "wg-quick@wg0"]));
    }

    #[test]
    fn is_active_returns_false_when_inactive() {
        // systemctl is-active exits non-zero when the unit is inactive.
        let runner = FakeRunner::new()
            .push_response(toride_runner::CommandOutput::from_stderr("inactive", 3));
        let svc = WireguardService::with_runner("wg0", runner);
        let active = svc.is_active().unwrap();
        assert!(!active);
    }

    #[test]
    fn enable_runs_systemctl_enable() {
        let runner = FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(""));
        let svc = WireguardService::with_runner("wg0", runner);
        svc.enable().unwrap();
        svc.runner()
            .assert_called_with(&CommandSpec::new("systemctl").args(["enable", "wg-quick@wg0"]));
    }

    #[test]
    fn disable_runs_systemctl_disable() {
        let runner = FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(""));
        let svc = WireguardService::with_runner("wg0", runner);
        svc.disable().unwrap();
        svc.runner()
            .assert_called_with(&CommandSpec::new("systemctl").args(["disable", "wg-quick@wg0"]));
    }
}
