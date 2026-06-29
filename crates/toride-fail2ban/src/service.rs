//! Service manager layer wrapping `systemctl`.
//!
//! [`ServiceManager`] provides a typed interface for controlling the Fail2Ban
//! systemd service.  Every operation goes through the centralised [`Runner`]
//! trait so that the entire call stack remains testable via [`FakeRunner`] and
//! respects dry-run mode automatically.
//!
//! # Quick start
//!
//! ```ignore
//! use toride_fail2ban::command::DuctRunner;
//! use toride_fail2ban::service::ServiceManager;
//!
//! let runner = DuctRunner::new();
//! let svc = ServiceManager::new(&runner);
//!
//! if svc.is_active()? {
//!     svc.restart()?;
//! }
//! ```
//!
//! # Implementation tiers
//!
//! - **Current (default):** Uses `systemctl` through the [`Runner`] trait for all
//!   service operations (start, stop, restart, status queries, journal access).
//!   This is the production path and works on any system with systemd installed.
//!
//! - **Optional `systemd-zbus` feature:** Direct D-Bus communication with systemd
//!   via the `zbus` crate, avoiding the `systemctl` process spawn entirely.  This
//!   enables lower-latency service control and richer structured metadata from
//!   systemd properties.  **Not yet implemented.**
//!
//! - **Optional `service-manager` feature:** A portable service management
//!   abstraction that works across init systems (OpenRC, runit, s6, etc.), not
//!   just systemd.  **Not yet implemented.**
//!
//! # Non-systemd environments
//!
//! In v1 the service manager targets `systemctl` exclusively.  For non-systemd
//! hosts the caller can supply a [`FakeRunner`] that translates calls to the
//! local service manager, or simply avoid using this module altogether -- many
//! applications should only manage config and let the deploy system handle
//! restarts.

// ---------------------------------------------------------------------------
// Feature-gated stubs for planned backends
// ---------------------------------------------------------------------------

// The `systemd-zbus` feature is planned but not yet implemented.
//
// When complete it will provide direct D-Bus communication with systemd,
// removing the need to shell out to `systemctl` for each operation.
// Enable with `cargo build --features systemd-zbus`.
//
// FIXME: implement the D-Bus backend when the `systemd-zbus` feature is
// activated.  The stub below shows the intended public surface; each method
// should delegate to `zbus_systemd` instead of spawning `systemctl`.
//
// #[cfg(feature = "systemd-zbus")]
// mod zbus_backend { ... }

/// Placeholder module that marks the `systemd-zbus` feature as unimplemented.
///
/// Enabling the feature currently has no effect beyond reserving the feature
/// gate.  Once the `zbus_systemd` dependency is wired in, this module will be
/// replaced with a D-Bus–backed [`ServiceManager`] variant.
#[cfg(feature = "systemd-zbus")]
pub mod systemd_zbus_stub {
    //! **Not yet implemented.** This module exists so that the `systemd-zbus`
    //! feature compiles without pulling in the heavy `zbus` dependency in v1.
    //! See the project roadmap for scheduling.
}

use crate::command::{CommandOutput, Runner};
use crate::{Error, Result};

// ---------------------------------------------------------------------------
// Re-export from toride-service
// ---------------------------------------------------------------------------

/// Re-export of the shared [`toride_service::ServiceManager`] type.
///
/// The shared type owns a `Box<dyn Runner>` and takes the service name per
/// method call. The local [`ServiceManager`] borrows `&dyn Runner` and has a
/// fixed service name set at construction, which is more ergonomic for the
/// fail2ban use case.
pub use toride_service::ServiceManager as SharedServiceManager;

// ---------------------------------------------------------------------------
// ServiceManager
// ---------------------------------------------------------------------------

/// Manages the Fail2Ban systemd service through a [`Runner`].
///
/// Holds a borrowed reference to a `Runner` implementation, so the manager is
/// cheap to create and has no ownership of the runner itself.  The default
/// service unit name is `"fail2ban"` but can be overridden for testing or
/// non-standard installations.
pub struct ServiceManager<'a> {
    /// The command runner used to execute `systemctl` and `journalctl`.
    runner: &'a dyn Runner,
    /// The systemd unit name (without the `.service` suffix).
    service_name: String,
}

impl<'a> ServiceManager<'a> {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Create a manager targeting the default `"fail2ban"` service unit.
    pub fn new(runner: &'a dyn Runner) -> Self {
        Self {
            runner,
            service_name: "fail2ban".to_owned(),
        }
    }

    /// Create a manager targeting a custom service unit name.
    ///
    /// Use this when managing multiple Fail2Ban instances or in integration
    /// tests that run under a different unit name.
    pub fn with_service_name(runner: &'a dyn Runner, name: &str) -> Self {
        Self {
            runner,
            service_name: name.to_owned(),
        }
    }

    // -----------------------------------------------------------------------
    // Query operations
    // -----------------------------------------------------------------------

    /// Check whether the service unit is currently active (running).
    ///
    /// Returns `Ok(true)` when `systemctl is-active <unit>` exits with code 0,
    /// and `Ok(false)` for any non-zero exit.  This mirrors the `systemctl`
    /// semantics where non-zero indicates "inactive", "failed", or "unknown".
    pub fn is_active(&self) -> Result<bool> {
        let output = self.run_systemctl(&["is-active", &self.service_name])?;
        Ok(output.success)
    }

    /// Check whether the service unit is enabled at boot.
    ///
    /// Returns `Ok(true)` when `systemctl is-enabled <unit>` exits with code 0,
    /// and `Ok(false)` for any non-zero exit.
    pub fn is_enabled(&self) -> Result<bool> {
        let output = self.run_systemctl(&["is-enabled", &self.service_name])?;
        Ok(output.success)
    }

    // -----------------------------------------------------------------------
    // Lifecycle operations
    // -----------------------------------------------------------------------

    /// Start the service unit.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if `systemctl start` exits non-zero.
    pub fn start(&self) -> Result<()> {
        let output = self.run_systemctl(&["start", &self.service_name])?;
        if output.success {
            Ok(())
        } else {
            Err(command_failed(
                "systemctl",
                "start",
                &self.service_name,
                &output,
            ))
        }
    }

    /// Stop the service unit.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if `systemctl stop` exits non-zero.
    pub fn stop(&self) -> Result<()> {
        let output = self.run_systemctl(&["stop", &self.service_name])?;
        if output.success {
            Ok(())
        } else {
            Err(command_failed(
                "systemctl",
                "stop",
                &self.service_name,
                &output,
            ))
        }
    }

    /// Restart the service unit (stop then start).
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if `systemctl restart` exits non-zero.
    pub fn restart(&self) -> Result<()> {
        let output = self.run_systemctl(&["restart", &self.service_name])?;
        if output.success {
            Ok(())
        } else {
            Err(command_failed(
                "systemctl",
                "restart",
                &self.service_name,
                &output,
            ))
        }
    }

    /// Reload the service unit's configuration, or restart it if reloading
    /// is not supported.
    ///
    /// This is the preferred way to apply configuration changes because it
    /// avoids unnecessary downtime when the service supports graceful reload.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if `systemctl reload-or-restart` exits
    /// non-zero.
    pub fn reload_or_restart(&self) -> Result<()> {
        let output = self.run_systemctl(&["reload-or-restart", &self.service_name])?;
        if output.success {
            Ok(())
        } else {
            Err(command_failed(
                "systemctl",
                "reload-or-restart",
                &self.service_name,
                &output,
            ))
        }
    }

    // -----------------------------------------------------------------------
    // Journal access
    // -----------------------------------------------------------------------

    /// Tail recent journal entries for the service unit.
    ///
    /// Returns the last `lines` lines from `journalctl -u <unit> -n <lines>
    /// --no-pager`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if `journalctl` exits non-zero (e.g. the
    /// journal is inaccessible or the unit is unknown).
    pub fn journal_tail(&self, lines: usize) -> Result<String> {
        let lines_arg = lines.to_string();
        let output = self.runner.run(
            "journalctl",
            &["-u", &self.service_name, "-n", &lines_arg, "--no-pager"],
        )?;
        tracing::debug!(
            service = %self.service_name,
            lines,
            exit = ?output.exit_code,
            "journalctl completed"
        );
        if output.success {
            Ok(output.stdout)
        } else {
            Err(command_failed(
                "journalctl",
                "tail",
                &self.service_name,
                &output,
            ))
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Execute a `systemctl` subcommand through the runner.
    ///
    /// Logs the full command at debug level (with sensitive values redacted
    /// by the runner) and returns the captured output.
    fn run_systemctl(&self, args: &[&str]) -> Result<CommandOutput> {
        tracing::debug!(
            service = %self.service_name,
            args = ?args,
            "invoking systemctl"
        );
        self.runner.run("systemctl", args)
    }
}

// ---------------------------------------------------------------------------
// Private helper
// ---------------------------------------------------------------------------

/// Build an [`Error::CommandFailed`] from a failed command's output.
///
/// Includes the program name, subcommand, service unit, exit code, and stderr
/// in a single human-readable message so that callers see enough context to
/// diagnose the failure without digging through structured fields.
fn command_failed(
    program: &str,
    subcommand: &str,
    service_name: &str,
    output: &CommandOutput,
) -> Error {
    let code = output
        .exit_code
        .map_or("signal".to_owned(), |c| c.to_string());
    let stderr = output.stderr.trim();
    let detail = if stderr.is_empty() {
        format!("{program} {subcommand} {service_name} failed (exit {code})")
    } else {
        format!("{program} {subcommand} {service_name} failed (exit {code}): {stderr}")
    };
    Error::CommandFailed(detail)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "service.test.rs"]
mod tests;
