//! Service manager layer wrapping `systemctl`.
//!
//! [`ServiceManager`] provides a typed interface for controlling systemd
//! service units. Every operation goes through the centralised
//! [`toride_runner::Runner`] trait so that the entire call stack remains
//! testable and respects dry-run mode automatically.
//!
//! # Quick start
//!
//! ```ignore
//! use toride_service::ServiceManager;
//! use toride_runner::DuctRunner;
//!
//! let runner = Box::new(DuctRunner::new());
//! let mgr = ServiceManager::new(runner);
//!
//! if mgr.is_active("sshd")? {
//!     mgr.restart("sshd")?;
//! }
//! ```

use crate::{Error, Result};

// ---------------------------------------------------------------------------
// ServiceStatus
// ---------------------------------------------------------------------------

/// Represents the current state of a systemd service unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceStatus {
    /// The service is currently running.
    Active,
    /// The service is stopped.
    Inactive,
    /// The service has failed (exited with an error or was killed).
    Failed,
    /// The service is in the process of starting up.
    Activating,
    /// The service is in an unknown or unrecognized state.
    Unknown,
}

impl std::fmt::Display for ServiceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Inactive => write!(f, "inactive"),
            Self::Failed => write!(f, "failed"),
            Self::Activating => write!(f, "activating"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

impl std::str::FromStr for ServiceStatus {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim() {
            "active" | "running" => Ok(Self::Active),
            "inactive" | "stopped" => Ok(Self::Inactive),
            "failed" => Ok(Self::Failed),
            "activating" => Ok(Self::Activating),
            _ => Ok(Self::Unknown),
        }
    }
}

// ---------------------------------------------------------------------------
// ServiceManager
// ---------------------------------------------------------------------------

/// Manages systemd service units through a [`toride_runner::Runner`].
///
/// Owns a `Box<dyn Runner>`, so the manager has full ownership of the runner
/// lifecycle. All `systemctl` invocations are routed through the runner for
/// testability, logging, and dry-run support.
///
/// # Construction
///
/// - [`ServiceManager::new`] -- inject any `Runner` implementation.
///
/// # Example
///
/// ```ignore
/// use toride_service::ServiceManager;
/// use toride_runner::DuctRunner;
///
/// let mgr = ServiceManager::new(Box::new(DuctRunner::new()));
///
/// if mgr.is_active("nginx")? {
///     mgr.restart("nginx")?;
/// }
/// ```
pub struct ServiceManager {
    /// The command runner used to execute `systemctl`.
    runner: Box<dyn toride_runner::Runner>,
}

impl ServiceManager {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Create a new `ServiceManager` with the given command runner.
    ///
    /// The runner is used for all `systemctl` invocations, making the manager
    /// fully testable via a fake or mock runner.
    pub fn new(runner: Box<dyn toride_runner::Runner>) -> Self {
        Self { runner }
    }

    // -----------------------------------------------------------------------
    // Query operations
    // -----------------------------------------------------------------------

    /// Check whether the service unit is currently active (running).
    ///
    /// Returns `Ok(true)` when `systemctl is-active <service>` exits with
    /// code 0, and `Ok(false)` for any non-zero exit.
    pub fn is_active(&self, service: &str) -> Result<bool> {
        let output = self.run_systemctl(&["is-active", service])?;
        Ok(output.success)
    }

    /// Check whether the service unit is enabled at boot.
    ///
    /// Returns `Ok(true)` when `systemctl is-enabled <service>` exits with
    /// code 0, and `Ok(false)` for any non-zero exit.
    pub fn is_enabled(&self, service: &str) -> Result<bool> {
        let output = self.run_systemctl(&["is-enabled", service])?;
        Ok(output.success)
    }

    /// Query the current status of a service unit.
    ///
    /// Returns a [`ServiceStatus`] derived from the output of
    /// `systemctl is-active <service>`.
    pub fn status(&self, service: &str) -> Result<ServiceStatus> {
        let output = self.run_systemctl(&["is-active", service])?;
        let status: ServiceStatus = output
            .stdout
            .trim()
            .parse()
            .unwrap_or(ServiceStatus::Unknown);
        Ok(status)
    }

    /// Check whether the service unit is installed on the system.
    ///
    /// Returns `Ok(true)` when `systemctl cat <service>` exits with code 0,
    /// indicating the unit file exists.
    pub fn is_installed(&self, service: &str) -> Result<bool> {
        let output = self.run_systemctl(&["cat", service])?;
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
    pub fn start(&self, service: &str) -> Result<()> {
        let output = self.run_systemctl(&["start", service])?;
        if output.success {
            Ok(())
        } else {
            Err(command_failed("start", service, &output))
        }
    }

    /// Stop the service unit.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if `systemctl stop` exits non-zero.
    pub fn stop(&self, service: &str) -> Result<()> {
        let output = self.run_systemctl(&["stop", service])?;
        if output.success {
            Ok(())
        } else {
            Err(command_failed("stop", service, &output))
        }
    }

    /// Restart the service unit (stop then start).
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if `systemctl restart` exits non-zero.
    pub fn restart(&self, service: &str) -> Result<()> {
        let output = self.run_systemctl(&["restart", service])?;
        if output.success {
            Ok(())
        } else {
            Err(command_failed("restart", service, &output))
        }
    }

    /// Enable the service unit to start at boot.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if `systemctl enable` exits non-zero.
    pub fn enable(&self, service: &str) -> Result<()> {
        let output = self.run_systemctl(&["enable", service])?;
        if output.success {
            Ok(())
        } else {
            Err(command_failed("enable", service, &output))
        }
    }

    /// Disable the service unit from starting at boot.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if `systemctl disable` exits non-zero.
    pub fn disable(&self, service: &str) -> Result<()> {
        let output = self.run_systemctl(&["disable", service])?;
        if output.success {
            Ok(())
        } else {
            Err(command_failed("disable", service, &output))
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Execute a `systemctl` subcommand through the runner.
    ///
    /// Logs the full command at debug level and returns the captured output.
    fn run_systemctl(&self, args: &[&str]) -> Result<toride_runner::CommandOutput> {
        tracing::debug!(args = ?args, "invoking systemctl");
        let spec = toride_runner::CommandSpec::new("systemctl").args(args.iter().copied());
        Ok(self.runner.run(&spec)?)
    }
}

// ---------------------------------------------------------------------------
// Private helper
// ---------------------------------------------------------------------------

/// Build an [`Error::CommandFailed`] from a failed command's output.
fn command_failed(subcommand: &str, service: &str, output: &toride_runner::CommandOutput) -> Error {
    let code = output
        .exit_code
        .map_or("signal".to_owned(), |c| c.to_string());
    let stderr = output.stderr.trim();
    let detail = if stderr.is_empty() {
        format!("systemctl {subcommand} {service} failed (exit {code})")
    } else {
        format!("systemctl {subcommand} {service} failed (exit {code}): {stderr}")
    };
    Error::CommandFailed(detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_status_display_roundtrip() {
        assert_eq!(ServiceStatus::Active.to_string(), "active");
        assert_eq!(ServiceStatus::Inactive.to_string(), "inactive");
        assert_eq!(ServiceStatus::Failed.to_string(), "failed");
        assert_eq!(ServiceStatus::Activating.to_string(), "activating");
        assert_eq!(ServiceStatus::Unknown.to_string(), "unknown");
    }

    #[test]
    fn service_status_from_str() {
        assert_eq!(
            "active".parse::<ServiceStatus>().unwrap(),
            ServiceStatus::Active
        );
        assert_eq!(
            "running".parse::<ServiceStatus>().unwrap(),
            ServiceStatus::Active
        );
        assert_eq!(
            "inactive".parse::<ServiceStatus>().unwrap(),
            ServiceStatus::Inactive
        );
        assert_eq!(
            "failed".parse::<ServiceStatus>().unwrap(),
            ServiceStatus::Failed
        );
        assert_eq!(
            "activating".parse::<ServiceStatus>().unwrap(),
            ServiceStatus::Activating
        );
        assert_eq!(
            "something-else".parse::<ServiceStatus>().unwrap(),
            ServiceStatus::Unknown
        );
    }
}
