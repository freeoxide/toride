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
        let output = self.run_systemctl("is-active", service)?;
        Ok(output.success)
    }

    /// Check whether the service unit is enabled at boot.
    ///
    /// Returns `Ok(true)` when `systemctl is-enabled <service>` exits with
    /// code 0, and `Ok(false)` for any non-zero exit.
    pub fn is_enabled(&self, service: &str) -> Result<bool> {
        let output = self.run_systemctl("is-enabled", service)?;
        Ok(output.success)
    }

    /// Query the current status of a service unit.
    ///
    /// Returns a [`ServiceStatus`] derived from the exit code and output of
    /// `systemctl is-active <service>`.
    ///
    /// The exit code takes precedence over stdout: `systemctl is-active`
    /// prints `inactive` and exits non-zero for a unit that is missing or has
    /// errored. Rather than trusting the benign-looking stdout, a non-zero
    /// exit is reported as [`ServiceStatus::Failed`] so callers can tell a
    /// genuinely stopped unit (exit 0) apart from one that errored or does not
    /// exist (non-zero exit).
    pub fn status(&self, service: &str) -> Result<ServiceStatus> {
        let output = self.run_systemctl("is-active", service)?;
        if !output.success {
            // A non-zero exit means the unit is not cleanly active: it may be
            // stopped-but-missing, in a failed state, or the verb itself
            // errored. Report `Failed` so the benign "inactive" stdout of a
            // missing/errored unit is not mistaken for a clean stop.
            return Ok(ServiceStatus::Failed);
        }
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
        let output = self.run_systemctl("cat", service)?;
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
        let output = self.run_systemctl("start", service)?;
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
        let output = self.run_systemctl("stop", service)?;
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
        let output = self.run_systemctl("restart", service)?;
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
        let output = self.run_systemctl("enable", service)?;
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
        let output = self.run_systemctl("disable", service)?;
        if output.success {
            Ok(())
        } else {
            Err(command_failed("disable", service, &output))
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Validate a service unit name before handing it to `systemctl`.
    ///
    /// Rejects names that could be misinterpreted as flags or escape the unit
    /// namespace: empty strings, names with a leading `-` (flag injection),
    /// path separators (`/`), and embedded NUL bytes. This is a defence in
    /// depth; the `--` guard in [`Self::run_systemctl`] is the primary
    /// mitigation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Other`] with a descriptive message on rejection.
    fn validate_service_name(service: &str) -> Result<()> {
        if service.is_empty() {
            return Err(Error::Other("service name must not be empty".to_owned()));
        }
        if service.starts_with('-') {
            return Err(Error::Other(format!(
                "service name must not start with '-': {service:?}"
            )));
        }
        if service.contains('/') {
            return Err(Error::Other(format!(
                "service name must not contain a path separator: {service:?}"
            )));
        }
        if service.contains('\0') {
            return Err(Error::Other(format!(
                "service name must not contain a NUL byte: {service:?}"
            )));
        }
        Ok(())
    }

    /// Execute a `systemctl` subcommand through the runner.
    ///
    /// Validates the service name and inserts a literal `--` before it so a
    /// name beginning with `-` cannot be interpreted as a systemctl flag.
    /// Logs the full command at debug level and returns the captured output.
    fn run_systemctl(&self, verb: &str, service: &str) -> Result<toride_runner::CommandOutput> {
        Self::validate_service_name(service)?;
        tracing::debug!(%verb, service, "invoking systemctl");
        // The `--` terminator guarantees `service` is treated as a positional
        // unit argument even if it begins with `-`.
        let spec = toride_runner::CommandSpec::new("systemctl").args([verb, "--", service]);
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
    use std::sync::{Arc, Mutex};

    use toride_runner::{CommandOutput, CommandSpec, Runner};

    /// Minimal in-module [`Runner`] fake: returns a single canned output and
    /// records the last [`CommandSpec`] it was invoked with.
    ///
    /// Defined locally (rather than using `toride_runner::fake::FakeRunner`)
    /// so the tests run without enabling the optional `fake` feature of
    /// `toride-runner`.
    #[derive(Clone, Default)]
    struct CannedRunner {
        output: Arc<Mutex<Option<CommandOutput>>>,
        last_spec: Arc<Mutex<Option<CommandSpec>>>,
        call_count: Arc<Mutex<usize>>,
    }

    impl CannedRunner {
        fn new(output: CommandOutput) -> Self {
            Self {
                output: Arc::new(Mutex::new(Some(output))),
                last_spec: Arc::new(Mutex::new(None)),
                call_count: Arc::new(Mutex::new(0)),
            }
        }

        fn empty() -> Self {
            Self::default()
        }

        fn last_spec(&self) -> Option<CommandSpec> {
            self.last_spec.lock().expect("last_spec lock").clone()
        }

        fn call_count(&self) -> usize {
            *self.call_count.lock().expect("call_count lock")
        }
    }

    /// Assert the runner's recorded invocation matches the expected program
    /// and args. `CommandSpec` does not implement `PartialEq`, so we compare
    /// the fields manually.
    fn assert_invocation(runner: &CannedRunner, expected_program: &str, expected_args: &[&str]) {
        let spec = runner
            .last_spec()
            .expect("expected a systemctl invocation but none was recorded");
        assert_eq!(spec.program, expected_program, "wrong program");
        let actual: Vec<&str> = spec.args.iter().map(String::as_str).collect();
        assert_eq!(
            actual, expected_args,
            "wrong args — expected the service name after a `--` guard"
        );
    }

    impl Runner for CannedRunner {
        fn run(&self, spec: &CommandSpec) -> toride_runner::Result<CommandOutput> {
            *self.last_spec.lock().expect("last_spec lock") = Some(spec.clone());
            *self.call_count.lock().expect("call_count lock") += 1;
            Ok(self
                .output
                .lock()
                .expect("output lock")
                .clone()
                .unwrap_or_else(|| CommandOutput::from_stdout(String::new())))
        }
    }

    /// Build a `ServiceManager` backed by an empty (success) [`CannedRunner`].
    fn manager_with_fake() -> (ServiceManager, CannedRunner) {
        let runner = CannedRunner::empty();
        let mgr = ServiceManager::new(Box::new(runner.clone()));
        (mgr, runner)
    }

    /// Build a `ServiceManager` whose runner returns `output`, plus a clone of
    /// the runner for call inspection.
    fn manager_with_output(output: CommandOutput) -> (ServiceManager, CannedRunner) {
        let runner = CannedRunner::new(output);
        let mgr = ServiceManager::new(Box::new(runner.clone()));
        (mgr, runner)
    }

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

    // -------------------------------------------------------------------------
    // status() — exit-code precedence (correctness finding at line 139)
    // -------------------------------------------------------------------------

    #[test]
    fn status_active_when_exit_zero_and_active_stdout() {
        let (mgr, _runner) = manager_with_output(CommandOutput::from_stdout("active\n"));
        let status = mgr.status("sshd").unwrap();
        assert_eq!(status, ServiceStatus::Active);
    }

    #[test]
    fn status_inactive_when_exit_zero_and_inactive_stdout() {
        // A cleanly stopped unit exits 0 with "inactive" on stdout.
        let (mgr, _runner) =
            manager_with_output(CommandOutput::new("inactive\n".to_owned(), String::new(), Some(0)));
        let status = mgr.status("sshd").unwrap();
        assert_eq!(status, ServiceStatus::Inactive);
    }

    #[test]
    fn status_failed_when_nonzero_exit_even_if_stdout_says_inactive() {
        // The bug: a missing/errored unit prints "inactive" on stdout but
        // exits non-zero. We must NOT report Inactive — that masks the error.
        let (mgr, _runner) = manager_with_output(CommandOutput::new(
            "inactive\n".to_owned(),
            "Unit nosuch.service could not be found.\n".to_owned(),
            Some(3),
        ));
        let status = mgr.status("nosuch").unwrap();
        assert_eq!(
            status,
            ServiceStatus::Failed,
            "non-zero exit must surface as Failed, not the benign stdout Inactive"
        );
    }

    #[test]
    fn status_failed_when_nonzero_exit_with_failed_stdout() {
        let (mgr, _runner) =
            manager_with_output(CommandOutput::new("failed\n".to_owned(), String::new(), Some(3)));
        let status = mgr.status("broken").unwrap();
        assert_eq!(status, ServiceStatus::Failed);
    }

    // -------------------------------------------------------------------------
    // run_systemctl — `--` guard + name validation (security finding at 239)
    // -------------------------------------------------------------------------

    #[test]
    fn run_systemctl_inserts_double_dash_before_service() {
        // Every invocation must terminate options with `--` so a service name
        // cannot be parsed as a flag.
        let (mgr, runner) = manager_with_output(CommandOutput::from_stdout("active\n"));

        let _ = mgr.is_active("sshd").unwrap();

        assert_invocation(&runner, "systemctl", &["is-active", "--", "sshd"]);
    }

    #[test]
    fn run_systemctl_rejects_flag_shaped_service_name() {
        // A leading `-` would be interpreted as a systemctl flag without the
        // `--` guard; validation rejects it before any process is spawned.
        let (mgr, runner) = manager_with_fake();
        let err = mgr.status("--now").unwrap_err();
        assert!(
            matches!(err, Error::Other(ref m) if m.contains("must not start with '-'")),
            "expected rejection of leading-dash name, got {err:?}"
        );
        // No call should have reached the runner.
        assert_eq!(runner.call_count(), 0, "validation must short-circuit");
    }

    #[test]
    fn run_systemctl_rejects_empty_service_name() {
        let (mgr, _runner) = manager_with_fake();
        let err = mgr.start("").unwrap_err();
        assert!(
            matches!(err, Error::Other(ref m) if m.contains("empty")),
            "expected rejection of empty name, got {err:?}"
        );
    }

    #[test]
    fn run_systemctl_rejects_path_separator() {
        let (mgr, _runner) = manager_with_fake();
        let err = mgr.restart("../etc/passwd").unwrap_err();
        assert!(
            matches!(err, Error::Other(ref m) if m.contains("path separator")),
            "expected rejection of path separator, got {err:?}"
        );
    }

    #[test]
    fn run_systemctl_rejects_nul_byte() {
        let (mgr, _runner) = manager_with_fake();
        let err = mgr.stop("ssh\0d").unwrap_err();
        assert!(
            matches!(err, Error::Other(ref m) if m.contains("NUL")),
            "expected rejection of NUL byte, got {err:?}"
        );
    }

    #[test]
    fn run_systemctl_accepts_typical_unit_names() {
        // Sanity: the validator must not reject legitimate names, including
        // names that contain dots, at-signs, or template instances.
        for name in ["sshd", "nginx.service", "user@1000", "sysstat-collect.timer"] {
            let (mgr, _runner) = manager_with_output(CommandOutput::from_stdout("active\n"));
            let status = mgr.status(name).unwrap();
            assert_eq!(status, ServiceStatus::Active, "name {name:?} should be accepted");
        }
    }

    #[test]
    fn lifecycle_methods_pass_service_after_double_dash() {
        // The lifecycle verbs must also get the `--` guard.
        let (mgr, runner) = manager_with_output(CommandOutput::from_stdout(String::new()));

        mgr.restart("nginx").unwrap();

        assert_invocation(&runner, "systemctl", &["restart", "--", "nginx"]);
    }
}
