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

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

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
/// - [`ServiceManager::with_units_root`] -- same, with a custom unit file
///   install root (the default is `/etc/systemd/system`).
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
    units_root: PathBuf,
}

const DEFAULT_UNITS_ROOT: &str = "/etc/systemd/system";

const UNIT_FILE_MODE: u32 = 0o644;

impl ServiceManager {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Create a new `ServiceManager` with the given command runner.
    ///
    /// Unit files are installed under `/etc/systemd/system`. Use
    /// [`ServiceManager::with_units_root`] to override that location.
    ///
    /// The runner is used for all `systemctl` invocations, making the manager
    /// fully testable via a fake or mock runner.
    pub fn new(runner: Box<dyn toride_runner::Runner>) -> Self {
        Self {
            runner,
            units_root: PathBuf::from(DEFAULT_UNITS_ROOT),
        }
    }

    /// Create a new `ServiceManager` that installs unit files under
    /// `units_root` instead of `/etc/systemd/system`.
    pub fn with_units_root(
        runner: Box<dyn toride_runner::Runner>,
        units_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            runner,
            units_root: units_root.into(),
        }
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

    /// Reload the systemd manager configuration (`systemctl daemon-reload`),
    /// returning [`Error::CommandFailed`] when the verb exits non-zero.
    pub fn daemon_reload(&self) -> Result<()> {
        tracing::debug!("invoking systemctl daemon-reload");
        let spec = toride_runner::CommandSpec::new("systemctl").arg("daemon-reload");
        let output = self.runner.run(&spec)?;
        if output.success {
            Ok(())
        } else {
            Err(command_failed("daemon-reload", "", &output))
        }
    }

    /// Install `contents` as unit `name` under the units root, backing up any
    /// existing file to a timestamped sibling first, then writing atomically
    /// at mode 0644; name, backup, and write failures are typed.
    pub fn install_unit(&self, name: &str, contents: &str) -> Result<()> {
        self.prepare_unit(name, contents).map(|_| ())
    }

    /// Install `name`, then daemon-reload, enable, and start it in order; on
    /// post-write failure the previous file and enablement state is restored
    /// and a rollback error returned: [`Error::DeployRolledBack`] or
    /// [`Error::DeployRollbackFailed`].
    pub fn deploy_unit(&self, name: &str, contents: &str) -> Result<()> {
        let backup = self.prepare_unit(name, contents)?;
        let mut prior_enablement: Option<bool> = None;
        if let Err(cause) = self.activate_unit(name, &mut prior_enablement) {
            let rollback = self.rollback_deployment(name, backup.as_deref(), prior_enablement);
            let _ = self.daemon_reload();
            return Err(match rollback {
                Ok(()) => {
                    tracing::error!(unit = name, "deployment failed; unit rolled back");
                    Error::DeployRolledBack {
                        unit: name.to_owned(),
                        cause: Box::new(cause),
                    }
                }
                Err(rollback_error) => {
                    tracing::error!(unit = name, "deployment failed and rollback failed too");
                    Error::DeployRollbackFailed {
                        unit: name.to_owned(),
                        cause: Box::new(cause),
                        rollback_error: Box::new(rollback_error),
                    }
                }
            });
        }
        Ok(())
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

    fn prepare_unit(&self, name: &str, contents: &str) -> Result<Option<PathBuf>> {
        Self::validate_unit_name(name)?;
        fs::create_dir_all(&self.units_root)?;
        let unit_path = self.unit_path(name);
        let backup = if unit_path.is_file() {
            Some(self.backup_unit(name)?)
        } else {
            None
        };
        toride_fs::atomic_write_with_perms(&unit_path, contents, UNIT_FILE_MODE)?;
        tracing::info!(unit = name, path = %unit_path.display(), "installed unit file");
        Ok(backup)
    }

    fn backup_unit(&self, name: &str) -> Result<PathBuf> {
        let source = self.unit_path(name);
        let dest = self
            .units_root
            .join(format!("{name}.bak.{}", unix_timestamp_nanos()));
        fs::copy(&source, &dest).map_err(|e| {
            Error::BackupFailed(format!(
                "failed to copy {} to {}: {e}",
                source.display(),
                dest.display()
            ))
        })?;
        tracing::info!(
            from = %source.display(),
            to = %dest.display(),
            "backed up unit file"
        );
        Ok(dest)
    }

    fn activate_unit(&self, name: &str, prior_enablement: &mut Option<bool>) -> Result<()> {
        self.daemon_reload()?;
        prior_enablement.replace(self.is_enabled(name)?);
        self.enable(name)?;
        self.start(name)
    }

    fn rollback_deployment(
        &self,
        name: &str,
        backup: Option<&Path>,
        prior_enablement: Option<bool>,
    ) -> Result<()> {
        let mut failure: Option<Error> = None;
        if prior_enablement == Some(false)
            && let Err(e) = self.disable(name)
        {
            tracing::error!(unit = name, error = %e, "rollback could not disable the unit");
            failure.get_or_insert(e);
        }
        if let Err(e) = rollback_unit(&self.unit_path(name), backup) {
            tracing::error!(unit = name, error = %e, "rollback could not restore the unit file");
            failure.get_or_insert(e);
        }
        match failure {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn unit_path(&self, name: &str) -> PathBuf {
        self.units_root.join(name)
    }

    fn validate_unit_name(name: &str) -> Result<()> {
        if name.is_empty() {
            return Err(Error::InvalidUnitName("must not be empty".to_owned()));
        }
        if !name.ends_with(".service") {
            return Err(Error::InvalidUnitName(format!(
                "must end in .service: {name:?}"
            )));
        }
        if name.len() == ".service".len() {
            return Err(Error::InvalidUnitName(
                "must have a name before the .service suffix".to_owned(),
            ));
        }
        if name.starts_with('-') {
            return Err(Error::InvalidUnitName(format!(
                "must not start with '-': {name:?}"
            )));
        }
        if name.contains("..") {
            return Err(Error::InvalidUnitName(format!(
                "must not contain dotdot: {name:?}"
            )));
        }
        if let Some(bad) = name
            .chars()
            .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '@' | '.' | '_' | '+' | '-')))
        {
            return Err(Error::InvalidUnitName(format!(
                "disallowed character {bad:?} in {name:?}"
            )));
        }
        Ok(())
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
    let target = if service.is_empty() {
        String::new()
    } else {
        format!(" {service}")
    };
    let detail = if stderr.is_empty() {
        format!("systemctl {subcommand}{target} failed (exit {code})")
    } else {
        format!("systemctl {subcommand}{target} failed (exit {code}): {stderr}")
    };
    Error::CommandFailed(detail)
}

fn rollback_unit(unit_path: &Path, backup: Option<&Path>) -> Result<()> {
    match backup {
        Some(backup_path) => fs::copy(backup_path, unit_path)
            .map(|_| ())
            .map_err(Error::Io),
        None => fs::remove_file(unit_path).map_err(Error::Io),
    }
}

fn unix_timestamp_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use tempfile::TempDir;
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
        let (mgr, _runner) = manager_with_output(CommandOutput::new(
            "inactive\n".to_owned(),
            String::new(),
            Some(0),
        ));
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
        let (mgr, _runner) = manager_with_output(CommandOutput::new(
            "failed\n".to_owned(),
            String::new(),
            Some(3),
        ));
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
        for name in [
            "sshd",
            "nginx.service",
            "user@1000",
            "sysstat-collect.timer",
        ] {
            let (mgr, _runner) = manager_with_output(CommandOutput::from_stdout("active\n"));
            let status = mgr.status(name).unwrap();
            assert_eq!(
                status,
                ServiceStatus::Active,
                "name {name:?} should be accepted"
            );
        }
    }

    #[test]
    fn lifecycle_methods_pass_service_after_double_dash() {
        // The lifecycle verbs must also get the `--` guard.
        let (mgr, runner) = manager_with_output(CommandOutput::from_stdout(String::new()));

        mgr.restart("nginx").unwrap();

        assert_invocation(&runner, "systemctl", &["restart", "--", "nginx"]);
    }

    #[derive(Clone, Default)]
    struct VerbsRunner {
        specs: Arc<Mutex<Vec<CommandSpec>>>,
        failing_verb: Option<String>,
        enabled: bool,
    }

    impl VerbsRunner {
        fn succeeding() -> Self {
            Self::default()
        }

        fn failing_verb(verb: &str) -> Self {
            Self::with_failing_verb_and_enablement(verb, false)
        }

        fn with_failing_verb_and_enablement(verb: &str, enabled: bool) -> Self {
            Self {
                failing_verb: Some(verb.to_owned()),
                enabled,
                ..Self::default()
            }
        }

        fn invocation_count(&self) -> usize {
            self.specs.lock().expect("specs lock").len()
        }

        fn argv_at(&self, index: usize) -> (String, Vec<String>) {
            let specs = self.specs.lock().expect("specs lock");
            let spec = specs
                .get(index)
                .unwrap_or_else(|| panic!("no runner invocation at index {index}"));
            (spec.program.clone(), spec.args.clone())
        }

        fn verb_at(&self, index: usize) -> Option<String> {
            self.argv_at(index).1.into_iter().next()
        }
    }

    impl Runner for VerbsRunner {
        fn run(&self, spec: &CommandSpec) -> toride_runner::Result<CommandOutput> {
            self.specs.lock().expect("specs lock").push(spec.clone());
            let verb = spec.args.first().map(String::as_str);
            if self.failing_verb.as_deref() == verb {
                return Ok(CommandOutput::new(
                    String::new(),
                    "simulated systemctl failure\n".to_owned(),
                    Some(1),
                ));
            }
            if verb == Some("is-enabled") {
                let code = i32::from(!self.enabled);
                return Ok(CommandOutput::new(String::new(), String::new(), Some(code)));
            }
            Ok(CommandOutput::from_stdout(String::new()))
        }
    }

    fn units_root_entries(dir: &TempDir) -> Vec<String> {
        let mut names: Vec<_> = fs::read_dir(dir.path())
            .expect("units root should be readable")
            .filter_map(std::result::Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn new_defaults_to_the_system_units_root() {
        let (mgr, _runner) = manager_with_fake();
        assert_eq!(mgr.units_root, PathBuf::from(DEFAULT_UNITS_ROOT));
    }

    #[test]
    fn install_unit_writes_contents_at_mode_0644() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let runner = CannedRunner::empty();
        let mgr = ServiceManager::with_units_root(Box::new(runner.clone()), dir.path());

        mgr.install_unit("app.service", "[Unit]\nDescription=app\n")
            .expect("install should succeed");

        let installed =
            fs::read_to_string(dir.path().join("app.service")).expect("unit file readable");
        assert_eq!(installed, "[Unit]\nDescription=app\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.path().join("app.service"))
                .expect("metadata should be available")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o644);
        }
        assert_eq!(
            runner.call_count(),
            0,
            "install_unit must not invoke systemctl"
        );
    }

    #[test]
    fn install_unit_backs_up_previous_contents_in_a_timestamped_sibling() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        fs::write(dir.path().join("app.service"), "old contents")
            .expect("seed unit write should succeed");
        let mgr = ServiceManager::with_units_root(Box::new(CannedRunner::empty()), dir.path());

        mgr.install_unit("app.service", "new contents")
            .expect("install should succeed");

        assert_eq!(
            fs::read_to_string(dir.path().join("app.service")).expect("unit file readable"),
            "new contents"
        );
        let backups: Vec<_> = units_root_entries(&dir)
            .into_iter()
            .filter(|n| n != "app.service")
            .collect();
        assert_eq!(backups.len(), 1, "exactly one backup sibling: {backups:?}");
        let backup_name = &backups[0];
        let prefix = "app.service.bak.";
        assert!(
            backup_name.starts_with(prefix),
            "backup must follow <unit>.bak.<timestamp>: {backup_name}"
        );
        let timestamp = &backup_name[prefix.len()..];
        assert!(
            !timestamp.is_empty() && timestamp.chars().all(|c| c.is_ascii_digit()),
            "timestamp must be numeric: {timestamp}"
        );
        assert_eq!(
            fs::read_to_string(dir.path().join(backup_name)).expect("backup readable"),
            "old contents"
        );
    }

    #[test]
    fn install_unit_rejects_abusive_names() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let runner = CannedRunner::empty();
        let mgr = ServiceManager::with_units_root(Box::new(runner.clone()), dir.path());

        for name in [
            "",
            "..",
            "nginx",
            "nginx.timer",
            ".service",
            "../evil.service",
            "/etc/systemd/system/evil.service",
            "sub/dir.service",
            "a..b.service",
            "-flag.service",
            "with space.service",
            "nginx\0.service",
            "café.service",
        ] {
            let err = mgr.install_unit(name, "[Unit]\n").unwrap_err();
            assert!(
                matches!(err, Error::InvalidUnitName(_)),
                "name {name:?} must be rejected with InvalidUnitName, got {err:?}"
            );
        }

        assert_eq!(runner.call_count(), 0, "validation must short-circuit");
        assert!(
            units_root_entries(&dir).is_empty(),
            "no file may be created for a rejected name"
        );
    }

    #[test]
    fn install_unit_accepts_strictly_valid_names() {
        for name in ["nginx.service", "user@1000.service", "my-app_2+x.service"] {
            let dir = TempDir::new().expect("temp dir creation should succeed");
            let mgr = ServiceManager::with_units_root(Box::new(CannedRunner::empty()), dir.path());
            mgr.install_unit(name, "[Unit]\n")
                .unwrap_or_else(|e| panic!("name {name:?} should be accepted: {e}"));
            assert!(
                dir.path().join(name).is_file(),
                "unit file for {name:?} must exist"
            );
        }
    }

    #[test]
    fn daemon_reload_uses_exact_argv() {
        let runner = VerbsRunner::succeeding();
        let mgr = ServiceManager::new(Box::new(runner.clone()));

        mgr.daemon_reload().expect("daemon-reload should succeed");

        assert_eq!(runner.invocation_count(), 1);
        assert_eq!(
            runner.argv_at(0),
            ("systemctl".to_owned(), vec!["daemon-reload".to_owned()])
        );
    }

    #[test]
    fn daemon_reload_surfaces_nonzero_exit() {
        let runner = VerbsRunner::failing_verb("daemon-reload");
        let mgr = ServiceManager::new(Box::new(runner.clone()));

        let err = mgr.daemon_reload().unwrap_err();

        assert!(
            matches!(err, Error::CommandFailed(ref m) if m.contains("daemon-reload failed")),
            "got {err:?}"
        );
    }

    #[test]
    fn deploy_unit_sequences_reload_enable_start() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let runner = VerbsRunner::succeeding();
        let mgr = ServiceManager::with_units_root(Box::new(runner.clone()), dir.path());

        mgr.deploy_unit("app.service", "[Unit]\n")
            .expect("deploy should succeed");

        assert_eq!(runner.invocation_count(), 4);
        assert_eq!(
            runner.argv_at(0),
            ("systemctl".to_owned(), vec!["daemon-reload".to_owned()])
        );
        assert_eq!(
            runner.argv_at(1),
            (
                "systemctl".to_owned(),
                vec![
                    "is-enabled".to_owned(),
                    "--".to_owned(),
                    "app.service".to_owned()
                ]
            )
        );
        assert_eq!(
            runner.argv_at(2),
            (
                "systemctl".to_owned(),
                vec![
                    "enable".to_owned(),
                    "--".to_owned(),
                    "app.service".to_owned()
                ]
            )
        );
        assert_eq!(
            runner.argv_at(3),
            (
                "systemctl".to_owned(),
                vec![
                    "start".to_owned(),
                    "--".to_owned(),
                    "app.service".to_owned()
                ]
            )
        );
        assert_eq!(
            fs::read_to_string(dir.path().join("app.service")).expect("unit file readable"),
            "[Unit]\n"
        );
    }

    #[test]
    fn deploy_unit_restores_original_file_when_start_fails() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        fs::write(dir.path().join("app.service"), "original")
            .expect("seed unit write should succeed");
        let runner = VerbsRunner::failing_verb("start");
        let mgr = ServiceManager::with_units_root(Box::new(runner.clone()), dir.path());

        let err = mgr
            .deploy_unit("app.service", "replacement")
            .expect_err("deploy must fail when start fails");

        match &err {
            Error::DeployRolledBack { unit, cause } => {
                assert_eq!(unit, "app.service");
                assert!(
                    matches!(**cause, Error::CommandFailed(_)),
                    "cause must be the start failure: {cause}"
                );
            }
            other => panic!("expected DeployRolledBack, got {other:?}"),
        }
        assert!(
            err.to_string().contains("rolled back"),
            "error must say the rollback happened: {err}"
        );
        assert_eq!(
            fs::read_to_string(dir.path().join("app.service")).expect("unit file readable"),
            "original"
        );
        assert_eq!(
            runner.verb_at(4),
            Some("disable".to_owned()),
            "rollback must undo the enable that ran before start failed"
        );
        assert_eq!(
            runner.invocation_count(),
            6,
            "reload, is-enabled, enable, start, rollback disable, best-effort reload"
        );
        assert_eq!(
            runner.argv_at(5),
            ("systemctl".to_owned(), vec!["daemon-reload".to_owned()])
        );
    }

    #[test]
    fn deploy_unit_disables_fresh_unit_when_start_fails() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let runner = VerbsRunner::failing_verb("start");
        let mgr = ServiceManager::with_units_root(Box::new(runner.clone()), dir.path());

        let err = mgr
            .deploy_unit("app.service", "fresh")
            .expect_err("deploy must fail when start fails");

        assert!(matches!(err, Error::DeployRolledBack { .. }), "got {err:?}");
        assert!(
            !dir.path().join("app.service").exists(),
            "freshly written file must be removed on rollback"
        );
        assert_eq!(
            runner.verb_at(4),
            Some("disable".to_owned()),
            "rollback must remove the enablement our enable created"
        );
        assert_eq!(runner.invocation_count(), 6);
    }

    #[test]
    fn deploy_unit_keeps_enablement_when_unit_was_enabled_before() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        fs::write(dir.path().join("app.service"), "original")
            .expect("seed unit write should succeed");
        let runner = VerbsRunner::with_failing_verb_and_enablement("start", true);
        let mgr = ServiceManager::with_units_root(Box::new(runner.clone()), dir.path());

        let err = mgr
            .deploy_unit("app.service", "replacement")
            .expect_err("deploy must fail when start fails");

        assert!(matches!(err, Error::DeployRolledBack { .. }), "got {err:?}");
        assert_eq!(
            fs::read_to_string(dir.path().join("app.service")).expect("unit file readable"),
            "original"
        );
        let verbs: Vec<Option<String>> = (0..runner.invocation_count())
            .map(|i| runner.verb_at(i))
            .collect();
        assert!(
            !verbs.contains(&Some("disable".to_owned())),
            "a unit enabled before the deploy must stay enabled: {verbs:?}"
        );
        assert_eq!(
            runner.invocation_count(),
            5,
            "reload, is-enabled, enable, start, best-effort reload — no disable"
        );
    }

    #[test]
    fn deploy_unit_removes_fresh_file_when_daemon_reload_fails() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let runner = VerbsRunner::failing_verb("daemon-reload");
        let mgr = ServiceManager::with_units_root(Box::new(runner.clone()), dir.path());

        let err = mgr
            .deploy_unit("app.service", "fresh")
            .expect_err("deploy must fail when daemon-reload fails");

        assert!(matches!(err, Error::DeployRolledBack { .. }), "got {err:?}");
        assert!(
            !dir.path().join("app.service").exists(),
            "freshly written file must be removed on rollback"
        );
        assert_eq!(
            units_root_entries(&dir),
            Vec::<String>::new(),
            "no backup exists and no file may remain"
        );
        assert_eq!(
            runner.invocation_count(),
            2,
            "failed reload plus the best-effort reload after rollback"
        );
    }

    #[test]
    fn deploy_unit_rejects_invalid_name_before_any_write() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let runner = VerbsRunner::succeeding();
        let mgr = ServiceManager::with_units_root(Box::new(runner.clone()), dir.path());

        let err = mgr
            .deploy_unit("../evil.service", "contents")
            .expect_err("invalid name must be rejected");

        assert!(matches!(err, Error::InvalidUnitName(_)), "got {err:?}");
        assert_eq!(
            runner.invocation_count(),
            0,
            "validation must short-circuit before any systemctl call"
        );
        assert!(
            units_root_entries(&dir).is_empty(),
            "no file may be created for a rejected name"
        );
    }

    #[cfg(unix)]
    #[test]
    fn backup_failure_is_typed_when_units_root_is_not_writable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().expect("temp dir creation should succeed");
        let units = dir.path().join("units");
        fs::create_dir(&units).expect("units root creation should succeed");
        fs::write(units.join("app.service"), "original\n").expect("seed unit write should succeed");

        fs::set_permissions(&units, fs::Permissions::from_mode(0o555))
            .expect("chmod should succeed");
        let writable_anyway = fs::write(units.join(".probe"), b"probe").is_ok();
        let result = if writable_anyway {
            Ok(())
        } else {
            ServiceManager::with_units_root(Box::new(CannedRunner::empty()), &units)
                .install_unit("app.service", "replacement\n")
        };
        fs::set_permissions(&units, fs::Permissions::from_mode(0o755))
            .expect("chmod restore should succeed");
        let _ = fs::remove_file(units.join(".probe"));

        if writable_anyway {
            return;
        }
        let err = result.expect_err("backup copy must fail in a read-only units root");
        assert!(matches!(err, Error::BackupFailed(_)), "got {err:?}");
        assert_eq!(
            fs::read_to_string(units.join("app.service")).expect("original still readable"),
            "original\n",
            "the failed install must leave the original unit untouched"
        );
    }
}
