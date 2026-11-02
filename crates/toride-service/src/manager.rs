//! Service manager layer wrapping `systemctl`.
//!
//! [`ServiceManager`] provides a typed interface for controlling systemd
//! service units. Every operation goes through the centralised
//! [`toride_runner::Runner`] trait so that the entire call stack remains
//! testable with a fake runner.
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

use crate::ledger::{ActionKind, ActionLedger, ActionRecord, LedgerResult};
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
            "active" | "running" | "reloading" => Ok(Self::Active),
            "inactive" | "stopped" => Ok(Self::Inactive),
            "failed" => Ok(Self::Failed),
            "activating" => Ok(Self::Activating),
            _ => Ok(Self::Unknown),
        }
    }
}

/// Outcome of `systemctl is-enabled` mapped from its documented exit codes.
enum Enablement {
    Enabled,
    Disabled,
    Unknown,
}

/// Map a `systemctl is-active` result to a status per systemctl(1).
///
/// Exit 0 means active (stdout parsed); exit 3 with `inactive` stdout means a
/// cleanly stopped unit; exit 4 means no such unit; everything else, including
/// the `failed` state, is Failed.
fn classify_is_active(output: &toride_runner::CommandOutput) -> ServiceStatus {
    match output.exit_code {
        Some(0) => output
            .stdout
            .trim()
            .parse()
            .unwrap_or(ServiceStatus::Unknown),
        Some(3) if output.stdout.trim() == "inactive" => ServiceStatus::Inactive,
        Some(4) => ServiceStatus::Unknown,
        _ => ServiceStatus::Failed,
    }
}

/// Whether a unit file's `[Service]` section declares `Type=oneshot`.
fn is_oneshot_unit(contents: &str) -> bool {
    let mut in_service = false;
    for line in contents.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_service = line.eq_ignore_ascii_case("[service]");
        } else if in_service && let Some(value) = line.strip_prefix("Type=") {
            return value.trim() == "oneshot";
        }
    }
    false
}

// ---------------------------------------------------------------------------
// ServiceManager
// ---------------------------------------------------------------------------

/// Manages systemd service units through a [`toride_runner::Runner`].
///
/// Owns a `Box<dyn Runner>`, so the manager has full ownership of the runner
/// lifecycle. All `systemctl` invocations are routed through the runner for
/// testability and logging. Operations always run the real command; there is
/// no dry-run mode.
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
    action_ledger: ActionLedger,
}

const DEFAULT_UNITS_ROOT: &str = "/etc/systemd/system";

const UNIT_FILE_MODE: u32 = 0o644;

const MAX_RETAINED_UNIT_BACKUPS: usize = 5;

const UNITS_LOCK_FILE: &str = ".toride-units.lock";

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
        Self::with_units_root(runner, PathBuf::from(DEFAULT_UNITS_ROOT))
    }

    /// Create a new `ServiceManager` that installs unit files under
    /// `units_root` instead of `/etc/systemd/system`, recording completed
    /// deploys in the ledger at `units_root`/[`LEDGER_FILE`](crate::ledger::LEDGER_FILE).
    pub fn with_units_root(
        runner: Box<dyn toride_runner::Runner>,
        units_root: impl Into<PathBuf>,
    ) -> Self {
        let units_root = units_root.into();
        let action_ledger = ActionLedger::in_root(&units_root);
        Self {
            runner,
            units_root,
            action_ledger,
        }
    }

    /// Create a new `ServiceManager` with an explicit
    /// [`ActionLedger`] instead of the default one derived from
    /// `units_root`.
    pub fn with_action_ledger(
        runner: Box<dyn toride_runner::Runner>,
        units_root: impl Into<PathBuf>,
        action_ledger: ActionLedger,
    ) -> Self {
        Self {
            runner,
            units_root: units_root.into(),
            action_ledger,
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
    /// code 0 and `Ok(false)` when it exits with code 1, the documented code
    /// for a unit that is not enabled. Any other exit (bus failure, missing
    /// unit, signal) returns [`Error::CommandFailed`] so callers can tell
    /// "not enabled" apart from "could not determine".
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] when `systemctl is-enabled` cannot be
    /// executed or exits with a code other than 0 or 1.
    pub fn is_enabled(&self, service: &str) -> Result<bool> {
        let (state, output) = self.enablement_state(service)?;
        match state {
            Enablement::Enabled => Ok(true),
            Enablement::Disabled => Ok(false),
            Enablement::Unknown => Err(command_failed("is-enabled", service, &output)),
        }
    }

    /// Query the current status of a service unit.
    ///
    /// Returns a [`ServiceStatus`] derived from the exit code and stdout of
    /// `systemctl is-active <service>` per systemctl(1): exit 0 means the unit
    /// is active and stdout is parsed; exit 3 with `inactive` stdout is a
    /// cleanly stopped unit; exit 4 means no such unit exists; every other
    /// outcome, including the `failed` state (which also exits 3), maps to
    /// [`ServiceStatus::Failed`].
    pub fn status(&self, service: &str) -> Result<ServiceStatus> {
        let output = self.run_systemctl("is-active", service)?;
        Ok(classify_is_active(&output))
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
    /// existing file or symlink to a timestamped sibling first, then writing
    /// atomically at mode 0644; name, backup, and write failures are typed.
    pub fn install_unit(&self, name: &str, contents: &str) -> Result<()> {
        Self::validate_unit_name(name)?;
        self.with_units_lock(|| self.prepare_unit(name, contents).map(|_| ()))
    }

    /// Install `name`, then daemon-reload, enable, start, and confirm the unit
    /// went active; on post-write failure the previous file and enablement
    /// state is restored and a rollback error returned ([`Error::DeployRolledBack`]).
    ///
    /// Once the activity check succeeds, one ledger record
    /// ([`ActionKind::UnitDeployed`]) is appended; a failed ledger write
    /// downgrades to a warning instead of failing or rolling back the
    /// working deploy.
    pub fn deploy_unit(&self, name: &str, contents: &str) -> Result<()> {
        Self::validate_unit_name(name)?;
        self.with_units_lock(|| self.deploy_unit_locked(name, contents))
    }

    fn deploy_unit_locked(&self, name: &str, contents: &str) -> Result<()> {
        let backup = self.prepare_unit(name, contents)?;
        let mut prior_enablement: Option<bool> = None;
        match self.activate_unit(name, contents, &mut prior_enablement) {
            Ok(()) => {
                if let Err(ledger_error) = self.record_deployed_unit(name) {
                    tracing::warn!(
                        unit = name,
                        error = %ledger_error,
                        "deploy succeeded but the action ledger append failed"
                    );
                }
                Self::delete_backup(backup.as_deref());
                Ok(())
            }
            Err(cause) => {
                let rollback = self.rollback_deployment(name, backup.as_deref(), prior_enablement);
                let rollback_restored = rollback.is_ok();
                if rollback_restored {
                    Self::delete_backup(backup.as_deref());
                }
                if let Err(reload_error) = self.daemon_reload() {
                    tracing::warn!(
                        unit = name,
                        error = %reload_error,
                        "post-rollback daemon-reload failed; systemd may hold a stale unit cache"
                    );
                }
                Err(match rollback {
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
                })
            }
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
        let spec = toride_runner::CommandSpec::new("systemctl").args([verb, "--", service]);
        Ok(self.runner.run(&spec)?)
    }

    /// Append the unit-deployed ledger record after the activity check.
    fn record_deployed_unit(&self, name: &str) -> LedgerResult<()> {
        self.action_ledger
            .append(ActionRecord::now(ActionKind::UnitDeployed {
                unit: name.to_owned(),
            }))
    }

    fn prepare_unit(&self, name: &str, contents: &str) -> Result<Option<PathBuf>> {
        Self::validate_unit_name(name)?;
        fs::create_dir_all(&self.units_root)?;
        let unit_path = self.unit_path(name);
        let backup = if unit_path.symlink_metadata().is_ok() {
            Some(self.backup_unit(name)?)
        } else {
            None
        };
        if let Err(write_error) =
            toride_fs::atomic_write_with_perms(&unit_path, contents, UNIT_FILE_MODE)
        {
            return Err(Self::restore_after_failed_write(
                name,
                &unit_path,
                backup.as_deref(),
                Error::Filesystem(write_error),
            ));
        }
        tracing::info!(unit = name, path = %unit_path.display(), "installed unit file");
        if backup.is_some() {
            self.prune_unit_backups(name);
        }
        Ok(backup)
    }

    /// Restore the pre-install unit file when the atomic write fails after a
    /// backup was taken, so a failed install cannot leave the unit missing.
    fn restore_after_failed_write(
        name: &str,
        unit_path: &Path,
        backup: Option<&Path>,
        cause: Error,
    ) -> Error {
        if let Some(backup_path) = backup {
            if let Err(restore_error) = rollback_unit(unit_path, Some(backup_path)) {
                tracing::error!(
                    unit = name,
                    error = %restore_error,
                    "atomic unit write failed and the backup restore failed too"
                );
                return Error::BackupFailed(format!(
                    "atomic unit write failed ({cause}) and restoring the backup failed too \
                     ({restore_error})"
                ));
            }
            tracing::warn!(
                unit = name,
                error = %cause,
                "atomic unit write failed; unit file restored from backup"
            );
        } else if unit_path.exists()
            && let Err(remove_error) = fs::remove_file(unit_path)
        {
            tracing::warn!(
                unit = name,
                error = %remove_error,
                "atomic unit write failed and removing the partial unit failed"
            );
        }
        cause
    }

    fn backup_unit(&self, name: &str) -> Result<PathBuf> {
        let source = self.unit_path(name);
        let dest = self
            .units_root
            .join(format!("{name}.bak.{}", unix_timestamp_nanos()));
        let file_type = fs::symlink_metadata(&source)
            .map_err(|e| Error::BackupFailed(format!("cannot stat {}: {e}", source.display())))?
            .file_type();
        let copied = if file_type.is_symlink() {
            backup_symlink(&source, &dest)
        } else if file_type.is_file() {
            fs::copy(&source, &dest).map(|_| ())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "unit path is neither a regular file nor a symlink",
            ))
        };
        copied.map_err(|e| {
            Error::BackupFailed(format!(
                "failed to back up {} to {}: {e}",
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

    /// Remove a spent backup so successful deploys do not litter the units
    /// root; failures are logged, never propagated.
    fn delete_backup(backup: Option<&Path>) {
        if let Some(path) = backup
            && let Err(e) = fs::remove_file(path)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(
                backup = %path.display(),
                error = %e,
                "could not remove the spent unit backup"
            );
        }
    }

    /// Cap retained `<unit>.bak.<nanos>` siblings for `name` at
    /// [`MAX_RETAINED_UNIT_BACKUPS`], newest first; prune failures are logged.
    fn prune_unit_backups(&self, name: &str) {
        let prefix = format!("{name}.bak.");
        let entries = match fs::read_dir(&self.units_root) {
            Ok(entries) => entries,
            Err(e) => {
                tracing::warn!(
                    root = %self.units_root.display(),
                    error = %e,
                    "could not list the units root to prune backups"
                );
                return;
            }
        };
        let mut backups: Vec<(u128, PathBuf)> = entries
            .filter_map(std::result::Result::ok)
            .filter_map(|entry| {
                let file_name = entry.file_name().into_string().ok()?;
                let stamp = file_name.strip_prefix(&prefix)?.parse::<u128>().ok()?;
                Some((stamp, entry.path()))
            })
            .collect();
        backups.sort_by_key(|&(stamp, _)| std::cmp::Reverse(stamp));
        for (_, path) in backups.into_iter().skip(MAX_RETAINED_UNIT_BACKUPS) {
            if let Err(e) = fs::remove_file(&path) {
                tracing::warn!(
                    backup = %path.display(),
                    error = %e,
                    "could not prune the old unit backup"
                );
            }
        }
    }

    fn with_units_lock<F>(&self, f: F) -> Result<()>
    where
        F: FnOnce() -> Result<()>,
    {
        fs::create_dir_all(&self.units_root)?;
        let lock_path = self.units_root.join(UNITS_LOCK_FILE);
        let mut outcome = Ok(());
        toride_fs::with_lock(&lock_path, || {
            outcome = f();
            Ok(())
        })?;
        outcome
    }

    fn activate_unit(
        &self,
        name: &str,
        contents: &str,
        prior_enablement: &mut Option<bool>,
    ) -> Result<()> {
        self.daemon_reload()?;
        let (state, _) = self.enablement_state(name)?;
        let prior = match state {
            Enablement::Enabled => Some(true),
            Enablement::Disabled => Some(false),
            Enablement::Unknown => {
                tracing::warn!(
                    unit = name,
                    "prior enablement could not be determined; rollback will not disable"
                );
                None
            }
        };
        *prior_enablement = prior;
        if prior != Some(true) {
            self.enable(name)?;
        }
        self.start(name)?;
        self.confirm_unit_running(name, contents)
    }

    /// Confirm the started unit reached a running or otherwise successful
    /// state, accepting a cleanly finished `Type=oneshot` unit (inactive with
    /// `Result=success`) as a successful start.
    fn confirm_unit_running(&self, name: &str, contents: &str) -> Result<()> {
        let output = self.run_systemctl("is-active", name)?;
        match classify_is_active(&output) {
            ServiceStatus::Active | ServiceStatus::Activating => Ok(()),
            ServiceStatus::Inactive if is_oneshot_unit(contents) => {
                if self.unit_start_result_is_success(name)? {
                    Ok(())
                } else {
                    Err(Error::ServiceFailed(format!(
                        "oneshot unit {name} finished without success"
                    )))
                }
            }
            _ => Err(Error::ServiceFailed(format!(
                "unit {name} did not become active after start"
            ))),
        }
    }

    /// Query `systemctl show -p Result,SubState` and report whether the unit's
    /// last start job completed with `Result=success`.
    fn unit_start_result_is_success(&self, name: &str) -> Result<bool> {
        Self::validate_service_name(name)?;
        tracing::debug!(service = name, "invoking systemctl show");
        let spec = toride_runner::CommandSpec::new("systemctl").args([
            "show",
            "-p",
            "Result,SubState",
            "--",
            name,
        ]);
        let output = self.runner.run(&spec)?;
        Ok(output.success && output.stdout.lines().any(|l| l.trim() == "Result=success"))
    }

    /// Run `systemctl is-enabled` and classify its exit code.
    fn enablement_state(
        &self,
        service: &str,
    ) -> Result<(Enablement, toride_runner::CommandOutput)> {
        let output = self.run_systemctl("is-enabled", service)?;
        let state = match output.exit_code {
            Some(0) => Enablement::Enabled,
            Some(1) => Enablement::Disabled,
            _ => Enablement::Unknown,
        };
        Ok((state, output))
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
        if name.starts_with('.') {
            return Err(Error::InvalidUnitName(format!(
                "must not start with '.': systemd ignores dotfile units: {name:?}"
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
        Some(backup_path) => restore_unit_from_backup(backup_path, unit_path),
        None => fs::remove_file(unit_path).map_err(Error::Io),
    }
}

fn restore_unit_from_backup(backup_path: &Path, unit_path: &Path) -> Result<()> {
    let file_type = fs::symlink_metadata(backup_path)
        .map_err(Error::Io)?
        .file_type();
    if file_type.is_symlink() {
        return restore_symlink_backup(backup_path, unit_path);
    }
    let bytes = fs::read(backup_path).map_err(Error::Io)?;
    let mode = backup_mode(backup_path).unwrap_or(UNIT_FILE_MODE);
    toride_fs::atomic_write_bytes_with_perms(unit_path, &bytes, mode).map_err(Error::from)
}

/// Mode bits (masked to 0o777) of a backup file, or `None` off Unix and when
/// the metadata is unreadable.
#[cfg(unix)]
fn backup_mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path)
        .ok()
        .map(|m| m.permissions().mode() & 0o777)
}

#[cfg(not(unix))]
fn backup_mode(_path: &Path) -> Option<u32> {
    None
}

#[cfg(unix)]
fn restore_symlink_backup(backup_path: &Path, unit_path: &Path) -> Result<()> {
    let target = fs::read_link(backup_path).map_err(Error::Io)?;
    let staging = unit_path.with_file_name(format!(
        "{}.restore.{}",
        unit_path.file_name().map_or_else(
            || unit_path.to_string_lossy().into_owned(),
            |name| name.to_string_lossy().into_owned()
        ),
        unix_timestamp_nanos()
    ));
    std::os::unix::fs::symlink(&target, &staging).map_err(Error::Io)?;
    if let Err(rename_error) = fs::rename(&staging, unit_path) {
        let fallback = fs::remove_file(unit_path).or_else(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(e)
            }
        });
        if let Err(fallback_error) = fallback.and_then(|()| fs::rename(&staging, unit_path)) {
            let _ = fs::remove_file(&staging);
            return Err(Error::Io(fallback_error));
        }
        tracing::warn!(
            error = %rename_error,
            staging = %staging.display(),
            "symlink restore fell back to remove plus rename"
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn restore_symlink_backup(_backup_path: &Path, _unit_path: &Path) -> Result<()> {
    Err(Error::BackupFailed(
        "restoring a symlinked unit file requires a unix target".to_owned(),
    ))
}

#[cfg(unix)]
fn backup_symlink(source: &Path, dest: &Path) -> std::io::Result<()> {
    let target = fs::read_link(source)?;
    std::os::unix::fs::symlink(&target, dest)
}

#[cfg(not(unix))]
fn backup_symlink(_source: &Path, _dest: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "backing up a symlinked unit file requires a unix target",
    ))
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

    use crate::ledger::LEDGER_FILE;

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
            "wrong args: expected the service name after a `--` guard"
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

    #[test]
    fn status_active_when_exit_zero_and_active_stdout() {
        let (mgr, _runner) = manager_with_output(CommandOutput::from_stdout("active\n"));
        let status = mgr.status("sshd").unwrap();
        assert_eq!(status, ServiceStatus::Active);
    }

    #[test]
    fn status_inactive_when_exit_three_and_inactive_stdout() {
        let (mgr, _runner) = manager_with_output(CommandOutput::new(
            "inactive\n".to_owned(),
            String::new(),
            Some(3),
        ));
        let status = mgr.status("sshd").unwrap();
        assert_eq!(status, ServiceStatus::Inactive);
    }

    #[test]
    fn status_unknown_when_exit_four_no_such_unit() {
        let (mgr, _runner) = manager_with_output(CommandOutput::new(
            "inactive\n".to_owned(),
            "Unit nosuch.service could not be found.\n".to_owned(),
            Some(4),
        ));
        let status = mgr.status("nosuch").unwrap();
        assert_eq!(status, ServiceStatus::Unknown);
    }

    #[test]
    fn status_failed_when_exit_three_with_failed_stdout() {
        let (mgr, _runner) = manager_with_output(CommandOutput::new(
            "failed\n".to_owned(),
            String::new(),
            Some(3),
        ));
        let status = mgr.status("broken").unwrap();
        assert_eq!(status, ServiceStatus::Failed);
    }

    #[test]
    fn status_failed_when_exit_one() {
        let (mgr, _runner) = manager_with_output(CommandOutput::new(
            String::new(),
            "Failed to connect to bus\n".to_owned(),
            Some(1),
        ));
        let status = mgr.status("sshd").unwrap();
        assert_eq!(status, ServiceStatus::Failed);
    }

    #[test]
    fn status_failed_when_killed_by_signal() {
        let (mgr, _runner) =
            manager_with_output(CommandOutput::new(String::new(), String::new(), None));
        let status = mgr.status("sshd").unwrap();
        assert_eq!(status, ServiceStatus::Failed);
    }

    #[test]
    fn status_parses_reloading_as_active() {
        let (mgr, _runner) = manager_with_output(CommandOutput::from_stdout("reloading\n"));
        let status = mgr.status("sshd").unwrap();
        assert_eq!(status, ServiceStatus::Active);
    }

    #[test]
    fn status_unknown_when_exit_zero_with_unrecognized_stdout() {
        let (mgr, _runner) = manager_with_output(CommandOutput::from_stdout("\n"));
        let status = mgr.status("sshd").unwrap();
        assert_eq!(status, ServiceStatus::Unknown);
    }

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
        active: bool,
        show_stdout: Option<String>,
    }

    impl VerbsRunner {
        fn succeeding() -> Self {
            Self::post_start_activity(true)
        }

        fn post_start_activity(active: bool) -> Self {
            Self {
                active,
                ..Self::default()
            }
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

        /// Model a oneshot unit's `systemctl show -p Result,SubState` output.
        fn with_show_stdout(self, stdout: &str) -> Self {
            Self {
                show_stdout: Some(stdout.to_owned()),
                ..self
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
            if let Some(stdout) = self.show_stdout.as_deref()
                && verb == Some("show")
            {
                return Ok(CommandOutput::from_stdout(stdout.to_owned()));
            }
            match verb {
                Some("is-enabled") => {
                    return Ok(CommandOutput::new(
                        String::new(),
                        String::new(),
                        Some(i32::from(!self.enabled)),
                    ));
                }
                Some("is-active") => {
                    let (state, code) = if self.active {
                        ("active", 0)
                    } else {
                        ("inactive", 3)
                    };
                    return Ok(CommandOutput::new(
                        format!("{state}\n"),
                        String::new(),
                        Some(code),
                    ));
                }
                _ => {}
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
            .filter(|n| n != "app.service" && n != UNITS_LOCK_FILE)
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

    /// A failed atomic write after a backup was taken must restore the
    /// pre-install unit file instead of propagating with the unit deleted:
    /// the exact window foundations-20 pins. The restore helper is exercised
    /// directly because the atomic-write failure itself (a post-rename chmod
    /// failing under an unprivileged test user) cannot be triggered from
    /// outside `toride-fs`.
    #[test]
    fn failed_write_after_backup_restores_the_previous_unit_file() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let mgr = ServiceManager::with_units_root(Box::new(CannedRunner::empty()), dir.path());
        fs::write(dir.path().join("app.service"), "previous unit contents")
            .expect("seed unit write should succeed");

        let backup = mgr
            .backup_unit("app.service")
            .expect("backup should succeed");
        fs::write(dir.path().join("app.service"), "half-written garbage")
            .expect("simulated destroyed unit write should succeed");

        let cause = Error::Io(std::io::Error::other("injected write failure"));
        let returned = ServiceManager::restore_after_failed_write(
            "app.service",
            &dir.path().join("app.service"),
            Some(&backup),
            cause,
        );

        assert!(
            returned.to_string().contains("injected write failure"),
            "the original write error must be returned: {returned}"
        );
        assert_eq!(
            fs::read_to_string(dir.path().join("app.service")).expect("unit file readable"),
            "previous unit contents",
            "the pre-install unit file must be restored, not left destroyed"
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

        assert_eq!(runner.invocation_count(), 5);
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
            runner.argv_at(4),
            (
                "systemctl".to_owned(),
                vec![
                    "is-active".to_owned(),
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

    /// A `Type=oneshot` unit that ran and exited 0 is `inactive` (exit 3)
    /// after a successful start; the deploy must confirm it via
    /// `systemctl show -p Result,SubState` instead of rolling it back.
    #[test]
    fn deploy_unit_accepts_oneshot_unit_that_ran_and_exited_cleanly() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let runner = VerbsRunner::post_start_activity(false)
            .with_show_stdout("Result=success\nSubState=dead\n");
        let mgr = ServiceManager::with_units_root(Box::new(runner.clone()), dir.path());
        let contents = "[Unit]\nDescription=one\n[Service]\nType=oneshot\nExecStart=/bin/true\n";

        mgr.deploy_unit("app.service", contents)
            .expect("a cleanly finished oneshot unit must count as deployed");

        assert_eq!(
            runner.argv_at(runner.invocation_count() - 1),
            (
                "systemctl".to_owned(),
                vec![
                    "show".to_owned(),
                    "-p".to_owned(),
                    "Result,SubState".to_owned(),
                    "--".to_owned(),
                    "app.service".to_owned()
                ]
            ),
            "the oneshot confirmation must query the start job result"
        );
    }

    /// The same oneshot unit whose start job did not succeed must still fail
    /// and roll back.
    #[test]
    fn deploy_unit_rejects_oneshot_unit_whose_job_failed() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let runner = VerbsRunner::post_start_activity(false).with_show_stdout("Result=failed\n");
        let mgr = ServiceManager::with_units_root(Box::new(runner.clone()), dir.path());
        let contents = "[Service]\nType=oneshot\nExecStart=/bin/false\n";

        let err = mgr
            .deploy_unit("app.service", contents)
            .expect_err("a failed oneshot start job must fail the deploy");

        assert!(matches!(err, Error::DeployRolledBack { .. }), "got {err:?}");
    }

    /// A redeploy of an already-enabled unit must skip the no-op enable
    /// spawn: 4 invocations instead of 5.
    #[test]
    fn deploy_unit_skips_enable_when_the_unit_is_already_enabled() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let runner = VerbsRunner {
            enabled: true,
            ..VerbsRunner::succeeding()
        };
        let mgr = ServiceManager::with_units_root(Box::new(runner.clone()), dir.path());

        mgr.deploy_unit("app.service", "[Unit]\n")
            .expect("deploy should succeed");

        let verbs: Vec<Option<String>> = (0..runner.invocation_count())
            .map(|i| runner.verb_at(i))
            .collect();
        assert_eq!(
            verbs,
            vec![
                Some("daemon-reload".to_owned()),
                Some("is-enabled".to_owned()),
                Some("start".to_owned()),
                Some("is-active".to_owned())
            ],
            "the enable spawn is a no-op round trip when the unit is already enabled"
        );
    }

    /// A successful deploy must not leave its backup sibling behind, and a
    /// failed deploy that restores the backup must remove it afterwards too.
    #[test]
    fn deploy_unit_removes_its_backup_once_the_outcome_is_settled() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        fs::write(dir.path().join("app.service"), "original")
            .expect("seed unit write should succeed");

        let ok_runner = VerbsRunner::succeeding();
        ServiceManager::with_units_root(Box::new(ok_runner), dir.path())
            .deploy_unit("app.service", "replacement")
            .expect("deploy should succeed");
        assert!(
            units_root_entries(&dir)
                .into_iter()
                .all(|n| n == "app.service" || n == UNITS_LOCK_FILE || n == LEDGER_FILE),
            "a successful deploy must delete its spent backup"
        );

        fs::write(dir.path().join("app.service"), "original")
            .expect("seed unit write should succeed");
        let fail_runner = VerbsRunner::failing_verb("start");
        let mgr = ServiceManager::with_units_root(Box::new(fail_runner), dir.path());
        let err = mgr
            .deploy_unit("app.service", "replacement 2")
            .expect_err("deploy must fail when start fails");
        assert!(matches!(err, Error::DeployRolledBack { .. }), "got {err:?}");
        assert!(
            units_root_entries(&dir)
                .into_iter()
                .all(|n| n == "app.service" || n == UNITS_LOCK_FILE || n == LEDGER_FILE),
            "a rollback that restored the backup must then remove it"
        );
        assert_eq!(
            ActionLedger::in_root(dir.path()).records().unwrap().len(),
            1,
            "only the earlier successful deploy is recorded; the rolled-back one is not"
        );
        assert_eq!(
            fs::read_to_string(dir.path().join("app.service")).expect("unit file readable"),
            "original"
        );
    }

    /// Repeated installs of the same unit must cap retained backups at
    /// [`MAX_RETAINED_UNIT_BACKUPS`], keeping the newest.
    #[test]
    fn install_unit_caps_retained_backups_per_unit() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let mgr = ServiceManager::with_units_root(Box::new(CannedRunner::empty()), dir.path());

        for round in 0..(MAX_RETAINED_UNIT_BACKUPS + 3) {
            fs::write(dir.path().join("app.service"), format!("round {round}"))
                .expect("seed unit write should succeed");
            mgr.install_unit("app.service", "new contents")
                .expect("install should succeed");
        }

        let backups: Vec<String> = units_root_entries(&dir)
            .into_iter()
            .filter(|n| n.starts_with("app.service.bak."))
            .collect();
        assert_eq!(
            backups.len(),
            MAX_RETAINED_UNIT_BACKUPS,
            "retained backups must be capped at {MAX_RETAINED_UNIT_BACKUPS}: {backups:?}"
        );
    }

    /// The ledger record is written only after the post-start activity
    /// check confirms the unit, never for a deploy that failed to start.
    #[test]
    fn deploy_unit_records_the_deployment_after_the_activity_check() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let runner = VerbsRunner::succeeding();
        let mgr = ServiceManager::with_units_root(Box::new(runner.clone()), dir.path());

        mgr.deploy_unit("app.service", "[Unit]\n")
            .expect("deploy should succeed");

        let records = ActionLedger::in_root(dir.path()).records().unwrap();
        assert_eq!(records.len(), 1, "one record per deploy: {records:?}");
        assert_eq!(
            records[0].action,
            ActionKind::UnitDeployed {
                unit: String::from("app.service")
            }
        );
    }

    #[test]
    fn deploy_unit_records_nothing_when_the_unit_never_becomes_active() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let runner = VerbsRunner::post_start_activity(false);
        let mgr = ServiceManager::with_units_root(Box::new(runner), dir.path());

        let err = mgr
            .deploy_unit("app.service", "dies immediately")
            .expect_err("a unit that never becomes active must fail the deploy");

        assert!(matches!(err, Error::DeployRolledBack { .. }), "got {err:?}");
        assert!(
            !dir.path().join(LEDGER_FILE).exists(),
            "a deploy that failed the activity check must leave no ledger record"
        );
    }

    #[test]
    fn install_unit_records_nothing() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let mgr = ServiceManager::with_units_root(Box::new(CannedRunner::empty()), dir.path());

        mgr.install_unit("app.service", "[Unit]\n")
            .expect("install should succeed");

        assert!(
            !dir.path().join(LEDGER_FILE).exists(),
            "install_unit starts nothing, so it records nothing"
        );
    }

    #[test]
    fn deploy_unit_survives_a_failing_ledger() {
        let units = TempDir::new().expect("temp dir creation should succeed");
        let broken_ledger_dir = TempDir::new().expect("temp dir creation should succeed");
        let ledger = ActionLedger::at(broken_ledger_dir.path());
        let runner = VerbsRunner::succeeding();
        let mgr = ServiceManager::with_action_ledger(Box::new(runner), units.path(), ledger);

        let outcome = mgr.deploy_unit("app.service", "[Unit]\n");

        assert!(
            outcome.is_ok(),
            "a failed ledger append must not fail the working deploy: {outcome:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn restore_symlink_backup_restores_over_an_absent_unit_path() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let backup = dir.path().join("app.service.bak.1");
        std::os::unix::fs::symlink("/dev/null", &backup)
            .expect("backup symlink creation should succeed");
        let unit_path = dir.path().join("app.service");

        restore_symlink_backup(&backup, &unit_path)
            .expect("restoring over a missing unit path must not require a remove first");

        assert!(
            unit_path
                .symlink_metadata()
                .expect("unit metadata should be available")
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read_link(&unit_path).expect("restored link target readable"),
            Path::new("/dev/null")
        );
    }

    #[cfg(unix)]
    #[test]
    fn restore_symlink_backup_leaves_no_staging_sibling() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let backup = dir.path().join("app.service.bak.1");
        std::os::unix::fs::symlink("/dev/null", &backup)
            .expect("backup symlink creation should succeed");
        let unit_path = dir.path().join("app.service");
        fs::write(&unit_path, "replaced regular unit").expect("seed unit write should succeed");

        restore_symlink_backup(&backup, &unit_path)
            .expect("restore over an existing unit should succeed");

        assert_eq!(
            units_root_entries(&dir),
            vec!["app.service".to_owned(), "app.service.bak.1".to_owned()],
            "the staging sibling must be renamed away, never left behind"
        );
    }

    #[test]
    fn deploy_unit_rolls_back_when_unit_never_becomes_active() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let runner = VerbsRunner::post_start_activity(false);
        let mgr = ServiceManager::with_units_root(Box::new(runner.clone()), dir.path());

        let err = mgr
            .deploy_unit("app.service", "dies immediately")
            .expect_err("a unit that never becomes active must fail the deploy");

        match &err {
            Error::DeployRolledBack { unit, cause } => {
                assert_eq!(unit, "app.service");
                assert!(
                    matches!(**cause, Error::ServiceFailed(_)),
                    "cause must be the post-start inactivity check: {cause}"
                );
            }
            other => panic!("expected DeployRolledBack, got {other:?}"),
        }
        assert!(
            !dir.path().join("app.service").exists(),
            "the rolled-back deploy must not leave the unit file behind"
        );
        assert_eq!(
            runner.verb_at(4),
            Some("is-active".to_owned()),
            "the deploy must verify activity after start"
        );
        assert_eq!(
            runner.verb_at(5),
            Some("disable".to_owned()),
            "rollback must undo the enablement after the failed activity check"
        );
        assert_eq!(
            runner.invocation_count(),
            7,
            "reload, is-enabled, enable, start, is-active, rollback disable, best-effort reload"
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
        assert!(
            !verbs.contains(&Some("enable".to_owned())),
            "a unit already enabled must not be re-enabled: {verbs:?}"
        );
        assert_eq!(
            runner.invocation_count(),
            4,
            "reload, is-enabled, start, best-effort reload; enable is skipped and no disable runs"
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
            vec![UNITS_LOCK_FILE.to_owned()],
            "no backup exists and no unit file may remain, only the lock file"
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
    fn backup_failure_is_typed_when_existing_unit_is_unreadable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().expect("temp dir creation should succeed");
        let units = dir.path().join("units");
        fs::create_dir(&units).expect("units root creation should succeed");
        let unit = units.join("app.service");
        fs::write(&unit, "original\n").expect("seed unit write should succeed");

        fs::set_permissions(&unit, fs::Permissions::from_mode(0o000))
            .expect("chmod should succeed");
        let readable_anyway = fs::read_to_string(&unit).is_ok();
        let result = if readable_anyway {
            Ok(())
        } else {
            ServiceManager::with_units_root(Box::new(CannedRunner::empty()), &units)
                .install_unit("app.service", "replacement\n")
        };
        fs::set_permissions(&unit, fs::Permissions::from_mode(0o644))
            .expect("chmod restore should succeed");

        if readable_anyway {
            return;
        }
        let err = result.expect_err("backup copy must fail for an unreadable unit file");
        assert!(matches!(err, Error::BackupFailed(_)), "got {err:?}");
        assert_eq!(
            fs::read_to_string(&unit).expect("original readable again"),
            "original\n",
            "the failed install must leave the original unit untouched"
        );
    }

    #[cfg(unix)]
    #[test]
    fn install_unit_backs_up_symlinked_unit_as_a_symlink() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let real = dir.path().join("real.conf");
        fs::write(&real, "old contents").expect("seed target write should succeed");
        std::os::unix::fs::symlink(&real, dir.path().join("app.service"))
            .expect("symlink creation should succeed");
        let mgr = ServiceManager::with_units_root(Box::new(CannedRunner::empty()), dir.path());

        mgr.install_unit("app.service", "new contents")
            .expect("install should succeed");

        let unit_path = dir.path().join("app.service");
        assert!(
            unit_path
                .symlink_metadata()
                .expect("unit metadata should be available")
                .file_type()
                .is_file(),
            "the atomic rename must replace the symlink with the regular file"
        );
        assert_eq!(
            fs::read_to_string(&unit_path).expect("unit file readable"),
            "new contents"
        );
        let backup_name = units_root_entries(&dir)
            .into_iter()
            .find(|n| n != "app.service" && n != UNITS_LOCK_FILE)
            .expect("a backup sibling must exist");
        let backup = dir.path().join(&backup_name);
        assert!(
            backup
                .symlink_metadata()
                .expect("backup metadata should be available")
                .file_type()
                .is_symlink(),
            "the backup must preserve that the unit was a symlink"
        );
        assert_eq!(
            fs::read_link(&backup).expect("backup link target readable"),
            real,
            "the backup symlink must point at the original target"
        );
        assert_eq!(
            fs::read_to_string(&backup).expect("backup contents readable through the link"),
            "old contents"
        );
    }

    #[cfg(unix)]
    #[test]
    fn deploy_unit_restores_masked_symlink_when_start_fails() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let unit_path = dir.path().join("app.service");
        std::os::unix::fs::symlink("/dev/null", &unit_path)
            .expect("mask symlink creation should succeed");
        let runner = VerbsRunner::failing_verb("start");
        let mgr = ServiceManager::with_units_root(Box::new(runner.clone()), dir.path());

        let err = mgr
            .deploy_unit("app.service", "real unit")
            .expect_err("deploy must fail when start fails");

        assert!(matches!(err, Error::DeployRolledBack { .. }), "got {err:?}");
        let meta = unit_path
            .symlink_metadata()
            .expect("unit metadata should be available");
        assert!(
            meta.file_type().is_symlink(),
            "the pre-deploy mask symlink must be restored, not left as a regular file or removed"
        );
        assert_eq!(
            fs::read_link(&unit_path).expect("restored link target readable"),
            Path::new("/dev/null"),
            "the restored mask must still point at /dev/null"
        );
    }

    #[cfg(unix)]
    #[test]
    fn deploy_unit_restores_backup_atomically_at_unit_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().expect("temp dir creation should succeed");
        let unit_path = dir.path().join("app.service");
        fs::write(&unit_path, "original").expect("seed unit write should succeed");
        fs::set_permissions(&unit_path, fs::Permissions::from_mode(0o600))
            .expect("chmod should succeed");
        let runner = VerbsRunner::failing_verb("start");
        let mgr = ServiceManager::with_units_root(Box::new(runner.clone()), dir.path());

        let err = mgr
            .deploy_unit("app.service", "replacement")
            .expect_err("deploy must fail when start fails");

        assert!(matches!(err, Error::DeployRolledBack { .. }), "got {err:?}");
        assert_eq!(
            fs::read_to_string(&unit_path).expect("unit file readable"),
            "original"
        );
        let mode = fs::metadata(&unit_path)
            .expect("metadata should be available")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "the restore must preserve the backup's original mode, not normalize to 0o644"
        );
    }

    /// A backup containing non-UTF-8 bytes must still be restorable: the
    /// recovery path reads bytes and writes bytes, never a UTF-8 string.
    #[cfg(unix)]
    #[test]
    fn deploy_unit_restores_a_non_utf8_backup() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let unit_path = dir.path().join("app.service");
        fs::write(&unit_path, b"original \xff\xfe bytes").expect("seed unit write should succeed");
        let runner = VerbsRunner::failing_verb("start");
        let mgr = ServiceManager::with_units_root(Box::new(runner.clone()), dir.path());

        let err = mgr
            .deploy_unit("app.service", "replacement")
            .expect_err("deploy must fail when start fails");

        assert!(matches!(err, Error::DeployRolledBack { .. }), "got {err:?}");
        assert_eq!(
            fs::read(&unit_path).expect("unit file readable"),
            b"original \xff\xfe bytes",
            "the non-UTF-8 original must be restored byte for byte"
        );
    }

    #[test]
    fn install_unit_blocks_while_the_units_lock_is_held() {
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let dir = TempDir::new().expect("temp dir creation should succeed");
        let runner = CannedRunner::empty();
        let units_root = dir.path().to_path_buf();
        let lock_path = dir.path().join(UNITS_LOCK_FILE);
        let (tx, rx) = mpsc::channel();
        let mut spawned = None;
        toride_fs::with_lock(&lock_path, || {
            let units_root = units_root.clone();
            let runner = runner.clone();
            let tx = tx.clone();
            spawned = Some(thread::spawn(move || {
                let mgr = ServiceManager::with_units_root(Box::new(runner), &units_root);
                let _ = mgr.install_unit("app.service", "written after lock release");
                let _ = tx.send(());
            }));
            thread::sleep(Duration::from_millis(100));
            assert!(
                rx.try_recv().is_err(),
                "install_unit must block while another holder owns the units lock"
            );
            Ok(())
        })
        .expect("holding the units lock should succeed");
        rx.recv_timeout(Duration::from_secs(10))
            .expect("install_unit must complete once the lock is released");
        spawned
            .expect("install thread must have been spawned")
            .join()
            .expect("install thread must not panic");
        assert_eq!(
            fs::read_to_string(dir.path().join("app.service")).expect("unit file readable"),
            "written after lock release"
        );
        assert!(
            lock_path.is_file(),
            "the lock file must live in the units root"
        );
    }
}
