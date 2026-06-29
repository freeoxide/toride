//! Backup scheduling via systemd timers or cron.
//!
//! Manages the creation, validation, and lifecycle of backup schedules.
//! Supports systemd timer units (preferred on modern Linux) and cron
//! fallback for other systems.
//!
//! # systemd backend
//!
//! `install_systemd_timer` writes a real `.service` + `.timer` unit pair into
//! `/etc/systemd/system` (see systemd.unit(5) load path), runs
//! `systemctl daemon-reload`, then `systemctl enable --now <timer>.timer`. The
//! `.service` unit's `ExecStart=` invokes the toride-backup CLI to run the job
//! by name (`toride-backup backup <name>`) — the standard systemd-timer
//! pattern of "a thin service that runs one command", which keeps the schedule
//! decoupled from the full `BackupSpec` (the spec lives in the config file the
//! CLI reads).
//!
//! # cron backend
//!
//! `install_cron` writes a marked crontab entry into `/etc/cron.d/<name>`
//! using the 5-field format from crontab(5)
//! (<https://man7.org/linux/man-pages/man5/crontab.5.html>).

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use std::fmt::Write as _;

use crate::spec::Schedule;
use crate::systemd;
use crate::{Error, Result};
use toride_runner::{CommandSpec, DuctRunner, Runner};

// ---------------------------------------------------------------------------
// ScheduleBackend
// ---------------------------------------------------------------------------

/// Backend used for scheduling backups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScheduleBackend {
    /// Use systemd timer units (preferred on modern Linux).
    #[default]
    SystemdTimer,
    /// Use cron (crontab entries).
    Cron,
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

/// Directory holding per-job drop-in crontab files. `/etc/cron.d` entries are
/// read by cron alongside the system crontab (crontab(5)). Each file is a
/// complete crontab fragment.
const DEFAULT_CRON_D_DIR: &str = "/etc/cron.d";

/// CLI invoked by the generated `.service` unit / crontab line to run a job.
/// Defaults to the toride-backup binary name; overridable in tests.
const DEFAULT_CLI_BIN: &str = "toride-backup";

/// A process-wide override for the unit-file directory and cron directory.
/// Production callers leave these as the system defaults; tests inject temp
/// directories via [`ScheduleManager::with_dirs`].
fn default_unit_dir() -> &'static Path {
    static V: OnceLock<PathBuf> = OnceLock::new();
    V.get_or_init(|| PathBuf::from(systemd::SYSTEMD_UNIT_DIR))
}

// ---------------------------------------------------------------------------
// ScheduleManager
// ---------------------------------------------------------------------------

/// Manages backup schedule installation and removal.
///
/// Creates and manages systemd timer units or cron entries for backup jobs.
/// Each backup spec maps to one schedule entry.
///
/// All `systemctl` / `crontab` invocations are routed through a
/// [`toride_runner::Runner`], so the manager is fully testable via
/// [`FakeRunner`](toride_runner::FakeRunner). The default runner is a
/// [`DuctRunner`]; inject a custom one with [`ScheduleManager::with_runner`].
pub struct ScheduleManager {
    /// Which scheduling backend to use.
    backend: ScheduleBackend,
    /// Command runner used for systemctl / crontab invocations.
    runner: Box<dyn Runner>,
    /// Directory where systemd unit files are written.
    unit_dir: PathBuf,
    /// Directory where cron.d drop-in files are written.
    cron_dir: PathBuf,
    /// The CLI binary the generated units / crontab lines invoke.
    cli_bin: String,
}

impl ScheduleManager {
    /// Create a schedule manager targeting the default backend (systemd) with
    /// a [`DuctRunner`] and the system unit / cron directories.
    pub fn new() -> Self {
        Self {
            backend: ScheduleBackend::default(),
            runner: Box::new(DuctRunner),
            unit_dir: default_unit_dir().to_owned(),
            cron_dir: PathBuf::from(DEFAULT_CRON_D_DIR),
            cli_bin: DEFAULT_CLI_BIN.to_owned(),
        }
    }

    /// Create a schedule manager targeting a specific backend.
    pub fn with_backend(backend: ScheduleBackend) -> Self {
        let mut mgr = Self::new();
        mgr.backend = backend;
        mgr
    }

    /// Inject a custom command runner (used for tests and dry-run modes).
    #[must_use]
    pub fn with_runner(mut self, runner: Box<dyn Runner>) -> Self {
        self.runner = runner;
        self
    }

    /// Override the directory where systemd unit files are written and the
    /// directory where cron.d drop-in files are written.
    ///
    /// Production paths are `/etc/systemd/system` and `/etc/cron.d`; tests
    /// pass a temp directory so they don't need root.
    #[must_use]
    pub fn with_dirs(mut self, unit_dir: impl Into<PathBuf>, cron_dir: impl Into<PathBuf>) -> Self {
        self.unit_dir = unit_dir.into();
        self.cron_dir = cron_dir.into();
        self
    }

    /// Override the CLI binary invoked by generated units / crontab lines.
    #[must_use]
    pub fn with_cli_bin(mut self, bin: impl Into<String>) -> Self {
        self.cli_bin = bin.into();
        self
    }

    /// Install a schedule for the given backup job name.
    ///
    /// For systemd timers, this creates a `.service` and `.timer` unit pair,
    /// reloads systemd, and enables + starts the timer. For cron, this writes
    /// a marked crontab entry under `/etc/cron.d`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ScheduleError`] if the schedule cannot be installed
    /// (invalid cron, unit-file write failure, or systemctl failure).
    pub fn install(&self, name: &str, schedule: &Schedule) -> Result<()> {
        schedule.validate()?;

        match self.backend {
            ScheduleBackend::SystemdTimer => self.install_systemd_timer(name, schedule),
            ScheduleBackend::Cron => self.install_cron(name, schedule),
        }
    }

    /// Remove a schedule for the given backup job name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ScheduleError`] if the schedule cannot be removed.
    pub fn remove(&self, name: &str) -> Result<()> {
        match self.backend {
            ScheduleBackend::SystemdTimer => self.remove_systemd_timer(name),
            ScheduleBackend::Cron => self.remove_cron(name),
        }
    }

    /// Check whether a schedule is installed for the given backup job.
    ///
    /// For the systemd backend this performs a **real** probe: it first checks
    /// that systemd is the running init system on this host (via
    /// [`crate::systemd::detect`]); if systemd is absent it honestly reports
    /// `Ok(false)` and records an informational note (see
    /// [`schedule_note`](Self::schedule_note)). When systemd is present it
    /// looks for the job's timer unit (and, more broadly, any backup-related
    /// timer) via `systemctl cat` / `systemctl list-timers`. The cron backend
    /// checks for the job's cron.d drop-in file on disk.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ScheduleError`] if the check fails.
    pub fn is_installed(&self, name: &str) -> Result<bool> {
        match self.backend {
            ScheduleBackend::SystemdTimer => Ok(self.is_systemd_timer_installed(name)),
            ScheduleBackend::Cron => Ok(self.is_cron_installed(name)),
        }
    }

    /// Return an informational note explaining the most recent schedule probe.
    ///
    /// Performs a fresh systemd detection probe and returns `"systemd not
    /// detected"` when systemd is absent on this host, or an empty string when
    /// systemd is present (in which case `is_installed` reflects the real
    /// unit-file state). This lets the UI surface *why* a schedule read as
    /// `false` without changing the `is_installed` return type.
    pub fn schedule_note(&self) -> String {
        let detected = crate::systemd::detect();
        if detected.available {
            String::new()
        } else {
            detected.note
        }
    }

    // -----------------------------------------------------------------------
    // Systemd timer implementation
    // -----------------------------------------------------------------------

    /// Run a checked command through the runner, mapping
    /// [`toride_runner::Error`] into [`crate::Error`]. The runner's error type
    /// is a sibling of this crate's `Error` (no shared `From`), so we translate
    /// by `Display`, classifying binary-not-found vs other command failures.
    fn run(&self, spec: &CommandSpec) -> Result<()> {
        self.runner
            .run_checked(spec)
            .map(|_| ())
            .map_err(map_runner_error)
    }

    fn install_systemd_timer(&self, name: &str, schedule: &Schedule) -> Result<()> {
        let (service_unit, timer_unit) = systemd::unit_names(name);

        // Render the real unit-file bodies. The .service runs the managed CLI
        // by job name (ExecStart=<cli_bin> backup <name>); the passphrase is
        // owned by the CLI at runtime and never appears in the unit file.
        let exec_start = cli_exec_start(&self.cli_bin, name);
        let service_body = systemd::render_cli_service_unit(name, &exec_start);
        let timer_body = systemd::render_timer_unit(name, schedule)?;

        // Write both unit files. Writes are best-effort: a missing parent dir
        // (e.g. /etc/systemd/system on a non-systemd host) is an install-time
        // error surfaced to the caller.
        let service_path = self.unit_dir.join(&service_unit);
        let timer_path = self.unit_dir.join(&timer_unit);
        // Defense-in-depth: even though unit_names() sanitizes the job name,
        // assert both resolved paths stay *inside* the managed unit dir before
        // writing — refusing rather than emitting if a path escapes it.
        assert_inside_dir(&service_path, &self.unit_dir)?;
        assert_inside_dir(&timer_path, &self.unit_dir)?;
        std::fs::create_dir_all(&self.unit_dir).map_err(|e| {
            Error::ScheduleError(format!(
                "could not create unit dir {}: {e}",
                self.unit_dir.display()
            ))
        })?;
        std::fs::write(&service_path, &service_body).map_err(|e| {
            Error::ScheduleError(format!("could not write {}: {e}", service_path.display()))
        })?;
        std::fs::write(&timer_path, &timer_body).map_err(|e| {
            Error::ScheduleError(format!("could not write {}: {e}", timer_path.display()))
        })?;

        tracing::info!(unit = %timer_unit, "wrote systemd unit files");

        // Pick up the new unit files, then enable + start the timer.
        self.run(&systemd::daemon_reload_spec())?;
        self.run(&systemd::enable_now_spec(&timer_unit))?;

        tracing::info!(unit = %timer_unit, "enabled + started systemd timer");
        Ok(())
    }

    fn remove_systemd_timer(&self, name: &str) -> Result<()> {
        let (service_unit, timer_unit) = systemd::unit_names(name);

        // Stop + disable first (best-effort: ignore failure if already gone).
        let _ = self.runner.run(&systemd::disable_now_spec(&timer_unit));

        // Remove the unit files.
        for unit in [service_unit.as_str(), timer_unit.as_str()] {
            let path = self.unit_dir.join(unit);
            if path.exists() {
                std::fs::remove_file(&path).map_err(|e| {
                    Error::ScheduleError(format!("could not remove {}: {e}", path.display()))
                })?;
            }
        }

        // Reload so systemd forgets the removed units.
        self.run(&systemd::daemon_reload_spec())?;
        tracing::info!(name = %name, "removed systemd timer");
        Ok(())
    }

    fn is_systemd_timer_installed(&self, name: &str) -> bool {
        // If the unit file is present on disk in our managed dir, the schedule
        // is installed regardless of the host's init system (this lets the
        // answer be honest on a systemd-absent box where files were written
        // out-of-band). Otherwise fall through to the live systemd probe.
        let (_, timer_unit) = systemd::unit_names(name);
        let timer_path = self.unit_dir.join(&timer_unit);
        if timer_path.exists() {
            return true;
        }

        let detected = crate::systemd::detect();
        if !detected.available {
            tracing::debug!(note = %detected.note, "systemd absent; reporting schedule_installed=false");
            return false;
        }
        let probe = crate::systemd::probe_timer(&timer_unit);
        if probe.installed {
            return true;
        }
        crate::systemd::any_backup_timer_installed()
    }

    // -----------------------------------------------------------------------
    // Cron implementation
    // -----------------------------------------------------------------------

    fn install_cron(&self, name: &str, schedule: &Schedule) -> Result<()> {
        schedule.validate()?;
        let entry = self.render_cron_entry(name, schedule)?;

        std::fs::create_dir_all(&self.cron_dir).map_err(|e| {
            Error::ScheduleError(format!(
                "could not create cron dir {}: {e}",
                self.cron_dir.display()
            ))
        })?;
        // cron.d filenames must match `[a-zA-Z0-9_-]+`; sanitize the job name.
        let safe = sanitize_cron_filename(name);
        let path = self.cron_dir.join(format!("toride-backup-{safe}"));
        std::fs::write(&path, &entry).map_err(|e| {
            Error::ScheduleError(format!("could not write {}: {e}", path.display()))
        })?;

        tracing::info!(name = %name, path = %path.display(), "installed cron entry");
        Ok(())
    }

    fn remove_cron(&self, name: &str) -> Result<()> {
        let safe = sanitize_cron_filename(name);
        let path = self.cron_dir.join(format!("toride-backup-{safe}"));
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| {
                Error::ScheduleError(format!("could not remove {}: {e}", path.display()))
            })?;
            tracing::info!(name = %name, "removed cron entry");
        }
        Ok(())
    }

    fn is_cron_installed(&self, name: &str) -> bool {
        let safe = sanitize_cron_filename(name);
        let path = self.cron_dir.join(format!("toride-backup-{safe}"));
        path.exists()
    }

    // -----------------------------------------------------------------------
    // Rendering helpers (file-local)
    // -----------------------------------------------------------------------

    /// Render the marked crontab entry for a job.
    ///
    /// Format (crontab(5), <https://man7.org/linux/man-pages/man5/crontab.5.html>):
    ///
    /// ```text
    /// # toride-backup:BEGIN:<name>
    /// SHELL=/bin/sh
    /// <min> <hour> <dom> <month> <dow> <user> toride-backup backup <name>
    /// # toride-backup:END:<name>
    /// ```
    ///
    /// SECURITY: the job `name` and cron tokens are interpolated raw into a
    /// `SHELL=/bin/sh` root cron line, so both are defensively validated here
    /// (in addition to `Schedule::validate` / `BackupSpec::validate`) and the
    /// entry is refused rather than emitted when either fails the allowlist.
    fn render_cron_entry(&self, name: &str, schedule: &Schedule) -> Result<String> {
        if !crate::spec::is_valid_name(name) {
            return Err(Error::ScheduleError(format!(
                "cron job name {name:?} must match ^[A-Za-z0-9._-]+$ \
                 (no spaces, shell, or path separators)"
            )));
        }
        // Validate the cron expression itself (field count + per-field
        // allowlist) before interpolating any token.
        schedule.validate()?;

        let mut s = String::new();
        let _ = writeln!(s, "{}{name}", systemd::CRON_MARKER_BEGIN);
        s.push_str("SHELL=/bin/sh\n");
        s.push_str("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n");
        // The 5 cron fields, then `root` (system cron.d lines require a user
        // field), then the command.
        let _ = writeln!(
            s,
            "{cron} root {bin} backup {name}",
            cron = schedule.cron,
            bin = self.cli_bin
        );
        let _ = writeln!(s, "{}{name}", systemd::CRON_MARKER_END);
        Ok(s)
    }
}

impl Default for ScheduleManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------------

/// Map a [`toride_runner::Error`] into this crate's [`Error`].
///
/// The two enums are siblings (no shared `From`), so we translate by variant:
/// `BinaryNotFound` is preserved, everything else becomes
/// [`Error::CommandFailed`] using the runner error's `Display`. This keeps
/// errors actionable without leaking secret-bearing args (the runner's own
/// `CommandFailed` already scrubs stderr via `display::scrub_stderr`).
fn map_runner_error(e: toride_runner::Error) -> Error {
    match e {
        toride_runner::Error::BinaryNotFound(name) => Error::BinaryNotFound(name),
        other => Error::CommandFailed(other.to_string()),
    }
}

/// Build the `CommandSpec` that the generated `.service` unit's `ExecStart=`
/// runs. This is the **managed** invocation: the toride-backup CLI runs the
/// job by name, which reads the full spec from its config file.
///
/// Returned separately (rather than embedded in a `BackupSpec`) so callers and
/// tests can assert the exact `ExecStart=` string without reconstructing a
/// spec. The passphrase is **never** on this command line — the CLI sources it
/// from its own config at runtime.
pub fn cli_exec_start(cli_bin: &str, name: &str) -> String {
    format!("{cli_bin} backup {name}")
}

/// Reduce an arbitrary job name to a cron.d-safe filename
/// (`[A-Za-z0-9_-]`). cron(8) silently ignores files in `/etc/cron.d` whose
/// names contain a `.` or other characters outside that set.
fn sanitize_cron_filename(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push_str("job");
    }
    out
}

/// Assert that `path` resolves to a location inside `dir`.
///
/// Defense-in-depth guard for unit-file writes: after joining the (already
/// sanitized) unit name onto the unit dir, confirm the resolved path still
/// lives under that dir. Returns [`Error::ScheduleError`] if the path escapes
/// `dir` rather than writing outside it.
fn assert_inside_dir(path: &Path, dir: &Path) -> Result<()> {
    if path.strip_prefix(dir).is_ok() {
        Ok(())
    } else {
        Err(Error::ScheduleError(format!(
            "refusing to write {}: resolved path escapes unit dir {}",
            path.display(),
            dir.display()
        )))
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::Schedule;
    use toride_runner::{CommandOutput, FakeRunner};

    /// Build a manager that writes into a temp unit/cron dir and routes
    /// systemctl invocations through a `FakeRunner`.
    fn mgr_with_temp(
        backend: ScheduleBackend,
        runner: FakeRunner,
    ) -> (ScheduleManager, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let unit_dir = dir.path().join("systemd");
        let cron_dir = dir.path().join("cron.d");
        std::fs::create_dir_all(&unit_dir).unwrap();
        std::fs::create_dir_all(&cron_dir).unwrap();
        let mgr = ScheduleManager::with_backend(backend)
            .with_runner(Box::new(runner))
            .with_dirs(unit_dir, cron_dir)
            .with_cli_bin("toride-backup");
        (mgr, dir)
    }

    // -----------------------------------------------------------------------
    // systemd timer install — exact-command + file-content assertions
    // -----------------------------------------------------------------------

    #[test]
    fn install_systemd_writes_units_with_correct_execstart() {
        // FakeRunner in lenient mode returns empty success for both systemctl
        // calls; we assert the WRITTEN unit-file contents rather than the
        // runner calls (the next test covers the exact commands).
        let runner = FakeRunner::new()
            .push_response(CommandOutput::from_stdout("")) // daemon-reload
            .push_response(CommandOutput::from_stdout("")); // enable --now
        let (mgr, _dir) = mgr_with_temp(ScheduleBackend::SystemdTimer, runner);

        mgr.install("nightly", &Schedule::new("0 2 * * *"))
            .expect("install");

        let svc = mgr.unit_dir.join("toride-backup-nightly.service");
        let tmr = mgr.unit_dir.join("toride-backup-nightly.timer");
        assert!(svc.exists(), "service unit not written");
        assert!(tmr.exists(), "timer unit not written");

        let svc_body = std::fs::read_to_string(&svc).unwrap();
        // ExecStart runs the managed CLI by job name — passphrase NOT on CLI.
        // This is the standard systemd-timer pattern (systemd.service(5)):
        // https://www.freedesktop.org/software/systemd/man/systemd.service.html
        assert!(
            svc_body.contains("ExecStart=toride-backup backup nightly"),
            "expected CLI ExecStart, got: {svc_body}"
        );
        assert!(
            !svc_body.contains("--password"),
            "passphrase must not be a CLI flag: {svc_body}"
        );
        assert!(svc_body.contains("Type=oneshot"));

        let tmr_body = std::fs::read_to_string(&tmr).unwrap();
        // systemd.timer(5) OnCalendar translation of "0 2 * * *".
        // https://www.freedesktop.org/software/systemd/man/systemd.timer.html
        assert!(tmr_body.contains("OnCalendar=*-*-* 02:00:00"));
        assert!(tmr_body.contains("Persistent=true"));
        assert!(tmr_body.contains("WantedBy=timers.target"));
    }

    #[test]
    fn install_systemd_builds_exact_daemon_reload_and_enable_now() {
        // STRICT-mode FakeRunner: each expected systemctl command is registered
        // via `respond`. If install builds a DIFFERENT spec (wrong program,
        // args, or flags), strict mode returns an error and install fails —
        // proving install dispatches precisely these commands.
        // Source: systemctl(1) — `daemon-reload`, `enable --now UNIT`.
        //   https://www.freedesktop.org/software/systemd/man/systemctl.html
        let expected_reload = CommandSpec::new("systemctl").args(["daemon-reload"]);
        let expected_enable = CommandSpec::new("systemctl").args([
            "enable",
            "--now",
            "--",
            "toride-backup-nightly.timer",
        ]);

        let runner = FakeRunner::new()
            .strict()
            .respond(expected_reload, CommandOutput::from_stdout(""))
            .respond(expected_enable, CommandOutput::from_stdout(""));
        let (mgr, _dir) = mgr_with_temp(ScheduleBackend::SystemdTimer, runner);

        mgr.install("nightly", &Schedule::new("0 2 * * *"))
            .expect("install must build the exact systemctl commands");
    }

    #[test]
    fn install_systemd_fails_if_command_mismatched() {
        // Negative control: register the WRONG enable target; install must
        // fail because strict mode rejects the mismatched call.
        let wrong_enable =
            CommandSpec::new("systemctl").args(["enable", "--now", "--", "WRONG.timer"]);
        let runner = FakeRunner::new()
            .strict()
            .respond(
                CommandSpec::new("systemctl").args(["daemon-reload"]),
                CommandOutput::from_stdout(""),
            )
            .respond(wrong_enable, CommandOutput::from_stdout(""));
        let (mgr, _dir) = mgr_with_temp(ScheduleBackend::SystemdTimer, runner);

        let err = mgr.install("nightly", &Schedule::new("0 2 * * *"));
        assert!(err.is_err(), "install should fail on command mismatch");
    }

    #[test]
    fn install_systemd_unit_path_stays_inside_unit_dir() {
        // A traversal-style job name is sanitized by unit_names(), and the
        // install path additionally asserts strip_prefix(unit_dir) before any
        // write. The resulting unit file must live inside the unit dir and
        // never above it.
        let runner = FakeRunner::new()
            .push_response(CommandOutput::from_stdout("")) // daemon-reload
            .push_response(CommandOutput::from_stdout("")); // enable --now
        let (mgr, dir) = mgr_with_temp(ScheduleBackend::SystemdTimer, runner);

        mgr.install("../../../etc/payload", &Schedule::new("0 2 * * *"))
            .expect("install sanitizes the name and writes inside the dir");

        // No file may exist above the unit dir.
        let unit_dir = dir.path().join("systemd");
        let entries = std::fs::read_dir(&unit_dir).unwrap().count();
        assert!(
            entries >= 2,
            "both unit files should be inside the unit dir"
        );
        // Nothing escaped upward.
        assert!(!dir.path().join("payload.service").exists());
        assert!(!dir.path().join("payload.timer").exists());
    }

    #[test]
    fn assert_inside_dir_rejects_escape() {
        let unit_dir = Path::new("/etc/systemd/system");
        assert!(assert_inside_dir(&unit_dir.join("toride-backup-x.timer"), unit_dir,).is_ok());
        // A path that does not share the prefix is rejected.
        assert!(assert_inside_dir(Path::new("/etc/cron.d/x"), unit_dir,).is_err());
    }

    #[test]
    fn remove_systemd_disables_and_deletes_units() {
        // STRICT: prove remove dispatches `disable --now` + `daemon-reload`.
        let expected_disable = CommandSpec::new("systemctl").args([
            "disable",
            "--now",
            "--",
            "toride-backup-old.timer",
        ]);
        let expected_reload = CommandSpec::new("systemctl").args(["daemon-reload"]);

        let runner = FakeRunner::new()
            .strict()
            .respond(expected_disable, CommandOutput::from_stdout(""))
            .respond(expected_reload, CommandOutput::from_stdout(""));
        let (mgr, _dir) = mgr_with_temp(ScheduleBackend::SystemdTimer, runner);

        // Pre-create the unit files so remove has something to delete.
        std::fs::write(
            mgr.unit_dir.join("toride-backup-old.service"),
            "[Service]\n",
        )
        .unwrap();
        std::fs::write(mgr.unit_dir.join("toride-backup-old.timer"), "[Timer]\n").unwrap();

        mgr.remove("old").expect("remove");

        assert!(!mgr.unit_dir.join("toride-backup-old.service").exists());
        assert!(!mgr.unit_dir.join("toride-backup-old.timer").exists());
    }

    #[test]
    fn is_installed_true_when_unit_file_present() {
        let (mgr, _dir) = mgr_with_temp(ScheduleBackend::SystemdTimer, FakeRunner::new());
        std::fs::write(mgr.unit_dir.join("toride-backup-x.timer"), "[Timer]\n").unwrap();
        assert!(mgr.is_installed("x").unwrap());
    }

    #[test]
    fn is_installed_false_when_absent_and_systemd_missing() {
        // On a non-systemd host (CI) with no unit file, is_installed is false.
        let (mgr, _dir) = mgr_with_temp(ScheduleBackend::SystemdTimer, FakeRunner::new());
        if !crate::systemd::detect().available {
            assert!(!mgr.is_installed("nope-not-real").unwrap());
        }
    }

    // -----------------------------------------------------------------------
    // cron install — real crontab(5) format
    // -----------------------------------------------------------------------

    #[test]
    fn install_cron_writes_marked_entry_in_crontab5_format() {
        // crontab(5) format: 5 time fields + user + command.
        // Source: https://man7.org/linux/man-pages/man5/crontab.5.html
        //   "An environment variable ... name = value"
        //   and the five fields minute hour dom month dow.
        let (mgr, _dir) = mgr_with_temp(ScheduleBackend::Cron, FakeRunner::new());

        mgr.install("nightly", &Schedule::new("0 2 * * *")).unwrap();

        let path = mgr.cron_dir.join("toride-backup-nightly");
        assert!(path.exists(), "cron.d drop-in not written");
        let body = std::fs::read_to_string(&path).unwrap();
        // BEGIN/END markers for later removal.
        assert!(body.contains("# toride-backup:BEGIN:nightly"));
        assert!(body.contains("# toride-backup:END:nightly"));
        // The 5-field cron line + root user + CLI invocation.
        assert!(
            body.contains("0 2 * * * root toride-backup backup nightly"),
            "expected crontab(5) line, got: {body}"
        );
        // Passphrase never appears in the cron line.
        assert!(!body.contains("--password"));
        assert!(!body.contains("RESTIC_PASSWORD="));
        assert!(!body.contains("BORG_PASSPHRASE="));
    }

    #[test]
    fn install_cron_validates_schedule() {
        let (mgr, _dir) = mgr_with_temp(ScheduleBackend::Cron, FakeRunner::new());
        let err = mgr
            .install("bad", &Schedule::new("not enough fields"))
            .unwrap_err();
        assert!(matches!(err, Error::ScheduleError(_)));
    }

    #[test]
    fn install_cron_rejects_unsafe_job_name() {
        // A job name carrying shell metacharacters / path separators must be
        // refused before any cron line is written, even if the cron expression
        // itself is valid.
        let (mgr, dir) = mgr_with_temp(ScheduleBackend::Cron, FakeRunner::new());
        for evil in ["nightly; rm -rf /", "../etc/passwd", "a b c", "weird`cmd`"] {
            let err = mgr
                .install(evil, &Schedule::new("0 2 * * *"))
                .expect_err("unsafe name must be rejected");
            assert!(matches!(err, Error::ScheduleError(_)), "name {evil:?}");
        }
        // Nothing was written.
        assert!(
            std::fs::read_dir(dir.path().join("cron.d")).map_or(true, |mut it| it.next().is_none())
        );
    }

    #[test]
    fn install_cron_rejects_shell_metacharacters_in_cron_field() {
        // A cron expression smuggling shell metacharacters in a field must be
        // refused; the lexical per-field allowlist catches injection attempts
        // that would otherwise survive the 5-field-count check.
        let (mgr, _dir) = mgr_with_temp(ScheduleBackend::Cron, FakeRunner::new());
        let err = mgr
            .install("nightly", &Schedule::new("0 2 * * * ; rm -rf /"))
            .unwrap_err();
        assert!(matches!(err, Error::ScheduleError(_)));
        // Lists/ranges/steps are still allowed by the allowlist.
        mgr.install("ok", &Schedule::new("*/15 2 1,15 * 1-5"))
            .expect("valid cron with list/range/step is accepted");
    }

    #[test]
    fn render_cron_entry_emits_safe_name_and_cron() {
        // Positive control: a clean name + valid cron renders the expected
        // crontab(5) line.
        let (mgr, _dir) = mgr_with_temp(ScheduleBackend::Cron, FakeRunner::new());
        let entry = mgr
            .render_cron_entry("nightly", &Schedule::new("0 2 * * *"))
            .expect("valid entry");
        assert!(entry.contains("0 2 * * * root toride-backup backup nightly"));
    }

    #[test]
    fn render_cron_entry_refuses_bad_name_or_cron() {
        let (mgr, _dir) = mgr_with_temp(ScheduleBackend::Cron, FakeRunner::new());
        // Bad name.
        assert!(
            mgr.render_cron_entry("bad name", &Schedule::new("0 2 * * *"))
                .is_err()
        );
        // Bad cron field (shell metachar).
        assert!(
            mgr.render_cron_entry("nightly", &Schedule::new("0 2 * * $(touch x)"))
                .is_err()
        );
    }

    #[test]
    fn remove_cron_deletes_dropin() {
        let (mgr, _dir) = mgr_with_temp(ScheduleBackend::Cron, FakeRunner::new());
        mgr.install("db", &Schedule::new("0 4 * * *")).unwrap();
        assert!(mgr.is_installed("db").unwrap());
        mgr.remove("db").unwrap();
        assert!(!mgr.is_installed("db").unwrap());
    }

    #[test]
    fn sanitize_cron_filename_replaces_dots_and_slashes() {
        // cron.d rejects filenames containing '.'; sanitize defensively.
        assert_eq!(sanitize_cron_filename("my.job/v2"), "my_job_v2");
        assert_eq!(sanitize_cron_filename(""), "job");
    }

    // -----------------------------------------------------------------------
    // The single most important correctness property: NO passphrase on any
    // managed ExecStart / crontab command line.
    // -----------------------------------------------------------------------

    #[test]
    fn cli_exec_start_never_carries_passphrase() {
        // The managed ExecStart / crontab command never carries the repo
        // passphrase. The CLI sources RESTIC_PASSWORD / BORG_PASSPHRASE from
        // its own config at runtime.
        // restic env docs: https://restic.readthedocs.io/en/latest/040_backup.html
        let line = cli_exec_start("toride-backup", "nightly");
        assert_eq!(line, "toride-backup backup nightly");
        assert!(!line.contains("password"));
        assert!(!line.contains("passphrase"));
    }

    #[test]
    fn render_service_unit_keeps_passphrase_off_cli() {
        // Even the DIRECT restic ExecStart (used when a spec is rendered, e.g.
        // for ad-hoc unit generation) must source the password via env, never
        // a CLI flag. The documented restic CLI is
        //   restic -r /srv/restic-repo backup ~/work
        // with RESTIC_PASSWORD supplied via environment.
        // https://restic.readthedocs.io/en/latest/040_backup.html
        use crate::spec::{Backend, BackupSpec, Encryption, RetentionPolicy};
        use std::collections::HashMap;
        use std::path::PathBuf;
        let spec = BackupSpec {
            name: "nightly".into(),
            backend: Backend::Restic,
            repository: PathBuf::from("/srv/restic-repo"),
            sources: vec![PathBuf::from("/home/user/work")],
            schedule: Schedule::new("0 2 * * *"),
            retention: RetentionPolicy::default_policy(),
            encryption: Encryption::RepoKey,
            password_command: Some("cat /etc/restic/password".into()),
            exclude_patterns: vec!["*.tmp".into()],
            tags: vec!["auto".into()],
            extra_env: HashMap::new(),
        };
        let unit = systemd::render_service_unit(&spec);
        assert!(unit.contains("ExecStart=restic -r /srv/restic-repo backup"));
        assert!(
            !unit.contains("--password"),
            "password must not be a CLI flag: {unit}"
        );
        // systemd does not expand $(), so the password is delivered via a
        // root-owned file (RESTIC_PASSWORD_FILE) the install path materializes
        // from the password_command — never the literal $(...) form.
        assert!(
            unit.contains("RESTIC_PASSWORD_FILE=/etc/toride-backup/nightly.pw"),
            "expected RESTIC_PASSWORD_FILE env: {unit}"
        );
    }

    #[test]
    fn systemd_unit_files_use_system_load_path() {
        // The default unit dir is the systemd.unit(5) system load path
        // /etc/systemd/system.
        // https://www.freedesktop.org/software/systemd/man/systemd.unit.html
        let mgr = ScheduleManager::new();
        assert_eq!(
            mgr.unit_dir,
            std::path::PathBuf::from("/etc/systemd/system")
        );
        assert_eq!(mgr.cron_dir, std::path::PathBuf::from("/etc/cron.d"));
    }
}
