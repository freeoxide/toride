//! Backup scheduling via systemd timers or cron: `install_systemd_timer` writes
//! and enables a `.service` + `.timer` pair under `/etc/systemd/system`;
//! `install_cron` writes a marked `/etc/cron.d` entry (crontab(5)).

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use std::fmt::Write as _;

use crate::spec::Schedule;
use crate::systemd;
use crate::{Error, Result};
use toride_runner::{CommandSpec, DuctRunner, Runner};

/// Backend used for scheduling backups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScheduleBackend {
    /// Use systemd timer units (preferred on modern Linux).
    #[default]
    SystemdTimer,
    /// Use cron (crontab entries).
    Cron,
}

const DEFAULT_CRON_D_DIR: &str = "/etc/cron.d";

const DEFAULT_CLI_BIN: &str = "toride-backup";

fn default_unit_dir() -> &'static Path {
    static V: OnceLock<PathBuf> = OnceLock::new();
    V.get_or_init(|| PathBuf::from(systemd::SYSTEMD_UNIT_DIR))
}

/// One-pass schedule + timer snapshot returned by
/// [`ScheduleManager::timer_status`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleTimerStatus {
    /// Whether a schedule is installed (same verdict
    /// [`ScheduleManager::is_installed`] returns).
    pub installed: bool,
    /// Whether the job's systemd timer — or any backup-related timer on the
    /// host — is active.
    pub timer_active: bool,
    /// Empty when systemd is present; otherwise the explanatory note (e.g.
    /// "systemd not detected").
    pub note: String,
}

/// Manages systemd timer or cron schedule installation and removal for backup
/// jobs; every `systemctl` / `crontab` call goes through a [`toride_runner::Runner`]
/// (inject one with [`ScheduleManager::with_runner`]).
pub struct ScheduleManager {
    backend: ScheduleBackend,
    runner: Box<dyn Runner>,
    unit_dir: PathBuf,
    cron_dir: PathBuf,
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

    /// Override the unit-file and cron.d directories (tests pass temp dirs so
    /// they don't need root).
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

    /// Install a schedule for `name`: systemd writes + enables a `.service`/
    /// `.timer` pair; cron writes a marked `/etc/cron.d` entry.
    /// # Errors: [`Error::ScheduleError`] on invalid cron, write, or systemctl failure.
    pub fn install(&self, name: &str, schedule: &Schedule) -> Result<()> {
        schedule.validate()?;

        match self.backend {
            ScheduleBackend::SystemdTimer => self.install_systemd_timer(name, schedule),
            ScheduleBackend::Cron => self.install_cron(name, schedule),
        }
    }

    /// Remove the schedule for `name` (unit pair + enablement, or the cron.d drop-in).
    /// # Errors: [`Error::ScheduleError`] if removal fails.
    pub fn remove(&self, name: &str) -> Result<()> {
        match self.backend {
            ScheduleBackend::SystemdTimer => self.remove_systemd_timer(name),
            ScheduleBackend::Cron => self.remove_cron(name),
        }
    }

    /// Whether a schedule is installed: systemd probes the unit file then live
    /// timers (absent systemd ⇒ `Ok(false)` with a note from
    /// [`schedule_note`](Self::schedule_note)); cron checks the drop-in on disk.
    pub fn is_installed(&self, name: &str) -> Result<bool> {
        match self.backend {
            ScheduleBackend::SystemdTimer => Ok(self.is_systemd_timer_installed(name)),
            ScheduleBackend::Cron => Ok(self.is_cron_installed(name)),
        }
    }

    /// Note explaining the most recent schedule probe: "systemd not detected"
    /// when systemd is absent on this host, empty otherwise.
    pub fn schedule_note(&self) -> String {
        let detected = crate::systemd::detect();
        if detected.available {
            String::new()
        } else {
            detected.note
        }
    }

    /// One-pass schedule + timer status for the dashboard's refresh tick: the
    /// same verdicts as [`is_installed`](Self::is_installed) + `schedule_note`
    /// + `BackupServiceManager::is_timer_active`, sharing the systemd probes.
    pub fn timer_status(&self, name: &str) -> ScheduleTimerStatus {
        let detected = systemd::detect();
        let note = if detected.available {
            String::new()
        } else {
            detected.note
        };

        if !detected.available {
            return ScheduleTimerStatus {
                installed: match self.backend {
                    ScheduleBackend::SystemdTimer => {
                        let (_, timer_unit) = systemd::unit_names(name);
                        self.unit_dir.join(&timer_unit).exists()
                    }
                    ScheduleBackend::Cron => self.is_cron_installed(name),
                },
                timer_active: false,
                note,
            };
        }

        match self.backend {
            ScheduleBackend::Cron => {
                let (_, timer_unit) = systemd::unit_names(name);
                let timer_active =
                    systemd::probe_timer(&timer_unit).active || systemd::any_backup_timer_active();
                ScheduleTimerStatus {
                    installed: self.is_cron_installed(name),
                    timer_active,
                    note,
                }
            }
            ScheduleBackend::SystemdTimer => {
                let (_, timer_unit) = systemd::unit_names(name);
                let file_installed = self.unit_dir.join(&timer_unit).exists();
                let probe = systemd::probe_timer(&timer_unit);
                let mut installed = file_installed || probe.installed;
                let mut timer_active = probe.active;

                if !installed || !timer_active {
                    let probes = systemd::enumerate_backup_timers();
                    if !installed {
                        installed = !probes.is_empty();
                    }
                    if !timer_active {
                        timer_active = probes.iter().any(|p| p.active);
                    }
                }

                ScheduleTimerStatus {
                    installed,
                    timer_active,
                    note,
                }
            }
        }
    }

    fn run(&self, spec: &CommandSpec) -> Result<()> {
        self.runner
            .run_checked(spec)
            .map(|_| ())
            .map_err(map_runner_error)
    }

    fn install_systemd_timer(&self, name: &str, schedule: &Schedule) -> Result<()> {
        let (service_unit, timer_unit) = systemd::unit_names(name);

        let exec_start = cli_exec_start(&self.cli_bin, name);
        let service_body = systemd::render_cli_service_unit(name, &exec_start);
        let timer_body = systemd::render_timer_unit(name, schedule)?;

        let service_path = self.unit_dir.join(&service_unit);
        let timer_path = self.unit_dir.join(&timer_unit);
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

        self.run(&systemd::daemon_reload_spec())?;
        self.run(&systemd::enable_now_spec(&timer_unit))?;

        tracing::info!(unit = %timer_unit, "enabled + started systemd timer");
        Ok(())
    }

    fn remove_systemd_timer(&self, name: &str) -> Result<()> {
        let (service_unit, timer_unit) = systemd::unit_names(name);

        let _ = self.runner.run(&systemd::disable_now_spec(&timer_unit));

        for unit in [service_unit.as_str(), timer_unit.as_str()] {
            let path = self.unit_dir.join(unit);
            if path.exists() {
                std::fs::remove_file(&path).map_err(|e| {
                    Error::ScheduleError(format!("could not remove {}: {e}", path.display()))
                })?;
            }
        }

        self.run(&systemd::daemon_reload_spec())?;
        tracing::info!(name = %name, "removed systemd timer");
        Ok(())
    }

    fn is_systemd_timer_installed(&self, name: &str) -> bool {
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

    fn install_cron(&self, name: &str, schedule: &Schedule) -> Result<()> {
        schedule.validate()?;
        let entry = self.render_cron_entry(name, schedule)?;

        std::fs::create_dir_all(&self.cron_dir).map_err(|e| {
            Error::ScheduleError(format!(
                "could not create cron dir {}: {e}",
                self.cron_dir.display()
            ))
        })?;
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

    fn render_cron_entry(&self, name: &str, schedule: &Schedule) -> Result<String> {
        if !crate::spec::is_valid_name(name) {
            return Err(Error::ScheduleError(format!(
                "cron job name {name:?} must match ^[A-Za-z0-9._-]+$ \
                 (no spaces, shell, or path separators)"
            )));
        }
        schedule.validate()?;

        let mut s = String::new();
        let _ = writeln!(s, "{}{name}", systemd::CRON_MARKER_BEGIN);
        s.push_str("SHELL=/bin/sh\n");
        s.push_str("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n");
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

fn map_runner_error(e: toride_runner::Error) -> Error {
    match e {
        toride_runner::Error::BinaryNotFound(name) => Error::BinaryNotFound(name),
        other => Error::CommandFailed(other.to_string()),
    }
}

/// The `ExecStart=` line the generated units / crontab lines run: the managed
/// CLI invoking the job by name (the passphrase never appears on it).
pub fn cli_exec_start(cli_bin: &str, name: &str) -> String {
    format!("{cli_bin} backup {name}")
}

// cron silently ignores /etc/cron.d files whose names contain a `.` (crontab(5)):
// https://man7.org/linux/man-pages/man5/crontab.5.html
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::Schedule;
    use toride_runner::{CommandOutput, FakeRunner};

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

    #[test]
    fn install_systemd_writes_units_with_correct_execstart() {
        let runner = FakeRunner::new()
            .push_response(CommandOutput::from_stdout(""))
            .push_response(CommandOutput::from_stdout(""));
        let (mgr, _dir) = mgr_with_temp(ScheduleBackend::SystemdTimer, runner);

        mgr.install("nightly", &Schedule::new("0 2 * * *"))
            .expect("install");

        let svc = mgr.unit_dir.join("toride-backup-nightly.service");
        let tmr = mgr.unit_dir.join("toride-backup-nightly.timer");
        assert!(svc.exists(), "service unit not written");
        assert!(tmr.exists(), "timer unit not written");

        let svc_body = std::fs::read_to_string(&svc).unwrap();
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
        assert!(tmr_body.contains("OnCalendar=*-*-* 02:00:00"));
        assert!(tmr_body.contains("Persistent=true"));
        assert!(tmr_body.contains("WantedBy=timers.target"));
    }

    #[test]
    fn install_systemd_builds_exact_daemon_reload_and_enable_now() {
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
        let runner = FakeRunner::new()
            .push_response(CommandOutput::from_stdout(""))
            .push_response(CommandOutput::from_stdout(""));
        let (mgr, dir) = mgr_with_temp(ScheduleBackend::SystemdTimer, runner);

        mgr.install("../../../etc/payload", &Schedule::new("0 2 * * *"))
            .expect("install sanitizes the name and writes inside the dir");

        let unit_dir = dir.path().join("systemd");
        let entries = std::fs::read_dir(&unit_dir).unwrap().count();
        assert!(
            entries >= 2,
            "both unit files should be inside the unit dir"
        );
        assert!(!dir.path().join("payload.service").exists());
        assert!(!dir.path().join("payload.timer").exists());
    }

    #[test]
    fn assert_inside_dir_rejects_escape() {
        let unit_dir = Path::new("/etc/systemd/system");
        assert!(assert_inside_dir(&unit_dir.join("toride-backup-x.timer"), unit_dir,).is_ok());
        assert!(assert_inside_dir(Path::new("/etc/cron.d/x"), unit_dir,).is_err());
    }

    #[test]
    fn remove_systemd_disables_and_deletes_units() {
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
        let (mgr, _dir) = mgr_with_temp(ScheduleBackend::SystemdTimer, FakeRunner::new());
        if !crate::systemd::detect().available {
            assert!(!mgr.is_installed("nope-not-real").unwrap());
        }
    }

    #[test]
    fn install_cron_writes_marked_entry_in_crontab5_format() {
        let (mgr, _dir) = mgr_with_temp(ScheduleBackend::Cron, FakeRunner::new());

        mgr.install("nightly", &Schedule::new("0 2 * * *")).unwrap();

        let path = mgr.cron_dir.join("toride-backup-nightly");
        assert!(path.exists(), "cron.d drop-in not written");
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("# toride-backup:BEGIN:nightly"));
        assert!(body.contains("# toride-backup:END:nightly"));
        assert!(
            body.contains("0 2 * * * root toride-backup backup nightly"),
            "expected crontab(5) line, got: {body}"
        );
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
        let (mgr, dir) = mgr_with_temp(ScheduleBackend::Cron, FakeRunner::new());
        for evil in ["nightly; rm -rf /", "../etc/passwd", "a b c", "weird`cmd`"] {
            let err = mgr
                .install(evil, &Schedule::new("0 2 * * *"))
                .expect_err("unsafe name must be rejected");
            assert!(matches!(err, Error::ScheduleError(_)), "name {evil:?}");
        }
        assert!(
            std::fs::read_dir(dir.path().join("cron.d")).map_or(true, |mut it| it.next().is_none())
        );
    }

    #[test]
    fn install_cron_rejects_shell_metacharacters_in_cron_field() {
        let (mgr, _dir) = mgr_with_temp(ScheduleBackend::Cron, FakeRunner::new());
        let err = mgr
            .install("nightly", &Schedule::new("0 2 * * * ; rm -rf /"))
            .unwrap_err();
        assert!(matches!(err, Error::ScheduleError(_)));
        mgr.install("ok", &Schedule::new("*/15 2 1,15 * 1-5"))
            .expect("valid cron with list/range/step is accepted");
    }

    #[test]
    fn render_cron_entry_emits_safe_name_and_cron() {
        let (mgr, _dir) = mgr_with_temp(ScheduleBackend::Cron, FakeRunner::new());
        let entry = mgr
            .render_cron_entry("nightly", &Schedule::new("0 2 * * *"))
            .expect("valid entry");
        assert!(entry.contains("0 2 * * * root toride-backup backup nightly"));
    }

    #[test]
    fn render_cron_entry_refuses_bad_name_or_cron() {
        let (mgr, _dir) = mgr_with_temp(ScheduleBackend::Cron, FakeRunner::new());
        assert!(
            mgr.render_cron_entry("bad name", &Schedule::new("0 2 * * *"))
                .is_err()
        );
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
        assert_eq!(sanitize_cron_filename("my.job/v2"), "my_job_v2");
        assert_eq!(sanitize_cron_filename(""), "job");
    }

    #[test]
    fn cli_exec_start_never_carries_passphrase() {
        let line = cli_exec_start("toride-backup", "nightly");
        assert_eq!(line, "toride-backup backup nightly");
        assert!(!line.contains("password"));
        assert!(!line.contains("passphrase"));
    }

    #[test]
    fn render_service_unit_keeps_passphrase_off_cli() {
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
        assert!(
            unit.contains("RESTIC_PASSWORD_FILE=/etc/toride-backup/nightly.pw"),
            "expected RESTIC_PASSWORD_FILE env: {unit}"
        );
    }

    #[test]
    fn systemd_unit_files_use_system_load_path() {
        let mgr = ScheduleManager::new();
        assert_eq!(
            mgr.unit_dir,
            std::path::PathBuf::from("/etc/systemd/system")
        );
        assert_eq!(mgr.cron_dir, std::path::PathBuf::from("/etc/cron.d"));
    }

    #[test]
    fn timer_status_unit_file_present_means_installed() {
        let (mgr, _dir) = mgr_with_temp(ScheduleBackend::SystemdTimer, FakeRunner::new());
        let (_, timer_unit) = systemd::unit_names("toride-backup");
        std::fs::write(mgr.unit_dir.join(&timer_unit), b"[Timer]\n").unwrap();

        let status = mgr.timer_status("toride-backup");
        assert!(
            status.installed,
            "an on-disk managed timer file must read as installed regardless of the init system"
        );
    }

    #[test]
    fn timer_status_matches_separate_probes_and_note_tracks_detection() {
        let (mgr, _dir) = mgr_with_temp(ScheduleBackend::SystemdTimer, FakeRunner::new());
        let status = mgr.timer_status("toride-backup");
        let detected = systemd::detect();

        assert_eq!(status.installed, mgr.is_installed("toride-backup").unwrap());
        assert_eq!(status.note, mgr.schedule_note());

        if detected.available {
            assert!(status.note.is_empty(), "systemd host carries no note");
        } else {
            assert_eq!(status.note, detected.note);
            assert!(
                !status.timer_active,
                "a systemd-absent host must report timer_active=false"
            );
            assert!(
                !status.installed,
                "empty temp unit dir + no systemd -> not installed"
            );
        }
    }
}
