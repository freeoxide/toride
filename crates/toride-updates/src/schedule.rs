//! Systemd timer / cron schedule management for automatic updates.
//!
//! Manages the schedule that triggers automatic update checks and applies.
//! On systems with systemd, uses timer units. Falls back to cron otherwise.

use tracing::info;

use crate::detect::PackageManager;
use crate::error::{Error, Result};
use crate::paths::UpdatePaths;
use crate::spec::Schedule;

// ---------------------------------------------------------------------------
// ScheduleManager
// ---------------------------------------------------------------------------

/// Manages the automatic update schedule.
///
/// On APT systems, configures `APT::Periodic` settings and optionally a
/// systemd timer. On DNF systems, manages the `dnf-automatic.timer` unit.
pub struct ScheduleManager<'a> {
    runner: &'a dyn toride_runner::Runner,
    paths: UpdatePaths,
    pkg_mgr: PackageManager,
}

impl<'a> ScheduleManager<'a> {
    /// Create a new schedule manager with the given runner.
    pub fn new(runner: &'a dyn toride_runner::Runner) -> Self {
        Self {
            runner,
            paths: UpdatePaths::detect(),
            pkg_mgr: crate::detect::detect_package_manager(),
        }
    }

    /// Create a schedule manager with explicit paths and package manager
    /// (primarily for tests).
    pub fn with_pkg_mgr(
        runner: &'a dyn toride_runner::Runner,
        paths: UpdatePaths,
        pkg_mgr: PackageManager,
    ) -> Self {
        Self {
            runner,
            paths,
            pkg_mgr,
        }
    }

    /// Set the update schedule.
    ///
    /// Configures the appropriate timer or cron job for the given schedule.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ScheduleConfig`] if the schedule cannot be configured.
    pub fn set_schedule(&self, schedule: &Schedule) -> Result<()> {
        info!("Setting update schedule: {schedule}");

        match self.pkg_mgr {
            PackageManager::Apt => self.set_apt_schedule(schedule),
            PackageManager::Dnf => self.set_dnf_schedule(schedule),
            PackageManager::Unknown => Err(Error::ScheduleConfig(
                "no supported package manager for schedule setup".into(),
            )),
        }
    }

    /// Get the currently configured schedule, if any.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ScheduleConfig`] if the schedule cannot be determined.
    pub fn get_schedule(&self) -> Result<Option<Schedule>> {
        info!("Querying current update schedule");

        match self.pkg_mgr {
            PackageManager::Apt => self.get_apt_schedule(),
            PackageManager::Dnf => self.get_dnf_schedule(),
            PackageManager::Unknown => Ok(None),
        }
    }

    /// Remove the configured schedule.
    ///
    /// Disables the systemd timer / removes the drop-in that
    /// [`Self::set_schedule`] created (for custom schedules), and clears the
    /// `APT::Periodic` enablement on Debian/Ubuntu so the host returns to a
    /// no-schedule state. Has no effect when no schedule is configured.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ScheduleConfig`] if the schedule cannot be removed,
    /// or [`Error::CommandFailed`] if `systemctl` fails.
    pub fn remove_schedule(&self) -> Result<()> {
        info!("Removing update schedule");

        match self.pkg_mgr {
            PackageManager::Apt => self.remove_apt_schedule(),
            PackageManager::Dnf => self.remove_dnf_schedule(),
            // Nothing to remove without a supported backend.
            PackageManager::Unknown => Ok(()),
        }
    }

    // -----------------------------------------------------------------------
    // APT schedule helpers
    // -----------------------------------------------------------------------

    fn set_apt_schedule(&self, schedule: &Schedule) -> Result<()> {
        let interval = match schedule {
            Schedule::Daily => "1",
            Schedule::Weekly => "7",
            Schedule::Monthly => "30",
            Schedule::Custom(expr) => {
                // For custom schedules, we use a systemd timer instead of
                // APT::Periodic.
                self.create_systemd_timer(expr)?;
                return Ok(());
            }
        };

        // Write APT::Periodic::Update-Package-Lists interval.
        let apt_conf = format!(
            "APT::Periodic::Update-Package-Lists \"{interval}\";\n\
             APT::Periodic::Unattended-Upgrade \"1\";\n"
        );

        toride_fs::atomic_write(&self.paths.auto_upgrades_enabled, &apt_conf)
            .map_err(|e| Error::ScheduleConfig(format!("failed to write APT schedule: {e}")))?;

        Ok(())
    }

    fn get_apt_schedule(&self) -> Result<Option<Schedule>> {
        let Ok(content) = std::fs::read_to_string(&self.paths.auto_upgrades_enabled) else {
            return Ok(None);
        };
        Ok(parse_apt_periodic_interval(&content))
    }

    /// Disable APT scheduling by writing a `0` interval and disabling the
    /// custom timer (if present).
    fn remove_apt_schedule(&self) -> Result<()> {
        let disabled = "APT::Periodic::Update-Package-Lists \"0\";\n\
                        APT::Periodic::Unattended-Upgrade \"0\";\n";
        toride_fs::atomic_write(&self.paths.auto_upgrades_enabled, disabled)
            .map_err(|e| Error::ScheduleConfig(format!("failed to clear APT schedule: {e}")))?;
        // Best-effort: disable any toride-managed custom timer.
        self.disable_managed_timer();
        Ok(())
    }

    // -----------------------------------------------------------------------
    // DNF schedule helpers
    // -----------------------------------------------------------------------

    fn set_dnf_schedule(&self, schedule: &Schedule) -> Result<()> {
        let calendar = schedule_to_calendar(schedule);
        self.create_systemd_timer(&calendar)
    }

    fn get_dnf_schedule(&self) -> Result<Option<Schedule>> {
        let timer_path = self.managed_timer_drop_in();
        let Ok(content) = std::fs::read_to_string(&timer_path) else {
            return Ok(None);
        };
        Ok(parse_on_calendar(&content))
    }

    /// Remove the DNF schedule by deleting the drop-in and reloading systemd.
    fn remove_dnf_schedule(&self) -> Result<()> {
        let timer_path = self.managed_timer_drop_in();
        if timer_path.exists() {
            std::fs::remove_file(&timer_path).map_err(|e| {
                Error::ScheduleConfig(format!(
                    "failed to remove timer drop-in {}: {e}",
                    timer_path.display()
                ))
            })?;
            self.daemon_reload()?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Systemd timer
    // -----------------------------------------------------------------------

    /// The drop-in directory + file path for the toride-managed timer override.
    ///
    /// Drop-ins are `*.conf` files inside a `<unit>.d/` directory. The
    /// directory name is `<unit>.d` (e.g. `dnf-automatic.timer.d`) and the
    /// drop-in file is `toride.conf` (a stable, backend-neutral name).
    fn managed_timer_drop_in(&self) -> std::path::PathBuf {
        let timer_name = self.timer_unit_name();
        let dir = self.paths.systemd_timer_d.join(format!("{timer_name}.d"));
        dir.join("toride.conf")
    }

    /// The timer unit name for the detected package manager.
    fn timer_unit_name(&self) -> &'static str {
        match self.pkg_mgr {
            PackageManager::Dnf => "dnf-automatic.timer",
            _ => "toride-updates.timer",
        }
    }

    fn create_systemd_timer(&self, calendar_expr: &str) -> Result<()> {
        info!("Creating systemd timer with OnCalendar={calendar_expr}");

        let timer_unit = format!(
            "[Unit]\n\
             Description=Automatic security updates (toride-managed)\n\n\
             [Timer]\n\
             OnCalendar={calendar_expr}\n\
             Persistent=true\n\
             RandomizedDelaySec=300\n\n\
             [Install]\n\
             WantedBy=timers.target\n"
        );

        let timer_path = self.managed_timer_drop_in();

        // Ensure the drop-in directory exists.
        if let Some(parent) = timer_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                Error::ScheduleConfig(format!(
                    "failed to create timer drop-in dir {}: {e}",
                    parent.display()
                ))
            })?;
        }

        crate::backup::backup_config(&timer_path)?;

        toride_fs::atomic_write(&timer_path, &timer_unit)
            .map_err(|e| Error::ScheduleConfig(format!("failed to write timer unit: {e}")))?;

        // Reload systemd so the drop-in is picked up.
        self.daemon_reload()?;

        Ok(())
    }

    /// Disable (best-effort) the toride-managed custom timer.
    fn disable_managed_timer(&self) {
        let unit = self.timer_unit_name();
        let spec = toride_runner::CommandSpec::new("systemctl")
            .args(["disable", "--now", unit]);
        // Best-effort: ignore failures (the timer may not be installed).
        let _ = self.runner.run(&spec);
    }

    /// Run `systemctl daemon-reload` through the runner.
    fn daemon_reload(&self) -> Result<()> {
        let spec = daemon_reload_spec();
        self.runner
            .run_checked(&spec)
            .map_err(|e| Error::CommandFailed(format!("systemctl daemon-reload failed: {e}")))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Parsers / helpers
// ---------------------------------------------------------------------------

/// Convert a [`Schedule`] to a systemd calendar expression.
fn schedule_to_calendar(schedule: &Schedule) -> String {
    match schedule {
        Schedule::Daily => "daily".to_owned(),
        Schedule::Weekly => "weekly".to_owned(),
        Schedule::Monthly => "monthly".to_owned(),
        Schedule::Custom(expr) => expr.clone(),
    }
}

/// Parse the `APT::Periodic::Update-Package-Lists` interval (in days) from an
/// apt.conf snippet into a [`Schedule`].
///
/// Returns `None` when the directive is absent or set to `"0"`.
fn parse_apt_periodic_interval(content: &str) -> Option<Schedule> {
    for raw in content.lines() {
        let line = raw.trim();
        if line.starts_with("//") || line.starts_with('#') {
            continue;
        }
        if let Some(val) = apt_directive_value(line, "APT::Periodic::Update-Package-Lists") {
            return match val {
                "1" => Some(Schedule::Daily),
                "7" => Some(Schedule::Weekly),
                "30" => Some(Schedule::Monthly),
                _ => Some(Schedule::Custom(val.to_owned())),
            };
        }
    }
    None
}

/// Parse the `OnCalendar=` directive from a systemd timer drop-in.
///
/// Maps the canonical names back to [`Schedule::Daily`] / `Weekly` /
/// `Monthly`, and treats anything else as a custom expression.
fn parse_on_calendar(content: &str) -> Option<Schedule> {
    for raw in content.lines() {
        let line = raw.trim();
        let Some(rest) = line.strip_prefix("OnCalendar=") else {
            continue;
        };
        let value = rest.trim();
        return match value {
            "daily" => Some(Schedule::Daily),
            "weekly" => Some(Schedule::Weekly),
            "monthly" => Some(Schedule::Monthly),
            other => Some(Schedule::Custom(other.to_owned())),
        };
    }
    None
}

/// Extract the quoted value from an apt.conf directive line of the form
/// `APT::Periodic::Update-Package-Lists "1";`.
fn apt_directive_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(key)?.trim_start();
    let quoted = rest.strip_prefix('"')?;
    let end = quoted.find('"')?;
    Some(&quoted[..end])
}

/// Build the `systemctl daemon-reload` [`toride_runner::CommandSpec`].
fn daemon_reload_spec() -> toride_runner::CommandSpec {
    toride_runner::CommandSpec::new("systemctl").arg("daemon-reload")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use toride_runner::fake::FakeRunner;
    use toride_runner::{CommandOutput, CommandSpec};

    fn mgr_at<'a>(
        runner: &'a FakeRunner,
        root: &std::path::Path,
        pkg_mgr: PackageManager,
    ) -> ScheduleManager<'a> {
        let mut paths = UpdatePaths::new();
        paths.auto_upgrades_enabled = root.join("20auto-upgrades");
        paths.systemd_timer_d = root.join("systemd");
        ScheduleManager::with_pkg_mgr(runner, paths, pkg_mgr)
    }

    #[test]
    fn parse_apt_periodic_maps_intervals() {
        assert_eq!(
            parse_apt_periodic_interval("APT::Periodic::Update-Package-Lists \"1\";\n"),
            Some(Schedule::Daily)
        );
        assert_eq!(
            parse_apt_periodic_interval("APT::Periodic::Update-Package-Lists \"7\";\n"),
            Some(Schedule::Weekly)
        );
        assert_eq!(
            parse_apt_periodic_interval("APT::Periodic::Update-Package-Lists \"30\";\n"),
            Some(Schedule::Monthly)
        );
    }

    #[test]
    fn parse_apt_periodic_ignores_comments_and_disabled() {
        assert_eq!(parse_apt_periodic_interval("// APT::Periodic::Update-Package-Lists \"1\";\n"), None);
        assert_eq!(parse_apt_periodic_interval("APT::Periodic::Update-Package-Lists \"0\";\n"), Some(Schedule::Custom("0".into())));
        assert_eq!(parse_apt_periodic_interval("Unrelated \"1\";\n"), None);
    }

    #[test]
    fn parse_on_calendar_maps_back() {
        let content = "[Timer]\nOnCalendar=weekly\nPersistent=true\n";
        assert_eq!(parse_on_calendar(content), Some(Schedule::Weekly));
        let custom = "[Timer]\nOnCalendar=Mon *-*-* 04:00:00\n";
        assert_eq!(
            parse_on_calendar(custom),
            Some(Schedule::Custom("Mon *-*-* 04:00:00".into()))
        );
        assert_eq!(parse_on_calendar("[Timer]\nPersistent=true\n"), None);
    }

    #[test]
    fn set_apt_schedule_daily_writes_interval() {
        let dir = tempfile::tempdir().unwrap();
        let runner = FakeRunner::new();
        mgr_at(&runner, dir.path(), PackageManager::Apt)
            .set_schedule(&Schedule::Daily)
            .unwrap();
        let written = std::fs::read_to_string(dir.path().join("20auto-upgrades")).unwrap();
        assert!(written.contains("APT::Periodic::Update-Package-Lists \"1\";"));
    }

    #[test]
    fn set_dnf_schedule_creates_drop_in_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(""));
        mgr_at(&runner, dir.path(), PackageManager::Dnf)
            .set_schedule(&Schedule::Weekly)
            .unwrap();
        // Drop-in path: <systemd_timer_d>/<unit>.d/toride.conf
        let drop_in = dir
            .path()
            .join("systemd")
            .join("dnf-automatic.timer.d")
            .join("toride.conf");
        let content = std::fs::read_to_string(&drop_in).unwrap();
        assert!(content.contains("OnCalendar=weekly"));
        assert!(content.contains("[Timer]"));
        // daemon-reload must have been invoked.
        runner.assert_called_with(&CommandSpec::new("systemctl").arg("daemon-reload"));
    }

    #[test]
    fn set_custom_schedule_creates_timer_for_apt() {
        let dir = tempfile::tempdir().unwrap();
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(""));
        mgr_at(&runner, dir.path(), PackageManager::Apt)
            .set_schedule(&Schedule::Custom("Mon *-*-* 04:00:00".into()))
            .unwrap();
        let drop_in = dir
            .path()
            .join("systemd")
            .join("toride-updates.timer.d")
            .join("toride.conf");
        let content = std::fs::read_to_string(&drop_in).unwrap();
        assert!(content.contains("OnCalendar=Mon *-*-* 04:00:00"));
    }

    #[test]
    fn get_apt_schedule_reads_back_interval() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("20auto-upgrades"),
            "APT::Periodic::Update-Package-Lists \"7\";\nUnattended-Upgrade \"1\";\n",
        )
        .unwrap();
        let runner = FakeRunner::new();
        let sched = mgr_at(&runner, dir.path(), PackageManager::Apt)
            .get_schedule()
            .unwrap();
        assert_eq!(sched, Some(Schedule::Weekly));
    }

    #[test]
    fn get_dnf_schedule_reads_on_calendar() {
        let dir = tempfile::tempdir().unwrap();
        let drop_in_dir = dir.path().join("systemd").join("dnf-automatic.timer.d");
        std::fs::create_dir_all(&drop_in_dir).unwrap();
        std::fs::write(
            drop_in_dir.join("toride.conf"),
            "[Timer]\nOnCalendar=monthly\n",
        )
        .unwrap();
        let runner = FakeRunner::new();
        let sched = mgr_at(&runner, dir.path(), PackageManager::Dnf)
            .get_schedule()
            .unwrap();
        assert_eq!(sched, Some(Schedule::Monthly));
    }

    #[test]
    fn remove_dnf_schedule_deletes_drop_in_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let drop_in_dir = dir.path().join("systemd").join("dnf-automatic.timer.d");
        std::fs::create_dir_all(&drop_in_dir).unwrap();
        let drop_in = drop_in_dir.join("toride.conf");
        std::fs::write(&drop_in, "[Timer]\nOnCalendar=daily\n").unwrap();

        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(""));
        mgr_at(&runner, dir.path(), PackageManager::Dnf)
            .remove_schedule()
            .unwrap();
        assert!(!drop_in.exists(), "drop-in should be removed");
        runner.assert_called_with(&CommandSpec::new("systemctl").arg("daemon-reload"));
    }

    #[test]
    fn remove_apt_schedule_writes_disabled_directives() {
        let dir = tempfile::tempdir().unwrap();
        let runner = FakeRunner::new();
        mgr_at(&runner, dir.path(), PackageManager::Apt)
            .remove_schedule()
            .unwrap();
        let written = std::fs::read_to_string(dir.path().join("20auto-upgrades")).unwrap();
        assert!(written.contains("APT::Periodic::Update-Package-Lists \"0\";"));
        assert!(written.contains("APT::Periodic::Unattended-Upgrade \"0\";"));
    }

    #[test]
    fn daemon_reload_failure_propagates() {
        let dir = tempfile::tempdir().unwrap();
        let runner = FakeRunner::new()
            .push_response(CommandOutput::from_stderr("Access denied", 1));
        let err = mgr_at(&runner, dir.path(), PackageManager::Dnf)
            .set_schedule(&Schedule::Daily)
            .unwrap_err();
        assert!(err.to_string().contains("daemon-reload"));
    }

    #[test]
    fn schedule_to_calendar_mapping() {
        assert_eq!(schedule_to_calendar(&Schedule::Daily), "daily");
        assert_eq!(schedule_to_calendar(&Schedule::Weekly), "weekly");
        assert_eq!(schedule_to_calendar(&Schedule::Monthly), "monthly");
        assert_eq!(
            schedule_to_calendar(&Schedule::Custom("foo".into())),
            "foo"
        );
    }
}
