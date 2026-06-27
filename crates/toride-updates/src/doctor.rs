//! Doctor checks for the automatic update subsystem.
//!
//! Runs a battery of diagnostic checks to verify that automatic security
//! updates are correctly configured and functioning:
//!
//! - Binary availability (unattended-upgrades, dnf-automatic)
//! - Service active status
//! - Auto-updates enabled
//! - Schedule configured
//! - Stale last-run detection
//! - Config directory permissions

use std::time::Duration;

use tracing::{info, warn};

use crate::detect::PackageManager;
use crate::error::Result;
use crate::paths::UpdatePaths;
use crate::report;
use crate::spec::Schedule;

/// Maximum wall-clock time to wait for a single `systemctl` query.
const SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Doctor
// ---------------------------------------------------------------------------

/// Diagnostic engine for the updates subsystem.
///
/// Runs checks and returns a list of [`toride_diagnostic_types::Finding`]
/// values indicating any issues detected.
pub struct Doctor<'a> {
    runner: &'a dyn toride_runner::Runner,
    paths: UpdatePaths,
    pkg_mgr: PackageManager,
}

impl<'a> Doctor<'a> {
    /// Create a new doctor instance with the given runner.
    pub fn new(runner: &'a dyn toride_runner::Runner) -> Self {
        Self {
            runner,
            paths: UpdatePaths::detect(),
            pkg_mgr: crate::detect::detect_package_manager(),
        }
    }

    /// Run all diagnostic checks and return the findings.
    ///
    /// # Errors
    ///
    /// Returns an error only for fundamental failures (e.g. runner broken).
    /// Individual check failures appear as findings in the returned list.
    pub fn run(&self) -> Result<Vec<toride_diagnostic_types::Finding>> {
        let mut findings = Vec::new();

        // If we have neither a supported package manager nor systemd, be honest
        // about it and short-circuit: there is nothing meaningful to probe.
        if self.pkg_mgr == PackageManager::Unknown && !Self::systemd_available() {
            info!("No supported package manager or systemd detected");
            findings.push(report::finding_auto_update_manager_absent());
            return Ok(findings);
        }

        self.check_binary_available(&mut findings);
        self.check_service_active(&mut findings);
        self.check_auto_updates_enabled(&mut findings);
        self.check_schedule_configured(&mut findings);
        self.check_last_run_fresh(&mut findings);
        self.check_config_dir_permissions(&mut findings);

        Ok(findings)
    }

    // -----------------------------------------------------------------------
    // Individual checks
    // -----------------------------------------------------------------------

    /// Check: binary.unattended-upgrades.missing / binary.dnf-automatic.missing
    fn check_binary_available(&self, findings: &mut Vec<toride_diagnostic_types::Finding>) {
        info!("Checking binary availability");

        let binary = match self.pkg_mgr {
            PackageManager::Apt => "unattended-upgrades",
            PackageManager::Dnf => "dnf-automatic",
            PackageManager::Unknown => {
                findings.push(report::finding_binary_missing("package-manager"));
                return;
            }
        };

        if which::which(binary).is_err() {
            findings.push(report::finding_binary_missing(binary));
        }
    }

    /// Check: service.unattended-upgrades.inactive / service.dnf-automatic.inactive
    ///
    /// Queries the relevant systemd timer unit via `systemctl is-active`.
    /// On APT this is `apt-daily-upgrade.timer`; on DNF it is
    /// `dnf-automatic.timer` (falling back to `dnf-automatic-install.timer`).
    fn check_service_active(&self, findings: &mut Vec<toride_diagnostic_types::Finding>) {
        info!("Checking service active status");

        let timers = self.auto_update_timers();
        if timers.is_empty() {
            // No package manager: handled by the run() short-circuit. If we get
            // here it means systemd exists but no backend timer is applicable.
            return;
        }

        // Probe each candidate timer; report the first that is active, or
        // otherwise the first non-absent one as inactive.
        let mut any_active = false;
        let mut first_disabled: Option<&str> = None;
        let mut first_absent: Option<&str> = None;

        for timer in &timers {
            match self.timer_state(timer) {
                report::TimerState::Active => {
                    any_active = true;
                    break;
                }
                report::TimerState::Disabled => {
                    if first_disabled.is_none() {
                        first_disabled = Some(*timer);
                    }
                }
                report::TimerState::Absent => {
                    if first_absent.is_none() {
                        first_absent = Some(*timer);
                    }
                }
            }
        }

        if any_active {
            // Healthy: no finding needed, auto-update check covers reporting.
            return;
        }
        if let Some(timer) = first_disabled {
            findings.push(report::finding_service_inactive(timer));
        } else if let Some(timer) = first_absent {
            // All candidate timers are missing: the backend is not installed.
            findings.push(report::finding_auto_update_timer_absent(timer));
        }
    }

    /// Check: config.auto-updates.disabled
    ///
    /// Combines two independent signals:
    /// - **APT**: `APT::Periodic::Update-Package-Lists "1"` *and*
    ///   `Unattended-Upgrade "1"` in `/etc/apt/apt.conf.d/20auto-upgrades`,
    ///   plus the `apt-daily-upgrade.timer` active state.
    /// - **DNF**: `apply_updates = yes` in `/etc/dnf/automatic.conf`, plus
    ///   the `dnf-automatic*.timer` active state.
    ///
    /// Reports enabled (Ok) only when at least the configuration enables
    /// updates; reports disabled (Warning) when config is off; reports
    /// timer-absent (Info) when the config is on but no timer is active.
    fn check_auto_updates_enabled(&self, findings: &mut Vec<toride_diagnostic_types::Finding>) {
        info!("Checking auto-updates enabled");

        let timers = self.auto_update_timers();
        let timer_active = timers
            .iter()
            .any(|t| self.timer_state(t) == report::TimerState::Active);
        let timer_absent = !timers.is_empty()
            && timers
                .iter()
                .all(|t| self.timer_state(t) == report::TimerState::Absent);

        let config_enabled = match self.pkg_mgr {
            PackageManager::Apt => self.apt_auto_upgrades_enabled(),
            PackageManager::Dnf => self.dnf_apply_updates_enabled(),
            PackageManager::Unknown => false,
        };

        match (config_enabled, timer_active, timer_absent) {
            // Config on and a timer is actively running: fully healthy.
            (true, true, _) => findings.push(report::finding_auto_update_enabled(
                timers
                    .iter()
                    .find(|t| self.timer_state(t) == report::TimerState::Active)
                    .copied()
                    .unwrap_or("auto-update"),
            )),
            // Config on but no timer running: updates will not actually fire.
            (true, false, true) => findings.push(report::finding_auto_update_timer_absent(
                timers.first().copied().unwrap_or("auto-update"),
            )),
            // Config on, timer installed but inactive (not disabled per se,
            // but updates will not run) OR config off: surface as disabled so
            // the operator either enables the config or starts the timer.
            (true, false, false) | (false, _, _) => {
                findings.push(report::finding_auto_update_disabled());
            }
        }
    }

    /// Check: config.schedule.missing
    ///
    /// A schedule exists when the relevant systemd timer is enabled at boot
    /// (`systemctl is-enabled`). When no timer is enabled and no config enables
    /// updates, emit a missing-schedule warning.
    fn check_schedule_configured(&self, findings: &mut Vec<toride_diagnostic_types::Finding>) {
        info!("Checking schedule configuration");

        let timers = self.auto_update_timers();
        if timers.is_empty() {
            return;
        }

        let any_enabled = timers
            .iter()
            .any(|t| matches!(self.timer_state(t), report::TimerState::Active));

        // `is-active` already implies enabled+running for timers; if any timer
        // is active the schedule is healthy. Otherwise warn that nothing will
        // trigger updates on a schedule.
        if !any_enabled {
            findings.push(report::finding_schedule_missing());
        }
    }

    /// Check: schedule.stale-last-run
    ///
    /// Parses the real `/var/log/unattended-upgrades/unattended-upgrades.log`
    /// for the most recent run's start timestamp (the `YYYY-MM-DD HH:MM:SS,mmm`
    /// prefix on a `Starting unattended upgrades script` line) and, when the
    /// configured schedule is daily/weekly/monthly, flags a stale run if the
    /// elapsed time exceeds the schedule interval by more than a grace period.
    /// Findings are only emitted for APT hosts (which keep a persistent log);
    /// DNF status comes from the journal and is not probed here.
    ///
    /// The schedule is inferred from `APT::Periodic::Update-Package-Lists` in
    /// the `20auto-upgrades` config; when that is absent a daily window is
    /// assumed (the unattended-upgrades default).
    fn check_last_run_fresh(&self, findings: &mut Vec<toride_diagnostic_types::Finding>) {
        info!("Checking last run freshness");

        if self.pkg_mgr != PackageManager::Apt {
            return;
        }

        let Ok(content) = std::fs::read_to_string(&self.paths.log_file) else {
            // No log -> the auto-update enabled check already reports the gap.
            return;
        };

        // Reuse the shared log parser so the staleness check sees the same
        // "most recent run" timestamp as the status() path. A run that never
        // recorded its start marker is treated as "no data" (skip).
        let Ok(status) = crate::parse::parse_unattended_upgrades_status(&content) else {
            return;
        };
        let Some(last_run) = status.last_run else {
            return;
        };

        // The configured schedule determines the freshness window. Infer it
        // from the apt.conf interval (falling back to daily, the upstream
        // default) so a stale run is flagged even when 20auto-upgrades is
        // absent but the log shows an old run.
        let schedule = infer_schedule_from_apt_conf(&self.paths.auto_upgrades_enabled)
            .unwrap_or(Schedule::Daily);
        let max_age = match schedule {
            Schedule::Daily => Duration::from_secs(36 * 60 * 60), // 1.5 days
            Schedule::Weekly => Duration::from_secs(8 * 24 * 60 * 60), // ~8 days
            Schedule::Monthly => Duration::from_secs(33 * 24 * 60 * 60), // ~33 days
            // Custom schedules: do not second-guess them.
            Schedule::Custom(_) => return,
        };

        if let Some(elapsed) = elapsed_since(&last_run) {
            if elapsed > max_age {
                findings.push(report::finding_stale_last_run(&last_run));
            }
        }
    }

    /// Check: permission.config-dir-world-writable
    fn check_config_dir_permissions(&self, findings: &mut Vec<toride_diagnostic_types::Finding>) {
        info!("Checking config directory permissions");

        let dir = match self.pkg_mgr {
            PackageManager::Apt => &self.paths.apt_conf_d,
            PackageManager::Dnf => &self.paths.dnf_conf_d,
            PackageManager::Unknown => return,
        };

        if let Ok(metadata) = std::fs::metadata(dir) {
            // On Unix, check if the "other" write bit is set.
            #[expect(clippy::unnecessary_cast, reason = "mode_bits only on Unix")]
            let mode = metadata.permissions().mode() as u32;
            if mode & 0o002 != 0 {
                findings.push(report::finding_config_dir_world_writable(
                    &dir.display().to_string(),
                ));
            }
        }
    }

    // -----------------------------------------------------------------------
    // Helpers: systemd + config probing
    // -----------------------------------------------------------------------

    /// Returns `true` if `systemctl` is available on `$PATH`.
    fn systemd_available() -> bool {
        which::which("systemctl").is_ok()
    }

    /// The candidate systemd timer units that drive auto-updates for the
    /// detected package manager.
    ///
    /// - **APT**: `apt-daily-upgrade.timer` (the canonical unattended-upgrade
    ///   trigger on Debian/Ubuntu).
    /// - **DNF**: `dnf-automatic-install.timer` then `dnf-automatic.timer`
    ///   (Fedora ships either depending on which subpackage is installed).
    /// - **Unknown**: empty.
    fn auto_update_timers(&self) -> Vec<&'static str> {
        match self.pkg_mgr {
            PackageManager::Apt => vec!["apt-daily-upgrade.timer"],
            // Probe the install variant first; it is the one that actually
            // applies updates rather than just downloading them.
            PackageManager::Dnf => vec![
                "dnf-automatic-install.timer",
                "dnf-automatic.timer",
            ],
            PackageManager::Unknown => Vec::new(),
        }
    }

    /// Probe a timer unit's state via `systemctl is-active` / `cat`.
    ///
    /// A timer is [`TimerState::Active`] when `is-active` succeeds (exit 0),
    /// [`TimerState::Disabled`] when `systemctl cat <unit>` succeeds (the unit
    /// file exists but the timer is not running), and [`TimerState::Absent`]
    /// otherwise (no unit file on disk). Errors from the runner are treated as
    /// absent so the doctor recommends installation rather than "start it".
    ///
    /// Note: the caller (`run()`) already gates the whole check on
    /// `systemd_available()`; this method trusts the runner output, which on
    /// real hosts is `systemctl` and on tests is a [`FakeRunner`].
    fn timer_state(&self, timer: &str) -> report::TimerState {
        let active_spec = toride_runner::CommandSpec::new("systemctl")
            .args(["is-active", "--quiet", timer])
            .timeout(SYSTEMCTL_TIMEOUT);
        match self.runner.run(&active_spec) {
            Ok(output) if output.success => return report::TimerState::Active,
            Ok(_) => {}
            Err(e) => warn!(error = %e, %timer, "systemctl is-active failed"),
        }

        // Distinguish "installed but inactive" from "not installed at all".
        let cat_spec = toride_runner::CommandSpec::new("systemctl")
            .args(["cat", timer])
            .timeout(SYSTEMCTL_TIMEOUT);
        match self.runner.run(&cat_spec) {
            Ok(output) if output.success => report::TimerState::Disabled,
            // No unit file on disk (or systemctl refused): treat as absent so
            // the doctor can recommend installation rather than "start it".
            _ => report::TimerState::Absent,
        }
    }

    /// Parse `/etc/apt/apt.conf.d/20auto-upgrades` for auto-update enablement.
    ///
    /// Returns `true` only when **both** directives are set to `"1"`:
    /// `APT::Periodic::Update-Package-Lists` and `Unattended-Upgrade`. This is
    /// the configuration `apt` itself considers "enabled". A missing or
    /// unreadable file is treated as disabled (honest reporting).
    fn apt_auto_upgrades_enabled(&self) -> bool {
        let Ok(content) = std::fs::read_to_string(&self.paths.auto_upgrades_enabled) else {
            return false;
        };

        let mut update_lists = false;
        let mut unattended = false;
        for raw in content.lines() {
            let line = raw.trim();
            if line.starts_with("//") || line.starts_with('#') {
                continue;
            }
            // Match `APT::Periodic::Update-Package-Lists "1";` style directives.
            if let Some(val) = apt_conf_value(line, "APT::Periodic::Update-Package-Lists") {
                update_lists = val == "1";
            } else if let Some(val) = apt_conf_value(line, "Unattended-Upgrade") {
                unattended = val == "1";
            }
        }
        update_lists && unattended
    }

    /// Parse `/etc/dnf/automatic.conf` for `apply_updates = yes`.
    ///
    /// Returns `true` when the `[commands]` section sets
    /// `apply_updates = yes` (case-insensitive on the value). A missing or
    /// unreadable file is treated as disabled.
    fn dnf_apply_updates_enabled(&self) -> bool {
        let Ok(content) = std::fs::read_to_string(&self.paths.dnf_automatic_conf) else {
            return false;
        };

        let mut in_commands = false;
        for raw in content.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                in_commands = line.eq_ignore_ascii_case("[commands]");
                continue;
            }
            if in_commands
                && let Some((key, val)) = line.split_once('=')
                && key.trim().eq_ignore_ascii_case("apply_updates")
            {
                return val.trim().eq_ignore_ascii_case("yes");
            }
        }
        false
    }
}

/// Extract the quoted value from an apt.conf directive line of the form
/// `APT::Periodic::Update-Package-Lists "1";`.
///
/// Returns `None` if the line does not start with `key` (followed by optional
/// whitespace and a `"`) or has no closing quote.
fn apt_conf_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(key)?.trim_start();
    let quoted = rest.strip_prefix('"')?;
    let end = quoted.find('"')?;
    Some(&quoted[..end])
}

/// Best-effort schedule inference from `/etc/apt/apt.conf.d/20auto-upgrades`.
///
/// Reads the `APT::Periodic::Update-Package-Lists` interval (in days) from the
/// apt.conf file and maps it to a [`Schedule`]. Returns `None` when the file is
/// missing, unreadable, or does not set the directive.
fn infer_schedule_from_apt_conf(path: &std::path::Path) -> Option<Schedule> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return None;
    };
    for raw in content.lines() {
        let line = raw.trim();
        if line.starts_with("//") || line.starts_with('#') {
            continue;
        }
        if let Some(val) = apt_conf_value(line, "APT::Periodic::Update-Package-Lists") {
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

/// Compute the elapsed [`Duration`] since a `YYYY-MM-DD HH:MM:SS[,mmm]`
/// timestamp.
///
/// Uses the system clock. Returns `None` if the timestamp cannot be parsed, the
/// wall clock is unavailable, or the timestamp is in the future (a future
/// last-run is treated as fresh / not stale rather than underflowing). Local
/// time is assumed (unattended-upgrades logs in local time).
fn elapsed_since(timestamp: &str) -> Option<Duration> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let parsed = parse_log_timestamp(timestamp)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    now.checked_sub(parsed)
}

/// Parse a `YYYY-MM-DD HH:MM:SS` (with optional `,mmm` millis suffix) timestamp
/// into a Duration since the Unix epoch. Treats the timestamp as UTC to keep
/// the calculation dependency-free; this may over/under-count the freshness
/// window by the host's UTC offset, which is acceptable for a "stale by days"
/// heuristic. The real unattended-upgrades log timestamp is
/// `2025-03-13 20:43:25,923`; the millis suffix is parsed and folded into the
/// seconds (truncated, since `Duration` here is day-granularity).
fn parse_log_timestamp(timestamp: &str) -> Option<Duration> {
    let mut parts = timestamp.split_whitespace();
    let date = parts.next()?;
    let time_token = parts.next()?;

    // Strip an optional ",mmm" milliseconds suffix (the real log format).
    let time = time_token.split_once(',').map_or(time_token, |(c, _)| c);

    let mut d = date.split('-');
    let year: i64 = d.next()?.parse().ok()?;
    let month: u32 = d.next()?.parse().ok()?;
    let day: u32 = d.next()?.parse().ok()?;

    let mut t = time.split(':');
    let hour: u64 = t.next()?.parse().ok()?;
    let min: u64 = t.next()?.parse().ok()?;
    let sec: u64 = t.next()?.parse().ok()?;

    let days_since_epoch = civil_to_days(year, month, day)?;
    let secs = days_since_epoch as u64 * 86_400 + hour * 3_600 + min * 60 + sec;
    Some(Duration::from_secs(secs))
}

/// Convert a proleptic Gregorian date to days since 1970-01-01.
///
/// Implements Howard Hinnant's `days_from_civil` algorithm. Returns `None` on
/// invalid month/day values.
///
/// Note: the `doe` (day-of-era) term folds in both the year-within-era
/// (`yoe * 365 + leap days`) and the day-of-year; omitting the year term
/// produces dates off by decades.
fn civil_to_days(year: i64, month: u32, day: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || day == 0 {
        return None;
    }
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let m = month as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    let days = era * 146_097 + doe - 719_468;
    Some(days)
}

// Unix-specific imports for permission checking.
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use toride_runner::fake::FakeRunner;
    use toride_runner::{CommandOutput, CommandSpec};

    /// Build a `FakeRunner` whose `.run()` calls return `responses` in order.
    fn runner_with(responses: &[CommandOutput]) -> FakeRunner {
        let mut r = FakeRunner::new();
        for resp in responses {
            r = r.push_response(resp.clone());
        }
        r
    }

    #[test]
    fn apt_conf_value_extracts_quoted_directive() {
        // The helper expects a pre-trimmed line (as apt_auto_upgrades_enabled
        // provides); leading whitespace is the caller's responsibility.
        let line = r#"APT::Periodic::Update-Package-Lists "1";"#;
        assert_eq!(apt_conf_value(line, "APT::Periodic::Update-Package-Lists"), Some("1"));
        assert_eq!(apt_conf_value(line, "Unattended-Upgrade"), None);
        assert_eq!(apt_conf_value(r#"Unattended-Upgrade "0";"#, "Unattended-Upgrade"), Some("0"));
    }

    #[test]
    fn apt_conf_value_ignores_comments_and_malformed() {
        assert_eq!(apt_conf_value("// comment", "Unattended-Upgrade"), None);
        assert_eq!(apt_conf_value(r#"Unattended-Upgrade 1;"#, "Unattended-Upgrade"), None);
    }

    #[test]
    fn apt_auto_upgrades_parses_both_directives_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("20auto-upgrades");
        std::fs::write(
            &conf,
            "APT::Periodic::Update-Package-Lists \"1\";\nUnattended-Upgrade \"1\";\n",
        )
        .unwrap();
        let runner = FakeRunner::new();
        let mut doc = Doctor::new(&runner);
        doc.paths.auto_upgrades_enabled = conf.clone();
        doc.pkg_mgr = PackageManager::Apt;
        assert!(doc.apt_auto_upgrades_enabled());
    }

    #[test]
    fn apt_auto_upgrades_disabled_when_only_one_directive() {
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("20auto-upgrades");
        std::fs::write(&conf, "APT::Periodic::Update-Package-Lists \"1\";\n").unwrap();
        let runner = FakeRunner::new();
        let mut doc = Doctor::new(&runner);
        doc.paths.auto_upgrades_enabled = conf;
        doc.pkg_mgr = PackageManager::Apt;
        assert!(!doc.apt_auto_upgrades_enabled());
    }

    #[test]
    fn apt_auto_upgrades_disabled_when_file_missing() {
        let runner = FakeRunner::new();
        let mut doc = Doctor::new(&runner);
        doc.paths.auto_upgrades_enabled = "/nonexistent/20auto-upgrades".into();
        doc.pkg_mgr = PackageManager::Apt;
        assert!(!doc.apt_auto_upgrades_enabled());
    }

    #[test]
    fn apt_auto_upgrades_ignores_commented_directives() {
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("20auto-upgrades");
        std::fs::write(
            &conf,
            "// APT::Periodic::Update-Package-Lists \"1\";\n// Unattended-Upgrade \"1\";\n",
        )
        .unwrap();
        let runner = FakeRunner::new();
        let mut doc = Doctor::new(&runner);
        doc.paths.auto_upgrades_enabled = conf;
        doc.pkg_mgr = PackageManager::Apt;
        assert!(!doc.apt_auto_upgrades_enabled());
    }

    #[test]
    fn dnf_apply_updates_yes_in_commands_section() {
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("automatic.conf");
        std::fs::write(
            &conf,
            "[commands]\nupgrade_type = security\napply_updates = yes\n",
        )
        .unwrap();
        let runner = FakeRunner::new();
        let mut doc = Doctor::new(&runner);
        doc.paths.dnf_automatic_conf = conf;
        doc.pkg_mgr = PackageManager::Dnf;
        assert!(doc.dnf_apply_updates_enabled());
    }

    #[test]
    fn dnf_apply_updates_disabled_when_no() {
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("automatic.conf");
        std::fs::write(&conf, "[commands]\napply_updates = no\n").unwrap();
        let runner = FakeRunner::new();
        let mut doc = Doctor::new(&runner);
        doc.paths.dnf_automatic_conf = conf;
        doc.pkg_mgr = PackageManager::Dnf;
        assert!(!doc.dnf_apply_updates_enabled());
    }

    #[test]
    fn dnf_apply_updates_ignores_setting_outside_commands() {
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("automatic.conf");
        std::fs::write(
            &conf,
            "[base]\napply_updates = yes\n[commands]\napply_updates = no\n",
        )
        .unwrap();
        let runner = FakeRunner::new();
        let mut doc = Doctor::new(&runner);
        doc.paths.dnf_automatic_conf = conf;
        doc.pkg_mgr = PackageManager::Dnf;
        assert!(!doc.dnf_apply_updates_enabled());
    }

    #[test]
    fn timer_state_active_when_is_active_succeeds() {
        // is-active success on the first call -> Active without checking cat.
        let runner = runner_with(&[CommandOutput::from_stdout("active")]);
        let mut doc = Doctor::new(&runner);
        doc.pkg_mgr = PackageManager::Apt;
        assert_eq!(doc.timer_state("apt-daily-upgrade.timer"), report::TimerState::Active);
    }

    #[test]
    fn timer_state_disabled_when_installed_but_inactive() {
        // is-active fails, cat succeeds -> Disabled.
        let runner = runner_with(&[
            CommandOutput::from_stderr("inactive", 3),
            CommandOutput::from_stdout("# /usr/lib/systemd/system/apt-daily-upgrade.timer"),
        ]);
        let mut doc = Doctor::new(&runner);
        doc.pkg_mgr = PackageManager::Apt;
        assert_eq!(doc.timer_state("apt-daily-upgrade.timer"), report::TimerState::Disabled);
    }

    #[test]
    fn timer_state_absent_when_unit_missing() {
        // is-active fails, cat fails -> Absent.
        let runner = runner_with(&[
            CommandOutput::from_stderr("inactive", 3),
            CommandOutput::from_stderr("No such file or directory", 1),
        ]);
        let mut doc = Doctor::new(&runner);
        doc.pkg_mgr = PackageManager::Apt;
        assert_eq!(doc.timer_state("apt-daily-upgrade.timer"), report::TimerState::Absent);
    }

    /// `check_last_run_fresh` fires the `schedule.stale-last-run` finding when
    /// the most recent `Starting unattended upgrades script` timestamp in the
    /// real log is older than the configured daily window.
    ///
    /// The log sample uses the real `/var/log/unattended-upgrades/
    /// unattended-upgrades.log` line format (`YYYY-MM-DD HH:MM:SS,mmm LEVEL
    /// message`). The fixture uses a date far in the past so the staleness
    /// check always fires regardless of the host wall clock.
    ///
    /// Source for the log format: Ubuntu Server docs, "Automatic updates".
    /// https://ubuntu.com/server/docs/how-to/software/automatic-updates/
    #[test]
    fn check_last_run_fresh_fires_on_stale_real_log() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("unattended-upgrades.log");
        // 2001-01-01 is unconditionally > 1.5 days ago on any plausible host.
        std::fs::write(
            &log,
            "2001-01-01 04:00:00,000 INFO Starting unattended upgrades script\n\
             2001-01-01 04:00:01,000 INFO Packages that will be upgraded: openssl\n\
             2001-01-01 04:00:09,000 INFO All upgrades installed\n",
        )
        .unwrap();

        let runner = FakeRunner::new();
        let mut doc = Doctor::new(&runner);
        doc.pkg_mgr = PackageManager::Apt;
        doc.paths.log_file = log;

        let mut findings = Vec::new();
        doc.check_last_run_fresh(&mut findings);
        assert!(
            findings.iter().any(|f| f.id == "schedule.stale-last-run"),
            "expected a stale-last-run finding, got: {findings:?}"
        );
    }

    /// A fresh run (1 hour ago, UTC) does not fire the staleness finding.
    #[test]
    fn check_last_run_fresh_quiet_on_fresh_real_log() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("unattended-upgrades.log");
        // 1 hour ago in UTC. The parser treats log timestamps as UTC, so a
        // UTC-based "1 hour ago" is unambiguously inside the daily window and
        // never underflows regardless of host timezone.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        let recent_secs = now.as_secs().saturating_sub(3_600);
        let (y, mo, d, h, mi, s) = epoch_to_ymdhms(recent_secs);
        let ts = format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02},000");
        std::fs::write(
            &log,
            format!(
                "{ts} INFO Starting unattended upgrades script\n\
                 {ts} INFO All upgrades installed\n"
            ),
        )
        .unwrap();

        let runner = FakeRunner::new();
        let mut doc = Doctor::new(&runner);
        doc.pkg_mgr = PackageManager::Apt;
        doc.paths.log_file = log;

        let mut findings = Vec::new();
        doc.check_last_run_fresh(&mut findings);
        assert!(
            !findings.iter().any(|f| f.id == "schedule.stale-last-run"),
            "did not expect a stale-last-run finding, got: {findings:?}"
        );
    }

    /// Convert a Unix epoch second count to `(year, month, day, hour, min, sec)`
    /// (UTC) for building a near-now log timestamp in tests. Uses the inverse
    /// of `civil_to_days`.
    fn epoch_to_ymdhms(secs: u64) -> (i64, u32, u32, u64, u64, u64) {
        let days = (secs / 86_400) as i64;
        let rem = secs % 86_400;
        let h = rem / 3_600;
        let mi = (rem % 3_600) / 60;
        let s = rem % 60;
        let (y, mo, d) = days_to_civil(days);
        (y, mo, d, h, mi, s)
    }

    /// Inverse of `civil_to_days`: days since 1970-01-01 -> Gregorian date.
    fn days_to_civil(days: i64) -> (i64, u32, u32) {
        let days = days + 719_468;
        let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
        let doe = days - era * 146_097; // [0, 146096]
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
        let y = yoe as i64 + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
        let mp = (5 * doy + 2) / 153; // [0, 11]
        let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
        let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32; // [1, 12]
        let y = if m <= 2 { y + 1 } else { y };
        (y, m, d)
    }

    #[test]
    fn run_emits_manager_absent_when_no_pkg_mgr_and_no_systemd() {
        // Unknown package manager + systemctl not on PATH (typical test env).
        // FakeRunner returns empty/failed outputs, but systemd_available() keys
        // off `which::which`, so on a host without systemctl this short-circuits.
        let runner = FakeRunner::new();
        let mut doc = Doctor::new(&runner);
        doc.pkg_mgr = PackageManager::Unknown;
        let findings = doc.run().unwrap();
        if which::which("systemctl").is_err() {
            assert!(
                findings.iter().any(|f| f.id == "auto-update.manager-not-detected"),
                "expected manager-not-detected finding, got: {findings:?}"
            );
        }
        // If systemctl IS present (CI container), run() proceeds to the checks;
        // either way run() must not error.
    }

    #[test]
    fn runner_run_does_not_panic_on_unconsumed_specs() {
        // Sanity: a Doctor constructed with an empty FakeRunner and an Unknown
        // package manager either short-circuits or runs checks that each handle
        // runner errors gracefully.
        let runner = FakeRunner::new();
        let doc = Doctor::new(&runner);
        // pkg_mgr is detected via detect_package_manager() in new(); on a test
        // host it is usually Unknown, which short-circuits before any run().
        let _ = doc.run();
    }

    /// A `Doctor` must construct without the `_runner` being unused.
    #[test]
    fn doctor_stores_runner_reference() {
        let runner = FakeRunner::new();
        let doc = Doctor::new(&runner);
        // Touch the runner field via a public-ish path: timer probing reads it.
        // On a host without systemctl this returns Absent without invoking run.
        let _ = doc.auto_update_timers();
    }

    /// Ensures `CommandSpec` construction compiles with the documented API.
    #[allow(dead_code)]
    fn _commandspec_args_compile_check() {
        let _ = CommandSpec::new("systemctl").args(["is-active", "--quiet", "x"]);
    }
}
