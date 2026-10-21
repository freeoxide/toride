//! systemd detection and backup-timer enumeration. When systemd is not
//! detected (e.g. a macOS dev box), queries return `Ok(false)` with a note
//! from [`detect`] and no command is invoked.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::Error;
use crate::spec::Schedule;
use toride_runner::CommandSpec;

use std::fmt::Write as _;

/// Marker returned by [`detect`] describing why systemd is or is not in use;
/// `note` is a short string for the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemdDetect {
    /// `true` when systemd appears to be the running init system on this host.
    pub available: bool,
    /// Short informational note for the UI. Empty when systemd is present.
    pub note: String,
}

impl SystemdDetect {
    fn present() -> Self {
        Self {
            available: true,
            note: String::new(),
        }
    }

    fn absent(note: &str) -> Self {
        Self {
            available: false,
            note: note.to_owned(),
        }
    }
}

/// Result of probing for a single timer unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimerProbe {
    /// The unit name that was probed (e.g. `toride-backup.timer`).
    pub unit: String,
    /// `true` when the unit file is installed/known to systemd.
    pub installed: bool,
    /// `true` when the unit is loaded and in the `active` state.
    pub active: bool,
}

/// Detect whether systemd is the running init system: present only when
/// `systemctl` is on `$PATH` AND `/run/systemd/system` exists; otherwise
/// `available: false` + the note "systemd not detected", no commands run.
pub fn detect() -> SystemdDetect {
    if which::which("systemctl").is_err() {
        return SystemdDetect::absent("systemd not detected");
    }
    if !Path::new("/run/systemd/system").exists() {
        return SystemdDetect::absent("systemd not detected");
    }
    SystemdDetect::present()
}

fn run_systemctl(args: &[&str]) -> std::result::Result<std::process::Output, std::io::Error> {
    #[cfg(test)]
    SYSTEMCTL_SPAWNS.with(|c| c.set(c.get() + 1));
    Command::new("systemctl").args(args).output()
}

#[cfg(test)]
thread_local! {
    static SYSTEMCTL_SPAWNS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn unit_installed(unit: &str) -> bool {
    match run_systemctl(&["cat", "--", unit]) {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

fn unit_active(unit: &str) -> bool {
    match run_systemctl(&["is-active", "--", unit]) {
        Ok(out) => {
            if !out.status.success() {
                return false;
            }
            String::from_utf8_lossy(&out.stdout).trim() == "active"
        }
        Err(_) => false,
    }
}

fn unit_action(action: &str, unit: &str) -> crate::Result<()> {
    let detected = detect();
    if !detected.available {
        return Err(Error::CommandFailed(format!(
            "cannot {action} unit {unit}: {}",
            detected.note
        )));
    }
    match run_systemctl(&[action, "--", unit]) {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => Err(Error::CommandFailed(format!(
            "systemctl {action} {unit} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))),
        Err(e) => Err(Error::CommandFailed(format!(
            "systemctl {action} {unit}: {e}"
        ))),
    }
}

/// Start a systemd unit (`systemctl start <unit>`).
/// # Errors: [`crate::Error::CommandFailed`] if systemd is unavailable or the command fails.
pub fn start_unit(unit: &str) -> crate::Result<()> {
    unit_action("start", unit)
}

/// Stop a systemd unit (`systemctl stop <unit>`).
/// # Errors: [`crate::Error::CommandFailed`] if systemd is unavailable or the command fails.
pub fn stop_unit(unit: &str) -> crate::Result<()> {
    unit_action("stop", unit)
}

/// Enable a systemd unit to start at boot (`systemctl enable <unit>`).
/// # Errors: [`crate::Error::CommandFailed`] if systemd is unavailable or the command fails.
pub fn enable_unit(unit: &str) -> crate::Result<()> {
    unit_action("enable", unit)
}

/// Probe a single timer unit; `is-active` is only issued when `systemctl cat`
/// showed the unit installed (an absent unit can never read as active).
pub fn probe_timer(unit: &str) -> TimerProbe {
    let installed = unit_installed(unit);
    let active = installed && unit_active(unit);
    TimerProbe {
        unit: unit.to_owned(),
        installed,
        active,
    }
}

const BASE_BACKUP_TIMER_UNITS: &[&str] = &[
    "toride-backup.timer",
    "restic.timer",
    "restic-backup.timer",
    "restic-run.timer",
    "resticprofile.timer",
    "borg.timer",
    "borg-backup.timer",
    "borgmatic.timer",
];

const BACKUP_TIMER_PREFIXES: &[&str] = &[
    "toride-backup-",
    "restic",
    "resticprofile",
    "borg",
    "borgmatic",
];

/// Enumerate backup-related timers from a single `systemctl list-timers
/// --all --no-pager --plain` listing: exactly one spawn answers every
/// question this enumeration asks.
///
/// A timer that appears in the listing is loaded (installed) by definition;
/// its `NEXT` column (an `n/a` first column marks a loaded-but-inactive
/// timer) decides `active`. Vendor timer unit files that sit on disk but were
/// never loaded by systemd are not enumerated: the previous per-unit
/// `systemctl cat` fan-out (one spawn per fixed vendor name plus a re-probe
/// per match) cost around ten spawns on every dashboard refresh tick.
pub fn enumerate_backup_timers() -> Vec<TimerProbe> {
    let Ok(out) = run_systemctl(&["list-timers", "--all", "--no-pager", "--plain"]) else {
        return Vec::new();
    };
    if !out.status.success() && out.stdout.is_empty() {
        return Vec::new();
    }
    parse_backup_timers(&String::from_utf8_lossy(&out.stdout))
}

/// Parse `systemctl list-timers --all --plain` rows into probes for the
/// fixed vendor unit names and managed prefixes, de-duplicated in first-seen
/// order.
fn parse_backup_timers(text: &str) -> Vec<TimerProbe> {
    let mut probes: Vec<TimerProbe> = Vec::new();
    for line in text.lines() {
        let Some(unit) = extract_timer_unit(line) else {
            continue;
        };
        let known = BASE_BACKUP_TIMER_UNITS.contains(&unit.as_str())
            || BACKUP_TIMER_PREFIXES.iter().any(|p| unit.starts_with(p));
        if !known || probes.iter().any(|p| p.unit == unit) {
            continue;
        }
        probes.push(TimerProbe {
            unit,
            installed: true,
            active: !line.trim_start().starts_with("n/a"),
        });
    }
    probes
}

fn extract_timer_unit(line: &str) -> Option<String> {
    line.split_whitespace()
        .find(|tok| {
            std::path::Path::new(tok)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("timer"))
        })
        .map(std::borrow::ToOwned::to_owned)
}

/// Whether any backup-related timer unit is installed on this host.
pub fn any_backup_timer_installed() -> bool {
    !enumerate_backup_timers().is_empty()
}

/// Whether any backup-related timer unit is both installed and active.
pub fn any_backup_timer_active() -> bool {
    enumerate_backup_timers().iter().any(|p| p.active)
}

/// Default system unit-file directory (systemd.unit(5) system load path).
pub const SYSTEMD_UNIT_DIR: &str = "/etc/systemd/system";

/// Marker opening toride-managed crontab entries (`# toride-backup:BEGIN:<name>`,
/// closed by [`CRON_MARKER_END`]) so they can be located and removed later.
pub const CRON_MARKER_BEGIN: &str = "# toride-backup:BEGIN:";
/// Marker closing a toride-managed crontab entry (see [`CRON_MARKER_BEGIN`]).
pub const CRON_MARKER_END: &str = "# toride-backup:END:";

/// Build the systemd unit name pair for a job, e.g. `("toride-backup-myjob.service",
/// "toride-backup-myjob.timer")`. SECURITY: `name` is reduced to `[A-Za-z0-9_-]`
/// before interpolation so it cannot escape the unit dir or inject shell.
pub fn unit_names(name: &str) -> (String, String) {
    let base = format!("toride-backup-{}", sanitize_unit_name(name));
    (format!("{base}.service"), format!("{base}.timer"))
}

fn sanitize_unit_name(name: &str) -> String {
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

/// Parse a single cron numeric field, enforcing its value range so a
/// syntactically numeric but out-of-range field (`99` minutes) can never
/// render a broken `OnCalendar=` value that lexical-only schedule validation
/// would accept.
fn parse_ranged(
    field: &str,
    range: std::ops::RangeInclusive<u8>,
    label: &str,
) -> crate::Result<u8> {
    let n: u8 = field.parse().map_err(|_| {
        Error::ScheduleError(format!(
            "cron->OnCalendar: {label} {field:?} must be a single number in range {}-{}",
            range.start(),
            range.end()
        ))
    })?;
    if !range.contains(&n) {
        return Err(Error::ScheduleError(format!(
            "cron->OnCalendar: {label} value {n} out of range ({}-{})",
            range.start(),
            range.end()
        )));
    }
    Ok(n)
}

/// Convert a 5-field cron expression into a systemd `OnCalendar=` value
/// (systemd.time(7)); cron DOW 0/7=Sun maps to weekday abbreviations.
/// # Errors: expressions not losslessly representable (months, dom+dow, DOW lists) or numeric fields outside their cron ranges.
pub fn cron_to_oncalendar(cron: &str) -> crate::Result<String> {
    let fields: Vec<&str> = cron.split_whitespace().collect();
    if fields.len() != 5 {
        return Err(Error::ScheduleError(format!(
            "cron expression must have exactly 5 fields, got {}: {:?}",
            fields.len(),
            cron,
        )));
    }
    let minute = fields[0];
    let hour = fields[1];
    let dom = fields[2];
    let month = fields[3];
    let dow = fields[4];

    if month != "*" {
        return Err(Error::ScheduleError(format!(
            "cron->OnCalendar: month restriction ({month:?}) is not supported; \
             use a calendar event directly",
        )));
    }
    if dom != "*" && dow != "*" {
        return Err(Error::ScheduleError(format!(
            "cron->OnCalendar: both dom ({dom}) and dow ({dow}) restricted is ambiguous; \
             refusing to guess",
        )));
    }

    let time = format!(
        "{:02}:{:02}:00",
        parse_ranged(hour, 0..=23, "hour")?,
        parse_ranged(minute, 0..=59, "minute")?,
    );

    let weekday = if dow == "*" {
        None
    } else {
        let map = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
        let n: u8 = dow.parse().map_err(|_| {
            Error::ScheduleError(format!(
                "cron->OnCalendar: dow {dow:?} must be a single number 0-7 \
                     (lists/ranges not supported)"
            ))
        })?;
        if n > 7 {
            return Err(Error::ScheduleError(format!(
                "cron->OnCalendar: dow value {n} out of range (0-7)",
            )));
        }
        Some(map[n as usize])
    };

    let date_part: String = if dom == "*" {
        "*-*-*".to_owned()
    } else {
        let n = parse_ranged(dom, 1..=31, "day-of-month")?;
        format!("*-*-{n:02}")
    };

    Ok(match weekday {
        Some(wd) => format!("{wd} {date_part} {time}"),
        None => format!("{date_part} {time}"),
    })
}

/// Render a `.timer` unit translating the cron expression to `OnCalendar=`
/// with `Persistent=true` (missed runs catch up on next boot); systemd.timer(5).
pub fn render_timer_unit(name: &str, schedule: &Schedule) -> crate::Result<String> {
    let oncal = cron_to_oncalendar(&schedule.cron)?;
    let mut s = String::new();
    s.push_str("[Unit]\n");
    let _ = write!(s, "Description=toride backup timer: {name}\n\n");

    s.push_str("[Timer]\n");
    let _ = writeln!(s, "OnCalendar={oncal}");
    s.push_str("Persistent=true\n");
    s.push_str("AccuracySec=1min\n\n");

    s.push_str("[Install]\n");
    s.push_str("WantedBy=timers.target\n");
    Ok(s)
}

/// Resolve the on-disk path for a unit file under [`SYSTEMD_UNIT_DIR`].
pub fn unit_path(unit: &str) -> PathBuf {
    Path::new(SYSTEMD_UNIT_DIR).join(unit)
}

/// Build the `systemctl daemon-reload` command (pick up written/removed units).
pub fn daemon_reload_spec() -> CommandSpec {
    CommandSpec::new("systemctl").args(["daemon-reload"])
}

/// Build `systemctl enable --now <timer>`: enable at boot and start now.
pub fn enable_now_spec(timer_unit: &str) -> CommandSpec {
    CommandSpec::new("systemctl")
        .arg("enable")
        .arg("--now")
        .arg("--")
        .arg(timer_unit)
}

/// Build `systemctl disable --now <timer>`: stop it and remove the boot symlink.
pub fn disable_now_spec(timer_unit: &str) -> CommandSpec {
    CommandSpec::new("systemctl")
        .arg("disable")
        .arg("--now")
        .arg("--")
        .arg(timer_unit)
}

/// Render a `.service` whose `ExecStart=` runs the managed CLI
/// (`<cli_bin> backup <name>`); the passphrase is owned by the CLI at runtime
/// and never appears in the unit.
pub fn render_cli_service_unit(name: &str, exec_start: &str) -> String {
    let mut s = String::new();
    s.push_str("[Unit]\n");
    let _ = writeln!(s, "Description=toride backup job: {name}");
    s.push_str("Documentation=https://restic.readthedocs.io\n");
    s.push_str("Wants=network-online.target\n");
    s.push_str("After=network-online.target\n\n");

    s.push_str("[Service]\n");
    s.push_str("Type=oneshot\n");
    let _ = writeln!(s, "ExecStart={exec_start}");
    s.push_str("PrivateTmp=true\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_returns_bool_with_note() {
        let d = detect();
        if !d.available {
            assert!(!d.note.is_empty(), "absent detection must carry a note");
        }
    }

    #[test]
    fn extract_timer_unit_finds_suffix_token() {
        let line =
            "Sun 2025-01-01 00:00:00 UTC  1h left  -  -  restic-backup.timer restic-backup.service";
        assert_eq!(
            extract_timer_unit(line).as_deref(),
            Some("restic-backup.timer")
        );
    }

    #[test]
    fn extract_timer_unit_returns_none_when_absent() {
        let line = "no timers listed";
        assert!(extract_timer_unit(line).is_none());
    }

    #[test]
    fn base_units_are_nonempty() {
        assert_ne!(BASE_BACKUP_TIMER_UNITS, Vec::<&str>::new());
        assert!(BASE_BACKUP_TIMER_UNITS.iter().all(|u| {
            std::path::Path::new(u)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("timer"))
        }));
    }

    #[test]
    fn prefixes_are_nonempty() {
        assert_ne!(BACKUP_TIMER_PREFIXES, Vec::<&str>::new());
    }

    #[test]
    fn probe_timer_returns_consistent_state() {
        let probe = probe_timer("toride-backup-this-unit-does-not-exist-xyz.timer");
        if !probe.installed {
            assert!(!probe.active, "absent unit must not be active");
        }
    }

    #[test]
    fn probe_timer_absent_unit_spawns_exactly_once() {
        SYSTEMCTL_SPAWNS.with(|c| c.set(0));
        let probe = probe_timer("toride-backup-oracle-absent-unit-xyz.timer");
        let spawns = SYSTEMCTL_SPAWNS.with(std::cell::Cell::get);
        assert_eq!(
            spawns, 1,
            "absent unit: `cat` only: is-active must be skipped"
        );
        assert!(!probe.installed);
        assert!(
            !probe.active,
            "short-circuit must keep the absent-unit verdict false"
        );
    }

    /// Enumerate must issue exactly one spawn: the single `list-timers --all`
    /// query (the previous fan-out probed eight fixed vendor units with one
    /// `systemctl cat` each, plus a re-probe per match).
    #[test]
    fn enumerate_backup_timers_spawns_exactly_one_list_timers() {
        SYSTEMCTL_SPAWNS.with(|c| c.set(0));
        let _probes = enumerate_backup_timers();
        let spawns = SYSTEMCTL_SPAWNS.with(std::cell::Cell::get);
        assert_eq!(
            spawns, 1,
            "enumeration must be answered by one list-timers spawn"
        );
    }

    /// The list-timers parser derives installed/active from the table rows:
    /// an `n/a` NEXT column means loaded but inactive; unrelated timers are
    /// skipped.
    #[test]
    fn parse_backup_timers_reads_rows_and_na_activity() {
        let table = concat!(
            "NEXT                        LEFT          LAST       PASSED UNIT                    ACTIVATES\n",
            "Sun 2025-01-05 00:00:00 UTC 1h 20m left  Sat 2025-01-04 00:00:00 UTC 22h ago restic-backup.timer restic-backup.service\n",
            "n/a                         n/a           Sun 2024-12-01 00:00:00 UTC -       borg.timer               borg.service\n",
            "Mon 2025-01-06 00:00:00 UTC 2d left       n/a                         -       unrelated.timer          unrelated.service\n",
            "Sun 2025-01-05 00:00:00 UTC 1h left       n/a                         -       toride-backup-nightly.timer toride-backup-nightly.service\n",
            "\n1 timers listed.\n",
        );
        let probes = parse_backup_timers(table);
        let restic = probes
            .iter()
            .find(|p| p.unit == "restic-backup.timer")
            .expect("vendor timer found");
        assert!(restic.installed);
        assert!(restic.active, "a populated NEXT column means active");

        let borg = probes
            .iter()
            .find(|p| p.unit == "borg.timer")
            .expect("vendor timer found");
        assert!(borg.installed);
        assert!(!borg.active, "an n/a NEXT column means inactive");

        assert!(
            probes.iter().all(|p| p.unit != "unrelated.timer"),
            "non-backup timers must be skipped: {probes:?}"
        );
        assert!(
            probes
                .iter()
                .any(|p| p.unit == "toride-backup-nightly.timer"),
            "managed toride timers must be found: {probes:?}"
        );
    }

    use std::path::PathBuf;

    use crate::spec::Schedule;
    #[test]
    fn cron_to_oncalendar_daily_at_2am() {
        let oncal = cron_to_oncalendar("0 2 * * *").unwrap();
        assert_eq!(oncal, "*-*-* 02:00:00");
    }

    #[test]
    fn cron_to_oncalendar_weekly_sunday() {
        let oncal = cron_to_oncalendar("30 3 * * 0").unwrap();
        assert_eq!(oncal, "Sun *-*-* 03:30:00");
    }

    #[test]
    fn cron_to_oncalendar_dow_7_is_sunday() {
        let oncal = cron_to_oncalendar("0 0 * * 7").unwrap();
        assert_eq!(oncal, "Sun *-*-* 00:00:00");
    }

    #[test]
    fn cron_to_oncalendar_dom_is_zero_padded() {
        let oncal = cron_to_oncalendar("0 2 5 * *").unwrap();
        assert_eq!(oncal, "*-*-05 02:00:00");
    }

    /// Out-of-range numeric fields must be rejected: `0 99 * * *` previously
    /// rendered the broken `OnCalendar=*-*-* 99:00:00` and passed every
    /// lexical check the installer runs.
    #[test]
    fn cron_to_oncalendar_rejects_out_of_range_fields() {
        for cron in [
            "0 99 * * *",
            "99 0 * * *",
            "0 24 * * *",
            "60 0 * * *",
            "0 0 32 * *",
            "0 0 0 * *",
        ] {
            let err = cron_to_oncalendar(cron).unwrap_err();
            assert!(
                matches!(err, Error::ScheduleError(_)),
                "cron {cron:?}: expected ScheduleError, got {err:?}"
            );
        }
    }

    #[test]
    fn cron_to_oncalendar_rejects_month_restriction() {
        let err = cron_to_oncalendar("0 0 1 1 *").unwrap_err();
        assert!(matches!(err, Error::ScheduleError(_)));
    }

    #[test]
    fn cron_to_oncalendar_rejects_dow_list() {
        let err = cron_to_oncalendar("0 0 * * 1,3").unwrap_err();
        assert!(matches!(err, Error::ScheduleError(_)));
    }

    #[test]
    fn unit_names_pair() {
        let (svc, tmr) = unit_names("nightly");
        assert_eq!(svc, "toride-backup-nightly.service");
        assert_eq!(tmr, "toride-backup-nightly.timer");
    }

    #[test]
    fn unit_names_sanitizes_unsafe_input() {
        let (svc, tmr) = unit_names("../etc/passwd; rm -rf /");
        assert!(
            !svc.contains('/') && !svc.contains(' ') && !svc.contains(';'),
            "service unit must be sanitized: {svc}"
        );
        assert!(
            !tmr.contains('/') && !tmr.contains(' ') && !tmr.contains(';'),
            "timer unit must be sanitized: {tmr}"
        );
        assert!(svc.starts_with("toride-backup-") && svc.ends_with(".service"));
        assert!(
            tmr.starts_with("toride-backup-")
                && std::path::Path::new(&tmr)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("timer"))
        );
    }

    #[test]
    fn render_timer_unit_has_oncalendar_and_persistent() {
        let unit = render_timer_unit("nightly", &Schedule::new("0 2 * * *")).unwrap();
        assert!(unit.contains("OnCalendar=*-*-* 02:00:00"));
        assert!(unit.contains("Persistent=true"));
        assert!(unit.contains("WantedBy=timers.target"));
    }

    #[test]
    fn render_cli_service_unit_runs_managed_cli() {
        let unit = render_cli_service_unit("nightly", "toride-backup backup nightly");
        assert!(unit.contains("ExecStart=toride-backup backup nightly"));
        assert!(unit.contains("Type=oneshot"));
        assert!(!unit.contains("password"));
        assert!(!unit.contains("passphrase"));
    }

    #[test]
    fn enable_now_spec_matches_exact_systemctl_invocation() {
        let spec = enable_now_spec("toride-backup-nightly.timer");
        assert_eq!(spec.program, "systemctl");
        assert_eq!(
            spec.args,
            vec!["enable", "--now", "--", "toride-backup-nightly.timer"]
        );
    }

    #[test]
    fn disable_now_spec_exact_invocation() {
        let spec = disable_now_spec("toride-backup-nightly.timer");
        assert_eq!(spec.program, "systemctl");
        assert_eq!(
            spec.args,
            vec!["disable", "--now", "--", "toride-backup-nightly.timer"]
        );
    }

    #[test]
    fn daemon_reload_spec_exact_invocation() {
        let spec = daemon_reload_spec();
        assert_eq!(spec.program, "systemctl");
        assert_eq!(spec.args, vec!["daemon-reload"]);
    }

    #[test]
    fn unit_path_under_system_dir() {
        let p = unit_path("toride-backup-nightly.timer");
        assert_eq!(
            p,
            PathBuf::from("/etc/systemd/system/toride-backup-nightly.timer")
        );
    }
}
