//! systemd detection and backup-timer enumeration. When systemd is not
//! detected (e.g. a macOS dev box), queries return `Ok(false)` with a note
//! from [`detect`] and no command is invoked.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::Error;
use crate::spec::{Backend, BackupSpec, Schedule};
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

/// Enumerate backup-related timers: fixed vendor unit names plus prefix
/// matches from `systemctl list-timers --all`, de-duplicated in first-seen
/// order, each probed for installed/active status.
pub fn enumerate_backup_timers() -> Vec<TimerProbe> {
    let mut seen: Vec<String> = Vec::new();
    let mut probes: Vec<TimerProbe> = Vec::new();

    for unit in BASE_BACKUP_TIMER_UNITS {
        if seen.iter().any(|u| u == unit) {
            continue;
        }
        let probe = probe_timer(unit);
        if probe.installed {
            seen.push(probe.unit.clone());
            probes.push(probe);
        }
    }

    if let Ok(out) = run_systemctl(&["list-timers", "--all", "--no-pager", "--plain"])
        && (out.status.success() || !out.stdout.is_empty())
    {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            if let Some(unit) = extract_timer_unit(line) {
                let matches_prefix = BACKUP_TIMER_PREFIXES.iter().any(|p| unit.starts_with(p));
                if !matches_prefix {
                    continue;
                }
                if seen.contains(&unit) {
                    continue;
                }
                let probe = probe_timer(&unit);
                seen.push(probe.unit.clone());
                probes.push(probe);
            }
        }
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

/// Convert a 5-field cron expression into a systemd `OnCalendar=` value
/// (systemd.time(7)); cron DOW 0/7=Sun maps to weekday abbreviations.
/// # Errors: expressions not losslessly representable (months, dom+dow, DOW lists).
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
        hour.parse::<u8>().map_err(|_| {
            Error::ScheduleError(format!(
                "cron->OnCalendar: hour {hour:?} must be a number 0-23"
            ))
        })?,
        minute.parse::<u8>().map_err(|_| {
            Error::ScheduleError(format!(
                "cron->OnCalendar: minute {minute:?} must be a number 0-59"
            ))
        })?,
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
    } else if dom.parse::<u8>().is_ok() {
        format!("*-*-{dom}")
    } else {
        return Err(Error::ScheduleError(format!(
            "cron->OnCalendar: dom {dom:?} must be '*' or a single number"
        )));
    };

    Ok(match weekday {
        Some(wd) => format!("{wd} {date_part} {time}"),
        None => format!("{date_part} {time}"),
    })
}

/// Render a `.service` unit running the restic/borg backup command with
/// `Type=oneshot`, the passphrase delivered via `RESTIC_PASSWORD_FILE` /
/// `BORG_PASSCOMMAND` from a root-owned file — never as a CLI flag.
pub fn render_service_unit(spec: &BackupSpec) -> String {
    let mut s = String::new();
    s.push_str("[Unit]\n");
    let _ = writeln!(s, "Description=toride backup job: {}", spec.name);
    s.push_str("Documentation=https://restic.readthedocs.io\n");
    s.push_str("Wants=network-online.target\n");
    s.push_str("After=network-online.target\n\n");

    s.push_str("[Service]\n");
    s.push_str("Type=oneshot\n");

    let exec = exec_start(spec);
    let _ = writeln!(s, "ExecStart={exec}");

    s.push_str("PrivateTmp=true\n");

    if spec.password_command.is_some() {
        let pw_file = password_file_path(&spec.name);
        match spec.backend {
            Backend::Restic => {
                let val = quote_env_value(&pw_file.display().to_string());
                let _ = writeln!(s, "Environment=RESTIC_PASSWORD_FILE={val}");
            }
            Backend::Borg => {
                let val = quote_env_value(&format!("cat {}", pw_file.display()));
                let _ = writeln!(s, "Environment=BORG_PASSCOMMAND={val}");
            }
        }
    }

    for (k, v) in &spec.extra_env {
        if !is_valid_env_key(k) {
            tracing::warn!(key = %k, "skipping extra_env with invalid name");
            continue;
        }
        let _ = writeln!(s, "Environment={}={}", k, quote_env_value(v));
    }

    s
}

/// Directory under which per-job password files (root-owned, 0600) are
/// materialized at install time by running the spec's `password_command`.
pub const PASSWORD_FILE_DIR: &str = "/etc/toride-backup";

/// On-disk password-file path for a job; the name is sanitized (see
/// [`unit_names`]) so it cannot leave [`PASSWORD_FILE_DIR`].
pub fn password_file_path(name: &str) -> PathBuf {
    Path::new(PASSWORD_FILE_DIR).join(format!("{}.pw", sanitize_unit_name(name)))
}

fn is_valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn quote_env_value(value: &str) -> String {
    if value.contains('\n') {
        tracing::warn!("extra_env value contains a newline; replaced with placeholder");
        return "<<invalid-newline>>".to_owned();
    }
    let needs_quote = value.is_empty()
        || value
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '\'' | '"' | '\\' | '='));
    if needs_quote {
        // systemd.syntax(7): only `\'`/`\\` escapes apply in single quotes — the
        // POSIX `'\''` splice misparses. https://www.freedesktop.org/software/systemd/man/systemd.syntax.html
        let escaped = value.replace('\\', "\\\\").replace('\'', "\\'");
        format!("'{escaped}'")
    } else {
        value.to_owned()
    }
}

fn exec_start(spec: &BackupSpec) -> String {
    let repo = spec.repository.display().to_string();
    let mut tokens: Vec<String> = Vec::new();
    match spec.backend {
        Backend::Restic => {
            tokens.push("restic".into());
            tokens.push("-r".into());
            tokens.push(repo);
            tokens.push("backup".into());
            for src in &spec.sources {
                tokens.push(src.display().to_string());
            }
            for tag in &spec.tags {
                tokens.push("--tag".into());
                tokens.push(tag.clone());
            }
            for pat in &spec.exclude_patterns {
                tokens.push("--exclude".into());
                tokens.push(pat.clone());
            }
        }
        Backend::Borg => {
            tokens.push("borg".into());
            tokens.push("create".into());
            tokens.push(format!("{repo}::{{now}}"));
            for src in &spec.sources {
                tokens.push(src.display().to_string());
            }
            for pat in &spec.exclude_patterns {
                tokens.push("--exclude".into());
                tokens.push(pat.clone());
            }
        }
    }
    shell_join(&tokens)
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

fn shell_join(tokens: &[String]) -> String {
    tokens
        .iter()
        .map(|t| {
            let needs_quote = t.is_empty()
                || t.chars()
                    .any(|c| c.is_whitespace() || matches!(c, '"' | '\\' | '$' | '`' | '\''));
            if needs_quote {
                let escaped = t
                    .replace('\\', "\\\\")
                    .replace('"', "\\\"")
                    .replace('%', "%%");
                format!("\"{escaped}\"")
            } else if t.contains('%') {
                t.replace('%', "%%")
            } else {
                t.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
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
            "absent unit: `cat` only — is-active must be skipped"
        );
        assert!(!probe.installed);
        assert!(
            !probe.active,
            "short-circuit must keep the absent-unit verdict false"
        );
    }

    #[test]
    fn enumerate_backup_timers_spawn_ceiling() {
        SYSTEMCTL_SPAWNS.with(|c| c.set(0));
        let probes = enumerate_backup_timers();
        let spawns = SYSTEMCTL_SPAWNS.with(std::cell::Cell::get);
        let base = BASE_BACKUP_TIMER_UNITS.len();
        let installed = probes.iter().filter(|p| p.installed).count();
        let ceiling = 1 + base + probes.len() + installed;
        assert!(
            spawns <= ceiling,
            "enumerate spawned {spawns} times, over the structural ceiling {ceiling}"
        );
    }

    use std::collections::HashMap;
    use std::path::PathBuf;

    use crate::spec::{Backend, BackupSpec, Encryption, RetentionPolicy};

    fn sample_restic_spec() -> BackupSpec {
        BackupSpec {
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
        }
    }

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
    fn render_service_unit_has_execstart_without_password_on_cli() {
        let spec = sample_restic_spec();
        let unit = render_service_unit(&spec);
        assert!(unit.contains("ExecStart=restic -r /srv/restic-repo backup"));
        assert!(unit.contains("/home/user/work"));
        assert!(unit.contains("--tag auto"));
        assert!(unit.contains("--exclude *.tmp"));
        assert!(
            !unit.contains("--password"),
            "password must not be a CLI flag: {unit}"
        );
        assert!(
            unit.contains("RESTIC_PASSWORD_FILE=/etc/toride-backup/nightly.pw"),
            "expected RESTIC_PASSWORD_FILE pointing at the materialized file: {unit}"
        );
        assert!(
            !unit.contains("RESTIC_PASSWORD=$(cat"),
            "must not emit the un-expanded $(...) shell form: {unit}"
        );
        assert!(unit.contains("Type=oneshot"));
    }

    #[test]
    fn render_service_unit_borg_uses_create_and_passphrase_env() {
        let mut spec = sample_restic_spec();
        spec.backend = Backend::Borg;
        spec.repository = PathBuf::from("/mnt/borg/repo");
        let unit = render_service_unit(&spec);
        assert!(unit.contains("ExecStart=borg create /mnt/borg/repo::{now}"));
        assert!(
            unit.contains("BORG_PASSCOMMAND='cat /etc/toride-backup/nightly.pw'"),
            "expected quoted BORG_PASSCOMMAND pointing at the materialized file: {unit}"
        );
        assert!(
            !unit.contains("BORG_PASSCOMMAND=cat /etc/toride-backup/nightly.pw"),
            "BORG_PASSCOMMAND value must be quoted, not bare: {unit}"
        );
        assert!(
            !unit.contains("BORG_PASSPHRASE=$(cat"),
            "must not emit the un-expanded $(...) shell form: {unit}"
        );
    }

    fn parse_systemd_env_value(line: &str) -> Option<String> {
        let rest = line.strip_prefix("Environment=")?;
        let eq = rest.find('=')?;
        let mut value = &rest[eq + 1..];

        if value.starts_with('\'') {
            let mut out = String::new();
            let bytes = value.as_bytes();
            let mut i = 1;
            let mut closed = false;
            while i < bytes.len() {
                let c = bytes[i];
                if c == b'\\' && i + 1 < bytes.len() {
                    out.push(bytes[i + 1] as char);
                    i += 2;
                    continue;
                }
                if c == b'\'' {
                    closed = true;
                    break;
                }
                out.push(c as char);
                i += 1;
            }
            return if closed { Some(out) } else { None };
        }

        let trimmed = value.trim_start();
        let end = trimmed
            .find(|c: char| c.is_whitespace())
            .unwrap_or(trimmed.len());
        value = &trimmed[..end];
        Some(value.to_owned())
    }

    #[test]
    fn borg_passcommand_value_is_quoted_and_round_trips() {
        let mut spec = sample_restic_spec();
        spec.backend = Backend::Borg;
        spec.repository = PathBuf::from("/mnt/borg/repo");
        let unit = render_service_unit(&spec);

        let line = unit
            .lines()
            .find(|l| l.starts_with("Environment=BORG_PASSCOMMAND="))
            .expect("rendered unit must contain a BORG_PASSCOMMAND Environment= line");

        let expected_value = format!("cat {}", password_file_path(&spec.name).display());
        let parsed = parse_systemd_env_value(line)
            .expect("BORG_PASSCOMMAND line must be parseable as Environment=KEY=VALUE");

        assert_eq!(
            parsed, expected_value,
            "BORG_PASSCOMMAND value must round-trip to the full `cat <pwfile>`; \
             got {parsed:?} from line {line:?}. \
             An unquoted value would have been split to just `cat`.",
        );
    }

    #[test]
    fn unquoted_passcommand_would_be_split_by_systemd_parser() {
        let parsed =
            parse_systemd_env_value("Environment=BORG_PASSCOMMAND=cat /etc/toride-backup/x.pw")
                .unwrap();
        assert_eq!(
            parsed, "cat",
            "an unquoted space-bearing value must collapse to its first token"
        );
    }

    #[test]
    fn render_service_unit_quotes_and_validates_extra_env() {
        let mut spec = sample_restic_spec();
        spec.extra_env = std::collections::HashMap::from([
            (
                "RESTIC_REPOSITORY".to_owned(),
                "s3:https://host/bkt".to_owned(),
            ),
            ("GOOD_VAR".to_owned(), "has spaces".to_owned()),
            ("bad name".to_owned(), "rejected".to_owned()),
        ]);
        let unit = render_service_unit(&spec);
        assert!(unit.contains("Environment=RESTIC_REPOSITORY=s3:https://host/bkt"));
        assert!(unit.contains("Environment=GOOD_VAR='has spaces'"));
        assert!(
            !unit.contains("bad name"),
            "invalid extra_env key must be skipped: {unit}"
        );
    }

    #[test]
    fn password_file_path_sanitizes_name() {
        assert_eq!(
            password_file_path("nightly"),
            PathBuf::from("/etc/toride-backup/nightly.pw")
        );
        let p = password_file_path("../etc/passwd");
        assert!(p.starts_with("/etc/toride-backup/"));
        assert!(!p.to_string_lossy().contains("/etc/passwd"));
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

    fn restic_backup_command_spec(spec: &BackupSpec, passphrase: &str) -> CommandSpec {
        let mut cmd = CommandSpec::new("restic")
            .arg("-r")
            .arg(spec.repository.display().to_string())
            .arg("backup");
        for src in &spec.sources {
            cmd = cmd.arg(src.display().to_string());
        }
        for tag in &spec.tags {
            cmd = cmd.arg("--tag").arg(tag);
        }
        cmd.env("RESTIC_PASSWORD", passphrase).redact(true)
    }

    #[test]
    fn passphrase_bearing_command_has_redact_true_and_secret_in_env() {
        let spec = sample_restic_spec();
        let cmd = restic_backup_command_spec(&spec, "correct-horse-battery-staple");

        assert!(
            cmd.redact,
            "passphrase-bearing command must set redact(true)"
        );
        assert!(
            cmd.args.iter().all(|a| !a.contains("correct-horse")),
            "passphrase leaked into args: {:?}",
            cmd.args
        );
        assert_eq!(
            cmd.env.iter().find(|(k, _)| k == "RESTIC_PASSWORD"),
            Some(&(
                "RESTIC_PASSWORD".to_owned(),
                "correct-horse-battery-staple".to_owned()
            ))
        );
        assert!(
            !cmd.args
                .iter()
                .any(|a| a == "--password" || a.starts_with("--password=")),
            "--password flag must not appear on the CLI"
        );
    }

    #[test]
    fn exec_start_quotes_paths_with_spaces() {
        let mut spec = sample_restic_spec();
        spec.sources = vec![PathBuf::from("/home/user/my files")];
        let line = exec_start(&spec);
        assert!(line.contains("\"/home/user/my files\""));
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
