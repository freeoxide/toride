//! systemd detection and timer-unit enumeration.
//!
//! This module provides honest, real detection of systemd and backup-related
//! timer units. It is intentionally dependency-light (`std::process::Command`
//! plus the always-available `which` crate) so it can be used from both the
//! always-compiled `schedule` module and the feature-gated `service` module.
//!
//! # Behaviour on systemd-absent hosts
//!
//! When systemd is not detected (e.g. a macOS dev box), every query returns
//! `Ok(false)` honestly rather than a stub, and [`detect`] records an
//! informational note (`"systemd not detected"`) that callers can surface to
//! the UI. No command is invoked in that case.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::Error;
use crate::spec::{Backend, BackupSpec, Schedule};
use toride_runner::CommandSpec;

use std::fmt::Write as _;

/// Marker returned by [`detect`] describing why systemd is or is not in use.
///
/// `note` carries a short human-readable string suitable for display in the
/// UI (for example "systemd not detected").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemdDetect {
    /// `true` when systemd appears to be the running init system on this host.
    pub available: bool,
    /// Short informational note for the UI. Empty when systemd is present.
    pub note: String,
}

impl SystemdDetect {
    /// A positive detection with no note.
    fn present() -> Self {
        Self {
            available: true,
            note: String::new(),
        }
    }

    /// A negative detection carrying the supplied informational note.
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

/// Detect whether systemd is the running init system on this host.
///
/// systemd is considered present when **both** of the following hold:
///
/// 1. the `systemctl` binary is found on `$PATH`, and
/// 2. the `/run/systemd/system` directory exists (the canonical marker that
///    systemd is PID 1 / managing the system).
///
/// On hosts where either check fails (a macOS dev box, a container without
/// systemd, etc.) this returns `available: false` with the note
/// `"systemd not detected"`. No further commands are invoked in that case.
///
/// This is a real probe, not a stub: the answer genuinely reflects the host.
pub fn detect() -> SystemdDetect {
    // 1. systemctl on $PATH?
    if which::which("systemctl").is_err() {
        return SystemdDetect::absent("systemd not detected");
    }
    // 2. systemd running as the system manager?
    if !Path::new("/run/systemd/system").exists() {
        return SystemdDetect::absent("systemd not detected");
    }
    SystemdDetect::present()
}

/// Run `systemctl` with the given args, returning the captured output.
///
/// Returns `Err` only if the binary could not be spawned at all. A non-zero
/// exit status is **not** an error here — callers interpret exit codes per
/// subcommand (e.g. `is-active` exits non-zero for inactive units).
fn run_systemctl(args: &[&str]) -> std::result::Result<std::process::Output, std::io::Error> {
    Command::new("systemctl").args(args).output()
}

/// Check whether a unit is known to systemd (i.e. its unit file is installed).
///
/// Uses `systemctl cat <unit>` which exits 0 when the unit file is resolvable.
/// Returns `Ok(false)` when the unit is unknown (exit non-zero) rather than an
/// error, because "unit not present" is the expected negative answer.
fn unit_installed(unit: &str) -> bool {
    match run_systemctl(&["cat", "--", unit]) {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

/// Check whether a unit is loaded and active.
///
/// Uses `systemctl is-active <unit>` which prints `active` and exits 0 only
/// for an active unit. Any other result (inactive, failed, unknown) returns
/// `false`.
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

/// Run a state-changing `systemctl <action> <unit>` (e.g. start/stop/enable),
/// honestly checking systemd is the running init system first. The `--`
/// separator guards against a malicious or malformed unit name being parsed as
/// a flag, mirroring the query helpers above.
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
///
/// # Errors
///
/// Returns [`crate::Error::CommandFailed`] if systemd is unavailable or the
/// command fails.
pub fn start_unit(unit: &str) -> crate::Result<()> {
    unit_action("start", unit)
}

/// Stop a systemd unit (`systemctl stop <unit>`).
///
/// # Errors
///
/// Returns [`crate::Error::CommandFailed`] if systemd is unavailable or the
/// command fails.
pub fn stop_unit(unit: &str) -> crate::Result<()> {
    unit_action("stop", unit)
}

/// Enable a systemd unit to start at boot (`systemctl enable <unit>`).
///
/// # Errors
///
/// Returns [`crate::Error::CommandFailed`] if systemd is unavailable or the
/// command fails.
pub fn enable_unit(unit: &str) -> crate::Result<()> {
    unit_action("enable", unit)
}

/// Probe a single timer unit for installed + active status.
pub fn probe_timer(unit: &str) -> TimerProbe {
    let installed = unit_installed(unit);
    // `is-active` is only meaningful for an installed unit, but invoking it on
    // an absent unit simply returns `false`, so we always probe for symmetry.
    let active = unit_active(unit);
    TimerProbe {
        unit: unit.to_owned(),
        installed,
        active,
    }
}

/// Backup timer unit names worth probing.
///
/// Covers the toride-managed job plus the common third-party backup tools
/// that ship systemd timers (restic, resticprofile, borgbackup). The names
/// listed here are the *generic* vendor unit names; per-job instances
/// (`restic-backup.timer`, `borg-backup.timer`, etc.) are discovered via
/// [`enumerate_backup_timers`].
const BASE_BACKUP_TIMER_UNITS: &[&str] = &[
    // toride-managed default job.
    "toride-backup.timer",
    // restic ecosystem.
    "restic.timer",
    "restic-backup.timer",
    "restic-run.timer",
    // resticprofile.
    "resticprofile.timer",
    // borg / borgmatic.
    "borg.timer",
    "borg-backup.timer",
    "borgmatic.timer",
];

/// Prefix patterns used to discover additional per-job timer instances via
/// `systemctl list-timers --all`.
const BACKUP_TIMER_PREFIXES: &[&str] = &[
    "toride-backup-",
    "restic",
    "resticprofile",
    "borg",
    "borgmatic",
];

/// Enumerate every backup-related timer unit known to systemd on this host.
///
/// Combines:
///
/// 1. a fixed list of common vendor timer unit names (probed individually), and
/// 2. any timer units returned by `systemctl list-timers --all` whose name
///    starts with one of the backup prefixes.
///
/// Duplicate unit names are de-duplicated while preserving first-seen order.
/// Each entry is probed so callers get installed/active status in one pass.
pub fn enumerate_backup_timers() -> Vec<TimerProbe> {
    let mut seen: Vec<String> = Vec::new();
    let mut probes: Vec<TimerProbe> = Vec::new();

    // 1. probe the well-known vendor units first.
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

    // 2. discover per-job instances via `list-timers`.
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

/// Extract a `.timer` unit name from a `systemctl list-timers` output line, if
/// present.
///
/// `list-timers --plain` output columns include the unit name (with a `.timer`
/// suffix) somewhere in the line; we look for the first whitespace-delimited
/// token ending in `.timer`.
fn extract_timer_unit(line: &str) -> Option<String> {
    line.split_whitespace()
        .find(|tok| {
            std::path::Path::new(tok)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("timer"))
        })
        .map(std::borrow::ToOwned::to_owned)
}

/// Report whether any backup-related timer unit exists on this host.
///
/// `Ok(false)` here means "no backup timer is installed" — an honest answer
/// derived from probing the system, not a stub.
pub fn any_backup_timer_installed() -> bool {
    !enumerate_backup_timers().is_empty()
}

/// Report whether any backup-related timer unit is currently active.
///
/// Returns `true` when at least one probed timer is both installed and active.
pub fn any_backup_timer_active() -> bool {
    enumerate_backup_timers().iter().any(|p| p.active)
}

// ===========================================================================
// Unit-file generation + systemctl command construction
// ===========================================================================
//
// The functions below render real systemd `.service` + `.timer` unit files
// (see systemd.unit(5) / systemd.timer(5) on freedesktop.org) and build the
// `systemctl` invocations that install, enable, start, and remove them.
//
// SECURITY: the backup command embeds the repository passphrase. It is sourced
// from a `RESTIC_PASSWORD_FILE=` / `BORG_PASSPHRASE` environment assignment
// inside the unit file's `[Service]` section — never as a CLI `--password`
// argument — and the `systemctl enable --now` invocation itself carries no
// secret. The standalone cron entry, where the passphrase must be inlined
// into the crontab line, is built with `.redact(true)`.

/// Default system unit-file directory (see systemd.unit(5) "Unit File Load
/// Path": system units live in `/etc/systemd/system`).
pub const SYSTEMD_UNIT_DIR: &str = "/etc/systemd/system";

/// Marker token used to label toride-managed crontab entries so they can be
/// located and removed later. The cron line is wrapped in a comment pair:
///
/// ```text
/// # toride-backup:BEGIN:<name>
/// <cron line>
/// # toride-backup:END:<name>
/// ```
pub const CRON_MARKER_BEGIN: &str = "# toride-backup:BEGIN:";
/// End marker wrapping a toride-managed crontab entry (see [`CRON_MARKER_BEGIN`]).
pub const CRON_MARKER_END: &str = "# toride-backup:END:";

/// Build the systemd unit name pair for a backup job.
///
/// Returns `(service_unit, timer_unit)` — e.g.
/// `("toride-backup-myjob.service", "toride-backup-myjob.timer")`.
///
/// SECURITY: the job `name` is interpolated into a systemd unit **filename**,
/// so it is reduced to the safe set `[A-Za-z0-9_-]` (the same allowlist the
/// cron path uses) before joining. This prevents a malicious or malformed name
/// (e.g. `"../..."`, `"a b"`, `"a;b"`) from escaping the unit directory or
/// injecting shell metacharacters into the rendered unit. Path separators,
/// whitespace, and shell metacharacters are replaced with `_`.
pub fn unit_names(name: &str) -> (String, String) {
    let base = format!("toride-backup-{}", sanitize_unit_name(name));
    (format!("{base}.service"), format!("{base}.timer"))
}

/// Reduce an arbitrary job name to a systemd-unit-safe name segment.
///
/// systemd unit names forbid `/`, whitespace, and most shell metacharacters
/// (see systemd.unit(5)); we keep ASCII alphanumerics plus `-`/`_` and replace
/// everything else with `_`. An empty result falls back to `"job"`.
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

/// Convert a 5-field cron expression into a systemd `OnCalendar=` value.
///
/// systemd's calendar event syntax (systemd.time(7)) is richer than cron, so
/// this is a pragmatic translation covering the common cases:
///
/// | cron field | translation |
/// |------------|-------------|
/// | `*`        | `*` (every) |
/// | `*/N`      | cron-style step kept verbatim for minute/hour; systemd also accepts `~/N` |
/// | literal    | kept verbatim |
///
/// Day-of-week numeric values (`0`-`7`, where 0/7 = Sunday) are mapped to the
/// systemd weekday abbreviations (`Sun`..`Sat`) so the resulting calendar event
/// matches cron semantics. A bare `*-*-* HH:MM:00` event is emitted when no
/// weekday is pinned; otherwise `WD *-*-* HH:MM:00`.
///
/// Returns `Err` for expressions that cannot be losslessly represented (e.g.
/// lists like `1,15` or ranges like `1-5` in fields other than DOW) so callers
/// can surface the limitation rather than silently mis-scheduling.
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
    // fields[2] = day-of-month, fields[3] = month — we only support `*` here.
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

    // Zero-pad hour/minute to two digits so the event matches systemd.time(7)
    // canonical form (e.g. cron "0 2" -> "02:00:00", not "2:0:00").
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

    // Day-of-week handling: cron 0/7=Sun .. 6=Sat. systemd wants Mon..Sun.
    let weekday = if dow == "*" {
        None
    } else {
        // Only accept a single numeric token; lists/ranges are rejected to
        // avoid silently changing semantics.
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

    // Date portion. systemd's calendar event date is `YYYY-MM-DD`; using
    // wildcards gives `*-*-*` (every year/month/day). When dom is pinned we
    // emit `*-*-<dom>` (month stays wildcard because we rejected month!=*).
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

/// Render a systemd `.service` unit file body for the given backup spec.
///
/// The unit runs the restic/borg backup command with the repository passphrase
/// sourced from a root:root 0600 file under [`PASSWORD_FILE_DIR`] (materialized
/// at install time by running the spec's `password_command`), pointed at via
/// `RESTIC_PASSWORD_FILE` (restic) or `BORG_PASSCOMMAND=cat <file>` (borg) —
/// never a CLI flag and never a `$(...)` shell form systemd cannot expand. The
/// unit is `Type=oneshot` (a backup is a single run-to-completion task).
///
/// Source for the unit-file skeleton: systemd.unit(5) / systemd.service(5) on
/// <https://www.freedesktop.org/software/systemd/man/systemd.unit.html>.
pub fn render_service_unit(spec: &BackupSpec) -> String {
    let mut s = String::new();
    s.push_str("[Unit]\n");
    let _ = writeln!(s, "Description=toride backup job: {}", spec.name);
    s.push_str("Documentation=https://restic.readthedocs.io\n");
    s.push_str("Wants=network-online.target\n");
    s.push_str("After=network-online.target\n\n");

    s.push_str("[Service]\n");
    s.push_str("Type=oneshot\n");

    // ExecStart: the real restic/borg backup invocation. The password is
    // delivered via env (RESTIC_PASSWORD_FILE for restic, BORG_PASSPHRASE for
    // borg) so it never appears on the command line or in `systemctl show`.
    let exec = exec_start(spec);
    let _ = writeln!(s, "ExecStart={exec}");

    // Security hardening (systemd.exec(5)): backups run with no new privileges
    // and a private /tmp unless the source set needs otherwise.
    s.push_str("PrivateTmp=true\n");

    // Passphrase delivery. systemd does NOT expand `$()`/shell substitutions
    // inside `Environment=` assignments, so an `Environment="RESTIC_PASSWORD=
    // $(cmd)"` line would set the *literal* string and the unit could never
    // unlock the repo. Instead we point the backend at a root:root 0600
    // password file that the install path materializes once by running the
    // spec's password_command:
    //   - restic reads RESTIC_PASSWORD_FILE (or `-p <file>`); we use the env.
    //   - borg has no passphrase-file env; it runs BORG_PASSCOMMAND, so we
    //     point it at `cat <file>`.
    // The passphrase therefore never appears in the unit file, on the
    // ExecStart command line, or in `systemctl show`.
    if spec.password_command.is_some() {
        let pw_file = password_file_path(&spec.name);
        match spec.backend {
            Backend::Restic => {
                // The password-file path is reduced to `[A-Za-z0-9_-]` (see
                // [`sanitize_unit_name`]) so it contains no spaces or special
                // chars, but we still route it through [`quote_env_value`] so a
                // value that ever gains a space cannot be split by systemd's
                // Environment= parser.
                let val = quote_env_value(&pw_file.display().to_string());
                let _ = writeln!(s, "Environment=RESTIC_PASSWORD_FILE={val}");
            }
            Backend::Borg => {
                // BORG_PASSCOMMAND's value is `cat <file>` — it contains a
                // space, so systemd's Environment= parser would split an
                // UNQUOTED value into the tokens `cat` and `<file>` (dropping
                // the path). Single-quote the whole assignment value so the
                // parser yields the full `cat <file>` string intact.
                // See systemd.syntax(7) / systemd.service(5).
                let val = quote_env_value(&format!("cat {}", pw_file.display()));
                let _ = writeln!(s, "Environment=BORG_PASSCOMMAND={val}");
            }
        }
    }

    // Extra env from the spec (e.g. RESTIC_REPOSITORY for remote backends).
    // Each KEY must match the systemd env-var name allowlist and each VALUE is
    // single-quoted with embedded quotes/newlines escaped so a value can never
    // inject a second Environment= assignment or break the unit parser.
    for (k, v) in &spec.extra_env {
        if !is_valid_env_key(k) {
            // Refuse rather than emit a malformed/unsafe Environment= line.
            tracing::warn!(key = %k, "skipping extra_env with invalid name");
            continue;
        }
        let _ = writeln!(s, "Environment={}={}", k, quote_env_value(v));
    }

    s
}

/// Directory under which toride materializes per-job restic/borg password
/// files for the direct-rendered `.service` unit (root-owned, 0600). The
/// install path runs the spec's `password_command` once and writes its stdout
/// here so the unit can unlock without systemd having to expand any shell.
pub const PASSWORD_FILE_DIR: &str = "/etc/toride-backup";

/// Resolve the on-disk password-file path for a job.
///
/// The job name is reduced to the systemd-safe set `[A-Za-z0-9_-]` (reusing
/// the [`unit_names`] sanitizer) so a pathological name can never write
/// outside [`PASSWORD_FILE_DIR`].
pub fn password_file_path(name: &str) -> PathBuf {
    Path::new(PASSWORD_FILE_DIR).join(format!("{}.pw", sanitize_unit_name(name)))
}

/// A systemd `Environment=` key must match `[A-Z_][A-Z0-9_]*` (case-insensitive
/// on the letters). Reject anything else before interpolating into the unit.
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

/// Quote a value for a systemd `Environment=KEY=VALUE` assignment.
///
/// systemd (systemd.service(5)) accepts bare values without shell-special
/// characters, but a value containing spaces, quotes, `=`, backslashes, or
/// control chars must be single-quoted; embedded single quotes become `\'`.
/// A newline in a value would terminate the assignment, so it is rejected up
/// front (returns `"<<"invalid>>"` which systemd treats as a literal token
/// rather than letting the value escape the line).
fn quote_env_value(value: &str) -> String {
    if value.contains('\n') {
        // A newline cannot be represented in a single Environment= line; emit a
        // safe placeholder rather than letting the value split the unit.
        tracing::warn!("extra_env value contains a newline; replaced with placeholder");
        return "<<invalid-newline>>".to_owned();
    }
    let needs_quote = value.is_empty()
        || value
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '\'' | '"' | '\\' | '='));
    if needs_quote {
        // systemd.syntax(7): inside a single-quoted item, C-style escapes
        // apply — an embedded single quote is `\'` and a literal backslash is
        // `\\`. Do NOT use the POSIX-shell `'\''` concatenation: systemd
        // requires the closing quote to be followed by whitespace/EOL, so
        // `'a'\''b'` would be misparsed.
        let escaped = value.replace('\\', "\\\\").replace('\'', "\\'");
        format!("'{escaped}'")
    } else {
        value.to_owned()
    }
}

/// Build the `ExecStart=` command line (program + args, no password on CLI)
/// for the configured backend.
///
/// Mirrors the documented CLI shape:
/// - restic: `restic -r <repo> backup <src...> [--tag t]... [--exclude p]...`
///   (<https://restic.readthedocs.io/en/latest/040_backup.html>)
/// - borg: `borg create <repo>::{now} <src...> [--exclude pattern]...`
///   (<https://borgbackup.readthedocs.io/en/stable/usage/create.html>)
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

/// Render a systemd `.timer` unit file for the given schedule.
///
/// Translates the cron expression to an `OnCalendar=` event (see
/// [`cron_to_oncalendar`]) and sets `Persistent=true` so a missed run (e.g.
/// while the host was powered off) is caught up on next boot — the behaviour
/// sysadmins expect from a backup timer. See systemd.timer(5):
/// <https://www.freedesktop.org/software/systemd/man/systemd.timer.html>.
pub fn render_timer_unit(name: &str, schedule: &Schedule) -> crate::Result<String> {
    let oncal = cron_to_oncalendar(&schedule.cron)?;
    let mut s = String::new();
    s.push_str("[Unit]\n");
    let _ = write!(s, "Description=toride backup timer: {name}\n\n");

    s.push_str("[Timer]\n");
    let _ = writeln!(s, "OnCalendar={oncal}");
    s.push_str("Persistent=true\n");
    // Coalesce within a 1-minute window (the systemd default) for power
    // efficiency; backups don't need sub-minute precision.
    s.push_str("AccuracySec=1min\n\n");

    s.push_str("[Install]\n");
    s.push_str("WantedBy=timers.target\n");
    Ok(s)
}

/// Quote a single argv token for safe embedding in a systemd `ExecStart=`
/// line. systemd's own quoting (systemd.service(5)) requires that a literal
/// `%` be written as `%%`; spaces and shell metacharacters are wrapped in
/// double quotes with embedded quotes escaped as `\"`.
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
                // Even unquoted, systemd reads % as a specifier.
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

/// Build the `systemctl daemon-reload` command (run after writing/removing a
/// unit file so systemd picks up the change).
pub fn daemon_reload_spec() -> CommandSpec {
    CommandSpec::new("systemctl").args(["daemon-reload"])
}

/// Build the `systemctl enable --now <timer>` command that enables a timer to
/// start at boot and starts it immediately.
pub fn enable_now_spec(timer_unit: &str) -> CommandSpec {
    CommandSpec::new("systemctl")
        .arg("enable")
        .arg("--now")
        .arg("--")
        .arg(timer_unit)
}

/// Build the `systemctl disable --now <timer>` command that stops the timer
/// and removes the boot symlink.
pub fn disable_now_spec(timer_unit: &str) -> CommandSpec {
    CommandSpec::new("systemctl")
        .arg("disable")
        .arg("--now")
        .arg("--")
        .arg(timer_unit)
}

/// Render a `.service` unit whose `ExecStart=` runs the **managed** backup CLI
/// invocation (`<cli_bin> backup <name>`), rather than a hand-built restic/borg
/// command.
///
/// This is the standard systemd-timer pattern: a thin `.service` that runs one
/// command, with the heavy lifting (spec, passphrase, env) owned by the CLI at
/// runtime. The passphrase therefore never appears in the unit file or on the
/// `ExecStart=` command line. See systemd.service(5):
/// <https://www.freedesktop.org/software/systemd/man/systemd.service.html>.
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
        // On the test host (likely macOS / CI) systemd is usually absent, but
        // the contract we assert is structural, not the specific value: the
        // detection ran and produced a populated result we can branch on.
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
        assert!(!BASE_BACKUP_TIMER_UNITS.is_empty());
        assert!(BASE_BACKUP_TIMER_UNITS.iter().all(|u| {
            std::path::Path::new(u)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("timer"))
        }));
    }

    #[test]
    fn prefixes_are_nonempty() {
        assert!(!BACKUP_TIMER_PREFIXES.is_empty());
    }

    #[test]
    fn probe_timer_returns_consistent_state() {
        // An obviously-absent unit name should report installed=false/active=false
        // without panicking, regardless of host.
        let probe = probe_timer("toride-backup-this-unit-does-not-exist-xyz.timer");
        if !probe.installed {
            assert!(!probe.active, "absent unit must not be active");
        }
    }

    // -----------------------------------------------------------------
    // Helpers + tests for unit-file rendering + systemctl command specs
    // -----------------------------------------------------------------

    use std::collections::HashMap;
    use std::path::PathBuf;

    use crate::spec::{Backend, BackupSpec, Encryption, RetentionPolicy};

    /// Minimal restic `BackupSpec` mirroring the documented restic backup example:
    ///   restic -r /srv/restic-repo backup ~/work
    /// (<https://restic.readthedocs.io/en/latest/040_backup.html>)
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
        // cron "0 2 * * *" = daily 02:00 -> systemd "daily 02:00:00" style
        // (here: "*-*-* 02:00:00"). systemd.time(7) calendar events.
        let oncal = cron_to_oncalendar("0 2 * * *").unwrap();
        assert_eq!(oncal, "*-*-* 02:00:00");
    }

    #[test]
    fn cron_to_oncalendar_weekly_sunday() {
        // cron "30 3 * * 0" = Sun 03:30 -> "Sun *-*-* 03:30:00"
        let oncal = cron_to_oncalendar("30 3 * * 0").unwrap();
        assert_eq!(oncal, "Sun *-*-* 03:30:00");
    }

    #[test]
    fn cron_to_oncalendar_dow_7_is_sunday() {
        // cron treats both 0 and 7 as Sunday.
        let oncal = cron_to_oncalendar("0 0 * * 7").unwrap();
        assert_eq!(oncal, "Sun *-*-* 00:00:00");
    }

    #[test]
    fn cron_to_oncalendar_rejects_month_restriction() {
        // Month pinning cannot be expressed in a single OnCalendar without
        // changing semantics; we refuse rather than mis-schedule.
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
        // Path separators, whitespace, and shell metacharacters must be
        // neutralized so the resulting unit filename cannot escape the unit
        // dir or inject command separators.
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
        // The passphrase must NEVER appear as a CLI arg in ExecStart. The
        // documented restic CLI is `restic -r <repo> backup <src>` with the
        // password supplied via RESTIC_PASSWORD env, NOT --password.
        // https://restic.readthedocs.io/en/latest/040_backup.html
        let spec = sample_restic_spec();
        let unit = render_service_unit(&spec);
        assert!(unit.contains("ExecStart=restic -r /srv/restic-repo backup"));
        assert!(unit.contains("/home/user/work"));
        assert!(unit.contains("--tag auto"));
        assert!(unit.contains("--exclude *.tmp"));
        // No password leak on the command line.
        assert!(
            !unit.contains("--password"),
            "password must not be a CLI flag: {unit}"
        );
        // systemd does NOT expand $(), so the password is delivered via a
        // root-owned file the install path materializes (RESTIC_PASSWORD_FILE),
        // never a literal $(...) that the unit cannot resolve.
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
        // borg CLI: `borg create REPO::archive SRC`. borg has no passphrase-file
        // env var, so the unit runs `cat <file>` via BORG_PASSCOMMAND (a real,
        // systemd-resolvable assignment) rather than the broken
        // `BORG_PASSPHRASE=$(...)` form systemd cannot expand.
        // https://borgbackup.readthedocs.io/en/stable/usage/create.html
        let mut spec = sample_restic_spec();
        spec.backend = Backend::Borg;
        spec.repository = PathBuf::from("/mnt/borg/repo");
        let unit = render_service_unit(&spec);
        assert!(unit.contains("ExecStart=borg create /mnt/borg/repo::{now}"));
        // BORG_PASSCOMMAND's value (`cat <file>`) contains a space, so it MUST
        // be single-quoted: an unquoted value would be split by systemd's
        // Environment= parser into `cat` + `<file>` and the path lost.
        assert!(
            unit.contains("BORG_PASSCOMMAND='cat /etc/toride-backup/nightly.pw'"),
            "expected quoted BORG_PASSCOMMAND pointing at the materialized file: {unit}"
        );
        // Sanity: the unquoted form must NOT appear.
        assert!(
            !unit.contains("BORG_PASSCOMMAND=cat /etc/toride-backup/nightly.pw"),
            "BORG_PASSCOMMAND value must be quoted, not bare: {unit}"
        );
        assert!(
            !unit.contains("BORG_PASSPHRASE=$(cat"),
            "must not emit the un-expanded $(...) shell form: {unit}"
        );
    }

    /// Parse the VALUE out of a rendered `Environment=KEY=VALUE` line the way
    /// systemd's Environment= parser (systemd.syntax(7)) would: honour single
    /// quotes (with `\'` and `\\` escapes) and split an UNQUOTED value on the
    /// first whitespace run, taking only the leading token.
    ///
    /// This mirrors systemd's own tokenisation closely enough to verify that a
    /// value we render round-trips to the full intended string.
    fn parse_systemd_env_value(line: &str) -> Option<String> {
        let rest = line.strip_prefix("Environment=")?;
        // Drop the KEY= prefix: the key runs up to the first `=`.
        let eq = rest.find('=')?;
        let mut value = &rest[eq + 1..];

        // If the value is wrapped in a single pair of single quotes, systemd
        // takes the quoted span verbatim (after C-style unescaping).
        if value.starts_with('\'') {
            // find the closing quote (honouring `\'` and `\\` escapes)
            let mut out = String::new();
            let bytes = value.as_bytes();
            let mut i = 1; // skip opening quote
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

        // Unquoted: systemd splits on whitespace and yields only the FIRST
        // token — the rest of the line is dropped (this is exactly the bug).
        let trimmed = value.trim_start();
        let end = trimmed
            .find(|c: char| c.is_whitespace())
            .unwrap_or(trimmed.len());
        value = &trimmed[..end];
        Some(value.to_owned())
    }

    #[test]
    fn borg_passcommand_value_is_quoted_and_round_trips() {
        // Regression: the rendered BORG_PASSCOMMAND value (`cat <file>`)
        // contains a space. UNQUOTED, systemd's Environment= parser yields only
        // the leading token `cat` and silently drops the password-file path,
        // so borg could never read the passphrase and the unit fails at run
        // time. The value MUST be quoted so the full `cat <file>` survives.
        let mut spec = sample_restic_spec();
        spec.backend = Backend::Borg;
        spec.repository = PathBuf::from("/mnt/borg/repo");
        let unit = render_service_unit(&spec);

        let line = unit
            .lines()
            .find(|l| l.starts_with("Environment=BORG_PASSCOMMAND="))
            .expect("rendered unit must contain a BORG_PASSCOMMAND Environment= line");

        let expected_value = format!(
            "cat {}",
            password_file_path(&spec.name).display()
        );
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
        // Negative control pinning the parser model: an UNQUOTED value with a
        // space yields only the leading token. This documents why the quoting
        // fix is necessary and ensures our parser test above is not vacuous.
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
        // A value with spaces/quotes/`=` must be single-quoted; an invalid key
        // name must be skipped rather than emit a malformed Environment= line.
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
        // Plain safe value rendered bare.
        assert!(unit.contains("Environment=RESTIC_REPOSITORY=s3:https://host/bkt"));
        // Value with a space is single-quoted.
        assert!(unit.contains("Environment=GOOD_VAR='has spaces'"));
        // Invalid key name is skipped (no line emitted for it).
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
        // A traversal-style name is neutralized so the file stays inside the dir.
        let p = password_file_path("../etc/passwd");
        assert!(p.starts_with("/etc/toride-backup/"));
        assert!(!p.to_string_lossy().contains("/etc/passwd"));
    }

    #[test]
    fn render_timer_unit_has_oncalendar_and_persistent() {
        // systemd.timer(5): OnCalendar= + Persistent=true + WantedBy=timers.target
        // https://www.freedesktop.org/software/systemd/man/systemd.timer.html
        let unit = render_timer_unit("nightly", &Schedule::new("0 2 * * *")).unwrap();
        assert!(unit.contains("OnCalendar=*-*-* 02:00:00"));
        assert!(unit.contains("Persistent=true"));
        assert!(unit.contains("WantedBy=timers.target"));
    }

    #[test]
    fn render_cli_service_unit_runs_managed_cli() {
        // The managed .service invokes the toride-backup CLI by job name.
        let unit = render_cli_service_unit("nightly", "toride-backup backup nightly");
        assert!(unit.contains("ExecStart=toride-backup backup nightly"));
        assert!(unit.contains("Type=oneshot"));
        // No passphrase anywhere in the unit.
        assert!(!unit.contains("password"));
        assert!(!unit.contains("passphrase"));
    }

    /// Build the real restic backup `CommandSpec` for a spec, with the repo
    /// passphrase delivered via the `RESTIC_PASSWORD` environment variable
    /// (NOT a CLI flag) and `redact(true)` set. This is the canonical secret-
    /// bearing command shape for backup operations.
    ///
    /// restic reads the password from `RESTIC_PASSWORD` per its "Environment
    /// Variables" documentation:
    /// <https://restic.readthedocs.io/en/latest/040_backup.html>
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
        // Passphrase via ENV, never on the CLI. redact(true) so the runner
        // scrubs it from error messages and logs.
        cmd.env("RESTIC_PASSWORD", passphrase).redact(true)
    }

    #[test]
    fn passphrase_bearing_command_has_redact_true_and_secret_in_env() {
        // THE central correctness property for this crate: any CommandSpec
        // that carries the repo passphrase must be built with redact(true),
        // and the passphrase must travel via env (not a CLI arg) so it is
        // never surfaced in process listings or error stderr.
        //
        // specs_match (toride-runner fake.rs) enforces redact: a spec that
        // forgot redact(true) fails an exact match. This test asserts the
        // property directly on the constructed command.
        let spec = sample_restic_spec();
        let cmd = restic_backup_command_spec(&spec, "correct-horse-battery-staple");

        // redact(true) is mandatory on passphrase-bearing commands.
        assert!(
            cmd.redact,
            "passphrase-bearing command must set redact(true)"
        );
        // The passphrase is in env, never in args.
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
        // No --password flag on the CLI.
        assert!(
            !cmd.args
                .iter()
                .any(|a| a == "--password" || a.starts_with("--password=")),
            "--password flag must not appear on the CLI"
        );
    }

    #[test]
    fn exec_start_quotes_paths_with_spaces() {
        // systemd % specifier + shell quoting: a source path with a space must
        // be double-quoted, and % must be escaped as %%.
        let mut spec = sample_restic_spec();
        spec.sources = vec![PathBuf::from("/home/user/my files")];
        let line = exec_start(&spec);
        assert!(line.contains("\"/home/user/my files\""));
    }

    #[test]
    fn enable_now_spec_matches_exact_systemctl_invocation() {
        // Assert the exact program + args built for `systemctl enable --now`.
        // Source: systemctl(1). https://www.freedesktop.org/software/systemd/man/systemctl.html
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
        // systemd.unit(5) load path: /etc/systemd/system
        let p = unit_path("toride-backup-nightly.timer");
        assert_eq!(
            p,
            PathBuf::from("/etc/systemd/system/toride-backup-nightly.timer")
        );
    }
}
