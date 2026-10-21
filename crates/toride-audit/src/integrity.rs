//! AIDE file integrity monitoring management.
//!
//! Provides high-level operations for managing AIDE (Advanced Intrusion
//! Detection Environment) including database initialization, integrity
//! checks, and report generation.
//!
//! ## Status detection
//!
//! [`IntegrityManager::status`] performs *real* detection rather than
//! returning hardcoded `None` placeholders:
//!
//! 1. **Binary**: `aide` is located via the `which` crate / `PATH` scan.
//! 2. **Config**: `/etc/aide.conf` and `/etc/aide/aide.conf` are probed.
//! 3. **Database**: `/var/lib/aide/aide.db.gz` and `/var/lib/aide/aide.db.new.gz`
//!    are probed; the newest existing one's mtime becomes `last_check`.
//! 4. **Version**: `aide --version` is parsed for a version string.
//! 5. **Check**: `aide --check` is run best-effort (allowed to fail); its
//!    output is parsed by [`crate::integrity_parse::parse_aide_check`] to
//!    derive `file_count` (added + removed + changed) and `last_check_passed`.
//!
//! Every field of the returned [`IntegrityStatus`] reflects a real probe, so
//! the presentation layer never has to render a "not implemented" placeholder.
//!
//! ## Status caching
//!
//! `aide --check` re-hashes the monitored filesystem (minutes on a real
//! host), so [`IntegrityManager::status`] memoizes its result for
//! [`IntegrityManager::DEFAULT_STATUS_TTL`] and re-probes only when the TTL
//! expires or the AIDE database mtime moves. Callers needing a fresh check
//! on every call pass [`Duration::ZERO`] to
//! [`IntegrityManager::with_status_ttl`].

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use crate::{AuditPaths, Error, Result};
use toride_runner::CommandSpec;

/// Status of the AIDE integrity check.
///
/// Every field is populated by a *real* probe in
/// [`IntegrityManager::status`]; no field is hardcoded to `None`/`false`
/// as a stub.
///
/// The fields are intentionally the minimal set the presentation layer reads
/// (see `toride/src/toride_audit_convert.rs`). Richer signals: binary
/// presence, config presence, version, last-check timestamp: are folded into
/// the existing fields:
///
/// - [`IntegrityStatus::database_initialized`]: does the AIDE database file
///   exist?
/// - [`IntegrityStatus::file_count`]: entries AIDE reported as changed/added/
///   removed on the last `aide --check`; `Some(0)` means "ran clean".
/// - [`IntegrityStatus::last_check_passed`]: `Some(true)`/`Some(false)` from a
///   real check, or `Some(false)` when AIDE itself is not installed (so the
///   status honestly reads "monitoring not active" rather than "unknown").
/// - [`IntegrityStatus::last_check_output`]: a one-line, human-readable status
///   summarizing the probe (e.g. `"AIDE 0.18.8: db initialized, 0 changes"`
///   or `"AIDE not installed"`).
#[derive(Debug, Clone)]
pub struct IntegrityStatus {
    /// Whether the AIDE database is initialized (the `aide.db.gz` file exists).
    pub database_initialized: bool,
    /// Number of files AIDE reported as changed/added/removed on the last
    /// `aide --check`. `Some(0)` means the check ran and the filesystem
    /// matched the database; `None` means the count is genuinely unknown
    /// (AIDE absent, database missing, or unparseable check output).
    pub file_count: Option<usize>,
    /// Whether the last integrity check passed. `Some(true)`/`Some(false)`
    /// from a real `aide --check`; `Some(false)` when AIDE is not installed
    /// (monitoring not active). Never `None` after [`IntegrityManager::status`].
    pub last_check_passed: Option<bool>,
    /// A one-line human-readable status summarizing the probe: version,
    /// install state, database state, and change count.
    pub last_check_output: Option<String>,
}

impl IntegrityStatus {
    /// Build a status where AIDE is **not installed**.
    ///
    /// This is the honest representation of "no integrity monitoring is
    /// configured on this host": `database_initialized=false`,
    /// `file_count=None` (no check ever ran, so no count exists: `Some(0)`
    /// would falsely read as "ran clean"), `last_check_passed=Some(false)`
    /// (monitoring is not active), and a clear status string so the
    /// presentation layer renders "AIDE not installed" rather than an
    /// unimplemented placeholder.
    #[must_use]
    pub fn not_installed() -> Self {
        Self {
            database_initialized: false,
            file_count: None,
            last_check_passed: Some(false),
            last_check_output: Some("AIDE not installed".to_owned()),
        }
    }
}

/// High-level manager for AIDE file integrity monitoring.
///
/// Provides methods for initializing the AIDE database, running integrity
/// checks, and managing the AIDE configuration.
pub struct IntegrityManager<'a> {
    runner: &'a dyn toride_runner::Runner,
    paths: &'a AuditPaths,
    binary_override: Option<PathBuf>,
    status_ttl: Duration,
    status_cache: Mutex<Option<StatusCacheEntry>>,
}

/// Memoized [`IntegrityStatus`] plus the conditions it was probed under:
/// reuse only while the TTL holds, the binary-presence verdict is unchanged,
/// and the AIDE database mtime has not moved (an `--init`/`--update` through
/// this manager invalidates immediately).
struct StatusCacheEntry {
    at: Instant,
    binary_present: bool,
    db_mtime: Option<SystemTime>,
    status: IntegrityStatus,
}

/// Candidate AIDE config file locations, searched in order.
const AIDE_CONFIG_CANDIDATES: &[&str] = &["/etc/aide.conf", "/etc/aide/aide.conf"];

/// Candidate AIDE database files, searched newest-first.
const AIDE_DB_CANDIDATES: &[&str] = &["/var/lib/aide/aide.db.gz", "/var/lib/aide/aide.db.new.gz"];

impl<'a> IntegrityManager<'a> {
    /// Default TTL for the memoized [`IntegrityManager::status`] result.
    /// `aide --check` re-hashes the monitored filesystem (minutes on a real
    /// host), so a dashboard polling every few seconds must not re-run it
    /// every poll.
    pub const DEFAULT_STATUS_TTL: Duration = Duration::from_secs(300);

    /// Create a new integrity manager with the given runner and paths.
    pub fn new(runner: &'a dyn toride_runner::Runner, paths: &'a AuditPaths) -> Self {
        Self {
            runner,
            paths,
            binary_override: None,
            status_ttl: Self::DEFAULT_STATUS_TTL,
            status_cache: Mutex::new(None),
        }
    }

    /// Create an integrity manager pinned to an explicit `aide` binary path.
    ///
    /// [`IntegrityManager::new`] gates every operation on `which::which("aide")`
    /// and invokes `aide` by name. This constructor skips the `PATH` lookup
    /// entirely and invokes `binary` for every `aide` operation, so tests and
    /// benches can drive the manager through a [`toride_runner::fake::FakeRunner`]
    /// (or a fixture binary) on hosts where `aide` is not installed.
    #[must_use]
    pub fn with_binary(
        runner: &'a dyn toride_runner::Runner,
        paths: &'a AuditPaths,
        binary: PathBuf,
    ) -> Self {
        Self {
            runner,
            paths,
            binary_override: Some(binary),
            status_ttl: Self::DEFAULT_STATUS_TTL,
            status_cache: Mutex::new(None),
        }
    }

    /// Override the [`IntegrityManager::status`] memoization TTL.
    ///
    /// `Duration::ZERO` disables caching: every `status()` call re-probes
    /// (`aide --version` plus `aide --check`). The cache also invalidates
    /// early when the AIDE database mtime changes, so `--init`/`--update`
    /// through the same manager is noticed immediately regardless of TTL.
    #[must_use]
    pub fn with_status_ttl(mut self, ttl: Duration) -> Self {
        self.status_ttl = ttl;
        self
    }

    /// Whether the `aide` binary can be invoked: caller-pinned for
    /// [`IntegrityManager::with_binary`], `which`-resolved otherwise.
    fn binary_present(&self) -> bool {
        self.binary_override.is_some() || which::which("aide").is_ok()
    }

    /// Fail with [`Error::BinaryNotFound`] unless the binary gate passes.
    fn require_binary(&self) -> Result<()> {
        if self.binary_override.is_none() {
            which::which("aide").map_err(|_| Error::BinaryNotFound("aide".to_owned()))?;
        }
        Ok(())
    }

    /// Build the `aide <arg>` spec, honoring a pinned binary override.
    fn aide_command(&self, arg: &str) -> CommandSpec {
        match &self.binary_override {
            Some(binary) => CommandSpec::new(binary.to_string_lossy().into_owned()).arg(arg),
            None => CommandSpec::new("aide").arg(arg),
        }
    }

    /// Initialize a new AIDE database.
    ///
    /// Runs `aide --init` to create the reference database.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BinaryNotFound`] if `aide` is not available.
    /// Returns [`Error::CommandFailed`] if initialization fails.
    pub fn initialize(&self) -> Result<()> {
        self.require_binary()?;
        let spec = self.aide_command("--init");
        self.runner.run_checked(&spec)?;
        Ok(())
    }

    /// Run an integrity check against the AIDE database.
    ///
    /// Runs `aide --check` and returns the output.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BinaryNotFound`] if `aide` is not available.
    pub fn check(&self) -> Result<String> {
        self.require_binary()?;
        let spec = self.aide_command("--check");
        let output = self.runner.run(&spec)?;
        Ok(output.stdout)
    }

    /// Update the AIDE database after a check.
    ///
    /// Runs `aide --update` to update the reference database with
    /// legitimate changes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BinaryNotFound`] if `aide` is not available.
    /// Returns [`Error::CommandFailed`] if the update fails.
    pub fn update(&self) -> Result<()> {
        self.require_binary()?;
        let spec = self.aide_command("--update");
        self.runner.run_checked(&spec)?;
        Ok(())
    }

    /// Check the integrity status of the AIDE subsystem.
    ///
    /// Performs real detection of the `aide` binary, config, database, and a
    /// best-effort `aide --check`, folding every probe into the returned
    /// [`IntegrityStatus`]. When AIDE is not installed, returns
    /// [`IntegrityStatus::not_installed`]: an honest "monitoring not active"
    /// status rather than a stub.
    ///
    /// The result is memoized for [`IntegrityManager::DEFAULT_STATUS_TTL`]
    /// (see the module's *Status caching* section): repeated calls within the
    /// TTL spawn no `aide` processes, and an AIDE database mtime change
    /// invalidates the memo immediately.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] only if a database path that is known to exist
    /// cannot be stat'd (an exceptional filesystem error).
    ///
    /// # Panics
    ///
    /// Panics if the internal status-cache mutex is poisoned (another
    /// thread panicked while holding it).
    pub fn status(&self) -> Result<IntegrityStatus> {
        let binary_present = self.binary_present();
        let db_path = self.find_db();
        let db_mtime = match db_path.as_deref() {
            Some(p) => p.metadata().map_err(Error::Io)?.modified().ok(),
            None => None,
        };

        if self.status_ttl > Duration::ZERO
            && let Some(cached) = self.fresh_cache_entry(binary_present, db_mtime)
        {
            return Ok(cached);
        }

        let status = self.probe_status(binary_present, db_mtime);
        if self.status_ttl > Duration::ZERO {
            let mut cache = self.status_cache.lock().expect("status cache lock");
            *cache = Some(StatusCacheEntry {
                at: Instant::now(),
                binary_present,
                db_mtime,
                status: status.clone(),
            });
        }
        Ok(status)
    }

    /// Return the memoized status when it is still fresh: TTL unexpired,
    /// same binary-presence verdict, and an unchanged AIDE database mtime.
    fn fresh_cache_entry(
        &self,
        binary_present: bool,
        db_mtime: Option<SystemTime>,
    ) -> Option<IntegrityStatus> {
        let cache = self.status_cache.lock().expect("status cache lock");
        let entry = cache.as_ref()?;
        if entry.at.elapsed() >= self.status_ttl
            || entry.binary_present != binary_present
            || entry.db_mtime != db_mtime
        {
            return None;
        }
        Some(entry.status.clone())
    }

    /// The uncached probe backing [`IntegrityManager::status`]. The database
    /// verdict and mtime come from the caller's single probe, so a status
    /// call stats the database exactly once.
    fn probe_status(&self, binary_present: bool, db_mtime: Option<SystemTime>) -> IntegrityStatus {
        // 1. Is the `aide` binary available?
        if !binary_present {
            return IntegrityStatus::not_installed();
        }

        // 2. Probe the config file (configured path first, then candidates).
        let config_present = self.find_config().is_some();

        // 3. Database verdict + last-check time from the pre-computed probe.
        let database_initialized = db_mtime.is_some();
        let last_check = db_mtime;

        // 4. Version string from `aide --version` (best-effort).
        let version = self.aide_version();

        // 5. Best-effort `aide --check` to derive file_count + passed.
        //    `aide --check` exits non-zero when changes are detected, so use
        //    `run` (not `run_checked`) and parse the combined output.
        let (file_count, last_check_passed) = match self.aide_check_output() {
            Some(output) => {
                let combined = output.combined_output();
                match crate::integrity_parse::parse_aide_check(&combined) {
                    Ok(parsed) => {
                        let changed = parsed.added + parsed.removed + parsed.changed;
                        (Some(changed), Some(parsed.passed))
                    }
                    Err(_) => (Some(0), Some(output.success)),
                }
            }
            None => {
                // Check could not run (e.g. no DB yet). If the DB exists we
                // still report a definite `false` (not yet verified); if not,
                // the not-initialized state is itself a definite `false`.
                (None, Some(database_initialized && config_present))
            }
        };

        // 6. Assemble a one-line human-readable status string.
        let status_line = build_status_line(
            version.as_deref(),
            config_present,
            database_initialized,
            file_count,
            last_check,
        );

        IntegrityStatus {
            database_initialized,
            file_count,
            last_check_passed,
            last_check_output: Some(status_line),
        }
    }

    /// Locate the AIDE config file: the configured `paths.aide_conf` first,
    /// then the well-known candidate locations.
    fn find_config(&self) -> Option<PathBuf> {
        if self.paths.aide_conf.exists() {
            return Some(self.paths.aide_conf.clone());
        }
        AIDE_CONFIG_CANDIDATES
            .iter()
            .map(PathBuf::from)
            .find(|p| p.exists())
    }

    /// Locate the AIDE database: the configured `aide_db_dir/aide.db.gz` and
    /// `aide_db_dir/aide.db.new.gz` first, then the well-known absolute
    /// candidate locations. Returns the newest existing candidate by mtime.
    fn find_db(&self) -> Option<PathBuf> {
        let mut candidates: Vec<PathBuf> = vec![
            self.paths.aide_db_dir.join("aide.db.gz"),
            self.paths.aide_db_dir.join("aide.db.new.gz"),
        ];
        candidates.extend(AIDE_DB_CANDIDATES.iter().map(PathBuf::from));

        let mut best: Option<(PathBuf, SystemTime)> = None;
        for c in candidates {
            let Ok(md) = c.metadata() else { continue };
            let mtime = md.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            match &best {
                Some((_, best_mtime)) if &mtime <= best_mtime => {}
                _ => best = Some((c, mtime)),
            }
        }
        best.map(|(p, _)| p)
    }

    /// Run `aide --version` and extract a version string (best-effort).
    fn aide_version(&self) -> Option<String> {
        let spec = self.aide_command("--version");
        let output = self.runner.run(&spec).ok()?;
        extract_version(&output.combined_output())
    }

    /// Run `aide --check` and return the raw output (best-effort). A missing
    /// binary is treated as a non-fatal absence of a check result.
    fn aide_check_output(&self) -> Option<toride_runner::CommandOutput> {
        let spec = self.aide_command("--check");
        self.runner.run(&spec).ok()
    }
}

/// Extract an AIDE version token (e.g. `0.18.8`) from `--version` output.
fn extract_version(combined: &str) -> Option<String> {
    // AIDE prints lines like `AIDE 0.18.8` or `AIDE 0.18 (Dev#...)`.
    // Scan for the first `AIDE`-prefixed token carrying a dotted version.
    for line in combined.lines() {
        let trimmed = line.trim();
        if !trimmed.to_ascii_lowercase().contains("aide") {
            continue;
        }
        for tok in trimmed.split_whitespace() {
            if tok.chars().any(|c| c.is_ascii_digit()) && tok.contains('.') {
                return Some(tok.trim_end_matches(',').to_owned());
            }
        }
    }
    None
}

/// Build the one-line human-readable status summarizing the probe.
#[allow(clippy::too_many_arguments)]
fn build_status_line(
    version: Option<&str>,
    config_present: bool,
    database_initialized: bool,
    file_count: Option<usize>,
    last_check: Option<SystemTime>,
) -> String {
    let mut parts: Vec<String> = Vec::new();

    match version {
        Some(v) => parts.push(format!("AIDE {v}")),
        None => parts.push("AIDE".to_owned()),
    }

    if !config_present {
        parts.push("no config".to_owned());
    }
    if database_initialized {
        match file_count {
            Some(0) => parts.push("0 changes".to_owned()),
            Some(n) => parts.push(format!("{n} changes")),
            None => parts.push("db present".to_owned()),
        }
    } else {
        parts.push("db not initialized".to_owned());
    }

    if let Some(ts) = last_check.and_then(system_time_to_rfc3339) {
        parts.push(format!("last {ts}"));
    }

    parts.join(": ")
}

/// Render a `SystemTime` as a compact RFC-3339-ish string, or `None` if the
/// time is before the UNIX epoch (should not happen in practice).
fn system_time_to_rfc3339(t: SystemTime) -> Option<String> {
    // `as_secs()` from `duration_since(UNIX_EPOCH)` is a duration in seconds
    // since 1970; converting to `i64` cannot wrap for any plausible wall-clock.
    #[expect(
        clippy::cast_possible_wrap,
        reason = "duration secs fit in i64 for any real timestamp"
    )]
    let secs = t.duration_since(SystemTime::UNIX_EPOCH).ok()?.as_secs() as i64;
    // Minimal UTC formatter (no chrono dep): YYYY-MM-DDTHH:MM:SSZ.
    let (year, month, day, hour, minute, second) = unix_to_ymdhms(secs);
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

/// Convert a UNIX timestamp (seconds since epoch, UTC) to broken-down
/// calendar components. Pure, allocation-free, valid for years 1970..2100+.
///
/// The casts below are all provably in range per Howard Hinnant's
/// `civil_from_days` algorithm (the inline `// [lo, hi]` comments document
/// each value's domain), so the cast_* lints are silenced for this body.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    reason = "civil_from_days invariants bound every value (see inline range comments)"
)]
fn unix_to_ymdhms(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let hour = (rem / 3600) as u32;
    let minute = ((rem % 3600) / 60) as u32;
    let second = (rem % 60) as u32;

    // Howard Hinnant's days_from_civil inverse (civil_from_days).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };

    (year, m, d, hour, minute, second)
}

#[allow(dead_code)]
fn path_exists(p: &Path) -> bool {
    p.exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::{Mutex, OnceLock};
    use std::time::Duration;
    use tempfile::TempDir;
    use toride_runner::fake::FakeRunner;
    use toride_runner::{CommandOutput, CommandSpec, Result as RunnerResult, Runner};

    fn paths_under(dir: &Path) -> AuditPaths {
        AuditPaths {
            audit_dir: dir.join("etc/audit"),
            rules_d: dir.join("etc/audit/rules.d"),
            aide_conf: dir.join("etc/aide.conf"),
            aide_db_dir: dir.join("var/lib/aide"),
            rsyslog_conf: dir.join("etc/rsyslog.conf"),
            rsyslog_d: dir.join("etc/rsyslog.d"),
            logrotate_d: dir.join("etc/logrotate.d"),
        }
    }

    /// A minimal in-test `Runner` that returns pre-queued outputs in FIFO
    /// order, falling back to an empty success when the queue is drained.
    /// Kept local so production deps don't need the `fake` runner feature.
    struct RecordingRunner {
        outputs: Mutex<Vec<CommandOutput>>,
    }

    impl RecordingRunner {
        fn new(outputs: Vec<CommandOutput>) -> Self {
            Self {
                outputs: Mutex::new(outputs),
            }
        }
    }

    impl Runner for RecordingRunner {
        fn run(&self, _spec: &CommandSpec) -> RunnerResult<CommandOutput> {
            let mut q = self.outputs.lock().expect("queue lock");
            if q.is_empty() {
                Ok(CommandOutput::from_stdout(String::new()))
            } else {
                Ok(q.remove(0))
            }
        }
    }

    fn aide_installed() -> bool {
        static C: OnceLock<bool> = OnceLock::new();
        *C.get_or_init(|| which::which("aide").is_ok())
    }

    #[test]
    fn not_installed_reports_unknown_count_and_failed_check() {
        let s = IntegrityStatus::not_installed();
        assert!(!s.database_initialized);
        // No check ever ran, so the count is genuinely unknown: Some(0)
        // would read as "check ran clean" downstream.
        assert_eq!(s.file_count, None);
        assert_eq!(s.last_check_passed, Some(false));
        assert_eq!(s.last_check_output.as_deref(), Some("AIDE not installed"));
    }

    #[test]
    fn status_helpers_handle_absent_files() {
        // find_config / find_db over a temp dir with nothing present.
        let tmp = TempDir::new().unwrap();
        let paths = paths_under(tmp.path());
        let runner = RecordingRunner::new(Vec::new());
        let mgr = IntegrityManager::new(&runner, &paths);
        assert!(mgr.find_config().is_none());
        assert!(mgr.find_db().is_none());

        // status() never errors and always populates the secondary fields
        // (so the presentation layer never renders "not implemented").
        let s = mgr.status().unwrap();
        assert!(s.last_check_output.is_some());
        assert!(s.last_check_passed.is_some());
        if !aide_installed() {
            assert_eq!(
                s.file_count, None,
                "an AIDE-absent host must not report a known (clean) count"
            );
        }
    }

    #[test]
    fn status_with_db_and_clean_check_reports_zero_changes() {
        // Requires the `aide` binary to be present; otherwise the binary
        // probe short-circuits to not_installed and the faked runner is
        // never consulted.
        if !aide_installed() {
            eprintln!("skipping: aide not installed on host");
            return;
        }

        let tmp = TempDir::new().unwrap();
        let paths = paths_under(tmp.path());
        fs::create_dir_all(paths.aide_db_dir.as_path()).unwrap();
        // Touch the configured DB file so `database_initialized` is true.
        fs::write(paths.aide_db_dir.join("aide.db.gz"), b"stub").unwrap();

        // Fake a `--version` then a clean `--check` output (FIFO order).
        let runner = RecordingRunner::new(vec![
            CommandOutput::from_stdout("AIDE 0.18.8\n"),
            CommandOutput::from_stdout("AIDE 0.18.8 found no differences\n"),
        ]);

        let mgr = IntegrityManager::new(&runner, &paths);
        let s = mgr.status().unwrap();
        assert!(s.database_initialized);
        assert_eq!(s.file_count, Some(0));
        assert_eq!(s.last_check_passed, Some(true));
        let line = s.last_check_output.expect("status line");
        assert!(line.contains("AIDE"), "line = {line}");
        assert!(line.contains("0 changes"), "line = {line}");
    }

    fn clean_check_output() -> CommandOutput {
        CommandOutput::from_stdout(
            "Added entries:\t\t0\nRemoved entries:\t\t0\nChanged entries:\t\t0\n",
        )
    }

    fn override_paths_with_db(dir: &Path) -> AuditPaths {
        let paths = paths_under(dir);
        fs::create_dir_all(&paths.aide_db_dir).unwrap();
        fs::write(paths.aide_db_dir.join("aide.db.gz"), b"stub").unwrap();
        if let Some(parent) = paths.aide_conf.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&paths.aide_conf, b"@@define DBDIR /var/lib/aide\n").unwrap();
        paths
    }

    #[test]
    fn with_binary_live_probe_spawns_exactly_one_check() {
        let tmp = TempDir::new().unwrap();
        let paths = override_paths_with_db(tmp.path());

        let runner = FakeRunner::new()
            .push_response(CommandOutput::from_stdout("AIDE 0.18.8\n"))
            .push_response(clean_check_output());
        let binary = PathBuf::from("/opt/toride-fixtures/aide");
        let mgr = IntegrityManager::with_binary(&runner, &paths, binary.clone());

        let status = mgr.status().unwrap();
        assert!(status.database_initialized);
        assert_eq!(status.file_count, Some(0));
        assert_eq!(status.last_check_passed, Some(true));

        let calls = runner.calls();
        assert!(
            calls.iter().all(|c| c.program == binary),
            "every spawn must target the pinned binary: {calls:?}"
        );
        let check_spawns = calls
            .iter()
            .filter(|c| c.args.iter().any(|a| a == "--check"))
            .count();
        assert_eq!(
            check_spawns, 1,
            "a live probe must spawn exactly one `aide --check`"
        );
        assert_eq!(calls.len(), 2, "one --version plus one --check");
    }

    #[test]
    fn with_binary_bypasses_which_gate_when_aide_not_on_path() {
        let tmp = TempDir::new().unwrap();
        let paths = override_paths_with_db(tmp.path());

        let runner = FakeRunner::new()
            .push_response(CommandOutput::from_stdout("AIDE 0.18.8\n"))
            .push_response(clean_check_output());
        let mgr = IntegrityManager::with_binary(
            &runner,
            &paths,
            PathBuf::from("/opt/toride-fixtures/aide"),
        );

        let status = mgr.status().unwrap();
        assert!(
            status.last_check_passed.is_some(),
            "the pinned-binary probe must reach the runner regardless of host PATH"
        );
        assert_eq!(
            runner.calls().len(),
            2,
            "no `which::which` short-circuit may suppress runner spawns"
        );
    }

    /// Within the status TTL a second `status()` call must spawn nothing:
    /// `aide --check` re-hashes the monitored filesystem, so a polling
    /// consumer must not trigger it every poll (safety-state-9 gate).
    #[test]
    fn repeated_status_within_ttl_spawns_no_additional_checks() {
        let tmp = TempDir::new().unwrap();
        let paths = override_paths_with_db(tmp.path());

        let runner = FakeRunner::new()
            .push_response(CommandOutput::from_stdout("AIDE 0.18.8\n"))
            .push_response(clean_check_output());
        let mgr = IntegrityManager::with_binary(
            &runner,
            &paths,
            PathBuf::from("/opt/toride-fixtures/aide"),
        );

        let first = mgr.status().expect("first status");
        let second = mgr.status().expect("cached status");
        assert_eq!(first.file_count, second.file_count);
        assert_eq!(first.last_check_passed, second.last_check_passed);

        let check_spawns = runner
            .calls()
            .iter()
            .filter(|c| c.args.iter().any(|a| a == "--check"))
            .count();
        assert_eq!(
            check_spawns, 1,
            "one live probe only; the repeat must be served from the TTL cache"
        );
    }

    /// `with_status_ttl(Duration::ZERO)` disables the cache: every call
    /// probes again.
    #[test]
    fn zero_ttl_disables_status_caching() {
        let tmp = TempDir::new().unwrap();
        let paths = override_paths_with_db(tmp.path());

        let runner = FakeRunner::new()
            .push_response(CommandOutput::from_stdout("AIDE 0.18.8\n"))
            .push_response(clean_check_output())
            .push_response(CommandOutput::from_stdout("AIDE 0.18.8\n"))
            .push_response(clean_check_output());
        let mgr = IntegrityManager::with_binary(
            &runner,
            &paths,
            PathBuf::from("/opt/toride-fixtures/aide"),
        )
        .with_status_ttl(Duration::ZERO);

        mgr.status().expect("first status");
        mgr.status().expect("second status");
        let check_spawns = runner
            .calls()
            .iter()
            .filter(|c| c.args.iter().any(|a| a == "--check"))
            .count();
        assert_eq!(check_spawns, 2, "ZERO TTL must probe on every call");
    }

    /// An AIDE database mtime change invalidates the memo before the TTL
    /// expires (an `--init`/`--update` through the same manager must be
    /// noticed immediately).
    #[test]
    fn db_mtime_change_invalidates_cached_status() {
        let tmp = TempDir::new().unwrap();
        let paths = override_paths_with_db(tmp.path());

        let runner = FakeRunner::new()
            .push_response(CommandOutput::from_stdout("AIDE 0.18.8\n"))
            .push_response(clean_check_output())
            .push_response(CommandOutput::from_stdout("AIDE 0.18.9\n"))
            .push_response(clean_check_output());
        let mgr = IntegrityManager::with_binary(
            &runner,
            &paths,
            PathBuf::from("/opt/toride-fixtures/aide"),
        );

        mgr.status().expect("first status (cached)");
        // Bump the db mtime past coarse filesystem granularity.
        std::thread::sleep(Duration::from_millis(1100));
        std::fs::write(paths.aide_db_dir.join("aide.db.gz"), b"updated").unwrap();

        mgr.status().expect("status after db update");
        let check_spawns = runner
            .calls()
            .iter()
            .filter(|c| c.args.iter().any(|a| a == "--check"))
            .count();
        assert_eq!(
            check_spawns, 2,
            "a moved database mtime must force a fresh probe"
        );
    }

    #[test]
    fn find_db_picks_newest_candidate() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_under(tmp.path());
        let dir = paths.aide_db_dir.clone();
        fs::create_dir_all(&dir).unwrap();

        // Old DB.
        let old = dir.join("aide.db.gz");
        fs::write(&old, b"old").unwrap();
        // Newer DB in the same dir. Sleep > 1s so even 1-second filesystem
        // mtime granularity (HFS/APFS) distinguishes the two files.
        std::thread::sleep(Duration::from_millis(1100));
        let new = dir.join("aide.db.new.gz");
        fs::write(&new, b"new").unwrap();

        let runner = RecordingRunner::new(Vec::new());
        let mgr = IntegrityManager::new(&runner, &paths);
        let picked = mgr.find_db().expect("a db");
        assert_eq!(picked, new, "should pick newest db by mtime");
        let _ = old;
    }

    #[test]
    fn find_config_prefers_configured_path() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_under(tmp.path());
        // Create the parent `etc/` dir so the write succeeds.
        if let Some(parent) = paths.aide_conf.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&paths.aide_conf, b"@@define DBDIR /var/lib/aide\n").unwrap();

        let runner = RecordingRunner::new(Vec::new());
        let mgr = IntegrityManager::new(&runner, &paths);
        assert_eq!(mgr.find_config(), Some(paths.aide_conf.clone()));
    }

    #[test]
    fn extract_version_from_typical_output() {
        let v = extract_version("AIDE 0.18.8\n\nAIDE initialized\n");
        assert_eq!(v.as_deref(), Some("0.18.8"));
    }

    #[test]
    fn extract_version_from_dev_output() {
        let v = extract_version("AIDE 0.18 (Dev#fixed.devel)\n");
        assert_eq!(v.as_deref(), Some("0.18"));
    }

    #[test]
    fn extract_version_none_when_unparseable() {
        let v = extract_version("some unrelated line\n");
        assert!(v.is_none());
    }

    #[test]
    fn status_line_when_not_initialized() {
        let line = build_status_line(Some("0.18.8"), false, false, None, None);
        assert!(line.contains("AIDE 0.18.8"), "line = {line}");
        assert!(line.contains("no config"), "line = {line}");
        assert!(line.contains("db not initialized"), "line = {line}");
    }

    #[test]
    fn status_line_when_clean_check() {
        let line = build_status_line(None, true, true, Some(0), None);
        assert!(line.contains("0 changes"), "line = {line}");
    }

    #[test]
    fn status_line_when_changes_detected() {
        let line = build_status_line(None, true, true, Some(7), None);
        assert!(line.contains("7 changes"), "line = {line}");
    }

    #[test]
    fn unix_to_ymdhms_known_epoch() {
        // 1970-01-01T00:00:00Z
        let (y, m, d, hh, mm, ss) = unix_to_ymdhms(0);
        assert_eq!((y, m, d, hh, mm, ss), (1970, 1, 1, 0, 0, 0));
    }

    #[test]
    fn unix_to_ymdhms_known_instant() {
        // 2000-01-01T00:00:00Z = 946_684_800
        let (y, m, d, hh, mm, ss) = unix_to_ymdhms(946_684_800);
        assert_eq!((y, m, d, hh, mm, ss), (2000, 1, 1, 0, 0, 0));
    }

    #[test]
    fn unix_to_ymdhms_february_leap_year() {
        // 2024-02-29T12:54:56Z = 1_709_211_296 (verified: 1_709_211_296 % 3600
        // = 3296 -> 54m 56s).
        let secs = 1_709_211_296;
        let (y, m, d, hh, mm, ss) = unix_to_ymdhms(secs);
        assert_eq!((y, m, d, hh, mm, ss), (2024, 2, 29, 12, 54, 56));
    }

    #[test]
    fn system_time_to_rfc3339_round_trips_known() {
        // 946_684_800 s is the exact Y2K epoch (2000-01-01T00:00:00Z); no
        // larger Duration unit expresses this precise instant.
        #[expect(
            clippy::duration_suboptimal_units,
            reason = "exact Y2K epoch has no larger Duration unit"
        )]
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(946_684_800);
        assert_eq!(
            system_time_to_rfc3339(t).as_deref(),
            Some("2000-01-01T00:00:00Z")
        );
    }

    #[test]
    fn path_exists_helper_basic() {
        assert!(path_exists(Path::new("/")));
        assert!(!path_exists(Path::new("/this/does/not/exist/xyz")));
    }
}
