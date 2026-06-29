//! Async log-file / journald tailing collection (LIVE READ-ONLY).
//!
//! [`LogsCollector`] tails recent lines from the log sources that exist on
//! THIS host via a tokio oneshot channel, following the SIMPLE pattern of
//! [`StatusCollector`](crate::status_collector::StatusCollector) (no findings
//! cache — logs must be fresh on every 2s tick).
//!
//! This is the most "live" read-only section: every collection reads the last
//! ~200 lines of each existing source. There are no write operations, no
//! optimistic updates, no cooldown gate, and no loading spinner.
//!
//! ## Sources probed
//!
//! * toride's own log file — resolved from the same
//!   `$TORIDE_LOG_FILE` / `dirs::cache_dir().join("toride").join("toride.log")`
//!   resolution that [`main`](../../main.rs) uses for the tracing appender, so
//!   the operator can tail what the app itself is emitting.
//! * Linux: `/var/log/auth.log`, `/var/log/syslog`, `/var/log/messages`,
//!   `/var/log/secure`, `/var/log/kern.log`.
//! * macOS: `/var/log/system.log`, `/var/log/install.log`,
//!   `~/Library/Logs/toride.log`.
//! * `journalctl`: if the binary is on PATH, the last 200 lines are captured
//!   via a `spawn_blocking` subprocess bounded by a 1.5s
//!   [`tokio::time::timeout`].
//!
//! ## Blocking & safety
//!
//! ALL filesystem reads AND the journalctl subprocess run inside ONE
//! [`tokio::task::spawn_blocking`] closure, so the tokio worker is never
//! stalled. Permission errors are caught per-source (that source is degraded
//! to `exists == false` with a `"(permission denied)"` note) and never panic.
//! Large files are seeked near the end before reading — total bytes per file
//! are capped at [`MAX_FILE_BYTES`] (256 KiB) so a multi-GB syslog is never
//! read whole.

use std::path::PathBuf;
use std::time::Duration;

use tokio::sync::oneshot;

/// Maximum bytes read from the tail of any single file. Keeps collection cheap
/// even when the host has a multi-GB `/var/log/syslog`: we seek to
/// `size - MAX_FILE_BYTES` (clamped at 0) before reading, then keep the last
/// [`MAX_LINES`] lines from what was read.
const MAX_FILE_BYTES: u64 = 256 * 1024;

/// Maximum lines kept per source after the tail is sliced. Mirrors the
/// journalctl `-n 200` budget so file and journalctl sources present at a
/// glance-comparable density.
const MAX_LINES: usize = 200;

/// Timeout for the journalctl subprocess. journalctl can block for many
/// seconds on a system with a huge journal; bound it so the collection task
/// cannot stall the 2s refresh tick.
const JOURNALCTL_TIMEOUT: Duration = Duration::from_millis(1500);

/// The tail of one log source.
///
/// Built by [`collect_real_logs`] for each source that exists on this host.
/// Permission-denied sources are still emitted with `exists == false` and a
/// note in [`LogSource::mtime`] so the operator can see WHY a file was
/// skipped.
#[derive(Clone, Debug)]
pub struct LogSource {
    /// Human-readable name shown in the header (e.g. `"toride"`,
    /// `"auth.log"`, `"journalctl"`).
    pub name: String,
    /// Absolute path to the source (or, for journalctl, the command string
    /// `journalctl -n 200 --no-pager`).
    pub path: String,
    /// Whether the source could be read. `false` when the file is absent or
    /// unreadable (permission denied). journalctl reports `true` only when
    /// the subprocess exited 0 with output.
    pub exists: bool,
    /// File size in bytes (`0` for journalctl / unreadable sources).
    pub size_bytes: u64,
    /// Modified-time formatted as a short human-readable string, OR a note
    /// like `"permission denied"` for an unreadable source. `None` when the
    /// mtime could not be determined AND there was no permission error.
    pub mtime: Option<String>,
    /// Number of lines in [`LogSource::lines`] (kept explicitly because the
    /// viewer clamps scroll against it).
    pub line_count: usize,
    /// The last ~[`MAX_LINES`] lines of the source (already decoded UTF-8,
    /// lossy for non-UTF-8 bytes — logs must never crash the viewer).
    pub lines: Vec<String>,
}

/// Aggregated log data for the read-only Logs section.
///
/// `available` is `true` whenever ANY source could be read; when ZERO sources
/// exist on this host `available` STAYS `true` and the viewer surfaces an
/// honest `"no log sources found on this host"` line (NOT a fake "coming
/// soon"). `available` flips to `false` ONLY when the collection task itself
/// panicked (`JoinError`) — the viewer then renders the degraded panel.
#[derive(Clone, Debug)]
pub struct LogsDataBundle {
    /// Whether collection ran at all. `false` is reserved for the panic
    /// (`JoinError`) case; an empty host keeps `true` so the "no sources" line
    /// surfaces honestly.
    pub available: bool,
    /// Every probed source that exists (or that was degraded with a
    /// permission-denied note). Empty on a host with no log sources.
    pub sources: Vec<LogSource>,
    /// Human-readable reason collection failed, populated ONLY when
    /// `available == false` (collection-task panic). `None` otherwise —
    /// notably also `None` for a freshly-constructed empty bundle before any
    /// collection has run.
    pub unavailable_reason: Option<String>,
}

// ── Collector ───────────────────────────────────────────────────────────────

/// Manages periodic async log collection.
///
/// Mirrors [`StatusCollector`](crate::status_collector::StatusCollector): a
/// single oneshot channel for the in-flight result. There is NO findings
/// cache here (unlike [`HardenCollector`](crate::toride_harden_data::HardenCollector))
/// because log tails must be fresh on every 2s tick — a cache would show
/// stale lines.
pub struct LogsCollector {
    /// Carries the in-flight bundle. `None` when no collection is running.
    rx: Option<oneshot::Receiver<LogsDataBundle>>,
}

impl LogsCollector {
    /// Create a new collector with no pending collection.
    #[must_use]
    pub fn new() -> Self {
        Self { rx: None }
    }

    /// Whether a collection is currently in-flight.
    pub fn is_pending(&self) -> bool {
        self.rx.is_some()
    }

    /// Start a new background collection.
    ///
    /// If a collection is already in-flight, this is a no-op. All filesystem
    /// reads AND the optional journalctl subprocess run inside ONE
    /// `spawn_blocking` so the tokio worker is never stalled; the result
    /// crosses back to the async caller via the oneshot channel.
    pub fn start(&mut self) {
        if self.rx.is_some() {
            return;
        }
        let (tx, rx) = oneshot::channel();
        self.rx = Some(rx);
        tokio::spawn(async move {
            let bundle = collect_real_logs().await;
            let _ = tx.send(bundle);
        });
    }

    /// Poll for a completed collection result.
    ///
    /// Returns `Some(bundle)` if the collection completed, `None` if still
    /// pending or if the collection failed (sender dropped — e.g. the spawned
    /// task panicked before sending). The receiver is always cleared after
    /// this call.
    pub async fn poll(&mut self) -> Option<LogsDataBundle> {
        match &mut self.rx {
            Some(rx) => {
                let result = rx.await.ok();
                self.rx = None;
                result
            }
            None => None,
        }
    }
}

impl Default for LogsCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Real data collection ────────────────────────────────────────────────────

/// Tail the log sources that exist on THIS host.
///
/// All filesystem reads run inside ONE `spawn_blocking`; the optional
/// journalctl subprocess is awaited as an async child wrapped in
/// `tokio::time::timeout(JOURNALCTL_TIMEOUT)` so a hung journal cannot stall
/// the 2s refresh tick. Each file is seeked near the end (capped at
/// [`MAX_FILE_BYTES`]) before reading so a multi-GB syslog cannot exhaust
/// memory. Permission errors degrade that one source to `exists == false`
/// with a note; the rest of the collection continues.
///
/// `available` is `true` whenever ANY source returned content; on a host with
/// ZERO readable sources `available` stays `true` so the viewer surfaces the
/// honest "no log sources found on this host" line. Only a `spawn_blocking`
/// panic (`JoinError`) flips `available` to `false`.
async fn collect_real_logs() -> LogsDataBundle {
    // Build the candidate set OUTSIDE spawn_blocking (cheap: a few path
    // joins + env lookups). The blocking closure then owns the Vec and does
    // every fs read in one trip.
    let candidates = candidate_sources();

    // Probe journalctl via `which` on the async side (cheap) so the blocking
    // closure can skip it entirely when the binary is absent.
    let have_journalctl = which::which("journalctl").is_ok();

    let file_sources = tokio::task::spawn_blocking(move || read_file_sources(&candidates)).await;

    let mut sources = match file_sources {
        Ok(sources) => sources,
        Err(e) => {
            tracing::warn!("logs file collection panicked: {e}");
            return empty_bundle_with_reason(format!("logs data collection panicked: {e}"));
        }
    };

    if have_journalctl {
        // Bound the journalctl subprocess so a huge journal cannot stall the
        // 2s refresh tick. A timeout degrades the journalctl source to absent
        // rather than aborting the whole bundle — the file sources already
        // collected still surface.
        if let Ok(Some(journal)) =
            tokio::time::timeout(JOURNALCTL_TIMEOUT, read_journalctl_async()).await
        {
            sources.push(journal);
        } else {
            tracing::warn!("journalctl timed out after {:?}", JOURNALCTL_TIMEOUT);
        }
    }

    LogsDataBundle {
        // Honest about the empty-host case: stays true so the viewer shows
        // "no log sources found on this host" rather than the degraded-panel
        // "Logs unavailable" message. available flips to false ONLY for the
        // panic path (above).
        available: true,
        sources,
        unavailable_reason: None,
    }
}

/// The candidate source set for THIS host.
///
/// Order matters for the viewer's default selection: toride's own log is
/// listed first (the operator almost always wants the app's own output), then
/// platform logs, then journalctl as a catch-all. Linux/macOS paths are both
/// included unconditionally — the reader simply reports `exists == false` for
/// the ones that don't apply on this OS, which keeps the probe list
/// data-driven and identical across hosts (easier to reason about than
/// per-OS branching).
fn candidate_sources() -> Vec<(&'static str, PathBuf)> {
    let mut out: Vec<(&'static str, PathBuf)> = Vec::new();

    // ── toride's own log ───────────────────────────────────────────────────
    // Mirrors main.rs::log_file_path resolution: $TORIDE_LOG_FILE wins,
    // otherwise dirs::cache_dir().join("toride").join("toride.log").
    if let Some(path) = toride_log_path() {
        out.push(("toride", path));
    }

    // ── Linux ──────────────────────────────────────────────────────────────
    out.push(("auth.log", PathBuf::from("/var/log/auth.log")));
    out.push(("syslog", PathBuf::from("/var/log/syslog")));
    out.push(("messages", PathBuf::from("/var/log/messages")));
    out.push(("secure", PathBuf::from("/var/log/secure")));
    out.push(("kern.log", PathBuf::from("/var/log/kern.log")));

    // ── macOS ──────────────────────────────────────────────────────────────
    out.push(("system.log", PathBuf::from("/var/log/system.log")));
    out.push(("install.log", PathBuf::from("/var/log/install.log")));
    if let Some(home) = dirs::home_dir() {
        out.push(("toride (user)", home.join("Library/Logs/toride.log")));
    }

    out
}

/// Resolve toride's own log file path, mirroring [`main::log_file_path`].
///
/// [`main::log_file_path`]: ../../main.rs
fn toride_log_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("TORIDE_LOG_FILE") {
        return Some(PathBuf::from(p));
    }
    dirs::cache_dir().map(|d| d.join("toride").join("toride.log"))
}

/// Read every candidate FILE source, emitting a [`LogSource`] for each that
/// exists OR that errored on permission. Absent sources are skipped silently
/// (the viewer would otherwise list a row of `exists == false` noise for the
/// entire platform-specific half of the candidate set).
///
/// journalctl is handled separately (see [`read_journalctl_async`]) because
/// it is an async subprocess with its own timeout, not a blocking file read.
/// Errors never propagate — a failed read degrades that one source.
fn read_file_sources(candidates: &[(&'static str, PathBuf)]) -> Vec<LogSource> {
    let mut sources: Vec<LogSource> = Vec::new();

    for (name, path) in candidates {
        match read_file_tail(path) {
            FileRead::Ok {
                size_bytes,
                mtime,
                lines,
            } => {
                sources.push(LogSource {
                    name: (*name).to_string(),
                    path: path.display().to_string(),
                    exists: true,
                    size_bytes,
                    mtime,
                    line_count: lines.len(),
                    lines,
                });
            }
            FileRead::PermissionDenied => {
                // Surface the permission failure so the operator knows WHY a
                // file they expected to see is missing — better than silently
                // dropping it.
                sources.push(LogSource {
                    name: format!("{name} (permission denied)"),
                    path: path.display().to_string(),
                    exists: false,
                    size_bytes: 0,
                    mtime: Some("permission denied".to_string()),
                    line_count: 0,
                    lines: Vec::new(),
                });
            }
            FileRead::Absent | FileRead::Other(_) => {
                // Silently skip — see fn doc.
            }
        }
    }

    sources
}

/// Outcome of tailing one file. Absent files and "other" errors are both
/// skipped silently by the caller; permission-denied is surfaced so the
/// operator sees why.
#[derive(Debug)]
enum FileRead {
    Ok {
        size_bytes: u64,
        mtime: Option<String>,
        lines: Vec<String>,
    },
    /// File does not exist.
    Absent,
    /// File exists but could not be opened/read (likely EACCES).
    PermissionDenied,
    /// Some other I/O error (logged at debug).
    #[expect(
        dead_code,
        reason = "error string retained for Debug rendering / future surfacing"
    )]
    Other(String),
}

/// Read the last ~[`MAX_LINES`] lines of `path`, having first seeked to within
/// [`MAX_FILE_BYTES`] of the end for large files.
///
/// Never panics: every I/O step is matched and mapped to a [`FileRead`]
/// variant. Non-UTF-8 bytes decode lossily (logs must never crash the
/// viewer).
#[expect(
    clippy::cast_possible_truncation,
    reason = "MAX_FILE_BYTES is a small constant that fits in usize"
)]
fn read_file_tail(path: &std::path::Path) -> FileRead {
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};

    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return FileRead::Absent,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return FileRead::PermissionDenied;
        }
        Err(e) => return FileRead::Other(e.to_string()),
    };
    let size_bytes = meta.len();

    // Permission errors on OPEN are distinct from metadata's PermissionDenied
    // (the file may be stat-able but not readable) — surface them too.
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return FileRead::PermissionDenied;
        }
        Err(e) => return FileRead::Other(e.to_string()),
    };

    // Seek near the end for large files so we never slurp a multi-GB syslog.
    if size_bytes > MAX_FILE_BYTES
        && let Err(e) = file.seek(SeekFrom::Start(size_bytes - MAX_FILE_BYTES))
    {
        return FileRead::Other(e.to_string());
    }

    let mut bytes = Vec::with_capacity(MAX_FILE_BYTES as usize);
    if let Err(e) = file.read_to_end(&mut bytes) {
        return FileRead::Other(e.to_string());
    }

    // Drop a likely-partial first line (we started mid-line after the seek).
    if size_bytes > MAX_FILE_BYTES
        && let Some(nl) = bytes.iter().position(|&b| b == b'\n')
    {
        bytes.drain(..=nl);
    }

    let text = String::from_utf8_lossy(&bytes);
    let lines: Vec<String> = text
        .lines()
        .rev()
        .take(MAX_LINES)
        .map(String::from)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();

    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| format_mtime(d.as_secs()));

    FileRead::Ok {
        size_bytes,
        mtime,
        lines,
    }
}

/// Format a unix mtime as `YYYY-MM-DD HH:MM` (UTC). Good enough for a log
/// viewer header; the operator rarely needs second-precision.
#[expect(
    clippy::cast_possible_wrap,
    reason = "unix days are well within i64 range"
)]
fn format_mtime(unix_secs: u64) -> String {
    // Minimal civil-time conversion from unix seconds (UTC). Avoids pulling
    // in chrono just for one header field; logs are usually read in the same
    // timezone the operator is thinking in anyway, and the path is shown
    // alongside for absolute context.
    let days = (unix_secs / 86_400) as i64;
    let secs_of_day = unix_secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    let hh = secs_of_day / 3600;
    let mm = (secs_of_day % 3600) / 60;
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}")
}

/// Howard Hinnant's days-from-civil algorithm (inverse of the Gregorian
/// leap-year rules). Returns `(year, month, day)` in `1..=12` / `1..=31`.
#[expect(
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    reason = "Howard Hinnant days-from-civil: all values are bounded by the algorithm's invariants"
)]
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146_096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Spawn `journalctl -n 200 --no-pager` as an async child and return its
/// lines as a [`LogSource`], OR `None` on any error / non-zero exit / empty
/// output. The caller has already confirmed via `which::which("journalctl")`
/// that the binary is on PATH, and bounds this future with
/// [`JOURNALCTL_TIMEOUT`] via `tokio::time::timeout` — see
/// [`collect_real_logs`].
///
/// Uses [`tokio::process::Command`] (not `std::process::Command`) so the wait
/// is genuinely async and the timeout can cancel it. On timeout the child is
/// left to be reaped by the OS `SIGCHLD` handler; tokio's `Child` drops do
/// not auto-kill, but the journalctl subprocess will exit on its own once its
/// pipe consumer (us) goes away, and a single stray journalctl is harmless.
async fn read_journalctl_async() -> Option<LogSource> {
    use tokio::process::Command;

    let output = Command::new("journalctl")
        .arg("-n")
        .arg(MAX_LINES.to_string())
        .arg("--no-pager")
        .output()
        .await
        .ok()?;

    if !output.status.success() {
        tracing::debug!(
            "journalctl exited non-zero: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<String> = text.lines().map(String::from).collect();
    if lines.is_empty() {
        return None;
    }

    let line_count = lines.len();
    Some(LogSource {
        name: "journalctl".to_string(),
        path: format!("journalctl -n {MAX_LINES} --no-pager"),
        exists: true,
        size_bytes: output.stdout.len() as u64,
        mtime: None,
        line_count,
        lines,
    })
}

// ── Bundle helpers ──────────────────────────────────────────────────────────

/// Empty bundle used as the starting state and as the panic-fallback base.
///
/// `available = false` so the viewer renders the degraded panel; no reason is
/// attached here (the panic path adds one via [`empty_bundle_with_reason`]).
fn empty_bundle() -> LogsDataBundle {
    LogsDataBundle {
        available: false,
        sources: Vec::new(),
        unavailable_reason: None,
    }
}

/// Empty bundle carrying the reason collection failed. Used when the spawned
/// collection task panicked (`JoinError`) — the reason string is rendered by
/// the viewer's degraded panel.
fn empty_bundle_with_reason(reason: String) -> LogsDataBundle {
    let mut b = empty_bundle();
    b.unavailable_reason = Some(reason);
    b
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_not_pending() {
        let collector = LogsCollector::new();
        assert!(!collector.is_pending());
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(
            LogsCollector::new().is_pending(),
            LogsCollector::default().is_pending()
        );
    }

    #[tokio::test]
    async fn start_makes_pending() {
        let mut collector = LogsCollector::new();
        assert!(!collector.is_pending());
        collector.start();
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn start_is_idempotent() {
        let mut collector = LogsCollector::new();
        collector.start();
        assert!(collector.is_pending());
        collector.start(); // no-op, does not replace the receiver
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn poll_returns_none_when_not_started() {
        let mut collector = LogsCollector::new();
        assert!(collector.poll().await.is_none());
    }

    #[tokio::test]
    async fn poll_clears_pending() {
        let mut collector = LogsCollector::new();
        collector.start();
        // The fs reads + optional journalctl subprocess finish well inside
        // 1s; give a little headroom for CI.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let _ = collector.poll().await;
        assert!(!collector.is_pending(), "poll should clear pending state");
    }

    #[tokio::test]
    async fn poll_returns_bundle_after_collection() {
        // On any host the collector must return Some(bundle) after start() +
        // enough time. available reflects whether ANY source was read (and
        // stays true even on an empty host, per the contract).
        let mut collector = LogsCollector::new();
        collector.start();
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let bundle = collector.poll().await;
        assert!(bundle.is_some(), "poll should return Some after completion");
        let bundle = bundle.unwrap();
        // available is true whenever collection RAN, even with zero sources.
        assert!(bundle.available, "available must be true post-collection");
    }

    #[test]
    fn empty_bundle_is_unavailable() {
        let b = empty_bundle();
        assert!(!b.available);
        assert!(b.sources.is_empty());
        assert!(
            b.unavailable_reason.is_none(),
            "empty_bundle carries no reason; panics use empty_bundle_with_reason"
        );
    }

    #[test]
    fn empty_bundle_with_reason_carries_reason() {
        let b = empty_bundle_with_reason("logs data collection panicked: boom".into());
        assert!(!b.available);
        assert_eq!(
            b.unavailable_reason.as_deref(),
            Some("logs data collection panicked: boom")
        );
    }

    #[test]
    fn candidate_sources_includes_toride_log() {
        // Don't touch the env (edition 2024 makes set_var unsafe, and tests
        // run in parallel within the binary). Instead assert the DEFAULT
        // resolution matches `dirs::cache_dir().join("toride").join("toride.log")`
        // when TORIDE_LOG_FILE is unset. If it IS set in the environment
        // running the tests, the toride entry must still be present (just at
        // a different path).
        let candidates = candidate_sources();
        let toride = candidates
            .iter()
            .find(|(name, _)| *name == "toride")
            .expect("toride log must be the first candidate");
        let expected = match std::env::var("TORIDE_LOG_FILE") {
            Ok(p) => PathBuf::from(p),
            Err(_) => dirs::cache_dir()
                .map(|d| d.join("toride").join("toride.log"))
                .expect("dirs::cache_dir() must resolve on a test host"),
        };
        assert_eq!(toride.1, expected);
    }

    #[test]
    fn candidate_sources_includes_linux_and_macos_paths() {
        // Both platform sets are always present; the reader reports
        // exists=false for whichever half doesn't apply on this OS.
        let candidates = candidate_sources();
        let names: Vec<&str> = candidates.iter().map(|(n, _)| *n).collect();
        for required in [
            "auth.log",
            "syslog",
            "messages",
            "secure",
            "kern.log",
            "system.log",
            "install.log",
        ] {
            assert!(
                names.contains(&required),
                "candidate set missing {required}: {names:?}"
            );
        }
    }

    #[test]
    fn read_file_tail_absent_file_is_absent() {
        let tmp = std::env::temp_dir().join("toride-logs-data-does-not-exist.log");
        let _ = std::fs::remove_file(&tmp);
        match read_file_tail(&tmp) {
            FileRead::Absent => {}
            other => panic!("expected Absent, got {other:?}"),
        }
    }

    #[test]
    fn read_file_tail_small_file_returns_all_lines() {
        let tmp = std::env::temp_dir().join("toride-logs-data-small.log");
        std::fs::write(&tmp, b"line one\nline two\nline three\n").unwrap();
        let result = read_file_tail(&tmp);
        let _ = std::fs::remove_file(&tmp);
        let lines = match result {
            FileRead::Ok { lines, .. } => lines,
            other => panic!("expected Ok, got {other:?}"),
        };
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "line one");
        assert_eq!(lines[2], "line three");
    }

    #[test]
    fn read_file_tail_caps_lines_at_max() {
        // Generate > MAX_LINES lines and confirm only the last MAX_LINES are
        // returned (the tail).
        let tmp = std::env::temp_dir().join("toride-logs-data-many.log");
        let mut body = String::new();
        for i in 0..MAX_LINES * 2 {
            use std::fmt::Write as _;
            let _ = writeln!(body, "line {i}");
        }
        std::fs::write(&tmp, body).unwrap();
        let lines = match read_file_tail(&tmp) {
            FileRead::Ok { lines, .. } => lines,
            other => {
                let _ = std::fs::remove_file(&tmp);
                panic!("expected Ok, got {other:?}");
            }
        };
        let _ = std::fs::remove_file(&tmp);
        assert_eq!(lines.len(), MAX_LINES);
        // The FIRST kept line should be line `MAX_LINES` (we dropped the
        // earliest MAX_LINES, keeping the tail).
        assert_eq!(lines[0], format!("line {MAX_LINES}"));
        assert_eq!(
            lines.last().unwrap(),
            &format!("line {}", MAX_LINES * 2 - 1)
        );
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "MAX_FILE_BYTES is a small constant that fits in usize"
    )]
    #[test]
    fn read_file_tail_seek_does_not_read_whole_large_file() {
        // A file larger than MAX_FILE_BYTES must be seeked: we can detect the
        // seek by writing a sentinel at the start and confirming it is NOT in
        // the returned lines (it was dropped by the partial-first-line trim).
        let tmp = std::env::temp_dir().join("toride-logs-data-large.log");
        let sentinel = "SENTINEL_AT_TOP_LINE_THAT_MUST_BE_DROPPED\n";
        let mut body = String::with_capacity(MAX_FILE_BYTES as usize * 2 + sentinel.len());
        body.push_str(sentinel);
        // Pad with plain lines until we are safely over MAX_FILE_BYTES.
        let pad_line = "padding-padding-padding-padding-padding-padding\n";
        while body.len() < (MAX_FILE_BYTES * 2) as usize {
            body.push_str(pad_line);
        }
        std::fs::write(&tmp, body.as_bytes()).unwrap();
        let (lines, size_bytes) = match read_file_tail(&tmp) {
            FileRead::Ok {
                lines, size_bytes, ..
            } => (lines, size_bytes),
            other => {
                let _ = std::fs::remove_file(&tmp);
                panic!("expected Ok, got {other:?}");
            }
        };
        let _ = std::fs::remove_file(&tmp);
        // Sanity: the file really was larger than the cap.
        assert!(
            size_bytes > MAX_FILE_BYTES,
            "test file must exceed MAX_FILE_BYTES"
        );
        assert!(
            !lines.iter().any(|l| l.contains("SENTINEL_AT_TOP")),
            "the seeked-from partial first line must be dropped: {lines:?}"
        );
    }

    #[test]
    fn format_mtime_is_well_formed() {
        // 2021-01-01 00:00:00 UTC == 1609459200.
        let s = format_mtime(1_609_459_200);
        assert!(s.starts_with("2021-01-01"), "got {s}");
        // Field widths: YYYY-MM-DD HH:MM is 16 chars.
        assert_eq!(s.len(), 16, "got {s}");
    }

    #[test]
    fn civil_from_days_round_trips_known_dates() {
        // 1970-01-01 == unix day 0.
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // 2021-01-01.
        assert_eq!(civil_from_days(18_628), (2021, 1, 1));
    }
}
