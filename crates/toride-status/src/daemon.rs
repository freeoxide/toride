//! Daemon liveness and health checks.
//!
//! Reads PID files, checks `/proc` (Linux) or `kill -0` (macOS/Windows),
//! parses restart-count files, and detects stale Unix sockets.
//!
//! # PID file format
//!
//! The PID file must contain **only** an ASCII decimal integer, optionally
//! followed by a newline. Leading/trailing whitespace is trimmed. The
//! following are rejected:
//! - Empty files or whitespace-only content
//! - Non-numeric content (e.g., `"not-a-number"`)
//! - Mixed content (e.g., `"123abc"`)
//! - PID 0 (would target the process group via `kill(0, 0)`)
//! - PIDs greater than `i32::MAX` (would wrap to negative when cast,
//!   causing `kill(-1, 0)` which signals all processes)
//!
//! # Platform behavior
//!
//! | Feature              | Linux         | macOS         | Windows       |
//! |----------------------|:-------------:|:-------------:|:-------------:|
//! | PID check            | `/proc`       | `kill -0`     | `OpenProcess` |
//! | Process uptime       | `/proc/stat`  | `ps -o etime` | Not supported |
//! | Stale socket detect  | `connect()`   | `connect()`   | File exists   |
//! | Restart count        | File-based    | File-based    | File-based    |
//!
//! # Stale socket detection
//!
//! On Unix platforms, [`DaemonStatus::collect`] attempts to connect to the
//! daemon's Unix socket. If the connection is refused or times out, the
//! socket is flagged as stale so the caller can clean it up.
//!
//! # Examples
//!
//! ```no_run
//! use toride_status::daemon::DaemonStatus;
//!
//! let status = DaemonStatus::collect();
//! if status.alive {
//!     println!("Daemon is alive (PID {:?})", status.pid);
//!     println!("Uptime: {:?} seconds", status.uptime_secs);
//! } else {
//!     println!("Daemon is not running");
//!     if status.stale_socket {
//!         println!("Stale socket detected - cleanup recommended");
//!     }
//! }
//! ```

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

/// Daemon liveness and health snapshot.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct DaemonStatus {
    /// Whether the daemon process is alive.
    pub alive: bool,
    /// Daemon PID, if known.
    pub pid: Option<u32>,
    /// Daemon uptime in seconds, if known.
    pub uptime_secs: Option<u64>,
    /// Number of daemon restarts since last clean start.
    pub restart_count: u32,
    /// Whether the daemon's Unix socket is stale (connection refused).
    pub stale_socket: bool,
}

impl DaemonStatus {
    /// Collect daemon status using default paths.
    ///
    /// Default PID file: `/var/run/toride.pid`
    /// Default socket path: `/tmp/toride.sock`
    /// Default restart count file: `~/.local/share/toride/restart_count`
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use toride_status::daemon::DaemonStatus;
    ///
    /// let status = DaemonStatus::collect();
    /// if status.alive {
    ///     println!("Daemon is alive (PID {:?})", status.pid);
    /// }
    /// ```
    #[must_use]
    pub fn collect() -> Self {
        let pid_path = default_pid_path();
        let socket_path = default_socket_path();
        let restart_path = default_restart_count_path();

        Self::collect_with_paths(&pid_path, &socket_path, &restart_path)
    }

    /// Collect daemon status with explicit paths.
    ///
    /// This is the testable entry point — all filesystem interaction is
    /// confined to the paths passed here. Use this method when you need
    /// to check daemon status with custom PID file, socket, or restart
    /// count paths.
    ///
    /// # Arguments
    ///
    /// * `pid_path` - Path to the PID file containing the daemon's process ID.
    /// * `socket_path` - Path to the Unix socket for connectivity testing.
    /// * `restart_count_path` - Path to the restart count file.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::Path;
    /// use toride_status::daemon::DaemonStatus;
    ///
    /// let status = DaemonStatus::collect_with_paths(
    ///     Path::new("/var/run/myapp.pid"),
    ///     Path::new("/tmp/myapp.sock"),
    ///     Path::new("/tmp/restart_count"),
    /// );
    /// ```
    pub fn collect_with_paths(
        pid_path: &Path,
        socket_path: &Path,
        restart_count_path: &Path,
    ) -> Self {
        let pid = read_pid_file(pid_path);
        let alive = pid.is_some_and(is_process_alive);
        let uptime_secs = pid.and_then(uptime_for_pid);
        let restart_count = read_restart_count(restart_count_path);
        let stale_socket = check_stale_socket(socket_path);

        Self {
            alive,
            pid,
            uptime_secs,
            restart_count,
            stale_socket,
        }
    }
}

/// Default PID file path.
fn default_pid_path() -> PathBuf {
    PathBuf::from("/var/run/toride.pid")
}

/// Default Unix socket path.
fn default_socket_path() -> PathBuf {
    PathBuf::from("/tmp/toride.sock")
}

/// Default restart count file path.
fn default_restart_count_path() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("toride")
        .join("restart_count")
}

/// Read a PID from a file. Returns `None` if the file doesn't exist or
/// contains invalid content. PID 0 is rejected because `kill(0, 0)` signals
/// the entire process group, which would cause false-positive liveness checks.
fn read_pid_file(path: &Path) -> Option<u32> {
    let content = fs::read_to_string(path).ok()?;
    let trimmed = content.trim();
    // Reject empty files and files with extra content after the PID.
    if trimmed.is_empty() || trimmed.contains(|c: char| !c.is_ascii_digit()) {
        return None;
    }
    let pid = trimmed.parse::<u32>().ok()?;
    // PID 0 targets the process group via kill(0, 0), not a specific process.
    // PIDs > i32::MAX wrap to negative when cast, causing kill(-1, 0) which
    // signals all processes and always returns success.
    if pid == 0 || pid > i32::MAX as u32 {
        return None;
    }
    Some(pid)
}

/// Check if a process with the given PID is alive.
///
/// On Unix, uses `kill(pid, 0)` — no signal is sent, just checks existence.
/// On Windows, uses `OpenProcess` with `PROCESS_QUERY_LIMITED_INFORMATION`.
#[cfg(unix)]
fn is_process_alive(pid: u32) -> bool {
    use nix::sys::signal;
    use nix::unistd::Pid;
    signal::kill(Pid::from_raw(pid.cast_signed()), None).is_ok()
}

/// # Platform behavior
///
/// On Windows, this would use `OpenProcess` with
/// `PROCESS_QUERY_LIMITED_INFORMATION`. Currently stubbed to return `false`.
#[cfg(not(unix))]
fn is_process_alive(_pid: u32) -> bool {
    false
}

/// Get uptime in seconds for a given PID.
///
/// On macOS, uses `ps -o etime=` to get elapsed time.
/// On Linux, reads `/proc/<pid>/stat` for process start time.
#[cfg(target_os = "macos")]
fn uptime_for_pid(pid: u32) -> Option<u64> {
    use std::process::Command;
    let output = Command::new("ps")
        .args(["-o", "etime=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    let elapsed = String::from_utf8(output.stdout).ok()?;
    parse_elapsed_time(elapsed.trim())
}

#[cfg(target_os = "linux")]
fn uptime_for_pid(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Field 22 (0-indexed: 21) is starttime in clock ticks since boot.
    // The comm field (field 2) can contain spaces, parens, and special chars,
    // so we use rfind to locate the closing ')' reliably.
    let after_comm = stat.rfind(')')?;
    let rest = stat.get(after_comm + 2..)?;
    let start_ticks: u64 = rest.split_whitespace().nth(19)?.parse().ok()?;
    let ticks_per_sec = sysconf::sysconf(sysconf::SysconfVariable::ClkTck).unwrap_or(100) as u64;
    let boot_time = read_boot_time()?;
    let start_secs = boot_time + start_ticks / ticks_per_sec;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    now.checked_sub(start_secs)
}

/// # Platform behavior
///
/// On unsupported platforms (neither macOS nor Linux), process uptime
/// cannot be determined and this function always returns `None`.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn uptime_for_pid(_pid: u32) -> Option<u64> {
    None
}

/// Parse `ps` elapsed time format (``[[dd-]hh:]mm:ss``) into seconds.
fn parse_elapsed_time(s: &str) -> Option<u64> {
    let (days, time_str) = match s.split_once('-') {
        Some((day_str, rest)) => (day_str.parse::<u64>().ok()?, rest),
        None => (0, s),
    };

    let mut parts = time_str.split(':');
    let (hours, minutes, seconds) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(m), Some(s), None) => (
            h.parse::<u64>().ok()?,
            m.parse::<u64>().ok()?,
            s.parse::<u64>().ok()?,
        ),
        (Some(m), Some(s), None, None) => (
            0,
            m.parse::<u64>().ok()?,
            s.parse::<u64>().ok()?,
        ),
        _ => return None,
    };

    let day_secs = days.checked_mul(86400)?;
    let hour_secs = hours.checked_mul(3600)?;
    let min_secs = minutes.checked_mul(60)?;
    day_secs.checked_add(hour_secs)?.checked_add(min_secs)?.checked_add(seconds)
}

/// Read the restart count from an append-only file.
/// Parses as u64 first, then clamps to `u32::MAX` to avoid silent zero on overflow.
#[allow(clippy::cast_possible_truncation)] // Intentional: clamped to u32::MAX before cast
fn read_restart_count(path: &Path) -> u32 {
    fs::read_to_string(path)
        .ok()
        .and_then(|c| {
            c.trim()
                .parse::<u64>()
                .ok()
                .map(|v| v.min(u64::from(u32::MAX)) as u32)
        })
        .unwrap_or(0)
}

/// Check if a Unix socket is stale (connection refused or times out).
///
/// Returns `true` if the socket exists but cannot be connected to.
/// Returns `false` if the socket doesn't exist or is connectable.
#[cfg(unix)]
fn check_stale_socket(path: &Path) -> bool {
    use std::os::unix::net::UnixStream;

    // Stale = socket file exists but cannot be connected to.
    path.exists() && UnixStream::connect(path).is_err()
}

/// # Platform behavior
///
/// On non-Unix platforms, Unix socket connectivity cannot be tested. This
/// implementation returns `true` if the path exists (as a best-effort
/// heuristic), but cannot distinguish a live socket from a stale one.
#[cfg(not(unix))]
fn check_stale_socket(path: &Path) -> bool {
    path.exists()
}

/// Read the system boot time from `/proc/stat`.
///
/// Parses the `btime` field, which is the absolute time (in seconds since
/// the Unix epoch) at which the system booted. This value is used to
/// convert per-process start times (expressed in clock ticks since boot)
/// into absolute timestamps for uptime calculation.
///
/// Returns `None` if `/proc/stat` cannot be read or the `btime` line is
/// missing or unparseable.
#[cfg(target_os = "linux")]
fn read_boot_time() -> Option<u64> {
    let stat = fs::read_to_string("/proc/stat").ok()?;
    for line in stat.lines() {
        if let Some(rest) = line.strip_prefix("btime ") {
            return rest.trim().parse::<u64>().ok();
        }
    }
    None
}

impl fmt::Display for DaemonStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Daemon:")?;
        writeln!(f, "  Alive: {}", if self.alive { "yes" } else { "no" })?;
        if let Some(pid) = self.pid {
            writeln!(f, "  PID: {pid}")?;
        }
        if let Some(secs) = self.uptime_secs {
            writeln!(f, "  Uptime: {secs}s")?;
        }
        writeln!(f, "  Restarts: {}", self.restart_count)?;
        writeln!(
            f,
            "  Socket: {}",
            if self.stale_socket { "stale" } else { "ok" }
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Helper: create a temp dir with PID, socket, and restart count files.
    fn setup_test_dir(pid_content: Option<&str>, restart_content: Option<&str>) -> TempDir {
        let dir = TempDir::new().unwrap();
        if let Some(content) = pid_content {
            fs::write(dir.path().join("toride.pid"), content).unwrap();
        }
        if let Some(content) = restart_content {
            fs::write(dir.path().join("restart_count"), content).unwrap();
        }
        dir
    }

    #[test]
    fn collect_returns_default_state_when_no_files() {
        let dir = setup_test_dir(None, None);
        let status = DaemonStatus::collect_with_paths(
            &dir.path().join("toride.pid"),
            &dir.path().join("toride.sock"),
            &dir.path().join("restart_count"),
        );
        assert!(!status.alive);
        assert!(status.pid.is_none());
        assert!(status.uptime_secs.is_none());
        assert_eq!(status.restart_count, 0);
        assert!(!status.stale_socket);
    }

    #[test]
    fn read_pid_file_returns_none_for_missing_file() {
        assert_eq!(read_pid_file(Path::new("/nonexistent/pid")), None);
    }

    #[test]
    fn read_pid_file_returns_none_for_empty_file() {
        let dir = setup_test_dir(Some(""), None);
        assert_eq!(read_pid_file(&dir.path().join("toride.pid")), None);
    }

    #[test]
    fn read_pid_file_returns_none_for_non_numeric_content() {
        let dir = setup_test_dir(Some("not-a-number"), None);
        assert_eq!(read_pid_file(&dir.path().join("toride.pid")), None);
    }

    #[test]
    fn read_pid_file_returns_none_for_mixed_content() {
        let dir = setup_test_dir(Some("123abc"), None);
        assert_eq!(read_pid_file(&dir.path().join("toride.pid")), None);
    }

    #[test]
    fn read_pid_file_parses_valid_pid() {
        let dir = setup_test_dir(Some("42\n"), None);
        assert_eq!(read_pid_file(&dir.path().join("toride.pid")), Some(42));
    }

    #[test]
    fn read_pid_file_parses_pid_without_newline() {
        let dir = setup_test_dir(Some("12345"), None);
        assert_eq!(read_pid_file(&dir.path().join("toride.pid")), Some(12345));
    }

    #[test]
    fn read_pid_file_rejects_pid_zero() {
        // PID 0 targets the process group via kill(0, 0), not a specific process.
        let dir = setup_test_dir(Some("0"), None);
        assert_eq!(read_pid_file(&dir.path().join("toride.pid")), None);
    }

    #[test]
    fn read_pid_file_rejects_negative_pid() {
        let dir = setup_test_dir(Some("-1"), None);
        assert_eq!(read_pid_file(&dir.path().join("toride.pid")), None);
    }

    #[test]
    fn read_pid_file_rejects_whitespace_only() {
        let dir = setup_test_dir(Some("   \n  "), None);
        assert_eq!(read_pid_file(&dir.path().join("toride.pid")), None);
    }

    #[test]
    fn is_process_alive_returns_false_for_invalid_pid() {
        // PID 999999 is very unlikely to exist.
        assert!(!is_process_alive(999_999));
    }

    #[test]
    fn is_process_alive_returns_true_for_self() {
        let pid = std::process::id();
        assert!(is_process_alive(pid), "our own process should be alive");
    }

    #[test]
    fn read_restart_count_returns_zero_for_missing_file() {
        assert_eq!(read_restart_count(Path::new("/nonexistent/count")), 0);
    }

    #[test]
    fn read_restart_count_returns_zero_for_empty_file() {
        let dir = setup_test_dir(None, Some(""));
        assert_eq!(read_restart_count(&dir.path().join("restart_count")), 0);
    }

    #[test]
    fn read_restart_count_returns_zero_for_non_numeric() {
        let dir = setup_test_dir(None, Some("abc"));
        assert_eq!(read_restart_count(&dir.path().join("restart_count")), 0);
    }

    #[test]
    fn read_restart_count_parses_valid_count() {
        let dir = setup_test_dir(None, Some("5"));
        assert_eq!(read_restart_count(&dir.path().join("restart_count")), 5);
    }

    #[test]
    fn read_restart_count_handles_large_values() {
        let dir = setup_test_dir(None, Some("999999"));
        assert_eq!(
            read_restart_count(&dir.path().join("restart_count")),
            999_999
        );
    }

    #[cfg(unix)]
    #[test]
    fn check_stale_socket_returns_false_for_nonexistent() {
        assert!(!check_stale_socket(Path::new("/nonexistent/toride.sock")));
    }

    #[cfg(unix)]
    #[test]
    fn check_stale_socket_returns_true_for_stale_socket() {
        let dir = TempDir::new().unwrap();
        let sock_path = dir.path().join("stale.sock");
        // Create a regular file pretending to be a socket.
        fs::write(&sock_path, "").unwrap();
        assert!(check_stale_socket(&sock_path));
    }

    #[test]
    fn parse_elapsed_time_seconds_only() {
        assert_eq!(parse_elapsed_time("05"), None); // No colon = invalid
    }

    #[test]
    fn parse_elapsed_time_minutes_seconds() {
        assert_eq!(parse_elapsed_time("02:30"), Some(150));
    }

    #[test]
    fn parse_elapsed_time_hours_minutes_seconds() {
        assert_eq!(parse_elapsed_time("01:02:03"), Some(3723));
    }

    #[test]
    fn parse_elapsed_time_days_hours_minutes_seconds() {
        assert_eq!(parse_elapsed_time("2-03:04:05"), Some(183_845));
    }

    #[test]
    fn parse_elapsed_time_zero() {
        assert_eq!(parse_elapsed_time("00:00"), Some(0));
    }

    #[test]
    fn parse_elapsed_time_invalid_format() {
        assert_eq!(parse_elapsed_time("invalid"), None);
    }

    #[test]
    fn parse_elapsed_time_empty_string() {
        assert_eq!(parse_elapsed_time(""), None);
    }

    #[test]
    fn display_contains_section_header() {
        let status = DaemonStatus::collect();
        let output = format!("{status}");
        assert!(output.contains("Daemon:"));
        assert!(output.contains("Alive:"));
        assert!(output.contains("Restarts:"));
        assert!(output.contains("Socket:"));
    }

    #[test]
    fn display_shows_pid_when_present() {
        let status = DaemonStatus {
            alive: true,
            pid: Some(12345),
            uptime_secs: Some(3600),
            restart_count: 2,
            stale_socket: false,
        };
        let output = format!("{status}");
        assert!(output.contains("PID: 12345"));
        assert!(output.contains("Uptime: 3600s"));
    }

    #[test]
    fn display_shows_stale_socket() {
        let status = DaemonStatus {
            alive: false,
            pid: None,
            uptime_secs: None,
            restart_count: 0,
            stale_socket: true,
        };
        let output = format!("{status}");
        assert!(output.contains("Socket: stale"));
    }

    #[test]
    fn serialize_to_json_succeeds() {
        let status = DaemonStatus::collect();
        let json = serde_json::to_string(&status);
        assert!(
            json.is_ok(),
            "serialization should succeed: {:?}",
            json.err()
        );
    }

    #[test]
    fn read_pid_file_rejects_pid_above_i32_max() {
        // PIDs > i32::MAX would wrap to negative when cast, causing kill(-1, 0).
        let dir = setup_test_dir(Some("4294967295"), None);
        assert_eq!(
            read_pid_file(&dir.path().join("toride.pid")),
            None
        );
    }

    #[test]
    fn read_pid_file_accepts_max_i32_pid() {
        let dir = setup_test_dir(Some("2147483647"), None);
        assert_eq!(
            read_pid_file(&dir.path().join("toride.pid")),
            Some(2_147_483_647)
        );
    }

    #[test]
    fn read_pid_file_rejects_pid_zero_with_newline() {
        let dir = setup_test_dir(Some("0\n"), None);
        assert_eq!(read_pid_file(&dir.path().join("toride.pid")), None);
    }

    #[test]
    fn read_restart_count_clamps_overflow_value_to_u32_max() {
        // u32::MAX + 1 clamps to u32::MAX instead of silently returning 0.
        let dir = setup_test_dir(None, Some("4294967296"));
        assert_eq!(
            read_restart_count(&dir.path().join("restart_count")),
            u32::MAX
        );
    }

    #[test]
    fn read_restart_count_handles_whitespace_padded() {
        let dir = setup_test_dir(None, Some(" 5 \n"));
        assert_eq!(read_restart_count(&dir.path().join("restart_count")), 5);
    }

    #[test]
    fn parse_elapsed_time_handles_overflow() {
        // u64::MAX days * 86400 overflows checked_mul, so parse returns None.
        assert_eq!(
            parse_elapsed_time("18446744073709551615-00:00:00"),
            None
        );
    }

    #[test]
    fn snapshot_daemon_status_display() {
        let status = DaemonStatus {
            alive: true,
            pid: Some(54321),
            uptime_secs: Some(86400),
            restart_count: 2,
            stale_socket: false,
        };
        insta::assert_snapshot!("daemon_status_display", format!("{}", status));
    }

    #[cfg(unix)]
    #[test]
    fn check_stale_socket_with_real_stale_socket() {
        use std::os::unix::net::UnixListener;

        let dir = TempDir::new().unwrap();
        let sock_path = dir.path().join("real.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        // Drop the listener; the socket file persists but no one is listening.
        drop(listener);

        // The socket file exists but no server is bound — should be stale.
        // Note: on some platforms the file may be removed on drop, in which
        // case check_stale_socket returns false (socket doesn't exist).
        // We only assert stale=true if the file still exists after drop.
        if sock_path.exists() {
            assert!(
                check_stale_socket(&sock_path),
                "dropped listener socket should be stale"
            );
        }
    }

    // ============================================================
    // read_pid_file edge cases
    // ============================================================

    #[test]
    fn read_pid_file_rejects_only_tabs_and_newlines() {
        let dir = setup_test_dir(Some("\t\n\t\n  \t\n"), None);
        assert_eq!(read_pid_file(&dir.path().join("toride.pid")), None);
    }

    #[test]
    fn read_pid_file_parses_leading_zeros() {
        // "007" should parse as 7 — leading zeros are valid decimal.
        let dir = setup_test_dir(Some("007"), None);
        assert_eq!(read_pid_file(&dir.path().join("toride.pid")), Some(7));
    }

    #[test]
    fn read_pid_file_rejects_u32_max_value() {
        // u32::MAX (4294967295) is above i32::MAX and must be rejected.
        let dir = setup_test_dir(Some("4294967295"), None);
        assert_eq!(read_pid_file(&dir.path().join("toride.pid")), None);
    }

    #[test]
    fn read_pid_file_rejects_unicode_content() {
        let dir = setup_test_dir(Some("PID: \u{03c0}"), None);
        assert_eq!(read_pid_file(&dir.path().join("toride.pid")), None);
    }

    #[test]
    fn read_pid_file_rejects_null_bytes() {
        let dir = setup_test_dir(Some("123\0"), None);
        assert_eq!(read_pid_file(&dir.path().join("toride.pid")), None);
    }

    // ============================================================
    // read_restart_count edge cases
    // ============================================================

    #[test]
    fn read_restart_count_parses_zero() {
        let dir = setup_test_dir(None, Some("0"));
        assert_eq!(read_restart_count(&dir.path().join("restart_count")), 0);
    }

    #[test]
    fn read_restart_count_returns_zero_for_negative_number() {
        // "-1" fails u64 parsing, so we get the default 0.
        let dir = setup_test_dir(None, Some("-1"));
        assert_eq!(read_restart_count(&dir.path().join("restart_count")), 0);
    }

    #[test]
    fn read_restart_count_returns_zero_for_floating_point() {
        // "3.14" fails u64 parsing, so we get the default 0.
        let dir = setup_test_dir(None, Some("3.14"));
        assert_eq!(read_restart_count(&dir.path().join("restart_count")), 0);
    }

    #[test]
    fn read_restart_count_clamps_very_large_u64_value() {
        // A value much larger than u32::MAX should clamp to u32::MAX.
        let dir = setup_test_dir(None, Some("18446744073709551615"));
        assert_eq!(
            read_restart_count(&dir.path().join("restart_count")),
            u32::MAX
        );
    }

    // ============================================================
    // parse_elapsed_time edge cases
    // ============================================================

    #[test]
    fn parse_elapsed_time_rejects_single_digit_seconds() {
        // "5" has no colon separator, so it must be rejected.
        assert_eq!(parse_elapsed_time("5"), None);
    }

    #[test]
    fn parse_elapsed_time_rejects_multiple_dashes() {
        // "1-2-03:04:05" — split_once('-') yields day="1", rest="2-03:04:05"
        // which then fails to parse as HH:MM:SS.
        assert_eq!(parse_elapsed_time("1-2-03:04:05"), None);
    }

    #[test]
    fn parse_elapsed_time_handles_large_day_count() {
        // 365 days = 31536000 seconds, well within u64 range.
        assert_eq!(parse_elapsed_time("365-00:00:00"), Some(31_536_000));
    }

    #[test]
    fn parse_elapsed_time_rejects_empty_parts_double_colon() {
        // "::" produces empty strings that fail u64 parsing.
        assert_eq!(parse_elapsed_time("::"), None);
    }

    #[test]
    fn parse_elapsed_time_parses_leading_zeros() {
        // "01:02:03" = 1h 2m 3s = 3723 seconds.
        assert_eq!(parse_elapsed_time("01:02:03"), Some(3723));
    }

    // ============================================================
    // Display edge cases
    // ============================================================

    #[test]
    fn display_with_all_fields_at_zero_or_none() {
        let status = DaemonStatus {
            alive: false,
            pid: None,
            uptime_secs: None,
            restart_count: 0,
            stale_socket: false,
        };
        let output = format!("{status}");
        assert!(output.contains("Alive: no"));
        assert!(output.contains("Restarts: 0"));
        assert!(output.contains("Socket: ok"));
        // PID and Uptime lines should be absent when None.
        assert!(!output.contains("PID:"));
        assert!(!output.contains("Uptime:"));
    }

    #[test]
    fn display_with_very_large_uptime() {
        let status = DaemonStatus {
            alive: true,
            pid: Some(1),
            uptime_secs: Some(u64::MAX),
            restart_count: 0,
            stale_socket: false,
        };
        let output = format!("{status}");
        assert!(output.contains(&format!("Uptime: {}s", u64::MAX)));
    }

    // ============================================================
    // collect_with_paths edge cases
    // ============================================================

    #[test]
    fn collect_with_paths_in_nonexistent_directories() {
        // All paths point into directories that don't exist.
        let status = DaemonStatus::collect_with_paths(
            Path::new("/nonexistent/dir/toride.pid"),
            Path::new("/nonexistent/dir/toride.sock"),
            Path::new("/nonexistent/dir/restart_count"),
        );
        assert!(!status.alive);
        assert!(status.pid.is_none());
        assert!(status.uptime_secs.is_none());
        assert_eq!(status.restart_count, 0);
        assert!(!status.stale_socket);
    }

    #[cfg(unix)]
    #[test]
    fn collect_with_paths_with_special_characters() {
        let dir = TempDir::new().unwrap();
        // Create paths with spaces and special chars in the filename.
        let pid_path = dir.path().join("my daemon [v2].pid");
        let sock_path = dir.path().join("my daemon [v2].sock");
        let restart_path = dir.path().join("restart #count");
        fs::write(&pid_path, "12345").unwrap();
        fs::write(&restart_path, "3").unwrap();

        let status = DaemonStatus::collect_with_paths(&pid_path, &sock_path, &restart_path);
        assert_eq!(status.pid, Some(12345));
        assert_eq!(status.restart_count, 3);
    }
}
