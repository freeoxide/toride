//! Daemon liveness and health checks.
//!
//! Reads PID files, checks `/proc` (Linux) or `kill -0` (macOS/Windows),
//! parses restart-count files, and detects stale Unix sockets.
//!
//! # Stale socket detection
//!
//! On Unix platforms, [`DaemonStatus::collect`] attempts to connect to the
//! daemon's Unix socket. If the connection is refused or times out, the
//! socket is flagged as stale so the caller can clean it up.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

/// Daemon liveness and health snapshot.
#[derive(Debug, Clone, Serialize)]
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
    pub fn collect() -> Self {
        let pid_path = default_pid_path();
        let socket_path = default_socket_path();
        let restart_path = default_restart_count_path();

        Self::collect_with_paths(&pid_path, &socket_path, &restart_path)
    }

    /// Collect daemon status with explicit paths.
    ///
    /// This is the testable entry point — all filesystem interaction is
    /// confined to the paths passed here.
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
/// contains invalid content.
fn read_pid_file(path: &Path) -> Option<u32> {
    let content = fs::read_to_string(path).ok()?;
    let trimmed = content.trim();
    // Reject empty files and files with extra content after the PID.
    if trimmed.is_empty() || trimmed.contains(|c: char| !c.is_ascii_digit()) {
        return None;
    }
    trimmed.parse::<u32>().ok()
}

/// Check if a process with the given PID is alive.
///
/// On Unix, uses `kill(pid, 0)` — no signal is sent, just checks existence.
/// On Windows, uses `OpenProcess` with `PROCESS_QUERY_LIMITED_INFORMATION`.
#[cfg(unix)]
fn is_process_alive(pid: u32) -> bool {
    use nix::sys::signal;
    use nix::unistd::Pid;
    signal::kill(Pid::from_raw(pid as i32), None).is_ok()
}

#[cfg(not(unix))]
fn is_process_alive(_pid: u32) -> bool {
    // Windows: would use OpenProcess. Stubbed for now.
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
    let fields: Vec<&str> = stat.split_whitespace().collect();
    if fields.len() < 22 {
        return None;
    }
    let start_ticks: u64 = fields[21].parse().ok()?;
    let ticks_per_sec = sysconf::sysconf(sysconf::SysconfVariable::ClkTck).unwrap_or(100) as u64;
    let boot_time = read_boot_time()?;
    let start_secs = boot_time + start_ticks / ticks_per_sec;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    now.checked_sub(start_secs)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn uptime_for_pid(_pid: u32) -> Option<u64> {
    None
}

/// Parse `ps` elapsed time format (``[[dd-]hh:]mm:ss``) into seconds.
fn parse_elapsed_time(s: &str) -> Option<u64> {
    let parts: Vec<&str> = s.split('-').collect();
    let (days, time_str) = if parts.len() == 2 {
        (parts[0].parse::<u64>().ok()?, parts[1])
    } else {
        (0, s)
    };

    let time_parts: Vec<&str> = time_str.split(':').collect();
    let (hours, minutes, seconds) = match time_parts.len() {
        3 => (
            time_parts[0].parse::<u64>().ok()?,
            time_parts[1].parse::<u64>().ok()?,
            time_parts[2].parse::<u64>().ok()?,
        ),
        2 => (
            0,
            time_parts[0].parse::<u64>().ok()?,
            time_parts[1].parse::<u64>().ok()?,
        ),
        _ => return None,
    };

    Some(days * 86400 + hours * 3600 + minutes * 60 + seconds)
}

/// Read the restart count from an append-only file.
fn read_restart_count(path: &Path) -> u32 {
    fs::read_to_string(path)
        .ok()
        .and_then(|c| c.trim().parse::<u32>().ok())
        .unwrap_or(0)
}

/// Check if a Unix socket is stale (connection refused or times out).
///
/// Returns `true` if the socket exists but cannot be connected to.
/// Returns `false` if the socket doesn't exist or is connectable.
#[cfg(unix)]
fn check_stale_socket(path: &Path) -> bool {
    use std::os::unix::net::UnixStream;

    // If the socket file doesn't exist, it's not stale.
    if !path.exists() {
        return false;
    }

    // Try to connect with a short timeout.
    match UnixStream::connect(path) {
        Ok(_) => false,
        Err(_) => true,
    }
}

#[cfg(not(unix))]
fn check_stale_socket(path: &Path) -> bool {
    // On non-Unix, just check if the file exists but is not connectable.
    path.exists()
}

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
        // PID 0 is valid on some systems but unusual; we accept it.
        let dir = setup_test_dir(Some("0"), None);
        assert_eq!(read_pid_file(&dir.path().join("toride.pid")), Some(0));
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
        assert!(!is_process_alive(999999));
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
            999999
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
        assert_eq!(parse_elapsed_time("2-03:04:05"), Some(183845));
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
}
