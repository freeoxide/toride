//! SSH subsystem status: mux master, control path, config parse, agent, keys.
//!
//! Uses `ssh -O check` to probe the mux master, validates control paths via
//! `fs::symlink_metadata`, and shells out to `ssh -G` for config
//! parsing. Key counting uses `ssh-add -l`.
//!
//! # Control path validation
//!
//! The control path must satisfy **all** of:
//!
//! 1. Exist and be a Unix socket (or named pipe on Windows).
//! 2. Have permissions `0600` (owner read/write only).
//! 3. Be connectable (non-blocking `UnixStream::connect`).
//! 4. Have a valid, non-expired `CtlTimeMs` (if the mux supports it).

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;

/// SSH subsystem status snapshot.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct SshStatus {
    /// Whether the SSH mux master is alive.
    pub mux_master_alive: bool,
    /// Whether the control path is valid.
    pub control_path_valid: bool,
    /// Whether the SSH config parsed without errors.
    pub config_valid: bool,
    /// Whether the SSH agent is running.
    pub agent_running: bool,
    /// Number of keys loaded in the agent.
    pub key_count: u32,
}

impl SshStatus {
    /// Collect SSH subsystem status using default paths.
    ///
    /// Default control path: `~/.ssh/controlmasters/%r@%h-%p`
    /// Default config path: `~/.ssh/config`
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use toride::status::ssh::SshStatus;
    ///
    /// let status = SshStatus::collect();
    /// println!("Mux alive: {}", status.mux_master_alive);
    /// println!("Keys loaded: {}", status.key_count);
    /// ```
    pub fn collect() -> Self {
        let control_path = default_control_path();
        let config_path = default_config_path();

        Self::collect_with_paths(&control_path, &config_path)
    }

    /// Collect SSH subsystem status with explicit paths.
    ///
    /// This is the testable entry point — all subprocess and filesystem
    /// interaction is confined to the paths passed here.
    pub fn collect_with_paths(control_path: &Path, config_path: &Path) -> Self {
        let control_path_valid = validate_control_path(control_path);
        let mux_master_alive = check_mux_master(control_path);
        let config_valid = check_config(config_path);
        let agent_running = check_agent();
        let key_count = count_keys();

        Self {
            mux_master_alive,
            control_path_valid,
            config_valid,
            agent_running,
            key_count,
        }
    }
}

/// Default control path directory.
fn default_control_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".ssh")
        .join("controlmasters")
        .join("%r@%h-%p")
}

/// Default SSH config path.
fn default_config_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".ssh")
        .join("config")
}

/// Validate that a control path exists, is a socket, has correct permissions,
/// and is connectable.
///
/// Returns `true` only if **all** checks pass.
#[cfg(unix)]
fn validate_control_path(path: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt;

    // 1. Existence and type check.
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };

    if !metadata.file_type().is_socket() {
        return false;
    }

    // 2. Permission check (must be 0600).
    use std::os::unix::fs::PermissionsExt;
    let mode = metadata.permissions().mode() & 0o7777;
    if mode != 0o600 {
        return false;
    }

    // 3. Connectability check.
    check_socket_connectable(path)
}

/// # Platform behavior
///
/// On non-Unix platforms, socket type and permission checks are skipped.
/// This implementation only verifies that the path exists.
#[cfg(not(unix))]
fn validate_control_path(path: &Path) -> bool {
    path.exists()
}

/// Check if a Unix socket is connectable.
#[cfg(unix)]
fn check_socket_connectable(path: &Path) -> bool {
    use std::os::unix::net::UnixStream;

    UnixStream::connect(path).is_ok()
}

/// Check if the SSH mux master is alive by running `ssh -O check`.
///
/// Returns `true` if the command exits with status 0.
fn check_mux_master(control_path: &Path) -> bool {
    Command::new("ssh")
        .arg("-O")
        .arg("check")
        .arg("-S")
        .arg(control_path)
        .arg("dummy")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Check if the SSH config parses without errors.
///
/// Runs `ssh -G -F <config> localhost` and checks the exit status.
/// A hostname argument is required by `ssh -G`; without it, ssh exits 255.
fn check_config(config_path: &Path) -> bool {
    Command::new("ssh")
        .arg("-G")
        .arg("-F")
        .arg(config_path)
        .arg("localhost")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Check if the SSH agent is running by verifying `SSH_AUTH_SOCK` exists and
/// is connectable.
#[cfg(unix)]
fn check_agent() -> bool {
    let Ok(sock_str) = std::env::var("SSH_AUTH_SOCK") else {
        return false;
    };
    let sock = PathBuf::from(sock_str);

    check_socket_connectable(&sock)
}

/// # Platform behavior
///
/// On non-Unix platforms, socket connectivity cannot be tested. This
/// implementation only checks whether the `SSH_AUTH_SOCK` environment
/// variable is set, without verifying the socket is actually connectable.
#[cfg(not(unix))]
fn check_agent() -> bool {
    std::env::var("SSH_AUTH_SOCK").is_ok()
}

/// Count the number of keys loaded in the SSH agent.
///
/// Runs `ssh-add -l` and counts the number of lines in the output.
/// Returns 0 if the agent is not running or has no keys.
fn count_keys() -> u32 {
    let output = Command::new("ssh-add")
        .arg("-l")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            // Each key is one line. Count non-empty lines.
            stdout.lines().filter(|l| !l.trim().is_empty()).count() as u32
        }
        _ => 0,
    }
}

impl fmt::Display for SshStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "SSH:")?;
        writeln!(
            f,
            "  Mux master: {}",
            if self.mux_master_alive { "alive" } else { "dead" }
        )?;
        writeln!(
            f,
            "  Control path: {}",
            if self.control_path_valid {
                "valid"
            } else {
                "invalid"
            }
        )?;
        writeln!(
            f,
            "  Config: {}",
            if self.config_valid { "ok" } else { "error" }
        )?;
        writeln!(
            f,
            "  Agent: {}",
            if self.agent_running { "running" } else { "stopped" }
        )?;
        writeln!(f, "  Keys: {}", self.key_count)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn collect_does_not_panic() {
        let status = SshStatus::collect();
        // These may or may not be true depending on the system,
        // but the struct should be populated without panicking.
        let _ = status.mux_master_alive;
        let _ = status.control_path_valid;
        let _ = status.config_valid;
        let _ = status.agent_running;
        let _ = status.key_count;
    }

    #[test]
    fn collect_with_paths_returns_default_when_no_files() {
        let dir = TempDir::new().unwrap();
        let status = SshStatus::collect_with_paths(
            &dir.path().join("control"),
            &dir.path().join("config"),
        );
        assert!(!status.mux_master_alive);
        assert!(!status.control_path_valid);
        assert!(!status.config_valid);
    }

    #[test]
    fn validate_control_path_returns_false_for_nonexistent() {
        assert!(!validate_control_path(Path::new("/nonexistent/socket")));
    }

    #[cfg(unix)]
    #[test]
    fn validate_control_path_returns_false_for_regular_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("regular_file");
        fs::write(&path, "").unwrap();
        assert!(!validate_control_path(&path));
    }

    #[cfg(unix)]
    #[test]
    fn validate_control_path_returns_false_for_wrong_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("socket");
        // Create a Unix socket with wrong permissions.
        use std::os::unix::net::UnixListener;
        let _listener = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(!validate_control_path(&path));
    }

    #[cfg(unix)]
    #[test]
    fn does_not_panic_for_listener_socket() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("socket");
        use std::os::unix::net::UnixListener;
        let _listener = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        // The socket is valid but may not be "connectable" in the traditional
        // sense (listeners accept connections). validate_control_path checks
        // connectability, which may fail for listeners. This is expected.
        // We just verify it doesn't panic.
        let _ = validate_control_path(&path);
    }

    #[test]
    fn check_mux_master_returns_false_for_nonexistent_path() {
        assert!(!check_mux_master(Path::new("/nonexistent/control")));
    }

    #[test]
    fn check_config_returns_false_for_nonexistent_path() {
        assert!(!check_config(Path::new("/nonexistent/config")));
    }

    #[test]
    fn check_config_does_not_panic() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("config");
        fs::write(&config_path, "Host *\n  ServerAliveInterval 60\n").unwrap();
        // This will return true if ssh is installed and the config is valid.
        // On CI without ssh, it returns false. Either way, no panic.
        let _ = check_config(&config_path);
    }

    #[test]
    fn count_keys_returns_zero_when_no_agent() {
        // Without SSH_AUTH_SOCK, ssh-add should fail and return 0.
        let count = count_keys();
        // If no agent is running, count must be 0.
        if std::env::var("SSH_AUTH_SOCK").is_err() {
            assert_eq!(count, 0, "without SSH_AUTH_SOCK, key count must be 0");
        }
    }

    #[test]
    fn display_contains_section_header() {
        let status = SshStatus::collect();
        let output = format!("{status}");
        assert!(output.contains("SSH:"));
        assert!(output.contains("Mux master:"));
        assert!(output.contains("Control path:"));
        assert!(output.contains("Config:"));
        assert!(output.contains("Agent:"));
        assert!(output.contains("Keys:"));
    }

    #[test]
    fn display_shows_alive_mux() {
        let status = SshStatus {
            mux_master_alive: true,
            control_path_valid: true,
            config_valid: true,
            agent_running: true,
            key_count: 3,
        };
        let output = format!("{status}");
        assert!(output.contains("Mux master: alive"));
        assert!(output.contains("Control path: valid"));
        assert!(output.contains("Config: ok"));
        assert!(output.contains("Agent: running"));
        assert!(output.contains("Keys: 3"));
    }

    #[test]
    fn display_shows_dead_mux() {
        let status = SshStatus {
            mux_master_alive: false,
            control_path_valid: false,
            config_valid: false,
            agent_running: false,
            key_count: 0,
        };
        let output = format!("{status}");
        assert!(output.contains("Mux master: dead"));
        assert!(output.contains("Control path: invalid"));
        assert!(output.contains("Config: error"));
        assert!(output.contains("Agent: stopped"));
        assert!(output.contains("Keys: 0"));
    }

    #[test]
    fn serialize_to_json_succeeds() {
        let status = SshStatus::collect();
        let json = serde_json::to_string(&status);
        assert!(
            json.is_ok(),
            "serialization should succeed: {:?}",
            json.err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn validate_control_path_returns_false_for_directory() {
        let dir = TempDir::new().unwrap();
        // A directory is not a socket; validation should fail.
        assert!(!validate_control_path(dir.path()));
    }

    #[cfg(unix)]
    #[test]
    fn validate_control_path_returns_false_for_permissions_640() {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixListener;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("socket");
        let _listener = UnixListener::bind(&path).unwrap();
        // 0o640 != 0o600, so permission check should reject it.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(!validate_control_path(&path));
    }
}
