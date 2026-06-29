//! `ControlMaster` session management.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use toride_ssh_core::Result;

/// A single active SSH `ControlMaster` session.
#[derive(Debug, Clone)]
pub struct ControlSession {
    /// Path to the control socket.
    pub control_path: PathBuf,
    /// Host alias or `[user@]host` from the session.
    pub host: String,
    /// When the control socket was created (file modification time).
    pub established: SystemTime,
}

/// List active `ControlMaster` sessions by scanning for control sockets.
///
/// Scans the SSH directory (and any `ControlPath` pattern locations) for Unix
/// domain socket files that resemble OpenSSH `ControlMaster` sockets, then
/// verifies each is still alive using `ssh -O check`.
///
/// # Common socket patterns
///
/// OpenSSH places control sockets at the path specified by `ControlPath` in
/// `~/.ssh/config`. The default location varies by distro but common patterns
/// include:
///
/// - `~/.ssh/cm-%r@%h:%p`
/// - `~/.ssh/ctrl-%C`
/// - `/tmp/ssh-%r@%h:%p-*`
///
/// This function scans `ssh_dir` and `/tmp` for files that look like control
/// sockets.
pub async fn list_sessions(ssh_dir: &Path) -> Result<Vec<ControlSession>> {
    let mut sessions = Vec::new();
    let mut candidates = Vec::new();

    if ssh_dir.exists() {
        let mut entries = tokio::fs::read_dir(ssh_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if is_control_socket_candidate(&path).await {
                candidates.push(path);
            }
        }
    }

    let tmp_dir = std::env::temp_dir();
    if let Ok(mut entries) = tokio::fs::read_dir(&tmp_dir).await {
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if name.starts_with("ssh-") && is_control_socket_candidate(&path).await {
                candidates.push(path);
            }
        }
    }

    for socket_path in candidates {
        let host = extract_host_from_socket_path(&socket_path);

        match verify_control_session(&socket_path).await {
            Some(true) => {
                // The socket may have disappeared between the check above and now
                // (race with another process cleaning it up). Treat a missing file
                // as "session gone" rather than a fatal error.
                let Ok(metadata) = tokio::fs::metadata(&socket_path).await else {
                    continue;
                };
                let established = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);

                sessions.push(ControlSession {
                    control_path: socket_path,
                    host,
                    established,
                });
            }
            Some(false) => {
                // Dead socket — clean it up.
                if let Err(e) = tokio::fs::remove_file(&socket_path).await {
                    tracing::debug!(
                        "failed to remove dead socket {}: {e}",
                        socket_path.display()
                    );
                }
            }
            None => {
                // ssh binary not found — cannot determine status, skip cleanup
                // to avoid destroying active sessions.
                tracing::debug!(
                    "skipping socket {}: ssh binary not available",
                    socket_path.display()
                );
            }
        }
    }

    sessions.sort_by_key(|s| std::cmp::Reverse(s.established));

    Ok(sessions)
}

/// Check if a file looks like an SSH control socket.
///
/// On Unix, control sockets are Unix domain sockets. We check the file type
/// heuristically by looking at the name pattern first, then verifying it's
/// a socket.
async fn is_control_socket_candidate(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();

    let is_match = name.starts_with("cm-")
        || name.starts_with("ctrl-")
        || name.starts_with("mux-")
        || name.starts_with("ssh-")
        || name.contains('@');

    if !is_match {
        return false;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        let Ok(metadata) = tokio::fs::metadata(path).await else {
            return false;
        };
        metadata.file_type().is_socket()
    }

    #[cfg(not(unix))]
    {
        path.exists()
    }
}

/// Try to extract a host identifier from the socket path.
///
/// Socket paths often contain the host, e.g.:
/// - `cm-root@server.example.com:22` -> `root@server.example.com`
/// - `ctrl-1234abcd` -> `1234abcd`
/// - `ssh-user@host:22-abc` -> `user@host`
pub(crate) fn extract_host_from_socket_path(path: &Path) -> String {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    let stripped = name
        .strip_prefix("cm-")
        .or_else(|| name.strip_prefix("control-"))
        .or_else(|| name.strip_prefix("ctrl-"))
        .or_else(|| name.strip_prefix("mux-"))
        .or_else(|| name.strip_prefix("ssh-"))
        .unwrap_or(name);

    // Strip trailing port and random suffix, e.g. "root@host:22-abc" -> "root@host".
    if let Some(at_pos) = stripped.find('@') {
        let after_at = &stripped[at_pos..];
        if let Some(colon) = after_at.find(':') {
            return stripped[..at_pos + colon].to_string();
        }
        if let Some(dash) = after_at.find('-') {
            return stripped[..at_pos + dash].to_string();
        }
        return stripped.to_string();
    }

    // If there's no `@`, try to strip `:port` from any position.
    if let Some(colon) = stripped.find(':') {
        return stripped[..colon].to_string();
    }

    stripped.to_string()
}

/// Verify a control socket is still active using `ssh -O check`.
///
/// Returns `true` if `ssh -O check` exits with code 0 (master running).
/// Returns `None` if the `ssh` binary itself cannot be executed (not in PATH),
/// which is different from "master not running".
async fn verify_control_session(socket_path: &Path) -> Option<bool> {
    let path_str = match socket_path.to_str() {
        Some(s) => s.to_owned(),
        None => return Some(false),
    };

    // We need a dummy host argument for ssh -O check.  The host can be
    // anything since the -S option specifies the control socket path.
    // Using "localhost" as a placeholder.
    let result = tokio::task::spawn_blocking(move || {
        duct::cmd("ssh", ["-S", &path_str, "-O", "check", "localhost"])
            .stdout_null()
            .stderr_null()
            .run()
    })
    .await;

    match result {
        Ok(Ok(_)) => Some(true), // exit code 0 = master running
        Ok(Err(e)) => {
            // Distinguish between "ssh not found" and "master not running".
            // duct returns io::Error; when the binary is not found, kind is NotFound.
            if e.kind() == std::io::ErrorKind::NotFound {
                // ssh binary not in PATH — cannot determine status
                tracing::warn!("ssh binary not found, cannot check control socket");
                return None;
            }
            Some(false) // non-zero exit = master not running
        }
        Err(_) => Some(false), // task panic = treat as dead
    }
}

#[cfg(test)]
#[path = "session.test.rs"]
mod tests;
