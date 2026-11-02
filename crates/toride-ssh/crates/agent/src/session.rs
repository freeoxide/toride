//! `ControlMaster` session management.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use toride_ssh_core::Result;
use toride_ssh_core::control_master::ControlName;
use toride_ssh_core::control_master::collect_control_candidates;
use toride_ssh_core::control_master::collect_control_candidates_with;

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

/// A pinned, `Send` verification future as produced by [`VerifyFn`].
// Boxing keeps one concrete `Send` future type for the fan-out
// (rust-lang/rust#110338).
pub type BoxedVerifyFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = Option<bool>> + Send>>;

/// Verifier injected into [`list_sessions_with`]: `Some(true)` means a live
/// master, `Some(false)` a dead socket, `None` that `ssh` is unavailable.
pub type VerifyFn<'a> = &'a (dyn Fn(PathBuf) -> BoxedVerifyFuture + Send + Sync);

/// List active `ControlMaster` sessions by scanning for control sockets.
///
/// Scans `ssh_dir` and `/tmp` for Unix domain socket files that resemble
/// OpenSSH `ControlMaster` sockets, then verifies each is still alive via
/// `ssh -O check`. OpenSSH places control sockets at the `ControlPath`
/// pattern from `~/.ssh/config`; common patterns include `~/.ssh/cm-%r@%h:%p`,
/// `~/.ssh/ctrl-%C`, and `/tmp/ssh-%r@%h:%p-*`.
///
/// # Errors
///
/// Returns [`toride_ssh_core::Error::Io`] if `ssh_dir` cannot be read.
pub async fn list_sessions(ssh_dir: &Path) -> Result<Vec<ControlSession>> {
    list_sessions_with(ssh_dir, &|socket_path| {
        Box::pin(verify_control_session(socket_path))
    })
    .await
}

/// [`list_sessions`](fn@list_sessions) with an injected verifier.
///
/// The verifier replaces the `ssh -O check` spawn so tests and benches can
/// measure the bounded fan-out without a real `ssh` binary.
///
/// # Errors
///
/// Returns [`toride_ssh_core::Error::Io`] if `ssh_dir` cannot be read.
pub async fn list_sessions_with(
    ssh_dir: &Path,
    verify: VerifyFn<'_>,
) -> Result<Vec<ControlSession>> {
    let ssh_dir = ssh_dir.to_path_buf();
    let tmp_dir = std::env::temp_dir();

    let candidates = tokio::task::spawn_blocking(move || {
        let ssh_dir_candidates = collect_control_candidates_with(
            &ssh_dir,
            |name| SSH_DIR_NAME_PREFIXES.iter().any(|p| name.starts_with(p)) || name.contains('@'),
            false,
        )?;
        let tmp_candidates =
            collect_control_candidates(&tmp_dir, &["ssh-"], false).unwrap_or_default();
        Ok::<_, std::io::Error>(
            ssh_dir_candidates
                .into_iter()
                .chain(tmp_candidates)
                .map(|candidate| candidate.path)
                .collect::<Vec<PathBuf>>(),
        )
    })
    .await
    .map_err(|e| toride_ssh_core::Error::TaskFailed(e.to_string()))??;

    let checks: Vec<BoxedVerifyFuture> = candidates
        .iter()
        .map(|socket_path| {
            let socket_path = socket_path.clone();
            let fut: BoxedVerifyFuture = verify(socket_path);
            fut
        })
        .collect();
    let alive_flags =
        toride_ssh_core::fanout::join_all_bounded(MAX_CONCURRENT_CHECKS, checks).await;

    let mut sessions = Vec::new();
    for (socket_path, alive) in candidates.into_iter().zip(alive_flags) {
        match alive {
            Some(true) => {
                // The socket may vanish between the check and this read (a
                // concurrent cleanup); a missing file means the session is
                // gone, not an error.
                let Ok(metadata) = tokio::fs::metadata(&socket_path).await else {
                    continue;
                };
                let established = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);

                sessions.push(ControlSession {
                    host: extract_host_from_socket_path(&socket_path),
                    control_path: socket_path,
                    established,
                });
            }
            Some(false) => {
                // Dead socket, clean it up.
                if let Err(e) = tokio::fs::remove_file(&socket_path).await {
                    tracing::debug!(
                        "failed to remove dead socket {}: {e}",
                        socket_path.display()
                    );
                }
            }
            None => {
                // ssh binary not found, cannot determine status, skip cleanup
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

const MAX_CONCURRENT_CHECKS: usize = 8;

const SSH_DIR_NAME_PREFIXES: &[&str] = &["cm-", "ctrl-", "mux-", "ssh-"];

/// Render the `user@host` identifier of a control socket from its path,
/// e.g. `cm-root@server.example.com:22` -> `root@server.example.com`.
pub(crate) fn extract_host_from_socket_path(path: &Path) -> String {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    let parts = ControlName::parse(name);
    match parts.user {
        Some(user) => format!("{user}@{}", parts.host),
        None => parts.host,
    }
}

/// Verify a control socket is still active using `ssh -O check`.
///
/// Returns `true` if `ssh -O check` exits with code 0 (master running).
/// Returns `None` if the `ssh` binary itself cannot be executed (not in PATH),
/// which is different from "master not running".
async fn verify_control_session(socket_path: std::path::PathBuf) -> Option<bool> {
    let path_str = match socket_path.to_str() {
        Some(s) => s.to_owned(),
        None => return Some(false),
    };

    // The destination operand is syntactically required but ignored by the
    // mux protocol; -S selects the socket.
    let result = tokio::task::spawn_blocking(move || {
        duct::cmd("ssh", ["-S", &path_str, "-O", "check", "localhost"])
            .stdout_null()
            .stderr_null()
            .run()
    })
    .await;

    match result {
        Ok(Ok(_)) => Some(true),
        Ok(Err(e)) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                tracing::warn!("ssh binary not found, cannot check control socket");
                return None;
            }
            Some(false)
        }
        Err(_) => Some(false),
    }
}

#[cfg(test)]
#[path = "session.test.rs"]
mod tests;
