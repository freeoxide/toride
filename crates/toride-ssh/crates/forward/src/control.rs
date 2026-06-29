//! Port forwarding control via `ControlMaster` sessions.

#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use toride_ssh_core::{Error, Result};

/// Maximum file size (bytes) for a candidate control socket on non-socket
/// filesystems (e.g. NFS). Files larger than this are not considered sockets.
const MAX_CONTROL_SOCKET_CANDIDATE_SIZE: u64 = 1024;

/// Whether a forward is local (-L), remote (-R), or dynamic/SOCKS (-D).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ForwardType {
    /// `-L` local port forward.
    Local,
    /// `-R` remote port forward.
    Remote,
    /// `-D` dynamic (SOCKS proxy) forward.
    Dynamic,
}

impl std::fmt::Display for ForwardType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local => write!(f, "local"),
            Self::Remote => write!(f, "remote"),
            Self::Dynamic => write!(f, "dynamic"),
        }
    }
}

/// A single active port forward on a `ControlMaster` session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortForward {
    /// Local bind address (e.g. `127.0.0.1` or `*`).
    pub local_addr: String,
    /// Local listening port.
    pub local_port: u16,
    /// Remote address the forward targets.
    pub remote_addr: String,
    /// Remote port the forward targets.
    pub remote_port: u16,
    /// Whether this is a local, remote, or dynamic forward.
    pub forward_type: ForwardType,
}

/// A discovered `ControlMaster` session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlSession {
    /// Path to the control socket.
    pub control_path: PathBuf,
    /// Host alias or hostname the session is connected to.
    pub host: String,
    /// PID of the master SSH process, if known.
    pub pid: Option<u32>,
    /// When the session was established, if determinable.
    pub established: Option<std::time::SystemTime>,
}

/// Run an SSH control command (`-O <action>`) and return stdout.
async fn ssh_control_cmd(control_path: &Path, action: &str) -> Result<String> {
    let path_str = control_path
        .to_str()
        .ok_or_else(|| Error::ForwardFailed("control path is not valid UTF-8".into()))?;

    let action = action.to_owned();
    let path = path_str.to_owned();

    tokio::task::spawn_blocking(move || {
        duct::cmd("ssh", ["-O", &action, "-S", &path, "-x", "nohost"])
            .stderr_to_stdout()
            .read()
            .map_err(|e| Error::CommandFailed(format!("ssh -O {action}: {e}")))
    })
    .await
    .map_err(|e| Error::TaskFailed(e.to_string()))?
}

/// Check whether a control socket is still alive.
async fn check_alive(control_path: &Path) -> bool {
    ssh_control_cmd(control_path, "check").await.is_ok()
}

/// List active port forwards on a `ControlMaster` session.
///
/// Sends `ssh -O list -S <control_path>` and parses the output to extract
/// individual forward entries.
///
/// # Errors
///
/// Returns [`Error::ForwardFailed`] if the control path is not valid UTF-8,
/// or [`Error::CommandFailed`] if the `ssh -O list` command fails.
pub async fn list_forwards(control_path: &Path) -> Result<Vec<PortForward>> {
    let output = ssh_control_cmd(control_path, "list").await?;
    Ok(parse_forward_output(&output))
}

/// Parse the output of `ssh -O list` into structured forward entries.
///
/// Typical output looks like:
/// ```text
/// Local connections:
///   127.0.0. port 8080, forwarding to 10.0.0.1 port 80
/// Remote connections:
/// Dynamic connections:
///   127.0.0. port 1080
/// ```
///
/// The exact format varies across OpenSSH versions, so the parser is
/// intentionally lenient.
pub(crate) fn parse_forward_output(output: &str) -> Vec<PortForward> {
    let mut forwards = Vec::new();
    let mut current_type: Option<ForwardType> = None;

    for line in output.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("Local connections") {
            current_type = Some(ForwardType::Local);
            continue;
        }
        if trimmed.starts_with("Remote connections") {
            current_type = Some(ForwardType::Remote);
            continue;
        }
        if trimmed.starts_with("Dynamic connections") {
            current_type = Some(ForwardType::Dynamic);
            continue;
        }

        let Some(ft) = current_type else {
            continue;
        };

        // Try to parse a line like:
        //   "127.0.0. port 8080, forwarding to 10.0.0.1 port 80"
        //   "127.0.0.1 port 8080, forwarding to 10.0.0.1 port 80"
        // For dynamic: "127.0.0.1 port 1080"
        if let Some(fwd) = parse_forward_line(trimmed, ft) {
            forwards.push(fwd);
        }
    }

    forwards
}

/// Parse a single forward line from `ssh -O list` output.
///
/// # Safety
///
/// SSH `-O list` output is always ASCII, so byte-level indexing via
/// `find`/`split_at` is safe.
pub(crate) fn parse_forward_line(line: &str, forward_type: ForwardType) -> Option<PortForward> {
    // Two forms:
    //   "<addr> port <lport>, forwarding to <raddr> port <rport>"  (local/remote)
    //   "<addr> port <lport>"                                       (dynamic)
    let line = line.trim_start();

    let port_idx = line.find(" port ")?;
    let local_addr = line[..port_idx].trim().trim_end_matches('.').to_owned();

    let rest = &line[port_idx + 6..]; // skip " port "

    if forward_type == ForwardType::Dynamic {
        // Dynamic: "1080"
        let local_port: u16 = rest.trim().parse().ok()?;
        return Some(PortForward {
            local_addr,
            local_port,
            remote_addr: String::new(),
            remote_port: 0,
            forward_type,
        });
    }

    // Local/Remote: "8080, forwarding to 10.0.0.1 port 80"
    let comma_idx = rest.find(',')?;
    let local_port: u16 = rest[..comma_idx].trim().parse().ok()?;

    let fwd_rest = &rest[comma_idx + 1..];
    let fwd_label = "forwarding to ";
    let fwd_idx = fwd_rest.find(fwd_label)?;
    let rhost_port = &fwd_rest[fwd_idx + fwd_label.len()..];

    // rhost_port: "10.0.0.1 port 80"
    let rport_idx = rhost_port.rfind(" port ")?;
    let remote_addr = rhost_port[..rport_idx].trim().to_owned();
    let remote_port: u16 = rhost_port[rport_idx + 6..].trim().parse().ok()?;

    Some(PortForward {
        local_addr,
        local_port,
        remote_addr,
        remote_port,
        forward_type,
    })
}

/// Cancel a port forward on a `ControlMaster` session.
///
/// For local forwards this sends `ssh -O cancel -L <addr>:<host>:<port> -S <path>`.
/// For remote forwards, `-R` is used instead.  Since we only receive the
/// `local_port`, we first list the forwards to discover the full specification.
///
/// # Race conditions
///
/// There is an inherent TOCTOU race between listing forwards and issuing the
/// cancel command: the forward may vanish between the two calls.  The caller
/// should be prepared to handle [`Error::ForwardNotFound`] or a cancel
/// command that fails due to a stale forward.
///
/// # Errors
///
/// Returns [`Error::ForwardNotFound`] if no forward exists on the given
/// local port, or [`Error::CommandFailed`] if the cancel command fails.
pub async fn cancel_forward(control_path: &Path, local_port: u16) -> Result<()> {
    let forwards = list_forwards(control_path).await?;

    let forward = forwards
        .iter()
        .find(|f| f.local_port == local_port)
        .ok_or_else(|| {
            Error::ForwardNotFound(format!("no forward found on local port {local_port}"))
        })?;

    cancel_known_forward(control_path, forward).await
}

/// Cancel a port forward using a known [`PortForward`] directly (avoids a
/// redundant `list` round-trip).
///
/// # Cancel specification format
///
/// The spec passed to `ssh -O cancel` depends on the forward type:
/// - **Local/Remote**: `[bind_addr]:lport:rhost:rport`
/// - **Dynamic**: `[bind_addr]:lport`
///
/// When `GatewayPorts` is enabled the bind address may be `*` or `0.0.0.0`.
///
/// # Errors
///
/// Returns [`Error::ForwardFailed`] if the control path is not valid UTF-8,
/// or [`Error::CommandFailed`] if the cancel command fails.
pub async fn cancel_known_forward(control_path: &Path, forward: &PortForward) -> Result<()> {
    let path_str = control_path
        .to_str()
        .ok_or_else(|| Error::ForwardFailed("control path is not valid UTF-8".into()))?;

    let flag = match forward.forward_type {
        ForwardType::Local => "-L",
        ForwardType::Remote => "-R",
        ForwardType::Dynamic => "-D",
    };

    let spec = if forward.forward_type == ForwardType::Dynamic {
        format!("[{}]:{}", &forward.local_addr, forward.local_port)
    } else {
        format!(
            "[{}]:{}:{}:{}",
            &forward.local_addr,
            forward.local_port,
            if forward.remote_addr.is_empty() {
                "localhost"
            } else {
                &forward.remote_addr
            },
            forward.remote_port
        )
    };

    let path_owned = path_str.to_owned();

    tokio::task::spawn_blocking(move || {
        duct::cmd(
            "ssh",
            [
                flag,
                spec.as_str(),
                "-O",
                "cancel",
                "-S",
                &path_owned,
                "-x",
                "nohost",
            ],
        )
        .run()
        .map_err(|e| Error::CommandFailed(format!("ssh -O cancel: {e}")))
    })
    .await
    .map_err(|e| Error::TaskFailed(e.to_string()))??;

    Ok(())
}

/// Gracefully close a `ControlMaster` session (`ssh -O exit`).
///
/// After this call the control socket file may still exist on disk (it is
/// cleaned up asynchronously by the master process).  Callers that need to
/// verify cleanup should check for socket file removal separately.
///
/// # Errors
///
/// Returns [`Error::ForwardFailed`] if the control path is not valid UTF-8,
/// or [`Error::CommandFailed`] if the `ssh -O exit` command fails for a
/// reason other than a stale socket.
pub async fn exit_session(control_path: &Path) -> Result<()> {
    let path = control_path.to_path_buf();

    tokio::task::spawn_blocking(move || {
        let path_str = path
            .to_str()
            .ok_or_else(|| Error::ForwardFailed("control path is not valid UTF-8".into()))?;

        // ssh -O exit returns 0 on success; stderr may contain informational text.
        let result = duct::cmd("ssh", ["-O", "exit", "-S", path_str])
            .run()
            .map_err(|e| Error::CommandFailed(format!("ssh -O exit: {e}")));

        // Best-effort cleanup of stale socket file.  OpenSSH normally unlinks
        // the socket, but if the master is already gone the file lingers.
        if result.is_ok() || is_stale_socket(&path) {
            let _ = std::fs::remove_file(&path);
        }

        result
    })
    .await
    .map_err(|e| Error::TaskFailed(e.to_string()))??;

    Ok(())
}

/// Check whether a path looks like a stale (dead) control socket.
fn is_stale_socket(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(meta) => {
            #[cfg(unix)]
            if meta.file_type().is_socket() {
                // Socket file exists but `ssh -O check` presumably failed.
                // It is stale if `connect()` would fail, but we already know
                // it is dead because we only call this after a failed check.
                return true;
            }
            // Small regular file that could be a remnant on non-socket FS.
            meta.is_file() && meta.len() == 0
        }
        Err(_) => false,
    }
}

/// Discover active `ControlMaster` sessions by scanning common socket locations.
///
/// Checks:
/// 1. `~/.ssh/cm-*`, `~/.ssh/control-*`, `~/.ssh/mux-*`, `~/.ssh/ctrl-*`
/// 2. `/tmp/ssh-*` (default OpenSSH location)
/// 3. Any socket file in `~/.ssh/` that looks like a control socket
///
/// Each candidate is verified with `ssh -O check` to confirm it is alive.
///
/// # Errors
///
/// Returns [`Error::TaskFailed`] if the background scan task panics or is
/// cancelled.
pub async fn list_sessions(ssh_dir: &Path) -> Result<Vec<ControlSession>> {
    let ssh_dir = ssh_dir.to_path_buf();
    let tmp_dir = std::path::PathBuf::from("/tmp");

    let sessions = tokio::task::spawn_blocking(move || {
        let mut candidates: Vec<PathBuf> = Vec::new();

        // 1. ~/.ssh/cm-*, ~/.ssh/control-*, ~/.ssh/mux-*, ~/.ssh/ctrl-*
        collect_matching(&ssh_dir, "cm-*", &mut candidates);
        collect_matching(&ssh_dir, "control-*", &mut candidates);
        collect_matching(&ssh_dir, "mux-*", &mut candidates);
        collect_matching(&ssh_dir, "ctrl-*", &mut candidates);

        // 2. /tmp/ssh-*
        collect_matching(&tmp_dir, "ssh-*", &mut candidates);

        candidates.sort();
        candidates.dedup();

        candidates
    })
    .await
    .map_err(|e| Error::TaskFailed(e.to_string()))?;

    // Verify candidates sequentially to avoid overwhelming the system
    // with concurrent ssh processes when many stale sockets are present.
    let mut alive = Vec::new();
    for candidate in sessions {
        if check_alive(&candidate).await {
            let session = build_session(&candidate);
            alive.push(session);
        }
    }

    Ok(alive)
}

/// Collect paths matching a glob pattern inside a directory.
fn collect_matching(dir: &Path, pattern: &str, out: &mut Vec<PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if glob_matches(pattern, name) && is_socket_or_candidate(&path) {
                out.push(path);
            }
        }
    }
}

/// Simple glob matching supporting only `*` wildcard at the end of a prefix.
fn glob_matches(pattern: &str, name: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        name.starts_with(prefix)
    } else {
        name == pattern
    }
}

/// Check if a path is a Unix socket or a candidate control socket file.
fn is_socket_or_candidate(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(meta) => {
            let ft = meta.file_type();
            #[cfg(unix)]
            if ft.is_socket() {
                return true;
            }
            // On some filesystems (e.g. NFS) sockets may appear as regular files.
            // Accept small files with no extension as candidates.
            if ft.is_file() && meta.len() < MAX_CONTROL_SOCKET_CANDIDATE_SIZE {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                // Only accept names with no extension that don't look like
                // regular SSH files (known_hosts, config, *.pub, etc.)
                // Names without dots are unlikely to be regular SSH files
                // (known_hosts, config, *.pub all have extensions).
                return !name.contains('.');
            }
            false
        }
        Err(_) => false,
    }
}

/// Build a [`ControlSession`] from a control socket path.
///
/// Tries to extract the host from the socket filename using common naming
/// conventions like `cm-<user>@<host>:<port>` or `ssh-<hash>-<pid>`.
fn build_session(control_path: &Path) -> ControlSession {
    let name = control_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    let host = extract_host_from_name(name);

    let pid = extract_pid_from_name(name);

    let established = control_path.metadata().ok().and_then(|m| m.modified().ok());

    ControlSession {
        control_path: control_path.to_path_buf(),
        host,
        pid,
        established,
    }
}

/// Try to extract a hostname from common control socket naming patterns.
///
/// Patterns:
/// - `cm-<user>@<host>:<port>` -> `<host>`
/// - `control-<user>@<host>:<port>` -> `<host>`
/// - `mux-<user>@<host>:<port>` -> `<host>`
/// - `ssh-XXXXXXXXXX-<pid>` -> fallback to filename
pub(crate) fn extract_host_from_name(name: &str) -> String {
    // Strip common prefixes
    let rest = name
        .strip_prefix("cm-")
        .or_else(|| name.strip_prefix("control-"))
        .or_else(|| name.strip_prefix("mux-"))
        .or_else(|| name.strip_prefix("ctrl-"))
        .or_else(|| name.strip_prefix("ssh-"))
        .unwrap_or(name);

    // Try user@host:port pattern
    if let Some(at_idx) = rest.find('@') {
        let after_at = &rest[at_idx + 1..];
        // Check for bracket notation: [host]:port (used for IPv6)
        if after_at.starts_with('[')
            && let Some(bracket_end) = after_at.find(']')
        {
            return after_at[1..bracket_end].to_owned();
        }
        // If the address contains multiple colons it is likely a bare IPv6
        // address (e.g. "::1:22" or "fe80::1:22").  The helper tries to
        // split host from port; if it fails we treat the whole string as a
        // bare IPv6 address without a port.
        if after_at.matches(':').count() >= 2 {
            if let Some(host) = split_bare_ipv6_host_port(after_at) {
                return host.to_owned();
            }
            // Bare IPv6 without port (e.g. "::1", "fe80::1")
            return after_at.to_owned();
        }
        // Take up to the first colon (port separator) — IPv4 / hostname
        if let Some(colon_idx) = after_at.find(':') {
            return after_at[..colon_idx].to_owned();
        }
        // No port, take rest
        return after_at.to_owned();
    }

    // Fallback: use the stripped name
    rest.to_owned()
}

/// Split a bare IPv6 `host:port` string at the last colon that precedes a
/// numeric-only port suffix.
///
/// Returns `Some(host)` when a valid split is found, `None` otherwise.
///
/// Heuristic: we only split when the candidate host portion contains `::`
/// (the IPv6 compression marker) and the input has at least 3 colons, so
/// that a bare IPv6 address like `::1` (2 colons, no port) is not
/// mis-split into `::` + port `1`.
fn split_bare_ipv6_host_port(s: &str) -> Option<&str> {
    let colon_count = s.matches(':').count();
    if colon_count < 3 || !s.contains("::") {
        return None;
    }
    let last_colon = s.rfind(':')?;
    let port_part = &s[last_colon + 1..];
    if port_part.is_empty() || !port_part.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let host_part = &s[..last_colon];
    if host_part.is_empty() {
        return None;
    }
    Some(host_part)
}

/// Try to extract a PID from the control socket filename.
///
/// Returns `None` for PID 0 since it is never a valid process ID.
pub(crate) fn extract_pid_from_name(name: &str) -> Option<u32> {
    // Patterns like ssh-<hash>-<pid>
    let (_prefix, pid_str) = name.rsplit_once('-')?;
    let pid: u32 = pid_str.parse().ok()?;
    (pid > 0).then_some(pid)
}

#[cfg(test)]
#[path = "control.test.rs"]
mod tests;
