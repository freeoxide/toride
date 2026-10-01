//! Port forwarding control via `ControlMaster` sessions.

#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use toride_ssh_core::{Error, Result};

const MAX_CONTROL_SOCKET_CANDIDATE_SIZE: u64 = 1024;

/// Whether a forward is local (-L), remote (-R), or dynamic/SOCKS (-D).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ForwardType {
    Local,
    Remote,
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
    /// Local bind address (e.g. `127.0.0.1` or `*` under `GatewayPorts`).
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub forward_type: ForwardType,
}

/// A discovered `ControlMaster` session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlSession {
    pub control_path: PathBuf,
    pub host: String,
    pub pid: Option<u32>,
    pub established: Option<std::time::SystemTime>,
}

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

async fn check_alive(control_path: &Path) -> bool {
    ssh_control_cmd(control_path, "check").await.is_ok()
}

/// List active port forwards on a `ControlMaster` session.
///
/// # Errors
/// [`Error::ForwardFailed`] (non-UTF-8 path), [`Error::CommandFailed`]
/// (ssh fails), or [`Error::TaskFailed`] (spawn failure).
pub async fn list_forwards(control_path: &Path) -> Result<Vec<PortForward>> {
    let output = ssh_control_cmd(control_path, "list").await?;
    Ok(parse_forward_output(&output))
}

// Boxing works around the higher-ranked `Send` inference limitation
// ("Send is not general enough", rust-lang/rust#110338).
type BoxedFanoutFuture<T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send>>;

async fn join_all_bounded<I, T>(limit: usize, futs: I) -> Vec<T>
where
    I: IntoIterator,
    I::Item: std::future::Future<Output = T>,
{
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(limit));
    let guarded = futs.into_iter().map(|fut| {
        let semaphore = std::sync::Arc::clone(&semaphore);
        async move {
            let _permit = semaphore.acquire_owned().await.ok();
            fut.await
        }
    });
    futures::future::join_all(guarded).await
}

/// Run [`list_forwards`] for many control paths with bounded `ssh -O list`
/// spawns; results in input order, one failure never cancels the others.
pub async fn list_forwards_bounded<I>(paths: I) -> Vec<Result<Vec<PortForward>>>
where
    I: IntoIterator<Item = PathBuf>,
{
    let futs: Vec<BoxedFanoutFuture<Result<Vec<PortForward>>>> = paths
        .into_iter()
        .map(|path| {
            let fut: BoxedFanoutFuture<_> = Box::pin(async move { list_forwards(&path).await });
            fut
        })
        .collect();
    join_all_bounded(MAX_CONCURRENT_CONTROL_CMDS, futs).await
}

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

        if let Some(fwd) = parse_forward_line(trimmed, ft) {
            forwards.push(fwd);
        }
    }

    forwards
}

pub(crate) fn parse_forward_line(line: &str, forward_type: ForwardType) -> Option<PortForward> {
    let line = line.trim_start();

    let port_idx = line.find(" port ")?;
    let local_addr = line[..port_idx].trim().trim_end_matches('.').to_owned();

    let rest = &line[port_idx + 6..];

    if forward_type == ForwardType::Dynamic {
        let local_port: u16 = rest.trim().parse().ok()?;
        return Some(PortForward {
            local_addr,
            local_port,
            remote_addr: String::new(),
            remote_port: 0,
            forward_type,
        });
    }

    let comma_idx = rest.find(',')?;
    let local_port: u16 = rest[..comma_idx].trim().parse().ok()?;

    let fwd_rest = &rest[comma_idx + 1..];
    let fwd_label = "forwarding to ";
    let fwd_idx = fwd_rest.find(fwd_label)?;
    let rhost_port = &fwd_rest[fwd_idx + fwd_label.len()..];

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

/// Cancel the forward on `local_port` (lists first to find its spec);
/// an inherent TOCTOU race means it may vanish before the cancel lands.
///
/// # Errors
/// [`Error::ForwardNotFound`] if no forward is listening on `local_port`;
/// otherwise as [`list_forwards`] / [`cancel_known_forward`].
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

/// Cancel a known forward directly, skipping the list round-trip; the spec
/// is `[addr]:lport[:rhost:rport]`, with an empty rhost sent as `localhost`.
///
/// # Errors
/// [`Error::ForwardFailed`] (non-UTF-8 path), [`Error::CommandFailed`]
/// (ssh fails), or [`Error::TaskFailed`] (spawn failure).
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
        format!("[{}]:{}", forward.local_addr, forward.local_port)
    } else {
        format!(
            "[{}]:{}:{}:{}",
            forward.local_addr,
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

/// Close a `ControlMaster` session (`ssh -O exit`); the socket file is
/// unlinked asynchronously, so re-check the path before assuming removal.
///
/// # Errors
/// [`Error::ForwardFailed`] (non-UTF-8 path), [`Error::CommandFailed`]
/// (ssh fails), or [`Error::TaskFailed`] (spawn failure).
pub async fn exit_session(control_path: &Path) -> Result<()> {
    let path = control_path.to_path_buf();

    tokio::task::spawn_blocking(move || {
        let path_str = path
            .to_str()
            .ok_or_else(|| Error::ForwardFailed("control path is not valid UTF-8".into()))?;

        let result = duct::cmd("ssh", ["-O", "exit", "-S", path_str])
            .run()
            .map_err(|e| Error::CommandFailed(format!("ssh -O exit: {e}")));

        if result.is_ok() || is_stale_socket(&path) {
            let _ = std::fs::remove_file(&path);
        }

        result
    })
    .await
    .map_err(|e| Error::TaskFailed(e.to_string()))??;

    Ok(())
}

fn is_stale_socket(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(meta) => {
            #[cfg(unix)]
            if meta.file_type().is_socket() {
                return true;
            }
            meta.is_file() && meta.len() == 0
        }
        Err(_) => false,
    }
}

const MAX_CONCURRENT_CONTROL_CMDS: usize = 8;

/// Discover live `ControlMaster` sessions by scanning `ssh_dir` prefixes
/// (`cm-`, `control-`, `mux-`, `ctrl-`) and `/tmp/ssh-*` via `ssh -O check`.
///
/// # Errors
/// [`Error::TaskFailed`] if the directory scan task fails; individual
/// `ssh -O check` failures only exclude the candidate.
pub async fn list_sessions(ssh_dir: &Path) -> Result<Vec<ControlSession>> {
    let ssh_dir = ssh_dir.to_path_buf();
    let tmp_dir = std::path::PathBuf::from("/tmp");

    let candidates = tokio::task::spawn_blocking(move || {
        let mut candidates = collect_matching_any(&ssh_dir, SSH_DIR_PREFIXES);

        candidates.extend(collect_matching_any(&tmp_dir, &["ssh-"]));

        candidates.sort();
        candidates.dedup();

        candidates
    })
    .await
    .map_err(|e| Error::TaskFailed(e.to_string()))?;

    let checks: Vec<BoxedFanoutFuture<bool>> = candidates
        .iter()
        .map(|candidate| {
            let candidate = candidate.clone();
            let fut: BoxedFanoutFuture<bool> =
                Box::pin(async move { check_alive(&candidate).await });
            fut
        })
        .collect();
    let alive_flags = join_all_bounded(MAX_CONCURRENT_CONTROL_CMDS, checks).await;

    let alive = candidates
        .into_iter()
        .zip(alive_flags)
        .filter_map(|(candidate, alive)| alive.then(|| build_session(&candidate)))
        .collect();

    Ok(alive)
}

const SSH_DIR_PREFIXES: &[&str] = &["cm-", "control-", "mux-", "ctrl-"];

fn collect_matching_any(dir: &Path, prefixes: &[&str]) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if prefixes.iter().any(|p| name.starts_with(p)) && is_socket_or_candidate(&path) {
            out.push(path);
        }
    }
    out
}

fn is_socket_or_candidate(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(meta) => {
            let ft = meta.file_type();
            #[cfg(unix)]
            if ft.is_socket() {
                return true;
            }
            if ft.is_file() && meta.len() < MAX_CONTROL_SOCKET_CANDIDATE_SIZE {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                return !name.contains('.');
            }
            false
        }
        Err(_) => false,
    }
}

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

pub(crate) fn extract_host_from_name(name: &str) -> String {
    let rest = name
        .strip_prefix("cm-")
        .or_else(|| name.strip_prefix("control-"))
        .or_else(|| name.strip_prefix("mux-"))
        .or_else(|| name.strip_prefix("ctrl-"))
        .or_else(|| name.strip_prefix("ssh-"))
        .unwrap_or(name);

    if let Some(at_idx) = rest.find('@') {
        let after_at = &rest[at_idx + 1..];
        if after_at.starts_with('[')
            && let Some(bracket_end) = after_at.find(']')
        {
            return after_at[1..bracket_end].to_owned();
        }
        if after_at.matches(':').count() >= 2 {
            if let Some(host) = split_bare_ipv6_host_port(after_at) {
                return host.to_owned();
            }
            return after_at.to_owned();
        }
        if let Some(colon_idx) = after_at.find(':') {
            return after_at[..colon_idx].to_owned();
        }
        return after_at.to_owned();
    }

    rest.to_owned()
}

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

pub(crate) fn extract_pid_from_name(name: &str) -> Option<u32> {
    let (_prefix, pid_str) = name.rsplit_once('-')?;
    let pid: u32 = pid_str.parse().ok()?;
    (pid > 0).then_some(pid)
}

#[cfg(test)]
#[path = "control.test.rs"]
mod tests;
