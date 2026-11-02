//! Port forwarding control via `ControlMaster` sessions.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use toride_ssh_core::Error;
use toride_ssh_core::Result;
use toride_ssh_core::control_master::ControlName;
use toride_ssh_core::control_master::collect_control_candidates;
use toride_ssh_core::fanout::join_all_bounded;

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

/// A port forward spec for `ssh -O cancel`, supplied by the caller.
///
/// The mux protocol cannot enumerate a master's forwards (there is no
/// `-O list`), so canceling requires the spec of the forward as it was
/// passed to `ssh -L`/`-R`/`-D` at creation time.
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

// Boxing works around the higher-ranked `Send` inference limitation
// ("Send is not general enough", rust-lang/rust#110338).
type BoxedFanoutFuture<T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send>>;

/// Cancel a known forward directly; the spec sent to `ssh -O cancel`
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

/// Close a `ControlMaster` session (`ssh -O exit`).
///
/// The socket file is unlinked only after the exit command succeeds or,
/// when it fails, after `ssh -O check` confirms no master is listening,
/// so a live master's socket is never destroyed by a failed exit.
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

        let result = duct::cmd("ssh", ["-O", "exit", "-S", path_str, "-x", "nohost"])
            .run()
            .map_err(|e| Error::CommandFailed(format!("ssh -O exit: {e}")));

        if result.is_ok() || master_absent(&path) {
            let _ = std::fs::remove_file(&path);
        }

        result
    })
    .await
    .map_err(|e| Error::TaskFailed(e.to_string()))??;

    Ok(())
}

fn master_absent(path: &Path) -> bool {
    let Some(path_str) = path.to_str() else {
        return false;
    };
    duct::cmd("ssh", ["-O", "check", "-S", path_str, "-x", "nohost"])
        .stdout_null()
        .stderr_null()
        .run()
        .is_err()
}

const MAX_CONCURRENT_CONTROL_CMDS: usize = 8;

const SSH_DIR_PREFIXES: &[&str] = &["cm-", "control-", "mux-", "ctrl-"];

/// Discover live `ControlMaster` sessions by scanning `ssh_dir` prefixes
/// (`cm-`, `control-`, `mux-`, `ctrl-`) and `/tmp/ssh-*` via `ssh -O check`.
///
/// # Errors
/// [`Error::TaskFailed`] if the directory scan task fails; individual
/// `ssh -O check` failures only exclude the candidate.
pub async fn list_sessions(ssh_dir: &Path) -> Result<Vec<ControlSession>> {
    let ssh_dir = ssh_dir.to_path_buf();
    let tmp_dir = PathBuf::from("/tmp");

    let candidates = tokio::task::spawn_blocking(move || {
        let mut candidates: Vec<PathBuf> = [
            collect_control_candidates(&ssh_dir, SSH_DIR_PREFIXES, true),
            collect_control_candidates(&tmp_dir, &["ssh-"], true),
        ]
        .into_iter()
        .flat_map(|dir| dir.unwrap_or_default().into_iter().map(|c| c.path))
        .collect();

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

fn build_session(control_path: &Path) -> ControlSession {
    let name = control_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    let parts = ControlName::parse(name);

    let established = control_path.metadata().ok().and_then(|m| m.modified().ok());

    ControlSession {
        control_path: control_path.to_path_buf(),
        host: parts.host,
        pid: parts.pid,
        established,
    }
}

#[cfg(test)]
#[path = "control.test.rs"]
mod tests;
