//! Thin helpers for running external SSH tools via `duct`.
//!
//! These wrap the few operations that require shelling out:
//! FIDO key generation, `ssh-keyscan`, `ssh-copy-id`, passphrase changes, etc.
//! All calls go through `tokio::task::spawn_blocking` to avoid blocking the
//! async runtime.

use std::path::Path;

use crate::{Error, Result};

/// Run `ssh-keygen` with the given arguments and return stdout.
pub async fn ssh_keygen(args: &[&str]) -> Result<String> {
    let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
    tokio::task::spawn_blocking(move || {
        duct::cmd("ssh-keygen", &args)
            .read()
            .map_err(|e| Error::CommandFailed(e.to_string()))
    })
    .await
    .map_err(|e| Error::CommandFailed(e.to_string()))?
}

/// Run `ssh-keyscan -H <host>` and return the host key lines.
pub async fn ssh_keyscan(host: &str) -> Result<String> {
    let host = host.to_owned();
    tokio::task::spawn_blocking(move || {
        duct::cmd("ssh-keyscan", ["-H", &host])
            .read()
            .map_err(|e| Error::CommandFailed(e.to_string()))
    })
    .await
    .map_err(|e| Error::CommandFailed(e.to_string()))?
}

/// Run `ssh-add -l` to list agent identities.
pub async fn ssh_add_list() -> Result<String> {
    tokio::task::spawn_blocking(|| {
        duct::cmd("ssh-add", ["-l"])
            .read()
            .map_err(|e| Error::CommandFailed(e.to_string()))
    })
    .await
    .map_err(|e| Error::CommandFailed(e.to_string()))?
}

/// Run `ssh-copy-id -i <pubkey> <dest>`.
pub async fn ssh_copy_id(pubkey: &Path, dest: &str) -> Result<String> {
    let pubkey = pubkey.to_path_buf();
    let dest = dest.to_owned();
    tokio::task::spawn_blocking(move || {
        duct::cmd(
            "ssh-copy-id",
            ["-i", pubkey.to_str().unwrap_or(""), &dest],
        )
        .read()
        .map_err(|e| Error::CommandFailed(e.to_string()))
    })
    .await
    .map_err(|e| Error::CommandFailed(e.to_string()))?
}

/// Check whether a tool exists in `PATH`.
pub fn tool_exists(name: &str) -> bool {
    which::which(name).is_ok()
}
