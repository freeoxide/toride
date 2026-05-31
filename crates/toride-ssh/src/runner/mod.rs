//! Thin helpers for running external SSH tools via `duct`.
//!
//! These wrap the few operations that require shelling out:
//! FIDO key generation, `ssh-keyscan`, `ssh-copy-id`, passphrase changes, etc.
//! All calls go through `tokio::task::spawn_blocking` to avoid blocking the
//! async runtime.
//!
//! The [`cli_runner`] module provides a [`CliRunner`](cli_runner::CliRunner)
//! trait that abstracts over command execution for testability.

pub mod cli_runner;

use std::path::Path;

use crate::{Error, Result};

/// Run an external command via `tokio::task::spawn_blocking`.
async fn run_tool(cmd: &str, args: Vec<String>) -> Result<String> {
    let cmd = cmd.to_owned();
    tokio::task::spawn_blocking(move || {
        duct::cmd(&*cmd, &args)
            .read()
            .map_err(|e| Error::CommandFailed(e.to_string()))
    })
    .await
    .map_err(|e| Error::TaskFailed(e.to_string()))?
}

/// Run `ssh-keygen` with the given arguments and return stdout.
///
/// # Errors
///
/// Returns [`Error::ToolNotFound`] if `ssh-keygen` is not in `PATH`,
/// [`Error::CommandFailed`] if the command exits with a non-zero status,
/// or [`Error::TaskFailed`] if the background task panics.
pub async fn ssh_keygen(args: &[&str]) -> Result<String> {
    run_tool("ssh-keygen", args.iter().map(|s| (*s).to_owned()).collect()).await
}

/// Run `ssh-keyscan -H <host>` and return the host key lines.
///
/// The `-H` flag hashes hostnames in the output for privacy.
///
/// # Errors
///
/// Returns [`Error::CommandFailed`] if the scan fails, or
/// [`Error::TaskFailed`] if the background task panics.
pub async fn ssh_keyscan(host: &str) -> Result<String> {
    run_tool("ssh-keyscan", vec!["-H".into(), host.to_owned()]).await
}

/// Run `ssh-keyscan <host>` (without `-H`) and return the host key lines.
///
/// Hostnames appear in plaintext in the output, which is useful when the
/// caller wants to display or inspect the keys before deciding whether to
/// add them to `known_hosts`.
///
/// # Errors
///
/// Returns [`Error::CommandFailed`] if the scan fails, or
/// [`Error::TaskFailed`] if the background task panics.
pub async fn ssh_keyscan_no_hash(host: &str) -> Result<String> {
    run_tool("ssh-keyscan", vec![host.to_owned()]).await
}

/// Run `ssh-add -l` to list agent identities.
///
/// # Errors
///
/// Returns [`Error::CommandFailed`] if the command fails (e.g. agent not
/// running), or [`Error::TaskFailed`] if the background task panics.
pub async fn ssh_add_list() -> Result<String> {
    run_tool("ssh-add", vec!["-l".into()]).await
}

/// Run `ssh-copy-id -i <pubkey> <dest>`.
///
/// # Errors
///
/// Returns [`Error::CommandFailed`] if the copy fails (e.g. authentication
/// denied), or [`Error::TaskFailed`] if the background task panics.
pub async fn ssh_copy_id(pubkey: &Path, dest: &str) -> Result<String> {
    let pubkey_str = pubkey.to_str().ok_or_else(|| {
        Error::CommandFailed(format!(
            "public key path is not valid UTF-8: {}",
            pubkey.display()
        ))
    })?;
    run_tool("ssh-copy-id", vec!["-i".into(), pubkey_str.to_owned(), dest.to_owned()]).await
}

/// Check whether a tool exists in `PATH`.
pub fn tool_exists(name: &str) -> bool {
    which::which(name).is_ok()
}
