//! Host key scanning via `ssh-keyscan`.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::runner;
use crate::{Error, Result};

/// A host key discovered by `ssh-keyscan`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScannedHostKey {
    /// The original hostname or IP that was scanned.
    pub host: String,
    /// Key type label, e.g. `ssh-ed25519`.
    pub key_type: String,
    /// Base64-encoded public key blob.
    pub public_key: String,
    /// The host field as it appears in keyscan output.
    /// When `-H` is used this will be a `|1|salt|hash` string; otherwise it
    /// matches [`host`](ScannedHostKey::host).
    pub raw_host: String,
}

/// Scan a host for its public host keys.
///
/// Runs `ssh-keyscan <host>` (without `-H`) so that the returned keys contain
/// the plaintext hostname. Callers that need hashed entries should use
/// [`add_host_hashed`] or [`add_to_known_hosts`].
pub async fn scan_host(host: &str) -> Result<Vec<ScannedHostKey>> {
    let raw = runner::ssh_keyscan_no_hash(host).await?;
    Ok(parse_keyscan_output(host, &raw))
}

/// Scan a host with `-H` (hashed hostname) and parse the output.
///
/// Used internally by [`add_to_known_hosts`] so that written entries contain
/// hashed hostnames for privacy.
async fn scan_host_hashed(host: &str) -> Result<Vec<ScannedHostKey>> {
    let raw = runner::ssh_keyscan(host).await?;
    Ok(parse_keyscan_output(host, &raw))
}

/// Parse raw `ssh-keyscan` output into a list of [`ScannedHostKey`] values.
fn parse_keyscan_output(original_host: &str, raw: &str) -> Vec<ScannedHostKey> {
    let mut keys = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        match parse_keyscan_line(original_host, line) {
            Ok(key) => keys.push(key),
            Err(e) => {
                tracing::warn!(line, error = %e, "skipping unparseable keyscan line");
            }
        }
    }

    keys
}

/// Parse a single `ssh-keyscan` output line.
///
/// Format: `hostname key-type base64-key [comment...]`
pub(crate) fn parse_keyscan_line(original_host: &str, line: &str) -> Result<ScannedHostKey> {
    let mut parts = line.split_whitespace();
    let raw_host = parts.next().ok_or_else(|| {
        Error::CommandParseFailed(format!("expected at least 3 fields in keyscan output: {line}"))
    })?;
    let key_type = parts.next().ok_or_else(|| {
        Error::CommandParseFailed(format!("expected at least 3 fields in keyscan output: {line}"))
    })?;
    let public_key = parts.next().ok_or_else(|| {
        Error::CommandParseFailed(format!("expected at least 3 fields in keyscan output: {line}"))
    })?;

    Ok(ScannedHostKey {
        host: original_host.to_owned(),
        key_type: key_type.to_owned(),
        public_key: public_key.to_owned(),
        raw_host: raw_host.to_owned(),
    })
}

/// Append a batch of scanned host keys to a known_hosts file.
///
/// Creates the file (and parent directories) if it does not already exist.
/// All keys are written in a single I/O operation to avoid interleaved
/// partial writes.
pub async fn add_to_known_hosts(
    known_hosts_path: &Path,
    keys: &[ScannedHostKey],
) -> Result<()> {
    let mut buf = String::new();
    for key in keys {
        buf.push_str(&key.raw_host);
        buf.push(' ');
        buf.push_str(&key.key_type);
        buf.push(' ');
        buf.push_str(&key.public_key);
        buf.push('\n');
    }
    let path: PathBuf = known_hosts_path.to_path_buf();

    tokio::task::spawn_blocking(move || {
        use std::io::Write;

        // Ensure the parent directory exists.
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        file.write_all(buf.as_bytes())?;
        Ok(())
    })
    .await
    .map_err(|e| Error::TaskFailed(e.to_string()))?
}

/// Scan a host (with `-H` hashing) and append all discovered keys to
/// `known_hosts`.
pub async fn add_host_hashed(known_hosts_path: &Path, host: &str) -> Result<()> {
    let keys = scan_host_hashed(host).await?;
    if keys.is_empty() {
        return Err(Error::CommandFailed(format!(
            "ssh-keyscan returned no keys for {host}"
        )));
    }
    add_to_known_hosts(known_hosts_path, &keys).await
}

#[cfg(test)]
#[path = "scan.test.rs"]
mod tests;
