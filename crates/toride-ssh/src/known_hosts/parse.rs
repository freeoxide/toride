//! Parse `known_hosts` files.

use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD as BASE64;
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// A single entry parsed from a `known_hosts` file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownHostEntry {
    /// Markers such as `@cert-authority` or `@revoked`.
    pub markers: Vec<String>,
    /// Hostname patterns (comma-separated in the file; may include `*`/`?`
    /// globs, `!` negations, `[host]:port` forms, or `|1|...` hashed names).
    pub hosts: Vec<String>,
    /// Key type label, e.g. `ssh-ed25519`.
    pub key_type: String,
    /// Base64-encoded public key blob.
    pub public_key: String,
    /// Optional trailing comment on the line (everything after the base64 key,
    /// excluding any `#`-delimited note).
    pub comment: Option<String>,
    /// 1-based line number within the file.
    pub line_number: usize,
}

impl KnownHostEntry {
    /// Compute the SHA-256 fingerprint of this entry's public key.
    ///
    /// The fingerprint is computed by decoding the base64 public key blob,
    /// parsing it as an SSH public key, and hashing the encoded key data
    /// with SHA-256.  This matches the output of `ssh-keygen -lf`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KnownHostsParseFailed`] if the base64 key cannot be
    /// decoded or parsed as a valid SSH public key.
    pub fn fingerprint(&self) -> Result<crate::Fingerprint> {
        compute_key_fingerprint(&self.public_key, &self.key_type)
    }
}

/// Compute a SHA-256 fingerprint from a base64-encoded SSH public key blob.
///
/// The key blob is the base64-encoded SSH wire format as stored in
/// `known_hosts` files.  The fingerprint is computed using the same
/// algorithm as `ssh-keygen -lf`.
pub(crate) fn compute_key_fingerprint(
    public_key_b64: &str,
    key_type_str: &str,
) -> Result<crate::Fingerprint> {
    // SSH keys in known_hosts may or may not have padding.  Strip any
    // trailing '=' characters so `STANDARD_NO_PAD` can decode them.
    let trimmed = public_key_b64.trim_end_matches('=');
    let decoded = BASE64
        .decode(trimmed)
        .map_err(|e| Error::KnownHostsParseFailed(format!("invalid base64 key: {e}")))?;

    let pk = ssh_key::PublicKey::from_bytes(&decoded)
        .map_err(|e| Error::KnownHostsParseFailed(format!("invalid SSH key blob: {e}")))?;

    let ssh_fp = pk.fingerprint(ssh_key::HashAlg::Sha256);
    let fp_str = ssh_fp.to_string();
    let hash = fp_str
        .strip_prefix("SHA256:")
        .unwrap_or(&fp_str)
        .to_owned();

    let key_type = parse_key_type_string(key_type_str);

    Ok(crate::Fingerprint { hash, key_type })
}

/// Convert a raw key type string (e.g. `"ssh-ed25519"`) to the [`KeyType`]
/// enum.  Unknown types fall back to `Rsa { bits: 0 }`.
fn parse_key_type_string(s: &str) -> crate::types::KeyType {
    use crate::types::KeyType;
    match s {
        "ssh-ed25519" => KeyType::Ed25519,
        "ecdsa-sha2-nistp256" => KeyType::EcdsaP256,
        "ecdsa-sha2-nistp384" => KeyType::EcdsaP384,
        "ecdsa-sha2-nistp521" => KeyType::EcdsaP521,
        "ssh-dss" => KeyType::Dsa,
        "sk-ssh-ed25519@openssh.com" => KeyType::SkEd25519,
        "sk-ecdsa-sha2-nistp256@openssh.com" => KeyType::SkEcdsaP256,
        // ssh-rsa and unknown types default to RSA with unknown bit size.
        _ => KeyType::Rsa { bits: 0 },
    }
}

/// Parse a known_hosts file at the given path.
///
/// This reads the file asynchronously and parses each non-empty, non-comment
/// line into a [`KnownHostEntry`].  Hashed hostnames (`|1|...`) are preserved
/// as-is in the `hosts` field.
pub async fn parse_known_hosts(path: &Path) -> Result<Vec<KnownHostEntry>> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || parse_known_hosts_sync(&path))
        .await
        .map_err(|e| Error::TaskFailed(e.to_string()))?
}

/// Synchronous implementation that does the actual parsing.
fn parse_known_hosts_sync(path: &Path) -> Result<Vec<KnownHostEntry>> {
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };

    // We hand-parse here so we can capture the comment field and preserve
    // the raw host-pattern strings (the ssh-key crate decodes hashed
    // hosts into bytes which is less useful for display).
    Ok(contents
        .lines()
        .enumerate()
        .filter_map(|(idx, raw_line)| {
            let trimmed = raw_line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return None;
            }
            let line_number = idx + 1;
            match parse_line(trimmed, line_number) {
                Ok(entry) => Some(entry),
                Err(e) => {
                    // Log malformed lines but continue parsing the rest.
                    tracing::warn!(
                        line_number,
                        error = %e,
                        "skipping malformed known_hosts line"
                    );
                    None
                }
            }
        })
        .collect())
}

/// Parse a single trimmed known_hosts line.
///
/// Format: `[markers] host-patterns key-type base64-key [comment]`
///
/// The marker is an optional `@cert-authority` or `@revoked` prefixed token.
/// Only one marker is supported per OpenSSH known_hosts format.
pub(crate) fn parse_line(line: &str, line_number: usize) -> Result<KnownHostEntry> {
    // Skip full-line comments — these are filtered at the sync level,
    // but parse_line should handle them gracefully if called directly.
    if line.trim_start().starts_with('#') {
        return Err(Error::KnownHostsParseFailed(format!(
            "line {line_number}: comment"
        )));
    }

    // 1. Detect optional marker (starts with '@').
    let (markers, rest) = if line.starts_with('@') {
        let (marker_str, rest) = line
            .split_once(' ')
            .ok_or_else(|| Error::KnownHostsParseFailed(format!(
                "line {line_number}: marker without trailing fields"
            )))?;
        (vec![marker_str.to_owned()], rest)
    } else {
        (vec![], line)
    };

    // 2. Split into remaining whitespace-separated fields.
    //    We expect at least: hosts  keytype  base64key
    let fields: Vec<&str> = rest.split_whitespace().collect();
    if fields.len() < 3 {
        return Err(Error::KnownHostsParseFailed(format!(
            "line {line_number}: expected at least 3 fields (hosts, key-type, key), got {}",
            fields.len()
        )));
    }

    let hosts_str = fields[0];
    let hosts: Vec<String> = hosts_str.split_terminator(',').map(str::to_owned).collect();

    let key_type = fields[1].to_owned();
    let public_key = fields[2].to_owned();

    let comment = if fields.len() > 3 {
        Some(fields[3..].join(" "))
    } else {
        None
    };

    Ok(KnownHostEntry {
        markers,
        hosts,
        key_type,
        public_key,
        comment,
        line_number,
    })
}

#[cfg(test)]
#[path = "parse.test.rs"]
mod tests;
