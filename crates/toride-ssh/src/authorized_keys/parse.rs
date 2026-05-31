//! Parse `authorized_keys` files using ssh-key crate.

use std::path::Path;

use serde::{Deserialize, Serialize};

use super::options::AuthorizedKeyOptions;
use crate::Error;
use crate::Result;

/// A single entry parsed from an `authorized_keys` file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedKeyEntry {
    /// Parsed options, if any were present before the key.
    pub options: Option<AuthorizedKeyOptions>,
    /// Key type string (e.g. `ssh-ed25519`, `ssh-rsa`).
    pub key_type: String,
    /// Base64-encoded public key data.
    pub public_key: String,
    /// Comment field after the key.
    pub comment: Option<String>,
    /// 1-based line number in the file.
    pub line_number: usize,
    /// The raw original line text.
    pub raw_line: String,
}

impl AuthorizedKeyEntry {
    /// Reconstruct the OpenSSH key line (`key-type base64-key`) for re-parsing.
    fn openssh_key_line(&self) -> String {
        format!("{} {}", self.key_type, self.public_key)
    }

    /// Compute the SHA-256 fingerprint of this entry's public key.
    ///
    /// Returns `None` if the stored key data cannot be re-parsed (corrupted entry).
    pub(super) fn fingerprint(&self) -> Option<String> {
        let key_line = self.openssh_key_line();
        match ssh_key::PublicKey::from_openssh(&key_line) {
            Ok(pk) => Some(pk.fingerprint(ssh_key::HashAlg::Sha256).to_string()),
            Err(e) => {
                tracing::warn!(
                    "failed to re-parse authorized_keys entry at line {}: {e}",
                    self.line_number
                );
                None
            }
        }
    }
}

/// Parse an authorized_keys file at the given path.
///
/// Blank lines and comment lines (starting with `#`) are skipped.
/// Each valid key line is validated using `ssh_key::PublicKey::from_openssh`.
///
/// # Errors
///
/// - [`Error::Io`] if the file cannot be read.
/// - [`Error::AuthorizedKeysParseFailed`] if a key line fails to parse.
pub async fn parse_authorized_keys(path: &Path) -> Result<Vec<AuthorizedKeyEntry>> {
    let path = path.to_owned();

    // Read the file asynchronously first, then hand off only the CPU-bound
    // parsing to spawn_blocking.
    let contents = match tokio::fs::read_to_string(&path).await {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };

    tokio::task::spawn_blocking(move || parse_authorized_keys_sync(&contents))
        .await
        .map_err(|e| Error::AuthorizedKeysParseFailed(e.to_string()))?
}

/// Synchronous implementation that parses already-read file contents.
fn parse_authorized_keys_sync(contents: &str) -> Result<Vec<AuthorizedKeyEntry>> {

    let mut entries = Vec::new();

    for (line_idx, raw_line) in contents.lines().enumerate() {
        let line_number = line_idx + 1;
        let trimmed = raw_line.trim();

        // Skip blank lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // `parse_line` already includes line-number context in its errors,
        // so propagate directly to avoid double-prefixing.
        entries.push(parse_line(trimmed, line_number, raw_line)?);
    }

    Ok(entries)
}

/// Known SSH key type prefixes used in authorized_keys files.
const KEY_TYPE_PREFIXES: &[&str] = &[
    "ssh-rsa",
    "ssh-dss",
    "ssh-ed25519",
    "ssh-ed448",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

/// Parse a single non-empty, non-comment line from an authorized_keys file.
///
/// Format: `[options] key-type base64-key [comment]`
///
/// The options field may contain quoted values with spaces, commas, and escaped
/// quotes, so we cannot naively split on spaces. Instead, we scan forward
/// through the line tracking quote state to find where the key-type token begins.
fn parse_line(raw_line: &str, line_number: usize, original: &str) -> Result<AuthorizedKeyEntry> {
    // Find where the key portion starts by scanning for a known key-type prefix
    // that is preceded by a space (or is at position 0) and is not inside quotes.
    let key_start = find_key_type_offset(raw_line).ok_or_else(|| {
        Error::AuthorizedKeysParseFailed(format!(
            "line {line_number}: no recognized key type found"
        ))
    })?;

    let (options_str, key_and_comment) = if key_start == 0 {
        (None, raw_line)
    } else {
        let opts = &raw_line[..key_start];
        // Trim trailing comma and space from options
        let opts = opts.trim_end_matches(',').trim_end();
        let rest = &raw_line[key_start..];
        (if opts.is_empty() { None } else { Some(opts) }, rest)
    };

    // Split the key+comment portion: key-type base64-key [comment]
    // The key data is base64 so it contains no spaces. We can safely split on spaces.
    let mut parts = key_and_comment.splitn(3, ' ');

    let key_type = parts
        .next()
        .ok_or_else(|| {
            Error::AuthorizedKeysParseFailed(format!(
                "line {line_number}: missing key type or key data after options"
            ))
        })?
        .to_string();

    let public_key = parts
        .next()
        .ok_or_else(|| {
            Error::AuthorizedKeysParseFailed(format!(
                "line {line_number}: missing key type or key data after options"
            ))
        })?
        .to_string();

    let comment = parts.next().map(ToString::to_string);

    // Validate by attempting to parse the key portion through ssh-key.
    if let Err(e) = ssh_key::PublicKey::from_openssh(key_and_comment) {
        return Err(Error::AuthorizedKeysParseFailed(format!(
            "line {line_number}: invalid key: {e}"
        )));
    }

    let options = options_str
        .map(super::options::parse_options)
        .transpose()?;

    Ok(AuthorizedKeyEntry {
        options,
        key_type,
        public_key,
        comment,
        line_number,
        raw_line: original.to_string(),
    })
}

/// Find the byte offset in `line` where a known SSH key type prefix begins.
///
/// Scans character-by-character tracking double-quote state so that key-type
/// prefixes inside quoted option values are not falsely detected.
///
/// Returns `None` if no recognized key type is found.
pub(crate) fn find_key_type_offset(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let len = bytes.len();
    let mut in_quotes = false;
    let mut escape_next = false;
    let mut i = 0;

    while i < len {
        let ch = bytes[i];

        if escape_next {
            escape_next = false;
            i += 1;
            continue;
        }

        match ch {
            b'\\' => {
                escape_next = true;
                i += 1;
            }
            b'"' => {
                in_quotes = !in_quotes;
                i += 1;
            }
            b' ' if !in_quotes => {
                // At a space boundary outside quotes, check if a key-type
                // prefix starts at the next position.
                let next = i + 1;
                if next < len {
                    let rest = &line[next..];
                    if starts_with_key_type(rest) {
                        return Some(next);
                    }
                }
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }

    // Check if the line itself starts with a key type (no options)
    if starts_with_key_type(line) {
        Some(0)
    } else {
        None
    }
}

/// Check whether `s` starts with a known SSH key-type prefix followed by a space
/// (or spanning the entire string).
fn starts_with_key_type(s: &str) -> bool {
    for prefix in KEY_TYPE_PREFIXES {
        if s == *prefix {
            return true;
        }
        if let Some(rest) = s.strip_prefix(prefix) {
            // Must be followed by a space (before the base64 key data)
            if rest.starts_with(' ') {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
#[path = "parse.test.rs"]
mod tests;
