//! Key Revocation List (KRL) inspection.
//!
//! KRL is an OpenSSH binary format. There is no pure-Rust parser in the
//! `ssh-key` crate, so we shell out to `ssh-keygen -Q -l` and parse its output.
//!
//! ## Important: `ssh-keygen -Q` semantics
//!
//! `ssh-keygen -Q` is primarily a **query** tool: it tests whether specific keys
//! have been revoked in a KRL. The `-l` flag makes it also print the KRL
//! contents. Both `-Q` and `-l` require at least one file argument (a key or
//! certificate to test). We pass `/dev/null` as a dummy file solely to trigger
//! the listing; the actual query result is irrelevant.

use std::path::Path;

use serde::{Deserialize, Serialize};

use toride_ssh_core::Result;

/// Parsed details from an OpenSSH Key Revocation List.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KrlInfo {
    /// KRL format version (`0` is typical for current OpenSSH).
    pub version: u32,
    /// Timestamp when the KRL was generated, if present.
    pub generated_at: Option<i64>,
    /// Comment embedded in the KRL.
    pub comment: Option<String>,
    /// Revoked certificate serial numbers (expanded from ranges).
    pub revoked_serials: Vec<u64>,
    /// Revoked certificate key IDs.
    pub revoked_key_ids: Vec<String>,
    /// Revoked key fingerprints (SHA-256).
    pub revoked_fingerprints: Vec<String>,
    /// SHA-256 fingerprint of the CA key, if the KRL was signed by one.
    pub ca_fingerprint: Option<String>,
}

/// Inspect a KRL file and return structured information.
///
/// Uses `ssh-keygen -Q -l -f <krl> <dummy>` to dump and parse the KRL contents.
/// The dummy file (`/dev/null`) is required because `-Q` needs at least one key
/// to query, but we only care about the listing output produced by `-l`.
pub async fn inspect_krl(path: &Path) -> Result<KrlInfo> {
    let path_str = path.to_str().ok_or_else(|| {
        toride_ssh_core::Error::CommandFailed(format!(
            "KRL path is not valid UTF-8: {}",
            path.display()
        ))
    })?;

    // -Q queries a KRL, -l causes it to also print the KRL contents.
    // A dummy file argument is required; /dev/null works as a no-op input.
    let output =
        toride_ssh_core::runner::ssh_keygen(&["-Q", "-l", "-f", path_str, "/dev/null"]).await?;

    parse_krl_output(&output, path)
}

/// Best-effort parser for `ssh-keygen -Q -l -f <krl> <file>` output.
///
/// The output looks roughly like:
///
/// ```text
/// # KRL version 0
/// # Generated at 20240101T000000
///
/// # CA key ssh-ed25519 SHA256:xxxx
/// serial: 1-5
/// serial: 10
/// id: "compromised-key"
/// hash: SHA256:AAAA...
/// /dev/null: ok
/// ```
///
/// Key differences from the earlier (wrong) assumption:
/// - Version starts at `0`, not `1`.
/// - Date format is compact: `YYYYMMDDTHHMMSS` (no hyphens or colons).
/// - Fingerprints appear under `hash:` (not `sha256:`).
/// - A CA key line `# CA key <algo> SHA256:...` may appear.
/// - The last line(s) are the query result for the input file(s).
fn parse_krl_output(output: &str, path: &Path) -> Result<KrlInfo> {
    let mut version = 0u32;
    let mut generated_at: Option<i64> = None;
    let mut comment: Option<String> = None;
    let mut revoked_serials = Vec::new();
    let mut revoked_key_ids = Vec::new();
    let mut revoked_fingerprints = Vec::new();
    let mut ca_fingerprint: Option<String> = None;

    for line in output.lines() {
        let trimmed = line.trim();

        // Skip the query-result lines appended at the end for each input file.
        // Format: "<path>: REVOKED" or "<path>: ok"
        if trimmed.ends_with(": REVOKED") || trimmed.ends_with(": ok") {
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("# KRL version") {
            version = rest.trim().parse().map_err(|_| {
                toride_ssh_core::Error::KrlParseFailed(format!(
                    "invalid KRL version: {}",
                    rest.trim()
                ))
            })?;
        } else if let Some(rest) = trimmed.strip_prefix("# Generated at") {
            let dt_str = rest.trim();
            generated_at = parse_datetime_to_unix(dt_str);
        } else if let Some(rest) = trimmed.strip_prefix("# Comments:") {
            comment = Some(rest.trim().to_owned());
        } else if let Some(rest) = trimmed.strip_prefix("# CA key") {
            // Extract CA key fingerprint: "# CA key ssh-ed25519 SHA256:xxxx"
            if let Some(fp) = rest.split_whitespace().find(|s| s.starts_with("SHA256:")) {
                ca_fingerprint = Some(fp.to_owned());
            }
        } else if let Some(rest) = trimmed.strip_prefix("serial:") {
            // May be a single number or a range like "1-5".
            parse_serials(rest.trim(), &mut revoked_serials);
        } else if let Some(rest) = trimmed.strip_prefix("id:") {
            revoked_key_ids.push(rest.trim().trim_matches('"').to_owned());
        } else if let Some(rest) = trimmed.strip_prefix("hash:") {
            // ssh-keygen -Q -l outputs fingerprints as "hash: SHA256:AAAA..."
            revoked_fingerprints.push(rest.trim().to_owned());
        } else if let Some(rest) = trimmed.strip_prefix("sha256:") {
            // Older OpenSSH versions or alternative output may use this prefix.
            revoked_fingerprints.push(rest.trim().to_owned());
        }
    }

    // Validate that we got something or that the KRL is genuinely empty.
    if revoked_serials.is_empty() && revoked_key_ids.is_empty() && revoked_fingerprints.is_empty() {
        // The KRL might be empty or we failed to parse. Check if the output
        // indicates it's not a KRL at all.
        if output.contains("not a KRL file")
            || output.contains("Invalid")
            || output.contains("Unable to load KRL")
        {
            return Err(toride_ssh_core::Error::CertificateParseFailed(format!(
                "{} is not a valid KRL file",
                path.display()
            )));
        }
        // Otherwise it's a valid but empty KRL.
    }

    Ok(KrlInfo {
        version,
        generated_at,
        comment,
        revoked_serials,
        revoked_key_ids,
        revoked_fingerprints,
        ca_fingerprint,
    })
}

/// Maximum number of serials to expand from a range before storing as-is.
///
/// Expanding a range like `0-u64::MAX` would allocate 144 exabytes.
/// We cap expansion at a reasonable limit and log a warning for larger ranges.
const MAX_SERIAL_RANGE_EXPANSION: u64 = 10_000;

/// Parse serial entries, which may be single numbers or ranges like "1-5".
pub(crate) fn parse_serials(input: &str, out: &mut Vec<u64>) {
    if let Some((start, end)) = input.split_once('-') {
        if let (Ok(s), Ok(e)) = (start.trim().parse::<u64>(), end.trim().parse::<u64>()) {
            if s > e {
                tracing::warn!("invalid serial range: {s}-{e} (start > end)");
                return;
            }
            let count = e - s + 1;
            if count > MAX_SERIAL_RANGE_EXPANSION {
                tracing::warn!(
                    "serial range {s}-{e} is very large ({count} entries), \
                     capping expansion at {MAX_SERIAL_RANGE_EXPANSION}"
                );
                out.extend(s..s + MAX_SERIAL_RANGE_EXPANSION);
            } else {
                out.extend(s..=e);
            }
        }
    } else if let Ok(n) = input.parse::<u64>() {
        out.push(n);
    }
}

/// Best-effort datetime string to Unix timestamp.
///
/// Handles the compact format emitted by `ssh-keygen -Q -l`:
/// `20240101T000000` as well as the more common ISO-ish formats.
fn parse_datetime_to_unix(s: &str) -> Option<i64> {
    super::parse_ssh_datetime(s)
}

#[cfg(test)]
#[path = "krl.test.rs"]
mod tests;
