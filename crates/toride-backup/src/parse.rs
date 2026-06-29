//! Parsers for restic and borg CLI output.
//!
//! Provides functions to parse the structured text output from `restic
//! snapshots`, `restic check`, `borg list`, and similar commands into typed
//! Rust data structures.

// ---------------------------------------------------------------------------
// SnapshotInfo
// ---------------------------------------------------------------------------

/// Parsed snapshot metadata from a backup repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotInfo {
    /// Short snapshot ID (first 8 characters).
    pub id: String,
    /// Full snapshot ID.
    pub full_id: String,
    /// Timestamp of the snapshot (raw string, best-effort parse).
    pub timestamp: String,
    /// Hostname where the snapshot was created.
    pub hostname: Option<String>,
    /// Tags applied to the snapshot.
    pub tags: Vec<String>,
    /// Paths included in the snapshot.
    pub paths: Vec<String>,
}

// ---------------------------------------------------------------------------
// Restic parsers
// ---------------------------------------------------------------------------

/// Parse the output of `restic snapshots --json`.
///
/// The output is a JSON array of snapshot objects. Returns a vec of
/// [`SnapshotInfo`] parsed from the JSON.
///
/// # Errors
///
/// Returns [`Error::ConfigParse`](crate::Error::ConfigParse) if the output
/// cannot be parsed as valid JSON.
pub fn parse_restic_snapshots(output: &str) -> crate::Result<Vec<SnapshotInfo>> {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    // Best-effort JSON parsing. If the output is not JSON (e.g. restic was
    // invoked without --json), fall back to line-based parsing.
    if trimmed.starts_with('[') {
        parse_restic_snapshots_json(trimmed)
    } else {
        Ok(parse_restic_snapshots_text(trimmed))
    }
}

/// Parse JSON output from `restic snapshots --json`.
#[allow(
    clippy::unnecessary_wraps,
    reason = "serde branch propagates JSON parse errors via ?; both cfg branches keep Result for uniformity"
)]
fn parse_restic_snapshots_json(json: &str) -> crate::Result<Vec<SnapshotInfo>> {
    // Skeleton: parse via serde when the serde feature is enabled.
    // Without serde, we do a simple best-effort text parse.
    #[cfg(feature = "serde")]
    {
        let raw: Vec<serde_json::Value> = serde_json::from_str(json)?;
        Ok(raw
            .into_iter()
            .filter_map(|v| {
                let obj = v.as_object()?;
                let full_id = obj.get("id")?.as_str()?.to_string();
                let id = full_id.chars().take(8).collect();
                let timestamp = obj
                    .get("time")
                    .and_then(|t| t.as_str())
                    .unwrap_or("")
                    .to_string();
                let hostname = obj
                    .get("hostname")
                    .and_then(|h| h.as_str())
                    .map(String::from);
                let tags = obj
                    .get("tags")
                    .and_then(|t| t.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                let paths = obj
                    .get("paths")
                    .and_then(|p| p.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                Some(SnapshotInfo {
                    id,
                    full_id,
                    timestamp,
                    hostname,
                    tags,
                    paths,
                })
            })
            .collect())
    }

    #[cfg(not(feature = "serde"))]
    {
        // Without serde, just do line-based parsing.
        Ok(parse_restic_snapshots_text(json))
    }
}

/// Parse text (non-JSON) output from `restic snapshots`.
fn parse_restic_snapshots_text(output: &str) -> Vec<SnapshotInfo> {
    let mut snapshots = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("ID") || line.starts_with("---") {
            // Skip header lines.
            continue;
        }
        let parts: Vec<&str> = line.splitn(4, |c: char| c.is_whitespace()).collect();
        if parts.len() >= 2 {
            let full_id = parts[0].to_string();
            let id = full_id.chars().take(8).collect();
            let timestamp = parts.get(1).unwrap_or(&"").to_string();
            snapshots.push(SnapshotInfo {
                id,
                full_id,
                timestamp,
                hostname: None,
                tags: Vec::new(),
                paths: Vec::new(),
            });
        }
    }
    snapshots
}

// ---------------------------------------------------------------------------
// Restic check parser
// ---------------------------------------------------------------------------

/// Result of parsing `restic check` output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    /// Whether the integrity check passed.
    pub passed: bool,
    /// Number of errors detected.
    pub error_count: u64,
    /// Raw output lines from the check command.
    pub output_lines: Vec<String>,
}

/// Parse the output of `restic check`.
///
/// Looks for error indicators in the output and reports whether the
/// integrity check passed.
pub fn parse_restic_check(output: &str) -> CheckResult {
    let mut error_count = 0u64;
    let mut passed = true;
    let output_lines: Vec<String> = output.lines().map(String::from).collect();

    for line in &output_lines {
        let lower = line.to_ascii_lowercase();
        if lower.contains("error") || lower.contains("fatal") || lower.contains("failed") {
            error_count += 1;
            passed = false;
        }
    }

    // If the output contains "no errors were found", it passed.
    if output_lines
        .iter()
        .any(|l| l.to_ascii_lowercase().contains("no errors were found"))
    {
        passed = true;
        error_count = 0;
    }

    CheckResult {
        passed,
        error_count,
        output_lines,
    }
}

// ---------------------------------------------------------------------------
// Borg parsers
// ---------------------------------------------------------------------------

/// Parse the output of `borg list`.
///
/// Borg list output format: `<id> <timestamp> <hostname> <path>`.
/// Returns a vec of [`SnapshotInfo`] parsed from the output.
pub fn parse_borg_list(output: &str) -> crate::Result<Vec<SnapshotInfo>> {
    let mut snapshots = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.splitn(4, |c: char| c.is_whitespace()).collect();
        if parts.len() >= 2 {
            let full_id = parts[0].to_string();
            let id = full_id.chars().take(8).collect();
            let timestamp = parts.get(1).unwrap_or(&"").to_string();
            snapshots.push(SnapshotInfo {
                id,
                full_id,
                timestamp,
                hostname: None,
                tags: Vec::new(),
                paths: Vec::new(),
            });
        }
    }
    Ok(snapshots)
}
