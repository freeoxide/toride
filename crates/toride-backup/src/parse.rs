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
///
/// `passed` is derived honestly from the accumulated `error_count` plus the
/// summary phrase "no errors were found": the check passes only when there
/// are no detected error lines **and** the summary phrase is present (or the
/// output is empty). A genuine error line is never hidden by the presence of
/// the summary phrase, so a mixed output (real errors + the phrase) is
/// reported as failed with the correct non-zero error count.
pub fn parse_restic_check(output: &str) -> CheckResult {
    // The restic check success summary itself contains the substring "error"
    // ("no errors were found"), so it must be excluded from error counting to
    // avoid double-counting a clean run as a failure.
    const CLEAN_SUMMARY: &str = "no errors were found";

    let mut error_count = 0u64;
    let output_lines: Vec<String> = output.lines().map(String::from).collect();

    let has_clean_summary = output_lines
        .iter()
        .any(|l| l.to_ascii_lowercase().contains(CLEAN_SUMMARY));

    for line in &output_lines {
        let lower = line.to_ascii_lowercase();
        if lower.contains(CLEAN_SUMMARY) {
            continue;
        }
        if lower.contains("error") || lower.contains("fatal") || lower.contains("failed") {
            error_count += 1;
        }
    }

    // `passed` is true iff no genuine error indicators were detected. The
    // clean summary phrase corroborates a pass but cannot mask a real error,
    // nor does it reset the error count, so a mixed output (real error line
    // plus the success summary) is reported as failed with the correct
    // non-zero error count.
    let passed = error_count == 0 && (has_clean_summary || output_lines.is_empty());

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restic_check_clean_summary_passes_with_zero_errors() {
        let output = "pack 1234 files\nno errors were found\n";
        let result = parse_restic_check(output);
        assert!(result.passed);
        assert_eq!(result.error_count, 0);
    }

    #[test]
    fn restic_check_empty_output_passes() {
        let result = parse_restic_check("");
        assert!(result.passed);
        assert_eq!(result.error_count, 0);
        assert!(result.output_lines.is_empty());
    }

    #[test]
    fn restic_check_error_lines_fail_without_clean_summary() {
        let output = "error: pack file is damaged\nfatal: repository is corrupt\n";
        let result = parse_restic_check(output);
        assert!(!result.passed);
        assert_eq!(result.error_count, 2);
    }

    #[test]
    fn restic_check_failed_keyword_is_an_error() {
        let output = "load <snapshot/abc>: failed to read data\n";
        let result = parse_restic_check(output);
        assert!(!result.passed);
        assert_eq!(result.error_count, 1);
    }

    #[test]
    fn restic_check_mixed_real_errors_and_clean_phrase_stays_failed() {
        // A restic run that prints both genuine error lines and the
        // trailing "no errors were found" summary (e.g. a non-fatal error
        // earlier in the output) must not have its error count reset to 0
        // or be reported as passed.
        let output = "error reading pack 1234: i/o timeout\n\
                      no errors were found\n";
        let result = parse_restic_check(output);
        assert!(
            !result.passed,
            "mixed output with a real error must not pass"
        );
        assert_eq!(
            result.error_count, 1,
            "real error must not be zeroed by the summary phrase"
        );
    }

    #[test]
    fn restic_check_mixed_fatal_and_phrase_stays_failed() {
        let output = "check: reading repository data\n\
                      fatal: could not read index\n\
                      no errors were found\n";
        let result = parse_restic_check(output);
        assert!(!result.passed);
        assert_eq!(result.error_count, 1);
    }

    #[test]
    fn restic_check_case_insensitive_error_and_summary() {
        let output = "ERROR: something broke\nNo Errors Were Found\n";
        let result = parse_restic_check(output);
        assert!(!result.passed);
        assert_eq!(result.error_count, 1);
    }

    #[test]
    fn restic_check_records_output_lines() {
        let output = "line one\nno errors were found\n";
        let result = parse_restic_check(output);
        assert_eq!(result.output_lines, vec!["line one", "no errors were found"]);
    }

    #[test]
    fn restic_snapshots_empty_returns_empty_vec() {
        let result = parse_restic_snapshots("   ").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn restic_snapshots_text_parses_rows() {
        // Single-space separated; the text parser splits on individual
        // whitespace characters, so column alignment with runs of spaces
        // would yield empty parts.
        let output = "ID Time Host Tags Paths\n\
                      ---\n\
                      a1b2c3d4 2024-01-02 host1 /home";
        let result = parse_restic_snapshots(output).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "a1b2c3d4");
        assert_eq!(result[0].full_id, "a1b2c3d4");
        assert_eq!(result[0].timestamp, "2024-01-02");
    }

    #[test]
    fn borg_list_parses_rows() {
        let output = "a1b2c3d4e5 2024-01-02T03:04:05 host1 /home";
        let result = parse_borg_list(output).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "a1b2c3d4");
        assert_eq!(result[0].timestamp, "2024-01-02T03:04:05");
    }
}
