//! AIDE output parsing.
//!
//! Provides parsers for AIDE check and diff output, converting raw text
//! into structured types for programmatic consumption.

// ---------------------------------------------------------------------------
// AideChange
// ---------------------------------------------------------------------------

/// A single file change detected by AIDE.
#[derive(Debug, Clone)]
pub struct AideChange {
    /// The path of the changed file.
    pub path: String,
    /// The type of change detected.
    pub change_type: AideChangeType,
    /// Details about the change (old/new values).
    pub details: Vec<String>,
}

// ---------------------------------------------------------------------------
// AideChangeType
// ---------------------------------------------------------------------------

/// The type of change detected by AIDE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AideChangeType {
    /// A new file was added.
    Added,
    /// A file was removed.
    Removed,
    /// A file was modified.
    Changed,
    /// The change type could not be determined.
    Unknown,
}

// ---------------------------------------------------------------------------
// AideCheckResult
// ---------------------------------------------------------------------------

/// Parsed result of an AIDE integrity check.
#[derive(Debug, Clone)]
pub struct AideCheckResult {
    /// Whether the check passed (no changes detected).
    pub passed: bool,
    /// Number of files added.
    pub added: usize,
    /// Number of files removed.
    pub removed: usize,
    /// Number of files changed.
    pub changed: usize,
    /// Individual changes detected.
    pub changes: Vec<AideChange>,
    /// Raw output from AIDE.
    pub raw_output: String,
}

// ---------------------------------------------------------------------------
// Parsing functions
// ---------------------------------------------------------------------------

/// Parse AIDE check output into a structured result.
///
/// Attempts to extract summary counts from the AIDE output. Falls back
/// to scanning for change indicators if the summary line is not found.
///
/// # Errors
///
/// Returns [`crate::Error::AideError`] if the output cannot be parsed.
pub fn parse_aide_check(output: &str) -> crate::Result<AideCheckResult> {
    let mut result = AideCheckResult {
        passed: true,
        added: 0,
        removed: 0,
        changed: 0,
        changes: Vec::new(),
        raw_output: output.to_owned(),
    };

    for line in output.lines() {
        let trimmed = line.trim();

        // Look for summary line like "Changed entries: 5"
        if trimmed.starts_with("Changed entries:")
            && let Some(num) = extract_number(trimmed)
        {
            result.changed = num;
            if num > 0 {
                result.passed = false;
            }
        } else if trimmed.starts_with("Added entries:") {
            if let Some(num) = extract_number(trimmed) {
                result.added = num;
                if num > 0 {
                    result.passed = false;
                }
            }
        } else if trimmed.starts_with("Removed entries:")
            && let Some(num) = extract_number(trimmed)
        {
            result.removed = num;
            if num > 0 {
                result.passed = false;
            }
        }

        // Detect individual changes.
        if trimmed.starts_with("f = ") || trimmed.starts_with("f+++ ") {
            result.changes.push(AideChange {
                path: trimmed[4..].trim().to_owned(),
                change_type: AideChangeType::Added,
                details: Vec::new(),
            });
        } else if let Some(stripped) = trimmed.strip_prefix("f--- ") {
            result.changes.push(AideChange {
                path: stripped.trim().to_owned(),
                change_type: AideChangeType::Removed,
                details: Vec::new(),
            });
        } else if trimmed.starts_with("f!! ") || trimmed.starts_with("f>p ") {
            result.changes.push(AideChange {
                path: trimmed[4..].trim().to_owned(),
                change_type: AideChangeType::Changed,
                details: Vec::new(),
            });
        }
    }

    // Individual change markers (f+++, f---, f!!, f>p, f =) drive per-line
    // detection independent of the 'Changed/Added/Removed entries: N' summary.
    // If AIDE emits change markers but the summary line is absent, truncated,
    // or formatted differently (e.g. a different AIDE version, output captured
    // mid-run, or output captured from stderr where the summary goes to
    // stdout), `passed` must still reflect that changes were detected.
    if !result.changes.is_empty() {
        result.passed = false;
    }

    Ok(result)
}

/// Parse AIDE database initialization output.
///
/// Returns the raw output as a result, checking for success indicators.
pub fn parse_aide_init(output: &str) -> crate::Result<bool> {
    Ok(output.contains("AIDE database initialized"))
}

/// Extract a trailing number from a string like "Changed entries: 5".
fn extract_number(s: &str) -> Option<usize> {
    s.split_whitespace().last().and_then(|v| v.parse().ok())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_aide_check_clean_output_passed() {
        let output = "AIDE 0.17.4 found NO changes\n";
        let result = parse_aide_check(output).unwrap();
        assert!(result.passed);
        assert_eq!(result.changed, 0);
        assert_eq!(result.added, 0);
        assert_eq!(result.removed, 0);
    }

    #[test]
    fn parse_aide_check_detects_changed_entries() {
        let output = "\
Changed entries:
f!! /etc/passwd
Changed entries: 1
Added entries: 0
Removed entries: 0
";
        let result = parse_aide_check(output).unwrap();
        assert!(!result.passed);
        assert_eq!(result.changed, 1);
        assert_eq!(result.changes.len(), 1);
        assert_eq!(result.changes[0].path, "/etc/passwd");
        assert_eq!(result.changes[0].change_type, AideChangeType::Changed);
    }

    #[test]
    fn parse_aide_check_detects_added_entries() {
        let output = "Added entries:\nf+++ /etc/newfile\nAdded entries: 1\nChanged entries: 0\nRemoved entries: 0\n";
        let result = parse_aide_check(output).unwrap();
        assert!(!result.passed);
        assert_eq!(result.added, 1);
        assert_eq!(result.changes[0].change_type, AideChangeType::Added);
    }

    #[test]
    fn parse_aide_check_detects_removed_entries() {
        let output = "Removed entries:\nf--- /etc/oldfile\nRemoved entries: 1\nChanged entries: 0\nAdded entries: 0\n";
        let result = parse_aide_check(output).unwrap();
        assert!(!result.passed);
        assert_eq!(result.removed, 1);
        assert_eq!(result.changes[0].change_type, AideChangeType::Removed);
    }

    #[test]
    fn parse_aide_check_f_equals_prefix_is_added() {
        let output =
            "f = /etc/something\nChanged entries: 0\nAdded entries: 0\nRemoved entries: 0\n";
        let result = parse_aide_check(output).unwrap();
        // An `f = ` marker is an added-entry change: even though the summary
        // line reports zero changes, the per-line marker is a real change, so
        // `passed` must be false.
        assert!(!result.passed);
        assert_eq!(result.changes.len(), 1);
        assert_eq!(result.changes[0].change_type, AideChangeType::Added);
    }

    #[test]
    fn parse_aide_check_change_markers_without_summary_marks_failed() {
        // AIDE output can carry per-line change markers without the
        // 'Changed entries: N' summary (different AIDE version, truncated
        // output, output captured mid-run or from stderr). The parser must
        // still treat any detected change as a failure.
        let output = "\
Start timestamp: 2024-01-01 00:00:00
AIDE found differences between database and filesystem!!

Summary:
  Total number of entries: 1234

f!! /etc/passwd
f>p /etc/shadow
f+++ /etc/newfile
f--- /etc/oldfile
";
        let result = parse_aide_check(output).unwrap();
        assert!(!result.passed, "change markers must flip passed=false");
        // Summary line absent -> counts stay 0, but changes are populated.
        assert_eq!(result.changed, 0);
        assert_eq!(result.added, 0);
        assert_eq!(result.removed, 0);
        assert_eq!(result.changes.len(), 4);
    }

    #[test]
    fn parse_aide_check_zero_summary_with_no_markers_passes() {
        // A genuinely clean report (no markers, zero summary) stays passed.
        let output = "AIDE 0.17.4 found NO changes\nChanged entries: 0\nAdded entries: 0\nRemoved entries: 0\n";
        let result = parse_aide_check(output).unwrap();
        assert!(result.passed);
        assert!(result.changes.is_empty());
    }

    #[test]
    fn parse_aide_check_raw_output_preserved() {
        let output = "AIDE 0.17 found NO changes\n";
        let result = parse_aide_check(output).unwrap();
        assert_eq!(result.raw_output, output);
    }

    #[test]
    fn parse_aide_init_success() {
        let output = "AIDE database initialized at /var/lib/aide/aide.db";
        assert!(parse_aide_init(output).unwrap());
    }

    #[test]
    fn parse_aide_init_failure() {
        let output = "Error: could not initialize database";
        assert!(!parse_aide_init(output).unwrap());
    }

    #[test]
    fn parse_aide_init_empty() {
        assert!(!parse_aide_init("").unwrap());
    }

    #[test]
    fn extract_number_parses_trailing_integer() {
        assert_eq!(extract_number("Changed entries: 5"), Some(5));
        assert_eq!(extract_number("Changed entries: 0"), Some(0));
        assert_eq!(extract_number("no number here"), None);
    }
}
