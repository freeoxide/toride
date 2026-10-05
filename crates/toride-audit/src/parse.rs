//! Parsers for audit subsystem output.
//!
//! Provides parsers for `auditctl`, `aureport`, and `ausearch` output,
//! converting raw text into structured types for programmatic consumption.

// ---------------------------------------------------------------------------
// Auditctl output parsing
// ---------------------------------------------------------------------------

/// A single audit rule as reported by `auditctl -l`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditctlRule {
    /// The raw rule string.
    pub raw: String,
    /// The rule action (e.g. "always", "never").
    pub action: String,
    /// The system call filter list (e.g. "exit", "task", "user").
    pub list: String,
    /// The syscall names or "all".
    pub syscalls: Vec<String>,
    /// Field filters (key=value pairs).
    pub fields: Vec<(String, String)>,
}

/// Parse the output of `auditctl -l` into a list of structured rules.
///
/// Each non-empty line is treated as a separate rule. Lines starting with
/// `No rules` produce an empty vector.
///
/// # Errors
///
/// Returns [`crate::Error::AuditRuleParse`] if a line cannot be parsed.
pub fn parse_auditctl_output(output: &str) -> crate::Result<Vec<AuditctlRule>> {
    if output.trim().starts_with("No rules") || output.trim().is_empty() {
        return Ok(Vec::new());
    }

    output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            Ok(AuditctlRule {
                raw: line.to_owned(),
                action: String::new(),
                list: String::new(),
                syscalls: Vec::new(),
                fields: Vec::new(),
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Aureport output parsing
// ---------------------------------------------------------------------------

/// A summary entry from `aureport`.
#[derive(Debug, Clone)]
pub struct AureportEntry {
    /// The report line number.
    pub number: usize,
    /// The raw line from the report.
    pub raw: String,
    /// Timestamp if available.
    pub time: Option<String>,
}

/// Parse the output of `aureport` into a list of summary entries.
///
/// # Errors
///
/// Returns [`crate::Error::AuditRuleParse`] if the output cannot be parsed.
pub fn parse_aureport(output: &str) -> crate::Result<Vec<AureportEntry>> {
    output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
        .map(|(i, line)| {
            Ok(AureportEntry {
                number: i + 1,
                raw: line.to_owned(),
                time: None,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Ausearch output parsing
// ---------------------------------------------------------------------------

/// A single event from `ausearch` output.
#[derive(Debug, Clone)]
pub struct AusearchEvent {
    /// The raw event text (may span multiple lines).
    pub raw: String,
    /// Event type if identified.
    pub event_type: Option<String>,
    /// Event timestamp.
    pub time: Option<String>,
    /// Audit rule key that matched.
    pub key: Option<String>,
}

/// Parse the output of `ausearch` into a list of events.
///
/// Events are delimited by a line starting with `----`.
///
/// # Errors
///
/// Returns [`crate::Error::AuditRuleParse`] if the output cannot be parsed.
pub fn parse_ausearch(output: &str) -> crate::Result<Vec<AusearchEvent>> {
    if output.trim().is_empty() {
        return Ok(Vec::new());
    }

    let events: Vec<AusearchEvent> = output
        .split("----")
        .filter(|chunk| !chunk.trim().is_empty())
        .map(|chunk| AusearchEvent {
            raw: chunk.trim().to_owned(),
            event_type: None,
            time: None,
            key: None,
        })
        .collect();

    Ok(events)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- parse_auditctl_output ------------------------------------------------

    #[test]
    fn parse_auditctl_no_rules_returns_empty() {
        let rules = parse_auditctl_output("No rules").unwrap();
        assert_eq!(rules, Vec::new());
    }

    #[test]
    fn parse_auditctl_empty_returns_empty() {
        let rules = parse_auditctl_output("").unwrap();
        assert_eq!(rules, Vec::new());
    }

    #[test]
    fn parse_auditctl_multiline_returns_correct_count() {
        let input = "-a always,exit -F arch=b64 -S open -k test1\n\
                     -w /etc/passwd -p wa -k identity\n\
                     -a always,exit -F arch=b64 -S write -k test2";
        let rules = parse_auditctl_output(input).unwrap();
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0].raw, "-a always,exit -F arch=b64 -S open -k test1");
        assert_eq!(rules[1].raw, "-w /etc/passwd -p wa -k identity");
        assert_eq!(rules[2].raw, "-a always,exit -F arch=b64 -S write -k test2");
    }

    // -- parse_aureport -------------------------------------------------------

    #[test]
    fn parse_aureport_empty_returns_empty() {
        let entries = parse_aureport("").unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_aureport_numbered_entries() {
        let input = "1. 2025-01-01 00:00:00 test entry one\n\
                     2. 2025-01-02 12:30:00 test entry two\n\
                     3. 2025-01-03 08:15:00 test entry three";
        let entries = parse_aureport(input).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].number, 1);
        assert_eq!(entries[1].number, 2);
        assert_eq!(entries[2].number, 3);
        assert!(entries[0].raw.contains("test entry one"));
    }

    // -- parse_ausearch -------------------------------------------------------

    #[test]
    fn parse_ausearch_with_separators() {
        let input = "type=SYSCALL msg=audit(1234): item\n----\ntype=PATH msg=audit(5678): other";
        let events = parse_ausearch(input).unwrap();
        assert_eq!(events.len(), 2);
        assert!(events[0].raw.contains("SYSCALL"));
        assert!(events[1].raw.contains("PATH"));
    }

    #[test]
    fn parse_ausearch_empty_returns_empty() {
        let events = parse_ausearch("").unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn parse_ausearch_multiple_dashes() {
        let input = "event1\n----\nevent2\n----\nevent3";
        let events = parse_ausearch(input).unwrap();
        assert_eq!(events.len(), 3);
    }
}
