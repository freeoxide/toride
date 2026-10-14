//! Parsers for audit subsystem output.
//!
//! Provides parsers for `auditctl`, `aureport`, and `ausearch` output,
//! converting raw text into structured types for programmatic consumption.

/// A single audit rule as reported by `auditctl -l`.
///
/// Syscall rules (`-a always,exit -F arch=b64 -S open -k key`) populate
/// `action`, `list`, `syscalls`, and `fields`; watch rules
/// (`-w /path -p wa -k key`) have no action or list (both stay empty) and
/// carry the watched path, permissions, and key as `fields` entries
/// (`("path", ...)`, `("perm", ...)`, `("key", ...)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditctlRule {
    /// The raw rule string.
    pub raw: String,
    /// The rule action for `-a` rules (`"always"` or `""`-terminated tokens
    /// like `always`/`never`); empty for `-w` watch rules.
    pub action: String,
    /// The system call filter list (`"exit"`, `"task"`, `"user"`, ...);
    /// empty for `-w` watch rules.
    pub list: String,
    /// The syscall names or `["all"]`; empty for `-w` watch rules.
    pub syscalls: Vec<String>,
    /// Field filters (`-F name[op]value`, plus `key`/`perm`/`path` entries
    /// as described on the struct).
    pub fields: Vec<(String, String)>,
}

/// Parse the output of `auditctl -l` into a list of structured rules.
///
/// Each non-empty line is one rule: a syscall rule (`-a action,list ...`),
/// a watch rule (`-w path ...`), or an error. Lines starting with
/// `No rules` produce an empty vector.
///
/// # Errors
///
/// Returns [`crate::Error::AuditRuleParse`] for a line that is neither a
/// syscall rule nor a watch rule (auditctl only prints those two shapes).
pub fn parse_auditctl_output(output: &str) -> crate::Result<Vec<AuditctlRule>> {
    if output.trim().starts_with("No rules") || output.trim().is_empty() {
        return Ok(Vec::new());
    }

    output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(parse_auditctl_line)
        .collect()
}

/// Parse one `auditctl -l` line into an [`AuditctlRule`].
fn parse_auditctl_line(line: &str) -> crate::Result<AuditctlRule> {
    if let Some(rest) = line.strip_prefix("-a ") {
        parse_syscall_rule(line, rest)
    } else if let Some(rest) = line.strip_prefix("-w ") {
        parse_watch_rule(line, rest)
    } else {
        Err(crate::Error::AuditRuleParse(format!(
            "unrecognised auditctl rule (expected a `-a` syscall rule or a `-w` watch rule): {line:?}"
        )))
    }
}

/// Parse `-a action,list [-F name[op]value]... [-S syscalls]... [-k key]`.
fn parse_syscall_rule(raw: &str, rest: &str) -> crate::Result<AuditctlRule> {
    let mut tokens = rest.split_whitespace();
    let action_list = tokens.next().unwrap_or_default();
    let Some((action, list)) = action_list.split_once(',') else {
        return Err(crate::Error::AuditRuleParse(format!(
            "auditctl `-a` rule needs `action,list`, got {action_list:?}"
        )));
    };

    let mut syscalls: Vec<String> = Vec::new();
    let mut fields: Vec<(String, String)> = Vec::new();
    let mut pending = tokens.peekable();
    while let Some(token) = pending.next() {
        match token {
            "-S" => {
                let Some(list) = pending.next() else {
                    return Err(missing_value(raw, "-S"));
                };
                syscalls.extend(list.split(',').map(str::to_owned));
            }
            "-k" => {
                let Some(key) = pending.next() else {
                    return Err(missing_value(raw, "-k"));
                };
                fields.push(("key".to_owned(), key.to_owned()));
            }
            "-F" => {
                let Some(field) = pending.next() else {
                    return Err(missing_value(raw, "-F"));
                };
                fields.push(parse_field_filter(field));
            }
            other => {
                return Err(crate::Error::AuditRuleParse(format!(
                    "unsupported auditctl token {other:?} in {raw:?}"
                )));
            }
        }
    }

    Ok(AuditctlRule {
        raw: raw.to_owned(),
        action: action.to_owned(),
        list: list.to_owned(),
        syscalls,
        fields,
    })
}

/// Parse `-w path [-p perms] [-k key]`.
fn parse_watch_rule(raw: &str, rest: &str) -> crate::Result<AuditctlRule> {
    let mut tokens = rest.split_whitespace();
    let Some(path) = tokens.next() else {
        return Err(crate::Error::AuditRuleParse(format!(
            "auditctl `-w` rule needs a path: {raw:?}"
        )));
    };

    let mut fields = vec![("path".to_owned(), path.to_owned())];
    let mut pending = tokens.peekable();
    while let Some(token) = pending.next() {
        match token {
            "-p" => {
                let Some(perms) = pending.next() else {
                    return Err(missing_value(raw, "-p"));
                };
                fields.push(("perm".to_owned(), perms.to_owned()));
            }
            "-k" => {
                let Some(key) = pending.next() else {
                    return Err(missing_value(raw, "-k"));
                };
                fields.push(("key".to_owned(), key.to_owned()));
            }
            other => {
                return Err(crate::Error::AuditRuleParse(format!(
                    "unsupported auditctl token {other:?} in {raw:?}"
                )));
            }
        }
    }

    Ok(AuditctlRule {
        raw: raw.to_owned(),
        action: String::new(),
        list: String::new(),
        syscalls: Vec::new(),
        fields,
    })
}

fn missing_value(raw: &str, flag: &str) -> crate::Error {
    crate::Error::AuditRuleParse(format!("auditctl flag {flag} needs a value in {raw:?}"))
}

/// Split a `-F name[op]value` filter (`arch=b64`, `auid>=1000`, `key="x"`)
/// at the first operator character: the comparison operator stays with the
/// value (`("auid", ">=1000")`), except a bare `=` which is dropped
/// (`("arch", "b64")`).
fn parse_field_filter(field: &str) -> (String, String) {
    let body = field.strip_prefix("-F ").unwrap_or(field);
    match body.find(['=', '<', '>', '!']) {
        Some(i) => {
            let rest = &body[i..];
            let value = rest.strip_prefix('=').unwrap_or(rest);
            (body[..i].to_owned(), value.trim_matches('"').to_owned())
        }
        None => (body.to_owned(), String::new()),
    }
}

/// A summary entry from `aureport`.
#[derive(Debug, Clone)]
pub struct AureportEntry {
    /// The report line number.
    pub number: usize,
    /// The raw line from the report.
    pub raw: String,
    /// The leading `YYYY-MM-DD HH:MM:SS` timestamp, when the line carries one.
    pub time: Option<String>,
}

/// Parse the output of `aureport` into a list of summary entries.
///
/// Lines shaped like `N. YYYY-MM-DD HH:MM:SS description` (the summary
/// report format) populate [`AureportEntry::time`]; other non-empty lines
/// keep `time: None`.
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
                time: extract_aureport_time(line),
            })
        })
        .collect()
}

/// Extract the leading timestamp of an aureport summary line
/// (`"1. 2025-01-01 00:00:00 ..."`), or `None` when absent.
fn extract_aureport_time(line: &str) -> Option<String> {
    let after_number = line.split_once(". ").map(|(_, rest)| rest.trim_start())?;
    let candidate = after_number.get(..19)?;
    let bytes = candidate.as_bytes();
    let shape = |i: usize| bytes[i].is_ascii_digit();
    (shape(0)
        && shape(1)
        && shape(2)
        && shape(3)
        && bytes[4] == b'-'
        && shape(5)
        && shape(6)
        && bytes[7] == b'-'
        && shape(8)
        && shape(9)
        && bytes[10] == b' '
        && shape(11)
        && shape(12)
        && bytes[13] == b':'
        && shape(14)
        && shape(15)
        && bytes[16] == b':'
        && shape(17)
        && shape(18))
    .then(|| candidate.to_owned())
}

/// A single event from `ausearch` output.
#[derive(Debug, Clone)]
pub struct AusearchEvent {
    /// The raw event text (may span multiple lines).
    pub raw: String,
    /// The first `type=` record name in the event (e.g. `SYSCALL`).
    pub event_type: Option<String>,
    /// The audit timestamp inside `msg=audit(SECS.MILLIS:SERIAL)`.
    pub time: Option<String>,
    /// The rule key that matched (`key="..."`), when present.
    pub key: Option<String>,
}

/// Parse the output of `ausearch` into a list of events.
///
/// Events are delimited by a line starting with `----`. Within each chunk,
/// the first `type=NAME` token becomes [`AusearchEvent::event_type`], the
/// `msg=audit(SECS.MILLIS:...)` timestamp becomes [`AusearchEvent::time`],
/// and a `key="..."` token becomes [`AusearchEvent::key`].
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
            event_type: extract_ausearch_type(chunk),
            time: extract_ausearch_time(chunk),
            key: extract_ausearch_key(chunk),
        })
        .collect();

    Ok(events)
}

/// First `type=VALUE` token of a chunk.
fn extract_ausearch_type(chunk: &str) -> Option<String> {
    chunk
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix("type="))
        .map(str::to_owned)
}

/// `SECS.MILLIS` from the first `msg=audit(SECS.MILLIS:SERIAL)` token.
fn extract_ausearch_time(chunk: &str) -> Option<String> {
    let token = chunk
        .split_whitespace()
        .find(|tok| tok.starts_with("msg=audit("))?;
    let inner = token.strip_prefix("msg=audit(")?;
    let secs_millis = inner.split(':').next()?;
    (secs_millis.contains('.')).then(|| secs_millis.to_owned())
}

/// Unquoted value of a `key="..."` token.
fn extract_ausearch_key(chunk: &str) -> Option<String> {
    chunk
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix("key="))
        .map(|v| v.trim_matches('"').to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Syscall rules populate action, list, syscalls, and fields from the
    /// documented `auditctl -l` shapes instead of empty defaults.
    #[test]
    fn parse_auditctl_syscall_rule_extracts_structure() {
        let rules = parse_auditctl_output(
            "-a always,exit -F arch=b64 -S open,close -F auid>=1000 -k session",
        )
        .unwrap();
        assert_eq!(rules.len(), 1);
        let rule = &rules[0];
        assert_eq!(rule.action, "always");
        assert_eq!(rule.list, "exit");
        assert_eq!(rule.syscalls, vec!["open", "close"]);
        assert_eq!(
            rule.fields,
            vec![
                ("arch".to_owned(), "b64".to_owned()),
                ("auid".to_owned(), ">=1000".to_owned()),
                ("key".to_owned(), "session".to_owned()),
            ]
        );
    }

    /// Watch rules (`-w path -p perms -k key`) carry their path, permissions,
    /// and key as fields; action/list/syscalls stay empty.
    #[test]
    fn parse_auditctl_watch_rule_extracts_path_perm_key() {
        let rules = parse_auditctl_output("-w /etc/passwd -p wa -k identity").unwrap();
        assert_eq!(rules.len(), 1);
        let rule = &rules[0];
        assert_eq!(rule.action, "");
        assert_eq!(rule.list, "");
        assert_eq!(rule.syscalls, Vec::<String>::new());
        assert_eq!(
            rule.fields,
            vec![
                ("path".to_owned(), "/etc/passwd".to_owned()),
                ("perm".to_owned(), "wa".to_owned()),
                ("key".to_owned(), "identity".to_owned()),
            ]
        );
    }

    /// `-F key="quoted"` (newer auditctl rendering) lands in fields as a
    /// normal key entry.
    #[test]
    fn parse_auditctl_field_key_form_is_recognised() {
        let rules =
            parse_auditctl_output("-a never,exit -F arch=b64 -S all -F key=identity").unwrap();
        let rule = &rules[0];
        assert_eq!(rule.action, "never");
        assert_eq!(rule.syscalls, vec!["all"]);
        assert_eq!(
            rule.fields,
            vec![
                ("arch".to_owned(), "b64".to_owned()),
                ("key".to_owned(), "identity".to_owned()),
            ]
        );
    }

    /// Unstructured lines are a typed error, not an empty-default rule.
    #[test]
    fn parse_auditctl_rejects_unstructured_lines() {
        let err = parse_auditctl_output("this is not a rule").unwrap_err();
        assert!(matches!(err, crate::Error::AuditRuleParse(_)), "{err:?}");
    }

    #[test]
    fn parse_auditctl_rejects_missing_flag_values() {
        for line in ["-a always,exit -S", "-w /etc -p"] {
            let err = parse_auditctl_output(line).unwrap_err();
            assert!(
                matches!(err, crate::Error::AuditRuleParse(_)),
                "{line:?}: got {err:?}"
            );
        }
    }

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

    /// The leading `YYYY-MM-DD HH:MM:SS` timestamp is extracted per entry.
    #[test]
    fn parse_aureport_extracts_timestamps() {
        let input = "1. 2025-01-01 00:00:00 test entry one\n\
                     2. no timestamp line";
        let entries = parse_aureport(input).unwrap();
        assert_eq!(
            entries[0].time.as_deref(),
            Some("2025-01-01 00:00:00"),
            "numbered summary lines carry their timestamp"
        );
        assert_eq!(entries[1].time, None, "non-timestamp lines stay None");
    }

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

    /// Real-shaped ausearch records populate event type, audit timestamp,
    /// and matched rule key.
    #[test]
    fn parse_ausearch_extracts_type_time_and_key() {
        let input = "----\ntype=SYSCALL msg=audit(1699999999.123:456): arch=c300003 syscall=write success=yes exit=3 a0=1 key=\"session\"\n----\n";
        let events = parse_ausearch(input).unwrap();
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.event_type.as_deref(), Some("SYSCALL"));
        assert_eq!(event.time.as_deref(), Some("1699999999.123"));
        assert_eq!(event.key.as_deref(), Some("session"));
    }

    #[test]
    fn parse_ausearch_fields_absent_stay_none() {
        let events = parse_ausearch("plain text without markers").unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, None);
        assert_eq!(events[0].time, None);
        assert_eq!(events[0].key, None);
    }
}
