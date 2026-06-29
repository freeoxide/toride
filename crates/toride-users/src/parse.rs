//! Parsing functions for `/etc/passwd`, `/etc/group`, and `/etc/sudoers`.
//!
//! Each parser returns strongly-typed structs that can be inspected,
//! validated, and rendered back to text.

use std::path::Path;

use crate::Result;

// ---------------------------------------------------------------------------
// PasswdEntry
// ---------------------------------------------------------------------------

/// A single entry from `/etc/passwd`.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PasswdEntry {
    /// Login name.
    pub username: String,
    /// Placeholder password field (typically `x` pointing to shadow).
    pub password: String,
    /// User ID (UID).
    pub uid: u32,
    /// Primary group ID (GID).
    pub gid: u32,
    /// GECOS comment field (full name, room, etc.).
    pub gecos: String,
    /// Home directory path.
    pub home: String,
    /// Login shell.
    pub shell: String,
}

impl std::fmt::Display for PasswdEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}:{}:{}:{}",
            self.username, self.password, self.uid, self.gid, self.gecos, self.home, self.shell
        )
    }
}

/// Parse the contents of `/etc/passwd` into a list of entries.
///
/// Blank lines and comments (starting with `#`) are skipped.
///
/// This parser is LENIENT at the per-line granularity, mirroring
/// [`parse_sudoers`]: a line that does not have exactly 7 colon-separated
/// fields, or whose UID/GID fails `u32` parsing, is logged with
/// `tracing::warn!` and skipped — every other valid line still survives. This
/// matters because `/etc/passwd` is free-form text that an operator may
/// hand-edit; a single malformed line must not discard the whole file (which
/// would otherwise render the read as an empty table and hide every valid
/// entry).
///
/// IO failures (the file could not be read at all) are still surfaced as
/// `Err` from [`read_passwd`].
pub fn parse_passwd(content: &str) -> Result<Vec<PasswdEntry>> {
    let mut entries = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() != 7 {
            tracing::warn!(
                "skipping malformed passwd line ({} fields, expected 7): {line:?}",
                fields.len()
            );
            continue;
        }
        let uid = match fields[2].parse::<u32>() {
            Ok(u) => u,
            Err(e) => {
                tracing::warn!("skipping passwd line with invalid UID {:?}: {e}", fields[2]);
                continue;
            }
        };
        let gid = match fields[3].parse::<u32>() {
            Ok(g) => g,
            Err(e) => {
                tracing::warn!("skipping passwd line with invalid GID {:?}: {e}", fields[3]);
                continue;
            }
        };
        entries.push(PasswdEntry {
            username: fields[0].to_owned(),
            password: fields[1].to_owned(),
            uid,
            gid,
            gecos: fields[4].to_owned(),
            home: fields[5].to_owned(),
            shell: fields[6].to_owned(),
        });
    }
    Ok(entries)
}

// ---------------------------------------------------------------------------
// GroupEntry
// ---------------------------------------------------------------------------

/// A single entry from `/etc/group`.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GroupEntry {
    /// Group name.
    pub name: String,
    /// Placeholder password field (typically `x`).
    pub password: String,
    /// Group ID (GID).
    pub gid: u32,
    /// Comma-separated list of supplementary member usernames.
    pub members: Vec<String>,
}

impl std::fmt::Display for GroupEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}",
            self.name,
            self.password,
            self.gid,
            self.members.join(",")
        )
    }
}

/// Parse the contents of `/etc/group` into a list of entries.
///
/// This parser is LENIENT at the per-line granularity, mirroring
/// [`parse_sudoers`] and [`parse_passwd`]: a line that does not have exactly 4
/// colon-separated fields, or whose GID fails `u32` parsing, is logged with
/// `tracing::warn!` and skipped — every other valid line still survives. As
/// with `/etc/passwd`, `/etc/group` is free-form text that an operator may
/// hand-edit, so a single malformed line must not discard the whole file.
///
/// IO failures (the file could not be read at all) are still surfaced as
/// `Err` from [`read_group`].
pub fn parse_group(content: &str) -> Result<Vec<GroupEntry>> {
    let mut entries = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() != 4 {
            tracing::warn!(
                "skipping malformed group line ({} fields, expected 4): {line:?}",
                fields.len()
            );
            continue;
        }
        let gid = match fields[2].parse::<u32>() {
            Ok(g) => g,
            Err(e) => {
                tracing::warn!("skipping group line with invalid GID {:?}: {e}", fields[2]);
                continue;
            }
        };
        let members = if fields[3].is_empty() {
            Vec::new()
        } else {
            fields[3].split(',').map(String::from).collect()
        };
        entries.push(GroupEntry {
            name: fields[0].to_owned(),
            password: fields[1].to_owned(),
            gid,
            members,
        });
    }
    Ok(entries)
}

// ---------------------------------------------------------------------------
// SudoersEntry
// ---------------------------------------------------------------------------

/// A parsed sudoers rule line.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SudoersEntry {
    /// Who the rule applies to (user or `%group`).
    pub who: String,
    /// Which hosts the rule applies to (typically `ALL`).
    pub hosts: String,
    /// Which commands the rule applies to (typically `ALL` or a command list).
    pub commands: String,
    /// Whether `NOPASSWD` is set for this rule.
    pub nopasswd: bool,
    /// Optional run-as user (the `(root)` part).
    pub runas: Option<String>,
}

/// Parse a sudoers file into a list of entries.
///
/// This is a simplified parser that handles the most common sudoers syntax.
/// It skips blank lines, comments, `Defaults`, `@include`, and `@includedir`
/// directives.
///
/// # Errors
///
/// Returns [`Error::SudoError`] if a rule line cannot be parsed.
pub fn parse_sudoers(content: &str) -> Result<Vec<SudoersEntry>> {
    let mut entries = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('@') {
            continue;
        }
        if line.starts_with("Defaults") {
            continue;
        }
        // Simplified parsing: "who hosts = (runas) [NOPASSWD:] commands"
        let parts: Vec<&str> = line.splitn(4, ' ').collect();
        if parts.len() < 3 {
            continue; // skip malformed lines gracefully
        }
        let who = parts[0].to_owned();
        let hosts = parts[1].to_owned();

        // The remaining parts contain "= (runas) [NOPASSWD:] commands"
        let rest = parts[2..].join(" ");
        let rest = rest.trim_start_matches('=').trim();

        let (runas, rest) = if let Some(r) = rest.strip_prefix('(') {
            if let Some(end) = r.find(')') {
                (Some(r[..end].to_owned()), r[end + 1..].trim().to_owned())
            } else {
                (None, rest.to_owned())
            }
        } else {
            (None, rest.to_owned())
        };

        let nopasswd = rest.contains("NOPASSWD:");
        let commands = rest.replace("NOPASSWD:", "").trim().to_owned();

        entries.push(SudoersEntry {
            who,
            hosts,
            commands,
            nopasswd,
            runas,
        });
    }
    Ok(entries)
}

// ---------------------------------------------------------------------------
// File-level parsing helpers
// ---------------------------------------------------------------------------

/// Read and parse `/etc/passwd` from disk.
///
/// # Errors
///
/// Returns [`Error::Io`] if the file cannot be read. Malformed lines are
/// skipped by [`parse_passwd`] (logged via `tracing::warn!`), never propagated
/// as `Err`.
pub fn read_passwd(path: &Path) -> Result<Vec<PasswdEntry>> {
    let content = std::fs::read_to_string(path)?;
    parse_passwd(&content)
}

/// Read and parse `/etc/group` from disk.
///
/// # Errors
///
/// Returns [`Error::Io`] if the file cannot be read. Malformed lines are
/// skipped by [`parse_group`] (logged via `tracing::warn!`), never propagated
/// as `Err`.
pub fn read_group(path: &Path) -> Result<Vec<GroupEntry>> {
    let content = std::fs::read_to_string(path)?;
    parse_group(&content)
}

/// Read and parse a sudoers file from disk.
///
/// # Errors
///
/// Returns [`Error::Io`] if the file cannot be read. Malformed rule lines are
/// skipped by [`parse_sudoers`], never propagated as `Err`.
pub fn read_sudoers(path: &Path) -> Result<Vec<SudoersEntry>> {
    let content = std::fs::read_to_string(path)?;
    parse_sudoers(&content)
}

// ── Tests ───────────────────────────────────────────────────────────────────
//
// These exercise the PARSER edge cases — the unhappy paths the audit flagged as
// having zero coverage. They pin the per-line lenient degradation behavior: a
// single malformed line must never discard the whole file, matching
// `parse_sudoers`'s long-standing `continue` precedent.

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_passwd ─────────────────────────────────────────────────────────

    #[test]
    fn parse_passwd_empty_input_is_ok_empty() {
        assert!(parse_passwd("").unwrap().is_empty());
    }

    #[test]
    fn parse_passwd_whitespace_only_input_is_ok_empty() {
        assert!(parse_passwd("   \n\t\n  ").unwrap().is_empty());
    }

    #[test]
    fn parse_passwd_comment_only_input_is_ok_empty() {
        assert!(parse_passwd("# a comment\n# another\n").unwrap().is_empty());
    }

    #[test]
    fn parse_passwd_valid_line_parses_fields() {
        let entries = parse_passwd("root:x:0:0:root:/root:/bin/bash\n").expect("valid line parses");
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.username, "root");
        assert_eq!(e.password, "x");
        assert_eq!(e.uid, 0);
        assert_eq!(e.gid, 0);
        assert_eq!(e.gecos, "root");
        assert_eq!(e.home, "/root");
        assert_eq!(e.shell, "/bin/bash");
    }

    #[test]
    fn parse_passwd_malformed_line_is_skipped_not_fatal() {
        // A valid entry, a degenerate line, then another valid entry. The two
        // valid entries must survive — this is the core per-line degradation
        // contract that previously failed fast and lost everything.
        let input = concat!(
            "root:x:0:0:root:/root:/bin/bash\n",
            "BADMALFORMEDLINE\n",
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
        );
        let entries = parse_passwd(input).expect("partial read must be Ok, not Err");
        assert_eq!(entries.len(), 2, "both valid entries survive the bad line");
        assert_eq!(entries[0].username, "root");
        assert_eq!(entries[1].username, "daemon");
    }

    #[test]
    fn parse_passwd_non_numeric_uid_is_skipped() {
        // A well-formed field count but a non-numeric UID — previously
        // returned Err and dropped the whole file.
        let input =
            "weird:x:notanumber:0:weird:/home/weird:/bin/bash\nroot:x:0:0:root:/root:/bin/bash\n";
        let entries = parse_passwd(input).expect("bad-UID line skipped, not fatal");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].username, "root");
    }

    #[test]
    fn parse_passwd_non_numeric_gid_is_skipped() {
        let input =
            "weird:x:0:notanumber:weird:/home/weird:/bin/bash\nroot:x:0:0:root:/root:/bin/bash\n";
        let entries = parse_passwd(input).expect("bad-GID line skipped, not fatal");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].username, "root");
    }

    #[test]
    fn parse_passwd_too_few_fields_is_skipped() {
        let input = "only:three:fields\nroot:x:0:0:root:/root:/bin/bash\n";
        let entries = parse_passwd(input).expect("short line skipped, not fatal");
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn parse_passwd_too_many_fields_is_skipped() {
        let input = "a:b:c:d:e:f:g:extra\nroot:x:0:0:root:/root:/bin/bash\n";
        let entries = parse_passwd(input).expect("long line skipped, not fatal");
        assert_eq!(entries.len(), 1);
    }

    // ── parse_group ──────────────────────────────────────────────────────────

    #[test]
    fn parse_group_empty_input_is_ok_empty() {
        assert!(parse_group("").unwrap().is_empty());
    }

    #[test]
    fn parse_group_comment_only_input_is_ok_empty() {
        assert!(parse_group("# group file\n").unwrap().is_empty());
    }

    #[test]
    fn parse_group_valid_line_parses_fields() {
        let entries = parse_group("sudo:x:27:deployer,ops\n").expect("valid line parses");
        assert_eq!(entries.len(), 1);
        let g = &entries[0];
        assert_eq!(g.name, "sudo");
        assert_eq!(g.password, "x");
        assert_eq!(g.gid, 27);
        assert_eq!(g.members, vec!["deployer".to_string(), "ops".to_string()]);
    }

    #[test]
    fn parse_group_empty_members_field_is_ok_empty_vec() {
        let entries = parse_group("nogroup:x:65534:\n").expect("empty members parse");
        assert_eq!(entries.len(), 1);
        assert!(entries[0].members.is_empty());
    }

    #[test]
    fn parse_group_malformed_line_is_skipped_not_fatal() {
        let input = "sudo:x:27:deployer\nBADMALFORMEDLINE\nwheel:x:10:root\n";
        let entries = parse_group(input).expect("partial read must be Ok, not Err");
        assert_eq!(entries.len(), 2, "both valid groups survive the bad line");
        assert_eq!(entries[0].name, "sudo");
        assert_eq!(entries[1].name, "wheel");
    }

    #[test]
    fn parse_group_non_numeric_gid_is_skipped() {
        let input = "weird:x:notanumber:user\nsudo:x:27:deployer\n";
        let entries = parse_group(input).expect("bad-GID line skipped, not fatal");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "sudo");
    }

    #[test]
    fn parse_group_wrong_field_count_is_skipped() {
        // !=4 fields.
        let input = "only:two\nsudo:x:27:deployer\na:b:c:d:extra\n";
        let entries = parse_group(input).expect("wrong-count lines skipped, not fatal");
        assert_eq!(entries.len(), 1);
    }

    // ── parse_sudoers ────────────────────────────────────────────────────────

    #[test]
    fn parse_sudoers_empty_input_is_ok_empty() {
        assert!(parse_sudoers("").unwrap().is_empty());
    }

    #[test]
    fn parse_sudoers_comment_and_directive_only_is_ok_empty() {
        let input =
            "# comment\nDefaults env_reset\n@include /etc/sudoers.d\n@includedir /etc/sudoers.d\n";
        assert!(parse_sudoers(input).unwrap().is_empty());
    }

    #[test]
    fn parse_sudoers_line_with_too_few_tokens_is_skipped() {
        // <3 space-parts — the existing `continue` path.
        let input = "onlyoneword\nroot ALL\n";
        let entries = parse_sudoers(input).expect("short lines skipped, not fatal");
        assert!(
            entries.is_empty(),
            "lines with <3 tokens produce no entries; got {entries:?}"
        );
    }

    #[test]
    fn parse_sudoers_valid_rule_parses_fields() {
        // The simplified parser splits on spaces with `splitn(4, ' ')`, so the
        // `=` must be its own whitespace-separated token (i.e. `who hosts = …`,
        // not `who hosts=(…)` which glues the `=` onto the host).
        let input = "%sudo ALL = (root) NOPASSWD: ALL\n";
        let entries = parse_sudoers(input).expect("valid rule parses");
        assert_eq!(entries.len(), 1);
        let s = &entries[0];
        assert_eq!(s.who, "%sudo");
        assert_eq!(s.hosts, "ALL");
        assert_eq!(s.runas.as_deref(), Some("root"));
        assert!(s.nopasswd);
        assert_eq!(s.commands, "ALL");
    }

    #[test]
    fn parse_sudoers_unmatched_paren_falls_back_to_no_runas() {
        // `= (runas` with no closing paren — the fall-back branch sets runas=None
        // and keeps the rest verbatim. Space-separated so the `=` is its own
        // token and the `(runas` reaches the runas-extraction logic.
        let input = "bob ALL = (root NOPASSWD: /bin/true\n";
        let entries = parse_sudoers(input).expect("unmatched paren is not fatal");
        assert_eq!(entries.len(), 1);
        let s = &entries[0];
        assert_eq!(s.who, "bob");
        assert!(
            s.runas.is_none(),
            "unmatched paren must fall back to runas=None; got {:?}",
            s.runas
        );
    }

    #[test]
    fn parse_sudoers_malformed_line_mid_file_is_skipped() {
        // A valid rule, a degenerate line, then another valid rule. Space-
        // separated `=` so the rules parse cleanly.
        let input = "%sudo ALL = (root) ALL\nBADMALFORMED\nroot ALL = (ALL) ALL\n";
        let entries = parse_sudoers(input).expect("partial read must be Ok, not Err");
        assert_eq!(entries.len(), 2, "both valid rules survive the bad line");
        assert_eq!(entries[0].who, "%sudo");
        assert_eq!(entries[1].who, "root");
    }
}
