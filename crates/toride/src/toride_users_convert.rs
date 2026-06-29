//! Convert `toride-users` library types to UI presentation types.
//!
//! This is the ONLY module in the `toride` crate that imports `toride_users`
//! types — mirroring `fail2ban_convert.rs`'s role as the single boundary
//! between backend and presentation. Each function handles errors gracefully:
//! malformed input is skipped with a `tracing::warn!` and a placeholder, never
//! propagated (the read-only section must never crash the TUI).

use crate::ui::screens::toride_users::{GroupEntry, SudoersEntry, UserEntry, UserFindingEntry};

/// Map a backend [`toride_users::report::Severity`] to a lowercase string used
/// by the presentation layer: `"ok" | "info" | "warning" | "error" |
/// "critical"`. Kept here so the TUI never imports the Severity enum directly.
fn severity_str(s: toride_users::report::Severity) -> &'static str {
    use toride_users::report::Severity;
    match s {
        Severity::Ok => "ok",
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Error => "error",
        Severity::Critical => "critical",
    }
}

/// Convert a parsed `/etc/passwd` entry to a UI user row.
///
/// The `sudo`, `locked`, and `totp` fields are unknown at parse time (they
/// require extra probes that the collector runs separately) and default to
/// `None` here. The collector overlays the probe results onto the row.
pub fn convert_passwd(entry: toride_users::parse::PasswdEntry) -> UserEntry {
    let username = if entry.username.is_empty() {
        tracing::warn!("passwd entry with empty username: {entry:?}");
        "(unknown)".into()
    } else {
        entry.username
    };
    UserEntry {
        username,
        uid: entry.uid,
        gid: entry.gid,
        gecos: entry.gecos,
        home: entry.home,
        shell: entry.shell,
        // Unknown until the collector runs the sudo/locked/totp probes.
        sudo: None,
        locked: None,
        totp: None,
    }
}

/// Convert all parsed passwd entries to UI rows.
pub fn convert_passwd_all(entries: Vec<toride_users::parse::PasswdEntry>) -> Vec<UserEntry> {
    entries.into_iter().map(convert_passwd).collect()
}

/// Convert a parsed `/etc/group` entry to a UI group row.
pub fn convert_group(entry: toride_users::parse::GroupEntry) -> GroupEntry {
    let name = if entry.name.is_empty() {
        tracing::warn!("group entry with empty name: {entry:?}");
        "(unknown)".into()
    } else {
        entry.name
    };
    GroupEntry {
        name,
        gid: entry.gid,
        members: entry.members,
    }
}

/// Convert all parsed group entries to UI rows.
pub fn convert_group_all(entries: Vec<toride_users::parse::GroupEntry>) -> Vec<GroupEntry> {
    entries.into_iter().map(convert_group).collect()
}

/// Convert a parsed sudoers rule to a UI row.
///
/// Malformed entries (empty `who` or `hosts`) are logged but still produced
/// with placeholders so the row count matches the backend.
pub fn convert_sudoers(entry: toride_users::parse::SudoersEntry) -> SudoersEntry {
    if entry.who.is_empty() || entry.hosts.is_empty() {
        tracing::warn!(
            "sudoers entry with empty who/hosts: who={:?} hosts={:?}",
            entry.who,
            entry.hosts
        );
    }
    SudoersEntry {
        who: if entry.who.is_empty() {
            "(unknown)".into()
        } else {
            entry.who
        },
        hosts: entry.hosts,
        commands: entry.commands,
        nopasswd: entry.nopasswd,
        runas: entry.runas,
    }
}

/// Convert all parsed sudoers rules to UI rows.
pub fn convert_sudoers_all(entries: Vec<toride_users::parse::SudoersEntry>) -> Vec<SudoersEntry> {
    entries.into_iter().map(convert_sudoers).collect()
}

/// Convert backend doctor findings to UI entries.
///
/// Every finding maps 1:1. An empty `id` or `title` is logged and the entry is
/// still produced with a placeholder so the row count matches the backend (the
/// operator can see "something" even if the finding is malformed).
pub fn convert_findings(findings: Vec<toride_users::report::UserFinding>) -> Vec<UserFindingEntry> {
    findings
        .into_iter()
        .map(|f| {
            if f.id.is_empty() || f.title.is_empty() {
                tracing::warn!(
                    "users finding with empty id/title: id={:?} title={:?}",
                    f.id,
                    f.title
                );
            }
            UserFindingEntry {
                id: if f.id.is_empty() {
                    "(unknown)".into()
                } else {
                    f.id
                },
                severity: severity_str(f.severity).to_string(),
                title: if f.title.is_empty() {
                    "(no title)".into()
                } else {
                    f.title
                },
                detail: f.detail,
                fix: f.fix,
            }
        })
        .collect()
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use toride_users::parse::{
        GroupEntry as RawGroup, PasswdEntry as RawPasswd, SudoersEntry as RawSudoers,
    };
    use toride_users::report::{Severity, UserFinding};

    // ── convert_passwd ────────────────────────────────────────────────────────

    #[test]
    fn convert_passwd_maps_fields() {
        let raw = RawPasswd {
            username: "deployer".into(),
            password: "x".into(),
            uid: 1001,
            gid: 1001,
            gecos: "Deploy User".into(),
            home: "/home/deployer".into(),
            shell: "/bin/bash".into(),
        };
        let e = convert_passwd(raw);
        assert_eq!(e.username, "deployer");
        assert_eq!(e.uid, 1001);
        assert_eq!(e.shell, "/bin/bash");
        assert!(e.sudo.is_none());
        assert!(e.locked.is_none());
        assert!(e.totp.is_none());
    }

    #[test]
    fn convert_passwd_placeholder_for_empty_username() {
        let raw = RawPasswd {
            username: String::new(),
            password: "x".into(),
            uid: 0,
            gid: 0,
            gecos: String::new(),
            home: String::new(),
            shell: String::new(),
        };
        let e = convert_passwd(raw);
        assert_eq!(e.username, "(unknown)");
    }

    #[test]
    fn convert_passwd_all_empty() {
        assert!(convert_passwd_all(Vec::new()).is_empty());
    }

    // ── convert_group ─────────────────────────────────────────────────────────

    #[test]
    fn convert_group_maps_fields() {
        let raw = RawGroup {
            name: "sudo".into(),
            password: "x".into(),
            gid: 27,
            members: vec!["deployer".into(), "ops".into()],
        };
        let g = convert_group(raw);
        assert_eq!(g.name, "sudo");
        assert_eq!(g.gid, 27);
        assert_eq!(g.members.len(), 2);
    }

    #[test]
    fn convert_group_placeholder_for_empty_name() {
        let raw = RawGroup {
            name: String::new(),
            password: "x".into(),
            gid: 0,
            members: Vec::new(),
        };
        let g = convert_group(raw);
        assert_eq!(g.name, "(unknown)");
    }

    #[test]
    fn convert_group_all_empty() {
        assert!(convert_group_all(Vec::new()).is_empty());
    }

    // ── convert_sudoers ───────────────────────────────────────────────────────

    #[test]
    fn convert_sudoers_maps_fields() {
        let raw = RawSudoers {
            who: "%sudo".into(),
            hosts: "ALL".into(),
            commands: "ALL".into(),
            nopasswd: false,
            runas: Some("root".into()),
        };
        let s = convert_sudoers(raw);
        assert_eq!(s.who, "%sudo");
        assert!(!s.nopasswd);
        assert_eq!(s.runas.as_deref(), Some("root"));
    }

    #[test]
    fn convert_sudoers_placeholder_for_empty_who() {
        let raw = RawSudoers {
            who: String::new(),
            hosts: "ALL".into(),
            commands: "ALL".into(),
            nopasswd: false,
            runas: None,
        };
        let s = convert_sudoers(raw);
        assert_eq!(s.who, "(unknown)");
    }

    #[test]
    fn convert_sudoers_maps_all_fields_with_no_runas() {
        // The common case: a sudoers rule without a parenthesized runas.
        // Locks the plain runas=None + non-empty who mapping (the existing
        // None-runas test pairs None with an empty who).
        let raw = RawSudoers {
            who: "%wheel".into(),
            hosts: "ALL".into(),
            commands: "ALL".into(),
            nopasswd: true,
            runas: None,
        };
        let s = convert_sudoers(raw);
        assert_eq!(s.who, "%wheel");
        assert_eq!(s.hosts, "ALL");
        assert_eq!(s.commands, "ALL");
        assert!(s.nopasswd);
        assert!(s.runas.is_none());
    }

    #[test]
    fn convert_sudoers_all_empty() {
        assert!(convert_sudoers_all(Vec::new()).is_empty());
    }

    // ── convert_findings ──────────────────────────────────────────────────────

    #[test]
    fn convert_findings_empty() {
        assert!(convert_findings(Vec::new()).is_empty());
    }

    #[test]
    fn convert_findings_maps_severity() {
        let findings = vec![
            UserFinding::new("a", Severity::Critical, "t1"),
            UserFinding::new("b", Severity::Error, "t2"),
            UserFinding::new("c", Severity::Warning, "t3"),
            UserFinding::new("d", Severity::Info, "t4"),
            UserFinding::new("e", Severity::Ok, "t5"),
        ];
        let entries = convert_findings(findings);
        assert_eq!(entries.len(), 5);
        assert_eq!(entries[0].severity, "critical");
        assert_eq!(entries[1].severity, "error");
        assert_eq!(entries[2].severity, "warning");
        assert_eq!(entries[3].severity, "info");
        assert_eq!(entries[4].severity, "ok");
    }

    #[test]
    fn convert_findings_preserves_detail_and_fix() {
        let f = UserFinding::new("id", Severity::Warning, "title")
            .detail("the detail")
            .fix("the fix");
        let entries = convert_findings(vec![f]);
        assert_eq!(entries[0].detail, "the detail");
        assert_eq!(entries[0].fix.as_deref(), Some("the fix"));
    }

    #[test]
    fn convert_findings_placeholder_for_empty_fields() {
        let f = UserFinding::new("", Severity::Ok, "");
        let entries = convert_findings(vec![f]);
        assert_eq!(entries[0].id, "(unknown)");
        assert_eq!(entries[0].title, "(no title)");
    }
}
