//! Convert `toride-fail2ban` library types to UI presentation types.
//!
//! This is the ONLY module in the `toride` crate that imports
//! `toride_fail2ban` types — mirroring `ssh_convert.rs`'s role as the single
//! boundary between backend and presentation. Each function handles errors
//! gracefully: malformed input lines are skipped with a `tracing::warn!` and a
//! placeholder, never propagated (the read-only section must never crash the
//! TUI).

use crate::ui::screens::fail2ban::{BanEntry, FindingEntry, JailEntry};

/// Map a backend [`toride_fail2ban::report::Severity`] to a lowercase string
/// used by the presentation layer: `"ok" | "info" | "warning" | "error" |
/// "critical"`. Kept here so the TUI never imports the Severity enum directly.
fn severity_str(s: toride_fail2ban::report::Severity) -> &'static str {
    use toride_fail2ban::report::Severity;
    match s {
        Severity::Ok => "ok",
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Error => "error",
        Severity::Critical => "critical",
    }
}

/// Convert backend doctor findings to UI entries.
///
/// Every finding maps 1:1. An empty `id` or `title` is logged and the entry is
/// still produced with a placeholder so the row count matches the backend (the
/// operator can see "something" even if the finding is malformed).
pub fn convert_findings(findings: Vec<toride_fail2ban::report::Finding>) -> Vec<FindingEntry> {
    findings
        .into_iter()
        .map(|f| {
            if f.id.is_empty() || f.title.is_empty() {
                tracing::warn!(
                    "fail2ban finding with empty id/title: id={:?} title={:?}",
                    f.id,
                    f.title
                );
            }
            FindingEntry {
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

/// Parse jail names from `fail2ban-client status` output.
///
/// Looks for the `Jail list:` line and splits the comma-separated names after
/// the colon. This mirrors the backend's private `parse_jail_list` helper but
/// is reproduced here so the convert layer stays self-contained.
pub fn parse_jail_names(status: &str) -> Vec<String> {
    for line in status.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("jail list")
            && let Some(idx) = line.find(':')
        {
            return line[idx + 1..]
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
    }
    Vec::new()
}

/// Parse the global `fail2ban-client status` output into jail rows.
///
/// Returns one [`JailEntry`] per jail name discovered in the `Jail list:`
/// line. Per-jail detail (banned count, file count, total bans) is NOT
/// available from the global status output without a per-jail
/// `fail2ban-client status <name>` call, so this mapper only sets the name and
/// `is_running = true` (the jail appearing in the list implies it is active);
/// the collector enriches counts from the per-jail call when it has them.
pub fn parse_jails_from_status(status: &str) -> Vec<JailEntry> {
    let names = parse_jail_names(status);
    if names.is_empty() {
        return Vec::new();
    }
    names
        .into_iter()
        .map(|name| JailEntry {
            name,
            is_running: true,
            banned_count: 0,
            total_bans: 0,
            file_count: 0,
        })
        .collect()
}

/// Enrich a jail entry with parsed per-jail status counts.
///
/// Parses the output of `fail2ban-client status <jail>`, which looks like:
///
/// ```text
/// Status for the jail: sshd
/// |- Filter
/// |  |- Currently failed: 2
/// |  |- Total failed:     10
/// |  `- File list:        /var/log/auth.log
/// `- Actions
///    |- Currently banned: 3
///    |- Total banned:     12
///    `- Banned IP list:   203.0.113.42 198.51.100.7
/// ```
///
/// Returns the updated entry, or a clone with `is_running = false` if the
/// output indicates the jail is not running.
#[expect(
    clippy::cast_possible_truncation,
    reason = "banned/file counts fit in usize on any target"
)]
pub fn enrich_jail_from_status(mut jail: JailEntry, status: &str) -> JailEntry {
    // A jail that is "not running" reports a stub. Best-effort detection.
    if status.contains("not running") {
        jail.is_running = false;
        return jail;
    }

    // Primary parse of "Currently banned: N". Track success so the IP-list
    // fallback below only fires when this line was absent.
    let banned_from_primary = extract_int(status, "Currently banned").map(|n| n as usize);
    jail.banned_count = banned_from_primary.unwrap_or(jail.banned_count);
    jail.total_bans = extract_int(status, "Total banned").map_or(jail.total_bans, |n| n as usize);
    jail.file_count = extract_int(status, "File list").map_or(jail.file_count, |n| n as usize);

    // Fallback: if no "Currently banned" line was found, but a
    // "Banned IP list:" line exists, count the IPs on it. This handles older
    // fail2ban output that only lists banned IPs without a count.
    if banned_from_primary.is_none()
        && let Some(idx) = status.find("Banned IP list:")
    {
        let rest = &status[idx..];
        // Take up to the next newline.
        let line = rest.lines().next().unwrap_or("");
        if let Some(colon) = line.find(':') {
            // Mirror parse_bans: only count tokens that look like IPs, so a
            // stray label or parse artifact on the line can't inflate the count.
            let ip_count = line[colon + 1..]
                .split_whitespace()
                .filter(|s| !s.is_empty())
                .filter(|s| looks_like_ip(s))
                .count();
            if ip_count > 0 {
                jail.banned_count = ip_count;
            }
        }
    }

    jail
}

/// Extract the first integer following a label line in fail2ban status output.
///
/// `File list:` is special-cased: it is followed by paths, not a number, so we
/// return the count of whitespace-separated tokens instead.
fn extract_int(status: &str, label: &str) -> Option<u64> {
    for line in status.lines() {
        if line.contains(label)
            && let Some(colon) = line.find(':')
        {
            let rest = line[colon + 1..].trim();
            if label == "File list" {
                // Count tokens (paths).
                return Some(rest.split_whitespace().count() as u64);
            }
            // Take the first whitespace-delimited token and parse it.
            let token = rest.split_whitespace().next()?;
            if let Ok(n) = token.parse::<u64>() {
                return Some(n);
            }
            // Some fail2ban versions put the number before a trailing
            // label; skip silently on parse failure.
        }
    }
    None
}

/// Parse `fail2ban-client banned` output into ban entries.
///
/// The `banned` subcommand prints, in newer fail2ban versions, a structured
/// header followed by per-IP lines like:
///
/// ```text
/// Banned IP list:
/// 203.0.113.42
///   - sshd
/// 198.51.100.7
///   - sshd
/// ```
///
/// and in v1 a flat line `Banned IP list: 1.2.3.4 5.6.7.8`. Both forms are
/// handled: bare IPs become entries with empty `jails`, and an indented
/// `- jail` line attaches its jail to the preceding IP.
pub fn parse_bans(raw: &str) -> Vec<BanEntry> {
    let mut entries: Vec<BanEntry> = Vec::new();

    for raw_line in raw.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        // Skip header lines. Note `starts_with("banned ip list")` already
        // covers an exact `"banned ip list:"` line (and the v1 flat form
        // `Banned IP list: 1.2.3.4`), so no separate equality arm is needed.
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("banned ip list")
            || lower.starts_with("total banned")
            || lower.starts_with("sorry")
            || lower.contains("no ip is currently banned")
        {
            // But if there are IPs on the same line after the colon, capture them.
            if let Some(colon) = line.find(':') {
                let rest = &line[colon + 1..];
                for token in rest.split_whitespace() {
                    if looks_like_ip(token) {
                        entries.push(BanEntry {
                            ip: token.to_string(),
                            jails: Vec::new(),
                        });
                    } else {
                        tracing::warn!("fail2ban banned: skipping non-IP token {token:?}");
                    }
                }
            }
            continue;
        }
        // Indented "- jail" attaches to the most recent IP.
        if line.starts_with('-') || line.starts_with("Jail") {
            // Strip the leading '-' (then whitespace) and the literal "Jail:"
            // prefix explicitly. Do NOT use a char-set trim_start_matches here:
            // [' ', 'J', 'a', 'i', 'l', ':'] would eat any leading char that
            // happens to be one of those (e.g. '- apache-auth' -> "pache-auth",
            // '- asterisk-irc' -> "sterisk-irc").
            let jail_name = line.trim_start_matches('-').trim_start();
            let jail_name = jail_name
                .strip_prefix("Jail:")
                .unwrap_or(jail_name)
                .trim()
                .to_string();
            if !jail_name.is_empty()
                && let Some(last) = entries.last_mut()
                && !last.jails.contains(&jail_name)
            {
                last.jails.push(jail_name);
            }
            continue;
        }
        // Otherwise: a bare IP line.
        if looks_like_ip(line) {
            entries.push(BanEntry {
                ip: line.to_string(),
                jails: Vec::new(),
            });
        } else {
            tracing::warn!("fail2ban banned: skipping unrecognized line {line:?}");
        }
    }

    entries
}

/// Best-effort check that `s` looks like an IPv4 or IPv6 address.
///
/// Accepts dotted-quad with 1-3 digit octets, or colon-separated IPv6 groups.
/// Does NOT fully validate octet ranges — the goal is to distinguish IPs from
/// prose, not to enforce RFC validity.
fn looks_like_ip(s: &str) -> bool {
    // IPv4: four dot-separated groups of 1-3 digits.
    let v4: Vec<&str> = s.split('.').collect();
    if v4.len() == 4
        && v4
            .iter()
            .all(|g| !g.is_empty() && g.chars().all(|c| c.is_ascii_digit()))
    {
        return true;
    }
    // IPv6: contains at least one ':' and only hex digits / ':' / '.'.
    // Require either an explicit '::' compression literal OR a full 8-group
    // form, so degenerate tokens (':', '12:34', 'dead:beef', 'a:b:c') are
    // rejected while real addresses ('::', '::1', '2001:db8::1', and the
    // uncompressed 8-group form) are still accepted.
    if s.contains(':')
        && s.chars()
            .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
    {
        let non_empty_groups = s.split(':').filter(|g| !g.is_empty()).count();
        if s.contains("::") || non_empty_groups >= 8 {
            return true;
        }
    }
    false
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use toride_fail2ban::report::{Finding, Severity};

    // ── convert_findings ──────────────────────────────────────────────────────

    #[test]
    fn convert_findings_empty() {
        assert!(convert_findings(Vec::new()).is_empty());
    }

    #[test]
    fn convert_findings_maps_severity() {
        let findings = vec![
            Finding::new("a", Severity::Critical, "t1"),
            Finding::new("b", Severity::Error, "t2"),
            Finding::new("c", Severity::Warning, "t3"),
            Finding::new("d", Severity::Info, "t4"),
            Finding::new("e", Severity::Ok, "t5"),
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
        let f = Finding::new("id", Severity::Warning, "title")
            .detail("the detail")
            .fix("the fix");
        let entries = convert_findings(vec![f]);
        assert_eq!(entries[0].detail, "the detail");
        assert_eq!(entries[0].fix.as_deref(), Some("the fix"));
    }

    #[test]
    fn convert_findings_placeholder_for_empty_fields() {
        let f = Finding::new("", Severity::Ok, "");
        let entries = convert_findings(vec![f]);
        assert_eq!(entries[0].id, "(unknown)");
        assert_eq!(entries[0].title, "(no title)");
    }

    // ── parse_jails_from_status ───────────────────────────────────────────────

    #[test]
    fn parse_jails_from_status_finds_jail_list() {
        let status = "\
|- Number of jail:      2
`- Jail list:   sshd, nginx-limit-req";
        let jails = parse_jails_from_status(status);
        assert_eq!(jails.len(), 2);
        assert_eq!(jails[0].name, "sshd");
        assert_eq!(jails[1].name, "nginx-limit-req");
        assert!(jails[0].is_running);
    }

    #[test]
    fn parse_jails_from_status_no_jail_list_returns_empty() {
        let status = "Status\n|- Number of jail: 0";
        assert!(parse_jails_from_status(status).is_empty());
    }

    #[test]
    fn parse_jails_from_status_empty_input() {
        assert!(parse_jails_from_status("").is_empty());
    }

    // ── enrich_jail_from_status ───────────────────────────────────────────────

    #[test]
    fn enrich_jail_sets_counts() {
        let jail = JailEntry {
            name: "sshd".into(),
            is_running: true,
            banned_count: 0,
            total_bans: 0,
            file_count: 0,
        };
        let status = "\
Status for the jail: sshd
|- Filter
|  |- Currently failed: 2
|  |- Total failed:     10
|  `- File list:        /var/log/auth.log
`- Actions
   |- Currently banned: 3
   |- Total banned:     12
   `- Banned IP list:   1.2.3.4 5.6.7.8";
        let enriched = enrich_jail_from_status(jail, status);
        assert_eq!(enriched.banned_count, 3);
        assert_eq!(enriched.total_bans, 12);
        assert_eq!(enriched.file_count, 1);
    }

    #[test]
    fn enrich_jail_not_running_flag() {
        let jail = JailEntry {
            name: "x".into(),
            is_running: true,
            banned_count: 0,
            total_bans: 0,
            file_count: 0,
        };
        let enriched = enrich_jail_from_status(jail, "Jail is not running");
        assert!(!enriched.is_running);
    }

    #[test]
    fn enrich_jail_banned_ip_list_fallback() {
        let jail = JailEntry {
            name: "x".into(),
            is_running: true,
            banned_count: 0,
            total_bans: 5,
            file_count: 0,
        };
        // No "Currently banned:" line, but a "Banned IP list:" with 2 IPs.
        let status = "Banned IP list:   9.9.9.9 8.8.8.8";
        let enriched = enrich_jail_from_status(jail, status);
        assert_eq!(enriched.banned_count, 2);
        assert_eq!(enriched.total_bans, 5);
    }

    // ── parse_bans ────────────────────────────────────────────────────────────

    #[test]
    fn parse_bans_flat_v1_line() {
        let raw = "Banned IP list: 1.2.3.4 5.6.7.8";
        let bans = parse_bans(raw);
        assert_eq!(bans.len(), 2);
        assert_eq!(bans[0].ip, "1.2.3.4");
        assert_eq!(bans[1].ip, "5.6.7.8");
    }

    #[test]
    fn parse_bans_structured_v2_form() {
        let raw = "\
Banned IP list:
203.0.113.42
   - sshd
198.51.100.7
   - sshd";
        let bans = parse_bans(raw);
        assert_eq!(bans.len(), 2);
        assert_eq!(bans[0].ip, "203.0.113.42");
        assert_eq!(bans[0].jails, vec!["sshd".to_string()]);
        assert_eq!(bans[1].jails, vec!["sshd".to_string()]);
    }

    #[test]
    fn parse_bans_preserves_jail_names_not_in_trim_char_set() {
        // Regression: a char-set trim_start_matches([' ','J','a','i','l',':'])
        // ate the leading char of any jail whose name began with one of those
        // letters. apache-auth and asterisk-irc are common real-world jails and
        // both were corrupted ('apache-auth' -> 'pache-auth',
        // 'asterisk-irc' -> 'sterisk-irc'). The "Jail:" literal-prefix form is
        // also exercised.
        let raw = "\
Banned IP list:
192.0.2.10
   - apache-auth
198.51.100.23
   - asterisk-irc
203.0.113.99
   - Jail: sshd";
        let bans = parse_bans(raw);
        assert_eq!(bans.len(), 3);
        assert_eq!(bans[0].ip, "192.0.2.10");
        assert_eq!(bans[0].jails, vec!["apache-auth".to_string()]);
        assert_eq!(bans[1].ip, "198.51.100.23");
        assert_eq!(bans[1].jails, vec!["asterisk-irc".to_string()]);
        assert_eq!(bans[2].ip, "203.0.113.99");
        assert_eq!(bans[2].jails, vec!["sshd".to_string()]);
    }

    #[test]
    fn parse_bans_empty_returns_empty() {
        assert!(parse_bans("").is_empty());
    }

    #[test]
    fn parse_bans_no_ips_returns_empty() {
        let raw = "Sorry, but no IP is currently banned.";
        // The "sorry" / "no ip is currently banned" guard skips this line,
        // and there are no bare IP lines — result is empty.
        assert!(parse_bans(raw).is_empty());
    }

    #[test]
    fn parse_bans_skips_non_ip_lines() {
        let raw = "\
Banned IP list:
1.2.3.4
some garbage line";
        let bans = parse_bans(raw);
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].ip, "1.2.3.4");
    }

    #[test]
    fn parse_bans_ipv6_supported() {
        let raw = "Banned IP list: ::1 2001:db8::1";
        let bans = parse_bans(raw);
        assert_eq!(bans.len(), 2);
    }

    // ── looks_like_ip ─────────────────────────────────────────────────────────

    #[test]
    fn looks_like_ip_ipv4() {
        assert!(looks_like_ip("1.2.3.4"));
        assert!(looks_like_ip("255.255.255.255"));
    }

    #[test]
    fn looks_like_ip_ipv6() {
        assert!(looks_like_ip("::1"));
        assert!(looks_like_ip("2001:db8::1"));
    }

    #[test]
    fn looks_like_ip_rejects_prose() {
        assert!(!looks_like_ip("hello"));
        assert!(!looks_like_ip("not-an-ip"));
        assert!(!looks_like_ip(""));
    }

    #[test]
    fn looks_like_ip_rejects_degenerate_ipv6_tokens() {
        // A loose "contains ':' and only hex/':' chars" predicate would accept
        // these; the tightened rule (require `::` OR >=3 non-empty groups)
        // rejects them so stray timestamps / hex words can't become BanEntry IPs.
        assert!(!looks_like_ip(":"));
        assert!(!looks_like_ip("12:34"));
        assert!(!looks_like_ip("dead:beef"));
        assert!(!looks_like_ip("a:b:c"));
        // `::` (the IPv6 unspecified address) and real addresses still pass.
        assert!(looks_like_ip("::"));
        assert!(looks_like_ip("::1"));
        assert!(looks_like_ip("2001:db8::1"));
    }
}
