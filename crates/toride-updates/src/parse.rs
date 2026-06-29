//! Parsers for command output from update-related tools.
//!
//! Each function takes raw command output and returns a structured result:
//!
//! - [`parse_unattended_upgrades_status`] -- parses the real
//!   `/var/log/unattended-upgrades/unattended-upgrades.log` format (Python
//!   `logging` lines: `YYYY-MM-DD HH:MM:SS,mmm LEVEL message`).
//! - [`parse_apt_check`] -- parses `ubuntu-advantage security-status` or `apt-check` output
//! - [`parse_dnf_check`] -- parses `dnf check-update` output
//! - [`parse_dnf_automatic_journal`] -- parses `journalctl -u dnf-automatic`
//!   output (the dnf-automatic stdio/motd emitter messages).

use crate::error::{Error, Result};
use crate::report::UpdateStatus;

// ---------------------------------------------------------------------------
// parse_unattended_upgrades_status
// ---------------------------------------------------------------------------

/// Marker that opens an unattended-upgrades run.
///
/// Real log line (Ubuntu Server docs, "Automatic updates"):
/// ```text
/// 2025-03-13 22:44:29,802 INFO Starting unattended upgrades script
/// ```
const UU_START_MARKER: &str = "Starting unattended upgrades script";

/// Marker listing the packages slated for upgrade in the current run.
///
/// Real log line:
/// ```text
/// 2025-03-13 22:44:33,029 INFO Packages that will be upgraded: libc6 python3-jinja2
/// ```
const UU_PACKAGES_MARKER: &str = "Packages that will be upgraded:";

/// Marker emitted when an unattended-upgrades run completes successfully.
const UU_ALL_INSTALLED_MARKER: &str = "All upgrades installed";

/// Marker emitted when there is nothing to upgrade.
const UU_NOTHING_MARKER: &str = "No packages found that can be upgraded unattended";

/// Parse the real `/var/log/unattended-upgrades/unattended-upgrades.log` into
/// an [`UpdateStatus`].
///
/// The log is written by Python's `logging` module in the format
/// `YYYY-MM-DD HH:MM:SS,mmm LEVEL message`. A run looks like (from the Ubuntu
/// Server "Automatic updates" documentation):
///
/// ```text
/// 2025-03-13 22:44:29,802 INFO Starting unattended upgrades script
/// 2025-03-13 22:44:29,803 INFO Allowed origins are: o=Ubuntu,a=noble, ...
/// 2025-03-13 22:44:29,803 INFO Initial blacklist:
/// 2025-03-13 22:44:29,803 INFO Initial whitelist (not strict):
/// 2025-03-13 22:44:33,029 INFO Packages that will be upgraded: libc6 python3-jinja2
/// 2025-03-13 22:44:33,029 INFO Writing dpkg log to /var/log/unattended-upgrades/unattended-upgrades-dpkg.log
/// 2025-03-13 22:44:34,421 INFO All upgrades installed
/// ```
///
/// The parser walks the (append-only) log, tracking the most recent run's
/// start timestamp and the packages it upgraded. The returned status reports:
///
/// - `last_run` -- the timestamp of the most recent `Starting unattended
///   upgrades script` line (verbatim, e.g. `"2025-03-13 22:44:29,802"`).
/// - `pending_security` -- for the most recent run, the number of packages on
///   the `Packages that will be upgraded:` line. This is a best-effort count
///   of what the last run applied; unattended-upgrades does not separate
///   security from non-security packages in the log.
/// - `auto_updates_enabled` -- `true` when the log contains at least one
///   recognizable run marker (so a stale empty file is reported as disabled).
///
/// # Errors
///
/// Parsing is lenient (a missing/unparseable log yields an empty status);
/// this function does not return [`Error::ConfigParse`].
pub fn parse_unattended_upgrades_status(content: &str) -> Result<UpdateStatus> {
    let mut status = UpdateStatus::empty();
    let mut saw_run = false;

    // The log is append-only, so later runs overwrite earlier values. We track
    // the *current* run's package list and only commit it to `pending_security`
    // once we either see the run's outcome or the next run starts.
    let mut current_packages: Option<usize> = None;

    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }

        // Extract the timestamp (first two whitespace-separated tokens after
        // any journal prefix) when present, regardless of message content.
        let ts = extract_uu_timestamp(line);

        if line.contains(UU_START_MARKER) {
            saw_run = true;
            if let Some(ts) = ts {
                status.last_run = Some(ts.to_owned());
            }
            // Reset the per-run package accumulator.
            current_packages = Some(0);
        } else if let Some(rest) = find_after(line, UU_PACKAGES_MARKER) {
            saw_run = true;
            // `rest` may be empty (no packages matched) or a space-separated
            // list of `name (version origin)` entries. Count whitespace-split
            // tokens that look like bare package names (start at the token, not
            // a parenthesised origin string). Origin tokens like `o=Ubuntu`
            // live on the separate `Allowed origins are:` line, NOT here, so we
            // must not exclude names starting with 'o' — that would silently
            // drop openssl/openldap/openssh-*/openjdk-* and undercount.
            let count = rest
                .split_whitespace()
                .filter(|tok| !tok.starts_with('('))
                .count();
            current_packages = Some(count);
        } else if line.contains(UU_ALL_INSTALLED_MARKER) || line.contains(UU_NOTHING_MARKER) {
            saw_run = true;
            // Commit the current run's package count as the authoritative
            // "applied in the last run" value.
            if let Some(count) = current_packages.take() {
                status.pending_security = count;
            } else if line.contains(UU_NOTHING_MARKER) {
                status.pending_security = 0;
            }
        }
    }

    status.auto_updates_enabled = saw_run;
    Ok(status)
}

/// Extract the `YYYY-MM-DD HH:MM:SS[,mmm]` timestamp from an
/// unattended-upgrades log line.
///
/// Real lines (when reading the log file directly) begin with the timestamp:
/// ```text
/// 2025-03-13 22:44:29,802 INFO Starting unattended upgrades script
/// ```
/// When `journalctl` is layered on top, the line is prefixed with
/// `<MMM DD HH:MM:SS hostname> ...` -- in that case the embedded
/// unattended-upgrades timestamp still follows. This helper walks the
/// whitespace-delimited tokens of the line and returns the first
/// `YYYY-MM-DD HH:MM:SS` pair it finds. The returned span is the verbatim
/// `YYYY-MM-DD HH:MM:SS,mmm` (or `YYYY-MM-DD HH:MM:SS` when the log omits
/// the milliseconds), so callers preserve the real on-disk format.
fn extract_uu_timestamp(line: &str) -> Option<&str> {
    let mut tokens = token_spans(line);
    while let Some((d_start, date_tok)) = tokens.next() {
        if !looks_like_uu_date(date_tok) {
            continue;
        }
        let (t_start, time_tok) = tokens.next()?;
        if !looks_like_uu_time(time_tok) {
            continue;
        }
        let end = t_start + time_tok.len();
        return Some(&line[d_start..end]);
    }
    None
}

/// Yield `(start_byte_offset, &token)` for each whitespace-delimited token in
/// `line`, preserving offsets (unlike `str::split_whitespace` which discards
/// them).
fn token_spans(line: &str) -> std::iter::Peekable<std::vec::IntoIter<(usize, &str)>> {
    let mut out = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Skip whitespace.
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        // SAFETY: we advanced over ASCII-whitespace boundaries only, which are
        // valid char boundaries.
        let tok = std::str::from_utf8(&bytes[start..i]).unwrap_or("");
        out.push((start, tok));
    }
    out.into_iter().peekable()
}

/// Heuristic: does this token look like `YYYY-MM-DD`?
fn looks_like_uu_date(tok: &str) -> bool {
    let mut parts = tok.split('-');
    let y = parts.next();
    let m = parts.next();
    let d = parts.next();
    matches!((y, m, d), (Some(y), Some(_), Some(_)) if y.len() == 4 && tok.len() == 10)
}

/// Heuristic: does this token look like `HH:MM:SS` or `HH:MM:SS,mmm`?
fn looks_like_uu_time(tok: &str) -> bool {
    // Strip an optional ",mmm" milliseconds suffix.
    let core = tok.split_once(',').map_or(tok, |(c, _)| c);
    let bytes = core.as_bytes();
    core.len() == 8 && bytes[2] == b':' && bytes[5] == b':'
}

/// Return the slice of `line` following the first occurrence of `marker`,
/// trimming the marker and any immediately following whitespace. Returns
/// `None` when the marker is absent.
fn find_after<'a>(line: &'a str, marker: &str) -> Option<&'a str> {
    let idx = line.find(marker)?;
    Some(line[idx + marker.len()..].trim_start())
}

// ---------------------------------------------------------------------------
// parse_apt_check
// ---------------------------------------------------------------------------

/// Parse the output of `apt-check` (or equivalent) to extract update counts.
///
/// Returns a tuple of `(security_updates, total_updates)`.
///
/// Typical output format:
///
/// ```text
/// 3;12
/// ```
///
/// Where `3` is the number of security updates and `12` is the total.
///
/// # Errors
///
/// Returns [`Error::ConfigParse`] if the output cannot be parsed as `N;M`.
pub fn parse_apt_check(output: &str) -> Result<(usize, usize)> {
    let output = output.trim();
    let parts: Vec<&str> = output.split(';').collect();

    if parts.len() != 2 {
        return Err(Error::ConfigParse(format!(
            "expected 'N;M' format, got: {output:?}"
        )));
    }

    let security = parts[0]
        .trim()
        .parse::<usize>()
        .map_err(|e| Error::ConfigParse(format!("invalid security count: {e}")))?;
    let total = parts[1]
        .trim()
        .parse::<usize>()
        .map_err(|e| Error::ConfigParse(format!("invalid total count: {e}")))?;

    Ok((security, total))
}

// ---------------------------------------------------------------------------
// parse_dnf_check
// ---------------------------------------------------------------------------

/// Parse the output of `dnf check-update` to extract update counts.
///
/// Returns a tuple of `(security_updates, total_updates)`.
///
/// The output lists available updates, one per line. Security updates are
/// typically identified by advisory IDs starting with `ALSA-`, `FEDORA-`,
/// or `RHSA-`.
///
/// # Errors
///
/// Returns [`Error::ConfigParse`] if the output is fundamentally malformed
/// (though DNF output is relatively free-form, so parsing is lenient).
pub fn parse_dnf_check(output: &str) -> Result<(usize, usize)> {
    let mut security = 0usize;
    let mut total = 0usize;

    for line in output.lines() {
        let line = line.trim();
        // Skip empty lines and header/footer lines.
        if line.is_empty() || line.starts_with("Last metadata") || line.contains("Updating") {
            continue;
        }

        // Lines with package names contain update info.
        // A simple heuristic: count non-empty, non-header lines as updates.
        if line.contains('.') && line.contains(' ') {
            total += 1;
            // Check for security advisory patterns.
            if line.contains("security")
                || line.contains("ALSA-")
                || line.contains("ALAS-")
                || line.contains("RHSA-")
                || line.contains("CESA-")
                || line.contains("ELSA-")
                || line.contains("CLA-")
                || line.contains("FEDORA-")
            {
                security += 1;
            }
        }
    }

    Ok((security, total))
}

// ---------------------------------------------------------------------------
// parse_dnf_automatic_journal
// ---------------------------------------------------------------------------

/// Marker emitted by the dnf-automatic stdio/motd/command emitters when updates
/// are available but have not been installed yet.
///
/// Source: `dnf/automatic/emitter.py` in the upstream dnf repository:
/// `AVAILABLE = _("The following updates are available on '%s':")`
const DNF_AVAILABLE_MARKER: &str = "The following updates are available on";

/// Marker emitted by the dnf-automatic emitters after updates have been
/// applied (installed).
///
/// Source: `dnf/automatic/emitter.py`:
/// `APPLIED = _("The following updates have been applied on '%s':")`
const DNF_APPLIED_MARKER: &str = "The following updates have been applied on";

/// Marker emitted by the dnf-automatic emitters after updates have been
/// downloaded (but not installed).
///
/// Source: `dnf/automatic/emitter.py`:
/// `DOWNLOADED = _("The following updates were downloaded on '%s':")`
const DNF_DOWNLOADED_MARKER: &str = "The following updates were downloaded on";

/// Timestamp marker appended by the emitter after a successful apply.
///
/// Source: `dnf/automatic/emitter.py`:
/// `APPLIED_TIMESTAMP = _("Updates completed at %s")`
const DNF_COMPLETED_MARKER: &str = "Updates completed at";

/// Message printed by dnf when running in security-only mode and no security
/// errata are found, but other updates exist.
///
/// Source: `dnf/base.py` (upstream dnf repository):
/// `_("No security updates needed, but {} updates available")`
const DNF_NO_SECURITY_BUT_OTHERS: &str = "No security updates needed, but";

/// Parse `journalctl -u dnf-automatic` output into an [`UpdateStatus`].
///
/// dnf-automatic does not keep its own log file; its status is surfaced via
/// the systemd journal (the emitters defined in `dnf/automatic/emitter.py`).
/// The stdio/motd/command emitters print one of these marker lines followed by
/// a transaction listing:
///
/// ```text
/// The following updates have been applied on 'host.example.com':
///     bzip2-1.0.8-10.fc40.x86_64                  rockylinux-core
///     kernel-core-6.8.9-300.fc40.x86_64           updates
/// Updates completed at Mon Jun  2 06:42:11 2025
/// ```
///
/// or, in security-only mode with no security errata:
///
/// ```text
/// No security updates needed, but 154 updates available
/// ```
///
/// The parser reports:
///
/// - `last_run` -- the verbatim timestamp from the most recent
///   `Updates completed at <ts>` line, if any.
/// - `pending_security` -- the number of package lines listed under the most
///   recent `applied`/`downloaded`/`available` marker (the count of updates in
///   the last run's transaction).
/// - `auto_updates_enabled` -- `true` when any recognizable dnf-automatic
///   marker appears.
///
/// # Errors
///
/// Parsing is lenient; this function does not return [`Error::ConfigParse`].
pub fn parse_dnf_automatic_journal(content: &str) -> Result<UpdateStatus> {
    let mut status = UpdateStatus::empty();
    let mut saw_marker = false;

    // The transaction listing lines follow a marker line until a blank line or
    // another marker. We accumulate the count for the most recent transaction.
    let mut in_listing = false;
    let mut current_count = 0usize;

    for raw in content.lines() {
        let line = raw.trim();

        if line.starts_with(DNF_AVAILABLE_MARKER)
            || line.starts_with(DNF_APPLIED_MARKER)
            || line.starts_with(DNF_DOWNLOADED_MARKER)
        {
            saw_marker = true;
            in_listing = true;
            current_count = 0;
            continue;
        }

        if let Some(rest) = find_after(line, DNF_COMPLETED_MARKER) {
            saw_marker = true;
            in_listing = false;
            // Commit the just-finished transaction's count.
            status.pending_security = current_count;
            if !rest.is_empty() {
                status.last_run = Some(rest.trim().to_owned());
            }
            continue;
        }

        if line.contains(DNF_NO_SECURITY_BUT_OTHERS) {
            saw_marker = true;
            in_listing = false;
            // security-only run that found nothing: zero pending security.
            status.pending_security = 0;
            continue;
        }

        // Inside a transaction listing: count non-empty, non-blank lines that
        // look like package entries. The dnf transaction listing format is
        // `<nevra>  <repo>`, indented. Skip pure-summary lines.
        if in_listing && !line.is_empty() {
            if line.contains("Updates completed") || line.contains("Error") {
                in_listing = false;
                continue;
            }
            current_count += 1;
        }
    }

    // If the journal ended while still inside a listing (no `Updates
    // completed` line, e.g. an `available`-only run), surface that count as the
    // most recent pending/available set.
    if in_listing {
        status.pending_security = current_count;
    }

    status.auto_updates_enabled = saw_marker;
    Ok(status)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_apt_check_simple() {
        let (security, total) = parse_apt_check("3;12").unwrap();
        assert_eq!(security, 3);
        assert_eq!(total, 12);
    }

    #[test]
    fn parse_apt_check_zero() {
        let (security, total) = parse_apt_check("0;0").unwrap();
        assert_eq!(security, 0);
        assert_eq!(total, 0);
    }

    #[test]
    fn parse_apt_check_invalid() {
        assert!(parse_apt_check("invalid").is_err());
    }

    #[test]
    fn parse_dnf_check_empty() {
        let (security, total) = parse_dnf_check("").unwrap();
        assert_eq!(security, 0);
        assert_eq!(total, 0);
    }

    #[test]
    fn parse_unattended_upgrades_status_empty() {
        let status = parse_unattended_upgrades_status("").unwrap();
        assert!(!status.auto_updates_enabled);
        assert_eq!(status.pending_security, 0);
    }

    /// Real `/var/log/unattended-upgrades/unattended-upgrades.log` sample.
    ///
    /// Source: Ubuntu Server docs, "Automatic updates" -- the PPA-origin example
    /// run. <https://ubuntu.com/server/docs/how-to/software/automatic-updates/>
    #[test]
    fn parse_unattended_upgrades_status_real_log_with_upgrades() {
        let log = "\
2025-03-13 22:44:29,802 INFO Starting unattended upgrades script\n\
2025-03-13 22:44:29,803 INFO Allowed origins are: o=Ubuntu,a=noble, o=Ubuntu,a=noble-security, o=UbuntuESMApps,a=noble-apps-security, o=UbuntuESM,a=noble-infra-security, o=LP-PPA-canonical-server-server-backports,a=noble\n\
2025-03-13 22:44:29,803 INFO Initial blacklist:\n\
2025-03-13 22:44:29,803 INFO Initial whitelist (not strict):\n\
2025-03-13 22:44:33,029 INFO Option --dry-run given, *not* performing real actions\n\
2025-03-13 22:44:33,029 INFO Packages that will be upgraded: ibverbs-providers libibverbs1 rdma-core\n\
2025-03-13 22:44:33,029 INFO Writing dpkg log to /var/log/unattended-upgrades/unattended-upgrades-dpkg.log\n\
2025-03-13 22:44:34,421 INFO All upgrades installed\n\
2025-03-13 22:44:34,855 INFO The list of kept packages can't be calculated in dry-run mode.\n";
        let status = parse_unattended_upgrades_status(log).unwrap();
        assert!(status.auto_updates_enabled);
        assert_eq!(status.last_run.as_deref(), Some("2025-03-13 22:44:29,802"));
        // 3 packages on the "Packages that will be upgraded:" line.
        assert_eq!(status.pending_security, 3);
    }

    /// Real sample: a run that found nothing to upgrade.
    ///
    /// Source: Ubuntu Server docs, "Notifications" -- the no-changes email body
    /// uses the exact "No packages found that can be upgraded unattended"
    /// marker that unattended-upgrades writes to the log.
    /// <https://ubuntu.com/server/docs/how-to/software/automatic-updates/>
    #[test]
    fn parse_unattended_upgrades_status_real_log_nothing_to_do() {
        let log = "\
2025-03-13 06:00:12,001 INFO Starting unattended upgrades script\n\
2025-03-13 06:00:12,002 INFO Allowed origins are: o=Ubuntu,a=noble\n\
2025-03-13 06:00:14,330 INFO No packages found that can be upgraded unattended and no pending auto-removals\n";
        let status = parse_unattended_upgrades_status(log).unwrap();
        assert!(status.auto_updates_enabled);
        assert_eq!(status.last_run.as_deref(), Some("2025-03-13 06:00:12,001"));
        assert_eq!(status.pending_security, 0);
    }

    /// The log is append-only: a second, more recent run must win.
    #[test]
    fn parse_unattended_upgrades_status_latest_run_wins() {
        let log = "\
2025-03-10 06:00:01,000 INFO Starting unattended upgrades script\n\
2025-03-10 06:00:05,000 INFO Packages that will be upgraded: openssl\n\
2025-03-10 06:00:09,000 INFO All upgrades installed\n\
2025-03-11 06:00:01,000 INFO Starting unattended upgrades script\n\
2025-03-11 06:00:05,000 INFO Packages that will be upgraded: curl libcurl4\n\
2025-03-11 06:00:10,000 INFO All upgrades installed\n";
        let status = parse_unattended_upgrades_status(log).unwrap();
        assert_eq!(status.last_run.as_deref(), Some("2025-03-11 06:00:01,000"));
        assert_eq!(status.pending_security, 2);
    }

    /// Real `journalctl -u dnf-automatic` sample -- stdio emitter output after
    /// an apply run.
    ///
    /// Source: dnf upstream `dnf/automatic/emitter.py`:
    ///   APPLIED = "The following updates have been applied on '%s':"
    ///   `APPLIED_TIMESTAMP` = "Updates completed at %s"
    /// <https://github.com/rpm-software-management/dnf/blob/master/dnf/automatic/emitter.py>
    #[test]
    fn parse_dnf_automatic_journal_real_applied_run() {
        let journal = "\
The following updates have been applied on 'host.example.com':\n\
    bzip2-libs-1.0.8-10.el9.x86_64                       baseos\n\
    kernel-6.8.9-300.fc40.x86_64                         updates\n\
    kernel-core-6.8.9-300.fc40.x86_64                    updates\n\
Updates completed at Mon Jun  2 06:42:11 2025\n";
        let status = parse_dnf_automatic_journal(journal).unwrap();
        assert!(status.auto_updates_enabled);
        assert_eq!(status.last_run.as_deref(), Some("Mon Jun  2 06:42:11 2025"));
        // 3 package lines listed under the applied marker.
        assert_eq!(status.pending_security, 3);
    }

    /// Real sample: security-only run that found no security errata but other
    /// updates exist.
    ///
    /// Source: dnf upstream `dnf/base.py`:
    ///   _("No security updates needed, but {} updates available")
    /// Confirmed in the wild on Rocky Linux 9 / RHEL 9 dnf-automatic journal:
    ///   "No security updates needed, but 154 updates available"
    #[test]
    fn parse_dnf_automatic_journal_real_no_security_but_others() {
        let journal = "No security updates needed, but 154 updates available\n";
        let status = parse_dnf_automatic_journal(journal).unwrap();
        assert!(status.auto_updates_enabled);
        assert_eq!(status.pending_security, 0);
    }

    /// An `available`-only run (notify-only timer) with no `Updates completed`
    /// line: the pending count reflects the listed available updates.
    ///
    /// Source: dnf upstream `dnf/automatic/emitter.py`:
    ///   AVAILABLE = "The following updates are available on '%s':"
    #[test]
    fn parse_dnf_automatic_journal_available_only_run() {
        let journal = "\
The following updates are available on 'host.example.com':\n\
    openssl-3.0.9-1.el9.x86_64                           baseos\n\
    zlib-1.2.11-40.el9.x86_64                            baseos\n";
        let status = parse_dnf_automatic_journal(journal).unwrap();
        assert!(status.auto_updates_enabled);
        assert_eq!(status.pending_security, 2);
        // No `Updates completed at` -> last_run is None.
        assert!(status.last_run.is_none());
    }

    #[test]
    fn parse_dnf_automatic_journal_empty() {
        let status = parse_dnf_automatic_journal("").unwrap();
        assert!(!status.auto_updates_enabled);
        assert_eq!(status.pending_security, 0);
    }
}
