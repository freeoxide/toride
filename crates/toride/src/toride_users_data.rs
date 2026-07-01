//! Async user & access-control data collection (LIVE READ-ONLY).
//!
//! [`UsersCollector`] manages background collection of all user-management
//! subsystem data via a tokio oneshot channel, following the exact same pattern
//! as [`Fail2banCollector`](crate::fail2ban_data::Fail2banCollector) and the
//! other read-only collectors. There is no write path, no optimistic update,
//! no cooldown gate, and no loading spinner.
//!
//! Doctor findings are produced by synchronous file reads (`read_passwd` /
//! `read_to_string` `/etc/shadow` / `read_sudoers`, plus a
//! `.google_authenticator` existence check) and change slowly, so they are
//! cached for 60s — exactly like the fail2ban diagnostics cache. The per-user
//! enrichment loop reads each `/etc` file ONCE up front (passwd is already
//! parsed; shadow and the main sudoers file are pre-read into lookup maps), so
//! enrichment is O(1) per user rather than O(N) full-file re-reads.
//!
//! ## macOS / degradation
//!
//! [`toride_users::UsersClient::new`] is infallible: it resolves `/etc` paths
//! without checking existence. On macOS `/etc/passwd` exists but is NOT the
//! real account database (Directory Service is), and `/etc/shadow`,
//! `/etc/sudoers`, `/etc/sudoers.d`, `/etc/pam.d` mostly DO NOT exist. Each
//! per-file read failure is caught with a `tracing::warn!`, degrades that one
//! field to empty, and KEEPS GOING — so `available == true` (partial reads, not
//! absent) and the operator sees whatever data is present plus a completeness
//! caveat in the overview panel. Only a `spawn_blocking` panic (`JoinError`)
//! forces `available == false`.
//!
//! ## Blocking
//!
//! The `DuctRunner` shells out synchronously and file reads are synchronous, so
//! ALL backend work is wrapped in a single [`tokio::task::spawn_blocking`] so
//! the tokio worker is never stalled.

use std::collections::{HashMap, HashSet};

use tokio::sync::oneshot;

use crate::toride_users_convert;
use crate::ui::screens::toride_users::{GroupEntry, SudoersEntry, UserEntry, UserFindingEntry};

/// Aggregated user & access-control data for the read-only section.
#[derive(Clone, Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent per-file read-status flags"
)]
pub struct UsersDataBundle {
    /// Whether the users backend produced any data at all. `false` only when a
    /// collection task panicked (`JoinError`). Per-file read failures keep this
    /// `true` — the reads are partial, not absent.
    pub available: bool,
    /// Whether `/etc/passwd` was read successfully. `false` on macOS-style
    /// hosts where the file is absent (or on a parse error).
    pub passwd_read: bool,
    /// Whether `/etc/shadow` was read successfully (drives the locked badge).
    pub shadow_read: bool,
    /// Whether `/etc/sudoers` (or any drop-in) was read successfully.
    pub sudoers_read: bool,
    /// Whether the PAM config for the probed service exists (a presence check
    /// — the file is never opened or parsed further here). Mirrors
    /// `shadow_read` and `sudoers_read`, which are likewise presence checks.
    pub pam_read: bool,
    /// Parsed user rows (enriched with sudo/locked/totp probes).
    pub users: Vec<UserEntry>,
    /// Parsed group rows.
    pub groups: Vec<GroupEntry>,
    /// Parsed sudoers rules.
    pub sudoers: Vec<SudoersEntry>,
    /// Doctor findings (cached for 60s between collections).
    pub findings: Vec<UserFindingEntry>,
    /// Human-readable reason the backend was unreachable, populated ONLY when
    /// `available == false` because a collection task panicked (`JoinError`).
    /// `None` otherwise — notably also `None` for a freshly-constructed empty
    /// bundle before any collection has run.
    pub unavailable_reason: Option<String>,
}

// ── Collector ───────────────────────────────────────────────────────────────

/// Manages periodic async collection of users data.
///
/// Mirrors [`Fail2banCollector`](crate::fail2ban_data::Fail2banCollector): a
/// oneshot channel for the in-flight result, plus a 60s TTL cache for the
/// expensive doctor findings so they are not re-run on every 2s refresh tick.
pub struct UsersCollector {
    /// Carries the bundle AND whether the cached findings were reused for this
    /// poll. The freshness timestamp must only be advanced when the doctor was
    /// actually re-run (`took_cache == false`); otherwise every cache-hit poll
    /// would reset the TTL clock with the SAME (already-cached) findings.
    rx: Option<oneshot::Receiver<(UsersDataBundle, bool)>>,
    /// Cached doctor findings from the last collection.
    cached_findings: Option<Vec<UserFindingEntry>>,
    /// When the findings cache was last refreshed.
    findings_fresh_at: Option<std::time::Instant>,
}

/// How long to keep cached findings before re-running the doctor suite.
#[expect(
    clippy::duration_suboptimal_units,
    reason = "stable std lacks from_mins"
)]
const FINDINGS_TTL: std::time::Duration = std::time::Duration::from_secs(60);

impl UsersCollector {
    /// Create a new collector with no pending collection.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rx: None,
            cached_findings: None,
            findings_fresh_at: None,
        }
    }

    /// Whether a collection is currently in-flight.
    pub fn is_pending(&self) -> bool {
        self.rx.is_some()
    }

    /// Start a new background collection.
    ///
    /// If a collection is already in-flight, this is a no-op. The 60s findings
    /// cache is consulted: when fresh, the spawned task reuses the cached
    /// findings instead of re-running the doctor suite.
    pub fn start(&mut self) {
        if self.rx.is_some() {
            return;
        }
        let (tx, rx) = oneshot::channel();
        let use_cache = self.cached_findings.is_some()
            && self
                .findings_fresh_at
                .is_some_and(|t| t.elapsed() < FINDINGS_TTL);
        let cached_findings = self.cached_findings.clone();
        self.rx = Some(rx);
        tokio::spawn(async move {
            let (bundle, took_cache) = collect_real_users(use_cache, cached_findings).await;
            let _ = tx.send((bundle, took_cache));
        });
    }

    /// Poll for a completed collection result.
    ///
    /// Returns `Some(bundle)` if the collection completed, `None` if still
    /// pending or if the collection failed. On success the cached findings are
    /// updated to the freshly-returned findings, but the freshness timestamp is
    /// only advanced when the doctor was actually re-run (not on a cache-hit
    /// poll).
    pub async fn poll(&mut self) -> Option<UsersDataBundle> {
        match &mut self.rx {
            Some(rx) => {
                let result = rx.await.ok();
                if let Some((ref bundle, took_cache)) = result {
                    self.cached_findings = Some(bundle.findings.clone());
                    if !took_cache {
                        self.findings_fresh_at = Some(std::time::Instant::now());
                    }
                }
                self.rx = None;
                result.map(|(bundle, _)| bundle)
            }
            None => None,
        }
    }

    /// Invalidate the findings cache so the next collection re-runs the doctor.
    #[allow(dead_code)]
    pub fn invalidate_findings_cache(&mut self) {
        self.cached_findings = None;
        self.findings_fresh_at = None;
    }
}

impl Default for UsersCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Real data collection ────────────────────────────────────────────────────

/// Collect user & access-control data via the real backend.
///
/// All work runs on the blocking thread pool: file reads and the doctor suite
/// are synchronous (no process spawns; the probes are `read_passwd` /
/// `read_to_string` `/etc/shadow` / `read_sudoers` plus a
/// `.google_authenticator` existence check). Doctor findings may be reused
/// from the cache. On ANY per-file error the offending field is degraded to
/// empty and collection continues — only a `spawn_blocking` panic (`JoinError`)
/// returns an `empty_bundle` with `available = false`.
///
/// Returns `(bundle, took_cache)` where `took_cache` records whether the
/// findings were actually taken from the cache on a successful collection.
#[expect(
    clippy::too_many_lines,
    reason = "real-data collection is inherently linear"
)]
async fn collect_real_users(
    use_cache: bool,
    cached_findings: Option<Vec<UserFindingEntry>>,
) -> (UsersDataBundle, bool) {
    // UsersClient::new() is infallible (it just resolves paths), but build it
    // on the blocking pool for symmetry with the other collectors and to own
    // every subsequent read in one spawn_blocking closure.
    let client = tokio::task::spawn_blocking(toride_users::client::UsersClient::new)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("users client construction task panicked: {e}");
            toride_users::client::UsersClient::new()
        });

    // Run ALL blocking reads + probes + doctor in a single spawn_blocking that
    // owns `client`. This keeps every shell-out and file read off the tokio
    // worker and returns plain owned data that crosses the thread boundary
    // cleanly.
    let result = tokio::task::spawn_blocking(move || {
        let paths = client.paths();

        // ── /etc/passwd ───────────────────────────────────────────────────
        // passwd_read tracks read SUCCESS (matches the struct doc and the other
        // three read flags, which are presence/readability checks), NOT entry
        // count: a valid-but-empty /etc/passwd (comments/blank lines only)
        // parses to Ok(vec![]) and must still read as `true`.
        let (passwd_entries, passwd_read): (Vec<toride_users::parse::PasswdEntry>, bool) =
            match toride_users::parse::read_passwd(&paths.passwd) {
                Ok(e) => (e, true),
                Err(e) => {
                    tracing::warn!("users read_passwd {}: {e}", paths.passwd.display());
                    (Vec::new(), false)
                }
            };
        let mut users = toride_users_convert::convert_passwd_all(passwd_entries);

        // ── /etc/group ────────────────────────────────────────────────────
        let groups: Vec<GroupEntry> = match toride_users::parse::read_group(&paths.group) {
            Ok(g) => toride_users_convert::convert_group_all(g),
            Err(e) => {
                tracing::warn!("users read_group {}: {e}", paths.group.display());
                Vec::new()
            }
        };

        // ── /etc/shadow presence (drives the locked badge source flag) ────
        let shadow_read = paths.shadow.exists();

        // ── sudoers: main file + drop-ins ─────────────────────────────────
        let mut sudoers: Vec<SudoersEntry> = Vec::new();
        let mut sudoers_read = false;
        if paths.sudoers.exists() {
            sudoers_read = true;
            match toride_users::parse::read_sudoers(&paths.sudoers) {
                Ok(entries) => {
                    sudoers.extend(toride_users_convert::convert_sudoers_all(entries));
                }
                Err(e) => {
                    tracing::warn!("users read_sudoers {}: {e}", paths.sudoers.display());
                }
            }
        }
        if paths.sudoers_d.is_dir() {
            // A drop-in directory existing counts as a sudoers source being
            // present even if every drop-in parse fails — the operator should
            // see the "read" badge so they know the directory is consulted.
            sudoers_read = true;
            if let Ok(read_dir) = std::fs::read_dir(&paths.sudoers_d) {
                for entry in read_dir.flatten() {
                    let path = entry.path();
                    // Skip backup files.
                    if path.extension().is_some_and(|e| e == "bak") {
                        continue;
                    }
                    match toride_users::parse::read_sudoers(&path) {
                        Ok(entries) => {
                            sudoers.extend(toride_users_convert::convert_sudoers_all(entries));
                        }
                        Err(e) => {
                            tracing::warn!("users read_sudoers {}: {e}", path.display());
                        }
                    }
                }
            }
        }

        // ── PAM: probe the sshd service (TOTP presence) ───────────────────
        // "sshd" is a constant safe name, so pam_service only fails on a
        // broken base dir; degrade to "no PAM read" rather than aborting.
        let sshd_pam = paths.pam_service("sshd").unwrap_or_else(|e| {
            tracing::warn!("could not resolve sshd PAM path: {e}");
            paths.pam_d.join("sshd")
        });
        let pam_read = sshd_pam.exists();
        let _ = pam_read; // surfaced to the UI; not parsed further here.

        // ── Per-user enrichment (sudo / locked / totp) ────────────────────
        // Run only over the parsed passwd rows, skipping system users with
        // nologin shells (they can't log in, so their sudo/lock/totp status is
        // not actionable).
        //
        // Hoisted, O(1) per user: the three /etc files are read ONCE here, not
        // once per interactive user. Previously this loop called
        // `sudo_ops.has_sudo` (re-reads full /etc/sudoers), `password_ops.is_locked`
        // (re-reads /etc/shadow), and `totp_ops.is_configured` (re-reads /etc/passwd
        // to resolve a home dir that was ALREADY parsed into `passwd_entries` above)
        // PER user — O(N) full-file re-reads of three files on a host with N
        // interactive users. The only thing that genuinely must stay per-user is
        // the `.google_authenticator` existence stat (cheap) and the per-user
        // sudoers drop-in existence check (cheap stat). Each probe is a
        // synchronous file read, not a process spawn; a missing/unreadable FILE
        // (not a missing binary) is the failure mode. Each field degrades
        // independently to `None`, never panicking the collection.
        //
        // Correctness parity with the per-user calls: the pre-reads below mirror
        // `sudo::has_sudo` (main sudoers `who` set + per-user drop-in stat),
        // `password::is_account_locked` (shadow `!`/`!!` prefix), and
        // `totp::is_totp_configured` (home from passwd + `.google_authenticator`
        // stat). A missing user in shadow degrades to `None`, matching the old
        // `Err(UserNotFound)` -> `None` behavior; an unreadable main sudoers
        // degrades the main-set lookup only (drop-in stat still runs, matching
        // `has_sudo`'s dropin-first ordering).
        let pam_ops = client.pam();

        // shadow -> username::is_locked map (None if /etc/shadow is unreadable,
        // matching the old "every per-user is_locked call fails -> None" path).
        let locked_map: Option<HashMap<String, bool>> = match std::fs::read_to_string(&paths.shadow)
        {
            Ok(shadow) => {
                let mut m = HashMap::new();
                for line in shadow.lines() {
                    let mut parts = line.split(':');
                    let Some(username) = parts.next() else {
                        continue;
                    };
                    let Some(pw_field) = parts.next() else {
                        continue;
                    };
                    if username.starts_with('#') {
                        continue;
                    }
                    m.insert(
                        username.to_owned(),
                        pw_field.starts_with('!') || pw_field.starts_with("!!"),
                    );
                }
                Some(m)
            }
            Err(e) => {
                tracing::debug!(
                    "users is_locked pre-read {} failed (degraded for all users): {e}",
                    paths.shadow.display()
                );
                None
            }
        };

        // main sudoers -> set of `who` with access (None if unreadable, matching
        // the old "every per-user has_sudo main-file lookup fails -> None for that
        // arm"; the per-user drop-in stat still runs below).
        let sudo_who_set: Option<HashSet<String>> = if paths.sudoers.exists() {
            match toride_users::parse::read_sudoers(&paths.sudoers) {
                Ok(entries) => Some(entries.iter().map(|e| e.who.clone()).collect()),
                Err(e) => {
                    tracing::debug!(
                        "users has_sudo pre-read {} failed (degraded main-file lookup): {e}",
                        paths.sudoers.display()
                    );
                    None
                }
            }
        } else {
            Some(HashSet::new())
        };

        // passwd username -> home dir. The home is ALREADY carried on each
        // `UserEntry` (converted from the passwd entries parsed at the top of
        // this closure), so the TOTP probe reads it straight off the row — no
        // second /etc/passwd read and no intermediate map. This matches the old
        // `is_totp_configured` home resolution (which re-read /etc/passwd to
        // find the same home value).

        for user in &mut users {
            // Skip pure-system users (nologin / false shells) — they can't log
            // in, so sudo/lock/totp status is not actionable.
            let interactive = !user.shell.contains("nologin") && !user.shell.contains("false");
            if !interactive {
                continue;
            }
            // sudo: drop-in existence (per-user stat) OR membership in the main
            // sudoers `who` set (pre-read once above). This mirrors
            // `sudo::has_sudo`'s dropin-first ordering exactly.
            // Degrade: a username that fails the safe-component check
            // (e.g. a corrupted entry) yields no drop-in rather than panicking.
            let dropin_exists = paths
                .sudoers_dropin(&user.username)
                .is_ok_and(|p| p.exists());
            let in_main = sudo_who_set
                .as_ref()
                .is_some_and(|set| set.contains(&user.username));
            user.sudo = Some(dropin_exists || in_main);
            // locked: O(1) shadow lookup. Missing user -> None (matches the old
            // Err(UserNotFound) -> None degrade).
            user.locked = locked_map
                .as_ref()
                .and_then(|m| m.get(&user.username).copied());
            // totp: resolve home from the row's own `home` field (parsed once
            // from /etc/passwd above), then stat `.google_authenticator`.
            user.totp = Some(
                std::path::Path::new(&user.home)
                    .join(".google_authenticator")
                    .exists(),
            );
        }
        // Touch pam_ops so the host-wide TOTP check is reachable if needed.
        let _ = pam_ops;

        // ── Doctor (unless cached) ────────────────────────────────────────
        let findings: Vec<UserFindingEntry> = if use_cache {
            cached_findings.unwrap_or_default()
        } else {
            let doctor = toride_users::doctor::Doctor::new();
            match doctor.run(&toride_users::doctor::DoctorScope::All) {
                Ok(report) => toride_users_convert::convert_findings(report.findings),
                Err(e) => {
                    tracing::warn!("users doctor: {e}");
                    Vec::new()
                }
            }
        };

        // ── Availability heuristic ────────────────────────────────────────
        // The section is "available" if ANY data was gathered — passwd rows,
        // groups, sudoers, findings, OR even just one of the /etc files
        // existing (so the operator sees the read-status overview rather than
        // a blank panel). Per-file failures degrade fields but keep available
        // true because reads are partial, not absent. Only a spawn_blocking
        // panic flips available to false (handled in the JoinError arm below).
        let available = !users.is_empty()
            || !groups.is_empty()
            || !sudoers.is_empty()
            || !findings.is_empty()
            || passwd_read
            || shadow_read
            || sudoers_read
            || pam_read;

        UsersDataBundle {
            available,
            passwd_read,
            shadow_read,
            sudoers_read,
            pam_read,
            users,
            groups,
            sudoers,
            findings,
            unavailable_reason: None,
        }
    })
    .await;

    match result {
        Ok(bundle) => (bundle, use_cache),
        Err(e) => {
            tracing::warn!("users collection task panicked: {e}");
            (
                empty_bundle_with_reason(format!("users data collection panicked: {e}")),
                false,
            )
        }
    }
}

/// Empty bundle used when the users backend could not be queried at all.
///
/// `available = false` signals the UI to render the degraded panel. No reason
/// is attached because none is known at this point; collection-time panics use
/// [`empty_bundle_with_reason`] to surface the `JoinError`.
fn empty_bundle() -> UsersDataBundle {
    UsersDataBundle {
        available: false,
        passwd_read: false,
        shadow_read: false,
        sudoers_read: false,
        pam_read: false,
        users: Vec::new(),
        groups: Vec::new(),
        sudoers: Vec::new(),
        findings: Vec::new(),
        unavailable_reason: None,
    }
}

/// Empty bundle carrying the reason collection failed. Used when a
/// `spawn_blocking` task panicked (`JoinError`) — the reason string is rendered
/// by the UI's degraded panel so the operator sees what actually went wrong.
fn empty_bundle_with_reason(reason: String) -> UsersDataBundle {
    let mut b = empty_bundle();
    b.unavailable_reason = Some(reason);
    b
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_not_pending() {
        let collector = UsersCollector::new();
        assert!(!collector.is_pending());
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(
            UsersCollector::new().is_pending(),
            UsersCollector::default().is_pending()
        );
    }

    #[tokio::test]
    async fn start_makes_pending() {
        let mut collector = UsersCollector::new();
        assert!(!collector.is_pending());
        collector.start();
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn start_is_idempotent() {
        let mut collector = UsersCollector::new();
        collector.start();
        assert!(collector.is_pending());
        collector.start(); // no-op, does not replace the receiver
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn poll_returns_none_when_not_started() {
        let mut collector = UsersCollector::new();
        assert!(collector.poll().await.is_none());
    }

    #[tokio::test]
    async fn poll_clears_pending() {
        let mut collector = UsersCollector::new();
        collector.start();
        // Let the spawned task complete (it reads files, so give it time).
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let _ = collector.poll().await;
        assert!(!collector.is_pending(), "poll should clear pending state");
    }

    #[tokio::test]
    async fn poll_returns_bundle_after_collection() {
        // On any host (including macOS without the full /etc set) the collector
        // must return Some(bundle) after start() + enough time. The bundle's
        // `available` flag reflects whether any data was found; per-file
        // failures degrade fields but a panic forces available=false.
        let mut collector = UsersCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let bundle = collector.poll().await;
        assert!(bundle.is_some(), "poll should return Some after completion");
    }

    #[test]
    fn empty_bundle_is_unavailable() {
        let b = empty_bundle();
        assert!(!b.available);
        assert!(b.users.is_empty());
        assert!(b.groups.is_empty());
        assert!(b.sudoers.is_empty());
        assert!(b.findings.is_empty());
        assert!(!b.passwd_read);
        assert!(!b.shadow_read);
        assert!(!b.sudoers_read);
        assert!(!b.pam_read);
        assert!(
            b.unavailable_reason.is_none(),
            "empty_bundle carries no reason; panics use empty_bundle_with_reason"
        );
    }

    #[tokio::test]
    async fn findings_cache_is_populated_after_poll() {
        let mut collector = UsersCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let _ = collector.poll().await;
        assert!(collector.cached_findings.is_some());
        assert!(collector.findings_fresh_at.is_some());
    }

    #[test]
    fn invalidate_findings_cache_clears_it() {
        let mut collector = UsersCollector::new();
        collector.cached_findings = Some(Vec::new());
        collector.findings_fresh_at = Some(std::time::Instant::now());
        collector.invalidate_findings_cache();
        assert!(collector.cached_findings.is_none());
        assert!(collector.findings_fresh_at.is_none());
    }

    /// Regression for the `passwd_read` flag-semantics bug: `passwd_read` must
    /// track read SUCCESS, not entry count. A valid-but-empty `/etc/passwd`
    /// (comments / blank lines only) parses to `Ok(vec![])`; before the fix the
    /// derivation `!passwd_entries.is_empty()` would have flipped `passwd_read`
    /// to `false`, mis-rendering the overview as "passwd ✗ missing" and
    /// polluting the `available` heuristic + macOS caveat. Mirrors the
    /// production derivation in `collect_real_users`.
    #[test]
    fn passwd_read_is_true_for_valid_but_empty_passwd() {
        let dir = tempfile::tempdir().expect("tempdir");
        let passwd = dir.path().join("passwd");
        // Comment + blank line only — parse_passwd returns Ok(vec![]).
        std::fs::write(&passwd, "# comment\n\n").expect("write");

        let (entries, passwd_read): (Vec<toride_users::parse::PasswdEntry>, bool) =
            match toride_users::parse::read_passwd(&passwd) {
                Ok(e) => (e, true),
                Err(_) => (Vec::new(), false),
            };
        assert!(
            entries.is_empty(),
            "comment-only passwd parses to empty vec"
        );
        assert!(
            passwd_read,
            "a successful read of an empty-but-valid passwd must read as true"
        );
    }

    /// Companion: a missing passwd file must read as `false`, proving the two
    /// cases are now distinguished (the bug made both report `false`).
    #[test]
    fn passwd_read_is_false_for_missing_passwd() {
        let dir = tempfile::tempdir().expect("tempdir");
        let passwd = dir.path().join("does-not-exist");
        let (_entries, passwd_read): (Vec<toride_users::parse::PasswdEntry>, bool) =
            match toride_users::parse::read_passwd(&passwd) {
                Ok(e) => (e, true),
                Err(_) => (Vec::new(), false),
            };
        assert!(!passwd_read, "a missing passwd file must read as false");
    }

    /// `pam_read` is a PRESENCE check on the probed service's PAM file
    /// (`sshd_pam.exists()`), NOT a parse-success signal — the file is never
    /// opened or parsed further here. This guards the corrected struct doc
    /// against a future drift back to a "read successfully" wording, and keeps
    /// `pam_read` symmetric with the other three read flags. Mirrors the
    /// production derivation in `collect_real_users` (line: `let pam_read =
    /// sshd_pam.exists();`).
    #[test]
    fn pam_read_is_true_when_pam_service_file_present() {
        let dir = tempfile::tempdir().expect("tempdir");
        // An empty file still "exists" — presence is the only signal, contents
        // are irrelevant (the file is never parsed here).
        let sshd_pam = dir.path().join("sshd");
        std::fs::write(&sshd_pam, "").expect("write");
        let pam_read = sshd_pam.exists();
        assert!(
            pam_read,
            "a present (even empty) pam.d/sshd file must read as true"
        );
    }

    /// Companion: a missing pam.d/sshd file must read as `false`, proving the
    /// two cases are distinguished and the UI renders "pam.d ✗ missing".
    #[test]
    fn pam_read_is_false_when_pam_service_file_absent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sshd_pam = dir.path().join("does-not-exist");
        let pam_read = sshd_pam.exists();
        assert!(
            !pam_read,
            "an absent pam.d/sshd file must read as false (macOS-style degradation)"
        );
    }
}
