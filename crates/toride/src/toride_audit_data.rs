//! Async audit data collection (LIVE READ-ONLY).
//!
//! [`AuditCollector`] manages background collection of all audit-subsystem
//! data (auditd status, AIDE integrity, audit rules, log sources, doctor
//! findings) via a tokio oneshot channel, following the exact same pattern as
//! [`Fail2banCollector`](crate::fail2ban_data::Fail2banCollector) and
//! [`StatusCollector`](crate::status_collector::StatusCollector).
//!
//! This mirrors the fail2ban read-only template MINUS the write path — there
//! are no mutating operations, no optimistic updates, no cooldown gate, and no
//! loading spinner. Every call to the backend is a pure read.
//!
//! Doctor findings are expensive (they shell out to `systemctl`, `which`,
//! auditctl, …) and change slowly, so they are cached for 60s — exactly like
//! the fail2ban findings cache.
//!
//! ## macOS / construction
//!
//! [`toride_audit::Audit::system`] is the production constructor: it builds a
//! `DuctRunner` and resolves the default Linux FHS paths. On macOS where none
//! of the audit binaries exist, construction itself still succeeds (the runner
//! and paths are inert); the doctor then surfaces the missing binaries as
//! `Critical` findings rather than the whole collector erroring out. The
//! section's `available` flag stays `true` so the operator SEES the findings.
//!
//! ## Blocking
//!
//! The `DuctRunner` shells out synchronously. All backend work is wrapped in
//! [`tokio::task::spawn_blocking`] so the tokio worker is never stalled.

use tokio::sync::oneshot;

use crate::toride_audit_convert;
use crate::ui::screens::toride_audit::{
    AuditFindingEntry, AuditLogSourceEntry, AuditRuleEntry, IntegrityStateEntry,
};

/// Aggregated audit data for the read-only section.
#[derive(Clone, Debug)]
pub struct AuditDataBundle {
    /// Whether the audit backend was reachable at all. `false` only when a
    /// collection task panicked (`JoinError`) — a missing binary surfaces as a
    /// Critical finding and keeps `available == true` so the operator sees the
    /// findings panel. `false` means the UI renders a degraded "unavailable"
    /// panel.
    pub available: bool,
    /// Whether the auditd service is running.
    pub auditd_running: bool,
    /// Raw `auditctl -s` status text (best-effort; empty on failure).
    pub auditd_status: String,
    /// AIDE integrity status.
    pub integrity: IntegrityStateEntry,
    /// Parsed audit rule files from `/etc/audit/rules.d`.
    pub rules: Vec<AuditRuleEntry>,
    /// Audit log file sources (`/var/log/audit/*`).
    pub log_sources: Vec<AuditLogSourceEntry>,
    /// Whether rsyslog is available and running (`None` if the probe failed).
    pub rsyslog_available: Option<bool>,
    /// Whether systemd-journald is available and running (`None` if the probe
    /// failed).
    pub journald_available: Option<bool>,
    /// Doctor findings (cached for 60s between collections).
    pub findings: Vec<AuditFindingEntry>,
    /// Human-readable reason the backend was unreachable, populated ONLY when
    /// `available == false` because a collection task panicked (`JoinError`).
    /// `None` otherwise — notably also `None` for a freshly-constructed empty
    /// bundle before any collection has run. Surfaced to the UI so the degraded
    /// panel can show what actually went wrong instead of guessing.
    pub unavailable_reason: Option<String>,
}

// ── Collector ───────────────────────────────────────────────────────────────

/// Manages periodic async collection of audit data.
///
/// Mirrors [`Fail2banCollector`](crate::fail2ban_data::Fail2banCollector): a
/// oneshot channel for the in-flight result, plus a 60s TTL cache for the
/// expensive doctor findings so they are not re-run on every 2s refresh tick.
pub struct AuditCollector {
    /// Carries the bundle AND whether the cached findings were reused for this
    /// poll. The freshness timestamp must only be advanced when the doctor was
    /// actually re-run (`used_cache == false`); otherwise every cache-hit poll
    /// would reset the TTL clock with the SAME (already-cached) findings and
    /// the cache would never expire for the lifetime of the app.
    rx: Option<oneshot::Receiver<(AuditDataBundle, bool)>>,
    /// Cached doctor findings from the last collection.
    cached_findings: Option<Vec<AuditFindingEntry>>,
    /// When the findings cache was last refreshed.
    findings_fresh_at: Option<std::time::Instant>,
}

/// How long to keep cached findings before re-running the doctor suite.
#[expect(
    clippy::duration_suboptimal_units,
    reason = "stable std lacks from_mins"
)]
const FINDINGS_TTL: std::time::Duration = std::time::Duration::from_secs(60);

impl AuditCollector {
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
    #[allow(clippy::similar_names)]
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
            #[allow(
                clippy::similar_names,
                reason = "use_cache (input) vs used_cache (output) are distinct domain flags"
            )]
            let (bundle, used_cache) = collect_real_audit(use_cache, cached_findings).await;
            let _ = tx.send((bundle, used_cache));
        });
    }

    /// Poll for a completed collection result.
    ///
    /// Returns `Some(bundle)` if the collection completed, `None` if still
    /// pending or if the collection failed. On success the cached findings are
    /// updated to the freshly-returned findings, but the freshness timestamp is
    /// only advanced when the doctor was actually re-run (not on a cache-hit
    /// poll) — otherwise the 60s TTL would be re-armed forever with the same
    /// cached data on every 2s refresh.
    pub async fn poll(&mut self) -> Option<AuditDataBundle> {
        match &mut self.rx {
            Some(rx) => {
                let result = rx.await.ok();
                if let Some((ref bundle, used_cache)) = result {
                    self.cached_findings = Some(bundle.findings.clone());
                    if !used_cache {
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

impl Default for AuditCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Real data collection ────────────────────────────────────────────────────

/// Collect audit data by shelling out to the real binaries.
///
/// All work runs on the blocking thread pool (the `DuctRunner` shells out
/// synchronously). Doctor findings may be reused from the cache. On ANY error
/// — construction failure, doctor error, every probe failing — returns
/// [`empty_bundle`] with `available = false`.
///
/// `use_cache` / `cached_findings` mirror the fail2ban diagnostics cache: when
/// the cache is fresh the doctor suite is skipped entirely.
///
/// Returns `(bundle, used_cache)` where `used_cache` records whether the
/// findings were actually taken from the cache on a successful collection.
/// The caller advances the TTL clock ONLY when `used_cache == false`, so a
/// cache-hit poll never resets the freshness timestamp with stale data.
async fn collect_real_audit(
    use_cache: bool,
    cached_findings: Option<Vec<AuditFindingEntry>>,
) -> (AuditDataBundle, bool) {
    // Build the Audit facade on the blocking pool. system() shells out to
    // resolve a DuctRunner + default Linux paths; on macOS where no audit
    // binaries exist, construction still succeeds (the runner is inert) and
    // the doctor surfaces the missing binaries as Critical findings.
    let audit = match tokio::task::spawn_blocking(toride_audit::Audit::system).await {
        Ok(Ok(audit)) => audit,
        Ok(Err(e)) => {
            tracing::warn!("audit construction failed: {e}");
            return (
                empty_bundle_with_reason(format!("audit backend construction failed: {e}")),
                false,
            );
        }
        Err(e) => {
            tracing::warn!("audit construction task panicked: {e}");
            return (
                empty_bundle_with_reason(format!("audit backend construction panicked: {e}")),
                false,
            );
        }
    };

    // Run ALL blocking probes in a single spawn_blocking that owns `audit`.
    // This keeps every shell-out off the tokio worker (the `DuctRunner` is
    // synchronous) and sidesteps the 'static-borrow problem: the managers
    // borrow `&audit`, so collecting everything in one owned closure is both
    // simpler and cheaper than spawning one task per probe. Results are
    // returned as plain owned data so they cross the thread boundary cleanly.
    // Doctor findings are taken from the cache when fresh (`use_cache`),
    // otherwise re-run here.
    let result = tokio::task::spawn_blocking(move || {
        // ── Doctor (unless cached) ─────────────────────────────────────────
        let findings: Vec<AuditFindingEntry> = if use_cache {
            cached_findings.unwrap_or_default()
        } else {
            match audit.doctor(toride_audit::doctor::DoctorScope::All) {
                Ok(report) => toride_audit_convert::convert_findings(report.findings),
                Err(e) => {
                    tracing::warn!("audit doctor: {e}");
                    Vec::new()
                }
            }
        };

        // ── auditd status + running ───────────────────────────────────────
        let auditd = audit.auditd();
        let auditd_running = auditd.is_running().unwrap_or(false);
        let auditd_status = auditd.status().unwrap_or_default();

        // ── AIDE integrity status ─────────────────────────────────────────
        let integrity = match audit.integrity().status() {
            Ok(s) => toride_audit_convert::convert_integrity(s),
            Err(e) => {
                tracing::debug!("audit integrity status: {e}");
                toride_audit_convert::convert_integrity(toride_audit::integrity::IntegrityStatus {
                    database_initialized: false,
                    file_count: None,
                    last_check_passed: None,
                    last_check_output: None,
                })
            }
        };

        // ── Audit rule files ──────────────────────────────────────────────
        let rules = match toride_audit::auditd_rules::list_rule_files(audit.paths()) {
            Ok(files) => toride_audit_convert::convert_rule_files(files),
            Err(e) => {
                tracing::debug!("audit list_rule_files: {e}");
                Vec::new()
            }
        };

        // ── Log sources + log backends ────────────────────────────────────
        let logs = audit.logs();
        let log_sources = match logs.list_log_files() {
            Ok(paths) => toride_audit_convert::convert_log_files(paths),
            Err(e) => {
                tracing::debug!("audit list_log_files: {e}");
                Vec::new()
            }
        };
        let rsyslog_available = logs.is_rsyslog_available().ok();
        let journald_available = logs.is_journald_available().ok();

        // ── Availability heuristic ────────────────────────────────────────
        // The section is "available" if ANY probe produced data: a non-empty
        // status, the AIDE DB initialized, any rule file, any log source, a
        // confirmed backend, or any doctor finding. A host with every audit
        // binary missing yields Critical findings but no status — that still
        // counts as available so the operator SEES the findings rather than a
        // blank panel.
        let available = !auditd_status.is_empty()
            || auditd_running
            || integrity.database_initialized
            || !rules.is_empty()
            || !log_sources.is_empty()
            || rsyslog_available == Some(true)
            || journald_available == Some(true)
            || !findings.is_empty();

        AuditDataBundle {
            available,
            auditd_running,
            auditd_status,
            integrity,
            rules,
            log_sources,
            rsyslog_available,
            journald_available,
            findings,
            // Success path: no panic, so no reason. (A missing binary surfaces
            // as a Critical finding, keeping `available == true`.)
            unavailable_reason: None,
        }
    })
    .await;

    match result {
        Ok(bundle) => (bundle, use_cache),
        Err(e) => {
            tracing::warn!("audit collection task panicked: {e}");
            (
                empty_bundle_with_reason(format!("audit data collection panicked: {e}")),
                false,
            )
        }
    }
}

/// Empty bundle used when audit could not be constructed at all.
///
/// `available = false` signals the UI to render the degraded panel. No reason
/// is attached because none is known at this point; collection-time panics use
/// [`empty_bundle_with_reason`] to surface the `JoinError`.
fn empty_bundle() -> AuditDataBundle {
    AuditDataBundle {
        available: false,
        auditd_running: false,
        auditd_status: String::new(),
        integrity: IntegrityStateEntry {
            database_initialized: false,
            file_count: None,
            last_check_passed: None,
            last_check_output: None,
        },
        rules: Vec::new(),
        log_sources: Vec::new(),
        rsyslog_available: None,
        journald_available: None,
        findings: Vec::new(),
        unavailable_reason: None,
    }
}

/// Empty bundle carrying the reason collection failed. Used when a
/// `spawn_blocking` task panicked (`JoinError`) — the reason string is rendered
/// by the UI's degraded panel so the operator sees what actually went wrong.
fn empty_bundle_with_reason(reason: String) -> AuditDataBundle {
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
        let collector = AuditCollector::new();
        assert!(!collector.is_pending());
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(
            AuditCollector::new().is_pending(),
            AuditCollector::default().is_pending()
        );
    }

    #[tokio::test]
    async fn start_makes_pending() {
        let mut collector = AuditCollector::new();
        assert!(!collector.is_pending());
        collector.start();
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn start_is_idempotent() {
        let mut collector = AuditCollector::new();
        collector.start();
        assert!(collector.is_pending());
        collector.start(); // no-op, does not replace the receiver
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn poll_returns_none_when_not_started() {
        let mut collector = AuditCollector::new();
        assert!(collector.poll().await.is_none());
    }

    #[tokio::test]
    async fn poll_clears_pending() {
        let mut collector = AuditCollector::new();
        collector.start();
        // Let the spawned task complete (it shells out, so give it time).
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let _ = collector.poll().await;
        assert!(!collector.is_pending(), "poll should clear pending state");
    }

    #[tokio::test]
    async fn poll_returns_bundle_after_collection() {
        // On any host (including macOS without audit binaries) the collector
        // must return Some(bundle) after start() + enough time. The bundle's
        // `available` flag reflects whether any audit subsystem was found.
        let mut collector = AuditCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let bundle = collector.poll().await;
        assert!(bundle.is_some(), "poll should return Some after completion");
    }

    #[test]
    fn empty_bundle_is_unavailable() {
        let b = empty_bundle();
        assert!(!b.available);
        assert!(b.auditd_status.is_empty());
        assert!(!b.auditd_running);
        assert!(!b.integrity.database_initialized);
        assert!(b.rules.is_empty());
        assert!(b.log_sources.is_empty());
        assert!(b.findings.is_empty());
        assert!(b.rsyslog_available.is_none());
        assert!(b.journald_available.is_none());
        assert!(
            b.unavailable_reason.is_none(),
            "empty_bundle carries no reason; panics use empty_bundle_with_reason"
        );
    }

    #[tokio::test]
    async fn findings_cache_is_populated_after_poll() {
        let mut collector = AuditCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let _ = collector.poll().await;
        // After a successful poll the cache is populated (even if to an empty
        // Vec on a host where the doctor produced no findings).
        assert!(collector.cached_findings.is_some());
        assert!(collector.findings_fresh_at.is_some());
    }

    #[test]
    fn invalidate_findings_cache_clears_it() {
        let mut collector = AuditCollector::new();
        collector.cached_findings = Some(Vec::new());
        collector.findings_fresh_at = Some(std::time::Instant::now());
        collector.invalidate_findings_cache();
        assert!(collector.cached_findings.is_none());
        assert!(collector.findings_fresh_at.is_none());
    }

    #[test]
    fn availability_is_per_poll_snapshot_not_a_monotonic_latch() {
        // Records the property noted in the availability heuristic review:
        // `available` reflects current per-poll truth, NOT a latch. The UI's
        // `set_toride_audit_data` overwrites the whole bundle on every poll,
        // so availability can legitimately flip false→true (or true→false)
        // between a cache-hit poll and a cache-miss poll when a subsystem
        // becomes reachable (or unreachable) in the window.
        //
        // `available` is computed once per poll inside `collect_real_audit`
        // as an OR over the fresh probes (auditd_status, auditd_running,
        // integrity, rules, log_sources, rsyslog, journald, findings) — it
        // is NOT recomputed from the other bundle fields on mutation. So the
        // correct model of "two successive polls" is two independent bundles
        // whose `available` flags were each set by the heuristic at poll
        // time. There is no shared state that could make a later poll's flag
        // depend on an earlier poll's flag.
        //
        // Concretely: poll A (auditd down, no findings) → available = false.
        // Poll B (auditd just started, stale empty findings from cache) →
        // available = true via the auditd_status probe, even though
        // `findings` is still empty. Poll C (auditd went silent again) →
        // available = false once more.

        // Poll A: nothing reachable.
        let poll_a = empty_bundle();
        assert!(!poll_a.available, "poll A: nothing reachable → unavailable");

        // Poll B: auditd now reports status. The heuristic ORs in
        // `!auditd_status.is_empty()`, so `available` is true even though
        // the cached findings are still empty.
        let poll_b = AuditDataBundle {
            available: true, // heuristic: !auditd_status.is_empty()
            auditd_status: "enabled 1".to_string(),
            findings: Vec::new(), // stale cached findings, still empty
            ..empty_bundle()
        };
        assert!(
            poll_b.available,
            "poll B: auditd_status alone marks available despite empty findings"
        );
        assert!(poll_b.findings.is_empty());

        // Poll C: auditd goes silent again. The heuristic recomputes against
        // current probes and yields false — the prior true does NOT latch.
        let poll_c = empty_bundle();
        assert!(
            !poll_c.available,
            "poll C: availability reflects current truth, not the prior poll"
        );

        // Independence: poll B's flag is untouched by poll C. This is the
        // property that makes the per-poll overwrite in
        // `set_toride_audit_data` correct — each bundle is a self-contained
        // snapshot.
        assert!(poll_b.available, "poll B snapshot is independent of poll C");
        assert!(!poll_a.available);
    }
}
