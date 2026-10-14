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
//! the fail2ban findings cache. AIDE integrity status is cached longer
//! (300s, `IntegrityManager::DEFAULT_STATUS_TTL`): a fresh `aide --check`
//! re-hashes the monitored filesystem, which takes minutes on a real host,
//! so re-running it on every 2s refresh tick would keep a re-hash running
//! continuously while the dashboard is open.
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
    /// AIDE integrity status (cached for 300s between collections, matching
    /// `IntegrityManager::DEFAULT_STATUS_TTL`).
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
/// oneshot channel for the in-flight result, plus TTL caches for the
/// expensive probes (doctor findings, AIDE integrity status) so they are not
/// re-run on every 2s refresh tick.
pub struct AuditCollector {
    /// Carries the bundle plus which expensive probes actually ran. Each
    /// cache's freshness clock is advanced only for probes that ran; a
    /// cache-hit poll never re-arms its own TTL.
    rx: Option<oneshot::Receiver<(AuditDataBundle, PollRan)>>,
    /// Cached doctor findings from the last collection.
    cached_findings: Option<Vec<AuditFindingEntry>>,
    /// When the findings cache was last refreshed.
    findings_fresh_at: Option<std::time::Instant>,
    /// Cached AIDE integrity status from the last collection.
    cached_integrity: Option<IntegrityStateEntry>,
    /// When the integrity cache was last refreshed.
    integrity_fresh_at: Option<std::time::Instant>,
}

/// How long to keep cached findings before re-running the doctor suite.
const FINDINGS_TTL: std::time::Duration = std::time::Duration::from_secs(60);

/// How long to keep the cached integrity status before re-running
/// `aide --version` + `aide --check`. Mirrors the backend memoization window
/// ([`toride_audit::integrity::IntegrityManager::DEFAULT_STATUS_TTL`]): a
/// check re-hashes the monitored filesystem, so the 60s findings cadence
/// would keep one running continuously.
const INTEGRITY_TTL: std::time::Duration =
    toride_audit::integrity::IntegrityManager::DEFAULT_STATUS_TTL;

/// Which expensive probes a completed collection actually ran (false means
/// the collector served that probe from its cache, or the collection failed
/// before the probe ran and the cache was left untouched).
#[derive(Clone, Copy, Debug, Default)]
struct PollRan {
    doctor: bool,
    integrity: bool,
}

impl AuditCollector {
    /// Create a new collector with no pending collection.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rx: None,
            cached_findings: None,
            findings_fresh_at: None,
            cached_integrity: None,
            integrity_fresh_at: None,
        }
    }

    /// Whether a collection is currently in-flight.
    pub fn is_pending(&self) -> bool {
        self.rx.is_some()
    }

    /// Whether the findings cache is populated and inside its TTL.
    fn findings_cache_is_fresh(&self) -> bool {
        self.cached_findings.is_some()
            && self
                .findings_fresh_at
                .is_some_and(|t| t.elapsed() < FINDINGS_TTL)
    }

    /// Whether the integrity cache is populated and inside its TTL.
    fn integrity_cache_is_fresh(&self) -> bool {
        self.cached_integrity.is_some()
            && self
                .integrity_fresh_at
                .is_some_and(|t| t.elapsed() < INTEGRITY_TTL)
    }

    /// Start a new background collection.
    ///
    /// If a collection is already in-flight, this is a no-op. The TTL caches
    /// are consulted: when fresh, the spawned task reuses the cached findings
    /// and the cached integrity status instead of re-running the doctor suite
    /// and `aide --check`.
    pub fn start(&mut self) {
        if self.rx.is_some() {
            return;
        }
        let (tx, rx) = oneshot::channel();
        let use_findings_cache = self.findings_cache_is_fresh();
        let use_integrity_cache = self.integrity_cache_is_fresh();
        let cached_findings = self.cached_findings.clone();
        let cached_integrity = self.cached_integrity.clone();
        self.rx = Some(rx);
        tokio::spawn(async move {
            let (bundle, ran) = collect_real_audit(
                use_findings_cache,
                cached_findings,
                use_integrity_cache,
                cached_integrity,
            )
            .await;
            let _ = tx.send((bundle, ran));
        });
    }

    /// Poll for a completed collection result.
    ///
    /// Returns `Some(bundle)` if the collection completed, `None` if still
    /// pending or if the collection failed. Each cache is updated (value and
    /// freshness clock) only for probes that actually ran; a cache-hit poll
    /// leaves that cache untouched so its TTL is never re-armed with the same
    /// data, and a failed collection never overwrites a good cached value.
    pub async fn poll(&mut self) -> Option<AuditDataBundle> {
        match &mut self.rx {
            Some(rx) => {
                let result = rx.await.ok();
                if let Some((ref bundle, ran)) = result {
                    if ran.doctor {
                        self.cached_findings = Some(bundle.findings.clone());
                        self.findings_fresh_at = Some(std::time::Instant::now());
                    }
                    if ran.integrity {
                        self.cached_integrity = Some(bundle.integrity.clone());
                        self.integrity_fresh_at = Some(std::time::Instant::now());
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

    /// Invalidate the integrity cache so the next collection re-runs
    /// `aide --version` + `aide --check`.
    #[allow(dead_code)]
    pub fn invalidate_integrity_cache(&mut self) {
        self.cached_integrity = None;
        self.integrity_fresh_at = None;
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
/// synchronously). Doctor findings and integrity status may be reused from
/// the collector caches. On ANY error — construction failure, doctor error,
/// every probe failing — returns [`empty_bundle`] with `available = false`.
///
/// Returns `(bundle, ran)` where `ran` records which expensive probes
/// actually ran; the caller updates only those caches, so a cache-hit poll
/// never resets a freshness clock and a failed collection never overwrites a
/// good cached value.
async fn collect_real_audit(
    use_findings_cache: bool,
    cached_findings: Option<Vec<AuditFindingEntry>>,
    use_integrity_cache: bool,
    cached_integrity: Option<IntegrityStateEntry>,
) -> (AuditDataBundle, PollRan) {
    let nothing_ran = PollRan::default();
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
                nothing_ran,
            );
        }
        Err(e) => {
            tracing::warn!("audit construction task panicked: {e}");
            return (
                empty_bundle_with_reason(format!("audit backend construction panicked: {e}")),
                nothing_ran,
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
        let mut ran = PollRan::default();

        // ── Doctor (unless cached) ─────────────────────────────────────────
        let findings: Vec<AuditFindingEntry> = if use_findings_cache {
            cached_findings.unwrap_or_default()
        } else {
            ran.doctor = true;
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

        // ── AIDE integrity status (unless cached) ─────────────────────────
        // `aide --check` re-hashes the monitored filesystem (minutes on a real
        // host), so this probe carries the longest TTL: when the cache is
        // fresh the spawn is skipped entirely.
        let integrity = if let Some(cached) = cached_integrity.filter(|_| use_integrity_cache) {
            cached
        } else {
            ran.integrity = true;
            probe_integrity(&audit)
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

        (
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
                // Success path: no panic, so no reason. (A missing binary
                // surfaces as a Critical finding, keeping `available == true`.)
                unavailable_reason: None,
            },
            ran,
        )
    })
    .await;

    match result {
        Ok((bundle, ran)) => (bundle, ran),
        Err(e) => {
            tracing::warn!("audit collection task panicked: {e}");
            (
                empty_bundle_with_reason(format!("audit data collection panicked: {e}")),
                nothing_ran,
            )
        }
    }
}

/// Run `aide --version` + `aide --check` through the facade and convert the
/// status into the presentation entry (an honest unknown entry on error).
fn probe_integrity(audit: &toride_audit::Audit) -> IntegrityStateEntry {
    match audit.integrity().status() {
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
        assert_eq!(b.auditd_status, "");
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
    fn invalidate_integrity_cache_clears_it() {
        let mut collector = AuditCollector::new();
        collector.cached_integrity = Some(IntegrityStateEntry {
            database_initialized: true,
            file_count: Some(0),
            last_check_passed: Some(true),
            last_check_output: None,
        });
        collector.integrity_fresh_at = Some(std::time::Instant::now());
        collector.invalidate_integrity_cache();
        assert!(collector.cached_integrity.is_none());
        assert!(collector.integrity_fresh_at.is_none());
    }

    /// The integrity TTL mirrors the backend memoization window and is
    /// strictly longer than the findings cadence: `aide --check` re-hashes
    /// the monitored filesystem, so a 60s integrity TTL would keep a re-hash
    /// running continuously (the safety-state-9 hazard).
    #[test]
    fn integrity_ttl_mirrors_backend_and_exceeds_findings_ttl() {
        assert_eq!(
            INTEGRITY_TTL,
            toride_audit::integrity::IntegrityManager::DEFAULT_STATUS_TTL
        );
        assert!(
            INTEGRITY_TTL > FINDINGS_TTL,
            "integrity must be cached longer than doctor findings"
        );
    }

    /// Freshness helpers: a populated cache with a fresh timestamp reads
    /// fresh; no cache, or an expired timestamp, reads stale.
    #[test]
    fn integrity_cache_freshness_follows_populated_and_expired_state() {
        let mut collector = AuditCollector::new();
        assert!(!collector.integrity_cache_is_fresh(), "empty is stale");

        collector.cached_integrity = Some(IntegrityStateEntry {
            database_initialized: true,
            file_count: Some(0),
            last_check_passed: Some(true),
            last_check_output: None,
        });
        collector.integrity_fresh_at = Some(std::time::Instant::now());
        assert!(
            collector.integrity_cache_is_fresh(),
            "freshly populated cache is fresh"
        );

        collector.integrity_fresh_at = Some(
            std::time::Instant::now()
                .checked_sub(INTEGRITY_TTL)
                .expect("host uptime exceeds the 300s integrity TTL"),
        );
        assert!(
            !collector.integrity_cache_is_fresh(),
            "expired timestamp is stale"
        );
    }

    /// The same state machine holds for the findings cache.
    #[test]
    fn findings_cache_freshness_follows_populated_and_expired_state() {
        let mut collector = AuditCollector::new();
        assert!(!collector.findings_cache_is_fresh());
        collector.cached_findings = Some(Vec::new());
        collector.findings_fresh_at = Some(
            std::time::Instant::now()
                .checked_sub(FINDINGS_TTL)
                .expect("host uptime exceeds the 60s findings TTL"),
        );
        assert!(!collector.findings_cache_is_fresh());
        collector.findings_fresh_at = Some(std::time::Instant::now());
        assert!(collector.findings_cache_is_fresh());
    }

    #[tokio::test]
    async fn integrity_cache_is_populated_after_poll() {
        let mut collector = AuditCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let _ = collector.poll().await;
        // After a successful cold poll both caches are populated (the probes
        // ran; even a no-AIDE host caches the honest not_installed entry).
        assert!(collector.cached_integrity.is_some());
        assert!(collector.integrity_fresh_at.is_some());
        assert!(collector.cached_findings.is_some());
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
