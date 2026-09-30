//! Async backup data collection (LIVE READ-ONLY).
//!
//! [`BackupCollector`] manages background collection of backup subsystem state
//! via a tokio oneshot channel, following the exact same pattern as
//! [`Fail2banCollector`](crate::fail2ban_data::Fail2banCollector) and
//! [`SshDataCollector`](crate::ssh_data::SshDataCollector).
//!
//! This is a pure read-only integration: there are no write operations, no
//! optimistic updates, no cooldown gate, and no loading spinner. Every call to
//! the backend is a read.
//!
//! Doctor findings are the primary live signal — they shell out to `which` to
//! detect restic/borg, and (once implemented) will probe repositories,
//! schedules, integrity, encryption, retention, and free space. They are
//! cached for 60s between collections, exactly like the SSH diagnostics cache.
//!
//! ## macOS / construction
//!
//! [`toride_backup::BackupClient::system`] resolves XDG directories; it
//! succeeds even when no backup binary is present (the doctor then surfaces
//! the missing binary as a `Critical` finding rather than the whole collector
//! erroring out). `ScheduleManager` / `BackupServiceManager` queries are
//! best-effort and currently stubbed to `false` by the backend until systemd
//! timer plumbing lands — they are plumbed here so the UI is ready when they
//! are implemented.
//!
//! ## Blocking
//!
//! All backend work (`BackupClient::system`, `doctor`, schedule/timer probes,
//! `paths()`) runs synchronously. It is wrapped in a single
//! [`tokio::task::spawn_blocking`] so the tokio worker is never stalled,
//! exactly like `collect_real_fail2ban`.

use tokio::sync::oneshot;

use crate::toride_backup_convert;
use crate::ui::screens::toride_backup::FindingEntry;

/// Aggregated backup data for the read-only section.
#[derive(Clone, Debug)]
pub struct BackupDataBundle {
    /// Whether the backup backend was reachable at all. `false` only when the
    /// collection task panicked (`JoinError`) — a host missing restic/borg
    /// still yields `available == true` so the operator SEES the Critical
    /// doctor finding instead of a blank panel.
    pub available: bool,
    /// Whether dry-run mode is active on the constructed client.
    pub dry_run: bool,
    /// Resolved config directory (`XDG_CONFIG_HOME/toride/backup`), if known.
    pub config_dir: Option<String>,
    /// Resolved data directory (`XDG_DATA_HOME/toride/backup`), if known.
    pub data_dir: Option<String>,
    /// Resolved schedule directory, if known.
    pub schedule_dir: Option<String>,
    /// restic binary availability inferred from doctor findings
    /// (`binary.restic.found`/`.missing`). `None` when the Binary scope was
    /// not run.
    pub restic_available: Option<bool>,
    /// borg binary availability inferred from doctor findings. `None` when the
    /// Binary scope was not run.
    pub borg_available: Option<bool>,
    /// Whether a schedule is installed for the default `toride-backup` job
    /// (best-effort; backend currently stubs this to `false`).
    pub schedule_installed: Option<bool>,
    /// Whether the systemd timer for the default `toride-backup` job is active
    /// (best-effort; backend currently stubs this to `false`).
    pub timer_active: Option<bool>,
    /// Informational note explaining a negative schedule reading (e.g.
    /// `"systemd not detected"` on a host without systemd). Populated by the
    /// backend's `ScheduleManager::schedule_note()` so the UI can surface WHY
    /// the schedule read as false, distinguishing "no schedule configured"
    /// from "systemd absent". `None` when the note is empty or unavailable.
    pub schedule_note: Option<String>,
    /// Doctor findings (cached for 60s between collections).
    pub findings: Vec<FindingEntry>,
    /// Human-readable reason the backend was unreachable, populated ONLY when
    /// `available == false` because a collection task panicked (`JoinError`).
    pub unavailable_reason: Option<String>,
}

// ── Collector ───────────────────────────────────────────────────────────────

/// Manages periodic async collection of backup data.
///
/// Mirrors [`Fail2banCollector`](crate::fail2ban_data::Fail2banCollector): a
/// oneshot channel for the in-flight result, plus a 60s TTL cache for the
/// expensive doctor findings so they are not re-run on every 2s refresh tick.
pub struct BackupCollector {
    /// Carries the bundle AND whether the cached findings were reused for this
    /// poll. See [`Fail2banCollector`](crate::fail2ban_data::Fail2banCollector)
    /// for why the freshness timestamp must only advance when the doctor was
    /// actually re-run.
    rx: Option<oneshot::Receiver<(BackupDataBundle, bool)>>,
    /// Cached doctor findings from the last collection.
    cached_findings: Option<Vec<FindingEntry>>,
    /// When the findings cache was last refreshed.
    findings_fresh_at: Option<std::time::Instant>,
}

/// How long to keep cached findings before re-running the doctor suite.
const FINDINGS_TTL: std::time::Duration = std::time::Duration::from_mins(1);

/// Whether the findings-cache TTL has already elapsed for a cache that was
/// last refreshed at `fresh_at`.
///
/// Round-0 instrumentation seam, ZERO behavior change: outside `cfg(test)`
/// this is exactly the negation of the `t.elapsed() < FINDINGS_TTL` check
/// `start` always evaluated inline. Under `cfg(test)` the thread-local
/// [`TTL_TEST_OFFSET_MS`] is folded into the elapsed time so the cadence
/// oracles can observe TTL expiry deterministically — no 60s sleeps and no
/// dependence on host uptime (the `Instant::now() - TTL` backdating trick
/// fails on a machine whose monotonic clock started less than the TTL ago).
/// The offset is thread-local, so concurrently running tests on other cargo
/// test threads cannot perturb this module's cadence.
fn ttl_expired(fresh_at: std::time::Instant) -> bool {
    let elapsed = fresh_at.elapsed();
    #[cfg(test)]
    let elapsed =
        elapsed + std::time::Duration::from_millis(TTL_TEST_OFFSET_MS.with(std::cell::Cell::get));
    elapsed >= FINDINGS_TTL
}

// Extra milliseconds folded into `ttl_expired`'s elapsed time by the
// cadence oracles. Test-only: zero unless a test on this thread advances it
// (and resets it on drop), and not compiled at all outside `cfg(test)`.
// (Plain comments: rustdoc does not generate documentation for macro
// invocations, so a doc comment here warns as unused.)
#[cfg(test)]
thread_local! {
    static TTL_TEST_OFFSET_MS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// The default backup job name probed for schedule/timer status.
///
/// The backend does not yet enumerate configured jobs, so a single canonical
/// name is queried. When job discovery lands this can fan out over all known
/// specs.
const DEFAULT_JOB_NAME: &str = "toride-backup";

impl BackupCollector {
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
            && self.findings_fresh_at.is_some_and(|t| !ttl_expired(t));
        let cached_findings = self.cached_findings.clone();
        self.rx = Some(rx);
        tokio::spawn(async move {
            let (bundle, reused_cache) = collect_real_backup(use_cache, cached_findings).await;
            let _ = tx.send((bundle, reused_cache));
        });
    }

    /// Poll for a completed collection result.
    ///
    /// Returns `Some(bundle)` if the collection completed, `None` if still
    /// pending or if the collection failed. On success the cached findings are
    /// updated to the freshly-returned findings, but the freshness timestamp
    /// is only advanced when the doctor was actually re-run (not on a
    /// cache-hit poll) — otherwise the 60s TTL would be re-armed forever with
    /// the same cached data on every 2s refresh.
    pub async fn poll(&mut self) -> Option<BackupDataBundle> {
        match &mut self.rx {
            Some(rx) => {
                let result = rx.await.ok();
                if let Some((ref bundle, used_cache)) = result {
                    // On a collection panic the bundle is empty and marked
                    // `available == false`. We must NOT poison the findings
                    // cache with that empty Vec (and must NOT advance the
                    // freshness timestamp): doing so would keep the section in
                    // its degraded state for the full 60s TTL even if the
                    // underlying cause cleared on the next tick. Instead we
                    // invalidate so the very next refresh re-runs the doctor.
                    if bundle.available {
                        self.cached_findings = Some(bundle.findings.clone());
                        if !used_cache {
                            self.findings_fresh_at = Some(std::time::Instant::now());
                        }
                    } else {
                        self.invalidate_findings_cache();
                    }
                }
                self.rx = None;
                result.map(|(bundle, _)| bundle)
            }
            None => None,
        }
    }

    /// Invalidate the findings cache so the next collection re-runs the doctor.
    pub fn invalidate_findings_cache(&mut self) {
        self.cached_findings = None;
        self.findings_fresh_at = None;
    }
}

impl Default for BackupCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Real data collection ────────────────────────────────────────────────────

/// Collect backup data by constructing the real client and running the doctor.
///
/// All work runs on the blocking thread pool (`BackupClient::system` resolves
/// XDG dirs, `doctor` shells out to `which`, and the schedule/timer managers
/// will eventually shell out to `systemctl`). On ANY error — construction
/// failure, doctor error — returns [`empty_bundle`] with `available = false`.
///
/// Returns `(bundle, used_cache)` where `used_cache` records whether the
/// findings were actually taken from the cache on a successful collection.
#[expect(
    clippy::too_many_lines,
    reason = "real-data collection is inherently linear"
)]
async fn collect_real_backup(
    use_cache: bool,
    cached_findings: Option<Vec<FindingEntry>>,
) -> (BackupDataBundle, bool) {
    // Build the BackupClient facade on the blocking pool. system() resolves
    // XDG dirs (no shell-out), so construction succeeds even on macOS where
    // no backup binary is installed.
    let client =
        match tokio::task::spawn_blocking(toride_backup::client::BackupClient::system).await {
            Ok(Ok(client)) => client,
            Ok(Err(e)) => {
                tracing::warn!("backup backend construction failed: {e}");
                return (
                    empty_bundle_with_reason(format!("backup backend construction failed: {e}")),
                    false,
                );
            }
            Err(e) => {
                tracing::warn!("backup construction task panicked: {e}");
                return (
                    empty_bundle_with_reason(format!("backup backend construction panicked: {e}")),
                    false,
                );
            }
        };

    // Run ALL blocking probes in a single spawn_blocking that owns `client`.
    // This keeps every shell-out off the tokio worker and sidesteps the
    // 'static-borrow problem (the doctor + schedule + timer probes all borrow
    // `&client`). Results are returned as plain owned data so they cross the
    // thread boundary cleanly. Doctor findings are taken from the cache when
    // fresh (`use_cache`), otherwise re-run here.
    let result = tokio::task::spawn_blocking(move || {
        // ── Doctor (unless cached) ─────────────────────────────────────────
        let findings: Vec<FindingEntry> = if use_cache {
            cached_findings.unwrap_or_default()
        } else {
            match client.doctor(&toride_backup::doctor::DoctorScope::All) {
                Ok(report) => toride_backup_convert::convert_findings(report.findings),
                Err(e) => {
                    tracing::warn!("backup doctor: {e}");
                    Vec::new()
                }
            }
        };

        // ── Binary availability (derived from findings, no extra shell-out) ──
        let restic_available = toride_backup_convert::derive_binary_availability(
            &findings,
            toride_backup_convert::BackupBinary::Restic,
        );
        let borg_available = toride_backup_convert::derive_binary_availability(
            &findings,
            toride_backup_convert::BackupBinary::Borg,
        );

        // ── Dry-run flag ──────────────────────────────────────────────────
        let dry_run = client.is_dry_run();

        // ── Resolved paths ────────────────────────────────────────────────
        let paths = client.paths();
        let config_dir = paths
            .config_dir
            .to_str()
            .map(std::string::ToString::to_string);
        let data_dir = paths
            .data_dir
            .to_str()
            .map(std::string::ToString::to_string);
        let schedule_dir = paths
            .schedule_dir
            .to_str()
            .map(std::string::ToString::to_string);

        // ── Schedule / timer status (best-effort) ─────────────────────────
        // The backend currently stubs these to Ok(false); they are plumbed
        // here so the UI lights up automatically once the systemd plumbing
        // lands. A failure degrades that field to None (unknown) rather than
        // failing the whole collection.
        //
        // `schedule_note` is captured from the SAME ScheduleManager instance so
        // the UI can surface WHY a negative reading occurred (e.g. "systemd
        // not detected" on macOS / non-systemd hosts), distinguishing "no
        // schedule configured" from "systemd absent". Empty note → None.
        let schedule_mgr = toride_backup::schedule::ScheduleManager::new();
        let schedule_installed = match schedule_mgr.is_installed(DEFAULT_JOB_NAME) {
            Ok(b) => Some(b),
            Err(e) => {
                tracing::debug!("backup schedule is_installed: {e}");
                None
            }
        };
        let schedule_note = {
            let note = schedule_mgr.schedule_note();
            if note.is_empty() { None } else { Some(note) }
        };
        let timer_active = match toride_backup::service::BackupServiceManager::new()
            .is_timer_active(DEFAULT_JOB_NAME)
        {
            Ok(b) => Some(b),
            Err(e) => {
                tracing::debug!("backup timer is_timer_active: {e}");
                None
            }
        };

        // ── Availability heuristic ────────────────────────────────────────
        // The section is "available" if the client constructed AND the doctor
        // produced any findings (even on a host missing both binaries, the
        // doctor emits `binary.none-available` as a Critical finding). An empty
        // findings vec with no binaries is still available — the panel simply
        // shows "no findings" — because the backend is reachable. Only a panic
        // (handled above) or a construction failure flips available to false.
        let available = true;

        BackupDataBundle {
            available,
            dry_run,
            config_dir,
            data_dir,
            schedule_dir,
            restic_available,
            borg_available,
            schedule_installed,
            timer_active,
            schedule_note,
            findings,
            unavailable_reason: None,
        }
    })
    .await;

    match result {
        Ok(bundle) => (bundle, use_cache),
        Err(e) => {
            tracing::warn!("backup collection task panicked: {e}");
            (
                empty_bundle_with_reason(format!("backup data collection panicked: {e}")),
                false,
            )
        }
    }
}

/// Empty bundle used when backup could not be constructed at all.
///
/// `available = false` signals the UI to render the degraded panel.
fn empty_bundle() -> BackupDataBundle {
    BackupDataBundle {
        available: false,
        dry_run: false,
        config_dir: None,
        data_dir: None,
        schedule_dir: None,
        restic_available: None,
        borg_available: None,
        schedule_installed: None,
        timer_active: None,
        schedule_note: None,
        findings: Vec::new(),
        unavailable_reason: None,
    }
}

/// Empty bundle carrying the reason collection failed. Used when a
/// `spawn_blocking` task panicked (`JoinError`) — the reason string is rendered
/// by the UI's degraded panel so the operator sees what actually went wrong.
fn empty_bundle_with_reason(reason: String) -> BackupDataBundle {
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
        let collector = BackupCollector::new();
        assert!(!collector.is_pending());
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(
            BackupCollector::new().is_pending(),
            BackupCollector::default().is_pending()
        );
    }

    #[tokio::test]
    async fn start_makes_pending() {
        let mut collector = BackupCollector::new();
        assert!(!collector.is_pending());
        collector.start();
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn start_is_idempotent() {
        let mut collector = BackupCollector::new();
        collector.start();
        assert!(collector.is_pending());
        collector.start(); // no-op
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn poll_returns_none_when_not_started() {
        let mut collector = BackupCollector::new();
        assert!(collector.poll().await.is_none());
    }

    #[tokio::test]
    async fn poll_clears_pending() {
        let mut collector = BackupCollector::new();
        collector.start();
        // Let the spawned task complete.
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let _ = collector.poll().await;
        assert!(!collector.is_pending(), "poll should clear pending state");
    }

    #[tokio::test]
    async fn poll_returns_bundle_after_collection() {
        // On any host (including macOS without restic/borg) the collector must
        // return Some(bundle) after start() + enough time. The bundle's
        // `available` flag reflects whether the backend was reachable.
        let mut collector = BackupCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let bundle = collector.poll().await;
        assert!(bundle.is_some(), "poll should return Some after completion");
    }

    #[test]
    fn empty_bundle_is_unavailable() {
        let b = empty_bundle();
        assert!(!b.available);
        assert!(b.findings.is_empty());
        assert!(b.restic_available.is_none());
        assert!(b.borg_available.is_none());
        assert!(b.config_dir.is_none());
        assert!(b.schedule_installed.is_none());
        assert!(b.timer_active.is_none());
        assert!(
            b.unavailable_reason.is_none(),
            "empty_bundle carries no reason; panics use empty_bundle_with_reason"
        );
    }

    #[test]
    fn empty_bundle_with_reason_sets_reason() {
        let b = empty_bundle_with_reason("boom".into());
        assert!(!b.available);
        assert_eq!(b.unavailable_reason.as_deref(), Some("boom"));
    }

    #[tokio::test]
    async fn findings_cache_is_populated_after_poll() {
        let mut collector = BackupCollector::new();
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
        let mut collector = BackupCollector::new();
        collector.cached_findings = Some(Vec::new());
        collector.findings_fresh_at = Some(std::time::Instant::now());
        collector.invalidate_findings_cache();
        assert!(collector.cached_findings.is_none());
        assert!(collector.findings_fresh_at.is_none());
    }

    // ── Cache-poisoning edge case (finding 1) ────────────────────────────────
    //
    // A panicked collection returns an empty bundle with `available == false`.
    // poll() must NOT write that empty Vec into cached_findings (nor advance
    // findings_fresh_at), otherwise the degraded panel is pinned for the full
    // 60s TTL even once the underlying cause clears. We drive `rx` directly so
    // the test does not depend on a real panic.

    #[tokio::test]
    async fn poll_does_not_poison_cache_on_unavailable_bundle() {
        // Seed the collector with a prior good cache to prove it is dropped on
        // a panic rather than preserved (or replaced by the empty panicked
        // bundle's findings).
        let mut collector = BackupCollector::new();
        collector.cached_findings = Some(vec![FindingEntry {
            id: "binary.restic.found".into(),
            severity: "ok".into(),
            title: "restic found".into(),
            detail: String::new(),
            fix: None,
        }]);
        collector.findings_fresh_at = Some(std::time::Instant::now());

        let (tx, rx) = oneshot::channel();
        tx.send((empty_bundle_with_reason("panic".into()), false))
            .unwrap();
        collector.rx = Some(rx);
        let bundle = collector.poll().await;
        assert!(bundle.is_some(), "poll still returns the panicked bundle");
        assert!(
            bundle.unwrap().unavailable_reason.is_some(),
            "bundle carries the panic reason"
        );
        assert!(
            collector.cached_findings.is_none(),
            "cache must NOT be poisoned with the empty panicked bundle"
        );
        assert!(
            collector.findings_fresh_at.is_none(),
            "freshness must NOT advance on a panicked bundle"
        );
    }

    #[tokio::test]
    async fn poll_populates_cache_on_available_bundle() {
        // Counter-test: a healthy (available) bundle DOES populate the cache
        // and advance freshness, so the TTL re-arms normally on success.
        let mut collector = BackupCollector::new();
        let (tx, rx) = oneshot::channel();
        let bundle = BackupDataBundle {
            available: true,
            dry_run: false,
            config_dir: None,
            data_dir: None,
            schedule_dir: None,
            restic_available: Some(true),
            borg_available: None,
            schedule_installed: None,
            timer_active: None,
            schedule_note: None,
            findings: vec![FindingEntry {
                id: "binary.restic.found".into(),
                severity: "ok".into(),
                title: "restic found".into(),
                detail: String::new(),
                fix: None,
            }],
            unavailable_reason: None,
        };
        tx.send((bundle, false)).unwrap();
        collector.rx = Some(rx);
        let _ = collector.poll().await;
        assert!(collector.cached_findings.is_some());
        assert!(collector.findings_fresh_at.is_some());
    }
}

// ── Cadence oracles (round 0) ───────────────────────────────────────────────

/// Round-0 cadence oracles for the 60s findings cache.
///
/// These pin the CURRENT cache behavior with sentinel findings whose id the
/// real backup doctor can never emit (real ids are `binary.*` shaped):
/// "findings came back verbatim" proves the doctor was not re-run, and
/// "freshness timestamp untouched" proves the TTL is not re-armed on a cache
/// hit.
///
/// The lifecycle goes through the REAL `start()` / spawned collection.
/// `BackupClient::system` resolves XDG dirs without a shell-out, so
/// construction always succeeds and the success-path bundle is always
/// `available == true` — the strong arm of each oracle is deterministic on
/// any host (including ones without restic/borg, where the re-derived
/// doctor simply emits the missing-binary findings).
///
/// No spawn-counting seam is added at this layer: `collect_real_backup`
/// hardcodes `BackupClient::system`, and threading an injectable client
/// through `start()` would change production signatures — the sentinel
/// already answers "was the doctor re-run?".
#[cfg(test)]
mod cadence_oracle {
    use super::*;

    /// Sentinel id no real doctor finding can carry.
    const SENTINEL_ID: &str = "oracle-sentinel.backup.findings-cache";

    /// One sentinel finding — enough to distinguish cache passthrough from
    /// any real derivation.
    fn sentinel_findings() -> Vec<FindingEntry> {
        vec![FindingEntry {
            id: SENTINEL_ID.to_string(),
            severity: "ok".to_string(),
            title: "cadence-oracle sentinel".to_string(),
            detail: String::new(),
            fix: None,
        }]
    }

    /// Advances this thread's TTL test clock past the TTL, resetting it on
    /// drop so a failing assertion cannot leak a cranked clock into a later
    /// test scheduled on the same reused cargo-test thread.
    struct TtlOffsetGuard;

    impl TtlOffsetGuard {
        /// Set the thread-local offset to `FINDINGS_TTL` + 10s.
        fn past_ttl() -> Self {
            TTL_TEST_OFFSET_MS.with(|o| {
                o.set(
                    u64::try_from(FINDINGS_TTL.as_millis())
                        .expect("a 60s TTL in milliseconds always fits in u64")
                        + 10_000,
                );
            });
            Self
        }
    }

    impl Drop for TtlOffsetGuard {
        fn drop(&mut self) {
            TTL_TEST_OFFSET_MS.with(|o| o.set(0));
        }
    }

    /// ORACLE (current behavior): a fresh cache serves its cached findings
    /// verbatim on the next collection — the doctor is NOT re-run — and the
    /// freshness timestamp is NOT re-armed by the cache-hit poll.
    #[tokio::test]
    async fn cache_hit_returns_cached_findings_without_rederiving() {
        let mut collector = BackupCollector::new();
        collector.cached_findings = Some(sentinel_findings());
        let primed = std::time::Instant::now();
        collector.findings_fresh_at = Some(primed);

        collector.start();
        let bundle = collector.poll().await.expect("collection completes");

        assert!(
            bundle.available,
            "success-path backup collection is always available"
        );
        assert_eq!(
            bundle.findings.len(),
            1,
            "a cache hit must serve the cached findings verbatim"
        );
        assert_eq!(
            bundle.findings[0].id, SENTINEL_ID,
            "the sentinel id can only come from the cache, never from a real doctor run"
        );
        assert_eq!(
            collector.findings_fresh_at,
            Some(primed),
            "a cache-hit poll must not advance (re-arm) the freshness timestamp"
        );
    }

    /// ORACLE (current behavior): once the TTL has elapsed the cache is
    /// bypassed — the sentinel is NOT served — and the freshness timestamp
    /// advances past its primed value after the real re-derivation.
    #[tokio::test]
    async fn ttl_expiry_bypasses_cache_and_rederives() {
        let mut collector = BackupCollector::new();
        collector.cached_findings = Some(sentinel_findings());
        let primed = std::time::Instant::now();
        collector.findings_fresh_at = Some(primed);

        let _ttl = TtlOffsetGuard::past_ttl();
        collector.start();
        let bundle = collector.poll().await.expect("collection completes");

        assert!(
            bundle.findings.iter().all(|f| f.id != SENTINEL_ID),
            "an expired cache must not serve the sentinel"
        );
        // The success path is always `available`, and poll() advances the
        // clock for every available !used_cache result, so the
        // re-derivation must have re-armed it.
        assert!(
            collector.findings_fresh_at.is_some_and(|t| t > primed),
            "an expired cache must be re-derived and the freshness clock advanced"
        );
    }
}
