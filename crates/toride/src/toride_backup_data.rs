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
//! schedules, integrity, encryption, retention, and free space. The ENTIRE
//! collection — doctor findings AND the schedule/timer probe cluster (the
//! `systemctl cat` / `is-active` / `list-timers` fan-out, ~38-42 spawns per
//! tick before the cache) — is cached for 60s between collections, mirroring
//! the proxy collector's whole-report cache. Freshness caveat (deliberate
//! cadence decision): a newly installed/removed backup timer surfaces up to
//! 60s late.
//!
//! ## macOS / construction
//!
//! [`toride_backup::BackupClient::system`] resolves XDG directories; it
//! succeeds even when no backup binary is present (the doctor then surfaces
//! the missing binary as a `Critical` finding rather than the whole collector
//! erroring out). `ScheduleManager::timer_status` probes the real systemd
//! timer landscape in one pass (installed + active + note from a single
//! detect/probe/enumeration) and honestly reports `false` with a
//! `"systemd not detected"` note on hosts without systemd.
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
    /// (real probe via `ScheduleManager::timer_status`).
    pub schedule_installed: Option<bool>,
    /// Whether the systemd timer for the default `toride-backup` job is active
    /// (real probe via `ScheduleManager::timer_status`).
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
/// Mirrors the proxy collector's whole-report cache: a oneshot channel for
/// the in-flight result, plus a 60s TTL cache over the ENTIRE bundle (doctor
/// findings AND the schedule/timer probe cluster) so the systemctl fan-out
/// does not repeat on every 2s refresh tick.
pub struct BackupCollector {
    /// Carries the bundle AND whether the cached bundle was reused for this
    /// poll. See [`Fail2banCollector`](crate::fail2ban_data::Fail2banCollector)
    /// for why the freshness timestamp must only advance when the collection
    /// was actually re-run.
    rx: Option<oneshot::Receiver<(BackupDataBundle, bool)>>,
    /// Cached bundle (doctor findings + schedule/timer probes) from the last
    /// collection.
    cached_bundle: Option<BackupDataBundle>,
    /// When the bundle cache was last refreshed.
    bundle_fresh_at: Option<std::time::Instant>,
}

/// How long to keep the cached bundle before re-running the doctor suite and
/// the schedule/timer probes.
///
/// Deliberate freshness semantics: a newly installed/removed backup timer
/// surfaces up to this TTL late (see the module docs).
const BUNDLE_TTL: std::time::Duration = std::time::Duration::from_mins(1);

/// Whether the bundle-cache TTL has already elapsed for a cache that was
/// last refreshed at `fresh_at`.
///
/// Round-0 instrumentation seam, ZERO behavior change: outside `cfg(test)`
/// this is exactly the negation of the `t.elapsed() < BUNDLE_TTL` check
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
    elapsed >= BUNDLE_TTL
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
            cached_bundle: None,
            bundle_fresh_at: None,
        }
    }

    /// Whether a collection is currently in-flight.
    pub fn is_pending(&self) -> bool {
        self.rx.is_some()
    }

    /// Start a new background collection.
    ///
    /// If a collection is already in-flight, this is a no-op. The 60s
    /// whole-bundle cache is consulted: when fresh, the spawned task serves
    /// the cached bundle verbatim — the doctor AND the schedule/timer probes
    /// do not run at all.
    pub fn start(&mut self) {
        if self.rx.is_some() {
            return;
        }
        let (tx, rx) = oneshot::channel();
        let use_cache =
            self.cached_bundle.is_some() && self.bundle_fresh_at.is_some_and(|t| !ttl_expired(t));
        let cached_bundle = self.cached_bundle.clone();
        self.rx = Some(rx);
        tokio::spawn(async move {
            let (bundle, reused_cache) = collect_real_backup(use_cache, cached_bundle).await;
            let _ = tx.send((bundle, reused_cache));
        });
    }

    /// Poll for a completed collection result.
    ///
    /// Returns `Some(bundle)` if the collection completed, `None` if still
    /// pending or if the collection failed. On success the whole bundle is
    /// cached, but the freshness timestamp is only advanced when the
    /// collection was actually re-run (not on a cache-hit poll) — otherwise
    /// the 60s TTL would be re-armed forever with the same cached data on
    /// every 2s refresh.
    pub async fn poll(&mut self) -> Option<BackupDataBundle> {
        match &mut self.rx {
            Some(rx) => {
                let result = rx.await.ok();
                if let Some((ref bundle, used_cache)) = result {
                    // On a collection panic the bundle is empty and marked
                    // `available == false`. We must NOT poison the bundle
                    // cache with it (and must NOT advance the freshness
                    // timestamp): doing so would keep the section in its
                    // degraded state for the full 60s TTL even if the
                    // underlying cause cleared on the next tick. Instead we
                    // invalidate so the very next refresh re-runs everything.
                    if bundle.available {
                        // Only write the cache (and advance the clock) when
                        // the collection actually re-ran. On a cache-hit
                        // poll the bundle IS the data we already cached —
                        // identical by construction — so re-storing it would
                        // be a wasted deep clone per tick, and resetting the
                        // TTL would let the cache live forever.
                        if !used_cache {
                            self.cached_bundle = Some(bundle.clone());
                            self.bundle_fresh_at = Some(std::time::Instant::now());
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

    /// Invalidate the bundle cache so the next collection re-runs the probes.
    pub fn invalidate_findings_cache(&mut self) {
        self.cached_bundle = None;
        self.bundle_fresh_at = None;
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
/// When `use_cache` is set and a cached bundle is present, the cached bundle
/// is served verbatim and NOTHING runs — the doctor AND the schedule/timer
/// probe cluster are skipped entirely.
///
/// Otherwise all work runs on the blocking thread pool (`BackupClient::system`
/// resolves XDG dirs, `doctor` shells out to `which`, and the schedule/timer
/// snapshot shells out to `systemctl`). On ANY error — construction failure,
/// doctor error — returns [`empty_bundle`] with `available = false`.
///
/// Returns `(bundle, used_cache)` where `used_cache` records whether the
/// bundle was served verbatim from the cache.
async fn collect_real_backup(
    use_cache: bool,
    cached_bundle: Option<BackupDataBundle>,
) -> (BackupDataBundle, bool) {
    // Cache hit: serve the whole bundle verbatim. Neither the doctor nor any
    // schedule/timer probe spawns a subprocess.
    if use_cache && let Some(bundle) = cached_bundle {
        return (bundle, true);
    }

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
    // thread boundary cleanly.
    let result = tokio::task::spawn_blocking(move || {
        // ── Doctor ──────────────────────────────────────────────────────────
        let findings: Vec<FindingEntry> =
            match client.doctor(&toride_backup::doctor::DoctorScope::All) {
                Ok(report) => toride_backup_convert::convert_findings(report.findings),
                Err(e) => {
                    tracing::warn!("backup doctor: {e}");
                    Vec::new()
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

        // ── Schedule / timer status (best-effort, ONE pass) ────────────────
        // `ScheduleManager::timer_status` answers the installed question, the
        // timer-active question, AND the explanatory note from a single
        // detect + single per-unit probe + (only when needed) a single
        // enumeration fan-out — replacing the previous pair of independent
        // manager calls that each paid their own detect/probe/full fan-out
        // (~38-42 systemctl spawns per 2s tick before the whole-bundle cache).
        // The note lets the UI surface WHY a negative reading occurred (e.g.
        // "systemd not detected" on non-systemd hosts). Empty note → None.
        let snapshot =
            toride_backup::schedule::ScheduleManager::new().timer_status(DEFAULT_JOB_NAME);
        let schedule_installed = Some(snapshot.installed);
        let timer_active = Some(snapshot.timer_active);
        let schedule_note = {
            let note = snapshot.note;
            if note.is_empty() { None } else { Some(note) }
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
        // Reaching this point means the probes DID run (a cache hit returned
        // above), so the truthful provenance is "not from cache".
        Ok(bundle) => (bundle, false),
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
        // The success path is always `available`, so after a successful poll
        // the whole-bundle cache is populated (even with an empty findings Vec
        // on a host where the doctor produced no findings).
        assert!(collector.cached_bundle.is_some());
        assert!(collector.bundle_fresh_at.is_some());
    }

    #[test]
    fn invalidate_findings_cache_clears_it() {
        let mut collector = BackupCollector::new();
        collector.cached_bundle = Some(empty_bundle());
        collector.bundle_fresh_at = Some(std::time::Instant::now());
        collector.invalidate_findings_cache();
        assert!(collector.cached_bundle.is_none());
        assert!(collector.bundle_fresh_at.is_none());
    }

    // ── Cache-poisoning edge case (finding 1) ────────────────────────────────
    //
    // A panicked collection returns an empty bundle with `available == false`.
    // poll() must NOT write that empty bundle into cached_bundle (nor advance
    // bundle_fresh_at), otherwise the degraded panel is pinned for the full
    // 60s TTL even once the underlying cause clears. We drive `rx` directly so
    // the test does not depend on a real panic.

    #[tokio::test]
    async fn poll_does_not_poison_cache_on_unavailable_bundle() {
        // Seed the collector with a prior good cache to prove it is dropped on
        // a panic rather than preserved (or replaced by the empty panicked
        // bundle).
        let mut collector = BackupCollector::new();
        collector.cached_bundle = Some(available_bundle_with_finding());
        collector.bundle_fresh_at = Some(std::time::Instant::now());

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
            collector.cached_bundle.is_none(),
            "cache must NOT be poisoned with the empty panicked bundle"
        );
        assert!(
            collector.bundle_fresh_at.is_none(),
            "freshness must NOT advance on a panicked bundle"
        );
    }

    /// An available bundle with one restic finding — the prior-good cache
    /// shape for the poisoning test.
    fn available_bundle_with_finding() -> BackupDataBundle {
        BackupDataBundle {
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
        }
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
        assert!(collector.cached_bundle.is_some());
        assert!(collector.bundle_fresh_at.is_some());
    }
}

// ── Cadence oracles (round 0, extended round 1) ──────────────────────────────

/// Cadence oracles for the 60s whole-bundle cache.
///
/// Round 1 (F04) extended these from a findings-only cache to the whole
/// bundle: sentinel data now covers the schedule/timer snapshot fields as
/// well as the findings. The sentinel finding id (`binary.*` is the real
/// shape) and the sentinel schedule note (real notes are `""` or
/// `"systemd not detected"`) are values no real probe can emit, so "the
/// bundle came back verbatim" proves the doctor AND the schedule/timer
/// systemctl fan-out did not spawn a single subprocess.
///
/// The lifecycle goes through the REAL `start()` / spawned collection.
/// `BackupClient::system` resolves XDG dirs without a shell-out, so
/// construction always succeeds and the success-path bundle is always
/// `available == true` — the strong arm of each oracle is deterministic on
/// any host (including ones without restic/borg, where the re-derived
/// doctor simply emits the missing-binary findings, and non-systemd hosts,
/// where the re-derived note is `"systemd not detected"`).
///
/// No spawn-counting seam is added at this layer: `collect_real_backup`
/// hardcodes `BackupClient::system`, and threading an injectable client
/// through `start()` would change production signatures — the sentinel
/// bundle already answers "did anything re-run?". (A spawn-count seam for
/// the backend's own systemctl calls exists in toride-backup's systemd
/// module tests.)
#[cfg(test)]
mod cadence_oracle {
    use super::*;

    /// Sentinel id no real doctor finding can carry.
    const SENTINEL_ID: &str = "oracle-sentinel.backup.findings-cache";

    /// Sentinel schedule note no real `systemd::detect` can emit (real notes
    /// are empty or exactly "systemd not detected").
    const SENTINEL_NOTE: &str = "oracle-sentinel backup schedule-note";

    /// A sentinel bundle with `available == true` so `poll()` caches it.
    fn sentinel_bundle() -> BackupDataBundle {
        BackupDataBundle {
            available: true,
            dry_run: false,
            config_dir: None,
            data_dir: None,
            schedule_dir: None,
            restic_available: Some(true),
            borg_available: None,
            schedule_installed: Some(true),
            timer_active: Some(true),
            schedule_note: Some(SENTINEL_NOTE.to_string()),
            findings: vec![FindingEntry {
                id: SENTINEL_ID.to_string(),
                severity: "ok".to_string(),
                title: "cadence-oracle sentinel".to_string(),
                detail: String::new(),
                fix: None,
            }],
            unavailable_reason: None,
        }
    }

    /// Advances this thread's TTL test clock past the TTL, resetting it on
    /// drop so a failing assertion cannot leak a cranked clock into a later
    /// test scheduled on the same reused cargo-test thread.
    struct TtlOffsetGuard;

    impl TtlOffsetGuard {
        /// Set the thread-local offset to `BUNDLE_TTL` + 10s.
        fn past_ttl() -> Self {
            TTL_TEST_OFFSET_MS.with(|o| {
                o.set(
                    u64::try_from(BUNDLE_TTL.as_millis())
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

    /// ORACLE: a fresh cache serves the WHOLE cached bundle verbatim on the
    /// next collection — the doctor AND the schedule/timer probes are skipped
    /// (zero subprocess spawns) — and the freshness timestamp is NOT re-armed
    /// by the cache-hit poll.
    #[tokio::test]
    async fn cache_hit_returns_cached_bundle_without_reprobing() {
        let mut collector = BackupCollector::new();
        collector.cached_bundle = Some(sentinel_bundle());
        let primed = std::time::Instant::now();
        collector.bundle_fresh_at = Some(primed);

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
            bundle.schedule_note.as_deref(),
            Some(SENTINEL_NOTE),
            "the sentinel note can only come from the cache, never from a real detect probe"
        );
        assert_eq!(bundle.schedule_installed, Some(true));
        assert_eq!(bundle.timer_active, Some(true));
        assert_eq!(
            collector.bundle_fresh_at,
            Some(primed),
            "a cache-hit poll must not advance (re-arm) the freshness timestamp"
        );
    }

    /// ORACLE: once the TTL has elapsed the cache is bypassed — no sentinel
    /// survives in the findings OR the schedule/timer fields — and the
    /// freshness timestamp advances past its primed value after the real
    /// re-derivation.
    #[tokio::test]
    async fn ttl_expiry_bypasses_cache_and_rederives() {
        let mut collector = BackupCollector::new();
        collector.cached_bundle = Some(sentinel_bundle());
        let primed = std::time::Instant::now();
        collector.bundle_fresh_at = Some(primed);

        let _ttl = TtlOffsetGuard::past_ttl();
        collector.start();
        let bundle = collector.poll().await.expect("collection completes");

        assert!(
            bundle.findings.iter().all(|f| f.id != SENTINEL_ID),
            "an expired cache must not serve the sentinel finding"
        );
        assert_ne!(
            bundle.schedule_note.as_deref(),
            Some(SENTINEL_NOTE),
            "an expired cache must not serve the sentinel note"
        );
        // The success path is always `available`, and poll() advances the
        // clock for every available !used_cache result, so the
        // re-derivation must have re-armed it.
        assert!(
            collector.bundle_fresh_at.is_some_and(|t| t > primed),
            "an expired cache must be re-derived and the freshness clock advanced"
        );
    }
}
