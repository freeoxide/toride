//! Async updates data collection (LIVE READ-ONLY).
//!
//! [`UpdatesCollector`] manages background collection of automatic-update
//! subsystem data via a tokio oneshot channel, following the same pattern as
//! [`StatusCollector`](crate::status_collector::StatusCollector),
//! [`SshDataCollector`](crate::ssh_data::SshDataCollector), and the
//! [`Fail2banCollector`](crate::fail2ban_data::Fail2banCollector) template.
//!
//! This is a read-only integration: there are no write operations, no
//! optimistic updates, no cooldown gate, and no loading spinner. Every call to
//! the backend is a pure read.
//!
//! Doctor findings are expensive (they probe `$PATH`, stat config dirs, and —
//! once the TODOs in `doctor.rs` land — query systemd) and change slowly —
//! and so does the rest of the probe cluster: `check_updates` shells out to
//! `apt-check` (Python/apt, often the largest per-tick item) or
//! `dnf check-update --security` (network!), and `status`/`is_active` shell
//! out to `systemctl`. The ENTIRE collection is therefore cached for 60s,
//! mirroring the proxy collector's whole-report cache: a cache hit performs
//! zero subprocess spawns. Freshness caveat (deliberate cadence decision,
//! stated where the TTL lives): pending-update counts and service status
//! surface up to 60s late — the dnf path can take minutes on a slow network,
//! so a long TTL (rather than new network behavior) is the right trade.
//!
//! ## macOS / construction
//!
//! [`toride_updates::client::UpdatesClient::new`] calls
//! [`toride_updates::detect::detect_package_manager`], which returns
//! [`PackageManager::Unknown`](toride_updates::detect::PackageManager) on hosts
//! with neither `apt-get` nor `dnf` (notably macOS). `UpdatesClient::new`
//! then returns `Err(Error::PackageDetection)`. The collector surfaces this as
//! `available = false` with the error's display string as the reason, so the
//! degraded panel explains exactly why updates data is unavailable.
//!
//! ## Network
//!
//! [`UpdatesClient::check_updates`] hits the network (`apt-check` /
//! `dnf check-update`). The `DuctRunner` already enforces a per-command timeout
//! (60s via the `duct` `timeout` feature), and the whole probe closure is
//! further wrapped in a [`tokio::time::timeout`] so a wedged network cannot
//! hold the collector's task slot indefinitely.
//!
//! ## Blocking
//!
//! The `DuctRunner` shells out synchronously. All backend work is wrapped in
//! [`tokio::task::spawn_blocking`] so the tokio worker is never stalled.

use tokio::sync::oneshot;

use crate::toride_updates_convert;
use crate::ui::screens::toride_updates::FindingEntry;

/// Aggregated updates data for the read-only section.
#[derive(Clone, Debug)]
pub struct UpdatesDataBundle {
    /// Whether the updates backend was reachable at all. `false` when
    /// construction failed entirely (e.g. `PackageDetection` on macOS) or the
    /// collection task panicked — the UI renders a degraded "unavailable"
    /// panel.
    pub available: bool,
    /// Detected package manager label (e.g. "apt", "dnf"). Empty on a
    /// construction failure.
    pub package_manager: String,
    /// Whether automatic updates are enabled (from `UpdateStatus`).
    pub auto_updates_enabled: bool,
    /// Whether the update service is active (from `UpdateStatus`).
    pub service_active: bool,
    /// Number of pending security updates.
    pub pending_security: usize,
    /// Total number of pending updates.
    pub pending_total: usize,
    /// Timestamp of the last successful update run (ISO 8601), if available.
    pub last_run: Option<String>,
    /// Detected schedule label, if any (e.g. "daily", "weekly").
    pub schedule: Option<String>,
    /// Whether the systemd timer/service unit is active, if known. `None` when
    /// the probe failed or the package manager is unknown.
    pub timer_active: Option<bool>,
    /// Doctor findings (cached for 60s between collections).
    pub findings: Vec<FindingEntry>,
    /// Human-readable reason the backend was unreachable, populated ONLY when
    /// `available == false` because construction failed or the collection task
    /// panicked (`JoinError`). `None` otherwise — notably also `None` for a
    /// freshly-constructed empty bundle before any collection has run.
    pub unavailable_reason: Option<String>,
}

// ── Collector ───────────────────────────────────────────────────────────────

/// Manages periodic async collection of updates data.
///
/// Mirrors the proxy collector's whole-report cache: a oneshot channel for
/// the in-flight result, plus a 60s TTL cache over the ENTIRE bundle (doctor
/// findings, pending-update counts, service status) so the `apt-check` /
/// `dnf check-update` / `systemctl` shell-outs do not repeat on every 2s
/// refresh tick.
pub struct UpdatesCollector {
    /// Carries the bundle AND whether the cached bundle was reused for this
    /// poll. The freshness timestamp must only be advanced when the
    /// collection was actually re-run (`used_cache == false`); otherwise
    /// every cache-hit poll would reset the TTL clock with the SAME
    /// (already-cached) bundle and the cache would never expire for the
    /// lifetime of the app.
    rx: Option<oneshot::Receiver<(UpdatesDataBundle, bool)>>,
    /// Cached bundle (doctor findings + counts + status) from the last
    /// collection.
    cached_bundle: Option<UpdatesDataBundle>,
    /// When the bundle cache was last refreshed.
    bundle_fresh_at: Option<std::time::Instant>,
}

/// How long to keep the cached bundle before re-running the doctor suite and
/// the update-count / service-status probes.
///
/// Deliberate freshness semantics (the product decision this TTL encodes):
/// pending-update counts and service status surface up to this TTL late. The
/// alternative — probing every 2s tick — re-ran `apt-check` (Python/apt) or
/// `dnf check-update --security` (network, minutes on a slow link) thirty
/// times a minute. No new network behavior is introduced either way.
const BUNDLE_TTL: std::time::Duration = std::time::Duration::from_secs(60);

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

/// Hard deadline for the entire probe closure. `check_updates` shells out to
/// `apt-check` / `dnf check-update`, which can take minutes on a slow network.
/// The `DuctRunner` already enforces a 60s per-command timeout; this wraps the
/// WHOLE probe so a wedged sequence of commands cannot hold the collector's
/// task slot for far longer than a refresh interval.
const PROBE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

impl UpdatesCollector {
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
    /// the cached bundle verbatim — the doctor, `apt-check`/`dnf
    /// check-update`, and the `systemctl` status probes do not run at all.
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
            // Race the probe against a deadline so a wedged network cannot hold
            // the task slot. On timeout we surface a degraded bundle carrying
            // the reason; the next eligible refresh re-tries cleanly. (A cache
            // hit returns before any probe, so the deadline never bites there.)
            let outcome: (UpdatesDataBundle, bool) = match tokio::time::timeout(
                PROBE_DEADLINE,
                collect_real_updates(use_cache, cached_bundle),
            )
            .await
            {
                Ok(tuple) => tuple,
                Err(_elapsed) => {
                    tracing::warn!("updates collection exceeded {:?} deadline", PROBE_DEADLINE);
                    let reason =
                        format!("updates data collection timed out after {PROBE_DEADLINE:?}");
                    (empty_bundle_with_reason(reason), false)
                }
            };
            let _ = tx.send(outcome);
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
    pub async fn poll(&mut self) -> Option<UpdatesDataBundle> {
        match &mut self.rx {
            Some(rx) => {
                let result = rx.await.ok();
                if let Some((ref bundle, used_cache)) = result {
                    // Only cache when the bundle is a real (available) result.
                    // A timed-out, construction-failed, or panicked bundle
                    // carries an empty bundle and `available == false`; writing
                    // it into the cache would make the next start() take the
                    // `use_cache` branch and skip re-probing for up to the TTL,
                    // leaving the panel degraded after recovery. Leave the
                    // existing cache intact on a degraded bundle so the next
                    // collection re-runs everything.
                    if bundle.available {
                        self.cached_bundle = Some(bundle.clone());
                        // Only advance the freshness clock when the collection
                        // was actually re-run (mirrors fail2ban / backup).
                        if !used_cache {
                            self.bundle_fresh_at = Some(std::time::Instant::now());
                        }
                    }
                }
                self.rx = None;
                result.map(|(bundle, _)| bundle)
            }
            None => None,
        }
    }

    /// Invalidate the bundle cache so the next collection re-runs the probes.
    #[allow(dead_code)]
    pub fn invalidate_findings_cache(&mut self) {
        self.cached_bundle = None;
        self.bundle_fresh_at = None;
    }
}

impl Default for UpdatesCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Real data collection ────────────────────────────────────────────────────

/// Collect updates data by shelling out to the real binaries.
///
/// When `use_cache` is set and a cached bundle is present, the cached bundle
/// is served verbatim and NOTHING runs — the doctor, `apt-check` /
/// `dnf check-update`, and the `systemctl` status probes are skipped
/// entirely.
///
/// Otherwise all work runs on the blocking thread pool. The `UpdatesClient`
/// is constructed inside `spawn_blocking` (`new()` probes `$PATH`); on hosts
/// with neither apt nor dnf it returns `Err(PackageDetection)` and we surface
/// a degraded bundle. On ANY error or panic returns [`empty_bundle`] /
/// [`empty_bundle_with_reason`] with `available = false`.
///
/// Returns `(bundle, used_cache)` where `used_cache` records whether the
/// bundle was served verbatim from the cache.
async fn collect_real_updates(
    use_cache: bool,
    cached_bundle: Option<UpdatesDataBundle>,
) -> (UpdatesDataBundle, bool) {
    // Cache hit: serve the whole bundle verbatim. Neither the doctor nor any
    // update-count / status probe spawns a subprocess.
    if use_cache && let Some(bundle) = cached_bundle {
        return (bundle, true);
    }

    // Build the UpdatesClient on the blocking pool. new() probes $PATH for
    // apt-get / dnf; on macOS it returns Err(PackageDetection).
    let client = match tokio::task::spawn_blocking(toride_updates::client::UpdatesClient::new).await
    {
        Ok(Ok(client)) => client,
        Ok(Err(e)) => {
            // Construction failed (e.g. PackageDetection on macOS).
            tracing::debug!("updates construction failed: {e}");
            return (
                empty_bundle_with_reason(format!("updates backend unavailable: {e}")),
                false,
            );
        }
        Err(e) => {
            tracing::warn!("updates construction task panicked: {e}");
            return (
                empty_bundle_with_reason(format!("updates backend construction panicked: {e}")),
                false,
            );
        }
    };

    // Run ALL blocking probes in a single spawn_blocking that owns `client`.
    // This keeps every shell-out / file read off the tokio worker (the
    // `DuctRunner` is synchronous) and sidesteps the 'static-borrow problem:
    // the doctor / backend / service constructors each take `&dyn Runner`, so
    // collecting everything in one owned closure that builds a single
    // DuctRunner is both simpler and cheaper than spawning one task per
    // probe. Results are returned as plain owned data so they cross the
    // thread boundary cleanly.
    let result = tokio::task::spawn_blocking(move || {
        // One DuctRunner shared by every &dyn Runner consumer below. Mirrors
        // the wireguard / harden idiom (a fresh DuctRunner built inside the
        // closure), except here the backend constructors TAKE the runner ref
        // rather than reading a global.
        let runner = toride_updates::DuctRunner;

        // ── Doctor ──────────────────────────────────────────────────────────
        let findings: Vec<FindingEntry> = {
            let doc = toride_updates::doctor::Doctor::new(&runner);
            match doc.run() {
                Ok(raw) => toride_updates_convert::convert_findings(raw),
                Err(e) => {
                    tracing::warn!("updates doctor: {e}");
                    Vec::new()
                }
            }
        };

        // ── Package manager label (memoized on the client) ─────────────────
        // The client detected the manager once at construction; reading the
        // label through it (instead of a fresh detect_package_manager())
        // avoids re-scanning `$PATH` on every collection.
        let pm = client.package_manager();
        let package_manager = toride_updates_convert::package_manager_str(pm).to_string();

        // ── Pending updates (hits the network: apt-check / dnf check-update) ──
        // The DuctRunner enforces a 60s per-command timeout; a failure here
        // leaves the counts at zero rather than failing the whole section.
        let (pending_security, pending_total) = match client.check_updates() {
            Ok((sec, total)) => (sec, total),
            Err(e) => {
                tracing::debug!("updates check_updates: {e}");
                (0, 0)
            }
        };

        // ── Status (auto-enabled / service-active / last-run) ──────────────
        // `status()` internally probes `systemctl is-active --quiet` for the
        // SAME unit the old separate `ServiceManager::is_active()` call
        // probed ("unattended-upgrades" on apt, "dnf-automatic.timer" on
        // dnf) — so the unit-active answer is single-sourced from here and
        // the duplicate spawn is gone. `timer_active` degrades to `None`
        // (unknown) only when `status()` itself failed, which previously
        // meant the separate probe answered alone.
        let timer_active;
        let status = match client.status() {
            Ok(s) => {
                timer_active = Some(s.service_active);
                s
            }
            Err(e) => {
                tracing::debug!("updates status: {e}");
                timer_active = None;
                toride_updates::report::UpdateStatus::empty()
            }
        };

        // ── Schedule ───────────────────────────────────────────────────────
        // The `schedule` backend feature (ScheduleManager::get_schedule) is NOT
        // in the default feature set compiled into the `toride` crate
        // (default = ["client","doctor"]); enabling it would require editing
        // Cargo.toml, which this integration must not. The UpdateStatus
        // auto_updates_enabled flag already reflects whether a periodic
        // schedule is wired, so we leave the explicit cadence label as `None`
        // (the UI renders "not configured") until the feature is enabled.
        let schedule: Option<String> = None;

        // ── Availability heuristic ────────────────────────────────────────
        // The section is "available" if the package manager was detected
        // (construction succeeded). A host with the manager present but the
        // update binary missing yields a Critical finding, which keeps
        // `available == true` so the operator SEES the finding rather than a
        // blank panel. A host where construction failed entirely never reaches
        // this code path; it returns the degraded bundle above.
        let available = pm != toride_updates::detect::PackageManager::Unknown;

        UpdatesDataBundle {
            available,
            package_manager,
            auto_updates_enabled: status.auto_updates_enabled,
            service_active: status.service_active,
            pending_security,
            pending_total,
            last_run: status.last_run,
            schedule,
            timer_active,
            findings,
            // Success path: no panic, no construction failure, so no reason.
            unavailable_reason: None,
        }
    })
    .await;

    match result {
        // Reaching this point means the probes DID run (a cache hit returned
        // above), so the truthful provenance is "not from cache".
        Ok(bundle) => (bundle, false),
        Err(e) => {
            tracing::warn!("updates collection task panicked: {e}");
            (
                empty_bundle_with_reason(format!("updates data collection panicked: {e}")),
                false,
            )
        }
    }
}

/// Empty bundle used when updates could not be constructed at all.
///
/// `available = false` signals the UI to render the degraded panel. No reason
/// is attached because none is known at this point; construction failures and
/// collection-time panics use [`empty_bundle_with_reason`] to surface the
/// actual error.
fn empty_bundle() -> UpdatesDataBundle {
    UpdatesDataBundle {
        available: false,
        package_manager: String::new(),
        auto_updates_enabled: false,
        service_active: false,
        pending_security: 0,
        pending_total: 0,
        last_run: None,
        schedule: None,
        timer_active: None,
        findings: Vec::new(),
        unavailable_reason: None,
    }
}

/// Empty bundle carrying the reason collection failed. Used when construction
/// failed (e.g. `PackageDetection` on macOS), the probe hit the deadline, or a
/// `spawn_blocking` task panicked (`JoinError`) — the reason string is rendered
/// by the UI's degraded panel so the operator sees what actually went wrong.
fn empty_bundle_with_reason(reason: String) -> UpdatesDataBundle {
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
        let collector = UpdatesCollector::new();
        assert!(!collector.is_pending());
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(
            UpdatesCollector::new().is_pending(),
            UpdatesCollector::default().is_pending()
        );
    }

    #[tokio::test]
    async fn start_makes_pending() {
        let mut collector = UpdatesCollector::new();
        assert!(!collector.is_pending());
        collector.start();
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn start_is_idempotent() {
        let mut collector = UpdatesCollector::new();
        collector.start();
        assert!(collector.is_pending());
        collector.start(); // no-op, does not replace the receiver
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn poll_returns_none_when_not_started() {
        let mut collector = UpdatesCollector::new();
        assert!(collector.poll().await.is_none());
    }

    #[tokio::test]
    async fn poll_clears_pending() {
        let mut collector = UpdatesCollector::new();
        collector.start();
        // Let the spawned task complete (it shells out, so give it time).
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let _ = collector.poll().await;
        assert!(!collector.is_pending(), "poll should clear pending state");
    }

    #[tokio::test]
    async fn poll_returns_bundle_after_collection() {
        // On any host (including macOS without apt-get/dnf) the collector must
        // return Some(bundle) after start() + enough time. The bundle's
        // `available` flag reflects whether a package manager was found.
        let mut collector = UpdatesCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let bundle = collector.poll().await;
        assert!(bundle.is_some(), "poll should return Some after completion");
    }

    #[test]
    fn empty_bundle_is_unavailable() {
        let b = empty_bundle();
        assert!(!b.available);
        assert!(b.package_manager.is_empty());
        assert_eq!(b.pending_security, 0);
        assert_eq!(b.pending_total, 0);
        assert!(b.findings.is_empty());
        assert!(b.last_run.is_none());
        assert!(b.schedule.is_none());
        assert!(b.timer_active.is_none());
        assert!(
            b.unavailable_reason.is_none(),
            "empty_bundle carries no reason; failures use empty_bundle_with_reason"
        );
    }

    #[test]
    fn empty_bundle_with_reason_sets_reason() {
        let b = empty_bundle_with_reason("package detection failed: no apt-get".into());
        assert!(!b.available);
        assert_eq!(
            b.unavailable_reason.as_deref(),
            Some("package detection failed: no apt-get")
        );
    }

    #[tokio::test]
    async fn findings_cache_is_populated_after_poll() {
        let mut collector = UpdatesCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let bundle = collector.poll().await;
        // After a successful poll the cache is populated ONLY when the backend
        // produced a real (available) bundle. On hosts where the backend is
        // unavailable (e.g. macOS PackageDetection) the cache must stay None so
        // the next collection re-runs the doctor instead of replaying empties.
        match bundle {
            Some(b) if b.available => {
                assert!(
                    collector.cached_bundle.is_some(),
                    "cache must be populated from an available bundle"
                );
                assert!(
                    collector.bundle_fresh_at.is_some(),
                    "freshness clock must advance on a real collection"
                );
            }
            _ => {
                assert!(
                    collector.cached_bundle.is_none(),
                    "cache must NOT be populated from a degraded (unavailable) bundle"
                );
            }
        }
    }

    #[tokio::test]
    async fn poll_does_not_overwrite_cache_with_empty_on_degraded_bundle() {
        // Regression for the PROBE_DEADLINE / JoinError path: a degraded bundle
        // (available == false, empty findings) must NOT replace the existing
        // cached bundle, otherwise the next start() would take the `use_cache`
        // branch and skip re-probing for up to the TTL — leaving the panel
        // showing "no findings" for ~90s after a transient network stall.
        //
        // We feed a degraded bundle straight through the oneshot channel (the
        // same channel `start()` uses) so `poll()` exercises its real cache
        // write path against a controlled bundle shape.
        let mut collector = UpdatesCollector::new();
        // Seed the cache as if a prior successful collection had run.
        let prior = available_bundle_with_finding();
        collector.cached_bundle = Some(prior.clone());
        collector.bundle_fresh_at = Some(std::time::Instant::now());

        let (tx, rx) = oneshot::channel();
        tx.send((
            empty_bundle_with_reason("timed out after 30s".into()),
            false,
        ))
        .unwrap();
        collector.rx = Some(rx);

        let bundle = collector.poll().await;
        assert!(bundle.is_some(), "poll must return the degraded bundle");
        assert!(
            !bundle.as_ref().unwrap().available,
            "degraded bundle must be unavailable"
        );
        assert!(
            bundle.as_ref().unwrap().findings.is_empty(),
            "degraded bundle must carry empty findings"
        );
        // The cache must be UNCHANGED — not overwritten with an empty bundle.
        let cached = collector
            .cached_bundle
            .as_ref()
            .expect("cached bundle must NOT have been cleared by a degraded bundle");
        assert_eq!(
            cached.findings.len(),
            prior.findings.len(),
            "degraded bundle must not overwrite the existing cached bundle"
        );
        assert_eq!(
            cached.findings[0].id, prior.findings[0].id,
            "degraded bundle must not overwrite the existing cached bundle"
        );
    }

    #[test]
    fn invalidate_findings_cache_clears_it() {
        let mut collector = UpdatesCollector::new();
        collector.cached_bundle = Some(empty_bundle());
        collector.bundle_fresh_at = Some(std::time::Instant::now());
        collector.invalidate_findings_cache();
        assert!(collector.cached_bundle.is_none());
        assert!(collector.bundle_fresh_at.is_none());
    }

    /// An available bundle with one finding — the prior-good cache shape for
    /// the degraded-bundle test.
    fn available_bundle_with_finding() -> UpdatesDataBundle {
        UpdatesDataBundle {
            available: true,
            package_manager: "apt".to_string(),
            auto_updates_enabled: false,
            service_active: false,
            pending_security: 0,
            pending_total: 0,
            last_run: None,
            schedule: None,
            timer_active: Some(false),
            findings: vec![FindingEntry {
                id: "binary.unattended-upgrades.found".into(),
                severity: "ok".into(),
                title: "unattended-upgrades binary available".into(),
                detail: String::new(),
                fix: None,
            }],
            unavailable_reason: None,
        }
    }
}

// ── Cadence oracles (round 0, extended round 1) ──────────────────────────────

/// Cadence oracles for the 60s whole-bundle cache.
///
/// Round 1 (F06) extended these from a findings-only cache to the whole
/// bundle: sentinel data now covers the update counts, the package-manager
/// label, and the timer flag as well as the findings. The sentinel values
/// (finding id, label, counts) are ones no real probe can emit, so "the
/// bundle came back verbatim" proves the doctor, `apt-check`/`dnf
/// check-update`, and the `systemctl` status probes did not spawn a single
/// subprocess.
///
/// The lifecycle goes through the REAL `start()` / spawned collection. On a
/// host with apt/dnf (the campaign host) the bundle is `available` and the
/// strong arm of each oracle runs; on a host where [`UpdatesClient::new`]
/// fails package detection (e.g. macOS) the degraded arm pins that side of
/// the current behavior instead. Both arms are deterministic for the host
/// they run on.
///
/// No spawn-counting seam is added at this layer: `collect_real_updates`
/// hardcodes its `DuctRunner`, and threading an injectable runner through
/// `start()` would change production signatures — the sentinel bundle
/// already answers "did anything re-run?".
#[cfg(test)]
mod cadence_oracle {
    use super::*;

    /// Sentinel id no real doctor finding can carry.
    const SENTINEL_ID: &str = "oracle-sentinel.updates.findings-cache";

    /// Sentinel package-manager label no real detection can produce (real
    /// labels are "apt", "dnf", "unknown").
    const SENTINEL_LABEL: &str = "oracle-sentinel";

    /// A sentinel bundle with `available == true` so `poll()` caches it; the
    /// counts are ones no real `apt-check`/`dnf` run can be coerced into by
    /// the environment.
    fn sentinel_bundle() -> UpdatesDataBundle {
        UpdatesDataBundle {
            available: true,
            package_manager: SENTINEL_LABEL.to_string(),
            auto_updates_enabled: true,
            service_active: true,
            pending_security: 1234,
            pending_total: 5678,
            last_run: None,
            schedule: None,
            timer_active: Some(true),
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
    /// next collection — the doctor, the update-count probe, and the service
    /// status probe are skipped (zero subprocess spawns) — and the freshness
    /// timestamp is NOT re-armed by the cache-hit poll.
    #[tokio::test]
    async fn cache_hit_returns_cached_bundle_without_reprobing() {
        let mut collector = UpdatesCollector::new();
        collector.cached_bundle = Some(sentinel_bundle());
        let primed = std::time::Instant::now();
        collector.bundle_fresh_at = Some(primed);

        collector.start();
        let bundle = collector.poll().await.expect("collection completes");

        if bundle.available {
            // Package manager detected (the campaign host): the cache must be
            // served verbatim.
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
                bundle.package_manager, SENTINEL_LABEL,
                "the sentinel label can only come from the cache, never from a real detection"
            );
            assert_eq!(bundle.pending_security, 1234);
            assert_eq!(bundle.pending_total, 5678);
            assert_eq!(
                collector.bundle_fresh_at,
                Some(primed),
                "a cache-hit poll must not advance (re-arm) the freshness timestamp"
            );
        } else {
            // No apt/dnf: construction failed BEFORE the cache arm, so the
            // degraded bundle carries no findings and poll()'s availability
            // gate leaves both the cache and the clock untouched.
            assert!(
                bundle.findings.is_empty(),
                "construction failure bypasses the cache arm entirely"
            );
            assert_eq!(
                collector.bundle_fresh_at,
                Some(primed),
                "a degraded bundle must not advance the freshness timestamp"
            );
        }
    }

    /// ORACLE: once the TTL has elapsed the cache is bypassed — no sentinel
    /// survives in ANY field — and (on an available bundle) the freshness
    /// timestamp advances past its primed value after the real re-derivation.
    #[tokio::test]
    async fn ttl_expiry_bypasses_cache_and_rederives() {
        let mut collector = UpdatesCollector::new();
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
            bundle.package_manager, SENTINEL_LABEL,
            "an expired cache must not serve the sentinel label"
        );
        assert_ne!(
            bundle.pending_total, 5678,
            "an expired cache must re-run the real update-count probe"
        );
        if bundle.available {
            // poll() gates the clock write on `available`, and an available
            // re-derived bundle must have re-armed it.
            assert!(
                collector.bundle_fresh_at.is_some_and(|t| t > primed),
                "an expired cache must be re-derived and the freshness clock advanced"
            );
        } else {
            // Degraded bundle: the gate keeps the primed clock untouched.
            assert_eq!(
                collector.bundle_fresh_at,
                Some(primed),
                "a degraded bundle must not advance the freshness timestamp"
            );
        }
    }
}
