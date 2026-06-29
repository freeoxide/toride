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
//! once the TODOs in `doctor.rs` land — query systemd) and change slowly, so
//! they are cached for 60s — exactly like the fail2ban / wireguard / harden
//! findings caches.
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
/// Mirrors [`Fail2banCollector`](crate::fail2ban_data::Fail2banCollector): a
/// oneshot channel for the in-flight result, plus a 60s TTL cache for the
/// expensive doctor findings so they are not re-run on every 2s refresh tick.
pub struct UpdatesCollector {
    /// Carries the bundle AND whether the cached findings were reused for this
    /// poll. The freshness timestamp must only be advanced when the doctor was
    /// actually re-run (`used_cache == false`); otherwise every cache-hit poll
    /// would reset the TTL clock with the SAME (already-cached) findings and
    /// the cache would never expire for the lifetime of the app.
    rx: Option<oneshot::Receiver<(UpdatesDataBundle, bool)>>,
    /// Cached doctor findings from the last collection.
    cached_findings: Option<Vec<FindingEntry>>,
    /// When the findings cache was last refreshed.
    findings_fresh_at: Option<std::time::Instant>,
}

/// How long to keep cached findings before re-running the doctor suite.
#[expect(
    clippy::duration_suboptimal_units,
    reason = "stable std lacks from_mins"
)]
const FINDINGS_TTL: std::time::Duration = std::time::Duration::from_secs(60);

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
            // Race the probe against a deadline so a wedged network cannot hold
            // the task slot. On timeout we surface a degraded bundle carrying
            // the reason; the next eligible refresh re-tries cleanly.
            let outcome: (UpdatesDataBundle, bool) = match tokio::time::timeout(
                PROBE_DEADLINE,
                collect_real_updates(use_cache, cached_findings),
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
    /// pending or if the collection failed. On success the cached findings are
    /// updated to the freshly-returned findings, but the freshness timestamp is
    /// only advanced when the doctor was actually re-run (not on a cache-hit
    /// poll) — otherwise the 60s TTL would be re-armed forever with the same
    /// cached data on every 2s refresh.
    pub async fn poll(&mut self) -> Option<UpdatesDataBundle> {
        match &mut self.rx {
            Some(rx) => {
                let result = rx.await.ok();
                if let Some((ref bundle, used_cache)) = result {
                    // Only cache findings when the bundle is a real (available)
                    // result. A timed-out or panicked bundle carries an empty
                    // `findings` Vec and `available == false`; writing it into
                    // the cache would make the next start() take the `use_cache`
                    // branch and skip re-running the doctor for up to the TTL,
                    // leaving the panel showing "no findings" after recovery.
                    // Leave the existing cached findings intact on a degraded
                    // bundle so the next collection re-runs the doctor.
                    if bundle.available {
                        self.cached_findings = Some(bundle.findings.clone());
                    }
                    // Only advance the freshness clock when the doctor was
                    // actually re-run (mirrors fail2ban / wireguard / harden).
                    if !used_cache && bundle.available {
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

impl Default for UpdatesCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Real data collection ────────────────────────────────────────────────────

/// Collect updates data by shelling out to the real binaries.
///
/// All work runs on the blocking thread pool. The `UpdatesClient` is
/// constructed inside `spawn_blocking` (`new()` probes `$PATH`); on macOS it
/// returns `Err(PackageDetection)` and we surface a degraded bundle. Doctor
/// findings may be reused from the cache. On ANY error or panic returns
/// [`empty_bundle`] / [`empty_bundle_with_reason`] with `available = false`.
///
/// Returns `(bundle, used_cache)` where `used_cache` records whether the
/// findings were actually taken from the cache on a successful collection.
async fn collect_real_updates(
    use_cache: bool,
    cached_findings: Option<Vec<FindingEntry>>,
) -> (UpdatesDataBundle, bool) {
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
    // the doctor / backend / service / schedule constructors each take
    // `&dyn Runner`, so collecting everything in one owned closure that builds
    // a single DuctRunner is both simpler and cheaper than spawning one task
    // per probe. Results are returned as plain owned data so they cross the
    // thread boundary cleanly. Doctor findings are taken from the cache when
    // fresh (`use_cache`), otherwise re-run here.
    let result = tokio::task::spawn_blocking(move || {
        // One DuctRunner shared by every &dyn Runner consumer below. Mirrors
        // the wireguard / harden idiom (a fresh DuctRunner built inside the
        // closure), except here the backend constructors TAKE the runner ref
        // rather than reading a global.
        let runner = toride_updates::DuctRunner;

        // ── Doctor (unless cached) ─────────────────────────────────────────
        let findings: Vec<FindingEntry> = if use_cache {
            cached_findings.unwrap_or_default()
        } else {
            let doc = toride_updates::doctor::Doctor::new(&runner);
            match doc.run() {
                Ok(raw) => toride_updates_convert::convert_findings(raw),
                Err(e) => {
                    tracing::warn!("updates doctor: {e}");
                    Vec::new()
                }
            }
        };

        // ── Package manager label ──────────────────────────────────────────
        let pm = toride_updates::detect::detect_package_manager();
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
        let status = match client.status() {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!("updates status: {e}");
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

        // ── Timer / service-unit activity (ServiceManager::is_active) ──────
        let svc_mgr = toride_updates::service::ServiceManager::new(&runner);
        let timer_active = match svc_mgr.is_active() {
            Ok(active) => Some(active),
            Err(e) => {
                tracing::debug!("updates service is_active: {e}");
                None
            }
        };

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
        Ok(bundle) => (bundle, use_cache),
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
                    collector.cached_findings.is_some(),
                    "cache must be populated from an available bundle"
                );
                assert!(
                    collector.findings_fresh_at.is_some(),
                    "freshness clock must advance on a real collection"
                );
            }
            _ => {
                assert!(
                    collector.cached_findings.is_none(),
                    "cache must NOT be populated from a degraded (unavailable) bundle"
                );
            }
        }
    }

    #[tokio::test]
    async fn poll_does_not_overwrite_cache_with_empty_on_degraded_bundle() {
        // Regression for the PROBE_DEADLINE / JoinError path: a degraded bundle
        // (available == false, empty findings) must NOT replace existing cached
        // findings, otherwise the next start() would take the `use_cache` branch
        // and skip re-running the doctor for up to the TTL — leaving the panel
        // showing "no findings" for ~90s after a transient network stall.
        //
        // We feed a degraded bundle straight through the oneshot channel (the
        // same channel `start()` uses) so `poll()` exercises its real cache
        // write path against a controlled bundle shape.
        let mut collector = UpdatesCollector::new();
        // Seed the cache as if a prior successful collection had run.
        let prior = vec![FindingEntry {
            id: "binary.unattended-upgrades.found".into(),
            severity: "ok".into(),
            title: "unattended-upgrades binary available".into(),
            detail: String::new(),
            fix: None,
        }];
        collector.cached_findings = Some(prior.clone());
        collector.findings_fresh_at = Some(std::time::Instant::now());

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
        // The cache must be UNCHANGED — not overwritten with an empty Vec.
        // (FindingEntry has no PartialEq, so compare structurally.)
        let cached = collector
            .cached_findings
            .as_ref()
            .expect("cached findings must NOT have been cleared by a degraded bundle");
        assert_eq!(
            cached.len(),
            prior.len(),
            "degraded bundle must not overwrite existing cached findings"
        );
        assert_eq!(
            cached[0].id, prior[0].id,
            "degraded bundle must not overwrite existing cached findings"
        );
    }

    #[test]
    fn invalidate_findings_cache_clears_it() {
        let mut collector = UpdatesCollector::new();
        collector.cached_findings = Some(Vec::new());
        collector.findings_fresh_at = Some(std::time::Instant::now());
        collector.invalidate_findings_cache();
        assert!(collector.cached_findings.is_none());
        assert!(collector.findings_fresh_at.is_none());
    }
}
