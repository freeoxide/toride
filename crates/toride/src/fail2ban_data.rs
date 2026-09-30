//! Async fail2ban data collection (LIVE READ-ONLY).
//!
//! [`Fail2banCollector`] manages background collection of all fail2ban
//! subsystem data via a tokio oneshot channel, following the same pattern as
//! [`StatusCollector`](crate::status_collector::StatusCollector) and
//! [`SshDataCollector`](crate::ssh_data::SshDataCollector).
//!
//! This is the TEMPLATE read-only integration. It mirrors the SSH reference
//! (`SshDataCollector`) MINUS the entire write path — there are no
//! `SshOp`-equivalent operations, no optimistic updates, no cooldown gate, and
//! no `ssh_loading` spinner. Every call to the backend is a pure read.
//!
//! Doctor findings are expensive (they shell out to `fail2ban-client`,
//! `systemctl`, `nft`, `iptables`, …) and change slowly — and so does the
//! rest of the probe bundle (service status, jails, bans, firewall-backend
//! availability). The ENTIRE collection is therefore cached for 60s,
//! mirroring the proxy collector's whole-report cache: a cache hit performs
//! zero subprocess spawns. Freshness caveat (deliberate cadence decision):
//! new bans/jails and service transitions surface up to 60s late.
//!
//! ## macOS / construction
//!
//! [`toride_fail2ban::Fail2Ban::with_runner`] is used (NOT `::system()`), which
//! skips the `/etc/fail2ban` directory-existence check. On macOS where the
//! directory does not exist, construction still succeeds; the doctor then
//! surfaces the missing binary as a `Critical` finding rather than the whole
//! collector erroring out.
//!
//! ## Blocking
//!
//! The `DuctRunner` shells out synchronously. All backend work is wrapped in
//! [`tokio::task::spawn_blocking`] so the tokio worker is never stalled.

use tokio::sync::oneshot;

use crate::fail2ban_convert;
use crate::ui::screens::fail2ban::{BanEntry, FindingEntry, JailEntry};

/// Aggregated fail2ban data for the read-only section.
#[derive(Clone, Debug)]
pub struct Fail2banDataBundle {
    /// Whether the fail2ban backend was reachable at all. `false` when
    /// construction failed entirely or every probe returned no data — the UI
    /// renders a degraded "unavailable" panel.
    pub available: bool,
    /// Whether the systemd service is active (running).
    pub service_active: bool,
    /// Whether the service is enabled at boot.
    pub service_enabled: bool,
    /// Detected fail2ban version, if any.
    pub version: Option<String>,
    /// Active jails parsed from `fail2ban-client status`.
    pub jails: Vec<JailEntry>,
    /// Currently banned IPs parsed from `fail2ban-client banned`.
    pub bans: Vec<BanEntry>,
    /// Doctor findings (cached for 60s between collections).
    pub findings: Vec<FindingEntry>,
    /// Whether the `nft` binary is available (`None` if the probe failed).
    pub fw_nft_available: Option<bool>,
    /// Whether the `iptables` binary is available (`None` if the probe failed).
    pub fw_iptables_available: Option<bool>,
    /// Human-readable reason the backend was unreachable, populated ONLY when
    /// `available == false` because a collection task panicked (`JoinError`).
    /// `None` otherwise — notably also `None` for a freshly-constructed empty
    /// bundle before any collection has run. Surfaced to the UI so the degraded
    /// panel can show what actually went wrong instead of guessing.
    pub unavailable_reason: Option<String>,
}

// ── Collector ───────────────────────────────────────────────────────────────

/// Manages periodic async collection of fail2ban data.
///
/// Mirrors the proxy collector's whole-report cache: a oneshot channel for
/// the in-flight result, plus a 60s TTL cache over the ENTIRE bundle (doctor
/// findings AND the probe bundle: service status, jails, bans, firewall
/// availability) so the 6+N per-collection subprocess spawns do not repeat on
/// every 2s refresh tick.
pub struct Fail2banCollector {
    /// Carries the bundle AND whether the cached bundle was reused for this
    /// poll. The freshness timestamp must only be advanced when the probes
    /// were actually re-run (`used_cache == false`); otherwise every
    /// cache-hit poll would reset the TTL clock with the SAME (already-cached)
    /// bundle and the cache would never expire for the lifetime of the app.
    rx: Option<oneshot::Receiver<(Fail2banDataBundle, bool)>>,
    /// Cached bundle (doctor findings + all probe results) from the last
    /// collection.
    cached_bundle: Option<Fail2banDataBundle>,
    /// When the bundle cache was last refreshed.
    bundle_fresh_at: Option<std::time::Instant>,
}

/// How long to keep the cached bundle before re-running the doctor suite and
/// the probe bundle.
///
/// Deliberate freshness semantics: new bans/jails and service transitions
/// surface up to this TTL late (see the module docs).
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

impl Fail2banCollector {
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
    /// the cached bundle verbatim — the doctor AND the probe bundle
    /// (systemctl, fail2ban-client, nft/iptables) do not run at all.
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
            let (bundle, reused_cache) = collect_real_fail2ban(use_cache, cached_bundle).await;
            let _ = tx.send((bundle, reused_cache));
        });
    }

    /// Poll for a completed collection result.
    ///
    /// Returns `Some(bundle)` if the collection completed, `None` if still
    /// pending or if the collection failed. On an available bundle the whole
    /// bundle is cached, but the freshness timestamp is only advanced when the
    /// probes were actually re-run (not on a cache-hit poll) — otherwise the
    /// 60s TTL would be re-armed forever with the same cached data on every
    /// 2s refresh. A degraded bundle (a collection-task panic) is never
    /// cached, so the next refresh re-runs the probes instead of pinning the
    /// degraded panel for the TTL.
    pub async fn poll(&mut self) -> Option<Fail2banDataBundle> {
        match &mut self.rx {
            Some(rx) => {
                let result = rx.await.ok();
                // Only write the cache (and advance the freshness clock)
                // when the probes actually re-ran. On a cache-hit poll the
                // bundle IS the data we already cached — identical by
                // construction — so re-storing it would be a wasted deep
                // clone per tick, and resetting the TTL here would let the
                // cache live forever as long as the 2s refresh tick keeps
                // firing inside the TTL window.
                if let Some((ref bundle, used_cache)) = result
                    && bundle.available
                    && !used_cache
                {
                    self.cached_bundle = Some(bundle.clone());
                    self.bundle_fresh_at = Some(std::time::Instant::now());
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

impl Default for Fail2banCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Real data collection ────────────────────────────────────────────────────

/// Collect fail2ban data by shelling out to the real binaries.
///
/// When `use_cache` is set and a cached bundle is present, the cached bundle
/// is served verbatim and NOTHING runs — the doctor AND the probe bundle
/// (systemctl is-active/is-enabled, fail2ban-client version/status/banned,
/// nft/iptables availability) are skipped entirely.
///
/// Otherwise all work runs on the blocking thread pool (the `DuctRunner`
/// shells out synchronously). The `fail2ban-client` handle is constructed
/// ONCE per collection (`f2b.client()` resolves the binary through a `$PATH`
/// scan on every call, so the second construction the banned-IPs probe used
/// to pay is gone — the status and banned probes now share one client, and
/// with it one jail list). On ANY error — construction failure, doctor
/// error, every probe failing — returns [`empty_bundle`] with
/// `available = false`.
///
/// Returns `(bundle, used_cache)` where `used_cache` records whether the
/// bundle was served verbatim from the cache. The caller advances the TTL
/// clock ONLY when `used_cache == false`, so a cache-hit poll never resets
/// the freshness timestamp with stale data.
async fn collect_real_fail2ban(
    use_cache: bool,
    cached_bundle: Option<Fail2banDataBundle>,
) -> (Fail2banDataBundle, bool) {
    // Cache hit: serve the whole bundle verbatim. Neither the doctor nor any
    // probe spawns a subprocess.
    if use_cache && let Some(bundle) = cached_bundle {
        return (bundle, true);
    }

    // Build the Fail2Ban facade on the blocking pool. with_runner skips the
    // /etc/fail2ban existence check, so construction succeeds even on macOS.
    let f2b = match tokio::task::spawn_blocking(|| {
        toride_fail2ban::Fail2Ban::with_runner(
            Box::new(toride_fail2ban::command::DuctRunner::new()),
        )
    })
    .await
    {
        Ok(f2b) => f2b,
        Err(e) => {
            tracing::warn!("fail2ban construction task panicked: {e}");
            return (
                empty_bundle_with_reason(format!("fail2ban backend construction panicked: {e}")),
                false,
            );
        }
    };

    // Run ALL blocking probes in a single spawn_blocking that owns `f2b`.
    // This keeps every shell-out off the tokio worker (the `DuctRunner` is
    // synchronous) and sidesteps the 'static-borrow problem: the per-jail
    // enrichment calls `client.status_jail(&name)` repeatedly, so collecting
    // everything in one owned closure is both simpler and cheaper than
    // spawning one task per probe. Results are returned as plain owned data
    // so they cross the thread boundary cleanly. The fail2ban-client handle
    // is constructed once here and shared by the status and banned probes —
    // each `f2b.client()` call re-resolves the binary on `$PATH`.
    let result = tokio::task::spawn_blocking(move || {
        // ── Doctor ─────────────────────────────────────────────────────────
        let findings: Vec<FindingEntry> =
            match f2b.doctor(toride_fail2ban::doctor::DoctorScope::All) {
                Ok(report) => fail2ban_convert::convert_findings(report.findings),
                Err(e) => {
                    tracing::warn!("fail2ban doctor: {e}");
                    Vec::new()
                }
            };

        // ── Service status ────────────────────────────────────────────────
        let svc = f2b.service();
        let service_active = svc.is_active().unwrap_or(false);
        let service_enabled = svc.is_enabled().unwrap_or(false);

        // ── Client status + version + banned IPs (ONE client) ─────────────
        // A missing fail2ban-client degrades exactly as before: empty
        // jails/version AND empty bans, each with its own debug log.
        let (jails, version, bans) = match f2b.client() {
            Ok(client) => {
                let version = client.version().ok();
                let jails = match client.status() {
                    Ok(status) => {
                        let mut parsed = fail2ban_convert::parse_jails_from_status(&status);
                        // Enrich each jail from its per-jail status (best-effort;
                        // a failed per-jail call leaves the row with name only).
                        for jail in &mut parsed {
                            if let Ok(per_jail) = client.status_jail(&jail.name) {
                                let enriched = fail2ban_convert::enrich_jail_from_status(
                                    jail.clone(),
                                    &per_jail,
                                );
                                *jail = enriched;
                            }
                        }
                        parsed
                    }
                    Err(e) => {
                        tracing::debug!("fail2ban client status: {e}");
                        Vec::new()
                    }
                };
                let bans = match client.banned() {
                    Ok(raw) => fail2ban_convert::parse_bans(&raw),
                    Err(e) => {
                        tracing::debug!("fail2ban client banned: {e}");
                        Vec::new()
                    }
                };
                (jails, version, bans)
            }
            Err(e) => {
                tracing::debug!("fail2ban client init: {e}");
                (Vec::new(), None, Vec::new())
            }
        };

        // ── Firewall backend availability ─────────────────────────────────
        let fw = f2b.firewall();
        let fw_nft_available = fw.check_nft_available().ok();
        let fw_iptables_available = fw.check_iptables_available().ok();

        // ── Availability heuristic ────────────────────────────────────────
        // The section is "available" if EITHER the client responded (jails or
        // version known) OR the doctor produced any findings. A host with
        // fail2ban-client missing yields a single Critical finding
        // (binary.fail2ban-client.missing) but no jails/version — that still
        // counts as available so the operator SEES the finding rather than a
        // blank panel.
        let available =
            !jails.is_empty() || version.is_some() || !findings.is_empty() || service_active;

        Fail2banDataBundle {
            available,
            service_active,
            service_enabled,
            version,
            jails,
            bans,
            findings,
            fw_nft_available,
            fw_iptables_available,
            // Success path: no panic, so no reason. (A missing binary surfaces
            // as a Critical finding, keeping `available == true`.)
            unavailable_reason: None,
        }
    })
    .await;

    match result {
        // `use_cache == true` with an empty cache cannot happen via start()
        // (it only sets the flag when the cache is populated), and reaching
        // this point means every probe above DID run — so the truthful
        // provenance is "not from cache".
        Ok(bundle) => (bundle, false),
        Err(e) => {
            tracing::warn!("fail2ban collection task panicked: {e}");
            (
                empty_bundle_with_reason(format!("fail2ban data collection panicked: {e}")),
                false,
            )
        }
    }
}

/// Empty bundle used when fail2ban could not be constructed at all.
///
/// `available = false` signals the UI to render the degraded panel. No reason
/// is attached because none is known at this point; collection-time panics use
/// [`empty_bundle_with_reason`] to surface the `JoinError`.
fn empty_bundle() -> Fail2banDataBundle {
    Fail2banDataBundle {
        available: false,
        service_active: false,
        service_enabled: false,
        version: None,
        jails: Vec::new(),
        bans: Vec::new(),
        findings: Vec::new(),
        fw_nft_available: None,
        fw_iptables_available: None,
        unavailable_reason: None,
    }
}

/// Empty bundle carrying the reason collection failed. Used when a
/// `spawn_blocking` task panicked (`JoinError`) — the reason string is rendered
/// by the UI's degraded panel so the operator sees what actually went wrong.
fn empty_bundle_with_reason(reason: String) -> Fail2banDataBundle {
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
        let collector = Fail2banCollector::new();
        assert!(!collector.is_pending());
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(
            Fail2banCollector::new().is_pending(),
            Fail2banCollector::default().is_pending()
        );
    }

    #[tokio::test]
    async fn start_makes_pending() {
        let mut collector = Fail2banCollector::new();
        assert!(!collector.is_pending());
        collector.start();
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn start_is_idempotent() {
        let mut collector = Fail2banCollector::new();
        collector.start();
        assert!(collector.is_pending());
        collector.start(); // no-op, does not replace the receiver
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn poll_returns_none_when_not_started() {
        let mut collector = Fail2banCollector::new();
        assert!(collector.poll().await.is_none());
    }

    #[tokio::test]
    async fn poll_clears_pending() {
        let mut collector = Fail2banCollector::new();
        collector.start();
        // Let the spawned task complete (it shells out, so give it time).
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let _ = collector.poll().await;
        assert!(!collector.is_pending(), "poll should clear pending state");
    }

    #[tokio::test]
    async fn poll_returns_bundle_after_collection() {
        // On any host (including macOS without fail2ban) the collector must
        // return Some(bundle) after start() + enough time. The bundle's
        // `available` flag reflects whether fail2ban was found.
        let mut collector = Fail2banCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let bundle = collector.poll().await;
        assert!(bundle.is_some(), "poll should return Some after completion");
    }

    #[test]
    fn empty_bundle_is_unavailable() {
        let b = empty_bundle();
        assert!(!b.available);
        assert!(b.jails.is_empty());
        assert!(b.bans.is_empty());
        assert!(b.findings.is_empty());
        assert!(b.version.is_none());
        assert!(b.fw_nft_available.is_none());
        assert!(b.fw_iptables_available.is_none());
        assert!(
            b.unavailable_reason.is_none(),
            "empty_bundle carries no reason; panics use empty_bundle_with_reason"
        );
    }

    #[tokio::test]
    async fn findings_cache_is_populated_after_poll() {
        let mut collector = Fail2banCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let bundle = collector.poll().await;
        // After a successful AVAILABLE poll the whole-bundle cache is
        // populated. A host where every probe fails (available == false,
        // e.g. no fail2ban and a doctor that produced nothing) stays
        // uncached so the next tick re-runs the probes.
        if bundle.is_some_and(|b| b.available) {
            assert!(collector.cached_bundle.is_some());
            assert!(collector.bundle_fresh_at.is_some());
        } else {
            assert!(
                collector.cached_bundle.is_none(),
                "an unavailable bundle must not be cached"
            );
        }
    }

    #[test]
    fn invalidate_findings_cache_clears_it() {
        let mut collector = Fail2banCollector::new();
        collector.cached_bundle = Some(empty_bundle());
        collector.bundle_fresh_at = Some(std::time::Instant::now());
        collector.invalidate_findings_cache();
        assert!(collector.cached_bundle.is_none());
        assert!(collector.bundle_fresh_at.is_none());
    }
}

// ── Cadence oracles (round 0, extended round 1) ──────────────────────────────

/// Cadence oracles for the 60s whole-bundle cache.
///
/// Round 1 (F02) extended these from a findings-only cache to the whole
/// probe bundle: sentinel data now covers service flags, version, jails,
/// bans, and firewall availability as well as the findings. The sentinel
/// strings (finding id, jail name, version, ban IP) are values no real
/// fail2ban doctor/probe can emit, so "the bundle came back verbatim" proves
/// the doctor AND the probe bundle — systemctl, fail2ban-client
/// version/status/banned, nft/iptables — did not spawn a single subprocess.
///
/// The lifecycle goes through the REAL `start()` / spawned collection — the
/// same shell-out path the dashboard's 2s refresh tick drives. The cache-hit
/// arm is deterministic on any host (nothing runs). The expiry arm's clock
/// assertion is conditional on the re-derived bundle being `available`
/// (`poll()` only caches/advances for available bundles; a host where every
/// probe fails legitimately keeps its primed clock).
///
/// No spawn-counting seam is added at this layer: `collect_real_fail2ban`
/// hardcodes its `DuctRunner`, and threading an injectable runner through
/// `start()` would change production signatures for zero observed benefit —
/// the sentinel bundle already answers "did anything re-run?". (Counting
/// seams at the backend-crate level exist separately, e.g. toride-fail2ban's
/// `spawn_oracle`.)
#[cfg(test)]
mod cadence_oracle {
    use super::*;

    /// Sentinel id no real doctor finding can carry.
    const SENTINEL_ID: &str = "oracle-sentinel.fail2ban.findings-cache";

    /// Sentinel jail name no real `fail2ban-client status` can list.
    const SENTINEL_JAIL: &str = "oracle-sentinel-jail";

    /// Sentinel version string no real `fail2ban-client --version` prints.
    const SENTINEL_VERSION: &str = "oracle-sentinel 0.0.0";

    /// A sentinel bundle with `available == true` so `poll()` caches it: real
    /// probe outputs can never produce any of these field values.
    fn sentinel_bundle() -> Fail2banDataBundle {
        Fail2banDataBundle {
            available: true,
            service_active: true,
            service_enabled: true,
            version: Some(SENTINEL_VERSION.to_string()),
            jails: vec![JailEntry {
                name: SENTINEL_JAIL.to_string(),
                ..jail_entry_default()
            }],
            bans: Vec::new(),
            findings: vec![FindingEntry {
                id: SENTINEL_ID.to_string(),
                severity: "ok".to_string(),
                title: "cadence-oracle sentinel".to_string(),
                detail: String::new(),
                fix: None,
            }],
            fw_nft_available: Some(true),
            fw_iptables_available: Some(false),
            unavailable_reason: None,
        }
    }

    /// Fills the non-sentinel [`JailEntry`] fields with values no assertion
    /// depends on (`JailEntry` has no Default).
    fn jail_entry_default() -> JailEntry {
        JailEntry {
            name: String::new(),
            is_running: false,
            banned_count: 0,
            total_bans: 0,
            file_count: 0,
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
    /// next collection — the doctor AND every probe are skipped (zero
    /// subprocess spawns) — and the freshness timestamp is NOT re-armed by
    /// the cache-hit poll.
    #[tokio::test]
    async fn cache_hit_returns_cached_bundle_without_reprobing() {
        let mut collector = Fail2banCollector::new();
        collector.cached_bundle = Some(sentinel_bundle());
        let primed = std::time::Instant::now();
        collector.bundle_fresh_at = Some(primed);

        collector.start();
        let bundle = collector.poll().await.expect("collection completes");

        // Cached-vs-fresh parity: every sentinel field comes back verbatim.
        assert_eq!(bundle.findings.len(), 1);
        assert_eq!(
            bundle.findings[0].id, SENTINEL_ID,
            "the sentinel id can only come from the cache, never from a real doctor run"
        );
        assert_eq!(
            bundle.version.as_deref(),
            Some(SENTINEL_VERSION),
            "the sentinel version can only come from the cache"
        );
        assert_eq!(bundle.jails.len(), 1);
        assert_eq!(
            bundle.jails[0].name, SENTINEL_JAIL,
            "the sentinel jail can only come from the cache, never from a real status probe"
        );
        assert!(
            bundle.service_active,
            "sentinel service flag served verbatim"
        );
        assert_eq!(bundle.fw_nft_available, Some(true));
        assert_eq!(
            collector.bundle_fresh_at,
            Some(primed),
            "a cache-hit poll must not advance (re-arm) the freshness timestamp"
        );
    }

    /// ORACLE: once the TTL has elapsed the cache is bypassed — no sentinel
    /// survives in ANY field — and (on an available re-derivation) the
    /// freshness timestamp advances past its primed value.
    #[tokio::test]
    async fn ttl_expiry_bypasses_cache_and_rederives() {
        let mut collector = Fail2banCollector::new();
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
            bundle.version.as_deref(),
            Some(SENTINEL_VERSION),
            "an expired cache must not serve the sentinel version"
        );
        assert!(
            bundle.jails.iter().all(|j| j.name != SENTINEL_JAIL),
            "an expired cache must not serve the sentinel jail"
        );
        if bundle.available {
            // poll() gates the clock write on `available`; a host where the
            // doctor responded (any finding, incl. binary-missing) is
            // available and must have re-armed the clock.
            assert!(
                collector.bundle_fresh_at.is_some_and(|t| t > primed),
                "an expired cache must be re-derived and the freshness clock advanced"
            );
        } else {
            assert_eq!(
                collector.bundle_fresh_at,
                Some(primed),
                "an unavailable re-derivation must leave the primed clock untouched"
            );
        }
    }
}
