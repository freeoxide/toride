//! Async kernel-hardening data collection (LIVE READ-ONLY).
//!
//! [`HardenCollector`] manages background collection of all toride-harden
//! subsystem data via a tokio oneshot channel, following the same pattern as
//! [`Fail2banCollector`](crate::fail2ban_data::Fail2banCollector) and
//! [`FirewallCollector`](crate::ufw_kit_data::FirewallCollector) (which
//! themselves mirror [`SshDataCollector`](crate::ssh_data::SshDataCollector)
//! MINUS the write path).
//!
//! This is a read-only integration: there are no write operations, no
//! optimistic updates, no cooldown gate, and no loading spinner. Every call to
//! the backend is a pure read.
//!
//! Doctor findings are expensive (they shell out to `sysctl` for every checked
//! parameter, plus `findmnt` for shm) and change slowly, so they are cached for
//! 60s — exactly like the fail2ban / ufw-kit / SSH diagnostics cache.
//!
//! ## macOS / construction
//!
//! [`toride_harden::HardenClient::system`] is used. The constructor probes for
//! the `sysctl` binary via `which`; on macOS (where BSD `sysctl` semantics
//! differ from Linux's and the Linux keys the profiles reference do not exist)
//! the constructor still succeeds on macOS dev machines that happen to have a
//! `sysctl` on PATH, BUT each `sysctl -n <linux-key>` probe then fails and the
//! doctor surfaces per-key errors as `Important` findings. On hosts where
//! `sysctl` is genuinely absent the constructor returns
//! `Err(BinaryNotFound("sysctl"))`; that path yields `available = false` and
//! the degraded panel renders instead. The profile selector is ALWAYS populated
//! (via [`HardenProfile::all_names`]) so the desired state is described even
//! when the live state is unreadable.
//!
//! ## Blocking
//!
//! The `DuctRunner` shells out synchronously. All backend work is wrapped in
//! [`tokio::task::spawn_blocking`] so the tokio worker is never stalled.

use std::collections::BTreeMap;

use tokio::sync::oneshot;

use crate::toride_harden_convert;
use crate::ui::screens::toride_harden::{FindingEntry, HardenProfileEntry, MountEntry, SysctlRow};

/// Aggregated kernel-hardening data for the read-only section.
#[derive(Clone, Debug)]
pub struct HardenDataBundle {
    /// Whether the harden backend was reachable at all (`sysctl` binary
    /// present + construction succeeded). `false` when construction failed
    /// entirely or the collection task panicked — the UI renders a degraded
    /// "unavailable" panel.
    pub available: bool,
    /// Available hardening profiles (always populated when collection ran,
    /// even on an unreadable host, so the desired state is described).
    pub profiles: Vec<HardenProfileEntry>,
    /// Sysctl parameter rows (current vs desired) for EVERY profile, keyed by
    /// profile name (e.g. `"desktop"`). The UI holds its own
    /// `selected_profile` index and looks up the visible rows here on each
    /// Left/Right press, so cycling the selector actually swaps the table
    /// (previously the table was built only for profile 0 and the selector
    /// lied about which profile was shown). Built once per collection; the
    /// desired-side is cheap pure data and the live `current` column is one
    /// `status()` probe per profile.
    pub sysctl_rows_by_profile: BTreeMap<String, Vec<SysctlRow>>,
    /// Shared-memory mounts.
    pub mounts: Vec<MountEntry>,
    /// Doctor findings (cached for 60s between collections).
    pub findings: Vec<FindingEntry>,
    /// Human-readable reason the backend was unreachable, populated ONLY when
    /// `available == false` (construction error or collection-task panic).
    /// `None` otherwise — notably also `None` for a freshly-constructed empty
    /// bundle before any collection has run. Surfaced to the UI so the degraded
    /// panel can show what actually went wrong instead of guessing.
    pub unavailable_reason: Option<String>,
}

// ── Collector ───────────────────────────────────────────────────────────────

/// Manages periodic async collection of kernel-hardening data.
///
/// Mirrors [`Fail2banCollector`](crate::fail2ban_data::Fail2banCollector): a
/// oneshot channel for the in-flight result, plus a 60s TTL cache for the
/// expensive doctor findings so they are not re-run on every 2s refresh tick.
pub struct HardenCollector {
    /// Carries the bundle AND whether the cached findings were reused for this
    /// poll. The freshness timestamp must only be advanced when the doctor was
    /// actually re-run (`used_cache == false`); otherwise every cache-hit poll
    /// would reset the TTL clock with the SAME (already-cached) findings and
    /// the cache would never expire for the lifetime of the app.
    rx: Option<oneshot::Receiver<(HardenDataBundle, bool)>>,
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

impl HardenCollector {
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
            let (bundle, used_cache) = collect_real_harden(use_cache, cached_findings).await;
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
    pub async fn poll(&mut self) -> Option<HardenDataBundle> {
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

impl Default for HardenCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Real data collection ────────────────────────────────────────────────────

/// Collect kernel-hardening data by shelling out to the real binaries.
///
/// All work runs on the blocking thread pool (the `DuctRunner` shells out
/// synchronously). Doctor findings may be reused from the cache. On ANY error
/// — construction failure (`HardenClient::system()` `Err(BinaryNotFound)` on
/// macOS), doctor error, or a collection-task panic — returns
/// [`empty_bundle_with_profiles`] / [`empty_bundle_with_reason`] with
/// `available = false` but the profile selector STILL populated via
/// [`HardenProfile::all_names`] so the desired state is described.
///
/// `use_cache` / `cached_findings` mirror the fail2ban / ufw-kit diagnostics
/// cache: when the cache is fresh the doctor suite is skipped entirely.
///
/// Returns `(bundle, used_cache)` where `used_cache` records whether the
/// findings were actually taken from the cache on a successful collection.
async fn collect_real_harden(
    use_cache: bool,
    cached_findings: Option<Vec<FindingEntry>>,
) -> (HardenDataBundle, bool) {
    // Build the HardenClient facade on the blocking pool. system() probes for
    // the `sysctl` binary; on macOS / sysctl-less hosts it returns
    // Err(BinaryNotFound). Build the client INSIDE spawn_blocking exactly like
    // collect_real_fail2ban builds its facade.
    let client =
        match tokio::task::spawn_blocking(toride_harden::client::HardenClient::system).await {
            Ok(Ok(client)) => client,
            Ok(Err(e)) => {
                // Construction failed (e.g. BinaryNotFound("sysctl") on macOS).
                // Still populate the profile selector so the desired state is
                // described; available = false renders the degraded panel.
                tracing::debug!("harden construction failed: {e}");
                return (
                    empty_bundle_with_reason(format!("harden backend unavailable: {e}")),
                    false,
                );
            }
            Err(e) => {
                tracing::warn!("harden construction task panicked: {e}");
                return (
                    empty_bundle_with_reason(format!("harden backend construction panicked: {e}")),
                    false,
                );
            }
        };

    // Profiles are computable WITHOUT the client (pure backend data), so build
    // them once outside the per-collection spawn. (They change only with the
    // crate version, never at runtime — cheap to recompute.)
    let profiles = toride_harden_convert::convert_profiles();
    // Resolve each profile name to its backend enum so the blocking closure can
    // probe `status()` once per profile. The desired-side (`params()`) is pure
    // data; only the live `current` column shells out. Building all profiles
    // here (rather than only index 0) is what makes the Left/Right selector
    // actually swap the table — previously the selector advanced
    // `selected_profile` but the table stayed pinned to Desktop.
    let profile_specs: Vec<(String, toride_harden::HardenSpec)> = profiles
        .iter()
        .filter_map(|entry| {
            toride_harden::HardeningProfile::from_name(&entry.name).map(|p| {
                let spec = toride_harden::HardenSpec::builder()
                    .params(p.params())
                    .build();
                (entry.name.clone(), spec)
            })
        })
        .collect();

    // Run ALL blocking probes in a single spawn_blocking that owns `client`.
    // This keeps every shell-out off the tokio worker (the `DuctRunner` is
    // synchronous) and sidesteps the 'static-borrow problem. Results are
    // returned as plain owned data so they cross the thread boundary cleanly.
    // Doctor findings are taken from the cache when fresh (`use_cache`),
    // otherwise re-run here.
    let result = tokio::task::spawn_blocking(move || {
        // ── Doctor (unless cached) ─────────────────────────────────────────
        // The HardenClient does not expose its internal runner, and `doctor` is
        // a free function taking `&dyn Runner`. Build a fresh DuctRunner
        // (re-exportd at the toride_harden crate root) so the doctor probes
        // shell out on the same blocking pool as the rest of this closure.
        let findings: Vec<FindingEntry> = if use_cache {
            cached_findings.unwrap_or_default()
        } else {
            let runner = toride_harden::DuctRunner;
            toride_harden_convert::convert_findings(toride_harden::doctor::doctor(&runner))
        };

        // ── Sysctl tables for ALL profiles ───────────────────────────────
        // Probe `status()` once per profile (each call shells out once per
        // param). The desired-side comes from the spec built above; only the
        // live `current` column is read here. A profile whose probe errors is
        // recorded as an empty row list rather than aborting the whole bundle —
        // the operator can still cycle to the other profiles.
        let mut sysctl_rows_by_profile: BTreeMap<String, Vec<SysctlRow>> = BTreeMap::new();
        for (name, spec) in &profile_specs {
            let rows: Vec<SysctlRow> = match client.status(spec) {
                Ok(pairs) => pairs
                    .into_iter()
                    .map(|(param, current)| {
                        toride_harden_convert::convert_sysctl_row(&param, current)
                    })
                    .collect(),
                Err(e) => {
                    tracing::debug!("harden status for {name}: {e}");
                    Vec::new()
                }
            };
            sysctl_rows_by_profile.insert(name.clone(), rows);
        }

        // ── Shared-memory mounts ──────────────────────────────────────────
        let mounts: Vec<MountEntry> = match client.check_shm() {
            Ok(raw) => toride_harden_convert::convert_mounts(raw),
            Err(e) => {
                tracing::debug!("harden check_shm: {e}");
                Vec::new()
            }
        };

        // ── Availability heuristic ────────────────────────────────────────
        // The section is "available" if ANY profile's sysctl table is non-empty
        // (the status() probe succeeded for at least one parameter), OR the
        // doctor produced any findings, OR any shm mounts were discovered. A
        // host where sysctl is missing yields empty tables + a doctor that
        // errors per-key (each producing an `Important` finding) — that still
        // counts as available so the operator SEES the findings. A host where
        // construction failed entirely (BinaryNotFound) never reaches this code
        // path; it returns the degraded bundle above.
        let any_sysctl_rows = sysctl_rows_by_profile.values().any(|v| !v.is_empty());
        let available = any_sysctl_rows || !findings.is_empty() || !mounts.is_empty();

        HardenDataBundle {
            available,
            profiles,
            sysctl_rows_by_profile,
            mounts,
            findings,
            unavailable_reason: None,
        }
    })
    .await;

    match result {
        Ok(bundle) => (bundle, use_cache),
        Err(e) => {
            tracing::warn!("harden collection task panicked: {e}");
            (
                empty_bundle_with_reason(format!("harden data collection panicked: {e}")),
                false,
            )
        }
    }
}

/// Empty bundle used when harden could not be constructed at all.
///
/// `available = false` signals the UI to render the degraded panel. The profile
/// selector is populated via [`HardenProfile::all_names`] so the desired state
/// is described even when the live state is unreadable. No reason is attached
/// because none is known at this point; collection-time panics use
/// [`empty_bundle_with_reason`] to surface the `JoinError`.
fn empty_bundle() -> HardenDataBundle {
    HardenDataBundle {
        available: false,
        profiles: toride_harden_convert::convert_profiles(),
        sysctl_rows_by_profile: BTreeMap::new(),
        mounts: Vec::new(),
        findings: Vec::new(),
        unavailable_reason: None,
    }
}

/// Empty bundle carrying the reason collection failed. Used when construction
/// failed (`HardenClient::system()` `Err(BinaryNotFound)`) or when a
/// `spawn_blocking` task panicked (`JoinError`) — the reason string is rendered
/// by the UI's degraded panel so the operator sees what actually went wrong.
fn empty_bundle_with_reason(reason: String) -> HardenDataBundle {
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
        let collector = HardenCollector::new();
        assert!(!collector.is_pending());
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(
            HardenCollector::new().is_pending(),
            HardenCollector::default().is_pending()
        );
    }

    #[tokio::test]
    async fn start_makes_pending() {
        let mut collector = HardenCollector::new();
        assert!(!collector.is_pending());
        collector.start();
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn start_is_idempotent() {
        let mut collector = HardenCollector::new();
        collector.start();
        assert!(collector.is_pending());
        collector.start(); // no-op, does not replace the receiver
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn poll_returns_none_when_not_started() {
        let mut collector = HardenCollector::new();
        assert!(collector.poll().await.is_none());
    }

    #[tokio::test]
    async fn poll_clears_pending() {
        let mut collector = HardenCollector::new();
        collector.start();
        // Let the spawned task complete (it shells out, so give it time).
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let _ = collector.poll().await;
        assert!(!collector.is_pending(), "poll should clear pending state");
    }

    #[tokio::test]
    async fn poll_returns_bundle_after_collection() {
        // On any host (including macOS without sysctl) the collector must
        // return Some(bundle) after start() + enough time. The bundle's
        // `available` flag reflects whether sysctl was found.
        let mut collector = HardenCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let bundle = collector.poll().await;
        assert!(bundle.is_some(), "poll should return Some after completion");
    }

    #[test]
    fn empty_bundle_is_unavailable_but_has_profiles() {
        let b = empty_bundle();
        assert!(!b.available);
        assert!(b.sysctl_rows_by_profile.is_empty());
        assert!(b.mounts.is_empty());
        assert!(b.findings.is_empty());
        // The profile selector is ALWAYS populated (even on an unreadable host)
        // so the desired state is described — a regression to empty profiles
        // would hide the entire baseline from the operator.
        assert!(
            !b.profiles.is_empty(),
            "profile selector must be populated even when unavailable"
        );
        assert!(
            b.unavailable_reason.is_none(),
            "empty_bundle carries no reason; construction failures / panics use empty_bundle_with_reason"
        );
    }

    #[test]
    fn empty_bundle_with_reason_carries_reason() {
        let b = empty_bundle_with_reason("BinaryNotFound: sysctl".into());
        assert!(!b.available);
        assert_eq!(
            b.unavailable_reason.as_deref(),
            Some("BinaryNotFound: sysctl")
        );
        // Profiles still populated on the degraded bundle.
        assert!(!b.profiles.is_empty());
    }

    #[tokio::test]
    async fn findings_cache_is_populated_after_poll() {
        let mut collector = HardenCollector::new();
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
        let mut collector = HardenCollector::new();
        collector.cached_findings = Some(Vec::new());
        collector.findings_fresh_at = Some(std::time::Instant::now());
        collector.invalidate_findings_cache();
        assert!(collector.cached_findings.is_none());
        assert!(collector.findings_fresh_at.is_none());
    }
}
