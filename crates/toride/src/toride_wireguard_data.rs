//! Async `WireGuard` data collection (LIVE READ-ONLY).
//!
//! [`WireguardCollector`] manages background collection of all toride-wireguard
//! subsystem data via a tokio oneshot channel, following the same pattern as
//! [`Fail2banCollector`](crate::fail2ban_data::Fail2banCollector) and
//! [`HardenCollector`](crate::toride_harden_data::HardenCollector) (which
//! themselves mirror [`SshDataCollector`](crate::ssh_data::SshDataCollector)
//! MINUS the write path).
//!
//! This is a read-only integration: there are no write operations, no
//! optimistic updates, no cooldown gate, and no loading spinner. Every call to
//! the backend is a pure read.
//!
//! Doctor findings are expensive (they shell out to `which` for `wg` /
//! `wg-quick`, stat the config directory, and would probe `wg show`) and change
//! slowly, so they are cached for 60s — exactly like the fail2ban / ufw-kit /
//! harden / SSH diagnostics cache.
//!
//! ## macOS / construction
//!
//! [`toride_wireguard::client::WireguardClient::new`] is the constructor. The
//! backend is currently a scaffold (it does not actually shell out to `wg`
//! yet), so construction succeeds on ANY host — including macOS dev machines
//! where `wg` is absent. The doctor, run separately inside
//! [`collect_real_wireguard`], is what probes `$PATH` for `wg` / `wg-quick`
//! via `which::which(...)`. On macOS that probe surfaces a missing-`wg`
//! Error / Warning finding, and the availability heuristic below
//! (`available = !interfaces.is_empty() || !findings.is_empty()`) evaluates to
//! `true` — so the LIVE panel renders WITH those findings, not the degraded
//! panel.
//!
//! The `Err(BinaryNotFound)` / `available = false` / degraded-panel path
//! described by the `WireguardClient::new()` branch below is reserved for when
//! the backend constructor is actually wired to probe `$PATH` itself; today
//! that branch is unreachable because construction never returns `Err`.
//!
//! ## Blocking
//!
//! The `wg` CLI / file reads are synchronous. All backend work is wrapped in
//! [`tokio::task::spawn_blocking`] so the tokio worker is never stalled.

use tokio::sync::oneshot;

use crate::toride_wireguard_convert;
use crate::ui::screens::toride_wireguard::{FindingEntry, InterfaceEntry, PeerEntry, ServiceEntry};

/// Aggregated `WireGuard` data for the read-only section.
#[derive(Clone, Debug)]
pub struct WireguardDataBundle {
    /// Whether the `WireGuard` backend was reachable at all. `false` when
    /// construction failed entirely or every probe returned no data — the UI
    /// renders a degraded "unavailable" panel.
    pub available: bool,
    /// Active interfaces parsed from `wg show`.
    pub interfaces: Vec<InterfaceEntry>,
    /// Peers across all interfaces (from `PeerManager::list_peers()`).
    pub peers: Vec<PeerEntry>,
    /// Per-interface `wg-quick@<iface>` systemd service activity.
    pub services: Vec<ServiceEntry>,
    /// Whether the `wg` binary was found (from the doctor report).
    pub wg_binary_found: Option<bool>,
    /// Whether the `wg-quick` binary was found (from the doctor report).
    pub wg_quick_binary_found: Option<bool>,
    /// Whether the `/etc/wireguard` config directory exists.
    pub config_dir_exists: Option<bool>,
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

/// Manages periodic async collection of `WireGuard` data.
///
/// Mirrors [`Fail2banCollector`](crate::fail2ban_data::Fail2banCollector): a
/// oneshot channel for the in-flight result, plus a 60s TTL cache for the
/// expensive doctor findings so they are not re-run on every 2s refresh tick.
pub struct WireguardCollector {
    /// Carries the bundle AND whether the cached findings were reused for this
    /// poll. The freshness timestamp must only be advanced when the doctor was
    /// actually re-run (`used_cache == false`); otherwise every cache-hit poll
    /// would reset the TTL clock with the SAME (already-cached) findings and
    /// the cache would never expire for the lifetime of the app.
    rx: Option<oneshot::Receiver<(WireguardDataBundle, bool)>>,
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

impl WireguardCollector {
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
            let (bundle, used_cache) = collect_real_wireguard(use_cache, cached_findings).await;
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
    pub async fn poll(&mut self) -> Option<WireguardDataBundle> {
        match &mut self.rx {
            Some(rx) => {
                let result = rx.await.ok();
                if let Some((ref bundle, used_cache)) = result {
                    self.cached_findings = Some(bundle.findings.clone());
                    // Only advance the freshness clock when the doctor was
                    // actually re-run. On a cache-hit poll the findings are the
                    // SAME data we already cached, so resetting the TTL here
                    // would let the cache live forever as long as the 2s refresh
                    // tick keeps firing inside the TTL window.
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

impl Default for WireguardCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Real data collection ────────────────────────────────────────────────────

/// Collect `WireGuard` data by shelling out to the real binaries.
///
/// All work runs on the blocking thread pool (`wg` shells out synchronously,
/// config files are read synchronously). Doctor findings may be reused from the
/// cache. On ANY error — construction failure, doctor error, every probe
/// failing — returns [`empty_bundle`] / [`empty_bundle_with_reason`] with
/// `available = false`.
///
/// `use_cache` / `cached_findings` mirror the fail2ban / harden diagnostics
/// cache: when the cache is fresh the doctor suite is skipped entirely.
///
/// Returns `(bundle, used_cache)` where `used_cache` records whether the
/// findings were actually taken from the cache on a successful collection.
async fn collect_real_wireguard(
    use_cache: bool,
    cached_findings: Option<Vec<FindingEntry>>,
) -> (WireguardDataBundle, bool) {
    // Build the WireguardClient on the blocking pool. Construction is lazy
    // (it does NOT probe for `wg`), so it is effectively infallible here —
    // binary availability is surfaced by the cheap probes below and by the
    // doctor suite, and a missing `wg` instead surfaces as an error from the
    // first show()/list_peers() call inside collection. Built INSIDE
    // spawn_blocking exactly like collect_real_fail2ban / collect_real_harden.
    let client = match tokio::task::spawn_blocking(|| {
        toride_wireguard::client::WireguardClient::new()
    })
    .await
    {
        Ok(Ok(client)) => client,
        Ok(Err(e)) => {
            // Construction failed (rare; new() is lazy, so this is not the
            // missing-`wg` path — that surfaces later during collection).
            tracing::debug!("wireguard construction failed: {e}");
            return (
                empty_bundle_with_reason(format!("wireguard backend unavailable: {e}")),
                false,
            );
        }
        Err(e) => {
            tracing::warn!("wireguard construction task panicked: {e}");
            return (
                empty_bundle_with_reason(format!("wireguard backend construction panicked: {e}")),
                false,
            );
        }
    };

    // Run ALL blocking probes in a single spawn_blocking that owns `client`.
    // This keeps every shell-out / file read off the tokio worker and
    // sidesteps the 'static-borrow problem: each interface spawns its own
    // showconf / peer-list / service probe, so collecting everything in one
    // owned closure is both simpler and cheaper than spawning one task per
    // probe. Results are returned as plain owned data so they cross the thread
    // boundary cleanly. Doctor findings are taken from the cache when fresh
    // (`use_cache`), otherwise re-run here.
    let result = tokio::task::spawn_blocking(move || {
        // ── Findings (doctor) — the ONLY part gated by the 60s cache ──────
        // Mirror the fail2ban reference idiom (fail2ban_data.rs:219-229): the
        // expensive doctor suite is what we cache, and ONLY its findings Vec.
        // The doctor carries binary-availability + config-dir probes that
        // surface the missing-`wg` finding on macOS; DoctorScope::All runs
        // every check the backend implements (binaries, config dir,
        // interfaces, key permissions, dns leak — most are TODOs today). The
        // cheap binary / config-dir probes below are re-run every poll so the
        // Environment panel never flickers to "? unknown" on a cache-hit tick
        // (~29 of every 30 refresh ticks at the 2s cadence). On a doctor
        // error we surface no findings but still keep the cheap probes live.
        let findings: Vec<FindingEntry> = if use_cache {
            cached_findings.unwrap_or_default()
        } else {
            match toride_wireguard::doctor::Doctor::new()
                .run(&toride_wireguard::doctor::DoctorScope::All)
            {
                Ok(report) => toride_wireguard_convert::convert_findings(report.findings),
                Err(e) => {
                    tracing::warn!("wireguard doctor: {e}");
                    Vec::new()
                }
            }
        };

        // ── Cheap probes — re-run EVERY poll, outside the cache ──────────
        // Two `which::which` calls + one `is_dir`, exactly what the doctor
        // itself does (doctor.rs:94, 106, 124) and exactly what fail2ban does
        // for nft/iptables availability (fail2ban_data.rs:283-285). Cheap
        // enough to run on every 2s tick, never None, so the Environment
        // badges stay stable. `WireguardPaths::new()` points at `/etc/wireguard`
        // — the same root the doctor stats.
        let wg_binary_found = which::which("wg").is_ok();
        let wg_quick_binary_found = which::which("wg-quick").is_ok();
        let paths = toride_wireguard::paths::WireguardPaths::new();
        let config_dir_exists = paths.root().is_dir();

        // ── Interfaces via `wg show` ──────────────────────────────────────
        let interfaces: Vec<InterfaceEntry> = match client.show() {
            Ok(entries) => entries
                .iter()
                .map(toride_wireguard_convert::convert_show_entry)
                .collect(),
            Err(e) => {
                tracing::debug!("wireguard show: {e}");
                Vec::new()
            }
        };

        // ── Peers per interface + per-interface service activity ──────────
        // list_peers is the runtime peer list (via `wg show <iface> peers`).
        // WireguardService::is_active() probes the systemd unit. The on-disk
        // config (ConfigManager) is feature-gated behind `config`, which is NOT
        // in the default feature set, so we surface on-disk presence via the
        // `WireguardPaths` helper directly (the same `is_file()` check
        // `ConfigManager::exists` performs) without importing the gated module.
        // NOTE: `paths` is declared above alongside the cheap probes so the
        // config_dir check can share it.

        let mut peers: Vec<PeerEntry> = Vec::new();
        let mut services: Vec<ServiceEntry> = Vec::new();

        for iface in &interfaces {
            // Runtime peer list.
            let mgr = toride_wireguard::peer::PeerManager::new(&iface.name);
            match mgr.list_peers() {
                Ok(specs) => {
                    for spec in &specs {
                        peers.push(toride_wireguard_convert::convert_peer(spec));
                    }
                }
                Err(e) => {
                    tracing::debug!("wireguard list_peers {}: {e}", iface.name);
                }
            }

            // Per-interface systemd unit activity.
            let svc = toride_wireguard::service::WireguardService::new(&iface.name);
            let is_active = svc.is_active().unwrap_or(false);
            services.push(toride_wireguard_convert::convert_service(
                svc.service_name(),
                is_active,
                // is_enabled is not currently exposed by the backend; leave
                // None so the UI renders "unknown".
                None,
            ));
        }

        // ── Availability heuristic ────────────────────────────────────────
        // The section is "available" if EITHER the client returned any
        // interface OR the doctor produced any findings. A host with `wg`
        // missing yields an Error finding (binary.wg) but no interfaces —
        // that still counts as available so the operator SEES the finding
        // rather than a blank panel. A host where construction failed
        // entirely (BinaryNotFound) never reaches this code path; it returns
        // the degraded bundle above.
        let available = !interfaces.is_empty() || !findings.is_empty();

        WireguardDataBundle {
            available,
            interfaces,
            peers,
            services,
            wg_binary_found: Some(wg_binary_found),
            wg_quick_binary_found: Some(wg_quick_binary_found),
            config_dir_exists: Some(config_dir_exists),
            findings,
            // Success path: no panic, no construction failure, so no reason.
            unavailable_reason: None,
        }
    })
    .await;

    match result {
        Ok(bundle) => (bundle, use_cache),
        Err(e) => {
            tracing::warn!("wireguard collection task panicked: {e}");
            (
                empty_bundle_with_reason(format!("wireguard data collection panicked: {e}")),
                false,
            )
        }
    }
}

/// Empty bundle used when wireguard could not be constructed at all.
///
/// `available = false` signals the UI to render the degraded panel. No reason
/// is attached because none is known at this point; collection-time panics use
/// [`empty_bundle_with_reason`] to surface the `JoinError`.
fn empty_bundle() -> WireguardDataBundle {
    WireguardDataBundle {
        available: false,
        interfaces: Vec::new(),
        peers: Vec::new(),
        services: Vec::new(),
        wg_binary_found: None,
        wg_quick_binary_found: None,
        config_dir_exists: None,
        findings: Vec::new(),
        unavailable_reason: None,
    }
}

/// Empty bundle carrying the reason collection failed. Used when a
/// `spawn_blocking` task panicked (`JoinError`) during construction or
/// collection — `WireguardClient::new()` is lazy and effectively infallible,
/// so in practice this is reached only on a panic, not on a missing `wg`
/// binary (which surfaces as a doctor finding / collection error instead).
/// The reason string is rendered by the UI's degraded panel so the operator
/// sees what actually went wrong.
fn empty_bundle_with_reason(reason: String) -> WireguardDataBundle {
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
        let collector = WireguardCollector::new();
        assert!(!collector.is_pending());
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(
            WireguardCollector::new().is_pending(),
            WireguardCollector::default().is_pending()
        );
    }

    #[tokio::test]
    async fn start_makes_pending() {
        let mut collector = WireguardCollector::new();
        assert!(!collector.is_pending());
        collector.start();
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn start_is_idempotent() {
        let mut collector = WireguardCollector::new();
        collector.start();
        assert!(collector.is_pending());
        collector.start(); // no-op, does not replace the receiver
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn poll_returns_none_when_not_started() {
        let mut collector = WireguardCollector::new();
        assert!(collector.poll().await.is_none());
    }

    #[tokio::test]
    async fn poll_clears_pending() {
        let mut collector = WireguardCollector::new();
        collector.start();
        // Let the spawned task complete (it shells out, so give it time).
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let _ = collector.poll().await;
        assert!(!collector.is_pending(), "poll should clear pending state");
    }

    #[tokio::test]
    async fn poll_returns_bundle_after_collection() {
        // On any host (including macOS without wg) the collector must
        // return Some(bundle) after start() + enough time. The bundle's
        // `available` flag reflects whether wg was found.
        let mut collector = WireguardCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let bundle = collector.poll().await;
        assert!(bundle.is_some(), "poll should return Some after completion");
    }

    #[test]
    fn empty_bundle_is_unavailable() {
        let b = empty_bundle();
        assert!(!b.available);
        assert!(b.interfaces.is_empty());
        assert!(b.peers.is_empty());
        assert!(b.services.is_empty());
        assert!(b.findings.is_empty());
        assert!(b.wg_binary_found.is_none());
        assert!(b.wg_quick_binary_found.is_none());
        assert!(b.config_dir_exists.is_none());
        assert!(
            b.unavailable_reason.is_none(),
            "empty_bundle carries no reason; construction failures / panics use empty_bundle_with_reason"
        );
    }

    #[test]
    fn empty_bundle_with_reason_carries_reason() {
        let b = empty_bundle_with_reason("BinaryNotFound: wg".into());
        assert!(!b.available);
        assert_eq!(b.unavailable_reason.as_deref(), Some("BinaryNotFound: wg"));
    }

    #[tokio::test]
    async fn findings_cache_is_populated_after_poll() {
        let mut collector = WireguardCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let _ = collector.poll().await;
        // After a successful poll the cache is populated (even if to an empty
        // Vec on a host where the doctor produced no findings).
        assert!(collector.cached_findings.is_some());
        assert!(collector.findings_fresh_at.is_some());
    }

    /// Regression guard for the cache-boundary fix: on a CACHE-HIT poll
    /// (`use_cache == true`) the cheap binary / config-dir probes MUST still be
    /// re-run and returned as `Some(_)`, not `None`. The old code cached the
    /// whole doctor bundle (including these probes), so every cache-hit poll
    /// returned `None` for ~58s out of every 60s and the Environment panel
    /// flickered to "? unknown". Mirrors fail2ban's idiom where nft/iptables
    /// availability is re-probed every poll outside the doctor cache.
    #[tokio::test]
    async fn cache_hit_poll_still_probes_binaries() {
        // Simulate a cache-hit poll: findings are taken from the cache
        // (`use_cache == true`, cached_findings supplied) but the cheap probes
        // must still run and be `Some`.
        let (bundle, used_cache) = collect_real_wireguard(true, Some(Vec::new())).await;
        assert!(used_cache, "cache-hit poll must report used_cache == true");
        // The probes are re-run regardless of the cache; they are real
        // which::which / is_dir results so they are always Some(_).
        assert!(
            bundle.wg_binary_found.is_some(),
            "wg_binary_found must be Some(_) on a cache-hit poll, not None"
        );
        assert!(
            bundle.wg_quick_binary_found.is_some(),
            "wg_quick_binary_found must be Some(_) on a cache-hit poll, not None"
        );
        assert!(
            bundle.config_dir_exists.is_some(),
            "config_dir_exists must be Some(_) on a cache-hit poll, not None"
        );
    }

    #[test]
    fn invalidate_findings_cache_clears_it() {
        let mut collector = WireguardCollector::new();
        collector.cached_findings = Some(Vec::new());
        collector.findings_fresh_at = Some(std::time::Instant::now());
        collector.invalidate_findings_cache();
        assert!(collector.cached_findings.is_none());
        assert!(collector.findings_fresh_at.is_none());
    }
}
