//! Async Tailscale data collection (LIVE READ-ONLY).
//!
//! [`TailscaleCollector`] manages background collection of all Tailscale subsystem data
//! via a tokio oneshot channel, following the same pattern as
//! [`StatusCollector`](crate::status_collector::StatusCollector),
//! [`SshDataCollector`](crate::ssh_data::SshDataCollector), and (the closest analogue)
//! [`Fail2banCollector`](crate::fail2ban_data::Fail2banCollector).
//!
//! This is the TEMPLATE read-only integration. It mirrors `Fail2banCollector` MINUS the
//! entire write path — there are no operations, no optimistic updates, no cooldown gate,
//! and no loading spinner. Every call to the backend is a pure read.
//!
//! ## Async / network
//!
//! Unlike fail2ban/cloud (which shell out synchronously and so use `spawn_blocking`), the
//! Tailscale backend talks to the local daemon over HTTP (`localhost:41642`) via async
//! `reqwest`. So [`TailscaleClient::new`] (a sync ctor — it only builds the HTTP client,
//! no network) is built ONCE per collection and its async methods are awaited directly
//! inside the spawned `tokio::spawn(async move { ... })` task — NOT inside
//! `spawn_blocking`. This mirrors `ssh_data`'s direct-async pattern (the SSH services are
//! also async).
//!
//! ## Timeouts / degradation
//!
//! Every network call (`status_report`, `is_connected`, `topology`, `netcheck`,
//! `dns_config`, `Doctor::run`) is wrapped in [`tokio::time::timeout`] with a ~3s budget.
//! An absent `tailscaled` (the common case on a dev box without Tailscale) will refuse
//! the connection quickly, but a hung/blackholed `localhost:41642` must not stall the
//! collector task — the timeout caps each probe independently. A timed-out or errored
//! probe degrades that field but the collector keeps going; the section stays
//! `available == true` whenever ANY probe succeeded or the doctor produced findings, so
//! the operator sees what is wrong rather than a blank panel. Only a task panic (`JoinError`)
//! flips `available` to `false`.
//!
//! ## Doctor findings cache
//!
//! `Doctor::run` is expensive (it itself fans out to `is_connected` / `dns_config` /
//! `which::which`, each of which is a network call or binary lookup) and changes slowly,
//! so findings are cached for 60s — exactly like the fail2ban / cloud findings caches.

use std::time::Duration;

use tokio::sync::oneshot;

use crate::toride_tailscale_convert::{self, NetcheckInfo, NodeStatusInfo};
use crate::ui::screens::toride_tailscale::{
    DerpLatencyEntry, DnsInfo, PeerEntry, PortMapEntry, TailscaleFindingEntry,
};

/// Per-network-call timeout. Generous enough for a healthy local daemon (sub-10ms) but
/// short enough that an absent/hung `tailscaled` cannot stall the collector task.
const NET_TIMEOUT: Duration = Duration::from_secs(3);

/// Aggregated Tailscale data for the read-only section.
#[derive(Clone, Debug)]
pub struct TailscaleDataBundle {
    /// Whether the Tailscale backend was reachable at all. `false` is reserved for the
    /// panic case (a `tokio::spawn` `JoinError`) — an absent daemon degrades individual
    /// probes but the doctor surfaces that as a `critical` finding, keeping
    /// `available == true` so the operator SEES the finding rather than a blank panel.
    pub available: bool,
    /// Local-node status (connected, name, tailnet, IPs, exit node, `MagicDNS`).
    pub status: NodeStatusInfo,
    /// Peers in the tailnet (from the topology query).
    pub peers: Vec<PeerEntry>,
    /// Netcheck / DERP report (may be partially populated if a probe timed out).
    pub netcheck: NetcheckInfo,
    /// DNS configuration (from the dedicated DNS query).
    pub dns: DnsInfo,
    /// Doctor findings (cached for 60s between collections).
    pub findings: Vec<TailscaleFindingEntry>,
    /// Human-readable reason the backend was unreachable, populated ONLY when
    /// `available == false` because a collection task panicked (`JoinError`). `None`
    /// otherwise — notably also `None` for a freshly-constructed empty bundle before any
    /// collection has run. Surfaced to the UI so the degraded panel can show what
    /// actually went wrong instead of guessing.
    pub unavailable_reason: Option<String>,
}

// ── Collector ───────────────────────────────────────────────────────────────

/// Manages periodic async collection of Tailscale data.
///
/// Mirrors [`Fail2banCollector`](crate::fail2ban_data::Fail2banCollector): a oneshot
/// channel for the in-flight result, plus a 60s TTL cache for the expensive doctor
/// findings so they are not re-run on every 2s refresh tick.
pub struct TailscaleCollector {
    /// Carries the bundle AND whether the cached findings were reused for this poll.
    /// The freshness timestamp must only be advanced when the doctor was actually re-run
    /// (`used_cache == false`); otherwise every cache-hit poll would reset the TTL clock
    /// with the SAME (already-cached) findings and the cache would never expire for the
    /// lifetime of the app.
    rx: Option<oneshot::Receiver<(TailscaleDataBundle, bool)>>,
    /// Cached doctor findings from the last collection.
    cached_findings: Option<Vec<TailscaleFindingEntry>>,
    /// When the findings cache was last refreshed.
    findings_fresh_at: Option<std::time::Instant>,
}

/// How long to keep cached findings before re-running the doctor suite.
#[expect(
    clippy::duration_suboptimal_units,
    reason = "stable std lacks from_mins"
)]
const FINDINGS_TTL: Duration = Duration::from_secs(60);

impl TailscaleCollector {
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
    /// If a collection is already in-flight, this is a no-op. The 60s findings cache is
    /// consulted: when fresh, the spawned task reuses the cached findings instead of
    /// re-running the doctor suite.
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
        // The backend client is built OUTSIDE the hot loop (a sync ctor — no network),
        // and its async methods are awaited directly inside the spawned task. reqwest is
        // async, so (unlike fail2ban/cloud) there is NO spawn_blocking here — mirroring
        // ssh_data's direct-async pattern. The inner task body is itself spawned and
        // awaited so a JoinError (panic inside `collect_real_tailscale` / `doctor_run`)
        // is matched here and surfaced as a degraded `available == false` bundle with a
        // reason — mirroring the spawn_blocking JoinError path in fail2ban/cloud/etc.
        // Without this wrap a panic would drop `tx`, `rx.await` would return `Err`, and
        // poll() would map that to `None`, leaving the dashboard showing stale last-good
        // data indefinitely with no degraded-state signal.
        let handle =
            tokio::spawn(async move { collect_real_tailscale(use_cache, cached_findings).await });
        tokio::spawn(async move {
            let result = handle.await;
            let (bundle, reused_cache) = match result {
                Ok(tuple) => tuple,
                Err(e) => {
                    tracing::warn!("tailscale data collection panicked: {e}");
                    (
                        empty_bundle_with_reason(format!(
                            "tailscale data collection panicked: {e}"
                        )),
                        false,
                    )
                }
            };
            let _ = tx.send((bundle, reused_cache));
        });
    }

    /// Poll for a completed collection result.
    ///
    /// Returns `Some(bundle)` if the collection completed, `None` if still pending or if
    /// the collection failed. On success the cached findings are updated to the
    /// freshly-returned findings, but the freshness timestamp is only advanced when the
    /// doctor was actually re-run (not on a cache-hit poll) — otherwise the 60s TTL
    /// would be re-armed forever with the same cached data on every 2s refresh.
    pub async fn poll(&mut self) -> Option<TailscaleDataBundle> {
        match &mut self.rx {
            Some(rx) => {
                let result = rx.await.ok();
                if let Some((ref bundle, used_cache)) = result {
                    self.cached_findings = Some(bundle.findings.clone());
                    // Only advance the freshness clock when the doctor was actually
                    // re-run. On a cache-hit poll the findings are the SAME data we
                    // already cached, so resetting the TTL here would let the cache live
                    // forever as long as the 2s refresh tick keeps firing inside the TTL
                    // window.
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

impl Default for TailscaleCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Real data collection ────────────────────────────────────────────────────

/// Collect Tailscale data by querying the local daemon over HTTP.
///
/// All probes run concurrently via `tokio::join!`. Each network call is individually
/// wrapped in [`tokio::time::timeout(NET_TIMEOUT)`] so an absent or hung `tailscaled`
/// cannot stall the task — a timed-out probe degrades its field but the collection keeps
/// going. Doctor findings may be reused from the cache. On ANY panic (`JoinError` from the
/// outer `tokio::spawn` — the inner probes cannot panic because they use `?`/match)
/// returns [`empty_bundle_with_reason`] with `available = false`.
///
/// `use_cache` / `cached_findings` mirror the fail2ban findings cache: when the cache is
/// fresh the doctor suite is skipped entirely.
///
/// Returns `(bundle, used_cache)` where `used_cache` records whether the findings were
/// actually taken from the cache on a successful collection. The caller advances the TTL
/// clock ONLY when `used_cache == false`, so a cache-hit poll never resets the freshness
/// timestamp with stale data.
#[expect(
    clippy::similar_names,
    reason = "use_cache (input) vs used_cache (output) are distinct domain flags"
)]
async fn collect_real_tailscale(
    use_cache: bool,
    cached_findings: Option<Vec<TailscaleFindingEntry>>,
) -> (TailscaleDataBundle, bool) {
    // Build the client once (sync ctor, no network). Construction cannot fail today —
    // `TailscaleClient::new` only allocates a reqwest client — so there is no
    // construction-error branch; the first network call below surfaces a missing daemon.
    let client = toride_tailscale::TailscaleClient::new();

    // Run all probes concurrently. Each is independently timeout-bounded so one hung
    // probe cannot block the others. A timed-out or errored probe yields `None` for its
    // subsystem and the bundle is assembled from whatever succeeded.
    //
    // The doctor is skipped when the cache is fresh; its slot is computed after the join
    // from either the cache or the freshly-run report.
    let (status_r, topology_r, netcheck_r, dns_r, doctor_r) = tokio::join!(
        timeout_probe(async {
            client
                .status_report()
                .await
                .map(toride_tailscale_convert::convert_status)
        }),
        timeout_probe(async { client.topology().await }),
        timeout_probe(async {
            client
                .netcheck()
                .await
                .map(toride_tailscale_convert::convert_netcheck)
        }),
        timeout_probe(async {
            client
                .dns_config()
                .await
                .map(toride_tailscale_convert::convert_dns)
        }),
        async {
            if use_cache {
                None
            } else {
                Some(timeout_probe(async { doctor_run(&client).await }).await)
            }
        },
    );

    // ── Assemble the bundle from whatever probes returned ───────────────────
    let status = status_r.unwrap_or_else(empty_status);
    // topology_r is Option<TailnetTopology> — timeout_probe already collapsed
    // Result/timeout into None.
    let (peers, topology_ok) = match topology_r {
        Some(topo) => (toride_tailscale_convert::convert_peers(topo.peers()), true),
        None => (Vec::new(), false),
    };
    let netcheck_reachable = netcheck_r.is_some();
    let netcheck = netcheck_r.unwrap_or_else(empty_netcheck);
    let dns = dns_r.unwrap_or_else(empty_dns);

    // Findings: cache-hit when use_cache (reused below), otherwise from the doctor probe.
    // doctor_r is Option<Option<DoctorReport>> — the outer Option is "did we run the
    // doctor at all" (None when use_cache), the inner Option is "did the doctor probe
    // succeed" (None on timeout/error, already collapsed by timeout_probe).
    let (findings, used_cache) = if use_cache {
        (cached_findings.unwrap_or_default(), true)
    } else {
        let f = match doctor_r {
            Some(Some(report)) => toride_tailscale_convert::convert_findings(report.findings),
            // doctor ran but the probe timed out / errored — timeout_probe already
            // logged the failure, so there is nothing to surface beyond an empty list.
            Some(None) | None => Vec::new(),
        };
        (f, false)
    };

    // ── Availability heuristic ──────────────────────────────────────────────
    // The section is "available" whenever the daemon answered ANY probe OR the doctor
    // produced any finding. A host with tailscaled absent fails every probe AND the
    // doctor yields a `critical` finding (via the binary/connected checks, which do not
    // need the HTTP API for the binary check) — so an absent daemon still surfaces the
    // findings and stays `available == true`. Only a task panic flips this to `false`,
    // and that case never reaches this point: the panic is caught as a JoinError in
    // `start()`'s outer spawn, which returns [`empty_bundle_with_reason`] instead of
    // calling this function.
    let available = status.connected
        || !peers.is_empty()
        || !status.ip_addresses.is_empty()
        || !findings.is_empty()
        || topology_ok
        || netcheck_reachable;

    (
        TailscaleDataBundle {
            available,
            status,
            peers,
            netcheck,
            dns,
            findings,
            unavailable_reason: None,
        },
        used_cache,
    )
}

/// Run a future under a network timeout, mapping both the timeout and any backend error
/// to `None` so the caller's probe result is uniformly `Option<Result<T, _>>`-shaped.
///
/// The `E` error is logged at `debug` (a refused localhost connection is expected on
/// hosts without Tailscale); the timeout case is logged at `warn` (a hung daemon is
/// unusual and worth surfacing).
async fn timeout_probe<T, E>(fut: impl std::future::Future<Output = Result<T, E>>) -> Option<T>
where
    E: std::fmt::Display,
{
    match tokio::time::timeout(NET_TIMEOUT, fut).await {
        Ok(Ok(value)) => Some(value),
        Ok(Err(e)) => {
            tracing::debug!("tailscale probe failed: {e}");
            None
        }
        Err(_elapsed) => {
            tracing::warn!("tailscale probe timed out after {:?}", NET_TIMEOUT);
            None
        }
    }
}

/// Run the doctor suite against `client`, returning the raw [`DoctorReport`].
///
/// `Doctor::run` is itself async and fans out to `is_connected` / `dns_config` /
/// `which::which`; the caller's `timeout_probe` wrapper bounds the whole suite at
/// `NET_TIMEOUT`, which is ample for the binary check and the two extra HTTP calls it
/// makes (both also bounded individually by reqwest's own timeouts).
///
/// [`DoctorReport`]: toride_tailscale::doctor::DoctorReport
async fn doctor_run(
    client: &toride_tailscale::TailscaleClient,
) -> Result<toride_tailscale::doctor::DoctorReport, toride_tailscale::Error> {
    let doctor = toride_tailscale::doctor::Doctor::new(client);
    doctor
        .run(&toride_tailscale::doctor::DoctorScope::All)
        .await
}

/// Default empty node status (everything zeroed / placeholder).
fn empty_status() -> NodeStatusInfo {
    NodeStatusInfo {
        connected: false,
        node_name: String::new(),
        tailnet: String::new(),
        ip_addresses: Vec::new(),
        exit_node: None,
        dns_enabled: false,
    }
}

/// Default empty netcheck.
fn empty_netcheck() -> NetcheckInfo {
    NetcheckInfo {
        connectivity: false,
        derp_region: None,
        derp_latency: Vec::<DerpLatencyEntry>::new(),
        udp: false,
        ipv6: false,
        hairpin: false,
        port_mapping: Vec::<PortMapEntry>::new(),
    }
}

/// Default empty DNS configuration.
fn empty_dns() -> DnsInfo {
    DnsInfo {
        magic_dns: false,
        nameservers: Vec::new(),
        search_domains: Vec::new(),
        split_dns: Vec::new(),
    }
}

/// Empty bundle used when the collection task panicked (`tokio::spawn` `JoinError`) —
/// mirrors [`fail2ban_data::empty_bundle`] and the sibling collectors. `available = false`
/// signals the UI to render the degraded panel; no reason is attached because none is
/// known at this point (the `JoinError` reason is added by [`empty_bundle_with_reason`]).
///
/// [`fail2ban_data::empty_bundle`]: crate::fail2ban_data::empty_bundle
fn empty_bundle() -> TailscaleDataBundle {
    TailscaleDataBundle {
        available: false,
        status: empty_status(),
        peers: Vec::new(),
        netcheck: empty_netcheck(),
        dns: empty_dns(),
        findings: Vec::new(),
        unavailable_reason: None,
    }
}

/// Empty bundle carrying the reason collection failed. Used when the spawned collection
/// task panicked (`JoinError`) — the reason string is rendered by the UI's degraded panel
/// so the operator sees what actually went wrong, mirroring the `spawn_blocking` `JoinError`
/// path in fail2ban/cloud/etc.
fn empty_bundle_with_reason(reason: String) -> TailscaleDataBundle {
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
        let collector = TailscaleCollector::new();
        assert!(!collector.is_pending());
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(
            TailscaleCollector::new().is_pending(),
            TailscaleCollector::default().is_pending()
        );
    }

    #[tokio::test]
    async fn start_makes_pending() {
        let mut collector = TailscaleCollector::new();
        assert!(!collector.is_pending());
        collector.start();
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn start_is_idempotent() {
        let mut collector = TailscaleCollector::new();
        collector.start();
        assert!(collector.is_pending());
        collector.start(); // no-op, does not replace the receiver
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn poll_returns_none_when_not_started() {
        let mut collector = TailscaleCollector::new();
        assert!(collector.poll().await.is_none());
    }

    #[tokio::test]
    async fn poll_clears_pending() {
        let mut collector = TailscaleCollector::new();
        collector.start();
        // The probes are bounded by NET_TIMEOUT (3s) so the task completes quickly even
        // when the daemon is absent (refused connection returns near-instantly).
        tokio::time::sleep(Duration::from_millis(3500)).await;
        let _ = collector.poll().await;
        assert!(!collector.is_pending(), "poll should clear pending state");
    }

    #[tokio::test]
    async fn poll_returns_bundle_after_collection() {
        // On any host (including one without tailscaled) the collector must return
        // Some(bundle) after start() + enough time. available reflects whether the
        // daemon answered or the doctor produced findings.
        let mut collector = TailscaleCollector::new();
        collector.start();
        tokio::time::sleep(Duration::from_secs(4)).await;
        let bundle = collector.poll().await;
        assert!(bundle.is_some(), "poll should return Some after completion");
    }

    #[test]
    fn empty_status_is_zeroed() {
        let s = empty_status();
        assert!(!s.connected);
        assert!(s.node_name.is_empty());
        assert!(s.ip_addresses.is_empty());
        assert!(s.exit_node.is_none());
    }

    #[test]
    fn empty_netcheck_is_zeroed() {
        let n = empty_netcheck();
        assert!(!n.connectivity);
        assert!(n.derp_latency.is_empty());
        assert!(!n.udp);
    }

    #[test]
    fn empty_bundle_is_unavailable() {
        let b = empty_bundle();
        assert!(!b.available);
        assert!(b.peers.is_empty());
        assert!(b.findings.is_empty());
        assert!(b.status.node_name.is_empty());
        assert!(
            b.unavailable_reason.is_none(),
            "empty_bundle carries no reason; panics use empty_bundle_with_reason"
        );
    }

    #[test]
    fn empty_bundle_with_reason_carries_reason() {
        let b = empty_bundle_with_reason("tailscale data collection panicked: boom".into());
        assert!(!b.available);
        assert_eq!(
            b.unavailable_reason.as_deref(),
            Some("tailscale data collection panicked: boom")
        );
    }

    #[tokio::test]
    async fn findings_cache_is_populated_after_poll() {
        let mut collector = TailscaleCollector::new();
        collector.start();
        tokio::time::sleep(Duration::from_secs(4)).await;
        let _ = collector.poll().await;
        // After a successful poll the cache is populated (even if to an empty Vec on a
        // host where the doctor produced no findings).
        assert!(collector.cached_findings.is_some());
        assert!(collector.findings_fresh_at.is_some());
    }

    #[test]
    fn invalidate_findings_cache_clears_it() {
        let mut collector = TailscaleCollector::new();
        collector.cached_findings = Some(Vec::new());
        collector.findings_fresh_at = Some(std::time::Instant::now());
        collector.invalidate_findings_cache();
        assert!(collector.cached_findings.is_none());
        assert!(collector.findings_fresh_at.is_none());
    }
}
