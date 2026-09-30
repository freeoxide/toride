//! Async outbound-traffic-monitor data collection (LIVE READ-ONLY).
//!
//! [`MonitorCollector`] manages background collection of all monitor
//! subsystem data via a tokio oneshot channel, following the exact same
//! pattern as [`Fail2banCollector`](crate::fail2ban_data::Fail2banCollector)
//! and [`StatusCollector`](crate::status_collector::StatusCollector).
//!
//! This mirrors the fail2ban / SSH reference MINUS the entire write path —
//! there are no write operations, no optimistic updates, no cooldown gate, and
//! no loading spinner. Every call to the backend is a pure read.
//!
//! Two-tier cache (F11): doctor findings shell out (`iptables-save`, `which`,
//! etc.) and change slowly, so they are cached for 60s like the fail2ban /
//! SSH diagnostics caches. The SNAPSHOT cluster (`ss -tunap` +
//! `conntrack -L` + anomaly detection + the OUTPUT-rule count) gets a much
//! shorter TTL — 8s — because anomaly detection consumes snapshots: the
//! window stays bounded for detection while the per-2s-tick spawn storm
//! (2 subprocesses/tick + the iptables-save pass) drops to a fifth. The
//! listening-ports enumeration is native (netstat2, no subprocess) and stays
//! fresh every collection.
//!
//! ## macOS / construction
//!
//! [`MonitorClient::system`](toride_monitor::client::MonitorClient::system)
//! resolves `iptables`,
//! `iptables-save`, `conntrack`, `ss`, and `journalctl` via `which`. On macOS
//! none of these are on `$PATH`, so construction returns
//! `Err(BinaryNotFound)` and the whole section degrades to `available = false`
//! with the reason surfaced in the UI. On Linux the constructor succeeds and
//! individual probes degrade per-field (a missing `conntrack` binary leaves
//! the conntrack summary `None` but keeps the section available).
//!
//! ## Blocking
//!
//! The `DuctRunner` / `netstat2` calls are synchronous. All backend work is
//! wrapped in [`tokio::task::spawn_blocking`] so the tokio worker is never
//! stalled.

use tokio::sync::oneshot;

use crate::toride_monitor_convert;
use crate::ui::screens::toride_monitor::{
    AnomalyEntry, ConnectionEntry, ConntrackSummary, FindingEntry, PortEntry, SnapshotSummary,
};

/// Aggregated monitor data for the read-only section.
#[derive(Clone, Debug)]
pub struct MonitorDataBundle {
    /// Whether the monitor backend was reachable at all. `false` when
    /// `MonitorClient::system()` failed (typically `BinaryNotFound` on macOS)
    /// or when a collection task panicked — the UI renders a degraded
    /// "unavailable" panel.
    pub available: bool,
    /// Aggregated snapshot counters.
    pub summary: SnapshotSummary,
    /// Outbound connections table.
    pub connections: Vec<ConnectionEntry>,
    /// Listening ports.
    pub ports: Vec<PortEntry>,
    /// Conntrack counters.
    pub conntrack: ConntrackSummary,
    /// Number of installed OUTPUT chain LOG rules (`None` if the probe failed).
    pub output_rule_count: Option<usize>,
    /// Anomaly findings (from `MonitorClient::detect`).
    pub anomalies: Vec<AnomalyEntry>,
    /// Doctor findings (cached for 60s between collections).
    pub findings: Vec<FindingEntry>,
    /// Human-readable reason the backend was unreachable, populated ONLY when
    /// `available == false` (construction `Err`, or a panicked collection
    /// task). `None` otherwise. Surfaced to the UI so the degraded panel can
    /// show what actually went wrong instead of guessing.
    pub unavailable_reason: Option<String>,
}

// ── Collector ───────────────────────────────────────────────────────────────

/// What one monitor collection hands back: the bundle, which cache tier was
/// served, and the fresh snapshot cluster (present only when the snapshot
/// re-ran, mirroring the proxy collector's fresh-report hand-back).
type MonitorOutcome = (
    MonitorDataBundle,
    bool,                    // findings served from cache
    bool,                    // snapshot cluster served from cache
    Option<SnapshotCluster>, // fresh cluster, when re-run
);

/// The subprocess-spawning snapshot cluster, cached at the short
/// [`SNAPSHOT_TTL`] so anomaly detection keeps a bounded detection window.
#[derive(Clone, Debug)]
struct SnapshotCluster {
    /// Aggregated snapshot counters (`ss` + conntrack aggregates).
    summary: SnapshotSummary,
    /// Outbound connections table (parsed `ss -tunap` rows).
    connections: Vec<ConnectionEntry>,
    /// Anomaly findings derived from the snapshot report.
    anomalies: Vec<AnomalyEntry>,
    /// Conntrack counters (fast count + snapshot aggregates).
    conntrack: ConntrackSummary,
    /// Installed OUTPUT chain LOG rule count (`iptables-save` pass).
    output_rule_count: Option<usize>,
    /// Whether `client.snapshot()` itself succeeded — the availability
    /// heuristic's canonical "is the monitor actually working" signal.
    snapshot_ok: bool,
}

/// Manages periodic async collection of monitor data.
///
/// Two-tier cache: the doctor findings at `FINDINGS_TTL` (60s, like the
/// sibling read-only collectors) and the snapshot cluster at
/// `SNAPSHOT_TTL` (8s — short because anomaly detection consumes
/// snapshots; the window stays bounded without re-spawning every 2s tick).
pub struct MonitorCollector {
    /// Carries the [`MonitorOutcome`] for the in-flight collection.
    rx: Option<oneshot::Receiver<MonitorOutcome>>,
    /// Cached doctor findings from the last collection.
    cached_findings: Option<Vec<FindingEntry>>,
    /// When the findings cache was last refreshed.
    findings_fresh_at: Option<std::time::Instant>,
    /// Cached snapshot cluster from the last snapshot run.
    cached_snapshot: Option<SnapshotCluster>,
    /// When the snapshot cache was last refreshed.
    snapshot_fresh_at: Option<std::time::Instant>,
}

/// How long to keep cached findings before re-running the doctor suite.
const FINDINGS_TTL: std::time::Duration = std::time::Duration::from_mins(1);

/// How long to keep the cached snapshot cluster before re-running `ss
/// -tunap` + `conntrack -L` + anomaly detection.
///
/// Deliberate freshness semantics (F11): the anomaly detector consumes
/// snapshots, so the staleness window must stay inside the product's
/// detection window — 8s keeps a connection visible to detection well within
/// a 10s window while cutting the per-tick spawn storm (2 subprocesses per
/// 2s tick, 30×/minute) to a fifth.
const SNAPSHOT_TTL: std::time::Duration = std::time::Duration::from_secs(8);

/// Whether a cache TTL has already elapsed for an entry refreshed at
/// `fresh_at`.
///
/// Round-0 instrumentation seam pattern, ZERO behavior change outside
/// `cfg(test)`: the thread-local [`TTL_TEST_OFFSET_MS`] is folded into the
/// elapsed time so cadence oracles can observe each tier's TTL expiry
/// deterministically (no sleeps, no host-uptime dependence).
fn ttl_expired(ttl: std::time::Duration, fresh_at: std::time::Instant) -> bool {
    let elapsed = fresh_at.elapsed();
    #[cfg(test)]
    let elapsed =
        elapsed + std::time::Duration::from_millis(TTL_TEST_OFFSET_MS.with(std::cell::Cell::get));
    elapsed >= ttl
}

// Extra milliseconds folded into `ttl_expired`'s elapsed time by the cadence
// oracles. Test-only. (Plain comments: rustdoc does not document macro
// invocations, so a doc comment here warns as unused.)
#[cfg(test)]
thread_local! {
    static TTL_TEST_OFFSET_MS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

impl MonitorCollector {
    /// Create a new collector with no pending collection.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rx: None,
            cached_findings: None,
            findings_fresh_at: None,
            cached_snapshot: None,
            snapshot_fresh_at: None,
        }
    }

    /// Whether a collection is currently in-flight.
    pub fn is_pending(&self) -> bool {
        self.rx.is_some()
    }

    /// Which cache tiers the next collection should serve from cache, per the
    /// two TTL clocks. A tier is served only when BOTH its data and its
    /// freshness timestamp are present and the TTL has not elapsed.
    fn tier_decisions(&self) -> (bool, bool) {
        let use_findings = self.cached_findings.is_some()
            && self
                .findings_fresh_at
                .is_some_and(|t| !ttl_expired(FINDINGS_TTL, t));
        let use_snapshot = self.cached_snapshot.is_some()
            && self
                .snapshot_fresh_at
                .is_some_and(|t| !ttl_expired(SNAPSHOT_TTL, t));
        (use_findings, use_snapshot)
    }

    /// Start a new background collection.
    ///
    /// If a collection is already in-flight, this is a no-op. Each cache tier
    /// is consulted independently: a fresh findings tier skips the doctor, a
    /// fresh snapshot tier skips the `ss`/`conntrack`/detect/iptables passes.
    pub fn start(&mut self) {
        if self.rx.is_some() {
            return;
        }
        let (tx, rx) = oneshot::channel();
        let (use_findings, use_snapshot) = self.tier_decisions();
        let cached_findings = self.cached_findings.clone();
        let cached_snapshot = self.cached_snapshot.clone();
        self.rx = Some(rx);
        tokio::spawn(async move {
            let outcome =
                collect_real_monitor(use_findings, cached_findings, use_snapshot, cached_snapshot)
                    .await;
            let _ = tx.send(outcome);
        });
    }

    /// Test seam: [`Self::start`] with an INJECTED client instead of
    /// `MonitorClient::system()`.
    ///
    /// The cadence oracles drive this with a `FakeRunner`-backed client so
    /// their strong arms (sentinels served verbatim, tier independence,
    /// zero-spawn cache hits) run on EVERY host — `MonitorClient::system()`
    /// needs iptables/iptables-save/conntrack/ss/journalctl on `$PATH`, so
    /// the real-`start` oracles would silently degrade to their
    /// construction-failure arm on hosts without them. Tier decisions and
    /// `poll()` semantics are byte-identical to [`Self::start`]; only the
    /// client construction differs (none).
    #[cfg(test)]
    fn start_with_client(&mut self, client: toride_monitor::client::MonitorClient) {
        if self.rx.is_some() {
            return;
        }
        let (tx, rx) = oneshot::channel();
        let (use_findings, use_snapshot) = self.tier_decisions();
        let cached_findings = self.cached_findings.clone();
        let cached_snapshot = self.cached_snapshot.clone();
        self.rx = Some(rx);
        tokio::spawn(async move {
            let result = tokio::task::spawn_blocking(move || {
                collect_monitor_with_client(
                    &client,
                    use_findings,
                    cached_findings,
                    use_snapshot,
                    cached_snapshot,
                )
            })
            .await;
            let outcome = match result {
                Ok(tuple) => tuple,
                Err(e) => {
                    tracing::warn!("monitor collection task panicked: {e}");
                    (
                        empty_bundle_with_reason(format!("monitor data collection panicked: {e}")),
                        false,
                        false,
                        None,
                    )
                }
            };
            let _ = tx.send(outcome);
        });
    }

    /// Poll for a completed collection result.
    ///
    /// Returns `Some(bundle)` if the collection completed, `None` if still
    /// pending or if the collection failed. Each cache tier is written (and
    /// its clock advanced) only when that tier actually re-ran and the bundle
    /// is a real (available) result — otherwise the TTLs would be re-armed
    /// forever with cached data, and a degraded bundle would be pinned for
    /// the TTL instead of retried.
    pub async fn poll(&mut self) -> Option<MonitorDataBundle> {
        match &mut self.rx {
            Some(rx) => {
                let result = rx.await.ok();
                if let Some((ref bundle, findings_used, snapshot_used, ref fresh_cluster)) = result
                    && bundle.available
                {
                    if !findings_used {
                        self.cached_findings = Some(bundle.findings.clone());
                        self.findings_fresh_at = Some(std::time::Instant::now());
                    }
                    if let Some(cluster) = fresh_cluster
                        && !snapshot_used
                    {
                        // The fresh cluster is handed back only when the
                        // snapshot tier re-ran (`snapshot_used == false`).
                        self.cached_snapshot = Some(cluster.clone());
                        self.snapshot_fresh_at = Some(std::time::Instant::now());
                    }
                }
                self.rx = None;
                result.map(|(bundle, _, _, _)| bundle)
            }
            None => None,
        }
    }

    /// Invalidate both cache tiers so the next collection re-runs everything.
    #[allow(dead_code)]
    pub fn invalidate_findings_cache(&mut self) {
        self.cached_findings = None;
        self.findings_fresh_at = None;
        self.cached_snapshot = None;
        self.snapshot_fresh_at = None;
    }
}

impl Default for MonitorCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Real data collection ────────────────────────────────────────────────────

/// Collect monitor data by shelling out to the real binaries.
///
/// Construction (`MonitorClient::system()`) runs in its own `spawn_blocking`
/// so the `which` lookups don't stall the tokio worker. On macOS this returns
/// `Err(BinaryNotFound)` and we degrade to `available = false` with the reason
/// surfaced — NOT a panic, so the unavailable reason is accurate and
/// actionable. All blocking probes then run in a SECOND `spawn_blocking` that
/// owns the client. Each cache tier is independent: fresh findings skip the
/// doctor, a fresh snapshot cluster skips the `ss`/`conntrack`/detect/
/// iptables passes (only the native port enumeration always runs). On ANY
/// panic returns [`empty_bundle_with_reason`] with `available = false`.
///
/// Returns `(bundle, findings_used, snapshot_used, fresh_cluster)`:
/// `findings_used` / `snapshot_used` record which tiers were actually served
/// from a present cache, and `fresh_cluster` carries the freshly-run snapshot
/// cluster (present iff the snapshot tier re-ran) so the caller can cache it
/// — mirroring the proxy collector's fresh-report hand-back.
async fn collect_real_monitor(
    use_findings: bool,
    cached_findings: Option<Vec<FindingEntry>>,
    use_snapshot: bool,
    cached_snapshot: Option<SnapshotCluster>,
) -> MonitorOutcome {
    // Build the MonitorClient on the blocking pool. `system()` resolves
    // iptables/iptables-save/conntrack/ss/journalctl via `which`; on macOS
    // this returns Err(BinaryNotFound) and the section degrades cleanly.
    let client =
        match tokio::task::spawn_blocking(toride_monitor::client::MonitorClient::system).await {
            Ok(Ok(client)) => client,
            Ok(Err(e)) => {
                // Construction failed (typically BinaryNotFound on macOS). This is
                // a clean Err, NOT a panic, so we can surface the backend's own
                // error string verbatim. Cache flags are irrelevant on this
                // path — nothing was collected, so the caller must NOT write
                // either cache tier.
                tracing::debug!("monitor backend unavailable: {e}");
                return (empty_bundle_with_reason(format!("{e}")), false, false, None);
            }
            Err(e) => {
                tracing::warn!("monitor construction task panicked: {e}");
                return (
                    empty_bundle_with_reason(format!("monitor backend construction panicked: {e}")),
                    false,
                    false,
                    None,
                );
            }
        };

    // Run ALL blocking probes in a single spawn_blocking that owns `client`.
    // This keeps every shell-out / socket enumeration off the tokio worker and
    // sidesteps the 'static-borrow problem: each probe borrows `client.paths`,
    // so collecting everything in one owned closure is simpler than spawning
    // one task per probe. Results are returned as plain owned data so they
    // cross the thread boundary cleanly. Each cache tier is taken from its
    // cache when fresh, otherwise re-run here.
    let result = tokio::task::spawn_blocking(move || {
        collect_monitor_with_client(
            &client,
            use_findings,
            cached_findings,
            use_snapshot,
            cached_snapshot,
        )
    })
    .await;

    match result {
        Ok(tuple) => tuple,
        Err(e) => {
            tracing::warn!("monitor collection task panicked: {e}");
            (
                empty_bundle_with_reason(format!("monitor data collection panicked: {e}")),
                false,
                false,
                None,
            )
        }
    }
}

/// The blocking body of one monitor collection, run against an ALREADY
/// constructed client.
///
/// Split out of [`collect_real_monitor`] so the cadence oracles can drive the
/// full tier logic against an injected `FakeRunner`-backed client (no `$PATH`
/// resolution, no real subprocesses) while production keeps its
/// `MonitorClient::system()` construction.
#[expect(
    clippy::too_many_lines,
    reason = "real-data collection is inherently linear"
)]
fn collect_monitor_with_client(
    client: &toride_monitor::client::MonitorClient,
    use_findings: bool,
    cached_findings: Option<Vec<FindingEntry>>,
    use_snapshot: bool,
    cached_snapshot: Option<SnapshotCluster>,
) -> MonitorOutcome {
    {
        use toride_monitor::conntrack::ConntrackReader;
        use toride_monitor::doctor::{Doctor, DoctorScope};

        // ── Doctor (unless cached) ─────────────────────────────────────────
        // `findings_served` tracks the EFFECTIVE cache use: start() only sets
        // use_findings when the cache is populated, but the truthful flag
        // must also be false in the impossible race where it was not.
        let findings_served = use_findings && cached_findings.is_some();
        // Same for the snapshot tier: `true` means SERVED FROM CACHE (the
        // fresh cluster is absent), so poll() knows to write the cache.
        let snapshot_served = use_snapshot && cached_snapshot.is_some();
        let findings: Vec<FindingEntry> = if findings_served {
            cached_findings.unwrap_or_default()
        } else {
            let doctor = Doctor::new(client.paths(), client.runner());
            match doctor.run(&DoctorScope::All) {
                Ok(report) => toride_monitor_convert::convert_findings(report.findings),
                Err(e) => {
                    tracing::warn!("monitor doctor: {e}");
                    Vec::new()
                }
            }
        };

        // ── Snapshot cluster (unless cached) ───────────────────────────────
        // The snapshot's aggregated bytes/packets come from a conntrack table
        // read done inside `client.snapshot()` (`collect_conntrack_stats`). We
        // reuse those aggregates below for the conntrack summary instead of
        // forking `conntrack -L` a SECOND time — the only extra reads we
        // allow ourselves are the fast `conntrack -C` count and, when the
        // snapshot's bytes/packets are missing, a single fallback table read
        // for the count.
        let (cluster, fresh_cluster) = if use_snapshot && let Some(cached) = cached_snapshot {
            (cached, None)
        } else {
            let snapshot_report = client.snapshot();
            let (summary, snapshot_bytes, snapshot_packets) = match &snapshot_report {
                Ok(report) => {
                    let summary = toride_monitor_convert::convert_snapshot(report);
                    (summary, report.total_bytes, report.total_packets)
                }
                Err(e) => {
                    tracing::debug!("monitor snapshot: {e}");
                    (SnapshotSummary::default(), None, None)
                }
            };
            let connections = snapshot_report
                .as_ref()
                .map(|r| toride_monitor_convert::convert_connections(&r.connections))
                .unwrap_or_default();
            let anomalies = match snapshot_report.as_ref() {
                Ok(report) => match client.detect(report) {
                    Ok(anomaly_report) => {
                        toride_monitor_convert::convert_anomalies(anomaly_report.findings)
                    }
                    Err(e) => {
                        tracing::debug!("monitor detect: {e}");
                        Vec::new()
                    }
                },
                Err(_) => Vec::new(),
            };

            // Reuse the snapshot's already-aggregated bytes/packets — the
            // snapshot ran `conntrack -L` once via `collect_conntrack_stats`,
            // so re-reading the table here would double the fork+parse work.
            // For the COUNT we prefer the fast `conntrack -C`; only when that
            // fast count is unavailable AND the snapshot also failed (so we
            // have no connection count to fall back on) do we do a single
            // fallback `list_all()` read for the table length. Bytes/packets
            // are NEVER re-derived from a second table read.
            let reader = ConntrackReader::new(client.paths(), client.runner());
            let fast_count = reader.count().ok();
            // Snapshot-derived count fallback: `ss` already enumerated the
            // outbound flows, so `total_connections` is a valid lower-bound
            // count when the fast `conntrack -C` path is missing.
            let snapshot_count = snapshot_report.as_ref().ok().map(|r| r.total_connections);
            // Only when neither the fast count nor the snapshot succeeded do
            // we pay for a single fallback table read — purely to derive a
            // count.
            let fallback_table_count = if fast_count.is_none() && snapshot_count.is_none() {
                match reader.list_all() {
                    Ok(entries) => Some(entries.len() as u64),
                    Err(e) => {
                        tracing::debug!("monitor conntrack list_all: {e}");
                        None
                    }
                }
            } else {
                None
            };
            let conntrack = ConntrackSummary {
                // Prefer the fast count; fall back to the snapshot's
                // connection count; last resort the fallback table length. If
                // none worked, leave None so the UI renders "—".
                count: fast_count.or(snapshot_count).or(fallback_table_count),
                total_bytes: snapshot_bytes,
                total_packets: snapshot_packets,
            };

            // ── OUTPUT chain LOG rules ─────────────────────────────────────
            let output_rule_count =
                match toride_monitor::output::OutputChain::new(client.paths(), client.runner())
                    .list_rules()
                {
                    Ok(rules) => Some(rules.len()),
                    Err(e) => {
                        tracing::debug!("monitor output list_rules: {e}");
                        None
                    }
                };

            let cluster = SnapshotCluster {
                summary,
                connections,
                anomalies,
                conntrack,
                output_rule_count,
                snapshot_ok: snapshot_report.is_ok(),
            };
            (cluster.clone(), Some(cluster))
        };

        // ── Listening ports (always fresh — native netstat2, no shell-out) ──
        // list_listening_ports uses native netstat2 (no shell-out), so it can
        // succeed even where ss/conntrack are missing. Degrade to empty on
        // error.
        let ports: Vec<PortEntry> = match client.list_listening_ports() {
            Ok(raw) => toride_monitor_convert::convert_ports(&raw),
            Err(e) => {
                tracing::debug!("monitor list_listening_ports: {e}");
                Vec::new()
            }
        };

        // ── Availability heuristic ─────────────────────────────────────────
        // Mirrors the sibling read-only collectors (fail2ban_data,
        // ufw_kit_data, wireguard_data, ...): `available` is a disjunction of
        // meaningful probe-success signals, NOT an unconditional `true`.
        // Construction succeeding only proves the binaries EXIST on `$PATH`
        // (which/iptables-save/conntrack/ss/journalctl resolved); it does NOT
        // prove they RUN. `conntrack -L` requires CAP_NET_ADMIN/root on most
        // distros and `ss -tunap` can fail under seccomp/permissions. If every
        // runtime probe failed on an unprivileged host, an unconditional
        // `true` here would render `available == true` with empty data —
        // indistinguishable from a genuinely quiet host and surfacing the
        // misleading empty-state messages ('no outbound connections observed',
        // conntrack bytes '—') the audit's dimension #2 targets.
        //
        // `cluster.snapshot_ok` is the canonical 'is the monitor actually
        // working' probe (it ran `ss` + the conntrack table read). The
        // remaining disjuncts keep the section available when the snapshot
        // alone failed but another probe still produced data, matching the
        // sibling 'OR in at least one success signal' posture.
        let available = monitor_available(
            cluster.snapshot_ok,
            !cluster.connections.is_empty(),
            !ports.is_empty(),
            !findings.is_empty(),
        );

        let bundle = MonitorDataBundle {
            available,
            summary: cluster.summary,
            connections: cluster.connections,
            ports,
            conntrack: cluster.conntrack,
            output_rule_count: cluster.output_rule_count,
            anomalies: cluster.anomalies,
            findings,
            // Success path: no panic, no construction error, so no reason.
            unavailable_reason: None,
        };
        (bundle, findings_served, snapshot_served, fresh_cluster)
    }
}

/// Availability heuristic, factored out so it can be unit-tested.
///
/// Mirrors the sibling read-only collectors' disjunction of probe-success
/// signals. Returns `false` when EVERY probe failed at runtime — the case the
/// audit's dimension #2 targets: construction succeeded (binaries exist on
/// `$PATH`) but `conntrack -L` failed for lack of `CAP_NET_ADMIN` and `ss
/// -tunap` failed under seccomp, so the host produced no connections, no
/// ports, no findings, and the snapshot itself errored. Such a host must NOT
/// be reported as `available` (it would render misleading empty-state messages
/// indistinguishable from a genuinely quiet host).
///
/// `snapshot_ok` is the canonical 'is the monitor actually working' signal;
/// the remaining arguments keep the section available when the snapshot alone
/// failed but another probe still produced data.
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "four independent probe-presence flags ORed together"
)]
fn monitor_available(
    snapshot_ok: bool,
    has_connections: bool,
    has_ports: bool,
    has_findings: bool,
) -> bool {
    snapshot_ok || has_connections || has_ports || has_findings
}

/// Empty bundle used when the monitor backend could not be constructed at all.
///
/// `available = false` signals the UI to render the degraded panel. No reason
/// is attached because none is known at this point; construction errors and
/// collection-time panics use [`empty_bundle_with_reason`] to surface a cause.
fn empty_bundle() -> MonitorDataBundle {
    MonitorDataBundle {
        available: false,
        summary: SnapshotSummary::default(),
        connections: Vec::new(),
        ports: Vec::new(),
        conntrack: ConntrackSummary::default(),
        output_rule_count: None,
        anomalies: Vec::new(),
        findings: Vec::new(),
        unavailable_reason: None,
    }
}

/// Empty bundle carrying the reason collection failed. Used for both a
/// construction `Err` (e.g. `BinaryNotFound` on macOS) and a `spawn_blocking`
/// task panic (`JoinError`) — the reason string is rendered by the UI's degraded
/// panel so the operator sees what actually went wrong.
fn empty_bundle_with_reason(reason: String) -> MonitorDataBundle {
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
        let collector = MonitorCollector::new();
        assert!(!collector.is_pending());
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(
            MonitorCollector::new().is_pending(),
            MonitorCollector::default().is_pending()
        );
    }

    #[tokio::test]
    async fn start_makes_pending() {
        let mut collector = MonitorCollector::new();
        assert!(!collector.is_pending());
        collector.start();
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn start_is_idempotent() {
        let mut collector = MonitorCollector::new();
        collector.start();
        assert!(collector.is_pending());
        collector.start(); // no-op, does not replace the receiver
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn poll_returns_none_when_not_started() {
        let mut collector = MonitorCollector::new();
        assert!(collector.poll().await.is_none());
    }

    #[tokio::test]
    async fn poll_clears_pending() {
        let mut collector = MonitorCollector::new();
        collector.start();
        // Let the spawned task complete (it shells out / resolves binaries, so
        // give it time). On macOS construction fails fast (which()); on Linux
        // the probes shell out.
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let _ = collector.poll().await;
        assert!(!collector.is_pending(), "poll should clear pending state");
    }

    #[tokio::test]
    async fn poll_returns_bundle_after_collection() {
        // On any host (including macOS where the backend is unavailable) the
        // collector must return Some(bundle) after start() + enough time. The
        // bundle's `available` flag reflects whether the backend was found.
        let mut collector = MonitorCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let bundle = collector.poll().await;
        assert!(bundle.is_some(), "poll should return Some after completion");
    }

    #[test]
    fn empty_bundle_is_unavailable() {
        let b = empty_bundle();
        assert!(!b.available);
        assert!(b.connections.is_empty());
        assert!(b.ports.is_empty());
        assert!(b.anomalies.is_empty());
        assert!(b.findings.is_empty());
        assert!(b.output_rule_count.is_none());
        assert!(b.conntrack.count.is_none());
        assert!(
            b.unavailable_reason.is_none(),
            "empty_bundle carries no reason; errors/panics use empty_bundle_with_reason"
        );
    }

    #[test]
    fn empty_bundle_with_reason_attaches_reason() {
        let b = empty_bundle_with_reason("binary not found: iptables".into());
        assert!(!b.available);
        assert_eq!(
            b.unavailable_reason.as_deref(),
            Some("binary not found: iptables")
        );
    }

    #[test]
    fn monitor_available_false_when_every_probe_failed() {
        // The audit's dimension #2 edge case: construction succeeded (the
        // binaries exist on $PATH so `MonitorClient::system()` returned Ok),
        // but every RUNTIME probe failed — `ss -tunap` under seccomp,
        // `conntrack -L` for lack of CAP_NET_ADMIN — so the snapshot errored
        // and no connections/ports/findings were produced. Such a host must
        // NOT be reported `available`: it would otherwise render the
        // misleading empty-state messages ('no outbound connections observed',
        // conntrack bytes '—') indistinguishable from a genuinely quiet host.
        assert!(
            !monitor_available(false, false, false, false),
            "host where every runtime probe failed must not be 'available'"
        );
    }

    #[test]
    fn monitor_available_true_when_snapshot_ok() {
        // The canonical 'is the monitor actually working' signal.
        assert!(monitor_available(true, false, false, false));
    }

    #[test]
    fn monitor_available_true_when_any_probe_produced_data() {
        // Even with a failed snapshot, a single successful probe keeps the
        // section available (mirrors the sibling 'OR in at least one success
        // signal' posture).
        assert!(monitor_available(false, true, false, false)); // connections
        assert!(monitor_available(false, false, true, false)); // ports
        assert!(monitor_available(false, false, false, true)); // findings
    }

    #[tokio::test]
    async fn findings_cache_is_populated_after_poll() {
        let mut collector = MonitorCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let bundle = collector.poll().await;
        // After a successful AVAILABLE poll both cache tiers are populated.
        // A host where every runtime probe failed (available == false,
        // e.g. macOS construction failure) stays uncached so the next tick
        // retries.
        match bundle {
            Some(b) if b.available => {
                assert!(collector.cached_findings.is_some());
                assert!(collector.findings_fresh_at.is_some());
                assert!(collector.cached_snapshot.is_some());
                assert!(collector.snapshot_fresh_at.is_some());
            }
            _ => {
                assert!(
                    collector.cached_findings.is_none(),
                    "a degraded bundle must not be cached"
                );
            }
        }
    }

    #[test]
    fn invalidate_findings_cache_clears_it() {
        let mut collector = MonitorCollector::new();
        collector.cached_findings = Some(Vec::new());
        collector.findings_fresh_at = Some(std::time::Instant::now());
        collector.cached_snapshot = Some(SnapshotCluster {
            summary: SnapshotSummary::default(),
            connections: Vec::new(),
            anomalies: Vec::new(),
            conntrack: ConntrackSummary::default(),
            output_rule_count: None,
            snapshot_ok: false,
        });
        collector.snapshot_fresh_at = Some(std::time::Instant::now());
        collector.invalidate_findings_cache();
        assert!(collector.cached_findings.is_none());
        assert!(collector.findings_fresh_at.is_none());
        assert!(collector.cached_snapshot.is_none());
        assert!(collector.snapshot_fresh_at.is_none());
    }
}

// ── Cadence oracles (round 2, F11 two-tier cache) ────────────────────────────

/// Cadence oracles for the two-tier monitor cache (findings 60s, snapshot 8s).
///
/// HERMETIC: every oracle drives [`MonitorCollector::start_with_client`] with
/// a `FakeRunner`-backed client, so the strong arms run on every host — the
/// real `MonitorClient::system()` needs iptables/conntrack/ss on `$PATH` and
/// would silently flip these oracles to a construction-failure arm on hosts
/// without them. Sentinels cover both tiers — a finding id and a connection
/// destination no real probe can emit — so "the bundle came back verbatim"
/// proves NEITHER the doctor NOR the `ss`/`conntrack`/detect/iptables passes
/// spawned anything, and the runner's call log proves it directly (zero calls
/// on a both-tier hit). The tier-split oracle is the interesting one: cranking
/// the test clock past only the `SNAPSHOT_TTL` (9s < 60s) re-runs the
/// snapshot tier (exactly one `ss` spawn) while the findings tier keeps
/// serving its sentinel verbatim — pinning that the two TTLs expire
/// independently.
#[cfg(test)]
mod cadence_oracle {
    use super::*;

    /// Sentinel id no real monitor doctor finding can carry.
    const SENTINEL_ID: &str = "oracle-sentinel.monitor.findings-cache";

    /// Sentinel destination no real `ss` row can carry.
    const SENTINEL_DST: &str = "203.0.113.0";

    /// A sentinel snapshot cluster (`snapshot_ok` true so availability holds).
    fn sentinel_cluster() -> SnapshotCluster {
        SnapshotCluster {
            summary: SnapshotSummary::default(),
            connections: vec![ConnectionEntry {
                protocol: "tcp".to_string(),
                src: "198.51.100.7:40000".to_string(),
                dst: format!("{SENTINEL_DST}:443"),
                state: "ESTABLISHED".to_string(),
                bytes: None,
            }],
            anomalies: Vec::new(),
            conntrack: ConntrackSummary::default(),
            output_rule_count: Some(1),
            snapshot_ok: true,
        }
    }

    /// Sentinel findings for the 60s tier.
    fn sentinel_findings() -> Vec<FindingEntry> {
        vec![FindingEntry {
            id: SENTINEL_ID.to_string(),
            severity: "ok".to_string(),
            title: "cadence-oracle sentinel".to_string(),
            detail: String::new(),
            fix: None,
        }]
    }

    /// Advances this thread's TTL test clock by `ms`, resetting on drop.
    struct TtlOffsetGuard;

    impl TtlOffsetGuard {
        fn by_ms(ms: u64) -> Self {
            TTL_TEST_OFFSET_MS.with(|o| o.set(ms));
            Self
        }

        /// Past the 8s snapshot TTL but well under the 60s findings TTL.
        fn snapshot_only() -> Self {
            Self::by_ms(
                u64::try_from(SNAPSHOT_TTL.as_millis())
                    .expect("an 8s TTL in milliseconds always fits in u64")
                    + 1_000,
            )
        }

        /// Past both TTLs.
        fn both() -> Self {
            Self::by_ms(
                u64::try_from(FINDINGS_TTL.as_millis())
                    .expect("a 60s TTL in milliseconds always fits in u64")
                    + 10_000,
            )
        }
    }

    impl Drop for TtlOffsetGuard {
        fn drop(&mut self) {
            TTL_TEST_OFFSET_MS.with(|o| o.set(0));
        }
    }

    /// Deterministic `ss -tunap` output for the fresh-run oracles: two ESTAB
    /// rows under the REAL header shape (the F11 header-mapping fix's layout)
    /// whose destinations no sentinel collides with.
    const SS_FIXTURE: &str = concat!(
        "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n",
        "tcp ESTAB 0 0 198.51.100.7:40000 203.0.113.9:443 users:((\"fixture-proc\",pid=1,fd=3))\n",
        "tcp ESTAB 0 0 198.51.100.7:40001 203.0.113.9:443 users:((\"fixture-proc\",pid=1,fd=4))",
    );

    /// The `ss -tunap` spec `MonitorClient::snapshot()` issues (program is
    /// `paths.ss`, which `default_paths()` pins to `/usr/bin/ss`).
    fn ss_spec() -> toride_runner::CommandSpec {
        toride_runner::CommandSpec::new("/usr/bin/ss").args(["-tunap"])
    }

    /// A hermetic client: `ss -tunap` answers with the fixture; every other
    /// command answers with an empty success (lenient `FakeRunner`). The
    /// handle is kept so oracles can count what actually spawned.
    fn fake_client() -> (
        toride_monitor::client::MonitorClient,
        toride_runner::fake::FakeRunner,
    ) {
        let runner = toride_runner::fake::FakeRunner::new().respond(
            ss_spec(),
            toride_runner::CommandOutput::from_stdout(SS_FIXTURE),
        );
        let client = toride_monitor::client::MonitorClient::with_runner(
            Box::new(runner.clone()),
            toride_monitor::paths::MonitorPaths::default_paths(),
        );
        (client, runner)
    }

    /// How many `ss -tunap` spawns the runner recorded. `CommandSpec` has no
    /// `PartialEq`, so match on the public program/args fields — the same
    /// fields `FakeRunner`'s exact-match responder keys on (modulo the
    /// excluded policy fields, which the snapshot spec never sets).
    fn ss_spawn_count(runner: &toride_runner::fake::FakeRunner) -> usize {
        runner
            .calls()
            .iter()
            .filter(|c| c.program == "/usr/bin/ss" && c.args == ["-tunap"])
            .count()
    }

    /// ORACLE: with both tiers fresh the whole bundle is served verbatim —
    /// the sentinel connection AND the sentinel finding both survive — with
    /// ZERO subprocess spawns (not even `ss`), and neither clock re-arms.
    /// Hermetic: the injected client works on every host, so this arm can
    /// never silently degrade to a construction-failure branch.
    #[tokio::test]
    async fn both_tiers_fresh_serves_bundle_verbatim_with_zero_spawns() {
        let mut collector = MonitorCollector::new();
        collector.cached_findings = Some(sentinel_findings());
        collector.cached_snapshot = Some(sentinel_cluster());
        let primed_snapshot = std::time::Instant::now();
        let primed_findings = std::time::Instant::now();
        collector.snapshot_fresh_at = Some(primed_snapshot);
        collector.findings_fresh_at = Some(primed_findings);

        let (client, runner) = fake_client();
        collector.start_with_client(client);
        let bundle = collector.poll().await.expect("collection completes");

        assert!(
            bundle.available,
            "the sentinel cluster carries snapshot_ok == true"
        );
        assert_eq!(bundle.findings.len(), 1);
        assert_eq!(
            bundle.findings[0].id, SENTINEL_ID,
            "the sentinel finding can only come from the 60s tier"
        );
        assert_eq!(bundle.connections.len(), 1);
        assert_eq!(
            bundle.connections[0].dst,
            format!("{SENTINEL_DST}:443"),
            "the sentinel connection can only come from the 8s tier"
        );
        assert_eq!(bundle.output_rule_count, Some(1));
        assert_eq!(
            ss_spawn_count(&runner),
            0,
            "a both-tier cache hit must spawn NOTHING — no ss, no conntrack, no iptables-save"
        );
        assert!(
            runner.calls().is_empty(),
            "a both-tier cache hit performs zero subprocess spawns of any kind"
        );
        assert_eq!(
            collector.snapshot_fresh_at,
            Some(primed_snapshot),
            "a both-tier cache hit must not re-arm the snapshot clock"
        );
        assert_eq!(
            collector.findings_fresh_at,
            Some(primed_findings),
            "a both-tier cache hit must not re-arm the findings clock"
        );
    }

    /// ORACLE: the tiers expire INDEPENDENTLY. 9s after priming (past the 8s
    /// snapshot TTL, under the 60s findings TTL) the snapshot tier re-runs —
    /// exactly one `ss` spawn, the fixture rows come through, the sentinel
    /// connection is gone — while the findings tier still serves its sentinel
    /// verbatim with its clock untouched, and the re-run cluster is cached so
    /// the NEXT collection serves it with zero spawns.
    #[tokio::test]
    async fn snapshot_ttl_expires_before_findings_ttl() {
        let mut collector = MonitorCollector::new();
        collector.cached_findings = Some(sentinel_findings());
        collector.cached_snapshot = Some(sentinel_cluster());
        let primed = std::time::Instant::now();
        collector.snapshot_fresh_at = Some(primed);
        collector.findings_fresh_at = Some(primed);

        let ttl = TtlOffsetGuard::snapshot_only();
        let (client, runner) = fake_client();
        collector.start_with_client(client);
        let bundle = collector.poll().await.expect("collection completes");

        assert!(bundle.available, "the fixture snapshot parses Ok");
        assert!(
            bundle.connections.iter().all(|c| c.dst != SENTINEL_DST),
            "an expired snapshot tier must not serve the sentinel connection"
        );
        assert_eq!(
            bundle.connections.len(),
            2,
            "the fresh run parses both fixture rows through the F11 header mapping"
        );
        assert_eq!(bundle.connections[0].dst, "203.0.113.9:443");
        assert_eq!(
            ss_spawn_count(&runner),
            1,
            "the expired snapshot tier re-runs ss exactly once"
        );
        assert_eq!(
            bundle.findings.len(),
            1,
            "the findings tier must still be fresh at 9s"
        );
        assert_eq!(
            bundle.findings[0].id, SENTINEL_ID,
            "the sentinel finding survives: FINDINGS_TTL has not elapsed"
        );
        assert_eq!(
            collector.findings_fresh_at,
            Some(primed),
            "the findings clock must not re-arm while its tier is fresh"
        );
        assert!(
            collector.snapshot_fresh_at.is_some_and(|t| t > primed),
            "the re-run snapshot tier must re-arm its clock"
        );

        // The re-run cluster is now cached: an immediate second collection
        // serves it verbatim with ZERO spawns (the cache-write half of the
        // cadence). Drop the cranked clock first — the re-armed snapshot
        // clock is fresh against the REAL clock, so the hit must hold
        // without any test offset.
        drop(ttl);
        let (client2, runner2) = fake_client();
        collector.start_with_client(client2);
        let second = collector.poll().await.expect("second collection completes");
        assert!(second.available);
        assert_eq!(
            second.connections.len(),
            2,
            "the freshly cached cluster is served verbatim on the next hit"
        );
        assert_eq!(
            second.connections[0].dst, "203.0.113.9:443",
            "the fixture row survives the cache round-trip"
        );
        assert_eq!(
            ss_spawn_count(&runner2),
            0,
            "an immediate re-collect is a snapshot-tier cache hit: no ss spawn"
        );
    }

    /// ORACLE: past both TTLs every sentinel is gone — the doctor and the
    /// snapshot passes both re-ran, and both clocks re-arm.
    #[tokio::test]
    async fn both_ttls_expiring_reruns_everything() {
        let mut collector = MonitorCollector::new();
        collector.cached_findings = Some(sentinel_findings());
        collector.cached_snapshot = Some(sentinel_cluster());
        let primed = std::time::Instant::now();
        collector.snapshot_fresh_at = Some(primed);
        collector.findings_fresh_at = Some(primed);

        let _ttl = TtlOffsetGuard::both();
        let (client, runner) = fake_client();
        collector.start_with_client(client);
        let bundle = collector.poll().await.expect("collection completes");

        assert!(bundle.available, "the fixture snapshot parses Ok");
        assert!(
            bundle.findings.iter().all(|f| f.id != SENTINEL_ID),
            "an expired findings tier must not serve the sentinel finding"
        );
        assert!(
            bundle.connections.iter().all(|c| c.dst != SENTINEL_DST),
            "an expired snapshot tier must not serve the sentinel connection"
        );
        assert!(
            !runner.calls().is_empty(),
            "an expired tier set must re-run the doctor and snapshot passes"
        );
        assert!(
            collector.findings_fresh_at.is_some_and(|t| t > primed),
            "the re-run findings tier must re-arm its clock"
        );
        assert!(
            collector.snapshot_fresh_at.is_some_and(|t| t > primed),
            "the re-run snapshot tier must re-arm its clock"
        );
    }
}
