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
//! Doctor findings shell out (`iptables-save`, `which`, etc.) and change
//! slowly, so they are cached for 60s — exactly like the fail2ban / SSH
//! diagnostics cache.
//!
//! ## macOS / construction
//!
//! [`toride_monitor::MonitorClient::system`] resolves `iptables`,
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

/// Manages periodic async collection of monitor data.
///
/// Mirrors [`Fail2banCollector`](crate::fail2ban_data::Fail2banCollector): a
/// oneshot channel for the in-flight result, plus a 60s TTL cache for the
/// expensive doctor findings so they are not re-run on every 2s refresh tick.
pub struct MonitorCollector {
    /// Carries the bundle AND whether the cached findings were reused for this
    /// poll. See [`Fail2banCollector`](crate::fail2ban_data::Fail2banCollector)
    /// for the rationale on the `(bundle, used_cache)` tuple shape.
    rx: Option<oneshot::Receiver<(MonitorDataBundle, bool)>>,
    /// Cached doctor findings from the last collection.
    cached_findings: Option<Vec<FindingEntry>>,
    /// When the findings cache was last refreshed.
    findings_fresh_at: Option<std::time::Instant>,
}

/// How long to keep cached findings before re-running the doctor suite.
const FINDINGS_TTL: std::time::Duration = std::time::Duration::from_mins(1);

impl MonitorCollector {
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
            let (bundle, reused_cache) = collect_real_monitor(use_cache, cached_findings).await;
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
    pub async fn poll(&mut self) -> Option<MonitorDataBundle> {
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
/// owns the client. Doctor findings may be reused from the cache. On ANY panic
/// returns [`empty_bundle_with_reason`] with `available = false`.
///
/// Returns `(bundle, used_cache)` where `used_cache` records whether the
/// findings were actually taken from the cache on a successful collection.
#[expect(
    clippy::too_many_lines,
    reason = "real-data collection is inherently linear"
)]
async fn collect_real_monitor(
    use_cache: bool,
    cached_findings: Option<Vec<FindingEntry>>,
) -> (MonitorDataBundle, bool) {
    // Build the MonitorClient on the blocking pool. `system()` resolves
    // iptables/iptables-save/conntrack/ss/journalctl via `which`; on macOS
    // this returns Err(BinaryNotFound) and the section degrades cleanly.
    let client =
        match tokio::task::spawn_blocking(toride_monitor::client::MonitorClient::system).await {
            Ok(Ok(client)) => client,
            Ok(Err(e)) => {
                // Construction failed (typically BinaryNotFound on macOS). This is
                // a clean Err, NOT a panic, so we can surface the backend's own
                // error string verbatim. used_cache is irrelevant on this path —
                // nothing was collected, so the caller must NOT advance the TTL
                // clock (false).
                tracing::debug!("monitor backend unavailable: {e}");
                return (empty_bundle_with_reason(format!("{e}")), false);
            }
            Err(e) => {
                tracing::warn!("monitor construction task panicked: {e}");
                return (
                    empty_bundle_with_reason(format!("monitor backend construction panicked: {e}")),
                    false,
                );
            }
        };

    // Run ALL blocking probes in a single spawn_blocking that owns `client`.
    // This keeps every shell-out / socket enumeration off the tokio worker and
    // sidesteps the 'static-borrow problem: each probe borrows `client.paths`,
    // so collecting everything in one owned closure is simpler than spawning
    // one task per probe. Results are returned as plain owned data so they
    // cross the thread boundary cleanly. Doctor findings are taken from the
    // cache when fresh (`use_cache`), otherwise re-run here.
    let result = tokio::task::spawn_blocking(move || {
        use toride_monitor::conntrack::ConntrackReader;
        use toride_monitor::doctor::{Doctor, DoctorScope};

        // ── Doctor (unless cached) ─────────────────────────────────────────
        let findings: Vec<FindingEntry> = if use_cache {
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

        // ── Snapshot + anomaly detection ───────────────────────────────────
        // The snapshot's aggregated bytes/packets come from a conntrack table
        // read done inside `client.snapshot()` (`collect_conntrack_stats`). We
        // reuse those aggregates below for the conntrack summary instead of
        // forking `conntrack -L` a SECOND time — the only extra reads we
        // allow ourselves are the fast `conntrack -C` count and, when the
        // snapshot's bytes/packets are missing, a single fallback table read
        // for the count.
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

        // ── Listening ports ────────────────────────────────────────────────
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

        // ── Conntrack summary ──────────────────────────────────────────────
        // Reuse the snapshot's already-aggregated bytes/packets — the snapshot
        // ran `conntrack -L` once via `collect_conntrack_stats`, so re-reading
        // the table here would double the fork+parse work on every collection.
        // For the COUNT we prefer the fast `conntrack -C`; only when that fast
        // count is unavailable AND the snapshot also failed (so we have no
        // connection count to fall back on) do we do a single fallback
        // `list_all()` read for the table length. Bytes/packets are NEVER
        // re-derived from a second table read.
        let reader = ConntrackReader::new(client.paths(), client.runner());
        let fast_count = reader.count().ok();
        // Snapshot-derived count fallback: `ss` already enumerated the
        // outbound flows, so `total_connections` is a valid lower-bound count
        // when the fast `conntrack -C` path is missing.
        let snapshot_count = snapshot_report.as_ref().ok().map(|r| r.total_connections);
        // Only when neither the fast count nor the snapshot succeeded do we
        // pay for a single fallback table read — purely to derive a count.
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
            // Prefer the fast count; fall back to the snapshot's connection
            // count; last resort the fallback table length. If none worked,
            // leave None so the UI renders "—".
            count: fast_count.or(snapshot_count).or(fallback_table_count),
            total_bytes: snapshot_bytes,
            total_packets: snapshot_packets,
        };

        // ── OUTPUT chain LOG rules ─────────────────────────────────────────
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

        // ── Availability heuristic ─────────────────────────────────────────
        // Mirrors the sibling read-only collectors (fail2ban_data,
        // ufw_kit_data, wireguard_data, ...): `available` is a disjunction of
        // meaningful probe-success signals, NOT an unconditional `true`.
        // Construction succeeding only proves the binaries EXIST on `$PATH`
        // (which/iptables-save/conntrack/ss/journalctl resolved); it does NOT
        // prove they RUN. `conntrack -L` requires CAP_NET_ADMIN/root on most
        // distros and `ss -tunap` can fail under seccomp/permissions. If every
        // runtime probe failed on an unprivileged host, an unconditional
        // `true` here would render `available = true` with empty data —
        // indistinguishable from a genuinely quiet host and surfacing the
        // misleading empty-state messages ('no outbound connections observed',
        // conntrack bytes '—') the audit's dimension #2 targets.
        //
        // `snapshot_report.is_ok()` is the canonical 'is the monitor actually
        // working' probe (it ran `ss` + the conntrack table read). The
        // remaining disjuncts keep the section available when the snapshot
        // alone failed but another probe still produced data, matching the
        // sibling 'OR in at least one success signal' posture.
        let available = monitor_available(
            snapshot_report.is_ok(),
            !connections.is_empty(),
            !ports.is_empty(),
            !findings.is_empty(),
        );

        MonitorDataBundle {
            available,
            summary,
            connections,
            ports,
            conntrack,
            output_rule_count,
            anomalies,
            findings,
            // Success path: no panic, no construction error, so no reason.
            unavailable_reason: None,
        }
    })
    .await;

    match result {
        Ok(bundle) => (bundle, use_cache),
        Err(e) => {
            tracing::warn!("monitor collection task panicked: {e}");
            (
                empty_bundle_with_reason(format!("monitor data collection panicked: {e}")),
                false,
            )
        }
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
        let _ = collector.poll().await;
        // After a successful poll the cache is populated (even if to an empty
        // Vec on a host where the doctor produced no findings).
        assert!(collector.cached_findings.is_some());
        assert!(collector.findings_fresh_at.is_some());
    }

    #[test]
    fn invalidate_findings_cache_clears_it() {
        let mut collector = MonitorCollector::new();
        collector.cached_findings = Some(Vec::new());
        collector.findings_fresh_at = Some(std::time::Instant::now());
        collector.invalidate_findings_cache();
        assert!(collector.cached_findings.is_none());
        assert!(collector.findings_fresh_at.is_none());
    }
}
