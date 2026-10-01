//! Async read-only outbound-traffic-monitor collection. Two cache tiers:
//! doctor findings 60s, the snapshot cluster 8s (4s after a failed snapshot).

use tokio::sync::oneshot;

use crate::toride_monitor_convert;
use crate::ui::screens::toride_monitor::{
    AnomalyEntry, ConnectionEntry, ConntrackSummary, FindingEntry, PortEntry, SnapshotSummary,
};

/// A read-only snapshot of outbound-traffic monitor state.
#[derive(Clone, Debug)]
pub struct MonitorDataBundle {
    /// `false` when construction failed (typically `BinaryNotFound` on
    /// macOS) or the collection task panicked; renders the degraded panel.
    pub available: bool,
    /// Snapshot totals (connections, destinations, bytes, packets).
    pub summary: SnapshotSummary,
    /// Current outbound connections.
    pub connections: std::sync::Arc<[ConnectionEntry]>,
    /// Listening TCP/UDP ports.
    pub ports: Vec<PortEntry>,
    /// Conntrack byte/packet counters.
    pub conntrack: ConntrackSummary,
    /// Number of installed OUTPUT chain LOG rules; `None` when the probe failed.
    pub output_rule_count: Option<usize>,
    /// Anomaly-detection findings.
    pub anomalies: std::sync::Arc<[AnomalyEntry]>,
    /// Doctor findings.
    pub findings: std::sync::Arc<[FindingEntry]>,
    /// Populated only when `available == false` (construction `Err` or a
    /// panicked task); rendered by the degraded panel.
    pub unavailable_reason: Option<String>,
}

type MonitorOutcome = (
    MonitorDataBundle,
    bool,
    bool,
    Option<std::sync::Arc<SnapshotCluster>>,
);

#[derive(Clone, Debug)]
struct SnapshotCluster {
    summary: SnapshotSummary,
    connections: std::sync::Arc<[ConnectionEntry]>,
    anomalies: std::sync::Arc<[AnomalyEntry]>,
    conntrack: ConntrackSummary,
    output_rule_count: Option<usize>,
    snapshot_ok: bool,
}

/// Manages periodic async monitor collection with a two-tier cache: doctor
/// findings for 60s, the snapshot cluster for 8s (4s when it failed).
pub struct MonitorCollector {
    rx: Option<oneshot::Receiver<MonitorOutcome>>,
    cached_findings: Option<std::sync::Arc<[FindingEntry]>>,
    findings_fresh_at: Option<std::time::Instant>,
    cached_snapshot: Option<std::sync::Arc<SnapshotCluster>>,
    snapshot_fresh_at: Option<std::time::Instant>,
}

const FINDINGS_TTL: std::time::Duration = std::time::Duration::from_mins(1);

const SNAPSHOT_TTL: std::time::Duration = std::time::Duration::from_secs(8);

const SNAPSHOT_FAILURE_TTL: std::time::Duration = std::time::Duration::from_secs(4);

fn snapshot_ttl_for(cluster: &SnapshotCluster) -> std::time::Duration {
    if cluster.snapshot_ok {
        SNAPSHOT_TTL
    } else {
        SNAPSHOT_FAILURE_TTL
    }
}

fn ttl_expired(ttl: std::time::Duration, fresh_at: std::time::Instant) -> bool {
    let elapsed = fresh_at.elapsed();
    #[cfg(test)]
    let elapsed =
        elapsed + std::time::Duration::from_millis(TTL_TEST_OFFSET_MS.with(std::cell::Cell::get));
    elapsed >= ttl
}

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

    fn tier_decisions(&self) -> (bool, bool) {
        let use_findings = self.cached_findings.is_some()
            && self
                .findings_fresh_at
                .is_some_and(|t| !ttl_expired(FINDINGS_TTL, t));
        let use_snapshot = self.cached_snapshot.as_ref().is_some_and(|cluster| {
            let ttl = snapshot_ttl_for(cluster);
            self.snapshot_fresh_at.is_some_and(|t| !ttl_expired(ttl, t))
        });
        (use_findings, use_snapshot)
    }

    /// Start a background collection; a no-op if one is already in-flight.
    /// Each cache tier is consulted independently.
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
                    cached_findings.as_ref(),
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

    /// Returns `Some(bundle)` once the collection completes, `None` while
    /// pending; a tier's cache is written only when it re-ran on an available bundle.
    pub async fn poll(&mut self) -> Option<MonitorDataBundle> {
        match &mut self.rx {
            Some(rx) => {
                let result = rx.await.ok();
                if let Some((ref bundle, findings_used, snapshot_used, ref fresh_cluster)) = result
                    && bundle.available
                {
                    if !findings_used {
                        self.cached_findings = Some(std::sync::Arc::clone(&bundle.findings));
                        self.findings_fresh_at = Some(std::time::Instant::now());
                    }
                    if let Some(cluster) = fresh_cluster
                        && !snapshot_used
                    {
                        self.cached_snapshot = Some(std::sync::Arc::clone(cluster));
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

async fn collect_real_monitor(
    use_findings: bool,
    cached_findings: Option<std::sync::Arc<[FindingEntry]>>,
    use_snapshot: bool,
    cached_snapshot: Option<std::sync::Arc<SnapshotCluster>>,
) -> MonitorOutcome {
    let client =
        match tokio::task::spawn_blocking(toride_monitor::client::MonitorClient::system).await {
            Ok(Ok(client)) => client,
            Ok(Err(e)) => {
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

    let result = tokio::task::spawn_blocking(move || {
        collect_monitor_with_client(
            &client,
            use_findings,
            cached_findings.as_ref(),
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

#[expect(
    clippy::too_many_lines,
    reason = "real-data collection is inherently linear"
)]
fn collect_monitor_with_client(
    client: &toride_monitor::client::MonitorClient,
    use_findings: bool,
    cached_findings: Option<&std::sync::Arc<[FindingEntry]>>,
    use_snapshot: bool,
    cached_snapshot: Option<std::sync::Arc<SnapshotCluster>>,
) -> MonitorOutcome {
    {
        use toride_monitor::conntrack::ConntrackReader;
        use toride_monitor::doctor::{Doctor, DoctorScope};

        let findings_served = use_findings && cached_findings.is_some();
        let snapshot_served = use_snapshot && cached_snapshot.is_some();
        let findings: std::sync::Arc<[FindingEntry]> = if findings_served {
            std::sync::Arc::clone(cached_findings.expect("checked above"))
        } else {
            let doctor = Doctor::new(client.paths(), client.runner());
            match doctor.run(&DoctorScope::All) {
                Ok(report) => toride_monitor_convert::convert_findings(report.findings).into(),
                Err(e) => {
                    tracing::warn!("monitor doctor: {e}");
                    Vec::new().into()
                }
            }
        };

        let (cluster, fresh_cluster) = if snapshot_served && let Some(cached) = cached_snapshot {
            (std::sync::Arc::clone(&cached), None)
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
            let connections: std::sync::Arc<[ConnectionEntry]> = snapshot_report
                .as_ref()
                .map(|r| toride_monitor_convert::convert_connections(&r.connections))
                .unwrap_or_default()
                .into();
            let anomalies: std::sync::Arc<[AnomalyEntry]> = match snapshot_report.as_ref() {
                Ok(report) => match client.detect(report) {
                    Ok(anomaly_report) => {
                        toride_monitor_convert::convert_anomalies(anomaly_report.findings).into()
                    }
                    Err(e) => {
                        tracing::debug!("monitor detect: {e}");
                        Vec::new().into()
                    }
                },
                Err(_) => Vec::new().into(),
            };

            let reader = ConntrackReader::new(client.paths(), client.runner());
            let fast_count = reader.count().ok();
            let snapshot_count = snapshot_report.as_ref().ok().map(|r| r.total_connections);
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
                count: fast_count.or(snapshot_count).or(fallback_table_count),
                total_bytes: snapshot_bytes,
                total_packets: snapshot_packets,
            };

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
            let cluster = std::sync::Arc::new(cluster);
            (std::sync::Arc::clone(&cluster), Some(cluster))
        };

        let ports: Vec<PortEntry> = match client.list_listening_ports() {
            Ok(raw) => toride_monitor_convert::convert_ports(&raw),
            Err(e) => {
                tracing::debug!("monitor list_listening_ports: {e}");
                Vec::new()
            }
        };

        let available = monitor_available(
            cluster.snapshot_ok,
            !cluster.connections.is_empty(),
            !ports.is_empty(),
            !findings.is_empty(),
        );

        let bundle = MonitorDataBundle {
            available,
            summary: cluster.summary.clone(),
            connections: std::sync::Arc::clone(&cluster.connections),
            ports,
            conntrack: cluster.conntrack.clone(),
            output_rule_count: cluster.output_rule_count,
            anomalies: std::sync::Arc::clone(&cluster.anomalies),
            findings,
            unavailable_reason: None,
        };
        (bundle, findings_served, snapshot_served, fresh_cluster)
    }
}

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

fn empty_bundle() -> MonitorDataBundle {
    MonitorDataBundle {
        available: false,
        summary: SnapshotSummary::default(),
        connections: Vec::new().into(),
        ports: Vec::new(),
        conntrack: ConntrackSummary::default(),
        output_rule_count: None,
        anomalies: Vec::new().into(),
        findings: Vec::new().into(),
        unavailable_reason: None,
    }
}

fn empty_bundle_with_reason(reason: String) -> MonitorDataBundle {
    let mut b = empty_bundle();
    b.unavailable_reason = Some(reason);
    b
}

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
        collector.start();
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
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let _ = collector.poll().await;
        assert!(!collector.is_pending(), "poll should clear pending state");
    }

    #[tokio::test]
    async fn poll_returns_bundle_after_collection() {
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
        assert!(
            !monitor_available(false, false, false, false),
            "host where every runtime probe failed must not be 'available'"
        );
    }

    #[test]
    fn monitor_available_true_when_snapshot_ok() {
        assert!(monitor_available(true, false, false, false));
    }

    #[test]
    fn monitor_available_true_when_any_probe_produced_data() {
        assert!(monitor_available(false, true, false, false));
        assert!(monitor_available(false, false, true, false));
        assert!(monitor_available(false, false, false, true));
    }

    #[tokio::test]
    async fn findings_cache_is_populated_after_poll() {
        let mut collector = MonitorCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let bundle = collector.poll().await;
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
        collector.cached_findings = Some(Vec::new().into());
        collector.findings_fresh_at = Some(std::time::Instant::now());
        collector.cached_snapshot = Some(std::sync::Arc::new(SnapshotCluster {
            summary: SnapshotSummary::default(),
            connections: Vec::new().into(),
            anomalies: Vec::new().into(),
            conntrack: ConntrackSummary::default(),
            output_rule_count: None,
            snapshot_ok: false,
        }));
        collector.snapshot_fresh_at = Some(std::time::Instant::now());
        collector.invalidate_findings_cache();
        assert!(collector.cached_findings.is_none());
        assert!(collector.findings_fresh_at.is_none());
        assert!(collector.cached_snapshot.is_none());
        assert!(collector.snapshot_fresh_at.is_none());
    }
}

#[cfg(test)]
mod cadence_oracle {
    use super::*;

    const SENTINEL_ID: &str = "oracle-sentinel.monitor.findings-cache";

    const SENTINEL_DST: &str = "203.0.113.0";

    fn sentinel_cluster() -> SnapshotCluster {
        SnapshotCluster {
            summary: SnapshotSummary::default(),
            connections: vec![ConnectionEntry {
                protocol: "tcp".to_string(),
                src: "198.51.100.7:40000".to_string(),
                dst: format!("{SENTINEL_DST}:443"),
                state: "ESTABLISHED".to_string(),
                bytes: None,
            }]
            .into(),
            anomalies: Vec::new().into(),
            conntrack: ConntrackSummary::default(),
            output_rule_count: Some(1),
            snapshot_ok: true,
        }
    }

    fn sentinel_findings() -> std::sync::Arc<[FindingEntry]> {
        vec![FindingEntry {
            id: SENTINEL_ID.to_string(),
            severity: "ok".to_string(),
            title: "cadence-oracle sentinel".to_string(),
            detail: String::new(),
            fix: None,
        }]
        .into()
    }

    struct TtlOffsetGuard;

    impl TtlOffsetGuard {
        fn by_ms(ms: u64) -> Self {
            TTL_TEST_OFFSET_MS.with(|o| o.set(ms));
            Self
        }

        fn snapshot_only() -> Self {
            Self::by_ms(
                u64::try_from(SNAPSHOT_TTL.as_millis())
                    .expect("an 8s TTL in milliseconds always fits in u64")
                    + 1_000,
            )
        }

        fn failure_ttl_only() -> Self {
            Self::by_ms(
                u64::try_from(SNAPSHOT_FAILURE_TTL.as_millis())
                    .expect("a 4s TTL in milliseconds always fits in u64")
                    + 1_000,
            )
        }

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

    const SS_FIXTURE: &str = concat!(
        "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n",
        "tcp ESTAB 0 0 198.51.100.7:40000 203.0.113.9:443 users:((\"fixture-proc\",pid=1,fd=3))\n",
        "tcp ESTAB 0 0 198.51.100.7:40001 203.0.113.9:443 users:((\"fixture-proc\",pid=1,fd=4))",
    );

    fn ss_spec() -> toride_runner::CommandSpec {
        toride_runner::CommandSpec::new("/usr/bin/ss").args(["-tunap"])
    }

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

    fn failing_ss_client() -> (
        toride_monitor::client::MonitorClient,
        toride_runner::fake::FakeRunner,
    ) {
        let runner = toride_runner::fake::FakeRunner::new().respond_err(
            ss_spec(),
            toride_runner::Error::Io("oracle: ss spawn failure".into()),
        );
        let client = toride_monitor::client::MonitorClient::with_runner(
            Box::new(runner.clone()),
            toride_monitor::paths::MonitorPaths::default_paths(),
        );
        (client, runner)
    }

    fn ss_spawn_count(runner: &toride_runner::fake::FakeRunner) -> usize {
        runner
            .calls()
            .iter()
            .filter(|c| c.program == "/usr/bin/ss" && c.args == ["-tunap"])
            .count()
    }

    #[tokio::test]
    async fn both_tiers_fresh_serves_bundle_verbatim_with_zero_spawns() {
        let mut collector = MonitorCollector::new();
        collector.cached_findings = Some(sentinel_findings());
        collector.cached_snapshot = Some(std::sync::Arc::new(sentinel_cluster()));
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

    #[tokio::test]
    async fn snapshot_ttl_expires_before_findings_ttl() {
        let mut collector = MonitorCollector::new();
        collector.cached_findings = Some(sentinel_findings());
        collector.cached_snapshot = Some(std::sync::Arc::new(sentinel_cluster()));
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

    #[tokio::test]
    async fn both_ttls_expiring_reruns_everything() {
        let mut collector = MonitorCollector::new();
        collector.cached_findings = Some(sentinel_findings());
        collector.cached_snapshot = Some(std::sync::Arc::new(sentinel_cluster()));
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

    #[tokio::test]
    async fn failed_snapshot_backs_off_at_the_short_failure_ttl() {
        let mut collector = MonitorCollector::new();
        collector.cached_findings = Some(sentinel_findings());
        collector.findings_fresh_at = Some(std::time::Instant::now());

        let (client, runner) = failing_ss_client();
        collector.start_with_client(client);
        let bundle = collector.poll().await.expect("collection completes");
        assert!(
            bundle.available,
            "the sentinel findings keep the section available"
        );
        assert!(
            bundle.connections.is_empty(),
            "the failed snapshot produced no connections"
        );
        assert_eq!(ss_spawn_count(&runner), 1, "the snapshot tier did run ss");
        let failed_cluster = collector
            .cached_snapshot
            .as_ref()
            .expect("a failed fresh snapshot IS cached (for the short backoff TTL)");
        assert!(
            !failed_cluster.snapshot_ok,
            "the cached cluster records the failure"
        );
        assert!(collector.snapshot_fresh_at.is_some(), "and its clock armed");

        let (client2, runner2) = failing_ss_client();
        collector.start_with_client(client2);
        let second = collector.poll().await.expect("second collection completes");
        assert!(second.available);
        assert_eq!(
            ss_spawn_count(&runner2),
            0,
            "the immediate re-collect serves the failed cluster from cache: no spawn"
        );
        assert!(
            second.connections.is_empty(),
            "the cached failed cluster is served verbatim"
        );

        let ttl = TtlOffsetGuard::failure_ttl_only();
        let (client3, runner3) = fake_client();
        collector.start_with_client(client3);
        let third = collector.poll().await.expect("third collection completes");
        drop(ttl);
        assert!(third.available);
        assert_eq!(
            ss_spawn_count(&runner3),
            1,
            "the expired failure TTL re-ran ss exactly once"
        );
        assert_eq!(
            third.connections.len(),
            2,
            "the successful retry parsed both fixture rows"
        );
        assert!(
            collector
                .cached_snapshot
                .as_ref()
                .is_some_and(|c| c.snapshot_ok),
            "the SUCCESSFUL retry replaced the failed cluster in the cache"
        );

        let (client4, runner4) = fake_client();
        collector.start_with_client(client4);
        let fourth = collector.poll().await.expect("fourth collection completes");
        assert_eq!(
            ss_spawn_count(&runner4),
            0,
            "a healthy cluster is fresh for the full 8s TTL, not the 4s backoff"
        );
        assert_eq!(fourth.connections.len(), 2);
    }

    #[tokio::test]
    async fn healthy_cluster_outlives_the_failure_ttl() {
        let mut collector = MonitorCollector::new();
        collector.cached_findings = Some(sentinel_findings());
        collector.findings_fresh_at = Some(std::time::Instant::now());
        collector.cached_snapshot = Some(std::sync::Arc::new(sentinel_cluster()));
        let primed = std::time::Instant::now();
        collector.snapshot_fresh_at = Some(primed);

        let _ttl = TtlOffsetGuard::failure_ttl_only();
        let (client, runner) = fake_client();
        collector.start_with_client(client);
        let bundle = collector.poll().await.expect("collection completes");
        assert_eq!(
            ss_spawn_count(&runner),
            0,
            "5s of age must NOT expire a healthy 8s cluster"
        );
        assert_eq!(
            bundle.connections.len(),
            1,
            "the bundle served the cached sentinel cluster"
        );
        assert_eq!(
            bundle.connections[0].dst,
            format!("{SENTINEL_DST}:443"),
            "served verbatim"
        );
        assert_eq!(
            collector.snapshot_fresh_at,
            Some(primed),
            "a healthy-cluster cache hit must not re-arm the clock"
        );
    }

    #[tokio::test]
    async fn cache_hit_ticks_share_arc_allocations() {
        let mut collector = MonitorCollector::new();
        collector.cached_findings = Some(sentinel_findings());
        collector.cached_snapshot = Some(std::sync::Arc::new(sentinel_cluster()));
        collector.findings_fresh_at = Some(std::time::Instant::now());
        collector.snapshot_fresh_at = Some(std::time::Instant::now());

        let (client1, runner1) = fake_client();
        collector.start_with_client(client1);
        let b1 = collector.poll().await.expect("first collection completes");
        let (client2, runner2) = fake_client();
        collector.start_with_client(client2);
        let b2 = collector.poll().await.expect("second collection completes");
        assert_eq!(
            ss_spawn_count(&runner1) + ss_spawn_count(&runner2),
            0,
            "both collections were pure cache hits"
        );

        assert!(
            std::sync::Arc::ptr_eq(&b1.connections, &b2.connections),
            "consecutive hit bundles share the connections allocation"
        );
        assert!(
            std::sync::Arc::ptr_eq(&b1.anomalies, &b2.anomalies),
            "consecutive hit bundles share the anomalies allocation"
        );
        assert!(
            std::sync::Arc::ptr_eq(&b1.findings, &b2.findings),
            "consecutive hit bundles share the findings allocation"
        );
        assert!(
            std::sync::Arc::ptr_eq(
                &b1.connections,
                &collector
                    .cached_snapshot
                    .as_ref()
                    .expect("cache still populated")
                    .connections
            ),
            "the bundle's connections are the cache tier's own Arc"
        );
        assert!(
            std::sync::Arc::ptr_eq(
                &b1.findings,
                collector
                    .cached_findings
                    .as_ref()
                    .expect("cache still populated")
            ),
            "the bundle's findings are the cache tier's own Arc"
        );
    }
}
