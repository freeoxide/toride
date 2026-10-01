//! Async read-only UFW firewall collection: a missing `ufw` binary still
//! counts as `available` via a doctor finding; `false` means the task panicked.

use std::sync::Arc;

use tokio::sync::oneshot;

use crate::ufw_kit_convert;
use crate::ui::screens::ufw_kit::{FindingEntry, RuleEntry};

/// A read-only snapshot of UFW firewall state.
#[derive(Clone, Debug)]
pub struct FirewallDataBundle {
    /// `false` when construction failed or the collection task panicked;
    /// a missing `ufw` binary stays `true` (the doctor surfaces a finding).
    pub available: bool,
    /// Whether UFW is enabled.
    pub active: bool,
    /// Default incoming policy label.
    pub default_incoming: Option<String>,
    /// Default outgoing policy label.
    pub default_outgoing: Option<String>,
    /// Default routed policy label; `None` when routed is off (the parser
    /// maps UFW's "disabled" to `None`, rendered as "(unset)").
    pub default_routed: Option<String>,
    /// Logging level label.
    pub logging_level: Option<String>,
    /// UFW version string.
    pub version: Option<String>,
    /// Parsed firewall rules.
    pub rules: Vec<RuleEntry>,
    /// Doctor findings.
    pub findings: Vec<FindingEntry>,
    /// Populated only when `available == false` (a panicked task); rendered
    /// by the degraded panel.
    pub unavailable_reason: Option<String>,
}

/// Manages periodic async UFW collection with a 60s findings cache; the
/// long-lived [`ufw_kit::Ufw`] client carries its own read caches across ticks.
pub struct FirewallCollector {
    client: Arc<ufw_kit::Ufw>,
    rx: Option<oneshot::Receiver<(FirewallDataBundle, bool)>>,
    cached_findings: Option<Vec<FindingEntry>>,
    findings_fresh_at: Option<std::time::Instant>,
}

const FINDINGS_TTL: std::time::Duration = std::time::Duration::from_secs(60);

impl FirewallCollector {
    /// Create a new collector with no pending collection; the UFW client is
    /// constructed once here and reused for the collector's lifetime.
    #[must_use]
    pub fn new() -> Self {
        Self::with_client(Arc::new(ufw_kit::Ufw::system()))
    }

    fn with_client(client: Arc<ufw_kit::Ufw>) -> Self {
        Self {
            client,
            rx: None,
            cached_findings: None,
            findings_fresh_at: None,
        }
    }

    /// Whether a collection is currently in-flight.
    pub fn is_pending(&self) -> bool {
        self.rx.is_some()
    }

    /// Start a background collection; a no-op if one is already in-flight.
    /// A fresh 60s findings cache is served without re-running the doctor.
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
        let client = Arc::clone(&self.client);
        self.rx = Some(rx);
        tokio::spawn(async move {
            #[allow(
                clippy::similar_names,
                reason = "use_cache (input) vs used_cache (output) are distinct domain flags"
            )]
            let (bundle, used_cache) = collect_real_ufw(client, use_cache, cached_findings).await;
            let _ = tx.send((bundle, used_cache));
        });
    }

    /// Returns `Some(bundle)` once the collection completes, `None` if still
    /// pending; the freshness clock advances only when the doctor re-ran.
    pub async fn poll(&mut self) -> Option<FirewallDataBundle> {
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

impl Default for FirewallCollector {
    fn default() -> Self {
        Self::new()
    }
}

async fn collect_real_ufw(
    client: Arc<ufw_kit::Ufw>,
    use_cache: bool,
    cached_findings: Option<Vec<FindingEntry>>,
) -> (FirewallDataBundle, bool) {
    let result = tokio::task::spawn_blocking(move || {
        let ufw = client.as_ref();
        let findings: Vec<FindingEntry> = if use_cache {
            cached_findings.unwrap_or_default()
        } else {
            match ufw_kit::doctor::doctor(ufw, ufw_kit::spec::DoctorScope::All) {
                Ok(raw_findings) => ufw_kit_convert::convert_findings(raw_findings),
                Err(e) => {
                    tracing::warn!("ufw doctor: {e}");
                    Vec::new()
                }
            }
        };

        let (active, default_incoming, default_outgoing, default_routed, logging_level, rules) =
            match ufw.status_verbose() {
                Ok(s) => {
                    let rules = ufw_kit_convert::convert_rules(s.rules.clone());
                    (
                        s.active,
                        s.default_incoming.map(ufw_kit_convert::policy_to_string),
                        s.default_outgoing.map(ufw_kit_convert::policy_to_string),
                        s.default_routed.map(ufw_kit_convert::policy_to_string),
                        s.logging_level.map(ufw_kit_convert::logging_to_string),
                        rules,
                    )
                }
                Err(e) => {
                    tracing::debug!("ufw status verbose: {e}");
                    match ufw.status() {
                        Ok(s) => {
                            let rules = ufw_kit_convert::convert_rules(s.rules);
                            (s.active, None, None, None, None, rules)
                        }
                        Err(e2) => {
                            tracing::debug!("ufw status: {e2}");
                            (false, None, None, None, None, Vec::new())
                        }
                    }
                }
            };

        let version = match ufw.version() {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::debug!("ufw version: {e}");
                None
            }
        };

        let available = !rules.is_empty() || version.is_some() || !findings.is_empty() || active;

        FirewallDataBundle {
            available,
            active,
            default_incoming,
            default_outgoing,
            default_routed,
            logging_level,
            version,
            rules,
            findings,
            unavailable_reason: None,
        }
    })
    .await;

    match result {
        Ok(bundle) => (bundle, use_cache),
        Err(e) => {
            tracing::warn!("ufw collection task panicked: {e}");
            (
                empty_bundle_with_reason(format!("ufw data collection panicked: {e}")),
                false,
            )
        }
    }
}

fn empty_bundle() -> FirewallDataBundle {
    FirewallDataBundle {
        available: false,
        active: false,
        default_incoming: None,
        default_outgoing: None,
        default_routed: None,
        logging_level: None,
        version: None,
        rules: Vec::new(),
        findings: Vec::new(),
        unavailable_reason: None,
    }
}

fn empty_bundle_with_reason(reason: String) -> FirewallDataBundle {
    let mut b = empty_bundle();
    b.unavailable_reason = Some(reason);
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_not_pending() {
        let collector = FirewallCollector::new();
        assert!(!collector.is_pending());
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(
            FirewallCollector::new().is_pending(),
            FirewallCollector::default().is_pending()
        );
    }

    #[tokio::test]
    async fn start_makes_pending() {
        let mut collector = FirewallCollector::new();
        assert!(!collector.is_pending());
        collector.start();
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn start_is_idempotent() {
        let mut collector = FirewallCollector::new();
        collector.start();
        assert!(collector.is_pending());
        collector.start();
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn poll_returns_none_when_not_started() {
        let mut collector = FirewallCollector::new();
        assert!(collector.poll().await.is_none());
    }

    #[tokio::test]
    async fn poll_clears_pending() {
        let mut collector = FirewallCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let _ = collector.poll().await;
        assert!(!collector.is_pending(), "poll should clear pending state");
    }

    #[tokio::test]
    async fn poll_returns_bundle_after_collection() {
        let mut collector = FirewallCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let bundle = collector.poll().await;
        assert!(bundle.is_some(), "poll should return Some after completion");
    }

    #[test]
    fn empty_bundle_is_unavailable() {
        let b = empty_bundle();
        assert!(!b.available);
        assert!(b.rules.is_empty());
        assert!(b.findings.is_empty());
        assert!(b.version.is_none());
        assert!(b.default_incoming.is_none());
        assert!(b.logging_level.is_none());
        assert!(
            b.unavailable_reason.is_none(),
            "empty_bundle carries no reason; panics use empty_bundle_with_reason"
        );
    }

    #[tokio::test]
    async fn findings_cache_is_populated_after_poll() {
        let mut collector = FirewallCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let _ = collector.poll().await;
        assert!(collector.cached_findings.is_some());
        assert!(collector.findings_fresh_at.is_some());
    }

    struct CountingUfw {
        inner: ufw_kit::command::FakeRunner,
        spawns: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl CountingUfw {
        fn new(
            inner: ufw_kit::command::FakeRunner,
        ) -> (Self, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
            let spawns = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            (
                Self {
                    inner,
                    spawns: std::sync::Arc::clone(&spawns),
                },
                spawns,
            )
        }
    }

    impl ufw_kit::command::CommandRunner for CountingUfw {
        fn run(
            &self,
            spec: &ufw_kit::spec::CommandSpec,
        ) -> ufw_kit::Result<ufw_kit::spec::CommandResult> {
            self.spawns
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.inner.run(spec)
        }

        fn binary_exists(&self, name: &str) -> bool {
            self.inner.binary_exists(name)
        }
    }

    #[tokio::test]
    async fn first_collect_spawns_second_collect_within_windows_spawns_nothing() {
        let runner = CountingUfw::new(
            ufw_kit::command::FakeRunner::new()
                .respond_ok(
                    "ufw",
                    &["status", "verbose"],
                    "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing)\n",
                )
                .respond_ok("ufw", &["--version"], "ufw 0.36.2\n"),
        );
        let (runner, spawns) = runner;
        let ufw = ufw_kit::Ufw::with_runner(runner);
        let mut collector = FirewallCollector::with_client(std::sync::Arc::new(ufw));

        collector.start();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let first = collector.poll().await.expect("first bundle");
        let first_spawns = spawns.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            first.available,
            "canned verbose status keeps the section available"
        );
        assert!(
            first_spawns > 0,
            "the first collection on a fresh client must not be served from any cache"
        );

        collector.start();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let second = collector.poll().await.expect("second bundle");
        assert_eq!(
            spawns.load(std::sync::atomic::Ordering::Relaxed),
            first_spawns,
            "a collection inside the findings/status/version cache windows \
             must not spawn any command (F09)"
        );
        assert_eq!(
            format!("{first:?}"),
            format!("{second:?}"),
            "the cached collection must return the same bundle"
        );
    }

    #[test]
    fn invalidate_findings_cache_clears_it() {
        let mut collector = FirewallCollector::new();
        collector.cached_findings = Some(Vec::new());
        collector.findings_fresh_at = Some(std::time::Instant::now());
        collector.invalidate_findings_cache();
        assert!(collector.cached_findings.is_none());
        assert!(collector.findings_fresh_at.is_none());
    }
}
