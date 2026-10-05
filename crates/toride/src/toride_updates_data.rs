//! Async read-only updates collection with a 60s whole-bundle cache and a
//! 30s hard probe deadline; hosts without apt/dnf degrade to `available = false`.

use tokio::sync::oneshot;

use crate::toride_updates_convert;
use crate::ui::screens::toride_updates::FindingEntry;

/// A read-only snapshot of system-update state.
#[derive(Clone, Debug)]
pub struct UpdatesDataBundle {
    /// `false` when construction failed entirely (e.g. `PackageDetection`
    /// on macOS) or the collection task panicked; renders the degraded panel.
    pub available: bool,
    /// Detected package-manager label (e.g. `"apt"`); empty on construction failure.
    pub package_manager: String,
    /// Whether unattended/automatic updates are enabled.
    pub auto_updates_enabled: bool,
    /// Whether the automatic-update service is active.
    pub service_active: bool,
    /// Count of pending security updates.
    pub pending_security: usize,
    /// Count of all pending updates.
    pub pending_total: usize,
    /// Timestamp of the last successful update run, ISO 8601.
    pub last_run: Option<String>,
    /// Human-readable update schedule label; `None` when unknown.
    pub schedule: Option<String>,
    /// Whether the update timer/service unit is active; `None` when the probe
    /// failed or the package manager is unknown.
    pub timer_active: Option<bool>,
    /// Doctor findings.
    pub findings: Vec<FindingEntry>,
    /// Populated only when `available == false` (construction failure, probe
    /// deadline, or a panicked task); rendered by the degraded panel.
    pub unavailable_reason: Option<String>,
}

/// Manages periodic async updates collection with a 60s whole-bundle cache so
/// the `apt-check` / `dnf check-update` / `systemctl` probes skip cache-hit ticks.
pub struct UpdatesCollector {
    rx: Option<oneshot::Receiver<(UpdatesDataBundle, bool)>>,
    cached_bundle: Option<UpdatesDataBundle>,
    bundle_fresh_at: Option<std::time::Instant>,
}

const BUNDLE_TTL: std::time::Duration = std::time::Duration::from_secs(60);

fn ttl_expired(fresh_at: std::time::Instant) -> bool {
    let elapsed = fresh_at.elapsed();
    #[cfg(test)]
    let elapsed =
        elapsed + std::time::Duration::from_millis(TTL_TEST_OFFSET_MS.with(std::cell::Cell::get));
    elapsed >= BUNDLE_TTL
}

#[cfg(test)]
thread_local! {
    static TTL_TEST_OFFSET_MS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

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

    /// Start a background collection; a no-op if one is already in-flight.
    /// A fresh 60s cache is served verbatim without running any probe.
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

    /// Returns `Some(bundle)` once the collection completes, `None` while
    /// pending; a degraded bundle is never cached, so the next tick retries.
    pub async fn poll(&mut self) -> Option<UpdatesDataBundle> {
        match &mut self.rx {
            Some(rx) => {
                let result = rx.await.ok();
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

impl Default for UpdatesCollector {
    fn default() -> Self {
        Self::new()
    }
}

async fn collect_real_updates(
    use_cache: bool,
    cached_bundle: Option<UpdatesDataBundle>,
) -> (UpdatesDataBundle, bool) {
    if use_cache && let Some(bundle) = cached_bundle {
        return (bundle, true);
    }

    let client = match tokio::task::spawn_blocking(toride_updates::client::UpdatesClient::new).await
    {
        Ok(Ok(client)) => client,
        Ok(Err(e)) => {
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

    let result = tokio::task::spawn_blocking(move || {
        let runner = toride_updates::DuctRunner;

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

        let pm = client.package_manager();
        let package_manager = toride_updates_convert::package_manager_str(pm).to_string();

        let (pending_security, pending_total) = match client.check_updates() {
            Ok((sec, total)) => (sec, total),
            Err(e) => {
                tracing::debug!("updates check_updates: {e}");
                (0, 0)
            }
        };

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

        let schedule: Option<String> = None;

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
            unavailable_reason: None,
        }
    })
    .await;

    match result {
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

fn empty_bundle_with_reason(reason: String) -> UpdatesDataBundle {
    let mut b = empty_bundle();
    b.unavailable_reason = Some(reason);
    b
}

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
        collector.start();
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
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let _ = collector.poll().await;
        assert!(!collector.is_pending(), "poll should clear pending state");
    }

    #[tokio::test]
    async fn poll_returns_bundle_after_collection() {
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
        assert_eq!(b.package_manager, "");
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
        let mut collector = UpdatesCollector::new();
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

#[cfg(test)]
mod cadence_oracle {
    use super::*;

    const SENTINEL_ID: &str = "oracle-sentinel.updates.findings-cache";

    const SENTINEL_LABEL: &str = "oracle-sentinel";

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

    struct TtlOffsetGuard;

    impl TtlOffsetGuard {
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

    #[tokio::test]
    async fn cache_hit_returns_cached_bundle_without_reprobing() {
        let mut collector = UpdatesCollector::new();
        collector.cached_bundle = Some(sentinel_bundle());
        let primed = std::time::Instant::now();
        collector.bundle_fresh_at = Some(primed);

        collector.start();
        let bundle = collector.poll().await.expect("collection completes");

        if bundle.available {
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
            assert!(
                collector.bundle_fresh_at.is_some_and(|t| t > primed),
                "an expired cache must be re-derived and the freshness clock advanced"
            );
        } else {
            assert_eq!(
                collector.bundle_fresh_at,
                Some(primed),
                "a degraded bundle must not advance the freshness timestamp"
            );
        }
    }
}
