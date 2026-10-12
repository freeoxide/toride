//! Async setup-bundle collection (read-only).
//!
//! The whole presence walk (registry evaluate over `$PATH` + managed dirs)
//! is cached for 60s: a newly installed tool stops being offered up to 60s
//! late.

use std::time::Duration;

use tokio::sync::oneshot;
use toride_apps::Target;
use toride_installer::Detector;

use crate::setup_bundles::{DetectorPresence, SetupOffers, evaluate};
use crate::ui::screens::tools::FindingEntry;

/// Aggregated setup-bundle data for the read-only section.
#[derive(Clone, Debug)]
pub struct SetupDataBundle {
    /// Whether the presence walk ran; `false` only for a collection panic.
    /// A host with every suggested tool installed still yields `true` (the
    /// offers are honestly empty, the panel renders its empty state).
    pub available: bool,
    /// Evaluated offers for this host, in registry order.
    pub offers: SetupOffers,
    /// Info-level suggestion findings (`setup.suggest.<bundle>.<row>` ids).
    /// Empty until the phase-4 doctor adoption fills it via `to_findings`.
    pub findings: Vec<FindingEntry>,
    /// Reason collection failed; populated only when `available == false`
    /// (collection-task panic).
    pub unavailable_reason: Option<String>,
}

/// Manages periodic async collection of setup offers.
///
/// A 60s TTL cache covers the whole walk (offers + findings).
pub struct SetupCollector {
    rx: Option<oneshot::Receiver<(SetupDataBundle, bool)>>,
    cached_bundle: Option<SetupDataBundle>,
    bundle_fresh_at: Option<std::time::Instant>,
}

const SWEEP_TTL: Duration = Duration::from_secs(60);

fn ttl_expired(fresh_at: std::time::Instant) -> bool {
    let elapsed = fresh_at.elapsed();
    #[cfg(test)]
    let elapsed = elapsed + Duration::from_millis(TTL_TEST_OFFSET_MS.with(std::cell::Cell::get));
    elapsed >= SWEEP_TTL
}

#[cfg(test)]
thread_local! {
    static TTL_TEST_OFFSET_MS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

impl SetupCollector {
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
    /// If a collection is already in-flight, this is a no-op; a fresh cache
    /// is served verbatim without any presence walk.
    pub fn start(&mut self) {
        if self.rx.is_some() {
            return;
        }
        let (tx, rx) = oneshot::channel();
        let use_cache =
            self.cached_bundle.is_some() && self.bundle_fresh_at.is_some_and(|t| !ttl_expired(t));
        let cached_bundle = self.cached_bundle.clone();
        self.rx = Some(rx);
        let handle =
            tokio::spawn(async move { collect_real_offers(use_cache, cached_bundle).await });
        tokio::spawn(async move {
            let result = handle.await;
            let (bundle, reused_cache) = match result {
                Ok(tuple) => tuple,
                Err(e) => {
                    tracing::warn!("setup data collection panicked: {e}");
                    (
                        empty_bundle_with_reason(format!("setup data collection panicked: {e}")),
                        false,
                    )
                }
            };
            let _ = tx.send((bundle, reused_cache));
        });
    }

    /// Poll for a completed collection result.
    ///
    /// Returns `Some(bundle)` on completion, `None` while pending or failed.
    /// A degraded (panic) bundle is never cached.
    pub async fn poll(&mut self) -> Option<SetupDataBundle> {
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

    /// Invalidate the offers cache so the next collection re-runs the walk.
    #[allow(dead_code)]
    pub fn invalidate_offers_cache(&mut self) {
        self.cached_bundle = None;
        self.bundle_fresh_at = None;
    }
}

impl Default for SetupCollector {
    fn default() -> Self {
        Self::new()
    }
}

async fn collect_real_offers(
    use_cache: bool,
    cached_bundle: Option<SetupDataBundle>,
) -> (SetupDataBundle, bool) {
    if use_cache && let Some(bundle) = cached_bundle {
        return (bundle, true);
    }

    let result = tokio::task::spawn_blocking(move || {
        let detector = Detector::builder().probe_timeout(PRESENCE_TIMEOUT).build();
        let presence = DetectorPresence::new(detector);
        evaluate(&Target::host(), &presence)
    })
    .await;

    match result {
        Ok(offers) => (
            SetupDataBundle {
                available: true,
                offers,
                findings: Vec::new(),
                unavailable_reason: None,
            },
            false,
        ),
        Err(e) => {
            tracing::warn!("setup collection task panicked: {e}");
            (
                empty_bundle_with_reason(format!("setup data collection panicked: {e}")),
                false,
            )
        }
    }
}

const PRESENCE_TIMEOUT: Duration = Duration::from_millis(800);

fn empty_bundle() -> SetupDataBundle {
    SetupDataBundle {
        available: false,
        offers: SetupOffers {
            bundles: Vec::new(),
            satisfied: Vec::new(),
        },
        findings: Vec::new(),
        unavailable_reason: None,
    }
}

fn empty_bundle_with_reason(reason: String) -> SetupDataBundle {
    let mut b = empty_bundle();
    b.unavailable_reason = Some(reason);
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup_bundles::{SetupBundle, SetupOffers as Offers};

    #[test]
    fn new_is_not_pending() {
        let collector = SetupCollector::new();
        assert!(!collector.is_pending());
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(
            SetupCollector::new().is_pending(),
            SetupCollector::default().is_pending()
        );
    }

    #[tokio::test]
    async fn start_makes_pending() {
        let mut collector = SetupCollector::new();
        assert!(!collector.is_pending());
        collector.start();
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn start_is_idempotent() {
        let mut collector = SetupCollector::new();
        collector.start();
        assert!(collector.is_pending());
        collector.start();
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn poll_returns_none_when_not_started() {
        let mut collector = SetupCollector::new();
        assert!(collector.poll().await.is_none());
    }

    #[tokio::test]
    async fn poll_clears_pending() {
        let mut collector = SetupCollector::new();
        collector.start();
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let _ = collector.poll().await;
        assert!(!collector.is_pending(), "poll should clear pending state");
    }

    #[tokio::test]
    async fn poll_returns_bundle_after_collection() {
        let mut collector = SetupCollector::new();
        collector.start();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let bundle = collector.poll().await;
        let b = bundle.expect("poll should return Some after completion");
        assert!(b.available, "the walk always runs -> available == true");
        assert!(b.findings.is_empty(), "findings feed lands in phase 4");
        assert!(b.unavailable_reason.is_none());
        for bundle in &b.offers.bundles {
            assert!(
                !bundle.recommendations.is_empty(),
                "evaluate never offers an empty bundle: {}",
                bundle.id
            );
        }
    }

    #[test]
    fn empty_bundle_is_unavailable() {
        let b = empty_bundle();
        assert!(!b.available);
        assert!(b.offers.bundles.is_empty());
        assert!(b.findings.is_empty());
        assert!(
            b.unavailable_reason.is_none(),
            "empty_bundle carries no reason; panics use empty_bundle_with_reason"
        );
    }

    #[test]
    fn empty_bundle_with_reason_carries_reason() {
        let b = empty_bundle_with_reason("setup data collection panicked: boom".into());
        assert!(!b.available);
        assert_eq!(
            b.unavailable_reason.as_deref(),
            Some("setup data collection panicked: boom")
        );
    }

    #[tokio::test]
    async fn offers_cache_is_populated_after_poll() {
        let mut collector = SetupCollector::new();
        collector.start();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let _ = collector.poll().await;
        assert!(collector.cached_bundle.is_some());
        assert!(collector.bundle_fresh_at.is_some());
    }

    #[test]
    fn invalidate_offers_cache_clears_it() {
        let mut collector = SetupCollector::new();
        collector.cached_bundle = Some(sentinel_bundle());
        collector.bundle_fresh_at = Some(std::time::Instant::now());
        collector.invalidate_offers_cache();
        assert!(collector.cached_bundle.is_none());
        assert!(collector.bundle_fresh_at.is_none());
    }

    fn sentinel_bundle() -> SetupDataBundle {
        SetupDataBundle {
            available: true,
            offers: Offers {
                bundles: vec![SetupBundle {
                    id: "oracle-sentinel",
                    title: "oracle sentinel",
                    default_pick: "oracle-sentinel-row",
                    recommendations: Vec::new(),
                }],
                satisfied: Vec::new(),
            },
            findings: Vec::new(),
            unavailable_reason: None,
        }
    }
}

#[cfg(test)]
mod cadence_oracle {
    use super::*;
    use crate::setup_bundles::{SetupBundle, SetupOffers as Offers};

    const SENTINEL_ID: &str = "oracle-sentinel";

    fn sentinel_bundle() -> SetupDataBundle {
        SetupDataBundle {
            available: true,
            offers: Offers {
                bundles: vec![SetupBundle {
                    id: SENTINEL_ID,
                    title: "oracle sentinel",
                    default_pick: "oracle-sentinel-row",
                    recommendations: Vec::new(),
                }],
                satisfied: Vec::new(),
            },
            findings: Vec::new(),
            unavailable_reason: None,
        }
    }

    struct TtlOffsetGuard;

    impl TtlOffsetGuard {
        fn past_ttl() -> Self {
            TTL_TEST_OFFSET_MS.with(|o| {
                o.set(
                    u64::try_from(SWEEP_TTL.as_millis())
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
    async fn cache_hit_returns_cached_bundle_without_rewalking() {
        let mut collector = SetupCollector::new();
        collector.cached_bundle = Some(sentinel_bundle());
        let primed = std::time::Instant::now();
        collector.bundle_fresh_at = Some(primed);

        collector.start();
        let bundle = collector.poll().await.expect("collection completes");

        assert_eq!(
            bundle.offers.bundles.len(),
            1,
            "a cache hit must serve the cached bundles verbatim"
        );
        assert_eq!(
            bundle.offers.bundles[0].id, SENTINEL_ID,
            "the sentinel id can only come from the cache, never from a real walk"
        );
        assert_eq!(
            collector.bundle_fresh_at,
            Some(primed),
            "a cache-hit poll must not advance (re-arm) the freshness timestamp"
        );
    }

    #[tokio::test]
    async fn ttl_expiry_bypasses_cache_and_rederives() {
        let mut collector = SetupCollector::new();
        collector.cached_bundle = Some(sentinel_bundle());
        let primed = std::time::Instant::now();
        collector.bundle_fresh_at = Some(primed);

        let _ttl = TtlOffsetGuard::past_ttl();
        collector.start();
        let bundle = collector.poll().await.expect("collection completes");

        assert!(
            bundle.offers.bundles.iter().all(|b| b.id != SENTINEL_ID),
            "an expired cache must not serve the sentinel bundle"
        );
        assert!(
            collector.bundle_fresh_at.is_some_and(|t| t > primed),
            "an expired cache must be re-derived and the freshness clock advanced"
        );
    }
}
