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
use crate::ui::screens::setup::suggest_id;
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
    /// Info-level suggestion findings (`setup.suggest.<bundle>.<row>` ids),
    /// one per offered row; the setup screen filters its session dismissals.
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

/// Convert evaluated offers into suggestion findings, one per offered row.
///
/// Ids reuse [`suggest_id`] so they join the setup screen's session-dismissal
/// set by construction; severity is always `"info"` and never the doctor's
/// `tools.missing.*` warning space.
#[must_use]
pub fn to_findings(offers: &SetupOffers) -> Vec<FindingEntry> {
    offers
        .bundles
        .iter()
        .flat_map(|bundle| {
            bundle.recommendations.iter().map(|rec| FindingEntry {
                id: suggest_id(bundle.id, rec),
                severity: "info".to_string(),
                title: format!("{} — {}", rec.title, rec.rationale),
            })
        })
        .collect()
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
        Ok(offers) => {
            let findings = to_findings(&offers);
            (
                SetupDataBundle {
                    available: true,
                    offers,
                    findings,
                    unavailable_reason: None,
                },
                false,
            )
        }
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
    use crate::setup_bundles::{SetupBundle, SetupOffers as Offers, ToolPresence};
    use crate::ui::screens::section_overview::SectionOverview;
    use crate::ui::screens::setup::SetupContent;
    use crossterm::event::KeyCode;
    use toride_apps::{Arch, Os, Target};

    struct NoPresence;

    impl ToolPresence for NoPresence {
        fn is_present(&self, _binaries: &[&str]) -> bool {
            false
        }
    }

    fn mac_offers() -> SetupOffers {
        evaluate(&Target::new(Os::MacOs, Arch::Aarch64), &NoPresence)
    }

    #[test]
    fn to_findings_cover_every_offered_row_with_namespaced_ids() {
        let offers = mac_offers();
        let findings = to_findings(&offers);
        let rows: usize = offers
            .bundles
            .iter()
            .map(|bundle| bundle.recommendations.len())
            .sum();
        assert!(!findings.is_empty(), "NoPresence offers every row");
        assert_eq!(findings.len(), rows, "one finding per offered row");
        for f in &findings {
            assert_eq!(f.severity, "info", "suggestions are info-level: {}", f.id);
            assert!(
                f.id.starts_with("setup.suggest."),
                "namespaced id: {}",
                f.id
            );
        }
    }

    #[test]
    fn to_findings_stay_out_of_the_tools_doctor_id_space() {
        for f in to_findings(&mac_offers()) {
            assert_ne!(
                f.severity, "warning",
                "a suggestion must never warn: {}",
                f.id
            );
            assert!(
                !f.id.starts_with("tools.missing."),
                "a suggestion must never reuse doctor ids: {}",
                f.id
            );
        }
    }

    #[test]
    fn findings_join_the_setup_screen_dismissal_key_space() {
        let offers = mac_offers();
        let findings = to_findings(&offers);
        let total = findings.len();

        let mut c = SetupContent::new();
        c.set_available(true);
        c.set_offers(offers);
        c.set_findings(findings);
        assert_eq!(
            c.findings_count(),
            total,
            "the collector feed and the screen must share one key space"
        );

        c.handle_key(KeyCode::Char('x'));
        assert_eq!(
            c.findings_count(),
            total - 1,
            "dismissing the selected row drops exactly its own finding"
        );
    }

    #[test]
    fn dismissed_ids_stay_out_across_a_fresh_walk() {
        let offers = mac_offers();
        let total = to_findings(&offers).len();

        let mut c = SetupContent::new();
        c.set_available(true);
        c.set_offers(offers.clone());
        c.set_findings(to_findings(&offers));
        c.handle_key(KeyCode::Char('x'));

        c.set_findings(to_findings(&offers));
        assert_eq!(
            c.findings_count(),
            total - 1,
            "a fresh walk re-emits every id, but session dismissal holds until restart"
        );
    }

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
        let offered: usize = b
            .offers
            .bundles
            .iter()
            .map(|bundle| bundle.recommendations.len())
            .sum();
        assert_eq!(b.findings.len(), offered, "one finding per offered row");
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
