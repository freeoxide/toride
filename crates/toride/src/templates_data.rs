//! Async hardening-recipes catalogue data collection (LIVE READ-ONLY).
//!
//! [`TemplatesCollector`] manages background collection of the recipe catalogue
//! via a tokio oneshot channel, following the same pattern as
//! [`HardenCollector`](crate::toride_harden_data::HardenCollector) and
//! [`Fail2banCollector`](crate::fail2ban_data::Fail2banCollector) (which
//! themselves mirror [`SshDataCollector`](crate::ssh_data::SshDataCollector)
//! MINUS the write path).
//!
//! This is a read-only integration: there are no write operations, no
//! optimistic updates, no cooldown gate, and no loading spinner. The only
//! "backend" work is a `which::which` sweep over the catalogue, which is a
//! pure read.
//!
//! ## What is "live" here
//!
//! The recipe DEFINITIONS are the app feature manifest (a constant menu of
//! toride capabilities) — legitimate static app data, NOT fake user data. Each
//! recipe's per-recipe LIVE status is whether the underlying tool is present on
//! THIS host, probed via [`which::which`]. The catalogue itself never changes
//! at runtime; only the readiness column is live.
//!
//! ## Blocking
//!
//! [`which::which`] does a synchronous PATH walk. All probes for the whole
//! catalogue run in a SINGLE [`tokio::task::spawn_blocking`] so the tokio
//! worker is never stalled — exactly mirroring how `toride_harden_data` keeps
//! every shell-out off the worker in one blocking closure.
//!
//! ## Findings cache
//!
//! The `which` sweep is cheap, but the per-recipe readiness (and the derived
//! INFO findings for missing targets) changes slowly — tools are not
//! installed/uninstalled moment-to-moment. Findings are therefore cached for
//! 60s, exactly like the harden / fail2ban / ufw-kit / tailscale caches: the
//! 2s refresh tick reuses the cached findings instead of re-running the whole
//! sweep. The catalogue itself is re-derived on every poll (it is a `const`
//! slice, so this is free), so a future recipe added to the manifest surfaces
//! immediately even mid-cache-window.
//!
//! ## Availability heuristic
//!
//! The catalogue is constant app data and the `which` sweep cannot fail at
//! construction, so the section is `available == true` on every host after a
//! successful collection. Only a `spawn_blocking` task panic (`JoinError`) flips
//! `available` to `false`, surfacing the degraded panel — mirroring the
//! harden / fail2ban / cloud collectors' panic path.

use std::time::Duration;

use tokio::sync::oneshot;

use crate::templates_convert;
use crate::ui::screens::templates::{FindingEntry, RecipeEntry};

/// Aggregated recipe-catalogue data for the read-only section.
#[derive(Clone, Debug)]
pub struct TemplatesDataBundle {
    /// Whether the catalogue could be collected at all. `false` is reserved
    /// for the panic case (a `spawn_blocking` `JoinError`) — the catalogue is
    /// constant app data and the `which` sweep cannot fail at construction, so
    /// every successful collection yields `true`. `false` renders the degraded
    /// "unavailable" panel.
    pub available: bool,
    /// Live recipe entries (constant definitions + per-recipe `which` status).
    pub recipes: Vec<RecipeEntry>,
    /// Number of recipes whose target tool is installed (`status == "ready"`).
    pub ready_count: usize,
    /// Total recipes in the catalogue.
    pub total_count: usize,
    /// INFO-severity findings for recipes whose target tool is missing
    /// (cached for 60s between collections).
    pub findings: Vec<FindingEntry>,
    /// Human-readable reason the backend was unreachable, populated ONLY when
    /// `available == false` (collection-task panic). `None` otherwise —
    /// notably also `None` for a freshly-constructed empty bundle before any
    /// collection has run. Surfaced to the UI so the degraded panel can show
    /// what actually went wrong instead of guessing.
    pub unavailable_reason: Option<String>,
}

// ── Collector ───────────────────────────────────────────────────────────────

/// Manages periodic async collection of the recipe catalogue.
///
/// Mirrors [`HardenCollector`](crate::toride_harden_data::HardenCollector): a
/// oneshot channel for the in-flight result, plus a 60s TTL cache for the
/// readiness findings so the `which` sweep is not re-run on every 2s refresh
/// tick.
pub struct TemplatesCollector {
    /// Carries the bundle AND whether the cached findings were reused for this
    /// poll. The freshness timestamp must only be advanced when the sweep was
    /// actually re-run (`used_cache == false`); otherwise every cache-hit poll
    /// would reset the TTL clock with the SAME (already-cached) findings and
    /// the cache would never expire for the lifetime of the app.
    rx: Option<oneshot::Receiver<(TemplatesDataBundle, bool)>>,
    /// Cached readiness findings from the last sweep.
    cached_findings: Option<Vec<FindingEntry>>,
    /// When the findings cache was last refreshed.
    findings_fresh_at: Option<std::time::Instant>,
}

/// How long to keep cached findings before re-running the `which` sweep.
#[expect(
    clippy::duration_suboptimal_units,
    reason = "stable std lacks from_mins"
)]
const FINDINGS_TTL: Duration = Duration::from_secs(60);

impl TemplatesCollector {
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
    /// findings instead of re-running the `which` sweep.
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
            let (bundle, used_cache) = collect_real_templates(use_cache, cached_findings).await;
            let _ = tx.send((bundle, used_cache));
        });
    }

    /// Poll for a completed collection result.
    ///
    /// Returns `Some(bundle)` if the collection completed, `None` if still
    /// pending or if the collection failed. On success the cached findings are
    /// updated to the freshly-returned findings, but the freshness timestamp
    /// is only advanced when the sweep was actually re-run (not on a cache-hit
    /// poll) — otherwise the 60s TTL would be re-armed forever with the same
    /// cached data on every 2s refresh.
    pub async fn poll(&mut self) -> Option<TemplatesDataBundle> {
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

    /// Invalidate the findings cache so the next collection re-runs the sweep.
    #[allow(dead_code)]
    pub fn invalidate_findings_cache(&mut self) {
        self.cached_findings = None;
        self.findings_fresh_at = None;
    }
}

impl Default for TemplatesCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Real data collection ────────────────────────────────────────────────────

/// Collect the recipe catalogue by running the `which::which` sweep over every
/// recipe's target binary.
///
/// All work runs on the blocking thread pool (the `which` PATH walk is
/// synchronous). The whole catalogue is swept in a SINGLE
/// [`tokio::task::spawn_blocking`] so the tokio worker is never stalled.
/// Findings may be reused from the cache. On ANY panic (`JoinError` from the
/// outer `spawn_blocking`) returns [`empty_bundle_with_reason`] with
/// `available = false`.
///
/// `use_cache` / `cached_findings` mirror the harden / fail2ban findings cache:
/// when the cache is fresh the `which` sweep is skipped entirely (the catalogue
/// definitions are re-derived for free — they are a `const` slice — but the
/// readiness booleans and derived findings are reused).
///
/// Returns `(bundle, used_cache)` where `used_cache` records whether the
/// findings were actually taken from the cache on a successful collection. The
/// caller advances the TTL clock ONLY when `used_cache == false`, so a
/// cache-hit poll never resets the freshness timestamp with stale data.
#[allow(
    clippy::similar_names,
    reason = "use_cache (input) vs used_cache (output) are distinct domain flags"
)]
async fn collect_real_templates(
    use_cache: bool,
    cached_findings: Option<Vec<FindingEntry>>,
) -> (TemplatesDataBundle, bool) {
    // The catalogue definitions are pure static data (a `const` slice) — no
    // backend, no I/O — so total_count is known without any probe.
    let defs = templates_convert::catalogue();
    let total_count = defs.len();

    // Run the `which::which` sweep (unless cached) in a single spawn_blocking
    // that owns the catalogue. This keeps every synchronous PATH walk off the
    // tokio worker, mirroring the harden collector's single-blocking-closure
    // approach. Results are returned as plain owned data so they cross the
    // thread boundary cleanly. The closure threads `used_cache` out alongside
    // the bundle so the caller can advance the TTL clock correctly.
    let result = tokio::task::spawn_blocking(move || {
        // ── Readiness sweep (unless cached) ────────────────────────────────
        // One `which::which` call per recipe, exactly what the wireguard
        // collector does for `wg` / `wg-quick` and what fail2ban does for
        // nft/iptables availability. Cheap, but cached for 60s for
        // consistency with the other read-only sections.
        //
        // On a cache hit there is no fresh sweep: the cached findings ARE the
        // source of truth, so reuse them verbatim and re-derive the recipes'
        // per-entry `status` from their ids. The findings carry the
        // severity/title/fix strings we want to preserve across cache-hit
        // polls; converting the reconstructed `installed_vec` would
        // re-marshal those strings and risk drift.
        let used_cache = use_cache;
        let cached = cached_findings.unwrap_or_default();

        // Reconstruct per-recipe installed flags from the cached findings on a
        // cache hit; otherwise sweep freshly. A recipe is ready iff there is
        // no `templates.missing.<id>` finding for it.
        let installed_vec: Vec<bool> = if used_cache {
            let missing: std::collections::HashSet<&str> = cached
                .iter()
                .filter_map(|f| f.id.strip_prefix("templates.missing."))
                .collect();
            defs.iter().map(|d| !missing.contains(d.id)).collect()
        } else {
            defs.iter()
                .map(|d| which::which(d.target_binary).is_ok())
                .collect()
        };

        let recipes = templates_convert::convert_recipes(&installed_vec);
        let ready_count = recipes.iter().filter(|r| r.status == "ready").count();

        // Findings: reuse the cached Vec verbatim on a hit (preserves
        // severity/title/fix), otherwise convert freshly from the swept flags.
        let findings: Vec<FindingEntry> = if used_cache {
            cached
        } else {
            templates_convert::convert_findings(&installed_vec)
        };

        (
            TemplatesDataBundle {
                available: true,
                recipes,
                ready_count,
                total_count,
                findings,
                unavailable_reason: None,
            },
            used_cache,
        )
    })
    .await;

    match result {
        Ok((bundle, used_cache)) => (bundle, used_cache),
        Err(e) => {
            tracing::warn!("templates data collection panicked: {e}");
            (
                empty_bundle_with_reason(format!("templates data collection panicked: {e}")),
                false,
            )
        }
    }
}

/// Empty bundle used when the collection task panicked (`spawn_blocking`
/// `JoinError`) — mirrors [`harden_data::empty_bundle`] and the sibling
/// collectors. `available = false` signals the UI to render the degraded
/// panel; no reason is attached because none is known at this point (the
/// `JoinError` reason is added by [`empty_bundle_with_reason`]).
///
/// [`harden_data::empty_bundle`]: crate::toride_harden_data::HardenDataBundle
fn empty_bundle() -> TemplatesDataBundle {
    TemplatesDataBundle {
        available: false,
        recipes: Vec::new(),
        ready_count: 0,
        total_count: 0,
        findings: Vec::new(),
        unavailable_reason: None,
    }
}

/// Empty bundle carrying the reason collection failed. Used when the spawned
/// collection task panicked (`JoinError`) — the reason string is rendered by the
/// UI's degraded panel so the operator sees what actually went wrong, mirroring
/// the `spawn_blocking` `JoinError` path in harden / fail2ban / cloud / etc.
fn empty_bundle_with_reason(reason: String) -> TemplatesDataBundle {
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
        let collector = TemplatesCollector::new();
        assert!(!collector.is_pending());
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(
            TemplatesCollector::new().is_pending(),
            TemplatesCollector::default().is_pending()
        );
    }

    #[tokio::test]
    async fn start_makes_pending() {
        let mut collector = TemplatesCollector::new();
        assert!(!collector.is_pending());
        collector.start();
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn start_is_idempotent() {
        let mut collector = TemplatesCollector::new();
        collector.start();
        assert!(collector.is_pending());
        collector.start(); // no-op, does not replace the receiver
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn poll_returns_none_when_not_started() {
        let mut collector = TemplatesCollector::new();
        assert!(collector.poll().await.is_none());
    }

    #[tokio::test]
    async fn poll_clears_pending() {
        let mut collector = TemplatesCollector::new();
        collector.start();
        // The sweep is a quick `which::which` over 13 binaries; give it time.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let _ = collector.poll().await;
        assert!(!collector.is_pending(), "poll should clear pending state");
    }

    #[tokio::test]
    async fn poll_returns_bundle_after_collection() {
        // On any host the collector must return Some(bundle) after start() +
        // enough time. The bundle's `available` flag is true (the catalogue is
        // constant data and the `which` sweep cannot fail at construction).
        let mut collector = TemplatesCollector::new();
        collector.start();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let bundle = collector.poll().await;
        assert!(bundle.is_some(), "poll should return Some after completion");
        let b = bundle.unwrap();
        assert!(b.available, "catalogue is always available after a sweep");
        assert_eq!(b.total_count, templates_convert::catalogue().len());
        assert_eq!(b.recipes.len(), b.total_count);
        assert!(b.ready_count <= b.total_count);
    }

    #[test]
    fn empty_bundle_is_unavailable() {
        let b = empty_bundle();
        assert!(!b.available);
        assert!(b.recipes.is_empty());
        assert!(b.findings.is_empty());
        assert_eq!(b.ready_count, 0);
        assert_eq!(b.total_count, 0);
        assert!(
            b.unavailable_reason.is_none(),
            "empty_bundle carries no reason; panics use empty_bundle_with_reason"
        );
    }

    #[test]
    fn empty_bundle_with_reason_carries_reason() {
        let b = empty_bundle_with_reason("templates data collection panicked: boom".into());
        assert!(!b.available);
        assert_eq!(
            b.unavailable_reason.as_deref(),
            Some("templates data collection panicked: boom")
        );
    }

    #[tokio::test]
    async fn findings_cache_is_populated_after_poll() {
        let mut collector = TemplatesCollector::new();
        collector.start();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let _ = collector.poll().await;
        // After a successful poll the cache is populated (even if to an empty
        // Vec on a host where every target tool is installed).
        assert!(collector.cached_findings.is_some());
        assert!(collector.findings_fresh_at.is_some());
    }

    #[test]
    fn invalidate_findings_cache_clears_it() {
        let mut collector = TemplatesCollector::new();
        collector.cached_findings = Some(Vec::new());
        collector.findings_fresh_at = Some(std::time::Instant::now());
        collector.invalidate_findings_cache();
        assert!(collector.cached_findings.is_none());
        assert!(collector.findings_fresh_at.is_none());
    }
}
