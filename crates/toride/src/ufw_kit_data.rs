//! Async UFW firewall data collection (LIVE READ-ONLY).
//!
//! [`FirewallCollector`] manages background collection of all UFW subsystem
//! data via a tokio oneshot channel, following the same pattern as
//! [`Fail2banCollector`](crate::fail2ban_data::Fail2banCollector) (which itself
//! mirrors [`SshDataCollector`](crate::ssh_data::SshDataCollector) MINUS the
//! write path).
//!
//! This is a read-only integration: there are no write operations, no
//! optimistic updates, no cooldown gate, and no loading spinner. Every call to
//! the backend is a pure read.
//!
//! Doctor findings are expensive (they shell out to `ufw`, `iptables`,
//! `ip6tables`, …) and change slowly, so they are cached for 60s — exactly
//! like the fail2ban / SSH diagnostics cache.
//!
//! ## macOS / construction
//!
//! [`ufw_kit::Ufw::system`] is used. Unlike fail2ban's `with_runner`, the
//! `Ufw` constructor does not consult a config directory — it merely wraps a
//! `DuctRunner`. On macOS where the `ufw` binary is absent, construction still
//! succeeds; the first probe (`find_ufw` / `status` / doctor's binary check)
//! then errors, the doctor surfaces the missing binary as a `Critical` finding,
//! and the section stays `available == true` so the operator SEES the finding
//! rather than a blank panel. `available == false` is reserved for the case
//! where the construction task itself panicked.
//!
//! Caveat: the finding-surfacing guarantee above holds when `doctor()` itself
//! returns `Ok` — `check_binaries` unconditionally pushes a `bin:ufw:missing`
//! `Critical` finding even when `find_ufw()` fails, so a missing binary keeps
//! `available == true`. If `doctor()` returns `Err` (an exceptional whole-call
//! failure, not the per-check misses it wraps), the warn branch in
//! `collect_real_ufw` yields `findings = Vec::new()`, which combined with no
//! rules/version/active would flip `available` to `false` and surface the
//! generic degraded panel instead of the binary-missing finding. That path is
//! safe (no crash) but does not surface actionable detail, so the guarantee is
//! not categorical.
//!
//! ## Blocking
//!
//! The `DuctRunner` shells out synchronously. All backend work is wrapped in
//! [`tokio::task::spawn_blocking`] so the tokio worker is never stalled.

use tokio::sync::oneshot;

use crate::ufw_kit_convert;
use crate::ui::screens::ufw_kit::{FindingEntry, RuleEntry};

/// Aggregated UFW firewall data for the read-only section.
#[derive(Clone, Debug)]
pub struct FirewallDataBundle {
    /// Whether the UFW backend was reachable at all. `false` when construction
    /// failed entirely or the collection task panicked — the UI renders a
    /// degraded "unavailable" panel.
    pub available: bool,
    /// Whether UFW is active (running).
    pub active: bool,
    /// Default incoming policy label (e.g. `"deny"`), if parsed.
    pub default_incoming: Option<String>,
    /// Default outgoing policy label (e.g. `"allow"`), if parsed.
    pub default_outgoing: Option<String>,
    /// Default routed policy label (e.g. `"deny"` / `"reject"`), if parsed.
    /// `None` when routed is off — UFW's verbose output prints "disabled" for
    /// that case but the parser maps it to `None`, so the UI surfaces
    /// "(unset)" rather than a string.
    pub default_routed: Option<String>,
    /// Current logging level label (e.g. `"low"`), if parsed.
    pub logging_level: Option<String>,
    /// Detected UFW version, if any.
    pub version: Option<String>,
    /// Parsed rules.
    pub rules: Vec<RuleEntry>,
    /// Doctor findings (cached for 60s between collections).
    pub findings: Vec<FindingEntry>,
    /// Human-readable reason the backend was unreachable, populated ONLY when
    /// `available == false` because a collection task panicked (`JoinError`).
    /// `None` otherwise — notably also `None` for a freshly-constructed empty
    /// bundle before any collection has run. Surfaced to the UI so the degraded
    /// panel can show what actually went wrong instead of guessing.
    pub unavailable_reason: Option<String>,
}

// ── Collector ───────────────────────────────────────────────────────────────

/// Manages periodic async collection of UFW firewall data.
///
/// Mirrors [`Fail2banCollector`](crate::fail2ban_data::Fail2banCollector): a
/// oneshot channel for the in-flight result, plus a 60s TTL cache for the
/// expensive doctor findings so they are not re-run on every 2s refresh tick.
pub struct FirewallCollector {
    /// Carries the bundle AND whether the cached findings were reused for this
    /// poll. The freshness timestamp must only be advanced when the doctor was
    /// actually re-run (`used_cache == false`); otherwise every cache-hit poll
    /// would reset the TTL clock with the SAME (already-cached) findings and
    /// the cache would never expire for the lifetime of the app.
    rx: Option<oneshot::Receiver<(FirewallDataBundle, bool)>>,
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

impl FirewallCollector {
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
            let (bundle, used_cache) = collect_real_ufw(use_cache, cached_findings).await;
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
    pub async fn poll(&mut self) -> Option<FirewallDataBundle> {
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

impl Default for FirewallCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Real data collection ────────────────────────────────────────────────────

/// Collect UFW data by shelling out to the real binaries.
///
/// All work runs on the blocking thread pool (the `DuctRunner` shells out
/// synchronously). Doctor findings may be reused from the cache. On ANY error
/// — construction failure, doctor error, every probe failing — returns
/// [`empty_bundle`] with `available = false`.
///
/// `use_cache` / `cached_findings` mirror the fail2ban / SSH diagnostics cache:
/// when the cache is fresh the doctor suite is skipped entirely.
///
/// Returns `(bundle, used_cache)` where `used_cache` records whether the
/// findings were actually taken from the cache on a successful collection.
/// The caller advances the TTL clock ONLY when `used_cache == false`, so a
/// cache-hit poll never resets the freshness timestamp with stale data.
async fn collect_real_ufw(
    use_cache: bool,
    cached_findings: Option<Vec<FindingEntry>>,
) -> (FirewallDataBundle, bool) {
    // Build the Ufw facade on the blocking pool. system() merely wraps a
    // DuctRunner — it does not consult a config directory — so construction
    // succeeds even on macOS where the `ufw` binary is absent.
    let ufw = match tokio::task::spawn_blocking(ufw_kit::Ufw::system).await {
        Ok(ufw) => ufw,
        Err(e) => {
            tracing::warn!("ufw construction task panicked: {e}");
            return (
                empty_bundle_with_reason(format!("ufw backend construction panicked: {e}")),
                false,
            );
        }
    };

    // Run ALL blocking probes in a single spawn_blocking that owns `ufw`.
    // This keeps every shell-out off the tokio worker (the `DuctRunner` is
    // synchronous) and sidesteps the 'static-borrow problem. Results are
    // returned as plain owned data so they cross the thread boundary cleanly.
    // Doctor findings are taken from the cache when fresh (`use_cache`),
    // otherwise re-run here.
    let result = tokio::task::spawn_blocking(move || {
        // ── Doctor (unless cached) ─────────────────────────────────────────
        let findings: Vec<FindingEntry> = if use_cache {
            cached_findings.unwrap_or_default()
        } else {
            match ufw_kit::doctor::doctor(&ufw, ufw_kit::spec::DoctorScope::All) {
                Ok(raw_findings) => ufw_kit_convert::convert_findings(raw_findings),
                Err(e) => {
                    tracing::warn!("ufw doctor: {e}");
                    Vec::new()
                }
            }
        };

        // ── Verbose status (default policies + logging) ───────────────────
        // Verbose status is preferred over plain status because it carries
        // the default policies. On failure we fall back to plain status.
        let (active, default_incoming, default_outgoing, default_routed, logging_level, rules) =
            match ufw.status_verbose() {
                Ok(s) => {
                    let rules = ufw_kit_convert::convert_rules(s.rules.clone());
                    (
                        s.active,
                        s.default_incoming.map(ufw_kit_convert::policy_to_string),
                        s.default_outgoing.map(ufw_kit_convert::policy_to_string),
                        // `default_routed` is `Option<Policy>`; the verbose
                        // output prints "disabled" when routed is off, but the
                        // parser maps that to None. Surface the parsed policy
                        // when present.
                        s.default_routed.map(ufw_kit_convert::policy_to_string),
                        s.logging_level.map(ufw_kit_convert::logging_to_string),
                        rules,
                    )
                }
                Err(e) => {
                    tracing::debug!("ufw status verbose: {e}");
                    // Fall back to plain status (rules only, no defaults).
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

        // ── Version ───────────────────────────────────────────────────────
        let version = match ufw.version() {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::debug!("ufw version: {e}");
                None
            }
        };

        // ── Availability heuristic ────────────────────────────────────────
        // The section is "available" if the status query returned (any rules
        // OR an explicit active/inactive answer), a version is known, OR the
        // doctor produced any findings. A host with `ufw` missing yields a
        // Critical finding (bin:ufw:missing) but no status/version — that
        // still counts as available so the operator SEES the finding rather
        // than a blank panel. Note this guarantee holds when `doctor()` itself
        // returned `Ok`; a whole-call `doctor` error (the warn branch above)
        // yields `findings = Vec::new()`, which would flip `available` to
        // `false` and surface the degraded panel instead of the missing-binary
        // finding. That path is safe but does not surface actionable detail.
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
            // Success path: no panic, so no reason. (A missing binary surfaces
            // as a Critical finding, keeping `available == true`, as long as
            // `doctor()` itself returned `Ok` — see the heuristic comment above.)
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

/// Empty bundle used when UFW could not be constructed at all.
///
/// `available = false` signals the UI to render the degraded panel. No reason
/// is attached because none is known at this point; collection-time panics use
/// [`empty_bundle_with_reason`] to surface the `JoinError`.
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

/// Empty bundle carrying the reason collection failed. Used when a
/// `spawn_blocking` task panicked (`JoinError`) — the reason string is rendered
/// by the UI's degraded panel so the operator sees what actually went wrong.
fn empty_bundle_with_reason(reason: String) -> FirewallDataBundle {
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
        collector.start(); // no-op, does not replace the receiver
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
        // Let the spawned task complete (it shells out, so give it time).
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let _ = collector.poll().await;
        assert!(!collector.is_pending(), "poll should clear pending state");
    }

    #[tokio::test]
    async fn poll_returns_bundle_after_collection() {
        // On any host (including macOS without ufw) the collector must
        // return Some(bundle) after start() + enough time. The bundle's
        // `available` flag reflects whether ufw was found.
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
        // After a successful poll the cache is populated (even if to an empty
        // Vec on a host where the doctor produced no findings).
        assert!(collector.cached_findings.is_some());
        assert!(collector.findings_fresh_at.is_some());
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
