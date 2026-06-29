//! Async cloud provider data collection (LIVE READ-ONLY).
//!
//! [`CloudCollector`] manages background collection of all cloud-provider data
//! via a tokio oneshot channel, following the same pattern as
//! [`StatusCollector`](crate::status_collector::StatusCollector),
//! [`SshDataCollector`](crate::ssh_data::SshDataCollector), and (the closest
//! analogue) [`Fail2banCollector`](crate::fail2ban_data::Fail2banCollector).
//!
//! This is the TEMPLATE read-only integration. It mirrors `Fail2banCollector`
//! MINUS the entire write path — there are no operations, no optimistic
//! updates, no cooldown gate, and no loading spinner. Every call to the
//! backend is a pure read.
//!
//! Doctor findings are expensive (they shell out to `aws` / `gcloud` / `doctl`
//! / `hcloud`, consult `which::which`, …) and change slowly, so they are
//! cached for 60s — exactly like the fail2ban findings cache.
//!
//! ## macOS / detection
//!
//! [`toride_cloud::client::CloudClient::detect`] probes environment variables
//! (`AWS_REGION`, `GOOGLE_CLOUD_PROJECT`, `DIGITALOCEAN_TOKEN`, …) and
//! `/sys/class/dmi/id/*` files. On a macOS dev box none of those match, so the
//! provider resolves to [`toride_cloud::CloudProvider::Unknown`]. That is NOT
//! an error: `detect()` returns `Ok` with `provider == Unknown`, and the
//! section stays `available == true` so the operator sees the doctor's
//! `provider.unknown` Warning finding rather than a blank panel.
//!
//! ## Blocking
//!
//! The `DuctRunner` shells out synchronously and `which::which` is blocking.
//! ALL backend work — `CloudClient::detect`, `list_security_groups`,
//! `report`, `Doctor::run`, `ServiceManager` probes — runs inside a single
//! [`tokio::task::spawn_blocking`] block inside the spawned task, exactly like
//! `collect_real_fail2ban`.

use tokio::sync::oneshot;

use crate::toride_cloud_convert;
use crate::ui::screens::toride_cloud::{CloudFindingEntry, ProviderInfo, SecurityGroupEntry};

/// Aggregated cloud-provider data for the read-only section.
#[derive(Clone, Debug)]
pub struct CloudDataBundle {
    /// Whether the cloud backend was reachable at all. `false` is reserved for
    /// the panic case (a `spawn_blocking` `JoinError`) — a missing provider or
    /// CLI surfaces as doctor findings and keeps `available == true` so the
    /// operator SEES the findings rather than a blank panel.
    pub available: bool,
    /// Detected provider summary (provider label, CLI tool, metadata URL).
    pub provider: ProviderInfo,
    /// Whether the provider's agent service is running.
    pub agent_running: bool,
    /// Whether the provider's agent service is enabled at boot.
    pub agent_enabled: bool,
    /// Name of the provider's agent service (empty when unknown provider).
    pub agent_service_name: String,
    /// Security groups / firewalls (from `list_security_groups`).
    pub security_groups: Vec<SecurityGroupEntry>,
    /// Doctor findings (cached for 60s between collections).
    pub findings: Vec<CloudFindingEntry>,
    /// Human-readable reason the backend was unreachable, populated ONLY when
    /// `available == false` because a collection task panicked (`JoinError`).
    /// `None` otherwise — notably also `None` for a freshly-constructed empty
    /// bundle before any collection has run. Surfaced to the UI so the degraded
    /// panel can show what actually went wrong instead of guessing.
    pub unavailable_reason: Option<String>,
}

// ── Collector ───────────────────────────────────────────────────────────────

/// Manages periodic async collection of cloud-provider data.
///
/// Mirrors [`Fail2banCollector`](crate::fail2ban_data::Fail2banCollector): a
/// oneshot channel for the in-flight result, plus a 60s TTL cache for the
/// expensive doctor findings so they are not re-run on every 2s refresh tick.
pub struct CloudCollector {
    /// Carries the bundle AND whether the cached findings were reused for this
    /// poll. The freshness timestamp must only be advanced when the doctor was
    /// actually re-run (`used_cache == false`); otherwise every cache-hit poll
    /// would reset the TTL clock with the SAME (already-cached) findings and
    /// the cache would never expire for the lifetime of the app.
    rx: Option<oneshot::Receiver<(CloudDataBundle, bool)>>,
    /// Cached doctor findings from the last collection.
    cached_findings: Option<Vec<CloudFindingEntry>>,
    /// When the findings cache was last refreshed.
    findings_fresh_at: Option<std::time::Instant>,
}

/// How long to keep cached findings before re-running the doctor suite.
#[expect(
    clippy::duration_suboptimal_units,
    reason = "stable std lacks from_mins"
)]
const FINDINGS_TTL: std::time::Duration = std::time::Duration::from_secs(60);

impl CloudCollector {
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
            let (bundle, reused_cache) = collect_real_cloud(use_cache, cached_findings).await;
            let _ = tx.send((bundle, reused_cache));
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
    pub async fn poll(&mut self) -> Option<CloudDataBundle> {
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

impl Default for CloudCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Real data collection ────────────────────────────────────────────────────

/// Collect cloud-provider data by running the real backend.
///
/// ALL work — `CloudClient::detect` (env vars + DMI file reads),
/// `list_security_groups` (provider CLI shells out), `report`, `Doctor::run`,
/// `ServiceManager` probes — runs inside a single `spawn_blocking` block that
/// owns the constructed client, so no synchronous work ever stalls the tokio
/// worker. Doctor findings may be reused from the cache. On ANY panic
/// (`JoinError`) returns [`empty_bundle_with_reason`] with `available = false`.
///
/// `use_cache` / `cached_findings` mirror the fail2ban findings cache: when the
/// cache is fresh the doctor suite is skipped entirely.
///
/// Returns `(bundle, used_cache)` where `used_cache` records whether the
/// findings were actually taken from the cache on a successful collection.
/// The caller advances the TTL clock ONLY when `used_cache == false`, so a
/// cache-hit poll never resets the freshness timestamp with stale data.
async fn collect_real_cloud(
    use_cache: bool,
    cached_findings: Option<Vec<CloudFindingEntry>>,
) -> (CloudDataBundle, bool) {
    // Build the CloudClient on the blocking pool. detect() reads env vars and
    // DMI files; on macOS it resolves to Unknown but returns Ok (not an error),
    // so construction succeeds even with no cloud VM.
    let client = match tokio::task::spawn_blocking(toride_cloud::client::CloudClient::detect).await
    {
        Ok(Ok(client)) => client,
        Ok(Err(e)) => {
            // detect() only errors on a fundamental failure (today it always
            // returns Ok(Unknown), but the backend reserves the right to error).
            tracing::warn!("cloud detect failed: {e}");
            return (
                empty_bundle_with_reason(format!("cloud provider detection failed: {e}")),
                false,
            );
        }
        Err(e) => {
            tracing::warn!("cloud detect task panicked: {e}");
            return (
                empty_bundle_with_reason(format!("cloud provider detection panicked: {e}")),
                false,
            );
        }
    };

    // Run ALL blocking probes in a single spawn_blocking that owns `client`.
    // This keeps every shell-out / which::which call off the tokio worker and
    // sidesteps the 'static-borrow problem: the doctor, security-group listing,
    // and service probes all borrow `client.provider`, so collecting everything
    // in one owned closure is both simpler and cheaper than spawning one task
    // per probe. Results are returned as plain owned data so they cross the
    // thread boundary cleanly. Doctor findings are taken from the cache when
    // fresh (`use_cache`), otherwise re-run here.
    let provider_for_doctor = client.provider;
    let result = tokio::task::spawn_blocking(move || {
        // ── Doctor (unless cached) ─────────────────────────────────────────
        let findings: Vec<CloudFindingEntry> = if use_cache {
            cached_findings.unwrap_or_default()
        } else {
            let doctor = toride_cloud::doctor::Doctor::new(provider_for_doctor);
            match doctor.run(&toride_cloud::doctor::DoctorScope::All) {
                Ok(report) => toride_cloud_convert::convert_findings(report.findings),
                Err(e) => {
                    tracing::warn!("cloud doctor: {e}");
                    Vec::new()
                }
            }
        };

        // ── Security groups / firewalls ───────────────────────────────────
        let security_groups = match client.list_security_groups() {
            Ok(groups) => toride_cloud_convert::convert_security_groups(groups),
            Err(e) => {
                tracing::debug!("cloud list_security_groups: {e}");
                Vec::new()
            }
        };

        // ── Agent service status ──────────────────────────────────────────
        let svc = toride_cloud::service::ServiceManager::new(provider_for_doctor);
        let agent_running = svc.is_agent_running().unwrap_or(false);
        let agent_enabled = svc.is_agent_enabled().unwrap_or(false);
        let agent_service_name = svc.agent_service_name().to_string();

        // ── Provider summary ──────────────────────────────────────────────
        let provider = toride_cloud_convert::convert_provider(provider_for_doctor);

        // ── Availability heuristic ────────────────────────────────────────
        // The section is "available" whenever collection did not panic. A host
        // with no cloud VM resolves to provider == Unknown and produces a
        // `provider.unknown` Warning finding — that STILL counts as available
        // so the operator SEES the finding rather than a blank panel. (A
        // missing CLI similarly surfaces as a Warning finding.) Only a panic
        // (handled by the JoinError branch below) flips available to false.
        let available = true;

        CloudDataBundle {
            available,
            provider,
            agent_running,
            agent_enabled,
            agent_service_name,
            security_groups,
            findings,
            // Success path: no panic, so no reason.
            unavailable_reason: None,
        }
    })
    .await;

    match result {
        Ok(bundle) => (bundle, use_cache),
        Err(e) => {
            tracing::warn!("cloud collection task panicked: {e}");
            (
                empty_bundle_with_reason(format!("cloud data collection panicked: {e}")),
                false,
            )
        }
    }
}

/// Empty bundle used when cloud data could not be collected at all.
///
/// `available = false` signals the UI to render the degraded panel. No reason
/// is attached because none is known at this point; collection-time panics use
/// [`empty_bundle_with_reason`] to surface the `JoinError`.
fn empty_bundle() -> CloudDataBundle {
    CloudDataBundle {
        available: false,
        provider: toride_cloud_convert::convert_provider(toride_cloud::CloudProvider::Unknown),
        agent_running: false,
        agent_enabled: false,
        agent_service_name: String::new(),
        security_groups: Vec::new(),
        findings: Vec::new(),
        unavailable_reason: None,
    }
}

/// Empty bundle carrying the reason collection failed. Used when a
/// `spawn_blocking` task panicked (`JoinError`) — the reason string is rendered
/// by the UI's degraded panel so the operator sees what actually went wrong.
fn empty_bundle_with_reason(reason: String) -> CloudDataBundle {
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
        let collector = CloudCollector::new();
        assert!(!collector.is_pending());
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(
            CloudCollector::new().is_pending(),
            CloudCollector::default().is_pending()
        );
    }

    #[tokio::test]
    async fn start_makes_pending() {
        let mut collector = CloudCollector::new();
        assert!(!collector.is_pending());
        collector.start();
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn start_is_idempotent() {
        let mut collector = CloudCollector::new();
        collector.start();
        assert!(collector.is_pending());
        collector.start(); // no-op, does not replace the receiver
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn poll_returns_none_when_not_started() {
        let mut collector = CloudCollector::new();
        assert!(collector.poll().await.is_none());
    }

    #[tokio::test]
    async fn poll_clears_pending() {
        let mut collector = CloudCollector::new();
        collector.start();
        // Let the spawned task complete (it shells out, so give it time).
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let _ = collector.poll().await;
        assert!(!collector.is_pending(), "poll should clear pending state");
    }

    #[tokio::test]
    async fn poll_returns_bundle_after_collection() {
        // On any host (including macOS with no cloud VM) the collector must
        // return Some(bundle) after start() + enough time. The bundle's
        // `available` flag reflects whether cloud data was found; on a dev box
        // it stays true (provider Unknown + a provider.unknown Warning finding).
        let mut collector = CloudCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let bundle = collector.poll().await;
        assert!(bundle.is_some(), "poll should return Some after completion");
    }

    #[test]
    fn empty_bundle_is_unavailable() {
        let b = empty_bundle();
        assert!(!b.available);
        assert!(b.security_groups.is_empty());
        assert!(b.findings.is_empty());
        assert_eq!(b.provider.provider, "none");
        assert!(b.provider.cli_tool.is_none());
        assert!(
            b.unavailable_reason.is_none(),
            "empty_bundle carries no reason; panics use empty_bundle_with_reason"
        );
    }

    #[tokio::test]
    async fn findings_cache_is_populated_after_poll() {
        let mut collector = CloudCollector::new();
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
        let mut collector = CloudCollector::new();
        collector.cached_findings = Some(Vec::new());
        collector.findings_fresh_at = Some(std::time::Instant::now());
        collector.invalidate_findings_cache();
        assert!(collector.cached_findings.is_none());
        assert!(collector.findings_fresh_at.is_none());
    }
}
