//! Async fail2ban data collection (read-only) via a tokio oneshot channel.
//!
//! The whole bundle is cached for 60s: new bans/jails and service
//! transitions surface up to that TTL late.

use tokio::sync::oneshot;

use crate::fail2ban_convert;
use crate::ui::screens::fail2ban::{BanEntry, FindingEntry, JailEntry};

/// Aggregated fail2ban data for the read-only section.
#[derive(Clone, Debug)]
pub struct Fail2banDataBundle {
    /// Whether the fail2ban backend was reachable at all (`false` renders
    /// the degraded "unavailable" panel).
    pub available: bool,
    /// Whether the systemd service is active (running).
    pub service_active: bool,
    /// Whether the service is enabled at boot.
    pub service_enabled: bool,
    /// Detected fail2ban version, if any.
    pub version: Option<String>,
    /// Active jails parsed from `fail2ban-client status`.
    pub jails: Vec<JailEntry>,
    /// Currently banned IPs parsed from `fail2ban-client banned`.
    pub bans: Vec<BanEntry>,
    /// Doctor findings (cached for 60s between collections).
    pub findings: Vec<FindingEntry>,
    /// Whether the `nft` binary is available (`None` if the probe failed).
    pub fw_nft_available: Option<bool>,
    /// Whether the `iptables` binary is available (`None` if the probe failed).
    pub fw_iptables_available: Option<bool>,
    /// Reason collection failed; populated only when `available == false`
    /// because the collection task panicked (`JoinError`).
    pub unavailable_reason: Option<String>,
}

/// Manages periodic async collection of fail2ban data.
///
/// A 60s TTL cache covers the whole bundle (doctor + probes).
pub struct Fail2banCollector {
    rx: Option<oneshot::Receiver<(Fail2banDataBundle, bool)>>,
    cached_bundle: Option<Fail2banDataBundle>,
    bundle_fresh_at: Option<std::time::Instant>,
}

const BUNDLE_TTL: std::time::Duration = std::time::Duration::from_mins(1);

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

impl Fail2banCollector {
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
    /// is served verbatim without running any probe.
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
            let (bundle, reused_cache) = collect_real_fail2ban(use_cache, cached_bundle).await;
            let _ = tx.send((bundle, reused_cache));
        });
    }

    /// Poll for a completed collection result.
    ///
    /// Returns `Some(bundle)` on completion, `None` while pending or failed.
    /// A degraded (panic) bundle is never cached.
    pub async fn poll(&mut self) -> Option<Fail2banDataBundle> {
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

impl Default for Fail2banCollector {
    fn default() -> Self {
        Self::new()
    }
}

async fn collect_real_fail2ban(
    use_cache: bool,
    cached_bundle: Option<Fail2banDataBundle>,
) -> (Fail2banDataBundle, bool) {
    if use_cache && let Some(bundle) = cached_bundle {
        return (bundle, true);
    }

    let f2b = match tokio::task::spawn_blocking(|| {
        toride_fail2ban::Fail2Ban::with_runner(
            Box::new(toride_fail2ban::command::DuctRunner::new()),
        )
    })
    .await
    {
        Ok(f2b) => f2b,
        Err(e) => {
            tracing::warn!("fail2ban construction task panicked: {e}");
            return (
                empty_bundle_with_reason(format!("fail2ban backend construction panicked: {e}")),
                false,
            );
        }
    };

    let result = tokio::task::spawn_blocking(move || {
        let findings: Vec<FindingEntry> =
            match f2b.doctor(toride_fail2ban::doctor::DoctorScope::All) {
                Ok(report) => fail2ban_convert::convert_findings(report.findings),
                Err(e) => {
                    tracing::warn!("fail2ban doctor: {e}");
                    Vec::new()
                }
            };

        let svc = f2b.service();
        let service_active = svc.is_active().unwrap_or(false);
        let service_enabled = svc.is_enabled().unwrap_or(false);

        let (jails, version, bans) = match f2b.client() {
            Ok(client) => {
                let version = client.version().ok();
                let jails = match client.status() {
                    Ok(status) => {
                        let mut parsed = fail2ban_convert::parse_jails_from_status(&status);
                        for jail in &mut parsed {
                            if let Ok(per_jail) = client.status_jail(&jail.name) {
                                let enriched = fail2ban_convert::enrich_jail_from_status(
                                    jail.clone(),
                                    &per_jail,
                                );
                                *jail = enriched;
                            }
                        }
                        parsed
                    }
                    Err(e) => {
                        tracing::debug!("fail2ban client status: {e}");
                        Vec::new()
                    }
                };
                let bans = match client.banned() {
                    Ok(raw) => fail2ban_convert::parse_bans(&raw),
                    Err(e) => {
                        tracing::debug!("fail2ban client banned: {e}");
                        Vec::new()
                    }
                };
                (jails, version, bans)
            }
            Err(e) => {
                tracing::debug!("fail2ban client init: {e}");
                (Vec::new(), None, Vec::new())
            }
        };

        let fw = f2b.firewall();
        let fw_nft_available = fw.check_nft_available().ok();
        let fw_iptables_available = fw.check_iptables_available().ok();

        let available =
            !jails.is_empty() || version.is_some() || !findings.is_empty() || service_active;

        Fail2banDataBundle {
            available,
            service_active,
            service_enabled,
            version,
            jails,
            bans,
            findings,
            fw_nft_available,
            fw_iptables_available,
            unavailable_reason: None,
        }
    })
    .await;

    match result {
        Ok(bundle) => (bundle, false),
        Err(e) => {
            tracing::warn!("fail2ban collection task panicked: {e}");
            (
                empty_bundle_with_reason(format!("fail2ban data collection panicked: {e}")),
                false,
            )
        }
    }
}

fn empty_bundle() -> Fail2banDataBundle {
    Fail2banDataBundle {
        available: false,
        service_active: false,
        service_enabled: false,
        version: None,
        jails: Vec::new(),
        bans: Vec::new(),
        findings: Vec::new(),
        fw_nft_available: None,
        fw_iptables_available: None,
        unavailable_reason: None,
    }
}

fn empty_bundle_with_reason(reason: String) -> Fail2banDataBundle {
    let mut b = empty_bundle();
    b.unavailable_reason = Some(reason);
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_not_pending() {
        let collector = Fail2banCollector::new();
        assert!(!collector.is_pending());
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(
            Fail2banCollector::new().is_pending(),
            Fail2banCollector::default().is_pending()
        );
    }

    #[tokio::test]
    async fn start_makes_pending() {
        let mut collector = Fail2banCollector::new();
        assert!(!collector.is_pending());
        collector.start();
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn start_is_idempotent() {
        let mut collector = Fail2banCollector::new();
        collector.start();
        assert!(collector.is_pending());
        collector.start();
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn poll_returns_none_when_not_started() {
        let mut collector = Fail2banCollector::new();
        assert!(collector.poll().await.is_none());
    }

    #[tokio::test]
    async fn poll_clears_pending() {
        let mut collector = Fail2banCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let _ = collector.poll().await;
        assert!(!collector.is_pending(), "poll should clear pending state");
    }

    #[tokio::test]
    async fn poll_returns_bundle_after_collection() {
        let mut collector = Fail2banCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let bundle = collector.poll().await;
        assert!(bundle.is_some(), "poll should return Some after completion");
    }

    #[test]
    fn empty_bundle_is_unavailable() {
        let b = empty_bundle();
        assert!(!b.available);
        assert!(b.jails.is_empty());
        assert!(b.bans.is_empty());
        assert!(b.findings.is_empty());
        assert!(b.version.is_none());
        assert!(b.fw_nft_available.is_none());
        assert!(b.fw_iptables_available.is_none());
        assert!(
            b.unavailable_reason.is_none(),
            "empty_bundle carries no reason; panics use empty_bundle_with_reason"
        );
    }

    #[tokio::test]
    async fn findings_cache_is_populated_after_poll() {
        let mut collector = Fail2banCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let bundle = collector.poll().await;
        if bundle.is_some_and(|b| b.available) {
            assert!(collector.cached_bundle.is_some());
            assert!(collector.bundle_fresh_at.is_some());
        } else {
            assert!(
                collector.cached_bundle.is_none(),
                "an unavailable bundle must not be cached"
            );
        }
    }

    #[test]
    fn invalidate_findings_cache_clears_it() {
        let mut collector = Fail2banCollector::new();
        collector.cached_bundle = Some(empty_bundle());
        collector.bundle_fresh_at = Some(std::time::Instant::now());
        collector.invalidate_findings_cache();
        assert!(collector.cached_bundle.is_none());
        assert!(collector.bundle_fresh_at.is_none());
    }
}

#[cfg(test)]
mod cadence_oracle {
    use super::*;

    const SENTINEL_ID: &str = "oracle-sentinel.fail2ban.findings-cache";

    const SENTINEL_JAIL: &str = "oracle-sentinel-jail";

    const SENTINEL_VERSION: &str = "oracle-sentinel 0.0.0";

    fn sentinel_bundle() -> Fail2banDataBundle {
        Fail2banDataBundle {
            available: true,
            service_active: true,
            service_enabled: true,
            version: Some(SENTINEL_VERSION.to_string()),
            jails: vec![JailEntry {
                name: SENTINEL_JAIL.to_string(),
                ..jail_entry_default()
            }],
            bans: Vec::new(),
            findings: vec![FindingEntry {
                id: SENTINEL_ID.to_string(),
                severity: "ok".to_string(),
                title: "cadence-oracle sentinel".to_string(),
                detail: String::new(),
                fix: None,
            }],
            fw_nft_available: Some(true),
            fw_iptables_available: Some(false),
            unavailable_reason: None,
        }
    }

    fn jail_entry_default() -> JailEntry {
        JailEntry {
            name: String::new(),
            is_running: false,
            banned_count: 0,
            total_bans: 0,
            file_count: 0,
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
        let mut collector = Fail2banCollector::new();
        collector.cached_bundle = Some(sentinel_bundle());
        let primed = std::time::Instant::now();
        collector.bundle_fresh_at = Some(primed);

        collector.start();
        let bundle = collector.poll().await.expect("collection completes");

        assert_eq!(bundle.findings.len(), 1);
        assert_eq!(
            bundle.findings[0].id, SENTINEL_ID,
            "the sentinel id can only come from the cache, never from a real doctor run"
        );
        assert_eq!(
            bundle.version.as_deref(),
            Some(SENTINEL_VERSION),
            "the sentinel version can only come from the cache"
        );
        assert_eq!(bundle.jails.len(), 1);
        assert_eq!(
            bundle.jails[0].name, SENTINEL_JAIL,
            "the sentinel jail can only come from the cache, never from a real status probe"
        );
        assert!(
            bundle.service_active,
            "sentinel service flag served verbatim"
        );
        assert_eq!(bundle.fw_nft_available, Some(true));
        assert_eq!(
            collector.bundle_fresh_at,
            Some(primed),
            "a cache-hit poll must not advance (re-arm) the freshness timestamp"
        );
    }

    #[tokio::test]
    async fn ttl_expiry_bypasses_cache_and_rederives() {
        let mut collector = Fail2banCollector::new();
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
            bundle.version.as_deref(),
            Some(SENTINEL_VERSION),
            "an expired cache must not serve the sentinel version"
        );
        assert!(
            bundle.jails.iter().all(|j| j.name != SENTINEL_JAIL),
            "an expired cache must not serve the sentinel jail"
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
                "an unavailable re-derivation must leave the primed clock untouched"
            );
        }
    }
}
