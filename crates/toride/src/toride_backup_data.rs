//! Async backup data collection (read-only) via a tokio oneshot channel.
//!
//! The whole bundle (doctor findings + schedule/timer probes) is cached
//! for 60s: a newly installed/removed backup timer surfaces up to 60s late.

use tokio::sync::oneshot;

use crate::toride_backup_convert;
use crate::ui::screens::toride_backup::FindingEntry;

/// Aggregated backup data for the read-only section.
#[derive(Clone, Debug)]
pub struct BackupDataBundle {
    /// Whether the backup backend was reachable; `false` only on a
    /// collection panic (missing restic/borg still yields `true`).
    pub available: bool,
    /// Whether dry-run mode is active on the constructed client.
    pub dry_run: bool,
    /// Resolved config directory (`XDG_CONFIG_HOME/toride/backup`), if known.
    pub config_dir: Option<String>,
    /// Resolved data directory (`XDG_DATA_HOME/toride/backup`), if known.
    pub data_dir: Option<String>,
    /// Resolved schedule directory, if known.
    pub schedule_dir: Option<String>,
    /// restic availability inferred from doctor findings; `None` when the
    /// Binary scope was not run.
    pub restic_available: Option<bool>,
    /// borg binary availability inferred from doctor findings. `None` when the
    /// Binary scope was not run.
    pub borg_available: Option<bool>,
    /// Whether a schedule is installed for the default `toride-backup` job
    /// (real probe via `ScheduleManager::timer_status`).
    pub schedule_installed: Option<bool>,
    /// Whether the systemd timer for the default `toride-backup` job is active
    /// (real probe via `ScheduleManager::timer_status`).
    pub timer_active: Option<bool>,
    /// Note explaining a negative schedule reading (e.g. `"systemd not
    /// detected"`); `None` when empty or unavailable.
    pub schedule_note: Option<String>,
    /// Doctor findings (cached for 60s between collections).
    pub findings: Vec<FindingEntry>,
    /// Human-readable reason the backend was unreachable, populated ONLY when
    /// `available == false` because a collection task panicked (`JoinError`).
    pub unavailable_reason: Option<String>,
}

/// Manages periodic async collection of backup data.
///
/// A 60s TTL cache covers the whole bundle (doctor + schedule/timer probes).
pub struct BackupCollector {
    rx: Option<oneshot::Receiver<(BackupDataBundle, bool)>>,
    cached_bundle: Option<BackupDataBundle>,
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

const DEFAULT_JOB_NAME: &str = "toride-backup";

impl BackupCollector {
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
            let (bundle, reused_cache) = collect_real_backup(use_cache, cached_bundle).await;
            let _ = tx.send((bundle, reused_cache));
        });
    }

    /// Poll for a completed collection result.
    ///
    /// Returns `Some(bundle)` on completion, `None` while pending or failed.
    /// A degraded (panic) bundle never populates the cache.
    pub async fn poll(&mut self) -> Option<BackupDataBundle> {
        match &mut self.rx {
            Some(rx) => {
                let result = rx.await.ok();
                if let Some((ref bundle, used_cache)) = result {
                    if bundle.available {
                        if !used_cache {
                            self.cached_bundle = Some(bundle.clone());
                            self.bundle_fresh_at = Some(std::time::Instant::now());
                        }
                    } else {
                        self.invalidate_findings_cache();
                    }
                }
                self.rx = None;
                result.map(|(bundle, _)| bundle)
            }
            None => None,
        }
    }

    /// Invalidate the bundle cache so the next collection re-runs the probes.
    pub fn invalidate_findings_cache(&mut self) {
        self.cached_bundle = None;
        self.bundle_fresh_at = None;
    }
}

impl Default for BackupCollector {
    fn default() -> Self {
        Self::new()
    }
}

async fn collect_real_backup(
    use_cache: bool,
    cached_bundle: Option<BackupDataBundle>,
) -> (BackupDataBundle, bool) {
    if use_cache && let Some(bundle) = cached_bundle {
        return (bundle, true);
    }

    let client =
        match tokio::task::spawn_blocking(toride_backup::client::BackupClient::system).await {
            Ok(Ok(client)) => client,
            Ok(Err(e)) => {
                tracing::warn!("backup backend construction failed: {e}");
                return (
                    empty_bundle_with_reason(format!("backup backend construction failed: {e}")),
                    false,
                );
            }
            Err(e) => {
                tracing::warn!("backup construction task panicked: {e}");
                return (
                    empty_bundle_with_reason(format!("backup backend construction panicked: {e}")),
                    false,
                );
            }
        };

    let result = tokio::task::spawn_blocking(move || {
        let findings: Vec<FindingEntry> =
            match client.doctor(&toride_backup::doctor::DoctorScope::All) {
                Ok(report) => toride_backup_convert::convert_findings(report.findings),
                Err(e) => {
                    tracing::warn!("backup doctor: {e}");
                    Vec::new()
                }
            };

        let restic_available = toride_backup_convert::derive_binary_availability(
            &findings,
            toride_backup_convert::BackupBinary::Restic,
        );
        let borg_available = toride_backup_convert::derive_binary_availability(
            &findings,
            toride_backup_convert::BackupBinary::Borg,
        );

        let dry_run = client.is_dry_run();

        let paths = client.paths();
        let config_dir = paths
            .config_dir
            .to_str()
            .map(std::string::ToString::to_string);
        let data_dir = paths
            .data_dir
            .to_str()
            .map(std::string::ToString::to_string);
        let schedule_dir = paths
            .schedule_dir
            .to_str()
            .map(std::string::ToString::to_string);

        let snapshot =
            toride_backup::schedule::ScheduleManager::new().timer_status(DEFAULT_JOB_NAME);
        let schedule_installed = Some(snapshot.installed);
        let timer_active = Some(snapshot.timer_active);
        let schedule_note = {
            let note = snapshot.note;
            if note.is_empty() { None } else { Some(note) }
        };

        let available = true;

        BackupDataBundle {
            available,
            dry_run,
            config_dir,
            data_dir,
            schedule_dir,
            restic_available,
            borg_available,
            schedule_installed,
            timer_active,
            schedule_note,
            findings,
            unavailable_reason: None,
        }
    })
    .await;

    match result {
        Ok(bundle) => (bundle, false),
        Err(e) => {
            tracing::warn!("backup collection task panicked: {e}");
            (
                empty_bundle_with_reason(format!("backup data collection panicked: {e}")),
                false,
            )
        }
    }
}

fn empty_bundle() -> BackupDataBundle {
    BackupDataBundle {
        available: false,
        dry_run: false,
        config_dir: None,
        data_dir: None,
        schedule_dir: None,
        restic_available: None,
        borg_available: None,
        schedule_installed: None,
        timer_active: None,
        schedule_note: None,
        findings: Vec::new(),
        unavailable_reason: None,
    }
}

fn empty_bundle_with_reason(reason: String) -> BackupDataBundle {
    let mut b = empty_bundle();
    b.unavailable_reason = Some(reason);
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_not_pending() {
        let collector = BackupCollector::new();
        assert!(!collector.is_pending());
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(
            BackupCollector::new().is_pending(),
            BackupCollector::default().is_pending()
        );
    }

    #[tokio::test]
    async fn start_makes_pending() {
        let mut collector = BackupCollector::new();
        assert!(!collector.is_pending());
        collector.start();
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn start_is_idempotent() {
        let mut collector = BackupCollector::new();
        collector.start();
        assert!(collector.is_pending());
        collector.start();
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn poll_returns_none_when_not_started() {
        let mut collector = BackupCollector::new();
        assert!(collector.poll().await.is_none());
    }

    #[tokio::test]
    async fn poll_clears_pending() {
        let mut collector = BackupCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let _ = collector.poll().await;
        assert!(!collector.is_pending(), "poll should clear pending state");
    }

    #[tokio::test]
    async fn poll_returns_bundle_after_collection() {
        let mut collector = BackupCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let bundle = collector.poll().await;
        assert!(bundle.is_some(), "poll should return Some after completion");
    }

    #[test]
    fn empty_bundle_is_unavailable() {
        let b = empty_bundle();
        assert!(!b.available);
        assert!(b.findings.is_empty());
        assert!(b.restic_available.is_none());
        assert!(b.borg_available.is_none());
        assert!(b.config_dir.is_none());
        assert!(b.schedule_installed.is_none());
        assert!(b.timer_active.is_none());
        assert!(
            b.unavailable_reason.is_none(),
            "empty_bundle carries no reason; panics use empty_bundle_with_reason"
        );
    }

    #[test]
    fn empty_bundle_with_reason_sets_reason() {
        let b = empty_bundle_with_reason("boom".into());
        assert!(!b.available);
        assert_eq!(b.unavailable_reason.as_deref(), Some("boom"));
    }

    #[tokio::test]
    async fn findings_cache_is_populated_after_poll() {
        let mut collector = BackupCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let _ = collector.poll().await;
        assert!(collector.cached_bundle.is_some());
        assert!(collector.bundle_fresh_at.is_some());
    }

    #[test]
    fn invalidate_findings_cache_clears_it() {
        let mut collector = BackupCollector::new();
        collector.cached_bundle = Some(empty_bundle());
        collector.bundle_fresh_at = Some(std::time::Instant::now());
        collector.invalidate_findings_cache();
        assert!(collector.cached_bundle.is_none());
        assert!(collector.bundle_fresh_at.is_none());
    }

    #[tokio::test]
    async fn poll_does_not_poison_cache_on_unavailable_bundle() {
        let mut collector = BackupCollector::new();
        collector.cached_bundle = Some(available_bundle_with_finding());
        collector.bundle_fresh_at = Some(std::time::Instant::now());

        let (tx, rx) = oneshot::channel();
        tx.send((empty_bundle_with_reason("panic".into()), false))
            .unwrap();
        collector.rx = Some(rx);
        let bundle = collector.poll().await;
        assert!(bundle.is_some(), "poll still returns the panicked bundle");
        assert!(
            bundle.unwrap().unavailable_reason.is_some(),
            "bundle carries the panic reason"
        );
        assert!(
            collector.cached_bundle.is_none(),
            "cache must NOT be poisoned with the empty panicked bundle"
        );
        assert!(
            collector.bundle_fresh_at.is_none(),
            "freshness must NOT advance on a panicked bundle"
        );
    }

    fn available_bundle_with_finding() -> BackupDataBundle {
        BackupDataBundle {
            available: true,
            dry_run: false,
            config_dir: None,
            data_dir: None,
            schedule_dir: None,
            restic_available: Some(true),
            borg_available: None,
            schedule_installed: None,
            timer_active: None,
            schedule_note: None,
            findings: vec![FindingEntry {
                id: "binary.restic.found".into(),
                severity: "ok".into(),
                title: "restic found".into(),
                detail: String::new(),
                fix: None,
            }],
            unavailable_reason: None,
        }
    }

    #[tokio::test]
    async fn poll_populates_cache_on_available_bundle() {
        let mut collector = BackupCollector::new();
        let (tx, rx) = oneshot::channel();
        let bundle = BackupDataBundle {
            available: true,
            dry_run: false,
            config_dir: None,
            data_dir: None,
            schedule_dir: None,
            restic_available: Some(true),
            borg_available: None,
            schedule_installed: None,
            timer_active: None,
            schedule_note: None,
            findings: vec![FindingEntry {
                id: "binary.restic.found".into(),
                severity: "ok".into(),
                title: "restic found".into(),
                detail: String::new(),
                fix: None,
            }],
            unavailable_reason: None,
        };
        tx.send((bundle, false)).unwrap();
        collector.rx = Some(rx);
        let _ = collector.poll().await;
        assert!(collector.cached_bundle.is_some());
        assert!(collector.bundle_fresh_at.is_some());
    }
}

#[cfg(test)]
mod cadence_oracle {
    use super::*;

    const SENTINEL_ID: &str = "oracle-sentinel.backup.findings-cache";

    const SENTINEL_NOTE: &str = "oracle-sentinel backup schedule-note";

    fn sentinel_bundle() -> BackupDataBundle {
        BackupDataBundle {
            available: true,
            dry_run: false,
            config_dir: None,
            data_dir: None,
            schedule_dir: None,
            restic_available: Some(true),
            borg_available: None,
            schedule_installed: Some(true),
            timer_active: Some(true),
            schedule_note: Some(SENTINEL_NOTE.to_string()),
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
        let mut collector = BackupCollector::new();
        collector.cached_bundle = Some(sentinel_bundle());
        let primed = std::time::Instant::now();
        collector.bundle_fresh_at = Some(primed);

        collector.start();
        let bundle = collector.poll().await.expect("collection completes");

        assert!(
            bundle.available,
            "success-path backup collection is always available"
        );
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
            bundle.schedule_note.as_deref(),
            Some(SENTINEL_NOTE),
            "the sentinel note can only come from the cache, never from a real detect probe"
        );
        assert_eq!(bundle.schedule_installed, Some(true));
        assert_eq!(bundle.timer_active, Some(true));
        assert_eq!(
            collector.bundle_fresh_at,
            Some(primed),
            "a cache-hit poll must not advance (re-arm) the freshness timestamp"
        );
    }

    #[tokio::test]
    async fn ttl_expiry_bypasses_cache_and_rederives() {
        let mut collector = BackupCollector::new();
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
            bundle.schedule_note.as_deref(),
            Some(SENTINEL_NOTE),
            "an expired cache must not serve the sentinel note"
        );
        assert!(
            collector.bundle_fresh_at.is_some_and(|t| t > primed),
            "an expired cache must be re-derived and the freshness clock advanced"
        );
    }
}
