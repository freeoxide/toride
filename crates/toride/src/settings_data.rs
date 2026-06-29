//! Async app-settings data collection (LIVE READ-ONLY).
//!
//! [`SettingsCollector`] manages background collection of the app's live
//! configuration + runtime environment via a tokio oneshot channel, following
//! the same SIMPLE pattern as
//! [`StatusCollector`](crate::status_collector::StatusCollector) and the other
//! read-only collectors MINUS their 60s findings cache — the Settings section
//! has no doctor/findings concept, so there is nothing expensive to throttle.
//!
//! This is a read-only integration: there are no write operations, no
//! optimistic updates, no cooldown gate, and no loading spinner. Every probe
//! is a pure read of the local config file + environment variables.
//!
//! ## What it gathers
//!
//! - **Config**: the toride config file path, whether it exists, the active
//!   theme name and log level parsed from it (best-effort), and every other
//!   `key = value` row. When the config module grows a real loader, swap it in
//!   here; today it parses `key = value` lines directly (the config crate is a
//!   stub).
//! - **Runtime**: `RUST_LOG`, the standard `dirs` data/config directories, the
//!   configured log file path, `$SHELL`, and `$TERM`.
//!
//! ## Blocking
//!
//! The config file read + `dirs` calls + `std::env` reads are all synchronous,
//! so the whole collection is wrapped in [`tokio::task::spawn_blocking`] so the
//! tokio worker is never stalled. An unreadable config file degrades the
//! `config` field (sets `exists = false`, empties `raw_keys`) but keeps
//! `available = true`; only a collection-task panic yields `available = false`
//! with a reason, mirroring every sibling collector.

use tokio::sync::oneshot;

use crate::settings_convert;
use crate::ui::screens::settings::{SettingsConfig, SettingsRuntime};

/// Aggregated app-settings data for the read-only section.
#[derive(Clone, Debug)]
pub struct SettingsDataBundle {
    /// Whether collection ran at all. `false` is reserved for the panic case
    /// (a `tokio::spawn` `JoinError`); an unreadable config file degrades the
    /// `config` field but keeps `available == true` so the operator still sees
    /// the runtime block + theme list.
    pub available: bool,
    /// Parsed toride config (path, exists, theme, log level, raw key=value rows).
    pub config: SettingsConfig,
    /// Runtime environment snapshot (`RUST_LOG`, dirs, shell, term, ...).
    pub runtime: SettingsRuntime,
    /// Human-readable reason collection failed, populated ONLY when
    /// `available == false` because the collection task panicked (`JoinError`).
    /// `None` otherwise — notably also `None` for a freshly-constructed empty
    /// bundle before any collection has run. Surfaced to the UI so the degraded
    /// panel can show what actually went wrong instead of guessing.
    pub unavailable_reason: Option<String>,
}

// ── Collector ───────────────────────────────────────────────────────────────

/// Manages periodic async collection of app-settings data.
///
/// Mirrors [`StatusCollector`](crate::status_collector::StatusCollector): a
/// oneshot channel for the in-flight result, no findings cache. There is no
/// expensive doctor suite to throttle, so every refresh re-reads the config
/// file + env fresh (cheap fs read on the blocking pool).
pub struct SettingsCollector {
    /// Carries the bundle result. No `bool`/cache companion because there are
    /// no findings to reuse.
    rx: Option<oneshot::Receiver<SettingsDataBundle>>,
}

impl SettingsCollector {
    /// Create a new collector with no pending collection.
    #[must_use]
    pub fn new() -> Self {
        Self { rx: None }
    }

    /// Whether a collection is currently in-flight.
    pub fn is_pending(&self) -> bool {
        self.rx.is_some()
    }

    /// Start a new background collection.
    ///
    /// If a collection is already in-flight, this is a no-op.
    pub fn start(&mut self) {
        if self.rx.is_some() {
            return;
        }
        let (tx, rx) = oneshot::channel();
        self.rx = Some(rx);
        // Mirror toride_harden_data's panic-safe wrap: the inner task body is
        // awaited inside an outer spawn so a JoinError (panic inside
        // collect_real_settings) is matched here and surfaced as a degraded
        // `available == false` bundle with a reason. Without this wrap a panic
        // would drop `tx`, `rx.await` would return `Err`, and poll() would map
        // that to `None`, leaving the dashboard showing stale last-good data
        // indefinitely with no degraded-state signal.
        let handle = tokio::spawn(async move { collect_real_settings().await });
        tokio::spawn(async move {
            let bundle = match handle.await {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!("settings data collection panicked: {e}");
                    empty_bundle_with_reason(format!("settings data collection panicked: {e}"))
                }
            };
            let _ = tx.send(bundle);
        });
    }

    /// Poll for a completed collection result.
    ///
    /// Returns `Some(bundle)` if the collection completed, `None` if still
    /// pending or if the collection failed.
    pub async fn poll(&mut self) -> Option<SettingsDataBundle> {
        match &mut self.rx {
            Some(rx) => {
                let result = rx.await.ok();
                self.rx = None;
                result
            }
            None => None,
        }
    }
}

impl Default for SettingsCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Real data collection ────────────────────────────────────────────────────

/// Collect app-settings data by reading the config file + environment.
///
/// All work (file read, `dirs`, `std::env`) runs on the blocking thread pool
/// via a single [`tokio::task::spawn_blocking`]. Every sub-probe degrades
/// gracefully: an unreadable / absent config file sets `config.exists = false`
/// and empties `raw_keys` but keeps `available == true`; a missing env var
/// just yields `None` for its slot. Only a collection-task panic (caught as a
/// `JoinError` in `start()`) flips `available` to `false`.
async fn collect_real_settings() -> SettingsDataBundle {
    let result = tokio::task::spawn_blocking(settings_convert::collect_local).await;
    match result {
        Ok(bundle) => bundle,
        Err(e) => {
            tracing::warn!("settings collection task panicked: {e}");
            empty_bundle_with_reason(format!("settings data collection panicked: {e}"))
        }
    }
}

/// Empty bundle used before the first collection and when the collection task
/// panicked. `available = false` signals the UI to render the degraded panel;
/// no reason is attached here (the `JoinError` reason is added by
/// [`empty_bundle_with_reason`]).
fn empty_bundle() -> SettingsDataBundle {
    SettingsDataBundle {
        available: false,
        config: settings_convert::empty_config(),
        runtime: settings_convert::empty_runtime(),
        unavailable_reason: None,
    }
}

/// Empty bundle carrying the reason collection failed. Used when the spawned
/// collection task panicked (`JoinError`) — the reason string is rendered by the
/// UI's degraded panel so the operator sees what actually went wrong, mirroring
/// every sibling collector's panic path.
fn empty_bundle_with_reason(reason: String) -> SettingsDataBundle {
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
        let collector = SettingsCollector::new();
        assert!(!collector.is_pending());
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(
            SettingsCollector::new().is_pending(),
            SettingsCollector::default().is_pending()
        );
    }

    #[tokio::test]
    async fn start_makes_pending() {
        let mut collector = SettingsCollector::new();
        assert!(!collector.is_pending());
        collector.start();
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn start_is_idempotent() {
        let mut collector = SettingsCollector::new();
        collector.start();
        assert!(collector.is_pending());
        collector.start(); // no-op, does not replace the receiver
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn poll_returns_none_when_not_started() {
        let mut collector = SettingsCollector::new();
        assert!(collector.poll().await.is_none());
    }

    #[tokio::test]
    async fn poll_clears_pending() {
        let mut collector = SettingsCollector::new();
        collector.start();
        // The blocking fs read completes near-instantly; give it a beat.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let _ = collector.poll().await;
        assert!(!collector.is_pending(), "poll should clear pending state");
    }

    #[tokio::test]
    async fn poll_returns_bundle_after_collection() {
        // On any host the collector must return Some(bundle) after start() +
        // enough time. `available` is true whenever the task body ran without
        // panicking (config-file presence only gates the config block, not
        // availability).
        let mut collector = SettingsCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_millis(800)).await;
        let bundle = collector.poll().await;
        assert!(bundle.is_some(), "poll should return Some after completion");
    }

    #[test]
    fn empty_bundle_is_unavailable() {
        let b = empty_bundle();
        assert!(!b.available);
        assert!(!b.config.exists);
        assert!(b.config.raw_keys.is_empty());
        assert!(
            b.unavailable_reason.is_none(),
            "empty_bundle carries no reason; panics use empty_bundle_with_reason"
        );
    }

    #[test]
    fn empty_bundle_with_reason_carries_reason() {
        let b = empty_bundle_with_reason("settings data collection panicked: boom".into());
        assert!(!b.available);
        assert_eq!(
            b.unavailable_reason.as_deref(),
            Some("settings data collection panicked: boom")
        );
    }
}
