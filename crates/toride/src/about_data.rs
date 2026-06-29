//! Async About-toride data collection (LIVE READ-ONLY).
//!
//! [`AboutCollector`] manages background collection of system + app identity
//! via a tokio oneshot channel, following the SAME simple-variant pattern as
//! [`StatusCollector`](crate::status_collector::StatusCollector): there is no
//! 60s findings cache because the About screen has no doctor / findings
//! concept — it is identity metadata, not a health check.
//!
//! This is the read-only counterpart to `StatusCollector`: it reuses
//! [`crate::status::TorideStatus::collect`] (via `spawn_blocking`, exactly like
//! `StatusCollector`) for the live host/system block, and layers the
//! compile-time app build metadata + the runtime env block on top.
//!
//! ## Blocking
//!
//! [`TorideStatus::collect`] shells out / reads `/proc` / `sysctl`
//! synchronously, so it runs on the blocking thread pool via
//! [`tokio::task::spawn_blocking`] — the tokio worker is never stalled. The env
//! reads and `dirs` lookups are cheap and safe to run inline on the async task.
//!
//! ## Availability
//!
//! `available == true` once [`collect_real_about`] returns. The only path to
//! `available == false` is a `spawn_blocking` `JoinError` (a panic inside
//! `TorideStatus::collect`) — that yields [`empty_bundle_with_reason`] so the
//! UI renders a degraded panel with the reason. Individual field failures
//! degrade that field (via the convert layer's placeholders) but keep
//! `available == true`, mirroring the harden / tailscale graceful-degradation
//! contract.
//!
//! ## Note on the cache variant
//!
//! This collector does NOT carry the 60s findings cache used by the doctor-
//! based collectors (`fail2ban` / `harden` / `tailscale` / etc.), because there
//! is no expensive doctor suite to throttle. The simple oneshot shape mirrors
//! [`StatusCollector`] exactly.

use tokio::sync::oneshot;

use crate::about_convert;
use crate::status::TorideStatus;
use crate::ui::screens::about::{AboutApp, AboutRuntime, AboutSystem};

/// Aggregated About-toride data for the read-only section.
#[derive(Clone, Debug)]
pub struct AboutDataBundle {
    /// Whether the About bundle was collected at all. `false` is reserved for
    /// the panic case (a `spawn_blocking` `JoinError`) — individual probe
    /// failures degrade a field (via placeholders) but keep `available == true`
    /// so the operator sees what is populated rather than a blank panel.
    pub available: bool,
    /// Live host/system identity (hostname, os, kernel, arch, cpu, cores,
    /// memory, uptime, load).
    pub system: AboutSystem,
    /// Compile-time app build metadata (name, version, profile, homepage,
    /// authors).
    pub app: AboutApp,
    /// Runtime environment context (term, shell, user, lang, home, cwd, config
    /// / data dir, log path).
    pub runtime: AboutRuntime,
    /// Human-readable reason the bundle was unavailable, populated ONLY when
    /// `available == false` (a `spawn_blocking` `JoinError`). `None` otherwise —
    /// notably also `None` for a freshly-constructed empty bundle before any
    /// collection has run. Surfaced to the UI so the degraded panel can show
    /// what actually went wrong instead of guessing.
    pub unavailable_reason: Option<String>,
}

// ── Collector ───────────────────────────────────────────────────────────────

/// Manages periodic async collection of About-toride data.
///
/// Mirrors [`StatusCollector`]: a single oneshot channel for the in-flight
/// result, no findings cache. The collection reuses
/// [`TorideStatus::collect`] (the same call `StatusCollector` makes) so the
/// two collectors do duplicate work on the blocking pool — but the About
/// screen needs the structured identity fields in a different shape than the
/// dashboard's gauges, so the dedicated collector keeps the two render paths
/// decoupled.
pub struct AboutCollector {
    /// Carries the bundle once the spawned collection completes. `None` when no
    /// collection is in-flight (after `poll()` consumes a result, or before the
    /// first `start()`).
    rx: Option<oneshot::Receiver<AboutDataBundle>>,
}

impl AboutCollector {
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
    /// If a collection is already in-flight, this is a no-op. The blocking
    /// `TorideStatus::collect` runs on the tokio blocking pool; the cheap env /
    /// `dirs` reads and the convert assembly run inline on the async task.
    pub fn start(&mut self) {
        if self.rx.is_some() {
            return;
        }
        let (tx, rx) = oneshot::channel();
        self.rx = Some(rx);
        tokio::spawn(async move {
            let bundle = collect_real_about().await;
            let _ = tx.send(bundle);
        });
    }

    /// Poll for a completed collection result.
    ///
    /// Returns `Some(bundle)` if the collection completed, `None` if still
    /// pending or if the collection failed (the sender was dropped — only
    /// possible if the spawned task panicked before the outer join wrapper ran,
    /// which cannot happen with the current `collect_real_about` shape).
    pub async fn poll(&mut self) -> Option<AboutDataBundle> {
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

impl Default for AboutCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Real data collection ────────────────────────────────────────────────────

/// Collect About-toride data by gathering the live status snapshot + env.
///
/// All blocking work (`TorideStatus::collect`) runs on the blocking thread
/// pool. The convert layer assembles the three presentation blocks
/// (system / app / runtime) from the snapshot + env, degrading each field
/// gracefully. On a `spawn_blocking` `JoinError` (a panic inside
/// `TorideStatus::collect`) returns [`empty_bundle_with_reason`] with
/// `available = false`.
///
/// `available` is `true` whenever collection completed — the underlying probes
/// cannot fail wholesale (an unreadable hostname, say, degrades to a
/// placeholder via the convert layer, it does not flip the whole bundle
/// offline).
async fn collect_real_about() -> AboutDataBundle {
    // ── Live status snapshot (blocking) ──────────────────────────────────
    // Reuse TorideStatus::collect exactly like StatusCollector does. On a
    // JoinError the closure fell back to a direct collect already; here we
    // surface the panic as a degraded bundle instead, so the UI can show the
    // reason rather than a silently-fallback result that hides the panic.
    let status_result = tokio::task::spawn_blocking(TorideStatus::collect).await;
    let status = match status_result {
        Ok(status) => status,
        Err(e) => {
            tracing::warn!("about status collection panicked: {e}");
            return empty_bundle_with_reason(format!("about data collection panicked: {e}"));
        }
    };

    // ── App build metadata (compile-time constants; always populated) ────
    let app = about_convert::convert_app();

    // ── Runtime env (cheap env reads + dirs lookups; safe inline) ────────
    let runtime = about_convert::convert_runtime();

    // ── System identity (derived from the status snapshot) ───────────────
    let system = about_convert::convert_system(&status);

    AboutDataBundle {
        available: true,
        system,
        app,
        runtime,
        unavailable_reason: None,
    }
}

/// Empty bundle used before any collection has run, or when the spawned
/// collection task panicked before producing a result.
///
/// `available = false` signals the UI to render the degraded panel. All three
/// blocks are placeholder-only so a stale render (if any) does not show
/// partial identity data. No reason is attached because none is known at this
/// point; collection-time panics use [`empty_bundle_with_reason`] to surface
/// the `JoinError`.
fn empty_bundle() -> AboutDataBundle {
    AboutDataBundle {
        available: false,
        system: AboutSystem::empty_for_bundle(),
        app: AboutApp::empty_for_bundle(),
        runtime: AboutRuntime::empty_for_bundle(),
        unavailable_reason: None,
    }
}

/// Empty bundle carrying the reason collection failed. Used when a
/// `spawn_blocking` task panicked (`JoinError`) — the reason string is rendered
/// by the UI's degraded panel so the operator sees what actually went wrong,
/// mirroring the `empty_bundle_with_reason` path in harden / tailscale / etc.
fn empty_bundle_with_reason(reason: String) -> AboutDataBundle {
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
        let collector = AboutCollector::new();
        assert!(!collector.is_pending());
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(
            AboutCollector::new().is_pending(),
            AboutCollector::default().is_pending()
        );
    }

    #[tokio::test]
    async fn start_makes_pending() {
        let mut collector = AboutCollector::new();
        assert!(!collector.is_pending());
        collector.start();
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn start_is_idempotent() {
        let mut collector = AboutCollector::new();
        collector.start();
        assert!(collector.is_pending());
        collector.start(); // no-op, does not replace the receiver
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn poll_returns_none_when_not_started() {
        let mut collector = AboutCollector::new();
        assert!(collector.poll().await.is_none());
    }

    #[tokio::test]
    async fn poll_clears_pending() {
        let mut collector = AboutCollector::new();
        collector.start();
        // Let the spawned task complete (TorideStatus::collect runs on the
        // blocking pool; give it time).
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let _ = collector.poll().await;
        assert!(!collector.is_pending(), "poll should clear pending state");
    }

    #[tokio::test]
    async fn poll_returns_bundle_after_collection() {
        // On any host the collector must return Some(bundle) after start() +
        // enough time. The bundle's `available` flag is true whenever
        // collection completed.
        let mut collector = AboutCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let bundle = collector.poll().await;
        assert!(bundle.is_some(), "poll should return Some after completion");
        let b = bundle.unwrap();
        assert!(b.available, "bundle should be available after collection");
        // App metadata is always populated (compile-time constants).
        assert!(!b.app.name.is_empty());
    }

    #[tokio::test]
    async fn poll_bundle_has_nonblank_system_fields() {
        // Each system field degrades to a placeholder rather than blank.
        let mut collector = AboutCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let b = collector.poll().await.expect("poll should return Some");
        for (label, value) in [
            ("hostname", &b.system.hostname),
            ("os", &b.system.os),
            ("kernel", &b.system.kernel),
            ("arch", &b.system.arch),
            ("cpu_brand", &b.system.cpu_brand),
            ("cores", &b.system.cores),
            ("mem_total", &b.system.mem_total),
            ("uptime", &b.system.uptime),
            ("load", &b.system.load),
        ] {
            assert!(
                !value.is_empty(),
                "{label} must never be blank after collection: {value:?}"
            );
        }
    }

    #[test]
    fn empty_bundle_is_unavailable() {
        let b = empty_bundle();
        assert!(!b.available);
        assert!(b.system.hostname.is_empty());
        assert!(b.app.name.is_empty());
        assert!(b.runtime.shell.is_empty());
        assert!(
            b.unavailable_reason.is_none(),
            "empty_bundle carries no reason; panics use empty_bundle_with_reason"
        );
    }

    #[test]
    fn empty_bundle_with_reason_carries_reason() {
        let b = empty_bundle_with_reason("about data collection panicked: boom".into());
        assert!(!b.available);
        assert_eq!(
            b.unavailable_reason.as_deref(),
            Some("about data collection panicked: boom")
        );
    }
}
