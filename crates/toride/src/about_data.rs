//! Async About-toride data collection (LIVE READ-ONLY) via [`AboutCollector`],
//! reusing the shared [`TorideStatus`] snapshot delivered by the app's tick.

use tokio::sync::oneshot;

use crate::about_convert;
use crate::status::TorideStatus;
use crate::ui::screens::about::{AboutApp, AboutRuntime, AboutSystem};

/// Aggregated About-toride data for the read-only section.
#[derive(Clone, Debug)]
pub struct AboutDataBundle {
    /// Whether the bundle was collected at all. `false` is reserved for a
    /// `spawn_blocking` `JoinError`; field-level failures keep `true`.
    pub available: bool,
    /// Live host/system identity (hostname, os, kernel, arch, cpu, cores,
    /// memory, uptime, load).
    pub system: AboutSystem,
    /// Compile-time app build metadata (name, version, profile, homepage,
    /// authors).
    pub app: AboutApp,
    /// Runtime environment context (term, shell, user, lang, home, cwd,
    /// config / data dir, log path).
    pub runtime: AboutRuntime,
    /// Reason the bundle was unavailable; populated only when `available ==
    /// false` (a `spawn_blocking` `JoinError`), `None` otherwise.
    pub unavailable_reason: Option<String>,
}

/// Manages async collection of About-toride data over a single in-flight
/// oneshot channel.
pub struct AboutCollector {
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

    /// Start a new background collection; a no-op if one is already
    /// in-flight.
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

    /// Start a collection from an already-collected [`TorideStatus`] snapshot.
    /// A no-op if a collection is already in-flight.
    pub fn start_with_status(&mut self, status: TorideStatus) {
        if self.rx.is_some() {
            return;
        }
        let (tx, rx) = oneshot::channel();
        self.rx = Some(rx);
        tokio::spawn(async move {
            let bundle = about_bundle_from_status(&status);
            let _ = tx.send(bundle);
        });
    }

    /// Poll for a completed collection result: `Some(bundle)` once complete,
    /// `None` while pending or never started.
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

async fn collect_real_about() -> AboutDataBundle {
    let status_result = tokio::task::spawn_blocking(TorideStatus::collect).await;
    let status = match status_result {
        Ok(status) => status,
        Err(e) => {
            tracing::warn!("about status collection panicked: {e}");
            return empty_bundle_with_reason(format!("about data collection panicked: {e}"));
        }
    };

    about_bundle_from_status(&status)
}

fn about_bundle_from_status(status: &TorideStatus) -> AboutDataBundle {
    let app = about_convert::convert_app();

    let runtime = about_convert::convert_runtime();

    let system = about_convert::convert_system(status);

    AboutDataBundle {
        available: true,
        system,
        app,
        runtime,
        unavailable_reason: None,
    }
}

fn empty_bundle() -> AboutDataBundle {
    AboutDataBundle {
        available: false,
        system: AboutSystem::empty_for_bundle(),
        app: AboutApp::empty_for_bundle(),
        runtime: AboutRuntime::empty_for_bundle(),
        unavailable_reason: None,
    }
}

fn empty_bundle_with_reason(reason: String) -> AboutDataBundle {
    let mut b = empty_bundle();
    b.unavailable_reason = Some(reason);
    b
}

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
        collector.start();
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
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let _ = collector.poll().await;
        assert!(!collector.is_pending(), "poll should clear pending state");
    }

    #[tokio::test]
    async fn poll_returns_bundle_after_collection() {
        let mut collector = AboutCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let bundle = collector.poll().await;
        assert!(bundle.is_some(), "poll should return Some after completion");
        let b = bundle.unwrap();
        assert!(b.available, "bundle should be available after collection");
        assert!(!b.app.name.is_empty());
    }

    #[tokio::test]
    async fn poll_bundle_has_nonblank_system_fields() {
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

    #[tokio::test]
    async fn start_with_status_serves_injected_snapshot_without_recollecting() {
        let status = crate::status_collector::tests::test_status("f03-shared-snapshot-host");
        let mut collector = AboutCollector::new();
        collector.start_with_status(status);
        let bundle = collector.poll().await.expect("pure conversion completes");

        assert!(bundle.available, "conversion-only path is always available");
        assert_eq!(
            bundle.system.hostname, "f03-shared-snapshot-host",
            "the identity block must derive from the INJECTED snapshot, never a re-collect"
        );
        assert!(
            !bundle.app.name.is_empty(),
            "compile-time app metadata still populated"
        );
    }

    #[tokio::test]
    async fn start_with_status_is_idempotent_while_pending() {
        let mut collector = AboutCollector::new();
        collector.start_with_status(crate::status_collector::tests::test_status("first"));
        assert!(collector.is_pending());
        collector.start_with_status(crate::status_collector::tests::test_status("second"));
        let bundle = collector.poll().await.expect("first feed completes");
        assert_eq!(
            bundle.system.hostname, "first",
            "the in-flight conversion wins; the second feed is a no-op"
        );
    }
}
