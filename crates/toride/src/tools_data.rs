//! Async installed-tools catalogue collection (read-only).
//!
//! The whole sweep (`$PATH` + version probes) is cached for 60s: a newly
//! installed or removed tool surfaces up to 60s late.

use std::time::Duration;

use tokio::sync::oneshot;
use toride_installer::{Detector, Tool};

use crate::tools_convert::{self, ToolSpec};
use crate::ui::screens::tools::{FindingEntry, ToolEntry};

/// Aggregated installed-tools data for the read-only section.
#[derive(Clone, Debug)]
pub struct ToolsDataBundle {
    /// Whether the sweep ran; `false` only for a collection panic. A host
    /// with every tool missing still yields `true` (findings stay visible).
    pub available: bool,
    /// One row per catalogue entry (installed or missing), in stable
    /// catalogue order. The UI groups these by category for display.
    pub tools: Vec<ToolEntry>,
    /// Count of installed tools across the whole catalogue.
    pub installed_count: usize,
    /// Total catalogue entries scanned.
    pub total_count: usize,
    /// Doctor findings (cached for 60s between collections). One
    /// `tools.missing.<name>` warning per MISSING expected tool.
    pub findings: Vec<FindingEntry>,
    /// Reason collection failed; populated only when `available == false`
    /// (collection-task panic).
    pub unavailable_reason: Option<String>,
}

/// Manages periodic async collection of the installed-tools catalogue.
///
/// A 60s TTL cache covers the whole sweep (rows, counts, findings).
pub struct ToolsCollector {
    rx: Option<oneshot::Receiver<(ToolsDataBundle, bool)>>,
    cached_bundle: Option<ToolsDataBundle>,
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

impl ToolsCollector {
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
    /// is served verbatim without any scan or probe.
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
            tokio::spawn(async move { collect_real_tools(use_cache, cached_bundle).await });
        tokio::spawn(async move {
            let result = handle.await;
            let (bundle, reused_cache) = match result {
                Ok(tuple) => tuple,
                Err(e) => {
                    tracing::warn!("tools data collection panicked: {e}");
                    (
                        empty_bundle_with_reason(format!("tools data collection panicked: {e}")),
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
    pub async fn poll(&mut self) -> Option<ToolsDataBundle> {
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

    /// Invalidate the sweep cache so the next collection re-runs the scan.
    #[allow(dead_code)]
    pub fn invalidate_findings_cache(&mut self) {
        self.cached_bundle = None;
        self.bundle_fresh_at = None;
    }
}

impl Default for ToolsCollector {
    fn default() -> Self {
        Self::new()
    }
}

async fn collect_real_tools(
    use_cache: bool,
    cached_bundle: Option<ToolsDataBundle>,
) -> (ToolsDataBundle, bool) {
    if use_cache && let Some(bundle) = cached_bundle {
        return (bundle, true);
    }

    let result = tokio::task::spawn_blocking(move || {
        let catalogue = tools_convert::catalogue();

        let detector = Detector::builder().probe_timeout(VERSION_TIMEOUT).build();

        let mut tools: Vec<ToolEntry> = Vec::with_capacity(catalogue.len());
        let mut installed_count = 0usize;

        for spec in &catalogue {
            let entry = detect_entry(spec, &detector);
            if entry.installed {
                installed_count += 1;
            }
            tools.push(entry);
        }

        let findings = tools_convert::convert_findings(&tools);

        let available = true;

        ToolsDataBundle {
            available,
            tools,
            installed_count,
            total_count: catalogue.len(),
            findings,
            unavailable_reason: None,
        }
    })
    .await;

    match result {
        Ok(bundle) => (bundle, false),
        Err(e) => {
            tracing::warn!("tools collection task panicked: {e}");
            (
                empty_bundle_with_reason(format!("tools data collection panicked: {e}")),
                false,
            )
        }
    }
}

const VERSION_TIMEOUT: Duration = Duration::from_millis(800);

fn catalogue_tool(name: &str, alias: &str) -> Tool {
    Tool {
        name: name.to_string(),
        bin_name: alias.to_string(),
        ..Tool::default()
    }
}

fn detect_entry(spec: &ToolSpec, detector: &Detector) -> ToolEntry {
    for alias in &spec.binaries {
        let status = detector.detect(&catalogue_tool(spec.name, alias));
        if let Some(entry) = entry_from_status(spec, &status) {
            return entry;
        }
        tracing::debug!("tools: '{alias}' not found on PATH or at the managed location");
    }
    missing_entry(spec)
}

fn entry_from_status(spec: &ToolSpec, status: &toride_installer::ToolStatus) -> Option<ToolEntry> {
    let path = status.path()?;
    Some(ToolEntry {
        name: spec.name.to_string(),
        category: spec.category.to_string(),
        installed: true,
        version: status.version().map(|v| v.line.clone()),
        path: Some(path.as_str().to_string()),
        expected: spec.expected,
    })
}

fn missing_entry(spec: &ToolSpec) -> ToolEntry {
    ToolEntry {
        name: spec.name.to_string(),
        category: spec.category.to_string(),
        installed: false,
        version: None,
        path: None,
        expected: spec.expected,
    }
}

fn empty_bundle() -> ToolsDataBundle {
    ToolsDataBundle {
        available: false,
        tools: Vec::new(),
        installed_count: 0,
        total_count: 0,
        findings: Vec::new(),
        unavailable_reason: None,
    }
}

fn empty_bundle_with_reason(reason: String) -> ToolsDataBundle {
    let mut b = empty_bundle();
    b.unavailable_reason = Some(reason);
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use toride_runner::{CommandOutput, CommandSpec, FakeRunner};

    #[test]
    fn new_is_not_pending() {
        let collector = ToolsCollector::new();
        assert!(!collector.is_pending());
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(
            ToolsCollector::new().is_pending(),
            ToolsCollector::default().is_pending()
        );
    }

    #[tokio::test]
    async fn start_makes_pending() {
        let mut collector = ToolsCollector::new();
        assert!(!collector.is_pending());
        collector.start();
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn start_is_idempotent() {
        let mut collector = ToolsCollector::new();
        collector.start();
        assert!(collector.is_pending());
        collector.start();
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn poll_returns_none_when_not_started() {
        let mut collector = ToolsCollector::new();
        assert!(collector.poll().await.is_none());
    }

    #[tokio::test]
    async fn poll_clears_pending() {
        let mut collector = ToolsCollector::new();
        collector.start();
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let _ = collector.poll().await;
        assert!(!collector.is_pending(), "poll should clear pending state");
    }

    #[tokio::test]
    async fn poll_returns_bundle_after_collection() {
        let mut collector = ToolsCollector::new();
        collector.start();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let bundle = collector.poll().await;
        assert!(bundle.is_some(), "poll should return Some after completion");
        let b = bundle.unwrap();
        assert!(b.available, "scan always runs -> available == true");
        assert!(
            !b.tools.is_empty(),
            "catalogue must be populated on any host"
        );
        assert_eq!(b.total_count, b.tools.len());
        assert_eq!(
            b.installed_count,
            b.tools.iter().filter(|t| t.installed).count()
        );
    }

    #[test]
    fn empty_bundle_is_unavailable() {
        let b = empty_bundle();
        assert!(!b.available);
        assert!(b.tools.is_empty());
        assert!(b.findings.is_empty());
        assert_eq!(b.installed_count, 0);
        assert_eq!(b.total_count, 0);
        assert!(
            b.unavailable_reason.is_none(),
            "empty_bundle carries no reason; panics use empty_bundle_with_reason"
        );
    }

    #[test]
    fn empty_bundle_with_reason_carries_reason() {
        let b = empty_bundle_with_reason("tools data collection panicked: boom".into());
        assert!(!b.available);
        assert_eq!(
            b.unavailable_reason.as_deref(),
            Some("tools data collection panicked: boom")
        );
    }

    #[tokio::test]
    async fn findings_cache_is_populated_after_poll() {
        let mut collector = ToolsCollector::new();
        collector.start();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let _ = collector.poll().await;
        assert!(collector.cached_bundle.is_some());
        assert!(collector.bundle_fresh_at.is_some());
    }

    #[test]
    fn invalidate_findings_cache_clears_it() {
        let mut collector = ToolsCollector::new();
        collector.cached_bundle = Some(available_empty_bundle());
        collector.bundle_fresh_at = Some(std::time::Instant::now());
        collector.invalidate_findings_cache();
        assert!(collector.cached_bundle.is_none());
        assert!(collector.bundle_fresh_at.is_none());
    }

    fn available_empty_bundle() -> ToolsDataBundle {
        ToolsDataBundle {
            available: true,
            tools: Vec::new(),
            installed_count: 0,
            total_count: 0,
            findings: Vec::new(),
            unavailable_reason: None,
        }
    }

    fn fixture_spec(name: &'static str, aliases: &[&str]) -> ToolSpec {
        ToolSpec {
            name,
            category: "Shell/System",
            binaries: aliases.iter().map(|a| (*a).to_string()).collect(),
            expected: true,
        }
    }

    fn production_detector() -> Detector {
        Detector::builder().probe_timeout(VERSION_TIMEOUT).build()
    }

    const BOGUS: &str = "this-binary-does-not-exist-toride-xyz";

    #[test]
    fn detect_entry_finds_a_known_alias_environmental() {
        let entry = detect_entry(
            &fixture_spec("cargo", &["which", "cargo"]),
            &production_detector(),
        );
        assert!(
            entry.installed,
            "expected at least one of [which, cargo] to resolve"
        );
    }

    #[test]
    fn detect_entry_missing_row_for_bogus_alias() {
        let entry = detect_entry(&fixture_spec(BOGUS, &[BOGUS]), &production_detector());
        assert!(!entry.installed);
        assert_eq!(entry.version, None);
        assert_eq!(entry.path, None);
        assert!(entry.expected);
    }

    #[test]
    fn detect_entry_tries_aliases_in_order_until_one_resolves() {
        let entry = detect_entry(
            &fixture_spec("cargo", &[BOGUS, "cargo"]),
            &production_detector(),
        );
        assert!(entry.installed);
        assert!(
            entry.path.as_deref().is_some_and(|p| p.ends_with("cargo")),
            "row path is the resolving alias: {:?}",
            entry.path
        );
    }

    #[test]
    fn entry_version_is_the_probe_line_byte_identical() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let bin_name = "toride-test-paritytool";
        let bin = tmp.path().join(bin_name);
        std::fs::write(&bin, b"#!/bin/sh\nexit 0\n").expect("write dummy executable");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))
                .expect("chmod dummy executable");
        }
        let bin_path = bin.to_str().expect("utf-8 tempdir").to_owned();

        let stdout = "paritytool version 12.0.1 (rev deadbeef)";
        let fake = FakeRunner::new().strict().respond(
            CommandSpec::new(bin_path.clone())
                .arg("--version")
                .stdin_null(true),
            CommandOutput::from_stdout(stdout),
        );
        let detector = Detector::with_runner(Arc::new(fake));

        let tool = Tool::builder()
            .name("paritytool")
            .bin_name(bin_name)
            .default_install_dir(tmp.path().to_str().expect("utf-8 tempdir"))
            .build()
            .expect("binary-kind descriptor always validates");
        let status = detector.detect(&tool);

        let entry = entry_from_status(&fixture_spec("paritytool", &[bin_name]), &status)
            .expect("the managed fixture is installed");
        assert_eq!(
            entry.version.as_deref(),
            Some(stdout),
            "ToolEntry.version must be ToolVersion.line, byte-identical"
        );
        assert_eq!(entry.path.as_deref(), Some(bin_path.as_str()));
    }

    #[test]
    fn entry_from_status_is_none_when_not_installed() {
        let status = toride_installer::ToolStatus::NotInstalled;
        assert!(entry_from_status(&fixture_spec("t", &["t"]), &status).is_none());
    }

    #[test]
    fn detect_entry_keeps_presence_when_probe_degrades() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let dir_str = dir.path().to_str().expect("utf-8 tempdir").to_owned();
        let tool = Tool::builder()
            .name("paritytool")
            .bin_name("toride-test-degradetool")
            .default_install_dir(dir_str)
            .build()
            .expect("binary-kind descriptor always validates");
        std::fs::write(dir.path().join("toride-test-degradetool"), b"x")
            .expect("write managed fixture");

        let detector = Detector::with_runner(Arc::new(FakeRunner::new().strict()));
        let status = detector.detect(&tool);
        let entry = entry_from_status(&fixture_spec("paritytool", &[]), &status)
            .expect("the managed fixture is installed");

        assert!(entry.installed);
        assert_eq!(entry.version, None);
    }

    #[test]
    fn catalogue_smoke_rows_are_well_formed_environmental() {
        let catalogue = tools_convert::catalogue();
        let detector = production_detector();

        let rows: Vec<ToolEntry> = catalogue
            .iter()
            .map(|spec| detect_entry(spec, &detector))
            .collect();

        assert_eq!(rows.len(), catalogue.len(), "one row per catalogue entry");
        for (spec, row) in catalogue.iter().zip(&rows) {
            assert_eq!(row.name, spec.name, "rows must stay in catalogue order");
            assert_eq!(row.category, spec.category);
            assert!(row.expected, "catalogue entries are expected");
            assert_eq!(
                row.installed,
                row.path.is_some(),
                "{}: installed iff a path resolved",
                row.name
            );
            if !row.installed {
                assert_eq!(
                    row.version, None,
                    "{}: a missing tool carries no version",
                    row.name
                );
            }
        }
    }
}

#[cfg(test)]
mod cadence_oracle {
    use super::*;

    const SENTINEL_ID: &str = "oracle-sentinel.tools.findings-cache";

    const SENTINEL_TOOL: &str = "oracle-sentinel-tools-row";

    fn sentinel_bundle() -> ToolsDataBundle {
        ToolsDataBundle {
            available: true,
            tools: vec![ToolEntry {
                name: SENTINEL_TOOL.to_string(),
                category: "oracle".to_string(),
                installed: true,
                version: Some("sentinel 1.2.3".to_string()),
                path: Some("/nonexistent/oracle-sentinel-bin".to_string()),
                expected: false,
            }],
            installed_count: 1,
            total_count: 1,
            findings: vec![FindingEntry {
                id: SENTINEL_ID.to_string(),
                severity: "warning".to_string(),
                title: "cadence-oracle sentinel".to_string(),
            }],
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
    async fn cache_hit_returns_cached_bundle_without_resweeping() {
        let mut collector = ToolsCollector::new();
        collector.cached_bundle = Some(sentinel_bundle());
        let primed = std::time::Instant::now();
        collector.bundle_fresh_at = Some(primed);

        collector.start();
        let bundle = collector.poll().await.expect("collection completes");

        assert_eq!(
            bundle.tools.len(),
            1,
            "a cache hit must serve the cached tool rows verbatim"
        );
        assert_eq!(
            bundle.tools[0].name, SENTINEL_TOOL,
            "the sentinel row name can only come from the cache, never from a real sweep"
        );
        assert_eq!(bundle.tools[0].version.as_deref(), Some("sentinel 1.2.3"));
        assert_eq!(bundle.installed_count, 1);
        assert_eq!(bundle.total_count, 1);
        assert_eq!(
            bundle.findings.len(),
            1,
            "a cache hit must serve the cached findings verbatim"
        );
        assert_eq!(
            bundle.findings[0].id, SENTINEL_ID,
            "the sentinel id can only come from the cache, never from a real catalogue scan"
        );
        let catalogue_len = tools_convert::catalogue().len();
        assert_ne!(
            bundle.total_count, catalogue_len,
            "total_count must be the cached sentinel, not a fresh catalogue count"
        );
        assert_eq!(
            collector.bundle_fresh_at,
            Some(primed),
            "a cache-hit poll must not advance (re-arm) the freshness timestamp"
        );
    }

    #[tokio::test]
    async fn ttl_expiry_bypasses_cache_and_rederives() {
        let mut collector = ToolsCollector::new();
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
        assert!(
            bundle.tools.iter().all(|t| t.name != SENTINEL_TOOL),
            "an expired cache must not serve the sentinel tool row"
        );
        let catalogue_len = tools_convert::catalogue().len();
        assert_eq!(
            bundle.total_count, catalogue_len,
            "an expired cache must re-run the real catalogue sweep"
        );
        assert!(
            collector.bundle_fresh_at.is_some_and(|t| t > primed),
            "an expired cache must be re-derived and the freshness clock advanced"
        );
    }
}
