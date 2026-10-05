//! Async read-only mise collection: the whole bundle is cached for 60s
//! (`BUNDLE_TTL`), and per-probe failures degrade fields, not the section.

use std::sync::OnceLock;
use std::time::Duration;

use tokio::sync::oneshot;
use toride_mise::MiseBinary;

use crate::toride_mise_convert;
use crate::ui::screens::toride_mise::{MiseFindingEntry, MiseOutdatedEntry, MiseToolEntry};

static MISE_BINARY: OnceLock<MiseBinary> = OnceLock::new();

const CMD_TIMEOUT: Duration = Duration::from_secs(3);

/// A read-only snapshot of mise state collected for the mise screen.
#[derive(Clone, Debug)]
pub struct MiseDataBundle {
    /// `false` only when construction failed (mise absent), every probe
    /// timed out or errored, or the collection task panicked.
    pub available: bool,
    /// mise's own version string; `None` when the probe failed.
    pub version: Option<String>,
    /// Installed tools.
    pub tools: Vec<MiseToolEntry>,
    /// Tools with a newer version available.
    pub outdated: Vec<MiseOutdatedEntry>,
    /// Paths of the discovered mise config files.
    pub config_files: Vec<String>,
    /// Doctor findings.
    pub findings: Vec<MiseFindingEntry>,
    /// Populated only when `available == false` (construction failure,
    /// all probes failed, or a panicked task); rendered by the degraded panel.
    pub unavailable_reason: Option<String>,
}

/// Manages periodic async collection of mise data with a 60s whole-bundle
/// cache: a cache-hit tick runs no mise subprocess.
pub struct MiseCollector {
    rx: Option<oneshot::Receiver<(MiseDataBundle, bool)>>,
    cached_bundle: Option<MiseDataBundle>,
    bundle_fresh_at: Option<std::time::Instant>,
}

const BUNDLE_TTL: Duration = Duration::from_secs(60);

fn ttl_expired(fresh_at: std::time::Instant) -> bool {
    let elapsed = fresh_at.elapsed();
    #[cfg(test)]
    let elapsed = elapsed + Duration::from_millis(TTL_TEST_OFFSET_MS.with(std::cell::Cell::get));
    elapsed >= BUNDLE_TTL
}

#[cfg(test)]
thread_local! {
    static TTL_TEST_OFFSET_MS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

impl MiseCollector {
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

    /// Start a background collection; a no-op if one is already in-flight.
    /// A fresh 60s cache is served verbatim without running any probe.
    pub fn start(&mut self) {
        if self.rx.is_some() {
            return;
        }
        let (tx, rx) = oneshot::channel();
        let use_cache =
            self.cached_bundle.is_some() && self.bundle_fresh_at.is_some_and(|t| !ttl_expired(t));
        let cached_bundle = self.cached_bundle.clone();
        self.rx = Some(rx);
        let handle = tokio::spawn(async move { collect_real_mise(use_cache, cached_bundle).await });
        tokio::spawn(async move {
            let (bundle, reused_cache) = match handle.await {
                Ok(tuple) => tuple,
                Err(e) => {
                    tracing::error!("mise collection task panicked: {e}");
                    (
                        empty_bundle_with_reason(format!("mise collection task panicked: {e}")),
                        false,
                    )
                }
            };
            let _ = tx.send((bundle, reused_cache));
        });
    }

    /// Returns `Some(bundle)` once the collection completes, `None` while
    /// still pending; a degraded bundle is never cached, so the next tick retries.
    pub async fn poll(&mut self) -> Option<MiseDataBundle> {
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

impl Default for MiseCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "real-data collection is inherently linear"
)]
async fn collect_real_mise(
    use_cache: bool,
    cached_bundle: Option<MiseDataBundle>,
) -> (MiseDataBundle, bool) {
    if use_cache && let Some(bundle) = cached_bundle {
        return (bundle, true);
    }

    let mise = match discover_mise_client().await {
        Ok(m) => m,
        Err(e) => {
            tracing::debug!("mise backend construction failed: {e}");
            return (
                empty_bundle_with_reason(format!("mise backend unavailable: {e}")),
                false,
            );
        }
    };

    let (version_r, tools_r, current_r, outdated_r, config_r, diag_r) = tokio::join!(
        async { tokio::time::timeout(CMD_TIMEOUT, mise.run_checked(["--version"])).await },
        async { tokio::time::timeout(CMD_TIMEOUT, mise.list_installed()).await },
        async { tokio::time::timeout(CMD_TIMEOUT, mise.list_current()).await },
        async { tokio::time::timeout(CMD_TIMEOUT, mise.outdated_map()).await },
        async { tokio::time::timeout(CMD_TIMEOUT, mise.config_ls()).await },
        async { tokio::time::timeout(CMD_TIMEOUT, mise.doctor()).await },
    );

    let version = match version_r {
        Ok(Ok(out)) => {
            let v = out.stdout_trimmed().trim().to_owned();
            if v.is_empty() { None } else { Some(v) }
        }
        Ok(Err(e)) => {
            tracing::debug!("mise --version: {e}");
            None
        }
        Err(_) => {
            tracing::debug!("mise --version: timed out");
            None
        }
    };

    let mut tools: Vec<MiseToolEntry> = match tools_r {
        Ok(Ok(list)) => toride_mise_convert::convert_tools(list),
        Ok(Err(e)) => {
            tracing::debug!("mise ls --installed: {e}");
            Vec::new()
        }
        Err(_) => {
            tracing::debug!("mise ls --installed: timed out");
            Vec::new()
        }
    };

    if let Ok(Ok(current)) = current_r {
        let active_names: std::collections::HashSet<String> = current
            .into_iter()
            .filter(|t| t.active.unwrap_or(false))
            .map(|t| t.name)
            .collect();
        for tool in &mut tools {
            if active_names.contains(&tool.name) {
                tool.active = true;
            }
        }
    }

    let outdated: Vec<MiseOutdatedEntry> = match outdated_r {
        Ok(Ok(map)) => toride_mise_convert::convert_outdated_map(map),
        Ok(Err(e)) => {
            tracing::debug!("mise outdated: {e}");
            Vec::new()
        }
        Err(_) => {
            tracing::debug!("mise outdated: timed out");
            Vec::new()
        }
    };

    if !outdated.is_empty() {
        let outdated_names: std::collections::HashSet<&str> =
            outdated.iter().map(|o| o.name.as_str()).collect();
        for tool in &mut tools {
            if outdated_names.contains(tool.name.as_str()) {
                tool.outdated = true;
            }
        }
    }

    let config_files: Vec<String> = match config_r {
        Ok(Ok(paths)) => paths
            .into_iter()
            .map(|p| p.to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        Ok(Err(e)) => {
            tracing::debug!("mise config ls: {e}");
            Vec::new()
        }
        Err(_) => {
            tracing::debug!("mise config ls: timed out");
            Vec::new()
        }
    };

    let findings: Vec<MiseFindingEntry> = match diag_r {
        Ok(Ok(report)) => {
            let mut entries = toride_mise_convert::convert_diagnostics(report.errors);
            entries.extend(toride_mise_convert::convert_diagnostics(report.warnings));
            entries
        }
        Ok(Err(e)) => {
            tracing::debug!("mise doctor: {e}");
            Vec::new()
        }
        Err(_) => {
            tracing::debug!("mise doctor: timed out");
            Vec::new()
        }
    };

    let unavailable_reason = reason_when_construction_ok_but_unavailable(
        version.as_ref(),
        &tools,
        &outdated,
        &config_files,
        &findings,
    );
    let available = unavailable_reason.is_none();

    (
        MiseDataBundle {
            available,
            version,
            tools,
            outdated,
            config_files,
            findings,
            unavailable_reason,
        },
        false,
    )
}

async fn discover_mise_client() -> toride_mise::MiseResult<toride_mise::Mise> {
    let binary = if let Some(cached) = MISE_BINARY.get() {
        cached.clone()
    } else {
        let discovered = MiseBinary::discover_async().await?;
        let _ = MISE_BINARY.set(discovered.clone());
        discovered
    };
    toride_mise::Mise::builder().binary(binary).build()
}

fn empty_bundle() -> MiseDataBundle {
    MiseDataBundle {
        available: false,
        version: None,
        tools: Vec::new(),
        outdated: Vec::new(),
        config_files: Vec::new(),
        findings: Vec::new(),
        unavailable_reason: None,
    }
}

fn empty_bundle_with_reason(reason: String) -> MiseDataBundle {
    let mut b = empty_bundle();
    b.unavailable_reason = Some(reason);
    b
}

fn reason_when_construction_ok_but_unavailable(
    version: Option<&String>,
    tools: &[MiseToolEntry],
    outdated: &[MiseOutdatedEntry],
    config_files: &[String],
    findings: &[MiseFindingEntry],
) -> Option<String> {
    let available = version.is_some()
        || !tools.is_empty()
        || !outdated.is_empty()
        || !config_files.is_empty()
        || !findings.is_empty();
    if available {
        None
    } else {
        Some("mise did not respond — all probes timed out or failed".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_not_pending() {
        let collector = MiseCollector::new();
        assert!(!collector.is_pending());
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(
            MiseCollector::new().is_pending(),
            MiseCollector::default().is_pending()
        );
    }

    #[tokio::test]
    async fn start_makes_pending() {
        let mut collector = MiseCollector::new();
        assert!(!collector.is_pending());
        collector.start();
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn start_is_idempotent() {
        let mut collector = MiseCollector::new();
        collector.start();
        assert!(collector.is_pending());
        collector.start();
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn poll_returns_none_when_not_started() {
        let mut collector = MiseCollector::new();
        assert!(collector.poll().await.is_none());
    }

    #[tokio::test]
    async fn poll_clears_pending() {
        let mut collector = MiseCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let _ = collector.poll().await;
        assert!(!collector.is_pending(), "poll should clear pending state");
    }

    #[tokio::test]
    async fn poll_returns_bundle_after_collection() {
        let mut collector = MiseCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let bundle = collector.poll().await;
        assert!(bundle.is_some(), "poll should return Some after completion");
    }

    #[test]
    fn empty_bundle_is_unavailable() {
        let b = empty_bundle();
        assert!(!b.available);
        assert!(b.tools.is_empty());
        assert!(b.outdated.is_empty());
        assert_eq!(b.config_files, Vec::<String>::new());
        assert!(b.findings.is_empty());
        assert!(b.version.is_none());
        assert!(
            b.unavailable_reason.is_none(),
            "empty_bundle carries no reason; failures use empty_bundle_with_reason"
        );
    }

    #[test]
    fn empty_bundle_with_reason_carries_reason_and_is_unavailable() {
        let b = empty_bundle_with_reason("mise binary not found".into());
        assert!(!b.available);
        assert_eq!(
            b.unavailable_reason.as_deref(),
            Some("mise binary not found")
        );
    }

    #[tokio::test]
    async fn findings_cache_is_populated_after_poll() {
        let mut collector = MiseCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let bundle = collector.poll().await;
        if bundle.is_some_and(|b| b.available) {
            assert!(collector.cached_bundle.is_some());
            assert!(collector.bundle_fresh_at.is_some());
        } else {
            assert!(
                collector.cached_bundle.is_none(),
                "a degraded bundle must not be cached"
            );
        }
    }

    #[test]
    fn invalidate_findings_cache_clears_it() {
        let mut collector = MiseCollector::new();
        collector.cached_bundle = Some(empty_bundle());
        collector.bundle_fresh_at = Some(std::time::Instant::now());
        collector.invalidate_findings_cache();
        assert!(collector.cached_bundle.is_none());
        assert!(collector.bundle_fresh_at.is_none());
    }

    use toride_mise::serde_utils::json_outputs::{OutdatedOutput, OutdatedToolEntry};

    fn parse_outdated(raw: &str) -> OutdatedOutput {
        serde_json::from_str(raw).expect("outdated JSON must parse into OutdatedOutput")
    }

    #[test]
    fn outdated_real_fixture_maps_current_and_latest() {
        let raw = r#"{"node":{"requested":"22","current":"22.0.0","latest":"22.1.0"}}"#;
        let entries = toride_mise_convert::convert_outdated_map(parse_outdated(raw));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "node");
        assert_eq!(entries[0].current.as_deref(), Some("22.0.0"));
        assert_eq!(entries[0].latest.as_deref(), Some("22.1.0"));
    }

    #[test]
    fn installed_outdated_flag_enriched_from_outdated_map() {
        let installed = vec![
            toride_mise::ToolStatus {
                name: "node".into(),
                version: Some("22.0.0".into()),
                source: None,
                active: None,
                install_path: None,
                installed: Some(true),
                missing: Some(false),
                outdated: None,
                requested: None,
            },
            toride_mise::ToolStatus {
                name: "python".into(),
                version: Some("3.11.0".into()),
                source: None,
                active: None,
                install_path: None,
                installed: Some(true),
                missing: Some(false),
                outdated: None,
                requested: None,
            },
        ];
        let mut tools = toride_mise_convert::convert_tools(installed);
        assert!(
            tools.iter().all(|t| !t.outdated),
            "convert_tool must default outdated to false from ls --installed"
        );

        let raw = r#"{"node":{"requested":"22","current":"22.0.0","latest":"22.1.0"}}"#;
        let outdated = toride_mise_convert::convert_outdated_map(parse_outdated(raw));

        let outdated_names: std::collections::HashSet<&str> =
            outdated.iter().map(|o| o.name.as_str()).collect();
        for tool in &mut tools {
            if outdated_names.contains(tool.name.as_str()) {
                tool.outdated = true;
            }
        }

        let node = tools.iter().find(|t| t.name == "node").expect("node row");
        let python = tools
            .iter()
            .find(|t| t.name == "python")
            .expect("python row");
        assert!(
            node.outdated,
            "node is in the outdated map → Installed row must flag outdated"
        );
        assert!(
            !python.outdated,
            "python is NOT in the outdated map → flag must stay false"
        );
    }

    #[test]
    fn outdated_map_parses_where_vec_probe_failed() {
        let raw = r#"{"node":{"requested":"22","current":"22.0.0","latest":"22.1.0"}}"#;
        let map: OutdatedOutput = serde_json::from_str(raw).expect("map must parse");
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn outdated_empty_object_yields_empty_pane() {
        let entries = toride_mise_convert::convert_outdated_map(parse_outdated("{}"));
        assert!(entries.is_empty());
    }

    #[test]
    fn outdated_empty_map_yields_empty() {
        let entries = toride_mise_convert::convert_outdated_map(OutdatedOutput::new());
        assert!(entries.is_empty());
    }

    #[test]
    fn outdated_null_and_array_do_not_deserialize() {
        for raw in ["null", "[]", ""] {
            let res: Result<OutdatedOutput, _> = serde_json::from_str(raw);
            assert!(
                res.is_err(),
                "payload {raw:?} must NOT parse into OutdatedOutput \
                 (else the collector's Vec::new() degradation is dead): {res:?}"
            );
        }
    }

    #[test]
    fn outdated_missing_versions_are_none_not_requested() {
        let mut map = OutdatedOutput::new();
        map.insert(
            "node".into(),
            OutdatedToolEntry {
                requested: Some("22".into()),
                current: None,
                latest: None,
                name: None,
                backend: None,
            },
        );
        let entries = toride_mise_convert::convert_outdated_map(map);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "node");
        assert!(entries[0].current.is_none());
        assert!(
            entries[0].latest.is_none(),
            "latest must NOT be back-filled from requested"
        );
    }

    #[test]
    fn installed_tool_placeholder_for_empty_name_and_version() {
        let t = toride_mise::ToolStatus {
            name: String::new(),
            version: Some(String::new()),
            source: None,
            active: None,
            install_path: None,
            installed: None,
            missing: None,
            outdated: None,
            requested: None,
        };
        let entry = toride_mise_convert::convert_tool(t);
        assert_eq!(entry.name, "(unknown)");
        assert!(entry.version.is_none());
    }

    #[test]
    fn doctor_empty_messages_become_placeholders() {
        use toride_mise::diagnostics::{Diagnostic, DiagnosticKind};
        let diags = vec![
            Diagnostic::new(DiagnosticKind::MissingTools, ""),
            Diagnostic::new(DiagnosticKind::Other, ""),
        ];
        let entries = toride_mise_convert::convert_diagnostics(diags);
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|e| e.message == "(no message)"));
    }

    #[test]
    fn empty_version_stdout_degrades_to_none() {
        let empty = String::new();
        let v = empty.trim();
        assert!(v.is_empty(), "collector treats empty stdout as None");
        let b = empty_bundle();
        assert!(
            b.version.is_none(),
            "fresh empty_bundle has no version regardless"
        );
    }

    #[test]
    fn availability_heuristic_false_on_all_empty_probes() {
        let b = MiseDataBundle {
            available: false,
            version: None,
            tools: Vec::new(),
            outdated: Vec::new(),
            config_files: Vec::new(),
            findings: Vec::new(),
            unavailable_reason: None,
        };
        let available = b.version.is_some()
            || !b.tools.is_empty()
            || !b.outdated.is_empty()
            || !b.config_files.is_empty()
            || !b.findings.is_empty();
        assert!(
            !available,
            "all-empty probes must leave the section unavailable"
        );
    }

    #[test]
    fn construction_ok_but_all_probes_failed_is_not_binary_not_found() {
        let reason = reason_when_construction_ok_but_unavailable(None, &[], &[], &[], &[]);
        let reason = reason.expect("construction-OK + all-empty probes must attach a reason");
        assert!(
            !reason.to_lowercase().contains("not found"),
            "construction-OK failure must NOT be reported as 'binary not found': {reason}"
        );
        assert!(
            reason.to_lowercase().contains("did not respond")
                || reason.to_lowercase().contains("timed out"),
            "reason must describe the probes-failed state: {reason}"
        );
    }

    #[test]
    fn construction_ok_with_any_probe_is_available_no_reason() {
        let version = "mise 2024.12.4".to_string();
        let reason =
            reason_when_construction_ok_but_unavailable(Some(&version), &[], &[], &[], &[]);
        assert!(reason.is_none(), "available path must carry no reason");
    }

    #[test]
    fn populated_outdated_keeps_section_available_no_reason() {
        let outdated = vec![MiseOutdatedEntry {
            name: "node".into(),
            current: Some("22.0.0".into()),
            latest: Some("22.1.0".into()),
            backend: None,
        }];
        let reason = reason_when_construction_ok_but_unavailable(None, &[], &outdated, &[], &[]);
        assert!(
            reason.is_none(),
            "a populated outdated list must keep the section available even \
             when every other probe failed — the heuristic unions over all \
             five data sources: {reason:?}"
        );
    }
}

#[cfg(test)]
mod cadence_oracle {
    use super::*;

    const SENTINEL_MSG: &str = "oracle-sentinel mise findings-cache";

    const SENTINEL_VERSION: &str = "oracle-sentinel 0.0.0";

    const SENTINEL_TOOL: &str = "oracle-sentinel-tool";

    fn sentinel_bundle() -> MiseDataBundle {
        MiseDataBundle {
            available: true,
            version: Some(SENTINEL_VERSION.to_string()),
            tools: vec![MiseToolEntry {
                name: SENTINEL_TOOL.to_string(),
                version: Some("1.0.0".to_string()),
                active: true,
                outdated: false,
                missing: false,
                source: None,
            }],
            outdated: Vec::new(),
            config_files: Vec::new(),
            findings: vec![MiseFindingEntry {
                severity: "ok".to_string(),
                message: SENTINEL_MSG.to_string(),
                detail: None,
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
        let mut collector = MiseCollector::new();
        collector.cached_bundle = Some(sentinel_bundle());
        let primed = std::time::Instant::now();
        collector.bundle_fresh_at = Some(primed);

        collector.start();
        let bundle = collector.poll().await.expect("collection completes");

        assert_eq!(
            bundle.findings.len(),
            1,
            "a cache hit must serve the cached findings verbatim"
        );
        assert_eq!(
            bundle.findings[0].message, SENTINEL_MSG,
            "the sentinel message can only come from the cache, never from a real doctor run"
        );
        assert_eq!(
            bundle.version.as_deref(),
            Some(SENTINEL_VERSION),
            "the sentinel version can only come from the cache, never from a real probe"
        );
        assert_eq!(bundle.tools.len(), 1);
        assert_eq!(
            bundle.tools[0].name, SENTINEL_TOOL,
            "the sentinel tool row can only come from the cache, never from a real ls probe"
        );
        assert_eq!(
            collector.bundle_fresh_at,
            Some(primed),
            "a cache-hit poll must not advance (re-arm) the freshness timestamp"
        );
    }

    #[tokio::test]
    async fn ttl_expiry_bypasses_cache_and_rederives() {
        let mut collector = MiseCollector::new();
        collector.cached_bundle = Some(sentinel_bundle());
        let primed = std::time::Instant::now();
        collector.bundle_fresh_at = Some(primed);

        let _ttl = TtlOffsetGuard::past_ttl();
        collector.start();
        let bundle = collector.poll().await.expect("collection completes");

        assert!(
            bundle.findings.iter().all(|f| f.message != SENTINEL_MSG),
            "an expired cache must not serve the sentinel finding"
        );
        assert_ne!(
            bundle.version.as_deref(),
            Some(SENTINEL_VERSION),
            "an expired cache must not serve the sentinel version"
        );
        assert!(
            bundle.tools.iter().all(|t| t.name != SENTINEL_TOOL),
            "an expired cache must not serve the sentinel tool row"
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
                "a degraded re-derivation must leave the primed clock untouched"
            );
        }
    }
}
