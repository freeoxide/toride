//! Async installed-tools catalogue collection (LIVE READ-ONLY).
//!
//! [`ToolsCollector`] manages background collection of the host's installed CLI
//! tools via a tokio oneshot channel, following the same pattern as
//! [`HardenCollector`](crate::toride_harden_data::HardenCollector),
//! [`TailscaleCollector`](crate::toride_tailscale_data::TailscaleCollector),
//! and (the closest analogue) [`MiseCollector`](crate::toride_mise_data::MiseCollector).
//!
//! This is a read-only integration: there are no write operations, no
//! optimistic updates, no cooldown gate, and no loading spinner. Every probe
//! is a pure read of the host.
//!
//! ## What "live" means here
//!
//! Unlike most sibling sections (which shell out to a specific backend
//! daemon), this one scans the host itself for a curated catalogue of CLI
//! tools toride cares about. Every catalogue alias is classified through
//! [`toride_installer::Detector`](toride_installer::Detector): the real
//! `$PATH` is probed first (what a shell would actually execute — trying
//! every alias in a tool's `binaries` list, e.g. `fd` resolves to `fdfind` on
//! Debian), then the installer's managed location (`~/.local/bin/<alias>`),
//! so a tool installed off-`$PATH` still surfaces as installed. A single
//! `spawn_blocking` runs a bounded `<binary> --version` / `-V` probe per
//! found tool through the runner and keeps the trimmed first non-empty stdout
//! line as the version string. The probes carry a null stdin (the Detector
//! wires each probe spec with `stdin_null`, exactly like the replaced
//! hand-rolled probe's `Stdio::null()`), so a catalogue binary that reads
//! stdin sees EOF and answers instead of blocking on — or consuming — this
//! TUI's terminal. The data is genuinely live: it reflects the actual
//! machine.
//!
//! ## Doctor findings cache
//!
//! The catalogue scan resolves ~30 binaries and runs a version probe on each
//! found tool, and a tool's presence changes slowly, so the findings (one
//! `tools.missing.<name>` warning per MISSING expected tool) are cached for
//! 60s — exactly like the harden / mise / fail2ban findings caches. The whole
//! scan is treated as the "doctor": `use_cache` reuses the cached findings and
//! skips re-probing; the tool list itself is still re-resolved each poll
//! (cheap) so a freshly-installed tool surfaces quickly.
//!
//! ## Blocking
//!
//! Binary discovery and the version probes are synchronous subprocess work.
//! ALL of this work runs inside a single [`tokio::task::spawn_blocking`] so
//! the tokio worker is never stalled — mirroring the harden / fail2ban /
//! ufw-kit pattern.
//!
//! # Name collision
//!
//! `toride_mise::ToolStatus` is a different type (the `mise ls --json`
//! listing, used by [`crate::toride_mise_convert`]); this module only ever
//! touches the installer's, kept fully qualified at every use.

use std::time::Duration;

use tokio::sync::oneshot;
use toride_installer::{Detector, Tool};

use crate::tools_convert::{self, ToolSpec};
use crate::ui::screens::tools::{FindingEntry, ToolEntry};

/// Aggregated installed-tools data for the read-only section.
#[derive(Clone, Debug)]
pub struct ToolsDataBundle {
    /// Whether the PATH scan ran at all. `false` is reserved for the panic
    /// case (a `tokio::spawn` `JoinError`) — a host where every catalogue entry
    /// is missing still yields `available == true` so the operator SEES the
    /// findings (every expected tool absent) rather than a blank panel.
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
    /// Human-readable reason the backend was unreachable, populated ONLY when
    /// `available == false` (collection-task panic). `None` otherwise —
    /// notably also `None` for a freshly-constructed empty bundle before any
    /// collection has run. Surfaced to the UI so the degraded panel can show
    /// what actually went wrong instead of guessing.
    pub unavailable_reason: Option<String>,
}

// ── Collector ───────────────────────────────────────────────────────────────

/// Manages periodic async collection of the installed-tools catalogue.
///
/// Mirrors [`HardenCollector`](crate::toride_harden_data::HardenCollector): a
/// oneshot channel for the in-flight result, plus a 60s TTL cache for the
/// expensive findings (missing-expected-tool warnings) so they are not
/// re-derived on every 2s refresh tick.
pub struct ToolsCollector {
    /// Carries the bundle AND whether the cached findings were reused for this
    /// poll. The freshness timestamp must only be advanced when the scan was
    /// actually re-run (`used_cache == false`); otherwise every cache-hit poll
    /// would reset the TTL clock with the SAME (already-cached) findings and
    /// the cache would never expire for the lifetime of the app.
    rx: Option<oneshot::Receiver<(ToolsDataBundle, bool)>>,
    /// Cached doctor findings (missing-expected-tool warnings) from the last
    /// collection.
    cached_findings: Option<Vec<FindingEntry>>,
    /// When the findings cache was last refreshed.
    findings_fresh_at: Option<std::time::Instant>,
}

/// How long to keep cached findings before re-running the catalogue scan.
const FINDINGS_TTL: Duration = Duration::from_secs(60);

impl ToolsCollector {
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
    /// findings instead of re-probing every binary's version.
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
        // The catalogue scan is entirely synchronous (PATH discovery plus
        // version subprocesses), so it runs inside ONE spawn_blocking owned
        // by the spawned task body
        // — mirroring the harden / fail2ban / ufw-kit pattern. The inner task
        // body is itself spawned and awaited so a JoinError (panic inside
        // `collect_real_tools`) is matched here and surfaced as a degraded
        // `available == false` bundle with a reason — mirroring the
        // spawn_blocking JoinError path in the sibling collectors. Without
        // this wrap a panic would drop `tx`, `rx.await` would return `Err`,
        // and poll() would map that to `None`, leaving the dashboard showing
        // stale last-good data indefinitely with no degraded-state signal.
        let handle =
            tokio::spawn(async move { collect_real_tools(use_cache, cached_findings).await });
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
    /// Returns `Some(bundle)` if the collection completed, `None` if still
    /// pending or if the collection failed. On success the cached findings are
    /// updated to the freshly-returned findings, but the freshness timestamp is
    /// only advanced when the scan was actually re-run (not on a cache-hit
    /// poll) — otherwise the 60s TTL would be re-armed forever with the same
    /// cached data on every 2s refresh.
    pub async fn poll(&mut self) -> Option<ToolsDataBundle> {
        match &mut self.rx {
            Some(rx) => {
                let result = rx.await.ok();
                if let Some((ref bundle, used_cache)) = result {
                    self.cached_findings = Some(bundle.findings.clone());
                    // Only advance the freshness clock when the scan was
                    // actually re-run. On a cache-hit poll the findings are
                    // the SAME data we already cached, so resetting the TTL
                    // here would let the cache live forever as long as the 2s
                    // refresh tick keeps firing inside the TTL window.
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

    /// Invalidate the findings cache so the next collection re-runs the scan.
    #[allow(dead_code)]
    pub fn invalidate_findings_cache(&mut self) {
        self.cached_findings = None;
        self.findings_fresh_at = None;
    }
}

impl Default for ToolsCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Real data collection ────────────────────────────────────────────────────

/// Collect the installed-tools catalogue by scanning the host for every
/// catalogue entry.
///
/// All work runs on the blocking thread pool inside a single
/// `spawn_blocking`: each catalogue alias is classified through a
/// [`Detector`](toride_installer::Detector) (`$PATH` first, then the managed
/// `~/.local/bin` location — the first resolving alias wins), and the found
/// binary is probed under [`VERSION_TIMEOUT`] (`--version`, falling back to
/// `-V`) for its version string. The findings (missing-expected-tool
/// warnings) are reused from the cache when fresh.
///
/// `use_cache` / `cached_findings` mirror the harden / mise findings cache:
/// when the cache is fresh the findings are taken verbatim and the version
/// probes are still run (the catalogue is short and discovery is cheap), but
/// the missing-tool warnings are not re-derived.
///
/// On ANY panic (`JoinError` from the outer `tokio::spawn`) returns
/// [`empty_bundle_with_reason`] with `available = false`.
///
/// Returns `(bundle, used_cache)` where `used_cache` records whether the
/// findings were actually taken from the cache on a successful collection.
async fn collect_real_tools(
    use_cache: bool,
    cached_findings: Option<Vec<FindingEntry>>,
) -> (ToolsDataBundle, bool) {
    // Run the entire catalogue scan in ONE spawn_blocking. Binary discovery
    // and the version probes are synchronous subprocess work, so this keeps
    // every probe off the tokio worker (mirroring the harden / fail2ban /
    // ufw-kit pattern).
    let result = tokio::task::spawn_blocking(move || {
        let catalogue = tools_convert::catalogue();

        // One detector drives the whole sweep: it is cheap and `Clone`, and
        // the 800ms per-probe cap ([`VERSION_TIMEOUT`]) preserves the
        // hand-rolled probe's worst-case bound per found binary.
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

        // Findings: one warning per MISSING expected tool. Reused from the
        // cache when fresh (`use_cache`), otherwise re-derived here.
        let findings = if use_cache {
            cached_findings.unwrap_or_default()
        } else {
            tools_convert::convert_findings(&tools)
        };

        // Availability heuristic: the scan ALWAYS ran (we got here), so the
        // section is available. Only a task panic flips this to false, and
        // that case never reaches this code path: the panic is caught as a
        // JoinError in `start()`'s outer spawn, which returns
        // [`empty_bundle_with_reason`] instead of calling this function.
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
        Ok(bundle) => (bundle, use_cache),
        Err(e) => {
            tracing::warn!("tools collection task panicked: {e}");
            (
                empty_bundle_with_reason(format!("tools data collection panicked: {e}")),
                false,
            )
        }
    }
}

/// Per-version-probe timeout fed to the
/// [`Detector`](toride_installer::Detector). Generous for a fast `--version`
/// (sub-50ms) but short enough that a hung binary cannot stall the scan —
/// the same cap the replaced hand-rolled probe enforced.
const VERSION_TIMEOUT: Duration = Duration::from_millis(800);

/// The detection descriptor for one catalogue alias.
///
/// `Tool`'s defaults are exactly the catalogue's detection semantics:
/// `ArtifactKind::Binary`, `Checksum::None` (detection never downloads), and
/// `default_install_dir: None` — the managed tier is therefore
/// `~/.local/bin/<alias>`, the installer's standard location, which is what
/// lets a tool installed off-`$PATH` still surface. Built as a struct literal
/// (an officially supported construction per `Tool`'s docs) because
/// `ToolBuilder::build`'s validation can only reject a tarball descriptor
/// without a `bin_path` — the `Result` cannot fail for a `Binary` descriptor.
fn catalogue_tool(name: &str, alias: &str) -> Tool {
    Tool {
        name: name.to_string(),
        bin_name: alias.to_string(),
        ..Tool::default()
    }
}

/// Resolve one catalogue spec to its UI row by trying every alias in order.
///
/// The first alias the [`Detector`](toride_installer::Detector) classifies as
/// installed (on `$PATH` or at the managed location) wins — e.g. `fd`
/// resolves to `fdfind` on Debian — matching the replaced `which`-based
/// resolver's first-hit semantics. A miss on one alias is the expected common
/// case and is logged at `debug`, never `warn`. When no alias resolves, a
/// missing row ([`missing_entry`]) is returned: presence is the path probe's
/// verdict, never the version probe's.
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

/// Map a detection status to the UI row for `spec`; `None` when the tool is
/// not installed (`ToolStatus::path` is `None` iff `NotInstalled`).
///
/// `version` carries [`toride_installer::ToolVersion::line`] verbatim — the
/// trimmed first non-empty `--version`/`-V` stdout line, byte-identical to
/// what the replaced hand-rolled probe returned. `path` is the resolved
/// executable path as a string, identical to the old
/// `to_string_lossy` rendering for the UTF-8 paths detection can produce.
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

/// The missing-tool row for `spec`: not installed, no version, no path.
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

/// Empty bundle used when the collection task panicked (`tokio::spawn`
/// `JoinError`) — mirrors [`harden_data::empty_bundle`] and the sibling
/// collectors. `available = false` signals the UI to render the degraded
/// panel; no reason is attached because none is known at this point (the
/// `JoinError` reason is added by [`empty_bundle_with_reason`]).
///
/// [`harden_data::empty_bundle`]: crate::toride_harden_data::empty_bundle
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

/// Empty bundle carrying the reason collection failed. Used when the spawned
/// collection task panicked (`JoinError`) — the reason string is rendered by the
/// UI's degraded panel so the operator sees what actually went wrong, mirroring
/// the `spawn_blocking` `JoinError` path in harden / fail2ban / cloud / etc.
fn empty_bundle_with_reason(reason: String) -> ToolsDataBundle {
    let mut b = empty_bundle();
    b.unavailable_reason = Some(reason);
    b
}

// ── Tests ───────────────────────────────────────────────────────────────────

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
        collector.start(); // no-op, does not replace the receiver
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
        // The catalogue scan resolves ~30 binaries; give it time. Discovery
        // is fast and version probes are bounded at 800ms each.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let _ = collector.poll().await;
        assert!(!collector.is_pending(), "poll should clear pending state");
    }

    #[tokio::test]
    async fn poll_returns_bundle_after_collection() {
        // On any host the collector must return Some(bundle) after start() +
        // enough time. The scan always runs (which is cheap), so available is
        // true and the catalogue is populated.
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
        // After a successful poll the cache is populated (even if to an empty
        // Vec on a host where every expected tool is installed).
        assert!(collector.cached_findings.is_some());
        assert!(collector.findings_fresh_at.is_some());
    }

    #[test]
    fn invalidate_findings_cache_clears_it() {
        let mut collector = ToolsCollector::new();
        collector.cached_findings = Some(Vec::new());
        collector.findings_fresh_at = Some(std::time::Instant::now());
        collector.invalidate_findings_cache();
        assert!(collector.cached_findings.is_none());
        assert!(collector.findings_fresh_at.is_none());
    }

    /// A catalogue spec for `name` trying `aliases` in order — the tests'
    /// stand-in for a `tools_convert::ToolSpec` row.
    fn fixture_spec(name: &'static str, aliases: &[&str]) -> ToolSpec {
        ToolSpec {
            name,
            category: "Shell/System",
            binaries: aliases.iter().map(|a| (*a).to_string()).collect(),
            expected: true,
        }
    }

    /// The detector construction the production collector uses (800ms
    /// per-probe cap) — the tests must exercise the same sweep as the app.
    fn production_detector() -> Detector {
        Detector::builder().probe_timeout(VERSION_TIMEOUT).build()
    }

    /// A bin name no real `$PATH` or `~/.local/bin` carries.
    const BOGUS: &str = "this-binary-does-not-exist-toride-xyz";

    #[test]
    fn detect_entry_finds_a_known_alias_environmental() {
        // `which` and `cargo` are guaranteed on the dev/CI host that runs
        // tests (they are how the test binary itself was built). Adapted from
        // the old `resolve_binary_finds_a_known_alias`: at least one alias in
        // the list must classify as installed.
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
        // Adapted from the old `resolve_binary_returns_none_for_bogus_name`:
        // an absent alias yields the missing row — no version, no path —
        // while `expected` (catalogue data) is preserved.
        let entry = detect_entry(&fixture_spec(BOGUS, &[BOGUS]), &production_detector());
        assert!(!entry.installed);
        assert_eq!(entry.version, None);
        assert_eq!(entry.path, None);
        assert!(entry.expected);
    }

    #[test]
    fn detect_entry_tries_aliases_in_order_until_one_resolves() {
        // The first alias is absent everywhere; the second is guaranteed on
        // the dev/CI host (it built this test binary). Proves iteration
        // continues past a miss and stops at the first resolving alias — the
        // first-hit semantics `fd` -> `fdfind` on Debian relies on.
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
        // Parity with the replaced hand-rolled probe: the row's version is
        // the trimmed first non-empty `--version` stdout line, verbatim. The
        // strict FakeRunner supplies the probe output; the tempdir stands in
        // for the managed install dir so the fixture is hermetic.
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
        // `timeout` is excluded from exact matching (runtime policy), but the
        // null-stdin wiring IS compared, so this spec must mirror what the
        // Detector's `probe_version` issues.
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
        // The `None` arm of the mapping is what drives `detect_entry`'s
        // alias loop and, once aliases are exhausted, the missing row.
        let status = toride_installer::ToolStatus::NotInstalled;
        assert!(entry_from_status(&fixture_spec("t", &["t"]), &status).is_none());
    }

    #[test]
    fn detect_entry_keeps_presence_when_probe_degrades() {
        // Hermetic: detect classifies the managed fixture file below as
        // installed, and the strict FakeRunner has NO responses, so both
        // version probes error. The row built from that status must stay
        // installed with no version — presence is the path probe's verdict,
        // never the version probe's.
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

        // detect_entry builds descriptors without an install dir, so drive
        // the same detector + mapping pair the collector uses, against the
        // fixture descriptor.
        let detector = Detector::with_runner(Arc::new(FakeRunner::new().strict()));
        let status = detector.detect(&tool);
        let entry = entry_from_status(&fixture_spec("paritytool", &[]), &status)
            .expect("the managed fixture is installed");

        assert!(entry.installed);
        assert_eq!(entry.version, None);
    }

    /// ENVIRONMENTAL smoke test: run the WHOLE production catalogue through
    /// the production detector on the real host. Pins the row contract the
    /// UI relies on — one row per catalogue entry, in catalogue order, with
    /// `installed ⇔ path` and no version on a missing row.
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
