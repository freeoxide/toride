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
//! ## Whole-sweep cache
//!
//! The catalogue scan resolves ~30 binaries and runs a version probe on each
//! found tool, and a tool's presence changes slowly, so the ENTIRE sweep —
//! tool rows, counts, and the findings (one `tools.missing.<name>` warning per
//! MISSING expected tool) — is cached for 60s, mirroring the proxy
//! collector's whole-report cache: a cache hit performs zero `$PATH` scans and
//! zero version-probe subprocesses. Freshness caveat (deliberate cadence
//! decision): a freshly installed or removed tool surfaces up to 60s late.
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
/// Mirrors the proxy collector's whole-report cache: a oneshot channel for the
/// in-flight result, plus a 60s TTL cache over the ENTIRE sweep (tool rows,
/// counts, and findings) so neither the per-alias `$PATH` scans nor the
/// version-probe subprocesses re-run on every 2s refresh tick.
pub struct ToolsCollector {
    /// Carries the bundle AND whether the cached bundle was reused for this
    /// poll. The freshness timestamp must only be advanced when the sweep was
    /// actually re-run (`used_cache == false`); otherwise every cache-hit poll
    /// would reset the TTL clock with the SAME (already-cached) bundle and
    /// the cache would never expire for the lifetime of the app.
    rx: Option<oneshot::Receiver<(ToolsDataBundle, bool)>>,
    /// Cached bundle (tool rows + counts + findings) from the last sweep.
    cached_bundle: Option<ToolsDataBundle>,
    /// When the bundle cache was last refreshed.
    bundle_fresh_at: Option<std::time::Instant>,
}

/// How long to keep the cached bundle before re-running the catalogue sweep.
///
/// Deliberate freshness semantics: a freshly installed or removed tool
/// surfaces up to this TTL late (see the module docs).
const SWEEP_TTL: Duration = Duration::from_secs(60);

/// Whether the sweep-cache TTL has already elapsed for a cache that was
/// last refreshed at `fresh_at`.
///
/// Round-0 instrumentation seam, ZERO behavior change: outside `cfg(test)`
/// this is exactly the negation of the `t.elapsed() < SWEEP_TTL` check
/// `start` always evaluated inline. Under `cfg(test)` the thread-local
/// [`TTL_TEST_OFFSET_MS`] is folded into the elapsed time so the cadence
/// oracles can observe TTL expiry deterministically — no 60s sleeps and no
/// dependence on host uptime (the `Instant::now() - TTL` backdating trick
/// fails on a machine whose monotonic clock started less than the TTL ago).
/// The offset is thread-local, so concurrently running tests on other cargo
/// test threads cannot perturb this module's cadence.
fn ttl_expired(fresh_at: std::time::Instant) -> bool {
    let elapsed = fresh_at.elapsed();
    #[cfg(test)]
    let elapsed = elapsed + Duration::from_millis(TTL_TEST_OFFSET_MS.with(std::cell::Cell::get));
    elapsed >= SWEEP_TTL
}

// Extra milliseconds folded into `ttl_expired`'s elapsed time by the
// cadence oracles. Test-only: zero unless a test on this thread advances it
// (and resets it on drop), and not compiled at all outside `cfg(test)`.
// (Plain comments: rustdoc does not generate documentation for macro
// invocations, so a doc comment here warns as unused.)
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
    /// If a collection is already in-flight, this is a no-op. The 60s
    /// whole-sweep cache is consulted: when fresh, the spawned task serves the
    /// cached bundle verbatim — no `$PATH` scans, no version-probe
    /// subprocesses.
    pub fn start(&mut self) {
        if self.rx.is_some() {
            return;
        }
        let (tx, rx) = oneshot::channel();
        let use_cache =
            self.cached_bundle.is_some() && self.bundle_fresh_at.is_some_and(|t| !ttl_expired(t));
        let cached_bundle = self.cached_bundle.clone();
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
    /// Returns `Some(bundle)` if the collection completed, `None` if still
    /// pending or if the collection failed. On a real (available) bundle the
    /// whole bundle is cached, but the freshness timestamp is only advanced
    /// when the sweep was actually re-run (not on a cache-hit poll) —
    /// otherwise the 60s TTL would be re-armed forever with the same cached
    /// data on every 2s refresh. A degraded bundle (a panic caught by the
    /// outer spawn) is never cached, so the next refresh re-runs the sweep
    /// instead of pinning an empty panel for the TTL.
    pub async fn poll(&mut self) -> Option<ToolsDataBundle> {
        match &mut self.rx {
            Some(rx) => {
                let result = rx.await.ok();
                if let Some((ref bundle, used_cache)) = result
                    && bundle.available
                {
                    self.cached_bundle = Some(bundle.clone());
                    // Only advance the freshness clock when the sweep was
                    // actually re-run. On a cache-hit poll the bundle is
                    // the SAME data we already cached, so resetting the TTL
                    // here would let the cache live forever as long as the
                    // 2s refresh tick keeps firing inside the TTL window.
                    if !used_cache {
                        self.bundle_fresh_at = Some(std::time::Instant::now());
                    }
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

// ── Real data collection ────────────────────────────────────────────────────

/// Collect the installed-tools catalogue by scanning the host for every
/// catalogue entry.
///
/// When `use_cache` is set and a cached bundle is present, the cached bundle
/// is served verbatim and NOTHING runs — no `$PATH` scans, no version-probe
/// subprocesses — mirroring the proxy collector's whole-report cache arm.
///
/// Otherwise all work runs on the blocking thread pool inside a single
/// `spawn_blocking`: each catalogue alias is classified through a
/// [`Detector`](toride_installer::Detector) (`$PATH` first, then the managed
/// `~/.local/bin` location — the first resolving alias wins), and the found
/// binary is probed under [`VERSION_TIMEOUT`] (`--version`, falling back to
/// `-V`) for its version string.
///
/// On ANY panic (`JoinError` from the outer `tokio::spawn`) returns
/// [`empty_bundle_with_reason`] with `available = false`.
///
/// Returns `(bundle, used_cache)` where `used_cache` records whether the
/// bundle was served verbatim from the cache.
async fn collect_real_tools(
    use_cache: bool,
    cached_bundle: Option<ToolsDataBundle>,
) -> (ToolsDataBundle, bool) {
    // Cache hit: serve the whole bundle verbatim. The sweep (per-alias PATH
    // scans + version-probe subprocesses) is skipped entirely.
    if use_cache && let Some(bundle) = cached_bundle {
        return (bundle, true);
    }

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

        // Findings: one warning per MISSING expected tool, derived from the
        // fresh rows. (A cache hit never reaches this point — it returned the
        // whole bundle verbatim above.)
        let findings = tools_convert::convert_findings(&tools);

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
        // Reaching this point means the sweep DID run (a cache hit returned
        // above), so the truthful provenance is "not from cache" — even for
        // the defensive use_cache-with-empty-cache fall-through.
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
        // After a successful poll the whole-bundle cache is populated (even
        // with an empty findings Vec on a host where every expected tool is
        // installed).
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

    /// An available bundle shape for seeding the cache in unit tests (the
    /// `empty_bundle` helpers all set `available == false`, which `poll()`
    /// would refuse to cache).
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

// ── Cadence oracles (round 0, extended round 1) ──────────────────────────────

/// Cadence oracles for the 60s whole-sweep cache.
///
/// Round 1 (F05) extended these from a findings-only cache to the whole
/// bundle: sentinel data now covers the tool ROWS as well as the findings.
/// The sentinel tool name and finding id are strings no real catalogue sweep
/// can produce, so "the bundle came back verbatim" proves the sweep — per
/// alias `$PATH` scans AND version-probe subprocesses — did not run at all
/// (a real sweep always emits the fixed catalogue's row names and real
/// `tools.missing.<name>` ids, never the sentinels).
///
/// The lifecycle goes through the REAL `start()` / spawned collection — the
/// same path the dashboard's 2s refresh tick drives. The ASSERTED state
/// (bundle provenance, freshness bookkeeping) is deterministic on any host.
///
/// No spawn-counting seam is added at this layer: `collect_real_tools`
/// hardcodes `Detector::builder()`, and threading an injectable runner
/// through `start()` would change production signatures — the sentinel
/// bundle already answers "did the sweep run?".
#[cfg(test)]
mod cadence_oracle {
    use super::*;

    /// Sentinel id no real catalogue finding can carry.
    const SENTINEL_ID: &str = "oracle-sentinel.tools.findings-cache";

    /// Sentinel tool name no catalogue row can carry (the catalogue is a
    /// fixed in-code list that never contains this string).
    const SENTINEL_TOOL: &str = "oracle-sentinel-tools-row";

    /// A sentinel bundle: one tool row + one finding + counts no real sweep
    /// can derive, with `available == true` so `poll()` caches it.
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

    /// Advances this thread's TTL test clock past the TTL, resetting it on
    /// drop so a failing assertion cannot leak a cranked clock into a later
    /// test scheduled on the same reused cargo-test thread.
    struct TtlOffsetGuard;

    impl TtlOffsetGuard {
        /// Set the thread-local offset to `SWEEP_TTL` + 10s.
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

    /// ORACLE: a fresh cache serves the WHOLE cached bundle verbatim on the
    /// next collection — the sweep (PATH scans + version probes) does NOT
    /// run — and the freshness timestamp is NOT re-armed by the cache-hit
    /// poll.
    #[tokio::test]
    async fn cache_hit_returns_cached_bundle_without_resweeping() {
        let mut collector = ToolsCollector::new();
        collector.cached_bundle = Some(sentinel_bundle());
        let primed = std::time::Instant::now();
        collector.bundle_fresh_at = Some(primed);

        collector.start();
        let bundle = collector.poll().await.expect("collection completes");

        // Cached-vs-fresh parity: every sentinel field comes back verbatim.
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
        // A real sweep re-derives total_count from the fixed catalogue; the
        // sentinel count of 1 proves zero rows were re-scanned.
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

    /// ORACLE: once the TTL has elapsed the cache is bypassed — no sentinel
    /// survives in rows OR findings — and the freshness timestamp advances
    /// past its primed value after the real re-derivation.
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
        // The sweep ALWAYS yields an available bundle, and poll() advances
        // the clock for every available !used_cache result, so the
        // re-derivation must have re-armed it.
        assert!(
            collector.bundle_fresh_at.is_some_and(|t| t > primed),
            "an expired cache must be re-derived and the freshness clock advanced"
        );
    }
}
