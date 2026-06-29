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
//! is a pure read of the host's `PATH`.
//!
//! ## What "live" means here
//!
//! Unlike most sibling sections (which shell out to a specific backend
//! daemon), this one scans the host `PATH` itself for a curated catalogue of
//! CLI tools toride cares about. `which::which(name)` resolves each binary
//! (trying every alias in a tool's `binaries` list — e.g. `fd` resolves to
//! `fdfind` on Debian), and a single `spawn_blocking` runs a bounded
//! `<binary> --version` / `-V` probe per found tool to capture the version
//! string. The data is genuinely live: it reflects the actual machine.
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
//! `which::which` and `std::process::Command` are synchronous. ALL of this
//! work runs inside a single [`tokio::task::spawn_blocking`] so the tokio
//! worker is never stalled — mirroring the harden / fail2ban / ufw-kit pattern.

use std::time::Duration;

use tokio::sync::oneshot;

use crate::tools_convert;
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
#[expect(
    clippy::duration_suboptimal_units,
    reason = "stable std lacks from_mins"
)]
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
        // The catalogue scan is entirely synchronous (`which` + `Command`),
        // so it runs inside ONE spawn_blocking owned by the spawned task body
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

/// Collect the installed-tools catalogue by scanning the host PATH.
///
/// All work runs on the blocking thread pool inside a single
/// `spawn_blocking`: `which::which` resolves each binary (trying every
/// alias), and a bounded `Command::new(binary).arg("--version")` (or `-V`)
/// probe captures the version string. The findings (missing-expected-tool
/// warnings) are reused from the cache when fresh.
///
/// `use_cache` / `cached_findings` mirror the harden / mise findings cache:
/// when the cache is fresh the findings are taken verbatim and the version
/// probes are still run (the catalogue is short and `which` is cheap), but
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
    // Run the entire catalogue scan in ONE spawn_blocking. `which` and
    // `std::process::Command` are synchronous, so this keeps every probe off
    // the tokio worker (mirroring the harden / fail2ban / ufw-kit pattern).
    let result = tokio::task::spawn_blocking(move || {
        let catalogue = tools_convert::catalogue();

        let mut tools: Vec<ToolEntry> = Vec::with_capacity(catalogue.len());
        let mut installed_count = 0usize;

        for spec in &catalogue {
            // Resolve the binary via which, trying each alias. A found alias
            // is recorded so the version probe and path display match what
            // actually resolved (e.g. `fd` -> `fdfind` on Debian).
            let resolved = resolve_binary(&spec.binaries);
            let (installed, path, version) = match resolved {
                Some((name, path)) => {
                    installed_count += 1;
                    let version = probe_version(&name, &path);
                    (true, Some(path), version)
                }
                None => (false, None, None),
            };
            tools.push(ToolEntry {
                name: spec.name.to_string(),
                category: spec.category.to_string(),
                installed,
                version,
                path,
                expected: spec.expected,
            });
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

/// Resolve a tool to its first found alias via `which::which`.
///
/// Tries each binary name in order (e.g. `["fd", "fdfind"]`) and returns the
/// first one found along with its resolved path. `None` if no alias resolved.
/// Errors from `which` (a binary simply not on PATH is the common case) are
/// logged at `debug` — not a warning — and degrade to `None`.
fn resolve_binary(aliases: &[String]) -> Option<(String, String)> {
    for alias in aliases {
        match which::which(alias) {
            Ok(path) => {
                let path_str = path.to_string_lossy().to_string();
                if path_str.is_empty() {
                    tracing::warn!(
                        "tools: which resolved '{alias}' to an empty path — skipping alias"
                    );
                    continue;
                }
                return Some((alias.clone(), path_str));
            }
            Err(e) => {
                // A missing binary is the expected/common case (not every host
                // has every tool); log at debug so the log isn't noisy.
                tracing::debug!("tools: which('{alias}') failed: {e}");
            }
        }
    }
    None
}

/// Probe a binary's version by running `<binary> --version` or `-V` under a
/// bounded timeout, capturing the first non-empty stdout line as the version.
///
/// `found-but-no-version` is fine — some binaries reject both flags, exit
/// non-zero, or print to stderr; in all those cases `None` is returned and the
/// tool is still recorded as installed (the `which` resolution is the source
/// of truth for presence). Never panics: every `Command` failure is mapped to
/// `None`.
fn probe_version(binary: &str, path: &str) -> Option<String> {
    // Try `--version` first, then `-V` (covers the common GNU/BSD split:
    // GNU tools accept `--version`, BSD/busybox/macOS tools often only `-V`).
    for arg in ["--version", "-V"] {
        match run_version_command(path, arg) {
            Ok(Some(line)) if !line.trim().is_empty() => {
                return Some(line.trim().to_string());
            }
            Ok(_) => {}
            Err(e) => {
                tracing::debug!("tools: version probe '{binary}' {arg}: {e}");
            }
        }
    }
    None
}

/// Run `<path> <arg>` under an ~800ms timeout, returning the first non-empty
/// stdout line (trimmed) on success. `Ok(None)` means the command ran but
/// produced no usable output; `Err` means spawn/wait failed or it timed out.
fn run_version_command(path: &str, arg: &str) -> std::io::Result<Option<String>> {
    let child = std::process::Command::new(path)
        .arg(arg)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .stdin(std::process::Stdio::null())
        .spawn()?;
    // Block on the child under a timeout. We are inside spawn_blocking so a
    // synchronous wait is fine; the timeout caps any hung binary (e.g. one
    // that reads stdin despite /dev/null) at ~800ms.
    let output = wait_with_timeout(child, VERSION_TIMEOUT)?;
    if !output.status.success() {
        return Ok(None);
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout
        .lines()
        .find(|l| !l.trim().is_empty())
        .map(String::from))
}

/// Per-version-probe timeout. Generous for a fast `--version` (sub-50ms) but
/// short enough that a hung binary cannot stall the scan.
const VERSION_TIMEOUT: Duration = Duration::from_millis(800);

/// Wait for a spawned child under a timeout, killing it if it overruns.
///
/// Synchronous (we are on the blocking pool). On timeout the child is killed
/// and reaped so no zombie lingers, then `Err` is returned so the caller maps
/// the probe to `None`.
fn wait_with_timeout(
    mut child: std::process::Child,
    timeout: Duration,
) -> std::io::Result<std::process::Output> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Some(_status) = child.try_wait()? {
            return child.wait_with_output();
        }
        if std::time::Instant::now() >= deadline {
            // Kill + reap so the child does not become a zombie.
            let _ = child.kill();
            let _ = child.wait();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("version probe exceeded {timeout:?}"),
            ));
        }
        // Short sleep to avoid a tight spin; we are on the blocking
        // pool so std::thread::sleep is appropriate here.
        std::thread::sleep(Duration::from_millis(20));
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
        // The catalogue scan resolves ~30 binaries; give it time. `which` is
        // fast and version probes are bounded at 800ms each.
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

    #[test]
    fn resolve_binary_finds_a_known_alias() {
        // `which` and `cargo` are guaranteed on the dev/CI host that runs
        // tests (they are how the test binary itself was built). Picking one
        // present in the catalogue makes this assertion stable across hosts.
        let aliases = vec!["which".to_string(), "cargo".to_string()];
        let resolved = resolve_binary(&aliases);
        // At least one of these MUST be on PATH on a host that compiled toride.
        assert!(
            resolved.is_some(),
            "expected at least one of [which, cargo] to resolve on PATH"
        );
    }

    #[test]
    fn resolve_binary_returns_none_for_bogus_name() {
        let resolved = resolve_binary(&["this-binary-does-not-exist-toride-xyz".to_string()]);
        assert!(resolved.is_none());
    }
}
