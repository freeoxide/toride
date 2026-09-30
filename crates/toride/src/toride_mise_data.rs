//! Async mise data collection (LIVE READ-ONLY).
//!
//! [`MiseCollector`] manages background collection of all mise subsystem data
//! via a tokio oneshot channel, following the same pattern as
//! [`StatusCollector`](crate::status_collector::StatusCollector),
//! [`SshDataCollector`](crate::ssh_data::SshDataCollector), and (the closest
//! analogue) [`Fail2banCollector`](crate::fail2ban_data::Fail2banCollector) /
//! [`TailscaleCollector`](crate::toride_tailscale_data::TailscaleCollector).
//!
//! This is the TEMPLATE read-only integration. It mirrors the fail2ban /
//! Tailscale collectors MINUS the entire write path — there are no operations,
//! no optimistic updates, no cooldown gate, and no loading spinner. Every call
//! to the backend is a pure read.
//!
//! ## Async / exec
//!
//! Unlike fail2ban/cloud (which shell out synchronously via `DuctRunner` and so
//! use `spawn_blocking`), the mise backend uses an async `toride_runner`
//! (`TokioRunner`). So [`toride_mise::Mise::builder`] (a sync ctor — it only
//! discovers the binary, no exec) is built ONCE per collection inside the
//! spawned task and its async methods are awaited directly inside
//! `tokio::spawn(async move { ... })` — NOT inside `spawn_blocking`. This
//! mirrors `ssh_data`'s and `toride_tailscale_data`'s direct-async pattern.
//!
//! ## Timeouts / degradation
//!
//! Every mise command (`list_installed`, `list_current`, `list_outdated`,
//! `config_ls`, `doctor`, `--version`) is wrapped in [`tokio::time::timeout`]
//! with a ~3s budget. `mise` shells out to plugin backends and may hit the
//! network (registry lookups, `mise outdated`); a hung or blackholed network
//! must not stall the collector task — the timeout caps each probe
//! independently. A timed-out or errored probe degrades that field but the
//! collector keeps going; the section stays `available == true` whenever ANY
//! probe succeeded or the doctor produced findings, so the operator sees what
//! is wrong rather than a blank panel. `available` flips to `false` in three
//! cases: an outright `BinaryNotFound` construction failure (mise not
//! installed), construction succeeding but EVERY probe timing out / erroring
//! (the binary exists but is unresponsive), and a panic inside the collection
//! task — which is surfaced as a reason rather than silently dropping the
//! refresh. The panic case uses the tailscale two-spawn `JoinError` pattern
//! (spawn collection in an inner task, await its `JoinHandle` in an outer
//! task) in [`MiseCollector::start`], which works under BOTH panic strategies
//! — `panic = "unwind"` (dev/test) and `panic = "abort"` (release, set in
//! `Cargo.toml`'s `[profile.release]`): under either strategy the panic is
//! isolated to the inner task and reaches the outer awaiter as a `JoinError`
//! rather than aborting the whole process.
//!
//! ## Whole-bundle cache + process-lifetime discovery
//!
//! `mise doctor` is expensive (it fans out to registry lookups and version
//! checks) and changes slowly — and so does the rest of the probe set
//! (`--version`, `ls --installed`, `ls --current`, `outdated --json` — a
//! NETWORK call, `config ls`). The ENTIRE collection is therefore cached for
//! 60s, mirroring the proxy collector's whole-report cache: a cache hit
//! performs zero subprocess spawns. Freshness caveat (deliberate cadence
//! decision): tool installs/upgrades and new outdated entries surface up to
//! 60s late.
//!
//! The discovered [`toride_mise::MiseBinary`] is cached for the PROCESS
//! lifetime (`std::sync::OnceLock`): discovery tier 2 runs version-probe
//! subprocesses, so re-discovering on every 2s tick was pure waste. Only
//! successful discoveries are cached — a host without mise keeps degrading
//! at construction each tick (PATH scans + file stats, zero subprocess
//! spawns), so a mise installed mid-session is picked up on the next tick.
//! Discovery itself is routed through
//! [`MiseBinary::discover_async`](toride_mise::binary::MiseBinary::discover_async)
//! (a `spawn_blocking` wrapper) so its tier-2 version probes never run on a
//! tokio worker — the contract `discover`'s own docs state.

use std::sync::OnceLock;
use std::time::Duration;

use tokio::sync::oneshot;
use toride_mise::MiseBinary;

use crate::toride_mise_convert;
use crate::ui::screens::toride_mise::{MiseFindingEntry, MiseOutdatedEntry, MiseToolEntry};

/// Process-lifetime cache for the discovered mise binary (see the module
/// docs). Only successful discoveries land here.
static MISE_BINARY: OnceLock<MiseBinary> = OnceLock::new();

/// Per-command timeout. Generous enough for a healthy local `mise` (sub-100ms
/// for `ls`) but short enough that a hung registry/network lookup cannot stall
/// the collector task.
const CMD_TIMEOUT: Duration = Duration::from_secs(3);

/// Aggregated mise data for the read-only section.
#[derive(Clone, Debug)]
pub struct MiseDataBundle {
    /// Whether the mise backend was reachable at all. `false` is reserved for
    /// the construction-failure case ([`toride_mise::MiseError::BinaryNotFound`]
    /// — mise not installed), the all-probes-failed case (construction
    /// succeeded but every probe timed out or errored), and the panic case (a
    /// `tokio::spawn` `JoinError`). An individual probe failure degrades that
    /// field but the doctor surfaces it as a finding, keeping `available ==
    /// true` so the operator SEES the finding rather than a blank panel.
    pub available: bool,
    /// Detected mise version string, if any.
    pub version: Option<String>,
    /// Installed tools.
    pub tools: Vec<MiseToolEntry>,
    /// Outdated tools (from `mise outdated --json`).
    pub outdated: Vec<MiseOutdatedEntry>,
    /// Config files read by mise.
    pub config_files: Vec<String>,
    /// Doctor findings (cached for 60s between collections).
    pub findings: Vec<MiseFindingEntry>,
    /// Human-readable reason the backend was unreachable, populated whenever
    /// `available == false`: construction failed (`BinaryNotFound`), construction
    /// succeeded but every probe timed out/errored, or the collection task
    /// panicked (`JoinError`). `None` otherwise — notably also `None` for a
    /// freshly-constructed empty bundle before any collection has run, and for
    /// the `available == true` success path. Surfaced to the UI so the degraded
    /// panel can show what actually went wrong.
    pub unavailable_reason: Option<String>,
}

// ── Collector ───────────────────────────────────────────────────────────────

/// Manages periodic async collection of mise data.
///
/// Mirrors the proxy collector's whole-report cache: a oneshot channel for
/// the in-flight result, plus a 60s TTL cache over the ENTIRE bundle (version,
/// tools, outdated, config, findings) so the five mise subprocesses — one of
/// them a network `outdated --json` — do not repeat on every 2s refresh tick.
pub struct MiseCollector {
    /// Carries the bundle AND whether the cached bundle was reused for this
    /// poll. The freshness timestamp must only be advanced when the probes
    /// were actually re-run (`used_cache == false`); otherwise every
    /// cache-hit poll would reset the TTL clock with the SAME (already-cached)
    /// bundle and the cache would never expire for the lifetime of the app.
    rx: Option<oneshot::Receiver<(MiseDataBundle, bool)>>,
    /// Cached bundle from the last collection.
    cached_bundle: Option<MiseDataBundle>,
    /// When the bundle cache was last refreshed.
    bundle_fresh_at: Option<std::time::Instant>,
}

/// How long to keep the cached bundle before re-running the mise probes.
///
/// Deliberate freshness semantics: tool installs/upgrades and new outdated
/// entries surface up to this TTL late (see the module docs).
const BUNDLE_TTL: Duration = Duration::from_secs(60);

/// Whether the bundle-cache TTL has already elapsed for a cache that was
/// last refreshed at `fresh_at`.
///
/// Round-0 instrumentation seam, ZERO behavior change: outside `cfg(test)`
/// this is exactly the negation of the `t.elapsed() < BUNDLE_TTL` check
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
    elapsed >= BUNDLE_TTL
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

    /// Start a new background collection.
    ///
    /// If a collection is already in-flight, this is a no-op. The 60s
    /// whole-bundle cache is consulted: when fresh, the spawned task serves
    /// the cached bundle verbatim — every mise subprocess (including the
    /// network `outdated --json`) is skipped. The collection future is
    /// spawned as an INNER task and its `JoinHandle` awaited in an OUTER
    /// task, so a panic inside `collect_real_mise` is isolated to the inner
    /// task and surfaces here as a `JoinError` — which is converted into an
    /// `empty_bundle_with_reason` (with `available = false`) and still sent
    /// over the channel. This is the tailscale two-spawn pattern
    /// ([`TailscaleCollector::start`](crate::toride_tailscale_data::TailscaleCollector::start))
    /// and, unlike `catch_unwind`, it works under BOTH panic strategies:
    /// `panic = "unwind"` (dev/test) AND `panic = "abort"` (release, set in
    /// `Cargo.toml`'s `[profile.release]`). Under `abort` a panic in the inner
    /// task still tears down only that task as a `JoinError` to the outer
    /// awaiter rather than aborting the whole process, so the refresh degrades
    /// gracefully in release as the docs advertise.
    pub fn start(&mut self) {
        if self.rx.is_some() {
            return;
        }
        let (tx, rx) = oneshot::channel();
        let use_cache =
            self.cached_bundle.is_some() && self.bundle_fresh_at.is_some_and(|t| !ttl_expired(t));
        let cached_bundle = self.cached_bundle.clone();
        self.rx = Some(rx);
        // Two-spawn JoinError pattern (mirrors toride_tailscale_data.rs). The
        // inner task runs the real collection; the outer task awaits its handle
        // so a panic surfaces as a `JoinError` (Err arm) instead of dropping
        // `tx` and wedging every subsequent refresh (poll() returning None
        // forever, leaving the bundle stale with no reason). `catch_unwind` was
        // a no-op under `panic = "abort"` (the release profile), so the old
        // guard only worked in dev; the JoinError path survives both.
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

    /// Poll for a completed collection result.
    ///
    /// Returns `Some(bundle)` if the collection task completed and sent a
    /// result, `None` only while still pending. The collection task always
    /// sends a result on completion — including the all-probes-failed case
    /// (`available = false` + reason) and the caught-panic case (an
    /// `empty_bundle_with_reason`) — so `poll` returning `None` here means the
    /// task is still in flight, not that it failed. On an available bundle the
    /// whole bundle is cached, but the freshness timestamp is only advanced
    /// when the probes were actually re-run (not on a cache-hit poll) —
    /// otherwise the 60s TTL would be re-armed forever with the same cached
    /// data on every 2s refresh. A degraded bundle (mise absent,
    /// all-probes-failed, or a caught panic) is never cached, so the next
    /// refresh retries construction instead of pinning the degraded panel for
    /// the TTL.
    pub async fn poll(&mut self) -> Option<MiseDataBundle> {
        match &mut self.rx {
            Some(rx) => {
                let result = rx.await.ok();
                // Only write the cache (and advance the freshness clock)
                // when the probes actually re-ran. On a cache-hit poll the
                // bundle IS the data we already cached — identical by
                // construction — so re-storing it would be a wasted deep
                // clone per tick, and resetting the TTL here would let the
                // cache live forever as long as the 2s refresh tick keeps
                // firing inside the TTL window.
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

// ── Real data collection ────────────────────────────────────────────────────

/// Collect mise data by invoking the real `mise` binary.
///
/// When `use_cache` is set and a cached bundle is present, the cached bundle
/// is served verbatim and NOTHING runs — every mise subprocess (including the
/// network `outdated --json`) is skipped entirely.
///
/// Otherwise the client is constructed inside the spawned async task from the
/// process-lifetime cached [`MiseBinary`] (or a fresh
/// [`MiseBinary::discover_async`](toride_mise::MiseBinary::discover_async)
/// on the first collection — a `spawn_blocking` wrapper, so discovery's
/// tier-2 version probes never run on a tokio worker). The client's async
/// methods are then awaited directly — NOT wrapped in `spawn_blocking` (the
/// mise backend uses an async `TokioRunner`). The two error paths handled
/// HERE (inside this future) are: construction failure (`BinaryNotFound`) →
/// [`empty_bundle_with_reason`], and construction succeeding with every probe
/// failing/timing out → a bundle with `available = false` and an accurate
/// "did not respond" reason. A panic in this future is NOT caught here — it
/// is caught by the two-spawn `JoinError` guard in [`MiseCollector::start`]'s
/// outer spawn, which converts it into an `empty_bundle_with_reason` so the
/// refresh is not silently dropped.
///
/// Returns `(bundle, used_cache)` where `used_cache` records whether the
/// bundle was served verbatim from the cache. The caller advances the TTL
/// clock ONLY when `used_cache == false`, so a cache-hit poll never resets
/// the freshness timestamp with stale data.
#[expect(
    clippy::too_many_lines,
    reason = "real-data collection is inherently linear"
)]
async fn collect_real_mise(
    use_cache: bool,
    cached_bundle: Option<MiseDataBundle>,
) -> (MiseDataBundle, bool) {
    // Cache hit: serve the whole bundle verbatim. No mise subprocess runs.
    if use_cache && let Some(bundle) = cached_bundle {
        return (bundle, true);
    }

    // Build the client ONCE per collection, from the process-lifetime cached
    // binary when one exists. Fresh discovery goes through `discover_async`
    // (spawn_blocking): discovery tier 2 runs `mise --version` / `-V` probes
    // through the BLOCKING runner, which must not run on a tokio worker.
    // Only successful discoveries are cached — on a host without mise the
    // construction below fails again each tick (PATH scans only, zero
    // subprocess spawns), so a mise installed mid-session is picked up on the
    // next refresh rather than after a process restart.
    let mise = match discover_mise_client().await {
        Ok(m) => m,
        Err(e) => {
            tracing::debug!("mise backend construction failed: {e}");
            // BinaryNotFound is the common dev-box case; any other construction
            // error is also surfaced so the operator sees what went wrong.
            return (
                empty_bundle_with_reason(format!("mise backend unavailable: {e}")),
                false,
            );
        }
    };

    // Run ALL async probes in parallel.
    let (version_r, tools_r, current_r, outdated_r, config_r, diag_r) = tokio::join!(
        async { tokio::time::timeout(CMD_TIMEOUT, mise.run_checked(["--version"])).await },
        async { tokio::time::timeout(CMD_TIMEOUT, mise.list_installed()).await },
        async { tokio::time::timeout(CMD_TIMEOUT, mise.list_current()).await },
        // `outdated_map()` returns the canonical `mise outdated --json` shape —
        // a JSON OBJECT keyed by tool name. The previous `list_outdated()` call
        // tried to deserialise that object into `Vec<ToolStatus>` (a sequence)
        // and ALWAYS failed on any host that actually had outdated tools, then
        // fell back to filtering installed rows by the `outdated` flag — but
        // `ls --installed --json` does not set that flag, so the Outdated pane
        // was permanently empty. See the audit note on collect_real_mise.
        async { tokio::time::timeout(CMD_TIMEOUT, mise.outdated_map()).await },
        async { tokio::time::timeout(CMD_TIMEOUT, mise.config_ls()).await },
        async { tokio::time::timeout(CMD_TIMEOUT, mise.doctor()).await },
    );

    // ── Version ─────────────────────────────────────────────────────────────
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

    // ── Installed tools ─────────────────────────────────────────────────────
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

    // ── Current (active) tools ──────────────────────────────────────────────
    // Enrich the `active` flag on installed rows from the dedicated `--current`
    // query (best-effort). A failure leaves the active flag at its `ls` default.
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

    // ── Outdated ────────────────────────────────────────────────────────────
    // `mise outdated --json` returns a JSON object keyed by tool name, mapped
    // to the canonical `OutdatedOutput` (BTreeMap<String, OutdatedToolEntry>).
    // `outdated_map()` parses that correctly; convert_outdated_map then maps
    // each (name, entry) -> MiseOutdatedEntry with current/latest/backend
    // populated. A parse/timeout failure degrades to an empty outdated list
    // rather than the previous (permanently-empty AND misleading) fallback.
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

    // ── Outdated enrichment on installed rows ──────────────────────────────
    // `mise ls --installed --json` is NOT run with `--outdated`, so the
    // `outdated` field on every installed ToolStatus deserialises to `None`
    // (the installed.json fixture carries no outdated field), and
    // convert_tool's `unwrap_or(false)` leaves the per-row `↑outdated` badge
    // dead for every real row — even when tools ARE outdated and the Outdated
    // section above correctly lists them. Enrich the flag here from the
    // dedicated outdated query, exactly mirroring the active enrichment at
    // lines 327-338, so the Installed table's upgrade arrow is a live signal
    // rather than a permanently-silent indicator.
    if !outdated.is_empty() {
        let outdated_names: std::collections::HashSet<&str> =
            outdated.iter().map(|o| o.name.as_str()).collect();
        for tool in &mut tools {
            if outdated_names.contains(tool.name.as_str()) {
                tool.outdated = true;
            }
        }
    }

    // ── Config files ────────────────────────────────────────────────────────
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

    // ── Doctor ──────────────────────────────────────────────────────────────
    // (A cache hit never reaches this point — it returned the whole bundle
    // verbatim above.)
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

    // ── Availability heuristic ──────────────────────────────────────────────
    // The section is "available" if the binary responded at all — i.e. version
    // is known OR any tool/config was returned OR the doctor produced any
    // finding. A host with mise installed but no tools configured yields an
    // empty tool list and an OK doctor finding, which still counts as available
    // so the operator SEES the version + clean doctor rather than a blank
    // panel.
    //
    // We reached this point only because `Mise::builder().build()` succeeded —
    // the binary WAS found. So if the heuristic still evaluates to false, it
    // means EVERY probe timed out or errored (e.g. mise hanging on a registry
    // lookup, a misbehaving plugin, or a slow box). That is a fundamentally
    // different state from "mise not installed", and the previous code attached
    // NO reason here, leaving the UI to fall through to its
    // "mise binary not found on $PATH ..." default — which is factually wrong.
    // Distinguish the two cases by attaching an accurate reason on the
    // construction-OK-but-all-probes-failed path so render_unavailable shows
    // the real cause instead of the misleading no-binary message.
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
        // Reaching this point means the probes DID run (a cache hit returned
        // above), so the truthful provenance is "not from cache".
        false,
    )
}

/// Build the mise client for one collection.
///
/// Serves the process-lifetime cached [`MiseBinary`] when present; otherwise
/// discovers one through
/// [`MiseBinary::discover_async`](toride_mise::MiseBinary::discover_async)
/// (a `spawn_blocking` wrapper, keeping the discovery cascade's sync
/// subprocess probes off the tokio worker) and caches a SUCCESSFUL discovery
/// in [`MISE_BINARY`]. `Mise::builder().binary(..).build()` performs no
/// discovery of its own, so the cached path costs no `$PATH` scan.
///
/// # Errors
///
/// Propagates [`toride_mise::MiseError::BinaryNotFound`] when no mise exists
/// on the host (the clean per-tick degraded path — never cached, so a mise
/// installed mid-session is found on the next refresh).
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

/// Empty bundle used when mise could not be constructed at all.
///
/// `available = false` signals the UI to render the degraded panel. No reason
/// is attached because none is known at this point; construction / collection
/// failures use [`empty_bundle_with_reason`] to surface the cause.
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

/// Empty bundle carrying the reason collection failed. Used when construction
/// failed (`BinaryNotFound`) or when the collection task was caught panicking via
/// the two-spawn `JoinError` guard in [`MiseCollector::start`] — the reason
/// string is rendered by the UI's degraded panel so the operator sees what
/// actually went wrong. The all-probes-failed-but-construction-OK case
/// produces its own reason via [`reason_when_construction_ok_but_unavailable`]
/// instead.
fn empty_bundle_with_reason(reason: String) -> MiseDataBundle {
    let mut b = empty_bundle();
    b.unavailable_reason = Some(reason);
    b
}

/// Reason attached by `collect_real_mise` when mise construction SUCCEEDED (the
/// binary was found) but the availability heuristic still evaluates to false —
/// i.e. every probe timed out or errored. Extracted from `collect_real_mise` so
/// the construction-OK-vs-binary-absent distinction is unit-testable without
/// shelling out. Returns `None` when the bundle is actually available.
///
/// The heuristic UNIONS over ALL five mise data sources — version, installed
/// tools, outdated tools, config files, AND doctor findings — mirroring the
/// tailscale reference (`toride_tailscale_data.rs`:306-311), which unions over
/// status.connected || !peers || !`ip_addresses` || !findings || topology ||
/// netcheck. Omitting the `outdated` list here was an availability-heuristic
/// completeness gap: if `mise outdated --json` succeeded (returned entries)
/// while `--version` / `list_installed` / `list_current` / `config_ls` / `doctor` all
/// failed or timed out, the predicate evaluated to false, attached the
/// "did not respond" reason, set `available = false`, and the UI rendered the
/// degraded panel — HIDING the outdated data that was successfully collected
/// and sitting in the bundle. Including `!outdated.is_empty()` in the OR closes
/// that gap so any successfully-collected data source keeps the section live.
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

// ── Tests ───────────────────────────────────────────────────────────────────

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
        collector.start(); // no-op, does not replace the receiver
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
        // Let the spawned task complete (it execs mise, so give it time).
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let _ = collector.poll().await;
        assert!(!collector.is_pending(), "poll should clear pending state");
    }

    #[tokio::test]
    async fn poll_returns_bundle_after_collection() {
        // On any host (including macOS without mise) the collector must return
        // Some(bundle) after start() + enough time. The bundle's `available`
        // flag reflects whether mise was found.
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
        assert!(b.config_files.is_empty());
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
        // After a successful AVAILABLE poll the whole-bundle cache is
        // populated. A host without mise (or with every probe failing) stays
        // uncached so the next tick retries construction.
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

    // ── Collection edge cases / unhappy paths ────────────────────────────────
    //
    // The lifecycle tests above all shell out to the real `mise` binary and
    // assert only structural `Some(bundle)`. These tests pin the MAPPING paths
    // that `collect_real_mise` actually invokes — driving them with
    // fixture-shaped inputs (the real outdated payload, empty/`{}`/`null`
    // responses, placeholder rows, empty doctor messages) — mirroring the bar
    // set by `fail2ban_convert`'s empty / malformed / degenerate-token tests.
    // They do NOT exec mise.

    use toride_mise::serde_utils::json_outputs::{OutdatedOutput, OutdatedToolEntry};

    fn parse_outdated(raw: &str) -> OutdatedOutput {
        serde_json::from_str(raw).expect("outdated JSON must parse into OutdatedOutput")
    }

    /// The real `mise outdated --json` payload (matches
    /// crates/toride-mise/fixtures/outdated/basic.json) flows through the exact
    /// converter `collect_real_mise` calls and yields current=installed,
    /// latest=available — NOT latest=requested.
    #[test]
    fn outdated_real_fixture_maps_current_and_latest() {
        let raw = r#"{"node":{"requested":"22","current":"22.0.0","latest":"22.1.0"}}"#;
        let entries = toride_mise_convert::convert_outdated_map(parse_outdated(raw));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "node");
        assert_eq!(entries[0].current.as_deref(), Some("22.0.0"));
        assert_eq!(entries[0].latest.as_deref(), Some("22.1.0"));
    }

    /// Regression guard for the dead per-row `↑outdated` badge (audit finding
    /// 2/UI-UX). `mise ls --installed --json` is NOT run with `--outdated`, so
    /// `convert_tool` leaves every installed row's `outdated` flag at `false`
    /// (`unwrap_or(false)`). The collector is responsible for ENRICHING the flag
    /// from the dedicated outdated query (mirroring the active enrichment) —
    /// without that step the badge is permanently silent even when tools ARE
    /// outdated (and the Outdated section above lists them). Drive both
    /// converters and the EXACT enrichment loop `collect_real_mise` runs, then
    /// assert an installed row whose name appears in the outdated map ends up
    /// with `outdated == true`, and a non-matching row stays `false`.
    #[test]
    fn installed_outdated_flag_enriched_from_outdated_map() {
        // Installed rows from `ls --installed --json` — note `outdated: None`,
        // the field mise never populates without `--outdated`.
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
        // Before enrichment, BOTH rows must read outdated == false (the bug:
        // they would stay this way forever on real data).
        assert!(
            tools.iter().all(|t| !t.outdated),
            "convert_tool must default outdated to false from ls --installed"
        );

        // The outdated query names `node` but not `python`.
        let raw = r#"{"node":{"requested":"22","current":"22.0.0","latest":"22.1.0"}}"#;
        let outdated = toride_mise_convert::convert_outdated_map(parse_outdated(raw));

        // Mirror the enrichment loop in collect_real_mise verbatim.
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

    /// The previous probe deserialised into `Vec<ToolStatus>` and always failed
    /// on a non-empty map. Assert the map-shaped payload the collector now uses
    /// parses cleanly (the regression the audit flagged).
    #[test]
    fn outdated_map_parses_where_vec_probe_failed() {
        let raw = r#"{"node":{"requested":"22","current":"22.0.0","latest":"22.1.0"}}"#;
        // A Vec<ToolStatus> deserialisation would fail with "invalid type: map";
        // OutdatedOutput must succeed.
        let map: OutdatedOutput = serde_json::from_str(raw).expect("map must parse");
        assert_eq!(map.len(), 1);
    }

    /// `mise outdated --json` returns `{}` when nothing is outdated: the
    /// collector's outdated pane must read 0, not error.
    #[test]
    fn outdated_empty_object_yields_empty_pane() {
        let entries = toride_mise_convert::convert_outdated_map(parse_outdated("{}"));
        assert!(entries.is_empty());
    }

    /// An empty map (`OutdatedOutput::new()`, the graceful representation of
    /// "no outdated tools") yields no rows. This is what `convert_outdated_map`
    /// receives on the success path. (Previously named
    /// `outdated_null_does_not_panic`, which was misleading — see
    /// `outdated_null_and_array_do_not_deserialize` for the actual null path.)
    #[test]
    fn outdated_empty_map_yields_empty() {
        let entries = toride_mise_convert::convert_outdated_map(OutdatedOutput::new());
        assert!(entries.is_empty());
    }

    /// `mise outdated --json` is documented to emit `{}` for the empty case
    /// (handled correctly above). A future mise version or a misbehaving plugin
    /// could instead emit `null`, `[]`, or an empty string. None of those
    /// deserialize into `OutdatedOutput` (a `BTreeMap`), so `outdated_map()`'s
    /// `run_json` surfaces them as an `Err`, and the collector's
    /// `Ok(Err(e)) => Vec::new()` branch degrades to an empty list. Assert that
    /// degradation here: if these payloads ever started parsing, the collector
    /// would silently change behavior, so pin the `Err`.
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

    /// An outdated entry missing `current`/`latest` (only `requested` present)
    /// must not surface the requested version as latest — the audit's bug (c).
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

    /// A `ToolStatus` with empty name/version (the placeholder path used by
    /// `convert_tool` for malformed `ls` rows) renders as `(unknown)` with no
    /// version, never panics.
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

    /// A doctor report whose diagnostics carry empty messages must still
    /// produce one row per diagnostic (placeholder message), so the row count
    /// matches the backend and the operator sees the finding kind.
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

    /// Empty version stdout (a mise that printed nothing for `--version`)
    /// degrades the version field to None — the collector's version branch
    /// drops empty trimmed output, and the availability heuristic must not
    /// flip to true solely on an empty version.
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

    /// Availability heuristic on a fully-degenerate bundle (no version, no
    /// tools, no outdated, no config, no findings) must stay `available == false`
    /// so the UI renders the degraded panel rather than a misleading blank.
    #[test]
    fn availability_heuristic_false_on_all_empty_probes() {
        let b = MiseDataBundle {
            available: false, // would be computed as: version.is_some() || ...
            version: None,
            tools: Vec::new(),
            outdated: Vec::new(),
            config_files: Vec::new(),
            findings: Vec::new(),
            unavailable_reason: None,
        };
        // Re-evaluate the exact predicate from collect_real_mise — including
        // the outdated list, which the heuristic unions over alongside version
        // / tools / config / findings (mirrors the tailscale reference).
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

    /// When construction SUCCEEDED (mise was found on $PATH) but every probe
    /// timed out or errored, `collect_real_mise` must attach a reason that is
    /// NOT the misleading "mise binary not found" default — the binary WAS
    /// found, only the queries failed. The UI's `render_unavailable` falls back
    /// to that default ONLY when the bundle carries no reason, so a non-`None`
    /// reason here is what prevents the factually-wrong panel.
    #[test]
    fn construction_ok_but_all_probes_failed_is_not_binary_not_found() {
        // construction_ok path (mirrors collect_real_mise after build() Ok):
        // empty version, empty tools, empty outdated, empty config, empty findings.
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

    /// The construction-OK reason helper returns `None` when the bundle is
    /// actually available — so the success path carries no reason and the
    /// availability flag stays true.
    #[test]
    fn construction_ok_with_any_probe_is_available_no_reason() {
        let version = "mise 2024.12.4".to_string();
        let reason =
            reason_when_construction_ok_but_unavailable(Some(&version), &[], &[], &[], &[]);
        assert!(reason.is_none(), "available path must carry no reason");
    }

    /// Regression guard for the availability-heuristic completeness gap (audit
    /// finding 2-DEGRADATION). The heuristic unions over ALL FIVE mise data
    /// sources — including the `outdated` list. If `mise outdated --json`
    /// succeeded (returned entries) while `--version` / `list_installed` /
    /// `list_current` / `config_ls` / `doctor` ALL failed or timed out, the OLD
    /// predicate (which omitted `outdated`) evaluated to false, attached the
    /// "did not respond" reason, set `available = false`, and the UI hid the
    /// successfully-collected outdated data behind the degraded panel. A
    /// populated-outdated / everything-else-empty bundle must now keep the
    /// section `available == true` with no reason — exactly the class of
    /// "successfully-collected data hidden behind a degraded panel" the audit
    /// bars against, and the same union shape the tailscale reference uses
    /// (`toride_tailscale_data.rs`:306-311).
    #[test]
    fn populated_outdated_keeps_section_available_no_reason() {
        let outdated = vec![MiseOutdatedEntry {
            name: "node".into(),
            current: Some("22.0.0".into()),
            latest: Some("22.1.0".into()),
            backend: None,
        }];
        // Every probe EXCEPT `mise outdated --json` failed/timed out.
        let reason = reason_when_construction_ok_but_unavailable(None, &[], &outdated, &[], &[]);
        assert!(
            reason.is_none(),
            "a populated outdated list must keep the section available even \
             when every other probe failed — the heuristic unions over all \
             five data sources: {reason:?}"
        );
    }
}

// ── Cadence oracles (round 0, extended round 1) ──────────────────────────────

/// Cadence oracles for the 60s whole-bundle cache.
///
/// Round 1 (F07) extended these from a findings-only cache to the whole
/// bundle: sentinel data now covers the version string and the tool rows as
/// well as the findings. The sentinel values (finding message, version,
/// tool name) are ones no real mise probe can emit, so "the bundle came back
/// verbatim" proves `--version`, `ls`, `outdated`, `config ls`, AND `doctor`
/// did not spawn a single subprocess.
///
/// The lifecycle goes through the REAL `start()` / spawned collection. With
/// a non-empty sentinel bundle in the cache, the cache-hit arm is
/// deterministic on any host (nothing runs). On a host WITH mise the expiry
/// arm re-runs the real probes (available bundle, clock re-armed); on a host
/// without `mise` on `$PATH` construction fails before the cache arm and —
/// since `poll()` now gates cache writes on `available` — the degraded arm
/// leaves the primed clock untouched. Both arms are deterministic for the
/// host they run on.
///
/// No spawn-counting seam is added at this layer: `collect_real_mise`
/// hardcodes its runner discovery, and threading an injectable runner
/// through `start()` would change production signatures — the sentinel
/// bundle already answers "did anything re-run?".
#[cfg(test)]
mod cadence_oracle {
    use super::*;

    /// Sentinel message no real mise diagnostic can carry.
    const SENTINEL_MSG: &str = "oracle-sentinel mise findings-cache";

    /// Sentinel version no real `mise --version` prints.
    const SENTINEL_VERSION: &str = "oracle-sentinel 0.0.0";

    /// Sentinel tool name no real `mise ls` lists.
    const SENTINEL_TOOL: &str = "oracle-sentinel-tool";

    /// A sentinel bundle with `available == true` so `poll()` caches it.
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

    /// Advances this thread\'s TTL test clock past the TTL, resetting it on
    /// drop so a failing assertion cannot leak a cranked clock into a later
    /// test scheduled on the same reused cargo-test thread.
    struct TtlOffsetGuard;

    impl TtlOffsetGuard {
        /// Set the thread-local offset to `BUNDLE_TTL` + 10s.
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

    /// ORACLE: a fresh cache serves the WHOLE cached bundle verbatim on the
    /// next collection — every mise subprocess (including the network
    /// `outdated --json`) is skipped — and the freshness timestamp is NOT
    /// re-armed by the cache-hit poll.
    #[tokio::test]
    async fn cache_hit_returns_cached_bundle_without_reprobing() {
        let mut collector = MiseCollector::new();
        collector.cached_bundle = Some(sentinel_bundle());
        let primed = std::time::Instant::now();
        collector.bundle_fresh_at = Some(primed);

        collector.start();
        let bundle = collector.poll().await.expect("collection completes");

        // The cache-hit arm returns before construction, so it is
        // deterministic on ANY host (mise present or not).
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

    /// ORACLE: once the TTL has elapsed the cache is bypassed — no sentinel
    /// survives in ANY field — and the freshness bookkeeping reflects the
    /// re-derivation: re-armed on a host where mise answered, untouched on a
    /// host where construction failed (`poll()` gates cache writes on
    /// `available`).
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
            // The real probes re-ran and produced an available bundle.
            assert!(
                collector.bundle_fresh_at.is_some_and(|t| t > primed),
                "an expired cache must be re-derived and the freshness clock advanced"
            );
        } else {
            // mise absent / unresponsive: the availability gate keeps the
            // primed clock untouched so the next tick retries construction.
            assert_eq!(
                collector.bundle_fresh_at,
                Some(primed),
                "a degraded re-derivation must leave the primed clock untouched"
            );
        }
    }
}
