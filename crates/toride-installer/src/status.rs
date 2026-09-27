//! Offline tool-availability detection.
//!
//! Answers, for a [`Tool`], three questions without ever touching the
//! network: is it installed ([`ToolStatus`]), where did the running copy
//! come from — the system `$PATH` or the installer's managed location
//! ([`ToolSource`]) — and what version does it report ([`ToolVersion`])?
//!
//! [`Detector::detect`] probes the real `$PATH` first (that is the binary a
//! shell would actually execute), then the managed install location — the
//! exact directory `resolve_install_dir` installs into, so "where we
//! look" cannot drift from "where we install". A `$PATH` hit that
//! canonicalizes to the managed path (or a managed file found with no
//! `$PATH` hit) is [`ToolSource::Managed`]; any other `$PATH` hit is the
//! shadow case [`ToolSource::Path`] (a package-manager copy ahead of
//! `~/.local/bin`, say).
//!
//! The detector never errors: a missing tool is [`ToolStatus::NotInstalled`],
//! and a binary that refuses both `--version` and `-V` (or exits non-zero,
//! or times out) keeps its presence with `version: None`. Presence is the
//! path probe's verdict, never the version probe's. Staleness is
//! deliberately not a [`ToolStatus`] variant — comparing against the newest
//! release needs a network fetch, so it is a derived [`Freshness`] computed
//! by callers that explicitly have a `latest` in hand.
//!
//! The one network-touching piece lives here too, kept behind an explicit
//! opt-in: [`latest`] is a single [`ReleaseResolver::resolve`] call for the
//! host [`Target`] with `"latest"`, and [`LatestCache`] is an in-memory TTL
//! cache of that lookup. Release-API failures — rate limiting above all —
//! surface there as ordinary errors; callers must treat them as non-fatal,
//! because an unreachable release API says nothing about the health of an
//! installed tool.
//!
//! On top of detection sits the install-on-missing front door,
//! [`ensure_installed`]: detect first; keep an installed copy that already
//! satisfies the request — `"latest"`, or a pinned semver the detected
//! version meets — with zero network, and only on a true miss run the
//! install pipeline, re-detecting afterwards for the freshly installed
//! version ([`EnsureOutcome`]).
//!
//! # Name collision
//!
//! `toride-mise` also exports a `ToolStatus` (its mise-installed-tool
//! listing) with a different meaning. One crate, one meaning; consumers
//! adopting both must qualify the import at every use.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use camino::{Utf8Path, Utf8PathBuf};
use toride_runner::discovery::find_binary;
use toride_runner::{CommandSpec, DuctRunner, Runner};

use crate::error::Result;
#[cfg(feature = "http")]
use crate::installer::Installer;
use crate::installer::resolve_install_dir;
use crate::target::Target;
use crate::tool::{ReleaseResolver, Tool};

/// Default per-tool version-probe timeout. A UI catalogue sweep typically
/// uses a much tighter per-probe cap (hundreds of ms) across many tools; a
/// single-tool detect can afford a few seconds so slow cold-start binaries
/// (first-run security scans on some platforms) still report a version.
pub const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Best-effort parsed version of a tool's `--version` (or `-V`) output.
///
/// Date-based versions like `2026.9.1` are valid semver (major 2026, minor
/// 9, patch 1) and parse natively, so [`Freshness`] and [`ToolVersion::is_at_least`]
/// compare them without special cases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolVersion {
    /// The trimmed first non-empty `--version`/`-V` stdout line — exactly
    /// what the host UI displays today, so UI parity survives adoption.
    pub line: String,

    /// The version token: prefix-stripped, first whitespace token
    /// (e.g. `"1.2.3"` or `"2026.9.1"`).
    pub raw: String,

    /// Best-effort `semver::Version` of `raw`; `None` when unparseable.
    pub parsed: Option<semver::Version>,
}

impl ToolVersion {
    /// Parse `<bin> --version` output.
    ///
    /// Takes the first non-empty stdout line and trims it (that is `line`);
    /// strips a leading `"<bin_name> version "` then `"<bin_name> "` prefix
    /// (covers tools printing `tool version 1.2.3 (rev …)` and `tool 1.2.3`);
    /// bare output passes through; takes the first whitespace token as
    /// `raw`; best-effort semver-parses. Never fails.
    #[must_use]
    pub fn parse(output: &str, bin_name: &str) -> Self {
        let line = output
            .lines()
            .find(|l| !l.trim().is_empty())
            .map(str::trim)
            .unwrap_or_default()
            .to_owned();
        let versioned = strip_bin_prefix(&line, bin_name);
        let raw = versioned
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_owned();
        let parsed = semver::Version::parse(&raw).ok();
        Self { line, raw, parsed }
    }

    /// Conservative `>=` check: `false` when unparseable.
    #[must_use]
    pub fn is_at_least(&self, required: &semver::Version) -> bool {
        self.parsed.as_ref().is_some_and(|v| v >= required)
    }
}

/// Strip a leading `"<bin_name> version "` then `"<bin_name> "` prefix from
/// a version line; anything else passes through untouched.
///
/// The prefix only counts when the binary name is followed by a separator
/// (`" version "` or a single space), so a line beginning with a *longer*
/// word that merely extends `bin_name` (`"mystery"` for `bin_name = "mist"`)
/// is left alone.
fn strip_bin_prefix<'line>(line: &'line str, bin_name: &str) -> &'line str {
    if bin_name.is_empty() {
        return line;
    }
    let Some(rest) = line.strip_prefix(bin_name) else {
        return line;
    };
    if let Some(rest) = rest.strip_prefix(" version ") {
        return rest.trim();
    }
    match rest.strip_prefix(' ') {
        Some(rest) => rest.trim_start(),
        None => line,
    }
}

/// Where a detected tool came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolSource {
    /// The `$PATH` resolved to a copy that is NOT the managed install path —
    /// the shadow case (e.g. a package-manager copy ahead of `~/.local/bin`).
    Path,

    /// The managed copy is what would run: the `$PATH` hit canonicalized to
    /// the managed path, or the binary exists there while off `$PATH`.
    Managed,
}

/// Offline availability of one tool. `Stale` is deliberately NOT a variant:
/// it needs a network `latest` lookup, and baking it in would either put
/// network on the detect hot path or lose the `OnPath`/`Managed` distinction
/// (see [`Freshness`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolStatus {
    /// Neither on `$PATH` nor at the managed install path.
    NotInstalled,

    /// `$PATH` resolved to a copy that is NOT the managed install path.
    OnPath {
        /// The resolved executable path.
        path: Utf8PathBuf,
        /// Best-effort version reported by the binary.
        version: Option<ToolVersion>,
    },

    /// The managed copy is what would run: `$PATH` resolved to exactly the
    /// managed path, or the binary exists there while off `$PATH`.
    Managed {
        /// The managed install path.
        path: Utf8PathBuf,
        /// Best-effort version reported by the binary.
        version: Option<ToolVersion>,
    },
}

impl ToolStatus {
    /// Private constructor from a classification, so `detect` stays linear.
    fn new(source: ToolSource, path: Utf8PathBuf, version: Option<ToolVersion>) -> Self {
        match source {
            ToolSource::Path => Self::OnPath { path, version },
            ToolSource::Managed => Self::Managed { path, version },
        }
    }

    /// `true` for any status with a runnable path (`OnPath` or `Managed`).
    #[must_use]
    pub fn is_installed(&self) -> bool {
        !matches!(self, Self::NotInstalled)
    }

    /// The executable path, `None` iff [`ToolStatus::NotInstalled`].
    #[must_use]
    pub fn path(&self) -> Option<&Utf8PathBuf> {
        match self {
            Self::NotInstalled => None,
            Self::OnPath { path, .. } | Self::Managed { path, .. } => Some(path),
        }
    }

    /// The best-effort reported version, when the binary answered a probe.
    #[must_use]
    pub fn version(&self) -> Option<&ToolVersion> {
        match self {
            Self::NotInstalled => None,
            Self::OnPath { version, .. } | Self::Managed { version, .. } => version.as_ref(),
        }
    }

    /// Where the copy came from; `None` iff [`ToolStatus::NotInstalled`].
    #[must_use]
    pub fn source(&self) -> Option<ToolSource> {
        match self {
            Self::NotInstalled => None,
            Self::OnPath { .. } => Some(ToolSource::Path),
            Self::Managed { .. } => Some(ToolSource::Managed),
        }
    }
}

/// Derived staleness — computed only when the caller explicitly has a
/// `latest` in hand (a network concern; `detect` itself never fetches).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Freshness {
    /// The installed version parses and is `>=` the latest.
    Current,

    /// The installed version parses and is `<` the latest.
    Stale {
        /// The version reported by the installed binary.
        installed: ToolVersion,
        /// The newest release version the caller fetched.
        latest: ToolVersion,
    },

    /// The installed version is missing or unparseable (or the tool is not
    /// installed, or `latest` itself is unparseable) — cannot compare.
    /// Never `Stale` on a guess.
    Unknown,
}

impl Freshness {
    /// `NotInstalled`/version-less/unparseable -> `Unknown`; both parseable
    /// -> `Current` iff `installed >= latest`.
    #[must_use]
    pub fn evaluate(status: &ToolStatus, latest: &ToolVersion) -> Self {
        let Some(installed) = status.version() else {
            return Self::Unknown;
        };
        let (Some(installed_v), Some(latest_v)) = (&installed.parsed, &latest.parsed) else {
            return Self::Unknown;
        };
        if installed_v >= latest_v {
            Self::Current
        } else {
            Self::Stale {
                installed: installed.clone(),
                latest: latest.clone(),
            }
        }
    }
}

/// Tool-availability detector. Cheap, `Clone`. Never errors: a missing tool
/// is [`ToolStatus::NotInstalled`], a binary that refuses version flags
/// keeps its presence with `version: None`.
#[derive(Clone)]
pub struct Detector {
    runner: Arc<dyn Runner>,
    probe_timeout: Duration,
    install_dir: Option<Utf8PathBuf>,
}

impl Default for Detector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector {
    /// Default runner + [`DEFAULT_PROBE_TIMEOUT`] + tool-default install dir.
    #[must_use]
    pub fn new() -> Self {
        Self::with_runner(Arc::new(DuctRunner))
    }

    /// Inject a runner — tests pass `Arc::new(FakeRunner::new().strict())`.
    #[must_use]
    pub fn with_runner(runner: Arc<dyn Runner>) -> Self {
        Self {
            runner,
            probe_timeout: DEFAULT_PROBE_TIMEOUT,
            install_dir: None,
        }
    }

    /// Begin a [`DetectorBuilder`].
    #[must_use]
    pub fn builder() -> DetectorBuilder {
        DetectorBuilder::new()
    }

    /// Offline availability of `tool`.
    ///
    /// Precedence (see module docs):
    ///
    /// 1. [`find_binary`](&tool.bin_name) over the real `$PATH` — the PATH
    ///    hit is what a shell would actually execute;
    /// 2. managed path = `resolve_install_dir(tool, self.install_dir)
    ///    .join(&tool.bin_name)` — the same fn installs use, so "where we
    ///    look" cannot drift from "where we install";
    /// 3. classify: a PATH hit canonicalizing equal to the managed path ->
    ///    `Managed`; a PATH hit elsewhere -> `OnPath`; no PATH hit but the
    ///    managed file exists -> `Managed`; neither -> `NotInstalled`. If
    ///    `resolve_install_dir` errors (no home dir, no default), the
    ///    managed arm is simply absent and classification is PATH-only.
    ///
    /// Then the classified path's version is probed through the injected
    /// runner as
    /// `CommandSpec::new(path).arg("--version").timeout(probe_timeout).stdin_null(true)`
    /// (capture output is the default; stdin is the null device so a probe
    /// can neither block on nor consume the caller's stdin), falling back to
    /// `-V`. A failed / timed-out / non-zero / empty-stdout probe degrades to
    /// `version: None` — presence is the path probe's verdict, never the
    /// version's. Never errors, never touches the network.
    #[must_use]
    pub fn detect(&self, tool: &Tool) -> ToolStatus {
        let managed = resolve_install_dir(tool, self.install_dir.as_ref())
            .ok()
            .map(|dir| dir.join(&tool.bin_name));

        // `find_binary` returns `std::path::PathBuf`; a non-UTF-8 hit cannot
        // be represented in `ToolStatus` (paths are `Utf8PathBuf` by
        // construction) and is treated as absent — detect then falls through
        // to the managed arm or `NotInstalled`. Executable paths are
        // effectively always UTF-8 on the platforms this crate supports.
        let path_hit = find_binary(&tool.bin_name)
            .ok()
            .and_then(|p| Utf8PathBuf::from_path_buf(p).ok());

        match classify(path_hit, managed) {
            Some((path, source)) => {
                let version = self.probe_version(&path, &tool.bin_name);
                ToolStatus::new(source, path, version)
            }
            None => ToolStatus::NotInstalled,
        }
    }

    /// `spawn_blocking` wrapper over [`Detector::detect`] — the crate is
    /// async-native but the probe is sync subprocess work, so it must not
    /// run on an async runtime worker.
    ///
    /// Parity: returns exactly what `detect` returns. A blocking task that
    /// panics or is cancelled has no error channel here (`detect` never
    /// errors by contract), so it degrades to [`ToolStatus::NotInstalled`].
    pub async fn detect_async(&self, tool: &Tool) -> ToolStatus {
        let detector = self.clone();
        let tool = tool.clone();
        tokio::task::spawn_blocking(move || detector.detect(&tool))
            .await
            .unwrap_or(ToolStatus::NotInstalled)
    }

    /// The managed install path for `tool` without detecting — exposes the
    /// full `resolve_install_dir` precedence (explicit `install_dir` >
    /// `tool.default_install_dir` > `~/.local/bin`) for callers that want
    /// shadow warnings.
    ///
    /// # Errors
    ///
    /// [`Error::NoHomeDir`](crate::Error::NoHomeDir) when no tier resolves.
    pub fn managed_path(tool: &Tool, install_dir: Option<&Utf8PathBuf>) -> Result<Utf8PathBuf> {
        resolve_install_dir(tool, install_dir).map(|dir| dir.join(&tool.bin_name))
    }

    /// Probe the classified binary's version: `--version` first, falling
    /// back to `-V`. Any failure — spawn error, timeout, non-zero exit,
    /// whitespace-only stdout — degrades to `None`; presence is never
    /// inferred from the probe.
    fn probe_version(&self, path: &Utf8Path, bin_name: &str) -> Option<ToolVersion> {
        for arg in ["--version", "-V"] {
            let spec = CommandSpec::new(path.as_str())
                .arg(arg)
                .timeout(self.probe_timeout)
                // Probes must never inherit the caller's stdin: an
                // unspecified stdin is wired to the parent's terminal by both
                // runners, so a stdin-reading catalogue binary would block
                // until the timeout (degrading to `version: None`) and could
                // consume the host UI's keystrokes, instead of seeing EOF and
                // answering. Null stdin is what the hand-rolled probes this
                // detector replaced spawned with.
                .stdin_null(true);
            // `Runner::run`, NOT `run_checked`: a non-zero exit is a probe
            // outcome (degrade / try the next flag), never an error.
            let Ok(output) = self.runner.run(&spec) else {
                continue;
            };
            if !output.success {
                continue;
            }
            if let Some(line) = output.stdout.lines().find(|l| !l.trim().is_empty()) {
                return Some(ToolVersion::parse(line, bin_name));
            }
        }
        None
    }
}

/// Builder for [`Detector`], mirroring the installer's builder.
pub struct DetectorBuilder {
    runner: Arc<dyn Runner>,
    probe_timeout: Duration,
    install_dir: Option<Utf8PathBuf>,
}

impl DetectorBuilder {
    /// Default runner + [`DEFAULT_PROBE_TIMEOUT`], no install-dir override.
    #[must_use]
    pub fn new() -> Self {
        Self {
            runner: Arc::new(DuctRunner),
            probe_timeout: DEFAULT_PROBE_TIMEOUT,
            install_dir: None,
        }
    }

    /// Inject a runner (e.g. `Arc::new(FakeRunner::new().strict())`).
    #[must_use]
    pub fn runner(mut self, runner: Arc<dyn Runner>) -> Self {
        self.runner = runner;
        self
    }

    /// Per-probe wall-clock timeout for the `--version` / `-V` probes.
    #[must_use]
    pub const fn probe_timeout(mut self, timeout: Duration) -> Self {
        self.probe_timeout = timeout;
        self
    }

    /// Override the managed-location tier for detect (the same precedence
    /// [`Detector::managed_path`] exposes).
    #[must_use]
    pub fn install_dir(mut self, dir: impl Into<Utf8PathBuf>) -> Self {
        self.install_dir = Some(dir.into());
        self
    }

    /// Build the [`Detector`].
    #[must_use]
    pub fn build(self) -> Detector {
        Detector {
            runner: self.runner,
            probe_timeout: self.probe_timeout,
            install_dir: self.install_dir,
        }
    }
}

impl Default for DetectorBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Network latest-version lookup: exactly one
/// [`ReleaseResolver::resolve`] call for the host [`Target`] with
/// `"latest"`.
///
/// The concrete version the resolver returns (per the trait's contract a
/// bare version like `"2026.6.14"` — no tag prefix, never the string
/// `"latest"`) becomes the [`ToolVersion`]: `line`/`raw` carry the version
/// text and `parsed` is a best-effort semver parse. The download URL is
/// discarded — a staleness verdict via [`Freshness::evaluate`] needs only
/// the version, and this function must not invite a download.
///
/// Only errors the pieces already produce can escape; there are no new
/// variants on the `#[non_exhaustive]` [`Error`](crate::Error) enum:
///
/// - [`Error::UnsupportedTarget`](crate::Error::UnsupportedTarget) when
///   [`Target::host`] cannot classify this platform;
/// - whatever the resolver's contract allows — typically
///   [`Error::Resolve`](crate::Error::Resolve),
///   [`Error::Download`](crate::Error::Download) or
///   [`Error::HttpStatus`](crate::Error::HttpStatus).
///
/// Callers must treat failure as non-fatal: release-API rate limiting
/// surfaces here as an [`Error::HttpStatus`](crate::Error::HttpStatus) on
/// a perfectly healthy install, so a staleness check that hard-fails
/// would report every rate limit as a broken tool. Report no verdict
/// instead.
///
/// # Errors
///
/// See above: host-target detection and the resolver itself — nothing
/// else.
pub async fn latest(resolver: &dyn ReleaseResolver) -> Result<ToolVersion> {
    let target = Target::host()?;
    let (version, _url) = resolver.resolve(target, "latest").await?;
    // An empty bin name disables prefix stripping: the resolver contract
    // already delivers a bare version, and there is no binary name to
    // strip here. `ToolVersion::parse` remains the single parsing path.
    Ok(ToolVersion::parse(&version, ""))
}

/// In-memory TTL cache for [`latest`], keyed by [`Tool::name`].
///
/// Deliberately minimal: `&mut self` access only (no interior mutability,
/// no shared handle) and no persistence — a `dirs::cache_dir()`-backed
/// cache adds fs-layout and staleness-semantics decisions with no
/// consumer yet. Repeats within the TTL (a doctor check plus a run in one
/// invocation, say) cost a single release-API lookup; a rate-limited miss
/// surfaces as [`Error::HttpStatus`](crate::Error::HttpStatus) and must
/// stay non-fatal in callers, exactly like [`latest`].
#[derive(Debug)]
pub struct LatestCache {
    /// How long an entry stays fresh.
    ttl: Duration,

    /// Per-tool `(fetched_at, version)` entries.
    entries: HashMap<String, (Instant, ToolVersion)>,
}

impl LatestCache {
    /// A cache whose entries stay fresh for `ttl`. A zero `ttl` disables
    /// caching: every lookup refetches.
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: HashMap::new(),
        }
    }

    /// The cached latest [`ToolVersion`] of `tool` while fresh within the
    /// TTL; otherwise a fresh [`latest`] fetch, stored for next time.
    ///
    /// # Errors
    ///
    /// Propagates [`latest`]'s error on a cache miss. A failed fetch is
    /// not cached, so the next call retries the resolver rather than
    /// replaying the error for the whole TTL.
    pub async fn get(
        &mut self,
        tool: &Tool,
        resolver: &dyn ReleaseResolver,
    ) -> Result<ToolVersion> {
        if let Some((fetched_at, version)) = self.entries.get(&tool.name)
            && fetched_at.elapsed() < self.ttl
        {
            return Ok(version.clone());
        }
        let version = latest(resolver).await?;
        self.entries
            .insert(tool.name.clone(), (Instant::now(), version.clone()));
        Ok(version)
    }
}

/// Outcome of install-on-missing with version-check-before-install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnsureOutcome {
    /// `detect` found a runnable copy that already satisfies the request;
    /// nothing was downloaded and the resolver was never consulted.
    AlreadyPresent(ToolStatus),

    /// Installed now. `path` is the install pipeline's destination (the
    /// authority on what was written); `version` comes from a post-install
    /// [`Detector`] re-probe — the pipeline returns only the path, its
    /// internally resolved concrete version is discarded — and is `None`
    /// in the rare case the fresh binary refuses both version flags. The
    /// install itself succeeded either way.
    Installed {
        /// The path the installer wrote.
        path: Utf8PathBuf,

        /// Best-effort version of the freshly installed copy.
        version: Option<ToolVersion>,
    },
}

/// Whether an already-detected copy satisfies the requested `version`.
///
/// - `"latest"`: always satisfied. Deciding whether a newer release exists
///   needs a network lookup by definition, so an existing copy is kept —
///   callers wanting upgrade-if-stale compose `detect` + `latest` +
///   [`Freshness`] and install explicitly.
/// - A pinned semver: satisfied when the detected version parses and is
///   `>=` the request. A `v`-prefixed request (`v1.2.3`) is accepted,
///   matching the resolvers' tag-prefix normalization. An unprobeable
///   detected version is never satisfied — the install runs rather than
///   guessing the copy is fine.
/// - Anything else (no semver in the request): never satisfied; the install
///   is attempted and the resolver's verdict surfaces.
///
/// Precondition: `status.is_installed()` — `ensure_installed` checks that
/// before consulting this.
///
/// `pub(crate)`: the per-tool ensure paths (`ensure_mise`) replicate the
/// detect-first flow so their misses can route through the checksum-pinning
/// per-tool installer, and must keep the same satisfaction rule.
///
/// Gated behind `http`: its only callers are the install-on-miss paths,
/// which need the engine.
#[cfg(feature = "http")]
pub(crate) fn version_satisfied(status: &ToolStatus, requested: &str) -> bool {
    if requested == "latest" {
        return true;
    }
    let pinned = requested.strip_prefix('v').unwrap_or(requested);
    let Ok(pinned) = semver::Version::parse(pinned) else {
        return false;
    };
    status.version().is_some_and(|v| v.is_at_least(&pinned))
}

/// The body of [`ensure_installed`], split out so tests can drive the
/// decision table through a [`Detector`] with an injected (fake) runner.
#[cfg(feature = "http")]
async fn ensure_with_detector(
    detector: &Detector,
    tool: &Tool,
    target: Target,
    version: &str,
    install_dir: Option<&Utf8PathBuf>,
    resolver: &(dyn ReleaseResolver + Send + Sync),
) -> Result<EnsureOutcome> {
    // 1. detect first — offline, never errors, and via `detect_async`: the
    //    version probe spawns subprocesses and must not run on an async
    //    runtime worker.
    let status = detector.detect_async(tool).await;

    // 2. a copy that satisfies the request is kept as-is, zero network.
    if status.is_installed() && version_satisfied(&status, version) {
        return Ok(EnsureOutcome::AlreadyPresent(status));
    }

    // 3. a true miss: run the install pipeline with the caller's resolver,
    //    then re-detect for the freshly installed version. In a shadowed
    //    environment the re-probe reports whichever copy `detect`
    //    classifies (the same one a subsequent ensure would keep). The
    //    re-probe goes through `detect_async` for the same reason.
    let path = Installer::new()
        .install_with_resolver(tool, target, version, install_dir, resolver)
        .await?;
    let version = detector.detect_async(tool).await.version().cloned();
    Ok(EnsureOutcome::Installed { path, version })
}

/// Detect-first install: install-on-missing with
/// version-check-before-install.
///
/// 1. A [`Detector`] honoring `install_dir` classifies `tool` — offline,
///    never errors.
/// 2. If a copy is installed and the request is satisfied by it —
///    `version == "latest"` (comparing against the newest release needs
///    network by definition, so an existing copy is kept), or a pinned
///    semver the detected version parses and meets (`>=`; a `v` tag prefix
///    is accepted) — return [`EnsureOutcome::AlreadyPresent`] with **zero
///    network**: the resolver is never consulted.
/// 3. Otherwise run the install pipeline with the caller's `resolver`,
///    then re-detect for the installed version (hence
///    [`EnsureOutcome::Installed`]'s `Option<ToolVersion>`).
///
/// The satisfaction check is deliberately conservative: a pinned request
/// against a copy whose version cannot be probed re-installs rather than
/// guessing. `ensure_installed` never spends network to *keep* a copy,
/// only to obtain one.
///
/// # Errors
///
/// Everything the install pipeline can return — the full
/// [`Error`](crate::Error) surface: `MissingConfig` (descriptor
/// validation), `Resolve`, `Download`, `DownloadStalled`, `HttpStatus`,
/// `TooLarge`, `TooSmall`, `ChecksumMismatch`, `NoChecksumEntry`,
/// `NoChecksum`, `Archive`, `EntryNotFound`, `Io`, `NoHomeDir` and
/// `BlockingJoin`. Detection and the version probe never error, so a
/// request satisfied by an installed copy cannot fail.
#[cfg(feature = "http")]
pub async fn ensure_installed(
    tool: &Tool,
    target: Target,
    version: &str,
    install_dir: Option<&Utf8PathBuf>,
    resolver: &(dyn ReleaseResolver + Send + Sync),
) -> Result<EnsureOutcome> {
    // The detector must look in the same directory the install writes to,
    // so "where we look" cannot drift from "where we install".
    let mut builder = Detector::builder();
    if let Some(dir) = install_dir {
        builder = builder.install_dir(dir);
    }
    ensure_with_detector(
        &builder.build(),
        tool,
        target,
        version,
        install_dir,
        resolver,
    )
    .await
}

/// Classify a discovered `$PATH` hit against the managed install path.
///
/// The PATH hit wins: canonicalized-equal to the managed path -> `Managed`
/// (reporting the managed path); any other hit -> `OnPath`; no hit but the
/// managed file exists -> `Managed`; otherwise `None` (nothing installed).
fn classify(
    path_hit: Option<Utf8PathBuf>,
    managed: Option<Utf8PathBuf>,
) -> Option<(Utf8PathBuf, ToolSource)> {
    match (path_hit, managed) {
        (Some(hit), Some(managed)) if same_file(hit.as_std_path(), managed.as_std_path()) => {
            Some((managed, ToolSource::Managed))
        }
        (Some(hit), _) => Some((hit, ToolSource::Path)),
        (None, Some(managed)) if managed.is_file() => Some((managed, ToolSource::Managed)),
        _ => None,
    }
}

/// Whether `a` and `b` refer to the same directory entry, compared by
/// canonicalized path with a literal-equality fallback.
///
/// Canonicalized equality (not inode comparison) is deliberate: the
/// installer writes binaries via temp-file + rename, so an upgrade replaces
/// the inode and silently orphans any hard link. A hard-linked `$PATH` copy
/// of the managed binary is therefore a *stale shadow* (`OnPath`), not the
/// managed copy — inode equality would misreport it as `Managed`. When
/// either side cannot be canonicalized (typically: the file does not
/// exist), literal path equality decides so classification stays total.
fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(canon_a), Ok(canon_b)) => canon_a == canon_b,
        _ => a == b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::TempDir;
    use toride_runner::error::Error as RunnerError;
    use toride_runner::{CommandOutput, FakeRunner};

    /// A bin name no real `$PATH` carries — the hermetic tests rely on
    /// `find_binary` missing it.
    const BIN: &str = "toride-test-demotool";

    /// A tempdir's path as `Utf8PathBuf` (tempdirs are UTF-8 on CI hosts).
    fn utf8_dir(dir: &TempDir) -> Utf8PathBuf {
        Utf8PathBuf::from_path_buf(dir.path().to_owned()).expect("tempdir path is utf-8")
    }

    /// A `Tool` managed at `<dir>/toride-test-demotool` plus a real dummy
    /// executable file there — the managed arm exists on disk, off `$PATH`.
    fn managed_tool(dir: &TempDir) -> Tool {
        let root = utf8_dir(dir);
        let bin = root.join(BIN);
        std::fs::write(&bin, b"#!/bin/sh\nexit 0\n").expect("write dummy executable");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))
                .expect("chmod dummy executable");
        }
        Tool::builder()
            .name(BIN)
            .bin_name(BIN)
            .default_install_dir(root)
            .build()
            .expect("valid tool descriptor")
    }

    /// The exact version-probe spec `Detector` issues — used both to
    /// register `FakeRunner` responses (which ignore `timeout` when
    /// matching) and to assert on recorded calls. Must mirror
    /// `probe_version`: exact matching compares the null-stdin wiring too,
    /// so a detector that stops carrying it fails every strict test here.
    fn probe_spec(path: &Utf8Path, arg: &str) -> CommandSpec {
        CommandSpec::new(path.as_str())
            .arg(arg)
            .timeout(DEFAULT_PROBE_TIMEOUT)
            .stdin_null(true)
    }

    /// Shorthand: parse with an arbitrary bin name.
    fn tv(output: &str) -> ToolVersion {
        ToolVersion::parse(output, "tool")
    }

    /// A `Tool` with a distinctive `name` — the key [`LatestCache`] uses.
    fn named_tool(name: &str) -> Tool {
        Tool::builder()
            .name(name)
            .bin_name(name)
            .build()
            .expect("valid tool descriptor")
    }

    // -----------------------------------------------------------------------
    // Version probing through the injected Runner (strict FakeRunner)
    // -----------------------------------------------------------------------

    #[test]
    fn detect_probes_long_version_flag_first() {
        let tmp = TempDir::new().unwrap();
        let tool = managed_tool(&tmp);
        let managed = Detector::managed_path(&tool, None).unwrap();

        let stdout = format!("{BIN} version 1.2.3");
        let fake = FakeRunner::new().strict().respond(
            probe_spec(&managed, "--version"),
            CommandOutput::from_stdout(stdout.clone()),
        );
        let status = Detector::with_runner(Arc::new(fake.clone())).detect(&tool);

        assert_eq!(
            status,
            ToolStatus::Managed {
                path: managed,
                version: Some(ToolVersion::parse(&stdout, BIN)),
            }
        );
        assert_eq!(
            fake.calls().len(),
            1,
            "a --version hit must not trigger the -V fallback"
        );
    }

    #[test]
    fn detect_falls_back_to_short_version_flag() {
        let tmp = TempDir::new().unwrap();
        let tool = managed_tool(&tmp);
        let managed = Detector::managed_path(&tool, None).unwrap();

        // Only `-V` is registered; in strict mode the unmatched `--version`
        // probe errors and must degrade to the fallback, not poison detect.
        let fake = FakeRunner::new().strict().respond(
            probe_spec(&managed, "-V"),
            CommandOutput::from_stdout(format!("{BIN} 2.0.0")),
        );
        let status = Detector::with_runner(Arc::new(fake.clone())).detect(&tool);

        let version = status.version().expect("-V-only tools keep their version");
        assert_eq!(version.raw, "2.0.0");
        assert_eq!(fake.calls().len(), 2);
        assert_eq!(fake.calls()[0].args, ["--version"]);
        assert_eq!(fake.calls()[1].args, ["-V"]);
    }

    #[test]
    fn detect_degrades_to_none_when_both_probes_time_out() {
        let tmp = TempDir::new().unwrap();
        let tool = managed_tool(&tmp);
        let managed = Detector::managed_path(&tool, None).unwrap();

        let timeout_err = |arg: &str| RunnerError::CommandTimeout {
            program: managed.as_str().to_owned(),
            args: vec![arg.to_owned()],
            timeout: DEFAULT_PROBE_TIMEOUT,
        };
        let fake = FakeRunner::new()
            .strict()
            .respond_err(probe_spec(&managed, "--version"), timeout_err("--version"))
            .respond_err(probe_spec(&managed, "-V"), timeout_err("-V"));
        let status = Detector::with_runner(Arc::new(fake)).detect(&tool);

        assert_eq!(
            status.source(),
            Some(ToolSource::Managed),
            "presence is the path probe's verdict, not the version probe's"
        );
        assert_eq!(status.version(), None);
    }

    #[test]
    fn detect_falls_through_when_version_flag_exits_nonzero() {
        let tmp = TempDir::new().unwrap();
        let tool = managed_tool(&tmp);
        let managed = Detector::managed_path(&tool, None).unwrap();

        let fake = FakeRunner::new()
            .strict()
            .respond(
                probe_spec(&managed, "--version"),
                CommandOutput::from_stderr("refused", 1),
            )
            .respond(
                probe_spec(&managed, "-V"),
                CommandOutput::from_stdout("3.1.4"),
            );
        let status = Detector::with_runner(Arc::new(fake)).detect(&tool);

        // `Runner::run` (not run_checked): a non-zero exit degrades, and the
        // search continues to the next flag.
        assert_eq!(status.version().map(|v| v.raw.as_str()), Some("3.1.4"));
    }

    #[test]
    fn detect_falls_through_on_whitespace_only_stdout() {
        let tmp = TempDir::new().unwrap();
        let tool = managed_tool(&tmp);
        let managed = Detector::managed_path(&tool, None).unwrap();

        let fake = FakeRunner::new()
            .strict()
            .respond(
                probe_spec(&managed, "--version"),
                CommandOutput::from_stdout("  \n\t\n"),
            )
            .respond(
                probe_spec(&managed, "-V"),
                CommandOutput::from_stdout("0.9.9"),
            );
        let status = Detector::with_runner(Arc::new(fake)).detect(&tool);

        assert_eq!(status.version().map(|v| v.raw.as_str()), Some("0.9.9"));
    }

    #[test]
    fn detect_not_installed_skips_probe() {
        // Strict runner with NO responses: any version probe would error and
        // fail the test — so reaching NotInstalled proves no probe fired.
        let fake = FakeRunner::new().strict();
        let detector = Detector::with_runner(Arc::new(fake.clone()));
        let tool = Tool::builder()
            .name("toride-test-absent")
            .bin_name("toride-test-absent")
            .build()
            .unwrap();

        assert_eq!(detector.detect(&tool), ToolStatus::NotInstalled);
        assert!(fake.calls().is_empty());
    }

    #[test]
    fn detector_default_runs_offline_and_reports_missing_tool() {
        // `Detector::new` wires the real (duct) runner; a missing tool is
        // classified without spawning anything.
        let tool = Tool::builder()
            .name("toride-test-absent")
            .bin_name("toride-test-absent")
            .build()
            .unwrap();
        assert_eq!(Detector::new().detect(&tool), ToolStatus::NotInstalled);
        assert_eq!(Detector::default().detect(&tool), ToolStatus::NotInstalled);
    }

    #[cfg(unix)]
    #[test]
    fn detect_probe_hands_the_child_eof_not_the_callers_stdin() {
        // End-to-end pin of the null-stdin probe wiring through the real
        // default runner: the fixture reads stdin BEFORE answering, so it can
        // only report a version if the probe handed it EOF. Under inherited
        // stdin the fixture blocks on the harness's stdin until the probe
        // timeout and this assert fails; on a harness whose stdin is already
        // at EOF (CI) the test is vacuous but harmless.
        let tmp = TempDir::new().unwrap();
        let dir = utf8_dir(&tmp);
        let bin = dir.join(BIN);
        std::fs::write(
            &bin,
            format!("#!/bin/sh\nhead -n 1 >/dev/null\necho \"{BIN} version 7.7.7\"\n"),
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))
                .expect("chmod dummy script");
        }
        let tool = Tool::builder()
            .name(BIN)
            .bin_name(BIN)
            .default_install_dir(dir)
            .build()
            .expect("valid tool descriptor");

        let status = Detector::new().detect(&tool);

        let version = status
            .version()
            .expect("a stdin-reading binary must still answer under a null stdin");
        assert_eq!(version.raw, "7.7.7");
    }

    // -----------------------------------------------------------------------
    // Classification: same_file + the four precedence arms (hermetic)
    // -----------------------------------------------------------------------

    #[test]
    fn same_file_true_for_canonical_equivalents() {
        let tmp = TempDir::new().unwrap();
        let file = utf8_dir(&tmp).join(BIN);
        std::fs::write(&file, b"x").unwrap();
        let detour = utf8_dir(&tmp).join(".").join(BIN);
        assert!(same_file(file.as_std_path(), detour.as_std_path()));
    }

    #[cfg(unix)]
    #[test]
    fn same_file_true_through_symlink() {
        let tmp = TempDir::new().unwrap();
        let dir = utf8_dir(&tmp);
        let file = dir.join(BIN);
        std::fs::write(&file, b"x").unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(same_file(file.as_std_path(), link.as_std_path()));
    }

    #[cfg(unix)]
    #[test]
    fn same_file_false_for_hardlinks() {
        // Pins the canonicalized-equality semantics: two hardlinks share an
        // inode but not a directory entry, and installs replace the file by
        // rename (orphaning links), so a hardlinked PATH copy classifies as
        // a shadow, not as the managed copy.
        let tmp = TempDir::new().unwrap();
        let dir = utf8_dir(&tmp);
        let file = dir.join(BIN);
        std::fs::write(&file, b"x").unwrap();
        let hardlink = dir.join("hardlink");
        std::fs::hard_link(&file, &hardlink).unwrap();
        assert!(!same_file(file.as_std_path(), hardlink.as_std_path()));
    }

    #[test]
    fn same_file_literal_fallback_when_missing() {
        let a = Path::new("/nonexistent-toride-test/tool");
        let b = Path::new("/nonexistent-toride-test/other");
        assert!(same_file(a, a));
        assert!(!same_file(a, b));
    }

    #[test]
    fn classify_managed_when_path_hit_equals_managed() {
        // Neither side exists, so canonicalization fails and the literal
        // equality fallback decides — the arm still classifies as Managed.
        let missing = Utf8PathBuf::from("/nonexistent-toride-test/tool");
        assert_eq!(
            classify(Some(missing.clone()), Some(missing.clone())),
            Some((missing, ToolSource::Managed))
        );
    }

    #[test]
    fn classify_on_path_when_path_hit_differs() {
        let hit = Utf8PathBuf::from("/nonexistent-toride-test/other-tool");
        let managed = Utf8PathBuf::from("/nonexistent-toride-test/tool");
        assert_eq!(
            classify(Some(hit.clone()), Some(managed)),
            Some((hit, ToolSource::Path))
        );
    }

    #[test]
    fn classify_managed_when_only_managed_file_exists() {
        let tmp = TempDir::new().unwrap();
        let managed = utf8_dir(&tmp).join(BIN);
        std::fs::write(&managed, b"x").unwrap();
        assert_eq!(
            classify(None, Some(managed.clone())),
            Some((managed, ToolSource::Managed))
        );
    }

    #[test]
    fn classify_none_when_no_hit_and_no_managed_file() {
        let missing = Utf8PathBuf::from("/nonexistent-toride-test/tool");
        assert_eq!(classify(None, Some(missing)), None);
        assert_eq!(classify(None, None), None);
    }

    #[test]
    fn classify_path_only_when_managed_arm_is_absent() {
        // The degrade when `resolve_install_dir` errors (no home dir, no
        // default): a PATH hit classifies OnPath with no managed arm in play.
        let hit = Utf8PathBuf::from("/nonexistent-toride-test/tool");
        assert_eq!(
            classify(Some(hit.clone()), None),
            Some((hit, ToolSource::Path))
        );
    }

    // -----------------------------------------------------------------------
    // detect() end-to-end over the managed arm (tempdir + FakeRunner)
    // -----------------------------------------------------------------------

    #[test]
    fn detect_reports_managed_copy_found_off_path() {
        let tmp = TempDir::new().unwrap();
        let tool = managed_tool(&tmp);
        let managed = Detector::managed_path(&tool, None).unwrap();

        let stdout = format!("{BIN} version 1.2.3");
        let fake = FakeRunner::new().strict().respond(
            probe_spec(&managed, "--version"),
            CommandOutput::from_stdout(stdout.clone()),
        );
        let status = Detector::with_runner(Arc::new(fake)).detect(&tool);

        assert_eq!(status.source(), Some(ToolSource::Managed));
        assert_eq!(status.path(), Some(&managed));
        let version = status.version().unwrap();
        assert_eq!(version.raw, "1.2.3");
        assert_eq!(
            version.line, stdout,
            "line preserves the full trimmed output line"
        );
    }

    #[test]
    fn detect_reports_managed_copy_with_unknown_version() {
        // Lenient FakeRunner: unmatched probes return empty success output,
        // so both flags "run" but yield no version line.
        let tmp = TempDir::new().unwrap();
        let tool = managed_tool(&tmp);
        let status = Detector::with_runner(Arc::new(FakeRunner::new())).detect(&tool);

        assert_eq!(status.source(), Some(ToolSource::Managed));
        assert_eq!(status.version(), None);
    }

    #[test]
    fn detector_install_dir_override_wins_over_tool_default() {
        let tool_dir = TempDir::new().unwrap();
        let override_dir = TempDir::new().unwrap();
        let tool = managed_tool(&tool_dir); // dummy file under the tool default
        let overridden = utf8_dir(&override_dir).join(BIN);
        std::fs::write(&overridden, b"x").unwrap();

        let fake = FakeRunner::new().strict().respond(
            probe_spec(&overridden, "--version"),
            CommandOutput::from_stdout("1.0.0"),
        );
        let status = Detector::builder()
            .runner(Arc::new(fake.clone()))
            .install_dir(utf8_dir(&override_dir))
            .build()
            .detect(&tool);

        assert_eq!(status.source(), Some(ToolSource::Managed));
        assert_eq!(status.path(), Some(&overridden));
        // The probe ran against the overridden path, not the tool default.
        assert_eq!(fake.calls()[0].program, overridden.as_str());
    }

    #[tokio::test]
    async fn detect_async_matches_detect() {
        let tmp = TempDir::new().unwrap();
        let tool = managed_tool(&tmp);
        let managed = Detector::managed_path(&tool, None).unwrap();

        let stdout = "1.2.3";
        // Exact responses are consumed once per match, and this test detects
        // twice (async + sync) — register the response for both probes.
        let fake = FakeRunner::new()
            .strict()
            .respond(
                probe_spec(&managed, "--version"),
                CommandOutput::from_stdout(stdout),
            )
            .respond(
                probe_spec(&managed, "--version"),
                CommandOutput::from_stdout(stdout),
            );
        let detector = Detector::with_runner(Arc::new(fake));

        assert_eq!(detector.detect_async(&tool).await, detector.detect(&tool));
    }

    /// ENVIRONMENTAL smoke test: hits the real `$PATH` (never mutated here)
    /// and runs a real `--version` probe on the host's `ls`, mirroring the
    /// discovery module's own `ls`-exists test. The version is deliberately
    /// unasserted — GNU `ls` answers `--version` while BSD `ls` may refuse
    /// both flags, and presence must not depend on the probe.
    #[cfg(unix)]
    #[test]
    fn detect_classifies_ls_on_path_environmental() {
        let tool = Tool::builder().name("ls").bin_name("ls").build().unwrap();
        let status = Detector::new().detect(&tool);

        assert!(status.is_installed());
        assert_eq!(status.source(), Some(ToolSource::Path));
        let path = status.path().expect("OnPath carries a path");
        assert!(path.as_str().ends_with("ls"), "unexpected path: {path}");
    }

    // -----------------------------------------------------------------------
    // Detector::managed_path — the resolve_install_dir precedence
    // -----------------------------------------------------------------------

    #[test]
    fn managed_path_honors_explicit_override() {
        let tmp = TempDir::new().unwrap();
        let dir = utf8_dir(&tmp);
        let tool = Tool::builder().name("t").bin_name(BIN).build().unwrap();
        assert_eq!(
            Detector::managed_path(&tool, Some(&dir)).unwrap(),
            dir.join(BIN)
        );
    }

    #[test]
    fn managed_path_uses_tool_default_dir() {
        let tmp = TempDir::new().unwrap();
        let dir = utf8_dir(&tmp);
        let tool = Tool::builder()
            .name("t")
            .bin_name(BIN)
            .default_install_dir(dir.clone())
            .build()
            .unwrap();
        assert_eq!(Detector::managed_path(&tool, None).unwrap(), dir.join(BIN));
    }

    #[test]
    fn managed_path_falls_back_to_local_bin() {
        let tool = Tool::builder().name("t").bin_name(BIN).build().unwrap();
        let path = Detector::managed_path(&tool, None).unwrap();
        assert!(
            path.as_str().ends_with(&format!(".local/bin/{BIN}")),
            "unexpected managed path: {path}"
        );
    }

    // -----------------------------------------------------------------------
    // ToolVersion::parse table
    // -----------------------------------------------------------------------

    #[test]
    fn parse_real_mise_output_shape() {
        let v = ToolVersion::parse("2026.5.18 macos-arm64 (2026-05-31)", "mise");
        assert_eq!(v.line, "2026.5.18 macos-arm64 (2026-05-31)");
        assert_eq!(v.raw, "2026.5.18");
        let parsed = v.parsed.expect("date-based version parses");
        assert_eq!((parsed.major, parsed.minor, parsed.patch), (2026, 5, 18));
    }

    #[test]
    fn parse_strips_name_version_prefix() {
        let v = ToolVersion::parse("mytool version 1.2.3 (rev abc1234)", "mytool");
        assert_eq!(v.line, "mytool version 1.2.3 (rev abc1234)");
        assert_eq!(v.raw, "1.2.3");
        assert_eq!(v.parsed, Some(semver::Version::new(1, 2, 3)));
    }

    #[test]
    fn parse_strips_bare_name_prefix() {
        let v = ToolVersion::parse("fd 1.2.3", "fd");
        assert_eq!(v.raw, "1.2.3");
        assert_eq!(v.parsed, Some(semver::Version::new(1, 2, 3)));
    }

    #[test]
    fn parse_bare_version_output() {
        let v = ToolVersion::parse("1.2.3", "anything");
        assert_eq!(v.line, "1.2.3");
        assert_eq!(v.raw, "1.2.3");
        assert_eq!(v.parsed, Some(semver::Version::new(1, 2, 3)));
    }

    #[test]
    fn parse_date_version_as_semver() {
        let v = ToolVersion::parse("2026.9.1", "mise");
        let parsed = v.parsed.expect("date versions are valid semver");
        assert_eq!(parsed.major, 2026);
        assert_eq!(parsed.minor, 9);
        assert_eq!(parsed.patch, 1);
    }

    #[test]
    fn parse_trims_first_non_empty_line() {
        // Trim parity: the UI renders exactly this trimmed line.
        let v = ToolVersion::parse("  \n\t mise 2024.1.2 \t\n", "mise");
        assert_eq!(v.line, "mise 2024.1.2");
        assert_eq!(v.raw, "2024.1.2");
    }

    #[test]
    fn parse_first_line_wins() {
        let v = ToolVersion::parse("banner\n1.2.3\n", "tool");
        assert_eq!(v.line, "banner");
        assert_eq!(v.raw, "banner");
        assert!(v.parsed.is_none());
    }

    #[test]
    fn parse_garbage_stays_unparsed() {
        let v = ToolVersion::parse("definitely not a version", "tool");
        assert_eq!(v.line, "definitely not a version");
        assert_eq!(v.raw, "definitely");
        assert!(v.parsed.is_none());
    }

    #[test]
    fn parse_does_not_strip_partial_name_prefix() {
        // "mystery" merely extends bin_name "mist" — no separator, no strip.
        let v = ToolVersion::parse("mystery 1.2.3", "mist");
        assert_eq!(v.raw, "mystery");
        assert!(v.parsed.is_none());
    }

    #[test]
    fn is_at_least_compares_parsed_versions() {
        let v = ToolVersion::parse("2026.9.1", "mise");
        assert!(v.is_at_least(&semver::Version::new(2026, 9, 0)));
        assert!(!v.is_at_least(&semver::Version::new(2026, 9, 2)));
        assert!(
            v.is_at_least(&semver::Version::new(2026, 9, 1)),
            "equal counts as at-least"
        );
    }

    #[test]
    fn is_at_least_is_conservative_when_unparsed() {
        let v = ToolVersion::parse("unknown", "tool");
        assert!(!v.is_at_least(&semver::Version::new(0, 0, 1)));
    }

    // -----------------------------------------------------------------------
    // Freshness::evaluate table
    // -----------------------------------------------------------------------

    #[test]
    fn freshness_current_when_installed_meets_latest() {
        let status = ToolStatus::Managed {
            path: Utf8PathBuf::from("/nonexistent-toride-test/tool"),
            version: Some(tv("1.2.3")),
        };
        assert_eq!(
            Freshness::evaluate(&status, &tv("1.2.3")),
            Freshness::Current
        );
        assert_eq!(
            Freshness::evaluate(&status, &tv("1.2.0")),
            Freshness::Current
        );
    }

    #[test]
    fn freshness_stale_carries_both_versions() {
        let status = ToolStatus::Managed {
            path: Utf8PathBuf::from("/nonexistent-toride-test/tool"),
            version: Some(tv("1.0.0")),
        };
        match Freshness::evaluate(&status, &tv("2.0.0")) {
            Freshness::Stale { installed, latest } => {
                assert_eq!(installed.raw, "1.0.0");
                assert_eq!(latest.raw, "2.0.0");
            }
            other => panic!("expected Stale, got {other:?}"),
        }
    }

    #[test]
    fn freshness_unknown_when_not_installed() {
        assert_eq!(
            Freshness::evaluate(&ToolStatus::NotInstalled, &tv("1.0.0")),
            Freshness::Unknown
        );
    }

    #[test]
    fn freshness_unknown_when_version_missing() {
        let status = ToolStatus::OnPath {
            path: Utf8PathBuf::from("/nonexistent-toride-test/tool"),
            version: None,
        };
        assert_eq!(
            Freshness::evaluate(&status, &tv("1.0.0")),
            Freshness::Unknown
        );
    }

    #[test]
    fn freshness_unknown_when_installed_unparseable() {
        let status = ToolStatus::Managed {
            path: Utf8PathBuf::from("/nonexistent-toride-test/tool"),
            version: Some(tv("nonsense")),
        };
        assert_eq!(
            Freshness::evaluate(&status, &tv("1.0.0")),
            Freshness::Unknown
        );
    }

    #[test]
    fn freshness_unknown_when_latest_unparseable() {
        // "Never Stale on a guess": an unparseable latest cannot be compared.
        let status = ToolStatus::Managed {
            path: Utf8PathBuf::from("/nonexistent-toride-test/tool"),
            version: Some(tv("1.0.0")),
        };
        assert_eq!(
            Freshness::evaluate(&status, &tv("nonsense")),
            Freshness::Unknown
        );
    }

    // -----------------------------------------------------------------------
    // ToolStatus accessors
    // -----------------------------------------------------------------------

    #[test]
    fn tool_status_accessors() {
        let not_installed = ToolStatus::NotInstalled;
        assert!(!not_installed.is_installed());
        assert!(not_installed.path().is_none());
        assert!(not_installed.version().is_none());
        assert!(not_installed.source().is_none());

        let path = Utf8PathBuf::from("/nonexistent-toride-test/tool");
        let on_path = ToolStatus::OnPath {
            path: path.clone(),
            version: Some(tv("1.0.0")),
        };
        assert!(on_path.is_installed());
        assert_eq!(on_path.path(), Some(&path));
        assert_eq!(on_path.version().map(|v| v.raw.as_str()), Some("1.0.0"));
        assert_eq!(on_path.source(), Some(ToolSource::Path));
    }

    // -----------------------------------------------------------------------
    // latest() + LatestCache — local stub resolver, zero network
    // -----------------------------------------------------------------------

    /// Canned [`ReleaseResolver`] for the `latest`/cache/ensure tests: each
    /// call pops the next outcome — `Some(version)` resolves, `None`
    /// errors — and the last outcome repeats on any extra call. Counts
    /// invocations and records every requested version; no HTTP, no TCP.
    struct StubResolver {
        outcomes: Mutex<Vec<Option<String>>>,
        calls: AtomicUsize,
        requests: Mutex<Vec<String>>,
    }

    impl StubResolver {
        /// One canned outcome, repeated forever.
        fn new(outcomes: Vec<Option<String>>) -> Self {
            Self {
                outcomes: Mutex::new(outcomes),
                calls: AtomicUsize::new(0),
                requests: Mutex::new(Vec::new()),
            }
        }

        /// Every call resolves to `version`.
        fn resolving(version: &str) -> Self {
            Self::new(vec![Some(version.to_owned())])
        }

        /// Calls resolve to `versions` in order; the last one repeats.
        fn resolving_in_order(versions: &[&str]) -> Self {
            Self::new(versions.iter().map(|v| Some((*v).to_owned())).collect())
        }

        /// The first call fails (a stubbed rate limit); later calls resolve
        /// to `version`.
        fn failing_then_resolving(version: &str) -> Self {
            Self::new(vec![None, Some(version.to_owned())])
        }

        /// Every call fails.
        fn always_failing() -> Self {
            Self::new(vec![None])
        }

        fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        /// Every version string the resolver was asked for, in order.
        fn requested_versions(&self) -> Vec<String> {
            self.requests.lock().expect("stub mutex poisoned").clone()
        }
    }

    #[async_trait::async_trait]
    impl ReleaseResolver for StubResolver {
        async fn resolve(&self, target: Target, version: &str) -> Result<(String, String)> {
            // The caller's target flows through unchanged (pinned for every
            // user of this stub: `latest`, the cache, and ensure).
            assert_eq!(
                target,
                Target::host().expect("test host is a supported target"),
                "the caller must resolve for the host target"
            );
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.requests
                .lock()
                .expect("stub mutex poisoned")
                .push(version.to_owned());
            let mut outcomes = self.outcomes.lock().expect("stub mutex poisoned");
            let outcome = if outcomes.len() > 1 {
                outcomes.remove(0)
            } else {
                outcomes[0].clone()
            };
            let concrete = outcome.ok_or_else(|| crate::Error::Resolve {
                tool: "stub".to_owned(),
                reason: "stubbed release-API failure".to_owned(),
            })?;
            Ok((concrete.clone(), format!("https://stub.invalid/{concrete}")))
        }
    }

    #[tokio::test]
    async fn latest_converts_concrete_version_and_discards_url() {
        let resolver = StubResolver::resolving("2026.6.14");

        let version = latest(&resolver).await.expect("stub resolves");

        assert_eq!(version.line, "2026.6.14");
        assert_eq!(version.raw, "2026.6.14");
        assert_eq!(version.parsed, Some(semver::Version::new(2026, 6, 14)));
        assert_eq!(
            resolver.call_count(),
            1,
            "latest() is exactly one resolve call"
        );
        assert_eq!(
            resolver.requested_versions(),
            ["latest"],
            "latest() must request exactly `latest`"
        );
    }

    #[tokio::test]
    async fn latest_propagates_resolver_error_without_new_variants() {
        let resolver = StubResolver::always_failing();

        let err = latest(&resolver).await.expect_err("stub always fails");

        assert!(
            matches!(err, crate::Error::Resolve { .. }),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn cache_get_within_ttl_does_not_reinvoke_resolver() {
        let resolver = StubResolver::resolving("1.0.0");
        let mut cache = LatestCache::new(Duration::from_secs(3600));
        let tool = named_tool("cache-fresh-tool");

        let first = cache.get(&tool, &resolver).await.unwrap();
        let second = cache.get(&tool, &resolver).await.unwrap();

        assert_eq!(first.raw, "1.0.0");
        assert_eq!(second, first);
        assert_eq!(
            resolver.call_count(),
            1,
            "a get within the TTL must be served from the cache"
        );
    }

    #[tokio::test]
    async fn cache_get_after_ttl_expiry_reinvokes_resolver() {
        // Deterministic without a mock clock: tokio's sleep guarantees at
        // least the requested duration, so afterwards the entry is
        // certainly older than the TTL. (A mock clock would need
        // tokio::time::Instant in LatestCache; the plan pins std Instant.)
        let resolver = StubResolver::resolving_in_order(&["1.0.0", "2.0.0"]);
        let mut cache = LatestCache::new(Duration::from_millis(20));
        let tool = named_tool("cache-expiry-tool");

        let first = cache.get(&tool, &resolver).await.unwrap();
        assert_eq!(first.raw, "1.0.0");

        tokio::time::sleep(Duration::from_millis(60)).await;

        let second = cache.get(&tool, &resolver).await.unwrap();
        assert_eq!(second.raw, "2.0.0", "an expired entry must be refetched");
        assert_eq!(resolver.call_count(), 2);
    }

    #[tokio::test]
    async fn cache_miss_error_is_not_cached() {
        // A failed lookup (e.g. a rate limit) must not poison the cache:
        // the next get retries the resolver instead of replaying the error
        // for the whole TTL.
        let resolver = StubResolver::failing_then_resolving("1.2.3");
        let mut cache = LatestCache::new(Duration::from_secs(3600));
        let tool = named_tool("cache-error-tool");

        assert!(cache.get(&tool, &resolver).await.is_err());

        let retried = cache.get(&tool, &resolver).await.unwrap();
        assert_eq!(retried.raw, "1.2.3");
        assert_eq!(resolver.call_count(), 2);
    }

    #[tokio::test]
    async fn cache_keys_entries_per_tool() {
        let resolver = StubResolver::resolving("3.0.0");
        let mut cache = LatestCache::new(Duration::from_secs(3600));
        let first = named_tool("cache-tool-a");
        let second_tool = named_tool("cache-tool-b");

        let a = cache.get(&first, &resolver).await.unwrap();
        let b = cache.get(&second_tool, &resolver).await.unwrap();
        let a_again = cache.get(&first, &resolver).await.unwrap();

        assert_eq!(a.raw, "3.0.0");
        assert_eq!(b.raw, "3.0.0");
        assert_eq!(a_again, a);
        assert_eq!(
            resolver.call_count(),
            2,
            "each tool name gets its own entry"
        );
    }

    // -----------------------------------------------------------------------
    // ensure_installed — the detect-first decision table
    //
    // The ensure path runs the install pipeline on a miss, so these tests
    // need the `http` engine and ride behind the same feature.
    // -----------------------------------------------------------------------

    #[cfg(feature = "http")]
    mod ensure {
        use super::*;

        /// The host target, resolved once per test.
        fn host_target() -> Target {
            Target::host().expect("test host is a supported target")
        }

        /// A `Managed` status at the usual non-existent fixture path.
        fn managed_status(version: Option<ToolVersion>) -> ToolStatus {
            ToolStatus::Managed {
                path: Utf8PathBuf::from("/nonexistent-toride-test/tool"),
                version,
            }
        }

        #[test]
        fn version_satisfied_table() {
            let installed = managed_status(Some(tv("1.2.3")));

            assert!(version_satisfied(&installed, "latest"));
            assert!(
                version_satisfied(&installed, "1.2.3"),
                "equal counts as satisfied"
            );
            assert!(version_satisfied(&installed, "1.2.0"));
            assert!(
                version_satisfied(&installed, "v1.2.3"),
                "tag prefix accepted, matching the resolvers' normalization"
            );
            assert!(!version_satisfied(&installed, "1.3.0"));
            assert!(
                !version_satisfied(&installed, "banana"),
                "no pinned semver in the request: never satisfied"
            );
            assert!(
                !version_satisfied(&managed_status(None), "1.0.0"),
                "an unprobeable copy is never confirmed"
            );
        }

        #[tokio::test]
        async fn ensure_latest_keeps_installed_copy_without_consulting_resolver() {
            let tmp = TempDir::new().unwrap();
            let tool = managed_tool(&tmp);
            let managed = Detector::managed_path(&tool, None).unwrap();

            let stdout = format!("{BIN} version 1.2.3");
            let fake = FakeRunner::new().strict().respond(
                probe_spec(&managed, "--version"),
                CommandOutput::from_stdout(stdout.clone()),
            );
            let detector = Detector::with_runner(Arc::new(fake));
            // The stub FAILS if consulted: reaching AlreadyPresent with zero
            // calls proves the keep-copy fast path spends no network.
            let resolver = StubResolver::always_failing();

            let outcome =
                ensure_with_detector(&detector, &tool, host_target(), "latest", None, &resolver)
                    .await
                    .expect("`latest` must keep an installed copy");

            assert_eq!(
                outcome,
                EnsureOutcome::AlreadyPresent(ToolStatus::Managed {
                    path: managed,
                    version: Some(ToolVersion::parse(&stdout, BIN)),
                })
            );
            assert_eq!(resolver.call_count(), 0);
        }

        #[tokio::test]
        async fn ensure_pinned_met_keeps_installed_copy_without_consulting_resolver() {
            let tmp = TempDir::new().unwrap();
            let tool = managed_tool(&tmp);
            let managed = Detector::managed_path(&tool, None).unwrap();

            let stdout = format!("{BIN} 1.2.3");
            let fake = FakeRunner::new().strict().respond(
                probe_spec(&managed, "--version"),
                CommandOutput::from_stdout(stdout.clone()),
            );
            let detector = Detector::with_runner(Arc::new(fake));
            let resolver = StubResolver::always_failing();

            // 1.2.0 < detected 1.2.3: the pin is met by the installed copy.
            let outcome =
                ensure_with_detector(&detector, &tool, host_target(), "1.2.0", None, &resolver)
                    .await
                    .expect("a met pin must keep the installed copy");

            assert_eq!(
                outcome,
                EnsureOutcome::AlreadyPresent(ToolStatus::Managed {
                    path: managed,
                    version: Some(ToolVersion::parse(&stdout, BIN)),
                })
            );
            assert_eq!(resolver.call_count(), 0);
        }

        #[tokio::test]
        async fn ensure_v_prefixed_pinned_is_understood() {
            let tmp = TempDir::new().unwrap();
            let tool = managed_tool(&tmp);
            let managed = Detector::managed_path(&tool, None).unwrap();

            let fake = FakeRunner::new().strict().respond(
                probe_spec(&managed, "--version"),
                CommandOutput::from_stdout(format!("{BIN} 1.2.3")),
            );
            let detector = Detector::with_runner(Arc::new(fake));
            let resolver = StubResolver::always_failing();

            let outcome =
                ensure_with_detector(&detector, &tool, host_target(), "v1.2.3", None, &resolver)
                    .await
                    .expect("a v-prefixed pin met by the copy must keep it");

            assert!(matches!(outcome, EnsureOutcome::AlreadyPresent(_)));
            assert_eq!(resolver.call_count(), 0);
        }

        #[tokio::test]
        async fn ensure_pinned_unmet_runs_the_installer_with_the_callers_resolver() {
            let tmp = TempDir::new().unwrap();
            let tool = managed_tool(&tmp);
            let managed = Detector::managed_path(&tool, None).unwrap();

            let fake = FakeRunner::new().strict().respond(
                probe_spec(&managed, "--version"),
                CommandOutput::from_stdout(format!("{BIN} 1.0.0")),
            );
            let detector = Detector::with_runner(Arc::new(fake));
            // The stub fails at resolve: enough to prove the install path was
            // entered and handed the caller's resolver — the download itself is
            // exercised only by the gated integration tests (it needs network).
            let resolver = StubResolver::always_failing();

            let err =
                ensure_with_detector(&detector, &tool, host_target(), "2.0.0", None, &resolver)
                    .await
                    .expect_err("2.0.0 is newer than the installed 1.0.0: the install must run");

            assert!(
                matches!(err, crate::Error::Resolve { .. }),
                "unexpected error: {err:?}"
            );
            assert_eq!(
                resolver.call_count(),
                1,
                "the miss must consult the caller's resolver exactly once"
            );
        }

        #[tokio::test]
        async fn ensure_pinned_against_unprobeable_version_reinstalls() {
            let tmp = TempDir::new().unwrap();
            let tool = managed_tool(&tmp);
            // Lenient runner: unmatched probes return empty success output, so
            // the copy's version is unknown. A pinned request cannot be
            // confirmed — the conservative verdict is to reinstall.
            let detector = Detector::with_runner(Arc::new(FakeRunner::new()));
            let resolver = StubResolver::always_failing();

            let err =
                ensure_with_detector(&detector, &tool, host_target(), "1.0.0", None, &resolver)
                    .await
                    .expect_err("an unconfirmed version must not short-circuit the install");

            assert!(
                matches!(err, crate::Error::Resolve { .. }),
                "unexpected error: {err:?}"
            );
            assert_eq!(resolver.call_count(), 1);
        }

        #[tokio::test]
        async fn ensure_not_installed_runs_the_installer_even_for_latest() {
            // Strict runner with NO responses: any version probe would error and
            // fail the test, so a resolver consultation proves detection
            // returned NotInstalled without probing — and that `latest` does
            // not short-circuit a true miss.
            let detector = Detector::with_runner(Arc::new(FakeRunner::new().strict()));
            let tool = Tool::builder()
                .name("toride-test-absent")
                .bin_name("toride-test-absent")
                .build()
                .unwrap();
            let resolver = StubResolver::always_failing();

            let err =
                ensure_with_detector(&detector, &tool, host_target(), "latest", None, &resolver)
                    .await
                    .expect_err("a missing tool must be installed");

            assert!(
                matches!(err, crate::Error::Resolve { .. }),
                "unexpected error: {err:?}"
            );
            assert_eq!(resolver.call_count(), 1);
        }

        // -------------------------------------------------------------------
        // ensure_installed through the public entry point (default duct runner)
        // -------------------------------------------------------------------

        /// Writes a real executable script at `<dir>/<BIN>` that answers
        /// `--version` with `<BIN> version <line>` (unix-only: needs a shebang
        /// plus the executable bit).
        #[cfg(unix)]
        fn write_echoing_script(dir: &Utf8Path, version: &str) -> Utf8PathBuf {
            use std::os::unix::fs::PermissionsExt;

            let bin = dir.join(BIN);
            std::fs::write(
                &bin,
                format!("#!/bin/sh\necho \"{BIN} version {version}\"\n"),
            )
            .expect("write dummy script");
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))
                .expect("chmod dummy script");
            bin
        }

        #[cfg(unix)]
        #[tokio::test]
        async fn ensure_public_probes_the_real_binary_and_skips_resolver() {
            // No FakeRunner here: the public entry point wires its own default
            // runner, so detection probes the real script. `latest` must keep
            // the copy without ever consulting the (deliberately failing)
            // resolver.
            let tmp = TempDir::new().unwrap();
            let dir = utf8_dir(&tmp);
            let bin = write_echoing_script(&dir, "9.9.9");
            let tool = Tool::builder()
                .name(BIN)
                .bin_name(BIN)
                .default_install_dir(dir)
                .build()
                .unwrap();
            let resolver = StubResolver::always_failing();

            let outcome = ensure_installed(&tool, host_target(), "latest", None, &resolver)
                .await
                .expect("an installed copy satisfies `latest` offline");

            assert_eq!(
                outcome,
                EnsureOutcome::AlreadyPresent(ToolStatus::Managed {
                    path: bin,
                    version: Some(ToolVersion::parse(&format!("{BIN} version 9.9.9"), BIN)),
                })
            );
            assert_eq!(resolver.call_count(), 0, "zero network when a copy runs");
        }

        #[cfg(unix)]
        #[tokio::test]
        async fn ensure_public_detects_against_the_install_dir_override() {
            // The tool's default dir stays empty; the override dir carries the
            // script. ensure must build its Detector with that override —
            // proving install_dir flows into detection, not just into install.
            let tool_dir = TempDir::new().unwrap();
            let override_tmp = TempDir::new().unwrap();
            let override_dir = utf8_dir(&override_tmp);
            let bin = write_echoing_script(&override_dir, "4.0.0");
            let tool = Tool::builder()
                .name(BIN)
                .bin_name(BIN)
                .default_install_dir(utf8_dir(&tool_dir))
                .build()
                .unwrap();
            let resolver = StubResolver::always_failing();

            let outcome = ensure_installed(
                &tool,
                host_target(),
                "latest",
                Some(&override_dir),
                &resolver,
            )
            .await
            .expect("the copy in the override dir satisfies `latest`");

            assert_eq!(
                outcome,
                EnsureOutcome::AlreadyPresent(ToolStatus::Managed {
                    path: bin,
                    version: Some(ToolVersion::parse(&format!("{BIN} version 4.0.0"), BIN)),
                })
            );
            assert_eq!(resolver.call_count(), 0);
        }
    }
}
