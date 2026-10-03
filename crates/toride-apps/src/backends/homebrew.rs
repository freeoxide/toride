//! # Homebrew backend (`brew`)
//!
//! [`HomebrewBackend`] is the [`Backend`] implementation for Homebrew on
//! macOS and Linux (Linuxbrew): it executes the planner's
//! [`Operation::BrewInstall`] / [`Operation::BrewUninstall`] argv verbatim
//! through the shared [`CommandRunner`] seam, and answers list/status/
//! outdated queries from brew's `--json=v2` machine output.
//!
//! ## Split
//!
//! - **Detection surface** — [`HomebrewBackend::detect`] (PATH check via
//!   `toride-runner`'s discovery helpers), [`HomebrewBackend::version`]
//!   (`brew --version`), [`HomebrewBackend::prefix`] (`brew --prefix`,
//!   cached after the first call). Offline tests exercise the seam probes
//!   via `FakeRunner` (toride-runner's `fake` feature); the PATH check in
//!   `detect` reads the real host PATH and is only covered by live tests.
//! - **Trait operations** — install/uninstall/update/list/status per the
//!   [`Backend`] contract (guard-first, seam-only execution), plus the
//!   homebrew-specific [`HomebrewBackend::outdated`],
//!   [`HomebrewBackend::installed_version`],
//!   [`HomebrewBackend::available_version`] /
//!   [`HomebrewBackend::available_versions`] probes, and the kind-scoped
//!   [`HomebrewBackend::pin`] / [`HomebrewBackend::unpin`] pair.
//! - **JSON parsing** — `brew info --json=v2 --installed` and
//!   `brew outdated --json=v2` documents parsed into typed entries.
//!   Per-item tolerance: a malformed item (missing its identifying field,
//!   wrong JSON type) is skipped, never fatal to the whole listing — the
//!   cask/formula item shape is the same one the registry crate's API
//!   fixtures carry (every field can be `null`, unknown keys are
//!   everywhere), so unknown keys are ignored and nulls are defaults.
//!   (`brew list --json` is deliberately not used: `--formula` and
//!   `--cask` conflict on `list`, and its `--versions --json` shape is a
//!   flat `{name, version}` array behind a jq fast path — `info
//!   --installed` emits the composite envelope for both kinds in one
//!   call.)
//!
//! ## Conventions honored
//!
//! - [`ensure_install_allowed`] / [`ensure_uninstall_allowed`] /
//!   [`ensure_update_allowed`] are the first statement of the trait's
//!   mutating operations (dry-run refusal + no auto-sudo).
//! - Interactivity: brew's install/uninstall/upgrade do not prompt y/n, so
//!   unlike apt/flatpak there are **no** runtime flags layered onto the
//!   plan's canonical argv — the executed spec is exactly the planned
//!   argv. `--zap` is not an execution-time option: it is baked into the
//!   [`Operation::BrewUninstall`] argv at plan time via
//!   [`UninstallOptions`](crate::UninstallOptions) `{ zap: true }`.
//! - Error mapping: non-zero exits surface as
//!   [`Error::Command`] carrying brew's stderr;
//!   unparseable machine output maps to the same variant wrapping
//!   `toride_runner::Error::OutputParse`. Where classification is cheap —
//!   the kind-scoped `brew list --versions` probes, whose absent tokens
//!   fail *silently* at exit 1 (the normal signal) and whose rare
//!   degenerate states raise matching `Error:` lines — a failed probe
//!   becomes `Ok(None)` instead of an error (see
//!   [`HomebrewBackend::installed_version`] for both not-installed
//!   signals).
//!
//! [`Operation::BrewInstall`]: crate::Operation::BrewInstall
//! [`Operation::BrewUninstall`]: crate::Operation::BrewUninstall
//! [`ensure_install_allowed`]: crate::backend::ensure_install_allowed
//! [`ensure_uninstall_allowed`]: crate::backend::ensure_uninstall_allowed
//! [`ensure_update_allowed`]: crate::backend::ensure_update_allowed

use std::path::PathBuf;
use std::sync::Mutex;

use async_trait::async_trait;
use camino::Utf8PathBuf;
use serde::Deserialize;
use toride_registry::Os;
use toride_runner::CommandOutput;

use crate::backend::{
    Backend, BackendId, InstallOutcome, InstallRequest, InstalledApp, ListQuery, OutdatedEntry,
    UninstallOutcome, UninstallRequest, UpdateRequest, Version, ensure_install_allowed,
    ensure_uninstall_allowed, ensure_update_allowed,
};
use crate::error::{Error, Result};
use crate::plan::{Operation, Target};
use crate::runner::{CommandRunner, command};

/// The Homebrew CLI binary every command in this module targets.
const BREW: &str = "brew";

/// Markers whose presence on a brew **`Error:` line** classifies a failure
/// as "the queried item is simply not installed" rather than a real error.
/// These lines are *not* the probes' normal absent-token signal (that is a
/// silent exit 1 — see [`HomebrewBackend::installed_version`]); they fire
/// only from degenerate states (a cask whose token directory exists
/// without the cask being installed) and from other brew paths sharing the
/// wording. Matched case-insensitively against `Error:`-prefixed lines
/// only (brew's diagnostics elsewhere — warnings, context lines — may
/// mention other packages being "not installed" without the probe's item
/// being the subject); deliberately cheap — exact brew wording varies
/// across versions.
const NOT_INSTALLED_MARKERS: [&str; 3] = [
    // `Error: Cask 'x' is not installed.` (degenerate cask state)
    "not installed",
    // `Error: No available formula with the name "x".` (info/uninstall paths)
    "no available formula",
    // `Error: No installed keg or formula with the name "x".`
    "no installed keg",
];
// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

/// Homebrew [`Backend`]: executes brew install/uninstall plans and answers
/// list/status/outdated queries from brew's JSON output.
///
/// Cloning is intentionally not implemented (the prefix cache is shared
/// state); share the backend itself behind an `Arc` or `&`.
///
/// # Example
///
/// ```rust,ignore
/// use std::sync::Arc;
/// use toride_apps::CommandRunner;
/// use toride_apps::backends::homebrew::HomebrewBackend;
///
/// # async fn demo() -> toride_apps::Result<()> {
/// let runner = CommandRunner::builder().build();
/// let backend = HomebrewBackend::detect(runner)?; // brew must be on PATH
/// let entries = backend.list_entries().await?; // typed cask/formula entries
/// # let _ = Arc::new(backend);
/// # Ok(())
/// # }
/// ```
pub struct HomebrewBackend {
    /// The seam every brew command flows through.
    runner: CommandRunner,
    /// `brew --prefix` result, memoized after the first successful call —
    /// the prefix is invariant for a brew installation, and several callers
    /// (artifact links, cellar paths) want it without re-spawning brew.
    prefix: Mutex<Option<Utf8PathBuf>>,
}

impl HomebrewBackend {
    /// Create the backend over an explicit seam, with no host assumptions.
    ///
    /// This is the test-friendly constructor: the seam's runner is
    /// injectable, so every command the backend issues is fake-able.
    #[must_use]
    pub fn new(runner: CommandRunner) -> Self {
        Self {
            runner,
            prefix: Mutex::new(None),
        }
    }

    /// Create the backend after verifying `brew` is on the host `$PATH`
    /// (via `toride-runner`'s discovery helpers — no command is executed).
    ///
    /// Use this in production entry points; use [`HomebrewBackend::new`]
    /// under a fake runner, where the real PATH is irrelevant.
    ///
    /// # Errors
    ///
    /// [`Error::Command`] wrapping `BinaryNotFound` when `brew` is not on
    /// the PATH.
    pub fn detect(runner: CommandRunner) -> Result<Self> {
        let _path: PathBuf = toride_runner::discovery::find_binary(BREW)?;
        Ok(Self::new(runner))
    }

    /// The installed brew's version, from `brew --version`.
    ///
    /// Parses the output's first line (`Homebrew 4.6.1` → `4.6.1`,
    /// development suffixes like `4.6.1-31-gc9d1e2` kept verbatim).
    ///
    /// # Errors
    ///
    /// [`Error::Command`] when the probe fails or its output does not
    /// carry the `Homebrew ` version prefix.
    pub async fn version(&self) -> Result<String> {
        let output = self
            .runner
            .run_checked(command(BREW, ["--version"]))
            .await?;
        parse_version_output(&output.stdout)
    }

    /// The brew installation prefix (`brew --prefix`), cached after the
    /// first successful call.
    ///
    /// # Errors
    ///
    /// [`Error::Command`] when the probe fails or prints no path.
    pub async fn prefix(&self) -> Result<Utf8PathBuf> {
        if let Some(cached) = self.cached_prefix()? {
            return Ok(cached);
        }
        let output = self.runner.run_checked(command(BREW, ["--prefix"])).await?;
        let prefix = parse_prefix_output(&output.stdout)?;
        self.store_prefix(prefix.clone())?;
        Ok(prefix)
    }

    /// The full typed listing (`brew info --json=v2 --installed`): every
    /// installed cask and formula with token, display name, kind, and
    /// version, from the composite `{"formulae": [...], "casks": [...]}`
    /// envelope of full info items.
    ///
    /// Richer than the trait's [`Backend::list_installed`] (which maps
    /// these entries to plain `InstalledApp`s) so callers that need the
    /// cask/formula distinction can take it directly. (`brew list --json`
    /// is not usable for this — its `--formula`/`--cask` flags conflict
    /// and its `--json` shape is a flat `{name, version}` array behind a
    /// jq fast path; `info --installed` gives both kinds in one call.)
    ///
    /// # Errors
    ///
    /// [`Error::Command`] when the listing command fails or its JSON
    /// document cannot be parsed at all (malformed *items* are skipped,
    /// not fatal).
    pub async fn list_entries(&self) -> Result<Vec<BrewEntry>> {
        let spec = command(BREW, ["info", "--json=v2", "--installed"]);
        let output = self.runner.run_checked(spec).await?;
        parse_installed_info_output(&output.stdout)
    }

    /// The sync twin of [`HomebrewBackend::list_entries`] — same listing,
    /// same parsing, executed on the calling thread.
    ///
    /// # Errors
    ///
    /// Same contract as [`HomebrewBackend::list_entries`].
    pub fn list_entries_sync(&self) -> Result<Vec<BrewEntry>> {
        let spec = command(BREW, ["info", "--json=v2", "--installed"]);
        let output = self.runner.run_checked_sync(spec)?;
        parse_installed_info_output(&output.stdout)
    }

    /// The installed version of one item, from the kind-scoped probe
    /// `brew list --cask|--formula --versions <token>`.
    ///
    /// The kind is load-bearing: the unscoped `brew list --versions` is
    /// formula-only (casks have no Cellar rack), so casks must probe with
    /// `--cask`. Not-installed is classified instead of erroring on two
    /// signals: the normal one is *silent* — an absent token on either
    /// kind fails with exit code 1 and empty stdout and stderr (brew only
    /// sets its failure flag); the other is a brew `Error:` line matching
    /// the not-installed markers, which brew emits only from degenerate
    /// states (e.g. a cask whose token directory exists without the cask
    /// being installed) and from other brew paths that share the probes'
    /// wording. The silent signal is exit-code-gated to 1 so a
    /// signal-killed brew (exit 130 and friends) stays a real error.
    ///
    /// `Ok(None)` also covers "installed but no version reported".
    ///
    /// # Errors
    ///
    /// [`Error::Command`] when brew fails any other way — stderr that is
    /// neither a not-installed `Error:` line nor, at exit code 1, empty.
    pub async fn installed_version(&self, kind: BrewKind, token: &str) -> Result<Option<String>> {
        let spec = command(BREW, ["list", kind.flag(), "--versions", token]);
        classify_version_probe(self.runner.run_checked(spec).await)
    }

    /// The sync twin of [`HomebrewBackend::installed_version`] — same probe,
    /// same classification, executed on the calling thread.
    ///
    /// # Errors
    ///
    /// Same contract as [`HomebrewBackend::installed_version`].
    pub fn installed_version_sync(&self, kind: BrewKind, token: &str) -> Result<Option<String>> {
        let spec = command(BREW, ["list", kind.flag(), "--versions", token]);
        classify_version_probe(self.runner.run_checked_sync(spec))
    }

    /// Outdated packages (`brew outdated --json=v2`), optionally scoped to
    /// casks or formulae. Pinned items are listed with `pinned: true` —
    /// brew reports them stale but skips upgrading them itself.
    ///
    /// `brew outdated` exits 1 whenever anything IS outdated — the entries
    /// on stdout are the answer, not a failure — so exit 1 parses like
    /// success.
    ///
    /// # Errors
    ///
    /// [`Error::Command`] when the command fails (any exit other than the
    /// answered 0-and-1 pair) or its JSON document cannot be parsed at
    /// all; malformed entries are skipped.
    pub async fn outdated(&self, scope: OutdatedScope) -> Result<Vec<OutdatedEntry>> {
        let mut args = vec!["outdated"];
        if let Some(flag) = scope.flag() {
            args.push(flag);
        }
        args.push("--json=v2");
        let spec = command(BREW, args);
        let output = self.runner.run(spec.clone()).await?;
        classify_outdated_probe(&spec, output)
    }

    /// The sync twin of [`HomebrewBackend::outdated`] — same probe, same
    /// parsing, executed on the calling thread.
    ///
    /// # Errors
    ///
    /// Same contract as [`HomebrewBackend::outdated`].
    pub fn outdated_sync(&self, scope: OutdatedScope) -> Result<Vec<OutdatedEntry>> {
        let mut args = vec!["outdated"];
        if let Some(flag) = scope.flag() {
            args.push(flag);
        }
        args.push("--json=v2");
        let spec = command(BREW, args);
        let output = self.runner.run_sync(spec.clone())?;
        classify_outdated_probe(&spec, output)
    }

    /// The version brew currently offers for the `kind`-scoped `token`
    /// (`brew info --json=v2 <token>`): the tap's `versions.stable`
    /// (formulae) / cask `version`, never the `installed` fields the same
    /// document also carries for a token brew has on disk — those report
    /// what is installed, not what is offered.
    ///
    /// # Errors
    ///
    /// [`Error::Command`] when the probe fails (an unknown token exits 1
    /// with brew's no-formula error) or the document is unparseable.
    pub async fn available_version(&self, kind: BrewKind, token: &str) -> Result<Option<Version>> {
        let spec = command(BREW, ["info", "--json=v2", token]);
        let output = self.runner.run_checked(spec).await?;
        parse_offered_version(&output.stdout, kind, token).map(|version| version.map(Version::new))
    }

    /// The sync twin of [`HomebrewBackend::available_version`] — same probe,
    /// same parsing, executed on the calling thread.
    ///
    /// # Errors
    ///
    /// Same contract as [`HomebrewBackend::available_version`].
    pub fn available_version_sync(&self, kind: BrewKind, token: &str) -> Result<Option<Version>> {
        let spec = command(BREW, ["info", "--json=v2", token]);
        let output = self.runner.run_checked_sync(spec)?;
        parse_offered_version(&output.stdout, kind, token).map(|version| version.map(Version::new))
    }

    /// The versions brew can install for the `kind`-scoped `token` today:
    /// the same `brew info --json=v2 <token>` document the singular probe
    /// reads, as a listing. One element at most — brew offers exactly one
    /// installable version per kind (older ones live under separate
    /// versioned tokens, which are their own identities).
    ///
    /// # Errors
    ///
    /// Same contract as [`HomebrewBackend::available_version`].
    pub async fn available_versions(&self, kind: BrewKind, token: &str) -> Result<Vec<Version>> {
        let offered = self.available_version(kind, token).await?;
        Ok(offered.into_iter().collect())
    }

    /// The sync twin of [`HomebrewBackend::available_versions`] — same
    /// document, executed on the calling thread.
    ///
    /// # Errors
    ///
    /// Same contract as [`HomebrewBackend::available_version`].
    pub fn available_versions_sync(&self, kind: BrewKind, token: &str) -> Result<Vec<Version>> {
        let offered = self.available_version_sync(kind, token)?;
        Ok(offered.into_iter().collect())
    }

    /// Hold the `kind`-scoped `token` back from `brew upgrade`
    /// (`brew pin [--cask|--formula] <token>`). Cask pinning is native
    /// from Homebrew 6.0; an older brew refuses the cask-scoped ask with
    /// its own error, which surfaces verbatim.
    ///
    /// # Errors
    ///
    /// [`Error::Command`] when brew fails (absent tokens, or older brews
    /// without cask pinning).
    pub async fn pin(&self, kind: BrewKind, token: &str) -> Result<()> {
        let spec = command(BREW, ["pin", kind.flag(), token]);
        self.runner.run_checked(spec).await.map(|_| ())
    }

    /// Release a pin — the mirror of [`HomebrewBackend::pin`]
    /// (`brew unpin [--cask|--formula] <token>`).
    ///
    /// # Errors
    ///
    /// Same contract as [`HomebrewBackend::pin`].
    pub async fn unpin(&self, kind: BrewKind, token: &str) -> Result<()> {
        let spec = command(BREW, ["unpin", kind.flag(), token]);
        self.runner.run_checked(spec).await.map(|_| ())
    }

    /// The sync twin of [`HomebrewBackend::pin`] — same command, executed
    /// on the calling thread.
    ///
    /// # Errors
    ///
    /// Same contract as [`HomebrewBackend::pin`].
    pub fn pin_sync(&self, kind: BrewKind, token: &str) -> Result<()> {
        let spec = command(BREW, ["pin", kind.flag(), token]);
        self.runner.run_checked_sync(spec).map(|_| ())
    }

    /// The sync twin of [`HomebrewBackend::unpin`] — same command, executed
    /// on the calling thread.
    ///
    /// # Errors
    ///
    /// Same contract as [`HomebrewBackend::pin`].
    pub fn unpin_sync(&self, kind: BrewKind, token: &str) -> Result<()> {
        let spec = command(BREW, ["unpin", kind.flag(), token]);
        self.runner.run_checked_sync(spec).map(|_| ())
    }

    /// Read the memoized prefix without running brew (`None` until the
    /// first [`HomebrewBackend::prefix`] call succeeds).
    fn cached_prefix(&self) -> Result<Option<Utf8PathBuf>> {
        let guard = self.prefix.lock().map_err(|_| cache_poisoned())?;
        Ok(guard.clone())
    }

    /// Memoize the prefix for later [`HomebrewBackend::prefix`] calls.
    fn store_prefix(&self, prefix: Utf8PathBuf) -> Result<()> {
        let mut guard = self.prefix.lock().map_err(|_| cache_poisoned())?;
        *guard = Some(prefix);
        Ok(())
    }
}

#[async_trait]
impl Backend for HomebrewBackend {
    fn id(&self) -> BackendId {
        BackendId::Homebrew
    }

    fn supports(&self, target: &Target) -> bool {
        // Homebrew proper is macOS; formulae (Linuxbrew) also run on Linux.
        // The finer cask-vs-formula rule lives in the planner.
        matches!(target.os, Os::MacOs | Os::Linux)
    }

    async fn install(&self, request: InstallRequest<'_>) -> Result<InstallOutcome> {
        ensure_install_allowed(&request)?;
        let Operation::BrewInstall { cask, token } = &request.plan.operation else {
            return Err(misrouted_operation(&request.plan.operation));
        };
        self.runner
            .run_checked(request.plan.operation.command_spec())
            .await?;
        // Post-verify: ask brew what it just installed, for the manifest
        // record — kind-scoped, since the plan already knows cask vs
        // formula. The install already succeeded, so a failing probe
        // degrades to "no version reported" instead of failing the outcome.
        let kind = if *cask {
            BrewKind::Cask
        } else {
            BrewKind::Formula
        };
        let version = self.installed_version(kind, token).await.ok().flatten();
        Ok(InstallOutcome {
            version,
            detail: request.plan.operation.description(),
        })
    }

    async fn uninstall(&self, request: UninstallRequest<'_>) -> Result<UninstallOutcome> {
        ensure_uninstall_allowed(&request)?;
        let Operation::BrewUninstall { .. } = &request.plan.operation else {
            return Err(misrouted_operation(&request.plan.operation));
        };
        self.runner
            .run_checked(request.plan.operation.command_spec())
            .await?;
        Ok(UninstallOutcome {
            detail: request.plan.operation.description(),
        })
    }

    async fn update(&self, request: UpdateRequest<'_>) -> Result<()> {
        ensure_update_allowed(&request)?;
        let Operation::BrewUpgrade { .. } = &request.plan.operation else {
            return Err(misrouted_operation(&request.plan.operation));
        };
        self.runner
            .run_checked(request.plan.operation.command_spec())
            .await?;
        Ok(())
    }

    async fn outdated(&self) -> Result<Vec<OutdatedEntry>> {
        self.outdated(OutdatedScope::All).await
    }

    async fn available_version(&self, id: &str) -> Result<Option<Version>> {
        let spec = command(BREW, ["info", "--json=v2", id]);
        let output = self.runner.run_checked(spec).await?;
        let formula = parse_offered_version(&output.stdout, BrewKind::Formula, id)?;
        let cask = parse_offered_version(&output.stdout, BrewKind::Cask, id)?;
        Ok(formula.or(cask).map(Version::new))
    }

    async fn available_versions(&self, id: &str) -> Result<Vec<Version>> {
        let spec = command(BREW, ["info", "--json=v2", id]);
        let output = self.runner.run_checked(spec).await?;
        let formula = parse_offered_version(&output.stdout, BrewKind::Formula, id)?;
        let cask = parse_offered_version(&output.stdout, BrewKind::Cask, id)?;
        let mut versions = Vec::new();
        for offered in [formula, cask].into_iter().flatten() {
            let version = Version::new(offered);
            if !versions.contains(&version) {
                versions.push(version);
            }
        }
        Ok(versions)
    }

    async fn pin(&self, id: &str) -> Result<()> {
        self.pin(BrewKind::Formula, id).await
    }

    async fn unpin(&self, id: &str) -> Result<()> {
        self.unpin(BrewKind::Formula, id).await
    }

    async fn list_installed(&self, query: ListQuery) -> Result<Vec<InstalledApp>> {
        let entries = self.list_entries().await?;
        Ok(entries
            .into_iter()
            .filter(|entry| query.ids.is_empty() || query.ids.contains(&entry.token))
            .map(|entry| InstalledApp {
                id: entry.token,
                version: entry.version,
            })
            .collect())
    }

    // `status` keeps the trait's default list-derived implementation: a
    // bare id carries no cask/formula kind, and the direct version probes
    // are kind-scoped (see `installed_version`) — so one id lookup rides
    // the `brew info --json=v2 --installed` listing. Callers that know
    // the kind (plan operations, manifest records) should call
    // `installed_version(kind, token)` directly.

    fn install_sync(&self, request: InstallRequest<'_>) -> Result<InstallOutcome> {
        ensure_install_allowed(&request)?;
        let Operation::BrewInstall { cask, token } = &request.plan.operation else {
            return Err(misrouted_operation(&request.plan.operation));
        };
        self.runner
            .run_checked_sync(request.plan.operation.command_spec())?;
        let kind = if *cask {
            BrewKind::Cask
        } else {
            BrewKind::Formula
        };
        let version = self.installed_version_sync(kind, token).ok().flatten();
        Ok(InstallOutcome {
            version,
            detail: request.plan.operation.description(),
        })
    }

    fn uninstall_sync(&self, request: UninstallRequest<'_>) -> Result<UninstallOutcome> {
        ensure_uninstall_allowed(&request)?;
        let Operation::BrewUninstall { .. } = &request.plan.operation else {
            return Err(misrouted_operation(&request.plan.operation));
        };
        self.runner
            .run_checked_sync(request.plan.operation.command_spec())?;
        Ok(UninstallOutcome {
            detail: request.plan.operation.description(),
        })
    }

    fn update_sync(&self, request: UpdateRequest<'_>) -> Result<()> {
        ensure_update_allowed(&request)?;
        let Operation::BrewUpgrade { .. } = &request.plan.operation else {
            return Err(misrouted_operation(&request.plan.operation));
        };
        self.runner
            .run_checked_sync(request.plan.operation.command_spec())?;
        Ok(())
    }

    fn list_installed_sync(&self, query: ListQuery) -> Result<Vec<InstalledApp>> {
        let entries = self.list_entries_sync()?;
        Ok(entries
            .into_iter()
            .filter(|entry| query.ids.is_empty() || query.ids.contains(&entry.token))
            .map(|entry| InstalledApp {
                id: entry.token,
                version: entry.version,
            })
            .collect())
    }

    fn outdated_sync(&self) -> Result<Vec<OutdatedEntry>> {
        self.outdated_sync(OutdatedScope::All)
    }

    fn available_version_sync(&self, id: &str) -> Result<Option<Version>> {
        let spec = command(BREW, ["info", "--json=v2", id]);
        let output = self.runner.run_checked_sync(spec)?;
        let formula = parse_offered_version(&output.stdout, BrewKind::Formula, id)?;
        let cask = parse_offered_version(&output.stdout, BrewKind::Cask, id)?;
        Ok(formula.or(cask).map(Version::new))
    }

    fn available_versions_sync(&self, id: &str) -> Result<Vec<Version>> {
        let spec = command(BREW, ["info", "--json=v2", id]);
        let output = self.runner.run_checked_sync(spec)?;
        let formula = parse_offered_version(&output.stdout, BrewKind::Formula, id)?;
        let cask = parse_offered_version(&output.stdout, BrewKind::Cask, id)?;
        let mut versions = Vec::new();
        for offered in [formula, cask].into_iter().flatten() {
            let version = Version::new(offered);
            if !versions.contains(&version) {
                versions.push(version);
            }
        }
        Ok(versions)
    }

    fn pin_sync(&self, id: &str) -> Result<()> {
        self.pin_sync(BrewKind::Formula, id)
    }

    fn unpin_sync(&self, id: &str) -> Result<()> {
        self.unpin_sync(BrewKind::Formula, id)
    }
}
// ---------------------------------------------------------------------------
// Typed query results
// ---------------------------------------------------------------------------

/// Whether a listed/updated item is a cask or a formula.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BrewKind {
    /// A homebrew/cask item — GUI macOS app, addressed by `token`.
    Cask,
    /// A homebrew/core item — CLI formula, addressed by `name`.
    Formula,
}

impl std::fmt::Display for BrewKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Cask => "cask",
            Self::Formula => "formula",
        })
    }
}

impl BrewKind {
    /// The brew CLI flag that scopes a command to this kind (`--cask` /
    /// `--formula`) — used by the kind-scoped `brew list` probes.
    #[must_use]
    pub const fn flag(self) -> &'static str {
        match self {
            Self::Cask => "--cask",
            Self::Formula => "--formula",
        }
    }
}

/// One item from `brew info --json=v2 --installed`: the typed,
/// backend-native view behind the trait's plain [`InstalledApp`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrewEntry {
    /// Cask token or formula name — the backend-native id and the join key
    /// against plan operations and manifest records.
    pub token: String,
    /// Cask or formula.
    pub kind: BrewKind,
    /// Display name (first of a cask's `name` array; a formula's `name`)
    /// when the item reports one.
    pub name: Option<String>,
    /// Installed version when the item reports one; items that only carry
    /// the tap's notion (API-shaped payloads where `installed` is null)
    /// fall back to that — in `brew list` output the item is installed by
    /// definition.
    pub version: Option<String>,
}

/// Scope for [`HomebrewBackend::outdated`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutdatedScope {
    /// Everything brew manages (no scope flag).
    #[default]
    All,
    /// Casks only (`--cask`).
    Casks,
    /// Formulae only (`--formula`).
    Formulae,
}

impl OutdatedScope {
    /// The `brew outdated` flag selecting this scope (`None` for all).
    #[must_use]
    pub const fn flag(self) -> Option<&'static str> {
        match self {
            Self::All => None,
            Self::Casks => Some("--cask"),
            Self::Formulae => Some("--formula"),
        }
    }
}
// ---------------------------------------------------------------------------
// Raw JSON shapes (brew --json=v2 items)
// ---------------------------------------------------------------------------

/// Top level of `brew info --json=v2` output (and the formulae.brew.sh
/// API's envelopes): one array per kind. Items are kept as raw
/// [`serde_json`] values so one malformed item cannot sink the listing.
#[derive(Deserialize)]
struct RawInstalledInfoDocument {
    #[serde(default)]
    formulae: Vec<serde_json::Value>,
    #[serde(default)]
    casks: Vec<serde_json::Value>,
}

/// The per-cask item shape shared by `brew info --json=v2` and the brew
/// API's cask payloads (registry fixtures carry the same shape). Only the
/// fields this backend consumes are modeled; every optional field can be
/// `null` or absent.
#[derive(Deserialize)]
struct RawCaskItem {
    /// Canonical token — the identifying field; an item without one is
    /// malformed and skipped.
    token: String,
    /// Display names (first is the primary); an array.
    #[serde(default)]
    name: Vec<String>,
    /// The tap's version for the cask.
    #[serde(default)]
    version: Option<String>,
    /// Installed version (a string in `brew info --json=v2 --installed`
    /// output; `null` in server-side API payloads).
    #[serde(default)]
    installed: Option<String>,
}

/// The per-formula item shape shared by `brew info --json=v2` and the brew
/// API's formula payloads.
#[derive(Deserialize)]
struct RawFormulaItem {
    /// Short formula name — the identifying field.
    name: String,
    /// Tap versions (`versions.stable` is the current stable).
    #[serde(default)]
    versions: Option<RawVersions>,
    /// Installed kegs; `brew info --json=v2 --installed` fills this with
    /// the poured kegs, API payloads with `[]` or `null`.
    #[serde(default)]
    installed: Option<Vec<RawKeg>>,
}

/// The `versions` sub-object of a formula item.
#[derive(Deserialize)]
struct RawVersions {
    #[serde(default)]
    stable: Option<String>,
}

/// One poured keg of an installed formula.
#[derive(Deserialize)]
struct RawKeg {
    #[serde(default)]
    version: Option<String>,
}

/// Top level of `brew outdated --json=v2`: one array per kind.
#[derive(Deserialize)]
struct RawOutdatedDocument {
    #[serde(default)]
    formulae: Vec<serde_json::Value>,
    #[serde(default)]
    casks: Vec<serde_json::Value>,
}

/// One outdated item — casks and formulae share this shape (the identifying
/// field is `name` in both; some brew versions also carry `token` on casks).
#[derive(Deserialize)]
struct RawOutdatedItem {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    installed_versions: Vec<String>,
    #[serde(default)]
    current_version: Option<String>,
    #[serde(default)]
    pinned: bool,
}
// ---------------------------------------------------------------------------
// Output parsing
// ---------------------------------------------------------------------------

/// Parse a `brew info --json=v2 --installed` document into typed entries,
/// skipping malformed items.
///
/// # Errors
///
/// [`Error::Command`] wrapping `OutputParse` when the payload is not a
/// JSON object with the expected envelope shape.
fn parse_installed_info_output(stdout: &str) -> Result<Vec<BrewEntry>> {
    let document: RawInstalledInfoDocument = serde_json::from_str(stdout)
        .map_err(|error| output_parse_error("brew info --json=v2", &error))?;
    let mut entries = Vec::new();
    // Document order: formulae array first, casks second.
    for value in document.formulae {
        if let Ok(item) = serde_json::from_value::<RawFormulaItem>(value) {
            entries.push(BrewEntry::from_formula(item));
        }
    }
    for value in document.casks {
        if let Ok(item) = serde_json::from_value::<RawCaskItem>(value) {
            entries.push(BrewEntry::from_cask(item));
        }
    }
    Ok(entries)
}

/// Parse the version brew OFFERS for the `kind`-scoped `token` out of a
/// `brew info --json=v2 <token>` document: the formula's `versions.stable`
/// / the cask's `version`. The `installed` fields the document carries for
/// a token brew has on disk are deliberately ignored — they report what is
/// installed, not what is offered (unlike [`parse_installed_info_output`],
/// which prefers them for exactly that reason).
///
/// # Errors
///
/// [`Error::Command`] wrapping `OutputParse` when the payload is not a
/// JSON object with the expected envelope shape.
fn parse_offered_version(stdout: &str, kind: BrewKind, token: &str) -> Result<Option<String>> {
    let document: RawInstalledInfoDocument = serde_json::from_str(stdout)
        .map_err(|error| output_parse_error("brew info --json=v2", &error))?;
    match kind {
        BrewKind::Formula => {
            for value in document.formulae {
                if let Ok(item) = serde_json::from_value::<RawFormulaItem>(value)
                    && item.name == token
                    && let Some(offered) = item
                        .versions
                        .and_then(|versions| versions.stable)
                        .filter(|version| !version.is_empty())
                {
                    return Ok(Some(offered));
                }
            }
            Ok(None)
        }
        BrewKind::Cask => {
            for value in document.casks {
                if let Ok(item) = serde_json::from_value::<RawCaskItem>(value)
                    && item.token == token
                    && let Some(offered) = item.version.filter(|version| !version.is_empty())
                {
                    return Ok(Some(offered));
                }
            }
            Ok(None)
        }
    }
}

/// Parse a `brew outdated --json=v2` document into typed entries, skipping
/// malformed entries.
///
/// # Errors
///
/// [`Error::Command`] wrapping `OutputParse` when the payload is not a
/// JSON object with the expected envelope shape.
fn parse_outdated_output(stdout: &str) -> Result<Vec<OutdatedEntry>> {
    let document: RawOutdatedDocument = serde_json::from_str(stdout)
        .map_err(|error| output_parse_error("brew outdated --json=v2", &error))?;
    let mut entries = Vec::new();
    for value in document.formulae.into_iter().chain(document.casks) {
        if let Ok(item) = serde_json::from_value::<RawOutdatedItem>(value)
            && let Some(entry) = OutdatedEntry::from_raw(item)
        {
            entries.push(entry);
        }
    }
    Ok(entries)
}

/// Classify a dispatched `brew list --versions` probe: parse its stdout on
/// success, and treat "not installed" — a marker-matching `Error:` line, or
/// a silent exit 1 (empty stderr; the exit-code gate keeps signal kills as
/// errors) — as `Ok(None)` instead of a failure. Anything else escapes.
fn classify_version_probe(result: Result<CommandOutput>) -> Result<Option<String>> {
    match result {
        Ok(output) => Ok(parse_versions_output(&output.stdout)),
        Err(Error::Command(toride_runner::Error::CommandFailed {
            stderr, exit_code, ..
        })) if stderr_says_not_installed(&stderr)
            || (stderr.trim().is_empty() && exit_code == Some(1)) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

/// Classify a dispatched `brew outdated --json=v2` probe: exit 0 and exit 1
/// both carry the answer on stdout — brew exits 1 exactly when something is
/// outdated — while any other exit (or an unparseable document at 0/1) is a
/// real failure.
fn classify_outdated_probe(
    spec: &toride_runner::CommandSpec,
    output: toride_runner::CommandOutput,
) -> Result<Vec<OutdatedEntry>> {
    if output.success || output.exit_code == Some(1) {
        return parse_outdated_output(&output.stdout);
    }
    Err(Error::Command(toride_runner::Error::CommandFailed {
        program: spec.program.clone(),
        args: spec.args.join(" "),
        exit_code: output.exit_code,
        stderr: output.stderr,
    }))
}

impl BrewEntry {
    /// Type a parsed cask item: token, first display name, version with the
    /// documented installed-then-tap fallback.
    fn from_cask(item: RawCaskItem) -> Self {
        let version = item
            .installed
            .as_deref()
            .filter(|version| !version.is_empty())
            .or(item.version.as_deref())
            .filter(|version| !version.is_empty())
            .map(str::to_owned);
        Self {
            token: item.token,
            kind: BrewKind::Cask,
            name: item.name.into_iter().next(),
            version,
        }
    }

    /// Type a parsed formula item: name, first poured keg's version with
    /// the `versions.stable` fallback.
    fn from_formula(item: RawFormulaItem) -> Self {
        let version = item
            .installed
            .as_ref()
            .and_then(|kegs| kegs.first())
            .and_then(|keg| keg.version.as_deref())
            .filter(|version| !version.is_empty())
            .or(item
                .versions
                .as_ref()
                .and_then(|versions| versions.stable.as_deref()))
            .filter(|version| !version.is_empty())
            .map(str::to_owned);
        Self {
            token: item.name,
            kind: BrewKind::Formula,
            name: None,
            version,
        }
    }
}

impl OutdatedEntry {
    /// Type a parsed outdated item; `None` marks a malformed one (neither
    /// `name` nor `token` present).
    fn from_raw(item: RawOutdatedItem) -> Option<Self> {
        Some(Self {
            id: item.name.or(item.token)?,
            installed_versions: item.installed_versions,
            current_version: item.current_version,
            pinned: item.pinned,
        })
    }
}

/// Parse `brew --version` output: first non-empty line, `Homebrew ` prefix
/// stripped, remainder trimmed (`4.6.1`, `4.6.1-31-gc9d1e2`).
///
/// # Errors
///
/// [`Error::Command`] wrapping `OutputParse` when the prefix is missing or
/// no version follows it.
fn parse_version_output(stdout: &str) -> Result<String> {
    let first = stdout.lines().find(|line| !line.trim().is_empty());
    let version = first
        .and_then(|line| line.trim().strip_prefix("Homebrew "))
        .map(str::trim)
        .filter(|version| !version.is_empty());
    version.map_or_else(
        || {
            Err(output_parse_error(
                "brew --version",
                format!("no `Homebrew <version>` line in {stdout:?}"),
            ))
        },
        |version| Ok(version.to_owned()),
    )
}

/// Parse `brew --prefix` output: first non-empty line as a path.
///
/// # Errors
///
/// [`Error::Command`] wrapping `OutputParse` when the output carries no
/// path.
fn parse_prefix_output(stdout: &str) -> Result<Utf8PathBuf> {
    let path = stdout.lines().map(str::trim).find(|line| !line.is_empty());
    path.map_or_else(
        || Err(output_parse_error("brew --prefix", "no path in output")),
        |path| Ok(Utf8PathBuf::from(path)),
    )
}

/// Parse the output of the kind-scoped `brew list --cask|--formula
/// --versions <token>` probes (`<name> <version>` per line, one line per
/// installed keg): the first line's version token. Empty output yields
/// `None`.
fn parse_versions_output(stdout: &str) -> Option<String> {
    let first = stdout.lines().find(|line| !line.trim().is_empty())?;
    // brew echoes the canonical name first; the version follows. The name
    // may differ from the queried token (aliases resolve), so it is not
    // checked — the version field is the payload.
    first.split_whitespace().nth(1).map(str::to_owned)
}

/// Whether brew stderr says the queried item is not installed (see
/// [`NOT_INSTALLED_MARKERS`]): markers are matched only on `Error:`-prefixed
/// lines, so multi-line stderr mentioning other packages' "not installed"
/// states does not misclassify. Best-effort: brew's exact wording varies by
/// version; anything unrecognized is treated as a real error.
fn stderr_says_not_installed(stderr: &str) -> bool {
    stderr
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with("Error:"))
        .any(|error_line| {
            let lower = error_line.to_ascii_lowercase();
            NOT_INSTALLED_MARKERS
                .iter()
                .any(|marker| lower.contains(marker))
        })
}

/// The error for a plan operation this backend cannot execute (a non-brew
/// operation routed to the homebrew backend).
fn misrouted_operation(operation: &Operation) -> Error {
    Error::Command(toride_runner::Error::Other(format!(
        "homebrew backend cannot execute non-brew operation: {operation:?}"
    )))
}

/// Build the unparseable-output error, naming the brew command and the
/// serde failure.
fn output_parse_error(brew_command: &str, cause: impl std::fmt::Display) -> Error {
    Error::Command(toride_runner::Error::OutputParse(format!(
        "{brew_command}: {cause}"
    )))
}

/// The error for a poisoned prefix-cache mutex (unreachable unless a
/// holder panicked mid-store).
fn cache_poisoned() -> Error {
    Error::Command(toride_runner::Error::Other(
        "homebrew prefix cache mutex poisoned".to_owned(),
    ))
}
// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{BackendStatus, StatusQuery};
    use crate::plan::{
        InstallOptions, InstallPlan, UninstallOptions, UninstallPlan, plan_install, plan_uninstall,
    };
    use std::path::Path;
    use std::sync::Arc;
    use toride_registry::{App, Arch, Availability, InstallMethod, TorideId};
    use toride_runner::fake::FakeRunner;

    // --- test helpers ----------------------------------------------------------

    /// Root of this crate's fixture tree (runtime reads, not `include_str!`
    /// — the house pattern from conventions.md §7).
    fn fixtures_dir() -> &'static Path {
        Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures"))
    }

    /// Read a fixture file as a UTF-8 string, relative to the fixtures dir.
    fn read_fixture(relative: &str) -> String {
        let path = fixtures_dir().join(relative);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read fixture {relative}: {error}"))
    }

    /// Parse a fixture JSON file into a [`serde_json::Value`].
    fn fixture_value(relative: &str) -> serde_json::Value {
        let raw = read_fixture(relative);
        serde_json::from_str(raw.trim())
            .unwrap_or_else(|error| panic!("failed to parse fixture {relative}: {error}"))
    }

    /// Wrap registry-shaped formula fixtures into the envelope `brew info
    /// --json=v2 --installed` emits: the same per-item payloads (full info
    /// objects) under `formulae` / `casks` keys.
    fn installed_info_payload(formulae: &[serde_json::Value]) -> String {
        let mut document = serde_json::Map::new();
        document.insert(
            "formulae".to_owned(),
            serde_json::Value::Array(formulae.to_vec()),
        );
        document.insert("casks".to_owned(), serde_json::Value::Array(Vec::new()));
        serde_json::Value::Object(document).to_string()
    }

    /// A registry `App` fixture with the given install method.
    fn app_with(method: InstallMethod) -> App {
        App {
            id: TorideId::slugify("brave-browser"),
            name: "Brave Browser".to_owned(),
            aliases: Vec::new(),
            summary: None,
            description: None,
            homepage: None,
            license: None,
            developer: None,
            binaries: Vec::new(),
            latest: None,
            platforms: Vec::new(),
            artifacts: Vec::new(),
            install: method,
            sources: Vec::new(),
            availability: Availability::Available,
        }
    }

    /// A cask (by default) or formula homebrew install method.
    fn brew_method(cask: bool) -> InstallMethod {
        InstallMethod::Homebrew {
            cask,
            token: "brave-browser".to_owned(),
        }
    }

    fn macos() -> Target {
        Target::macos(Arch::X86_64)
    }

    /// A backend over a strict fake runner (unmatched dispatches fail).
    fn backend(fake: &FakeRunner) -> HomebrewBackend {
        HomebrewBackend::new(CommandRunner::new(Arc::new(fake.clone())))
    }

    fn install_plan_for(cask: bool) -> InstallPlan {
        plan_install(
            &app_with(brew_method(cask)),
            &macos(),
            &InstallOptions::default(),
        )
        .unwrap()
    }

    fn uninstall_plan_for(cask: bool, zap: bool) -> UninstallPlan {
        plan_uninstall(
            &app_with(brew_method(cask)),
            &macos(),
            &UninstallOptions { zap },
        )
        .unwrap()
    }

    /// A homebrew-backend install plan carrying a hand-picked operation
    /// (tokens that differ from the shared fixture's, or non-brew
    /// operations for misrouting tests).
    fn manual_install_plan(operation: Operation) -> InstallPlan {
        InstallPlan {
            app: TorideId::slugify("brave-browser"),
            backend: BackendId::Homebrew,
            operation,
            dry_run: false,
            requires_elevation: false,
        }
    }

    /// A homebrew-backend update plan carrying a hand-picked operation.
    fn manual_update_plan(operation: Operation) -> crate::plan::UpdatePlan {
        crate::plan::UpdatePlan {
            app: TorideId::slugify("brave-browser"),
            backend: BackendId::Homebrew,
            operation,
            dry_run: false,
            requires_elevation: false,
        }
    }

    // --- version probe parsing ---------------------------------------------------

    #[test]
    fn parse_version_output_strips_homebrew_prefix_and_trims() {
        let version = parse_version_output("Homebrew 4.6.1\n").unwrap();
        assert_eq!(version, "4.6.1");
    }

    #[test]
    fn parse_version_output_keeps_development_suffixes_verbatim() {
        let version = parse_version_output("Homebrew 4.6.1-31-gc9d1e2e\n").unwrap();
        assert_eq!(version, "4.6.1-31-gc9d1e2e");
    }

    #[test]
    fn parse_version_output_rejects_output_without_the_prefix() {
        let error = parse_version_output("brew 4.6.1\n").unwrap_err();
        assert!(
            matches!(error, Error::Command(toride_runner::Error::OutputParse(_))),
            "{error:?}"
        );
    }

    #[test]
    fn parse_version_output_rejects_empty_output() {
        assert!(parse_version_output("").is_err());
    }

    // --- prefix probe parsing ------------------------------------------------------

    #[test]
    fn parse_prefix_output_takes_the_first_non_empty_line() {
        let prefix = parse_prefix_output("/opt/homebrew\n\n").unwrap();
        assert_eq!(prefix, Utf8PathBuf::from("/opt/homebrew"));
    }

    #[test]
    fn parse_prefix_output_rejects_empty_output() {
        let error = parse_prefix_output("  \n").unwrap_err();
        assert!(
            matches!(error, Error::Command(toride_runner::Error::OutputParse(_))),
            "{error:?}"
        );
    }

    // --- installed-info document parsing ------------------------------------------

    #[test]
    fn parse_installed_info_reads_real_formula_fixture_items() {
        // The registry crate's live-fetched formula payload, wrapped in the
        // brew info envelope: `installed` is `[]` (API shape), so the
        // version falls back to `versions.stable`.
        let payload = installed_info_payload(&[fixture_value("homebrew/formula-ripgrep.json")]);
        let entries = parse_installed_info_output(&payload).unwrap();
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(
            entries[0],
            BrewEntry {
                token: "ripgrep".to_owned(),
                kind: BrewKind::Formula,
                name: None,
                version: Some("15.2.0".to_owned()),
            }
        );
    }

    #[test]
    fn parse_installed_info_reads_real_cask_fixture_items() {
        // Same for the cask payload: `installed` is `null` (API shape), so
        // the version falls back to the cask's `version` field.
        let cask = fixture_value("homebrew/cask-brave-browser.json");
        let document = serde_json::json!({ "formulae": [], "casks": [cask] });
        let entries = parse_installed_info_output(&document.to_string()).unwrap();
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(
            entries[0],
            BrewEntry {
                token: "brave-browser".to_owned(),
                kind: BrewKind::Cask,
                name: Some("Brave".to_owned()),
                version: Some("1.96.59.0".to_owned()),
            }
        );
    }

    #[test]
    fn parse_installed_info_takes_the_first_display_name_of_a_cask() {
        // The vscode cask carries two display names
        // (["Microsoft Visual Studio Code", "VS Code"]); the first is the
        // primary one.
        let cask = fixture_value("homebrew/cask-visual-studio-code.json");
        let document = serde_json::json!({ "formulae": [], "casks": [cask] });
        let entries = parse_installed_info_output(&document.to_string()).unwrap();
        assert_eq!(
            entries[0].name.as_deref(),
            Some("Microsoft Visual Studio Code")
        );
    }

    #[test]
    fn parse_installed_info_prefers_the_reported_installed_version_over_the_tap_version() {
        let document = serde_json::json!({
            "casks": [{
                "token": "brave-browser",
                "name": ["Brave"],
                "version": "2.0.0",
                "installed": "1.0.0"
            }]
        });
        let entries = parse_installed_info_output(&document.to_string()).unwrap();
        assert_eq!(entries[0].version.as_deref(), Some("1.0.0"));
    }

    #[test]
    fn parse_installed_info_prefers_the_first_poured_keg_version_for_formulae() {
        let document = serde_json::json!({
            "formulae": [{
                "name": "ripgrep",
                "installed": [{ "version": "15.1.0" }, { "version": "15.2.0" }],
                "versions": { "stable": "15.2.0" }
            }]
        });
        let entries = parse_installed_info_output(&document.to_string()).unwrap();
        assert_eq!(entries[0].version.as_deref(), Some("15.1.0"));
    }

    #[test]
    fn parse_installed_info_tolerates_malformed_items_without_failing_the_listing() {
        let document = serde_json::json!({
            "formulae": [
                { "name": "ripgrep", "versions": { "stable": "15.2.0" } },
                { "versions": { "stable": "1.0" } },   // no name -> malformed
                "not-even-an-object",                   // wrong type -> malformed
                { "name": "wget" }                      // no versions at all -> fine
            ],
            "casks": [
                { "version": "1.0" },                  // no token -> malformed
                { "token": "brave-browser" }           // minimal cask -> fine
            ]
        });
        let entries = parse_installed_info_output(&document.to_string()).unwrap();
        let tokens: Vec<&str> = entries.iter().map(|entry| entry.token.as_str()).collect();
        assert_eq!(tokens, ["ripgrep", "wget", "brave-browser"], "{entries:?}");
    }

    #[test]
    fn parse_installed_info_tolerates_documents_missing_one_kind_entirely() {
        // A brew with no installed casks may omit the key entirely.
        let payload = installed_info_payload(&[fixture_value("homebrew/formula-ripgrep.json")]);
        let entries = parse_installed_info_output(&payload).unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn parse_installed_info_rejects_non_json_output() {
        let error = parse_installed_info_output("Error: not json at all").unwrap_err();
        assert!(
            matches!(error, Error::Command(toride_runner::Error::OutputParse(_))),
            "{error:?}"
        );
    }

    // --- outdated document parsing -----------------------------------------------

    #[test]
    fn parse_outdated_reads_typed_entries_from_the_fixture() {
        let raw = read_fixture("homebrew/outdated.json");
        let entries = parse_outdated_output(raw.trim()).unwrap();
        assert_eq!(entries.len(), 3, "{entries:?}");
        assert_eq!(
            entries[0],
            OutdatedEntry {
                id: "ripgrep".to_owned(),
                installed_versions: vec!["15.1.0".to_owned()],
                current_version: Some("15.2.0".to_owned()),
                pinned: false,
            }
        );
        assert!(entries[1].pinned, "wget entry: {entries:?}");
        assert_eq!(entries[2].id, "brave-browser");
    }

    #[test]
    fn parse_outdated_tolerates_malformed_entries_and_missing_optionals() {
        let document = serde_json::json!({
            "formulae": [
                { "installed_versions": ["1.0"] },  // no name/token -> malformed
                { "name": "wget" }                  // only the name -> defaults
            ],
            "casks": [ { "token": "brave-browser", "installed_versions": ["1.0"] } ]
        });
        let entries = parse_outdated_output(&document.to_string()).unwrap();
        assert_eq!(entries.len(), 2, "{entries:?}");
        assert_eq!(entries[0].id, "wget");
        assert_eq!(entries[0].installed_versions, Vec::<String>::new());
        assert_eq!(entries[0].current_version, None);
        assert!(!entries[0].pinned);
        // Casks accept `token` as the identifying field when `name` is absent.
        assert_eq!(entries[1].id, "brave-browser");
    }

    #[test]
    fn parse_outdated_rejects_non_json_output() {
        let error = parse_outdated_output("]").unwrap_err();
        assert!(
            matches!(error, Error::Command(toride_runner::Error::OutputParse(_))),
            "{error:?}"
        );
    }

    // --- versions-output + stderr classification ---------------------------------

    #[test]
    fn parse_versions_output_takes_the_first_version_token() {
        assert_eq!(
            parse_versions_output("ripgrep 15.2.0\n"),
            Some("15.2.0".to_owned())
        );
    }

    #[test]
    fn parse_versions_output_returns_none_for_empty_output() {
        assert_eq!(parse_versions_output(""), None);
    }

    #[test]
    fn stderr_classification_matches_each_not_installed_marker() {
        for stderr in [
            "Error: Cask 'brave-browser' is not installed.",
            "Error: No available formula with the name \"nope\".",
            "Error: No installed keg or formula with the name \"nope\".",
        ] {
            assert!(stderr_says_not_installed(stderr), "{stderr}");
        }
    }

    #[test]
    fn stderr_classification_ignores_markers_outside_error_lines() {
        // Multi-line stderr mentioning another package's "not installed"
        // state must not classify the probe's failure as not-installed
        // when the actual Error: line says something else.
        assert!(!stderr_says_not_installed(
            "Warning: dependency foo is not installed\nError: permission denied"
        ));
    }

    #[test]
    fn stderr_classification_rejects_unrelated_failures() {
        assert!(!stderr_says_not_installed(
            "Error: cannot clone tap: network unreachable"
        ));
    }

    // --- detection probes through the seam ----------------------------------------

    #[tokio::test]
    async fn version_probes_brew_version_with_exact_argv() {
        let spec = command(BREW, ["--version"]);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::from_stdout("Homebrew 4.6.1\n"),
        );
        let backend = backend(&fake);
        assert_eq!(backend.version().await.unwrap(), "4.6.1");
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn prefix_probes_brew_prefix_once_and_caches_across_calls() {
        let spec = command(BREW, ["--prefix"]);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::from_stdout("/opt/homebrew\n"),
        );
        let backend = backend(&fake);
        assert_eq!(
            backend.prefix().await.unwrap(),
            Utf8PathBuf::from("/opt/homebrew")
        );
        // Second call must come from the cache: the strict fake has no
        // further response, so a second dispatch would fail.
        assert_eq!(
            backend.prefix().await.unwrap(),
            Utf8PathBuf::from("/opt/homebrew")
        );
        assert_eq!(fake.calls().len(), 1, "prefix probe ran more than once");
        fake.assert_called_with(&spec);
    }

    // --- install ----------------------------------------------------------------

    #[tokio::test]
    async fn install_refuses_dry_run_plans_without_touching_the_runner() {
        let fake = FakeRunner::new().strict();
        let backend = backend(&fake);
        let plan = install_plan_for(true).dry_run(true);
        let target = macos();
        let error = backend
            .install(InstallRequest::new(&plan, &target))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::DryRun { .. }), "{error:?}");
        assert!(fake.calls().is_empty(), "no brew command may run");
    }

    #[tokio::test]
    async fn install_refuses_elevation_requiring_plans_without_a_grant() {
        let fake = FakeRunner::new().strict();
        let backend = backend(&fake);
        let mut plan = install_plan_for(true);
        plan.requires_elevation = true;
        let target = macos();
        let error = backend
            .install(InstallRequest::new(&plan, &target))
            .await
            .unwrap_err();
        assert!(
            matches!(error, Error::ElevationRequired { .. }),
            "{error:?}"
        );
        assert!(fake.calls().is_empty(), "no brew command may run");
    }

    #[tokio::test]
    async fn install_rejects_non_brew_operations() {
        let fake = FakeRunner::new().strict();
        let backend = backend(&fake);
        let plan = manual_install_plan(Operation::FlatpakInstall {
            remote: "flathub".to_owned(),
            app_ref: "app/com.brave.Browser/x86_64/stable".to_owned(),
            installation: crate::plan::FlatpakInstallation::User,
        });
        let target = macos();
        let error = backend
            .install(InstallRequest::new(&plan, &target))
            .await
            .unwrap_err();
        assert!(
            matches!(error, Error::Command(toride_runner::Error::Other(_))),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn install_runs_cask_argv_exactly_and_reports_the_installed_version() {
        let install_spec = command(BREW, ["install", "--cask", "brave-browser"]);
        // Post-verify probe is kind-scoped: casks must ask `--cask`.
        let probe_spec = command(BREW, ["list", "--cask", "--versions", "brave-browser"]);
        let fake = FakeRunner::new()
            .strict()
            .respond(
                install_spec.clone(),
                toride_runner::CommandOutput::from_stdout(""),
            )
            .respond(
                probe_spec.clone(),
                toride_runner::CommandOutput::from_stdout("brave-browser 1.96.59.0\n"),
            );
        let backend = backend(&fake);
        let plan = install_plan_for(true);
        let target = macos();
        let outcome = backend
            .install(InstallRequest::new(&plan, &target))
            .await
            .unwrap();
        assert_eq!(outcome.version.as_deref(), Some("1.96.59.0"));
        assert!(
            outcome.detail.contains("cask `brave-browser`"),
            "{}",
            outcome.detail
        );
        fake.assert_called_with(&install_spec);
        fake.assert_called_with(&probe_spec);
    }

    #[tokio::test]
    async fn install_runs_formula_argv_without_the_cask_flag() {
        let install_spec = command(BREW, ["install", "brave-browser"]);
        // Formula post-verify probes the formula-scoped list.
        let probe_spec = command(BREW, ["list", "--formula", "--versions", "brave-browser"]);
        let fake = FakeRunner::new()
            .strict()
            .respond(
                install_spec.clone(),
                toride_runner::CommandOutput::from_stdout(""),
            )
            .respond(probe_spec, toride_runner::CommandOutput::from_stdout(""));
        let backend = backend(&fake);
        let plan = install_plan_for(false);
        let target = macos();
        let outcome = backend
            .install(InstallRequest::new(&plan, &target))
            .await
            .unwrap();
        assert_eq!(outcome.version, None, "probe reported no version");
        fake.assert_called_with(&install_spec);
    }

    #[tokio::test]
    async fn install_maps_nonzero_exit_to_command_error_carrying_stderr() {
        let install_spec = command(BREW, ["install", "--cask", "nope"]);
        let fake = FakeRunner::new().strict().respond(
            install_spec,
            toride_runner::CommandOutput::from_stderr(
                "Error: Cask 'nope' is unavailable: no Cask with this name",
                1,
            ),
        );
        let backend = backend(&fake);
        let plan = manual_install_plan(Operation::BrewInstall {
            cask: true,
            token: "nope".to_owned(),
        });
        let target = macos();
        let error = backend
            .install(InstallRequest::new(&plan, &target))
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                Error::Command(toride_runner::Error::CommandFailed { .. })
            ),
            "{error:?}"
        );
        assert!(
            error.to_string().contains("no Cask with this name"),
            "stderr tail must travel with the error: {error}"
        );
    }

    #[tokio::test]
    async fn install_survives_a_failing_post_install_version_probe() {
        // The install itself succeeded; a "not installed" probe answer must
        // degrade the outcome to version=None, not fail it.
        let install_spec = command(BREW, ["install", "--cask", "brave-browser"]);
        let probe_spec = command(BREW, ["list", "--cask", "--versions", "brave-browser"]);
        let fake = FakeRunner::new()
            .strict()
            .respond(install_spec, toride_runner::CommandOutput::from_stdout(""))
            .respond(
                probe_spec,
                toride_runner::CommandOutput::from_stderr(
                    "Error: Cask 'brave-browser' is not installed.",
                    1,
                ),
            );
        let backend = backend(&fake);
        let plan = install_plan_for(true);
        let target = macos();
        let outcome = backend
            .install(InstallRequest::new(&plan, &target))
            .await
            .unwrap();
        assert_eq!(outcome.version, None);
    }

    // --- uninstall ----------------------------------------------------------------

    #[tokio::test]
    async fn uninstall_refuses_dry_run_plans_without_touching_the_runner() {
        let fake = FakeRunner::new().strict();
        let backend = backend(&fake);
        let plan = uninstall_plan_for(true, false).dry_run(true);
        let target = macos();
        let error = backend
            .uninstall(UninstallRequest::new(&plan, &target))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::DryRun { .. }), "{error:?}");
        assert!(fake.calls().is_empty(), "no brew command may run");
    }

    #[tokio::test]
    async fn uninstall_runs_cask_argv_with_the_cask_flag_exactly() {
        let spec = command(BREW, ["uninstall", "--cask", "brave-browser"]);
        let fake = FakeRunner::new()
            .strict()
            .respond(spec.clone(), toride_runner::CommandOutput::from_stdout(""));
        let backend = backend(&fake);
        let plan = uninstall_plan_for(true, false);
        let target = macos();
        let outcome = backend
            .uninstall(UninstallRequest::new(&plan, &target))
            .await
            .unwrap();
        assert!(
            outcome.detail.contains("cask `brave-browser`"),
            "{}",
            outcome.detail
        );
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn uninstall_runs_the_zap_variant_replacing_the_cask_flag() {
        let spec = command(BREW, ["uninstall", "--zap", "brave-browser"]);
        let fake = FakeRunner::new()
            .strict()
            .respond(spec.clone(), toride_runner::CommandOutput::from_stdout(""));
        let backend = backend(&fake);
        let plan = uninstall_plan_for(true, true);
        let target = macos();
        backend
            .uninstall(UninstallRequest::new(&plan, &target))
            .await
            .unwrap();
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn uninstall_runs_formula_argv_without_type_flags() {
        let spec = command(BREW, ["uninstall", "brave-browser"]);
        let fake = FakeRunner::new()
            .strict()
            .respond(spec.clone(), toride_runner::CommandOutput::from_stdout(""));
        let backend = backend(&fake);
        let plan = uninstall_plan_for(false, true);
        let target = macos();
        backend
            .uninstall(UninstallRequest::new(&plan, &target))
            .await
            .unwrap();
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn uninstall_maps_nonzero_exit_to_command_error_carrying_stderr() {
        let spec = command(BREW, ["uninstall", "--cask", "brave-browser"]);
        let fake = FakeRunner::new().strict().respond(
            spec,
            toride_runner::CommandOutput::from_stderr(
                "Error: Cask 'brave-browser' is not installed.",
                1,
            ),
        );
        let backend = backend(&fake);
        let plan = uninstall_plan_for(true, false);
        let target = macos();
        let error = backend
            .uninstall(UninstallRequest::new(&plan, &target))
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                Error::Command(toride_runner::Error::CommandFailed { .. })
            ),
            "{error:?}"
        );
        assert!(
            error.to_string().contains("not installed"),
            "stderr tail must travel with the error: {error}"
        );
    }

    fn update_plan_for(cask: bool) -> crate::plan::UpdatePlan {
        manual_update_plan(Operation::BrewUpgrade {
            cask,
            token: "brave-browser".to_owned(),
        })
    }

    #[tokio::test]
    async fn update_refuses_dry_run_plans_without_touching_the_runner() {
        let fake = FakeRunner::new().strict();
        let backend = backend(&fake);
        let plan = update_plan_for(true).dry_run(true);
        let target = macos();
        let error = backend
            .update(UpdateRequest::new(&plan, &target))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::DryRun { .. }), "{error:?}");
        assert!(fake.calls().is_empty(), "no brew command may run");
    }

    #[tokio::test]
    async fn update_refuses_elevation_requiring_plans_without_a_grant() {
        let fake = FakeRunner::new().strict();
        let backend = backend(&fake);
        let mut plan = update_plan_for(true);
        plan.requires_elevation = true;
        let target = macos();
        let error = backend
            .update(UpdateRequest::new(&plan, &target))
            .await
            .unwrap_err();
        assert!(
            matches!(error, Error::ElevationRequired { .. }),
            "{error:?}"
        );
        assert!(fake.calls().is_empty(), "no brew command may run");
    }

    #[tokio::test]
    async fn update_rejects_non_brew_operations() {
        let fake = FakeRunner::new().strict();
        let backend = backend(&fake);
        let plan = manual_update_plan(Operation::FlatpakUpdate {
            app_id: "com.brave.Browser".to_owned(),
            installation: crate::plan::FlatpakInstallation::User,
        });
        let target = macos();
        let error = backend
            .update(UpdateRequest::new(&plan, &target))
            .await
            .unwrap_err();
        assert!(
            matches!(error, Error::Command(toride_runner::Error::Other(_))),
            "{error:?}"
        );
        assert!(fake.calls().is_empty());
    }

    #[tokio::test]
    async fn update_runs_the_cask_upgrade_argv_exactly() {
        let spec = command(BREW, ["upgrade", "--cask", "brave-browser"]);
        let fake = FakeRunner::new()
            .strict()
            .respond(spec.clone(), toride_runner::CommandOutput::from_stdout(""));
        let backend = backend(&fake);
        let plan = update_plan_for(true);
        let target = macos();
        backend
            .update(UpdateRequest::new(&plan, &target))
            .await
            .unwrap();
        fake.assert_called_with(&spec);
        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn update_runs_the_formula_upgrade_argv_without_type_flags() {
        let spec = command(BREW, ["upgrade", "brave-browser"]);
        let fake = FakeRunner::new()
            .strict()
            .respond(spec.clone(), toride_runner::CommandOutput::from_stdout(""));
        let backend = backend(&fake);
        let plan = update_plan_for(false);
        let target = macos();
        backend
            .update(UpdateRequest::new(&plan, &target))
            .await
            .unwrap();
        fake.assert_called_with(&spec);
        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn update_maps_nonzero_exit_to_command_error_carrying_stderr() {
        let spec = command(BREW, ["upgrade", "--cask", "brave-browser"]);
        let fake = FakeRunner::new().strict().respond(
            spec,
            toride_runner::CommandOutput::from_stderr(
                "Error: Cask 'brave-browser' is not installed.",
                1,
            ),
        );
        let backend = backend(&fake);
        let plan = update_plan_for(true);
        let target = macos();
        let error = backend
            .update(UpdateRequest::new(&plan, &target))
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                Error::Command(toride_runner::Error::CommandFailed { .. })
            ),
            "{error:?}"
        );
        assert!(
            error.to_string().contains("not installed"),
            "stderr tail must travel with the error: {error}"
        );
    }

    #[tokio::test]
    async fn trait_outdated_delegates_to_the_unscoped_concrete_probe() {
        let spec = command(BREW, ["outdated", "--json=v2"]);
        let raw = read_fixture("homebrew/outdated.json");
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::from_stdout(raw.trim().to_owned()),
        );
        let backend = backend(&fake);
        let dyn_backend: &dyn Backend = &backend;
        let entries = dyn_backend.outdated().await.unwrap();
        assert_eq!(entries.len(), 3, "{entries:?}");
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn available_version_probes_the_token_info_envelope() {
        let spec = command(BREW, ["info", "--json=v2", "brave-browser"]);
        let cask = fixture_value("homebrew/cask-brave-browser.json");
        let document = serde_json::json!({ "formulae": [], "casks": [cask] });
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::from_stdout(document.to_string()),
        );
        let backend = backend(&fake);
        assert_eq!(
            backend
                .available_version(BrewKind::Cask, "brave-browser")
                .await
                .unwrap(),
            Some(Version::new("1.96.59.0"))
        );
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn available_version_reports_the_offered_stable_over_an_installed_formula_keg() {
        let spec = command(BREW, ["info", "--json=v2", "ripgrep"]);
        let document = serde_json::json!({
            "formulae": [{
                "name": "ripgrep",
                "versions": { "stable": "15.2.0" },
                "installed": [{ "version": "15.1.0" }]
            }],
            "casks": []
        });
        let fake = FakeRunner::new().strict().respond(
            spec,
            toride_runner::CommandOutput::from_stdout(document.to_string()),
        );
        let backend = backend(&fake);
        assert_eq!(
            backend
                .available_version(BrewKind::Formula, "ripgrep")
                .await
                .unwrap(),
            Some(Version::new("15.2.0")),
            "the offered stable, never the installed keg's version"
        );
    }

    #[tokio::test]
    async fn available_version_reports_the_offered_cask_version_over_the_installed_one() {
        let spec = command(BREW, ["info", "--json=v2", "brave-browser"]);
        let document = serde_json::json!({
            "formulae": [],
            "casks": [{
                "token": "brave-browser",
                "version": "139.0",
                "installed": "138.0.1"
            }]
        });
        let fake = FakeRunner::new().strict().respond(
            spec,
            toride_runner::CommandOutput::from_stdout(document.to_string()),
        );
        let backend = backend(&fake);
        assert_eq!(
            backend
                .available_version(BrewKind::Cask, "brave-browser")
                .await
                .unwrap(),
            Some(Version::new("139.0")),
            "the offered cask version, never the installed one"
        );
    }

    #[tokio::test]
    async fn available_version_discriminates_dual_kind_tokens_by_the_requested_kind() {
        let spec = command(BREW, ["info", "--json=v2", "widget"]);
        let document = serde_json::json!({
            "formulae": [{ "name": "widget", "versions": { "stable": "1.0" } }],
            "casks": [{ "token": "widget", "version": "2.0" }]
        });
        let output = toride_runner::CommandOutput::from_stdout(document.to_string());
        let fake = FakeRunner::new()
            .strict()
            .respond(spec.clone(), output.clone())
            .respond(spec, output);
        let backend = backend(&fake);
        assert_eq!(
            backend
                .available_version(BrewKind::Formula, "widget")
                .await
                .unwrap(),
            Some(Version::new("1.0")),
            "the formula arm answers a formula-scoped ask"
        );
        assert_eq!(
            backend
                .available_version(BrewKind::Cask, "widget")
                .await
                .unwrap(),
            Some(Version::new("2.0")),
            "the cask arm answers a cask-scoped ask"
        );
    }

    #[tokio::test]
    async fn available_version_skips_a_matching_formula_without_a_stable_version() {
        let spec = command(BREW, ["info", "--json=v2", "widget"]);
        let document = serde_json::json!({
            "formulae": [{ "name": "widget", "versions": { "stable": null }, "installed": [] }],
            "casks": [{ "token": "widget", "version": "2.0" }]
        });
        let output = toride_runner::CommandOutput::from_stdout(document.to_string());
        let fake = FakeRunner::new()
            .strict()
            .respond(spec.clone(), output.clone())
            .respond(spec, output);
        let backend = backend(&fake);
        assert_eq!(
            backend
                .available_version(BrewKind::Formula, "widget")
                .await
                .unwrap(),
            None,
            "a HEAD-only formula offers no stable version"
        );
        assert_eq!(
            backend
                .available_version(BrewKind::Cask, "widget")
                .await
                .unwrap(),
            Some(Version::new("2.0"))
        );
    }

    #[tokio::test]
    async fn trait_available_version_resolves_kind_less_formulae_first() {
        let spec = command(BREW, ["info", "--json=v2", "widget"]);
        let document = serde_json::json!({
            "formulae": [{ "name": "widget", "versions": { "stable": "1.0" } }],
            "casks": [{ "token": "widget", "version": "2.0" }]
        });
        let fake = FakeRunner::new().strict().respond(
            spec,
            toride_runner::CommandOutput::from_stdout(document.to_string()),
        );
        let backend = backend(&fake);
        let dyn_backend: &dyn Backend = &backend;
        assert_eq!(
            dyn_backend.available_version("widget").await.unwrap(),
            Some(Version::new("1.0")),
            "the kind-less trait ask resolves formulae before casks, the listing's document order"
        );
    }

    #[tokio::test]
    async fn available_version_returns_none_for_a_token_absent_from_the_envelope() {
        let spec = command(BREW, ["info", "--json=v2", "ghost"]);
        let document = serde_json::json!({ "formulae": [], "casks": [] });
        let fake = FakeRunner::new().strict().respond(
            spec,
            toride_runner::CommandOutput::from_stdout(document.to_string()),
        );
        let backend = backend(&fake);
        assert_eq!(
            backend
                .available_version(BrewKind::Cask, "ghost")
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn available_version_maps_an_unknown_token_failure_to_command_error() {
        let spec = command(BREW, ["info", "--json=v2", "ghost"]);
        let fake = FakeRunner::new().strict().respond(
            spec,
            toride_runner::CommandOutput::from_stderr(
                "Error: No available formula with the name \"ghost\".",
                1,
            ),
        );
        let backend = backend(&fake);
        let error = backend
            .available_version(BrewKind::Cask, "ghost")
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                Error::Command(toride_runner::Error::CommandFailed { .. })
            ),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn available_versions_lists_the_offered_version_for_the_kind() {
        let spec = command(BREW, ["info", "--json=v2", "ripgrep"]);
        let document = serde_json::json!({
            "formulae": [{
                "name": "ripgrep",
                "versions": { "stable": "15.2.0" },
                "installed": [{ "version": "15.1.0" }]
            }],
            "casks": []
        });
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::from_stdout(document.to_string()),
        );
        let backend = backend(&fake);
        assert_eq!(
            backend
                .available_versions(BrewKind::Formula, "ripgrep")
                .await
                .unwrap(),
            vec![Version::new("15.2.0")],
            "the offered stable — one element at most, never the installed keg"
        );
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn available_versions_is_empty_when_the_kind_offers_nothing() {
        let spec = command(BREW, ["info", "--json=v2", "widget"]);
        let document = serde_json::json!({
            "formulae": [{ "name": "widget", "versions": { "stable": null } }],
            "casks": [{ "token": "widget", "version": "2.0" }]
        });
        let fake = FakeRunner::new().strict().respond(
            spec,
            toride_runner::CommandOutput::from_stdout(document.to_string()),
        );
        let backend = backend(&fake);
        assert!(
            backend
                .available_versions(BrewKind::Formula, "widget")
                .await
                .unwrap()
                .is_empty(),
            "a HEAD-only formula offers no installable version"
        );
    }

    #[tokio::test]
    async fn trait_available_versions_collects_both_kinds_deduped() {
        let spec = command(BREW, ["info", "--json=v2", "widget"]);
        let dual = serde_json::json!({
            "formulae": [{ "name": "widget", "versions": { "stable": "1.0" } }],
            "casks": [{ "token": "widget", "version": "2.0" }]
        });
        let same = serde_json::json!({
            "formulae": [{ "name": "widget", "versions": { "stable": "1.0" } }],
            "casks": [{ "token": "widget", "version": "1.0" }]
        });
        let output = toride_runner::CommandOutput::from_stdout(dual.to_string());
        let deduped = toride_runner::CommandOutput::from_stdout(same.to_string());
        let fake = FakeRunner::new()
            .strict()
            .respond(spec.clone(), output)
            .respond(spec, deduped);
        let backend = backend(&fake);
        let dyn_backend: &dyn Backend = &backend;
        assert_eq!(
            dyn_backend.available_versions("widget").await.unwrap(),
            vec![Version::new("1.0"), Version::new("2.0")],
            "both kinds, document order"
        );
        assert_eq!(
            dyn_backend.available_versions("widget").await.unwrap(),
            vec![Version::new("1.0")],
            "a dual-kind token offering the same version lists it once"
        );
    }

    #[tokio::test]
    async fn pin_runs_the_kind_scoped_argv_exactly() {
        let spec = command(BREW, ["pin", "--formula", "ripgrep"]);
        let fake = FakeRunner::new()
            .strict()
            .respond(spec.clone(), toride_runner::CommandOutput::from_stdout(""));
        let backend = backend(&fake);
        backend.pin(BrewKind::Formula, "ripgrep").await.unwrap();
        fake.assert_called_with(&spec);
        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn unpin_scopes_the_cask_kind() {
        let spec = command(BREW, ["unpin", "--cask", "firefox"]);
        let fake = FakeRunner::new()
            .strict()
            .respond(spec.clone(), toride_runner::CommandOutput::from_stdout(""));
        let backend = backend(&fake);
        backend.unpin(BrewKind::Cask, "firefox").await.unwrap();
        fake.assert_called_with(&spec);
        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn trait_pin_resolves_the_formula_scope() {
        let spec = command(BREW, ["pin", "--formula", "ripgrep"]);
        let fake = FakeRunner::new()
            .strict()
            .respond(spec.clone(), toride_runner::CommandOutput::from_stdout(""));
        let backend = backend(&fake);
        let dyn_backend: &dyn Backend = &backend;
        dyn_backend.pin("ripgrep").await.unwrap();
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn pin_maps_failures_to_command_error_carrying_stderr() {
        let spec = command(BREW, ["pin", "--formula", "ghost"]);
        let fake = FakeRunner::new().strict().respond(
            spec,
            toride_runner::CommandOutput::from_stderr(
                "Error: No installed keg or formula with the name \"ghost\".",
                1,
            ),
        );
        let backend = backend(&fake);
        let error = backend.pin(BrewKind::Formula, "ghost").await.unwrap_err();
        assert!(
            matches!(
                error,
                Error::Command(toride_runner::Error::CommandFailed { .. })
            ),
            "{error:?}"
        );
        assert!(
            error.to_string().contains("No installed keg"),
            "stderr tail must travel with the error: {error}"
        );
    }

    // --- listing + status ----------------------------------------------------------

    /// The exact spec the installed listing runs, shared by the listing
    /// and status tests.
    fn installed_info_spec() -> toride_runner::CommandSpec {
        command(BREW, ["info", "--json=v2", "--installed"])
    }

    /// A strict fake answering the installed listing with both fixture
    /// items (ripgrep formula + brave cask) in the info envelope.
    fn listing_fake() -> FakeRunner {
        let cask = fixture_value("homebrew/cask-brave-browser.json");
        let formula = fixture_value("homebrew/formula-ripgrep.json");
        let document = serde_json::json!({ "formulae": [formula], "casks": [cask] });
        FakeRunner::new().strict().respond(
            installed_info_spec(),
            toride_runner::CommandOutput::from_stdout(document.to_string()),
        )
    }

    #[tokio::test]
    async fn list_installed_runs_brew_info_installed_json_v2_and_maps_entries() {
        let fake = listing_fake();
        let backend = backend(&fake);
        let apps = backend.list_installed(ListQuery::all()).await.unwrap();
        // The plain trait view keeps only id (= token) + version, in
        // document order (formulae first).
        assert_eq!(apps.len(), 2, "{apps:?}");
        assert_eq!(apps[0].id, "ripgrep");
        assert_eq!(apps[0].version.as_deref(), Some("15.2.0"));
        assert_eq!(apps[1].id, "brave-browser");
        assert_eq!(apps[1].version.as_deref(), Some("1.96.59.0"));
        fake.assert_called_with(&installed_info_spec());
    }

    #[tokio::test]
    async fn list_installed_keeps_the_fuller_typed_entries_available() {
        let fake = listing_fake();
        let backend = backend(&fake);
        let entries = backend.list_entries().await.unwrap();
        assert_eq!(entries.len(), 2, "{entries:?}");
        assert_eq!(entries[0].kind, BrewKind::Formula);
        assert_eq!(entries[1].kind, BrewKind::Cask);
        assert_eq!(entries[1].name.as_deref(), Some("Brave"));
    }

    #[tokio::test]
    async fn list_installed_filters_to_the_requested_ids() {
        let fake = listing_fake();
        let backend = backend(&fake);
        let apps = backend
            .list_installed(ListQuery::id("brave-browser"))
            .await
            .unwrap();
        assert_eq!(apps.len(), 1, "{apps:?}");
        assert_eq!(apps[0].id, "brave-browser");
    }

    #[tokio::test]
    async fn list_installed_maps_nonzero_exit_to_command_error() {
        let spec = installed_info_spec();
        let fake = FakeRunner::new().strict().respond(
            spec,
            toride_runner::CommandOutput::from_stderr("Error: could not read cellar", 1),
        );
        let backend = backend(&fake);
        let error = backend.list_installed(ListQuery::all()).await.unwrap_err();
        assert!(
            matches!(
                error,
                Error::Command(toride_runner::Error::CommandFailed { .. })
            ),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn status_derives_the_installed_version_from_the_listing() {
        // No status override exists: a bare id carries no cask/formula
        // kind (the direct probes are kind-scoped), so the trait's default
        // list-derived impl answers from the info listing.
        let fake = listing_fake();
        let backend = backend(&fake);
        let status = backend
            .status(StatusQuery::new("brave-browser"))
            .await
            .unwrap();
        assert_eq!(
            status,
            BackendStatus::Installed {
                version: Some("1.96.59.0".to_owned())
            }
        );
        fake.assert_called_with(&installed_info_spec());
    }

    #[tokio::test]
    async fn status_reports_not_installed_for_tokens_absent_from_the_listing() {
        let fake = listing_fake();
        let backend = backend(&fake);
        let status = backend.status(StatusQuery::new("nope")).await.unwrap();
        assert_eq!(status, BackendStatus::NotInstalled);
    }

    // --- installed-version probes ------------------------------------------------

    #[tokio::test]
    async fn installed_version_probes_casks_with_the_cask_scoped_flag() {
        let spec = command(BREW, ["list", "--cask", "--versions", "brave-browser"]);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::from_stdout("brave-browser 1.96.59.0\n"),
        );
        let backend = backend(&fake);
        assert_eq!(
            backend
                .installed_version(BrewKind::Cask, "brave-browser")
                .await
                .unwrap(),
            Some("1.96.59.0".to_owned())
        );
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn installed_version_probes_formulae_with_the_formula_scoped_flag() {
        let spec = command(BREW, ["list", "--formula", "--versions", "ripgrep"]);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::from_stdout("ripgrep 15.2.0\n"),
        );
        let backend = backend(&fake);
        assert_eq!(
            backend
                .installed_version(BrewKind::Formula, "ripgrep")
                .await
                .unwrap(),
            Some("15.2.0".to_owned())
        );
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn installed_version_returns_none_for_the_cask_degenerate_error_line() {
        // Absent casks normally fail silently like formulae (covered
        // below); brew emits this Error line only from the degenerate
        // token-dir-exists state — the markers must still catch it.
        let spec = command(BREW, ["list", "--cask", "--versions", "brave-browser"]);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::from_stderr(
                "Error: Cask 'brave-browser' is not installed.",
                1,
            ),
        );
        let backend = backend(&fake);
        assert_eq!(
            backend
                .installed_version(BrewKind::Cask, "brave-browser")
                .await
                .unwrap(),
            None
        );
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn installed_version_returns_none_for_the_silent_cask_not_installed_signal() {
        // The normal absent-cask signal is silent, same as formulae:
        // exit 1 with empty stdout and stderr.
        let spec = command(BREW, ["list", "--cask", "--versions", "nope"]);
        let fake = FakeRunner::new()
            .strict()
            .respond(spec, toride_runner::CommandOutput::from_stderr("", 1));
        let backend = backend(&fake);
        assert_eq!(
            backend
                .installed_version(BrewKind::Cask, "nope")
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn installed_version_returns_none_for_the_silent_formula_not_installed_signal() {
        // Unknown names to the formula-scoped list fail silently: exit 1
        // with empty stdout and stderr (brew only sets its failure flag).
        let spec = command(BREW, ["list", "--formula", "--versions", "nope"]);
        let fake = FakeRunner::new()
            .strict()
            .respond(spec, toride_runner::CommandOutput::from_stderr("", 1));
        let backend = backend(&fake);
        assert_eq!(
            backend
                .installed_version(BrewKind::Formula, "nope")
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn installed_version_maps_a_signal_killed_probe_to_command_error() {
        // Empty stderr alone must NOT classify not-installed: a brew killed
        // by a signal (exit 130, SIGINT) is a real error — the silent
        // not-installed signal is exit 1 only.
        let spec = command(BREW, ["list", "--cask", "--versions", "brave-browser"]);
        let fake = FakeRunner::new()
            .strict()
            .respond(spec, toride_runner::CommandOutput::from_stderr("", 130));
        let backend = backend(&fake);
        let error = backend
            .installed_version(BrewKind::Cask, "brave-browser")
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                Error::Command(toride_runner::Error::CommandFailed { .. })
            ),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn installed_version_maps_unrelated_failures_to_command_error() {
        let spec = command(BREW, ["list", "--cask", "--versions", "brave-browser"]);
        let fake = FakeRunner::new().strict().respond(
            spec,
            toride_runner::CommandOutput::from_stderr("Error: permission denied", 1),
        );
        let backend = backend(&fake);
        let error = backend
            .installed_version(BrewKind::Cask, "brave-browser")
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                Error::Command(toride_runner::Error::CommandFailed { .. })
            ),
            "{error:?}"
        );
    }

    // --- outdated ----------------------------------------------------------------

    #[tokio::test]
    async fn outdated_runs_unscoped_argv_and_returns_typed_entries() {
        let spec = command(BREW, ["outdated", "--json=v2"]);
        let raw = read_fixture("homebrew/outdated.json");
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::from_stdout(raw.trim().to_owned()),
        );
        let backend = backend(&fake);
        let entries = backend.outdated(OutdatedScope::All).await.unwrap();
        assert_eq!(entries.len(), 3, "{entries:?}");
        let ids: Vec<&str> = entries.iter().map(|entry| entry.id.as_str()).collect();
        assert_eq!(ids, ["ripgrep", "wget", "brave-browser"], "{entries:?}");
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn outdated_scopes_argv_to_casks() {
        let spec = command(BREW, ["outdated", "--cask", "--json=v2"]);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::from_stdout("{\"formulae\":[],\"casks\":[]}"),
        );
        let backend = backend(&fake);
        let entries = backend.outdated(OutdatedScope::Casks).await.unwrap();
        assert!(entries.is_empty());
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn outdated_scopes_argv_to_formulae() {
        let spec = command(BREW, ["outdated", "--formula", "--json=v2"]);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::from_stdout("{\"formulae\":[],\"casks\":[]}"),
        );
        let backend = backend(&fake);
        backend.outdated(OutdatedScope::Formulae).await.unwrap();
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn outdated_treats_exit_one_with_entries_as_the_answer() {
        let spec = command(BREW, ["outdated", "--json=v2"]);
        let raw = read_fixture("homebrew/outdated.json");
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::new(raw.trim().to_owned(), String::new(), Some(1)),
        );
        let backend = backend(&fake);
        let entries = backend.outdated(OutdatedScope::All).await.unwrap();
        assert_eq!(entries.len(), 3, "{entries:?}");
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn outdated_treats_exit_one_with_unparseable_stdout_as_failure() {
        let spec = command(BREW, ["outdated", "--json=v2"]);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::new(String::new(), String::new(), Some(1)),
        );
        let backend = backend(&fake);
        let error = backend.outdated(OutdatedScope::All).await.unwrap_err();
        assert!(
            matches!(error, Error::Command(toride_runner::Error::OutputParse(_))),
            "{error:?}"
        );
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn outdated_treats_other_exit_codes_as_failure() {
        let spec = command(BREW, ["outdated", "--json=v2"]);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::new(
                String::new(),
                "Error: unknown flag".to_owned(),
                Some(64),
            ),
        );
        let backend = backend(&fake);
        let error = backend.outdated(OutdatedScope::All).await.unwrap_err();
        assert!(
            matches!(
                error,
                Error::Command(toride_runner::Error::CommandFailed {
                    exit_code: Some(64),
                    ..
                })
            ),
            "{error:?}"
        );
        fake.assert_called_with(&spec);
    }

    #[test]
    fn outdated_sync_treats_exit_one_with_entries_as_the_answer() {
        let spec = command(BREW, ["outdated", "--json=v2"]);
        let raw = read_fixture("homebrew/outdated.json");
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::new(raw.trim().to_owned(), String::new(), Some(1)),
        );
        let backend = backend(&fake);
        let entries = backend.outdated_sync(OutdatedScope::All).unwrap();
        assert_eq!(entries.len(), 3, "{entries:?}");
        fake.assert_called_with(&spec);
    }

    // --- identity ----------------------------------------------------------------

    #[test]
    fn id_is_homebrew_and_supports_targets_by_os() {
        let backend = backend(&FakeRunner::new().strict());
        assert_eq!(backend.id(), BackendId::Homebrew);
        assert!(backend.supports(&Target::macos(Arch::Aarch64)));
        assert!(backend.supports(&Target::linux(
            Arch::X86_64,
            toride_registry::DistroFamily::Debian
        )));
        assert!(!backend.supports(&Target::new(Os::Windows, Arch::X86_64)));
    }

    #[test]
    fn brew_kind_displays_lowercase_slugs() {
        assert_eq!(BrewKind::Cask.to_string(), "cask");
        assert_eq!(BrewKind::Formula.to_string(), "formula");
    }

    #[test]
    fn brew_kind_flags_select_the_kind_scoped_probes() {
        assert_eq!(BrewKind::Cask.flag(), "--cask");
        assert_eq!(BrewKind::Formula.flag(), "--formula");
    }

    #[test]
    fn install_sync_refuses_dry_run_plans_without_dispatching() {
        let fake = FakeRunner::new().strict();
        let backend = backend(&fake);
        let target = macos();
        let error = backend
            .install_sync(InstallRequest::new(
                &install_plan_for(true).dry_run(true),
                &target,
            ))
            .unwrap_err();
        assert!(matches!(error, Error::DryRun { .. }), "{error:?}");
        assert!(fake.calls().is_empty(), "no brew command may run");
    }

    #[test]
    fn install_sync_runs_the_cask_argv_and_reports_the_probed_version() {
        let install_spec = command(BREW, ["install", "--cask", "brave-browser"]);
        let probe_spec = command(BREW, ["list", "--cask", "--versions", "brave-browser"]);
        let fake = FakeRunner::new()
            .strict()
            .respond(
                install_spec.clone(),
                toride_runner::CommandOutput::from_stdout(""),
            )
            .respond(
                probe_spec.clone(),
                toride_runner::CommandOutput::from_stdout("brave-browser 1.96.59.0\n"),
            );
        let backend = backend(&fake);
        let plan = install_plan_for(true);
        let target = macos();
        let outcome = backend
            .install_sync(InstallRequest::new(&plan, &target))
            .unwrap();
        assert_eq!(outcome.version.as_deref(), Some("1.96.59.0"));
        fake.assert_called_with(&install_spec);
        fake.assert_called_with(&probe_spec);
    }

    #[test]
    fn uninstall_sync_runs_the_cask_argv_exactly() {
        let spec = command(BREW, ["uninstall", "--cask", "brave-browser"]);
        let fake = FakeRunner::new()
            .strict()
            .respond(spec.clone(), toride_runner::CommandOutput::from_stdout(""));
        let backend = backend(&fake);
        let plan = uninstall_plan_for(true, false);
        let target = macos();
        backend
            .uninstall_sync(UninstallRequest::new(&plan, &target))
            .unwrap();
        fake.assert_called_with(&spec);
        fake.assert_no_unmatched_calls();
    }

    #[test]
    fn update_sync_runs_the_cask_upgrade_argv_exactly() {
        let spec = command(BREW, ["upgrade", "--cask", "brave-browser"]);
        let fake = FakeRunner::new()
            .strict()
            .respond(spec.clone(), toride_runner::CommandOutput::from_stdout(""));
        let backend = backend(&fake);
        let plan = update_plan_for(true);
        let target = macos();
        backend
            .update_sync(UpdateRequest::new(&plan, &target))
            .unwrap();
        fake.assert_called_with(&spec);
        fake.assert_no_unmatched_calls();
    }

    #[test]
    fn list_installed_sync_maps_and_filters_the_typed_listing() {
        let document = r#"{"formulae":[{"name":"ripgrep","versions":{"stable":"14.1.0"},"installed":[{"version":"14.1.0"}]}],"casks":[{"token":"brave-browser","name":["Brave"],"version":"1.96.59","installed":"1.96.59"}]}"#;
        let spec = command(BREW, ["info", "--json=v2", "--installed"]);
        let fake = FakeRunner::new()
            .strict()
            .respond(
                spec.clone(),
                toride_runner::CommandOutput::from_stdout(document),
            )
            .respond(
                spec.clone(),
                toride_runner::CommandOutput::from_stdout(document),
            );
        let backend = backend(&fake);
        let apps = backend.list_installed_sync(ListQuery::all()).unwrap();
        assert_eq!(
            apps,
            vec![
                InstalledApp {
                    id: "ripgrep".to_owned(),
                    version: Some("14.1.0".to_owned()),
                },
                InstalledApp {
                    id: "brave-browser".to_owned(),
                    version: Some("1.96.59".to_owned()),
                },
            ]
        );
        let only = backend
            .list_installed_sync(ListQuery::id("brave-browser"))
            .unwrap();
        assert_eq!(only.len(), 1);
        assert_eq!(only[0].id, "brave-browser");
    }

    #[test]
    fn installed_version_sync_classifies_present_and_silently_absent_tokens() {
        let present = command(BREW, ["list", "--cask", "--versions", "brave-browser"]);
        let absent = command(BREW, ["list", "--formula", "--versions", "ghost"]);
        let fake = FakeRunner::new()
            .strict()
            .respond(
                present.clone(),
                toride_runner::CommandOutput::from_stdout("brave-browser 1.96.59\n"),
            )
            .respond(
                absent.clone(),
                toride_runner::CommandOutput::from_stderr("", 1),
            );
        let backend = backend(&fake);
        assert_eq!(
            backend
                .installed_version_sync(BrewKind::Cask, "brave-browser")
                .unwrap()
                .as_deref(),
            Some("1.96.59")
        );
        assert_eq!(
            backend
                .installed_version_sync(BrewKind::Formula, "ghost")
                .unwrap(),
            None
        );
    }

    #[test]
    fn outdated_sync_parses_the_kind_scoped_document() {
        let spec = command(BREW, ["outdated", "--cask", "--json=v2"]);
        let document = r#"{"formulae":[],"casks":[{"name":"brave-browser","installed_versions":["1.90"],"current_version":"1.96","pinned":false}]}"#;
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::from_stdout(document),
        );
        let backend = backend(&fake);
        let entries = backend.outdated_sync(OutdatedScope::Casks).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "brave-browser");
        assert_eq!(entries[0].current_version.as_deref(), Some("1.96"));
    }

    #[test]
    fn available_version_sync_reports_the_offered_cask_version() {
        let spec = command(BREW, ["info", "--json=v2", "brave-browser"]);
        let document = r#"{"formulae":[],"casks":[{"token":"brave-browser","version":"1.96.59","installed":"1.90"}]}"#;
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::from_stdout(document),
        );
        let backend = backend(&fake);
        assert_eq!(
            backend
                .available_version_sync(BrewKind::Cask, "brave-browser")
                .unwrap(),
            Some(Version::new("1.96.59"))
        );
    }

    #[test]
    fn pin_sync_and_unpin_sync_run_the_kind_scoped_argv() {
        let pin_spec = command(BREW, ["pin", "--formula", "ripgrep"]);
        let unpin_spec = command(BREW, ["unpin", "--formula", "ripgrep"]);
        let fake = FakeRunner::new()
            .strict()
            .respond(
                pin_spec.clone(),
                toride_runner::CommandOutput::from_stdout(""),
            )
            .respond(
                unpin_spec.clone(),
                toride_runner::CommandOutput::from_stdout(""),
            );
        let backend = backend(&fake);
        backend.pin_sync(BrewKind::Formula, "ripgrep").unwrap();
        backend.unpin_sync(BrewKind::Formula, "ripgrep").unwrap();
        fake.assert_called_with(&pin_spec);
        fake.assert_called_with(&unpin_spec);
    }
}
