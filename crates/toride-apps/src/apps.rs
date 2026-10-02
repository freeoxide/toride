//! # Apps facade
//!
//! [`Apps`] is the front door of the execution layer: one call per user
//! intent — ensure an app is installed (at a version, when asked), update
//! it, uninstall it, adopt an install someone else made, ask where it
//! stands, search the registries, list the versions its backend offers,
//! pin and unpin — composing every lower layer this crate built:
//!
//! 1. **Detect before resolve** (the toride-installer
//!    `Detector`/`EnsureOutcome` rule): [`Apps::ensure_installed`] answers
//!    from purely local state first — the install manifest plus the
//!    backends' kind-aware probes — with **zero registry adapter calls**
//!    when the manifest already records the app and its backend still
//!    confirms it. Only a true miss resolves through the registry
//!    [`Adapter`]s, plans via [`plan_install`], and executes through the
//!    routed [`Backend`].
//! 2. **Record what actually ran**: after a successful install the manifest
//!    record is built from the **executed** plan operation — the flatpak
//!    ref the backend ran (never re-derived from the registry app), the
//!    brew token + cask kind, the distro package + family — plus the
//!    verified version, and saved atomically. Uninstalls read the
//!    **record's** identifiers back as the source of truth, never
//!    re-planning (an app installed under one arch must uninstall even
//!    when re-planning would spell a different ref).
//! 3. **Honest outcomes**: [`EnsureAppOutcome`] mirrors toride-installer's
//!    `EnsureOutcome` — `AlreadyPresent(AppStatus)` (the manifest+backend
//!    answer, including `Foreign`: an app someone else installed is kept
//!    as-is, like an on-`$PATH` copy) or `Installed { .. }` carrying the
//!    recorded identifiers, the version, and whether the facade's own
//!    post-install probe confirmed them. Every degraded-but-real outcome
//!    carries a typed `warning` instead of failing silently: execution
//!    succeeded but post-verify could not confirm, or the install
//!    succeeded but the manifest failed to save (surfaced, never claimed
//!    as a failed install).
//!
//! ## Record store and recovery
//!
//! The durable ledger lives behind a [`RecordStore`]
//! ([`AppsBuilder::with_record_store`]); the default is the crate's JSON
//! manifest at the resolved path. It loads once at [`AppsBuilder::build`]
//! and is held in memory (a single-process CLI assumption; concurrent
//! writers are last-rename-wins per the manifest's contract). A corrupt
//! document — above all one written by a newer toride — is **quarantined
//! aside, never a fatal stop and never saved over**: the facade starts
//! from empty, [`Apps::quarantined`] names the moved file, and the next
//! successful mutation writes a fresh document.
//!
//! [`RecordStore`]: crate::store::RecordStore
//!
//! ## Elevation and Foreign removal
//!
//! - Distro plans require root and toride never auto-sudoes (the A1
//!   contract): pass `elevated(true)` on the options after arranging
//!   privileges, or the backend refuses with
//!   [`Error::ElevationRequired`](crate::Error::ElevationRequired) before
//!   any dispatch.
//! - Uninstalling an app toride has no record for (a `Foreign` install)
//!   is refused by default with [`AppsError::ForeignNotManaged`]; pass
//!   `force` on [`AppUninstallOptions`] to remove it anyway, or
//!   [`Apps::adopt`] it first to claim the install — both explicit, typed
//!   decisions, never silent ones.
//!
//! ## The blocking twin
//!
//! [`AppsBlocking`] (via [`Apps::blocking`]) exposes the same lifecycle
//! verbs synchronously — every command on the calling thread, every
//! manifest save in-line — for embedders without an async runtime. The
//! registry's adapter trait is async, so the blocking surface takes
//! resolved registry apps where this facade resolves ids, its
//! registry-dependent arms answer
//! [`AppsError::BlockingResolveRequired`] (`status` alone degrades to
//! `NotInstalled`, matching this facade's resolve-failure arm), and it
//! offers no `search`.
//!
//! ## Example
//!
//! ```rust,ignore
//! use toride_apps::apps::{AppInstallOptions, Apps, EnsureAppOutcome};
//!
//! # async fn run(apps: &mut Apps, id: toride_registry::TorideId) -> toride_apps::apps::AppsResult<()> {
//! match apps.ensure_installed(&id, AppInstallOptions::default()).await? {
//!     EnsureAppOutcome::AlreadyPresent(status) => { /* kept as-is, nothing ran */ }
//!     EnsureAppOutcome::Installed { ids, version, warning, .. } => {
//!         if let Some(warning) = warning { eprintln!("{warning}"); }
//!     }
//! }
//! # Ok(())
//! # }
//! ```

use std::collections::BTreeMap;
use std::sync::Arc;

use camino::Utf8PathBuf;
use toride_registry::model::{App, InstallMethod, SourceRef};
use toride_registry::{Adapter, Registry, TorideId};

use crate::backend::{
    Backend, BackendId, BackendStatus, InstallRequest, StatusQuery, UninstallRequest,
    UpdateRequest, Version,
};
#[cfg(feature = "direct")]
use crate::backends::DirectBackend;
use crate::backends::distro::detect_host_family;
use crate::backends::flatpak::FlatpakListScope;
use crate::backends::homebrew::{BrewKind, OutdatedScope};
use crate::backends::{DistroBackend, FlatpakBackend, HomebrewBackend};
use crate::error::Error as BackendError;
use crate::manifest::{
    InstallManifest, InstallRecord, ManifestError, ManifestResult, NativeIds, RecordSnapshot,
};
use crate::plan::{
    FlatpakInstallation, InstallOptions, InstallPlan, Operation, PackageManager, Target,
    UninstallOptions, UninstallPlan, UpdatePlan, plan_install, plan_uninstall,
};
use crate::runner::CommandRunner;
use crate::status::{AppStatus, BackendSet, app_status, app_status_sync};
use crate::store::{JsonRecordStore, RecordStore, StoreLoad};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Convenience alias for results of the facade's operations.
pub type AppsResult<T> = std::result::Result<T, AppsError>;

/// Failures of the [`Apps`] facade. Deliberately a facade-local enum (the
/// same pattern as [`ManifestError`], not variants on the crate's
/// execution [`Error`](crate::Error)): the facade fails in ways no single
/// lower layer does — unresolved ids, refused Foreign removals, absent
/// backends — and it *wraps* each layer's own error via `#[from]`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AppsError {
    /// An execution-layer failure from the crate's core error: plan-stage
    /// refusals (disabled app, platform mismatch, unroutable method),
    /// elevation/dry-run guard refusals, or backend command failures.
    #[error(transparent)]
    Backend(#[from] crate::Error),

    /// A registry adapter failed during resolve or search.
    #[error("registry source failed: {0}")]
    Registry(#[from] toride_registry::Error),

    /// The record store failed to load in a way recovery could not
    /// absorb, or to persist after a mutation. A corrupt prior document
    /// is not a load failure: the default JSON store quarantines it
    /// aside and the facade starts from empty
    /// ([`Apps::quarantined`] names the moved file) — only a quarantine
    /// that cannot happen, or a store that cannot be read at all, errors
    /// here. Post-mutation persist failures surface per verb: as outcome
    /// warnings where the mutation itself already succeeded, as this
    /// error where the record is the operation.
    #[error("{0}")]
    Manifest(#[from] ManifestError),

    /// No registered adapter resolves the id: the facade asked every
    /// adapter (in registration order) to look up its source-native id
    /// equal to the canonical slug, and none knew it.
    #[error("no registered registry source resolves app `{id}`")]
    Unresolved {
        /// Canonical toride id nothing resolved.
        id: String,
    },

    /// The uninstall target is installed but carries no toride record —
    /// someone else installed it. Refused unless the caller passes
    /// `force` (an explicit, typed decision).
    #[error("`{id}` is installed but not by toride — {detail}; pass force to remove it anyway")]
    ForeignNotManaged {
        /// Canonical toride id of the refused app.
        id: String,
        /// Evidence the backends reported for the foreign presence.
        detail: String,
    },

    /// The plan routes to a backend this facade instance does not hold —
    /// e.g. a cask install on a facade built without the homebrew backend
    /// attached.
    #[error("the plan routes to {backend}, which is not attached to this facade")]
    BackendUnavailable {
        /// Backend the plan selected.
        backend: BackendId,
    },

    /// An operation the facade cannot turn into (or read back as) a
    /// manifest-recordable identity: a non-install operation where an
    /// install was required, or a flatpak ref without an app id segment.
    #[error("app `{app}` carries an operation the facade cannot record: {operation}")]
    UnrecordableOperation {
        /// Canonical toride id of the offending app.
        app: String,
        /// What was wrong with the operation.
        operation: String,
    },

    /// The builder found no manifest to bind: no record store was
    /// supplied, no path was set, and the platform data directory (the
    /// manifest's default location) did not resolve. Pass an explicit
    /// path or a record store.
    #[error(
        "no manifest path: the platform data directory did not resolve; pass an explicit path or a record store to the builder"
    )]
    NoManifestPath,

    /// The adopt target already carries a toride record: adoption claims
    /// installs toride never recorded, so a managed app is a caller
    /// mistake, not a state change.
    #[error("cannot adopt `{id}`: toride already has a record for it")]
    AlreadyRecorded {
        /// Canonical toride id of the app.
        id: String,
    },

    /// The adopt provenance names identifiers no attached backend reports
    /// present: adoption claims a detected install, so an absent one is
    /// refused rather than recorded.
    #[error("cannot adopt `{id}`: {detail}")]
    AdoptionAbsent {
        /// Canonical toride id of the app.
        id: String,
        /// What the confirming probe found absent.
        detail: String,
    },

    /// The update target carries no toride install record: update replays
    /// the record's own identifiers, so an app toride never recorded
    /// cannot be updated through this verb.
    #[error(
        "cannot update `{id}`: toride has no install record for it — ensure_installed it first"
    )]
    UnrecordedUpdate {
        /// Canonical toride id of the app.
        id: String,
    },

    /// The options name a target version this toride cannot pin to —
    /// install-time version selection and brew pinning exist, but the
    /// update verb itself always moves to the manager's current.
    #[error(
        "cannot update `{id}` to {target}: target pinning is not implemented — updates move to the manager's current version"
    )]
    UpdateTargetNotPinnable {
        /// Canonical toride id of the app.
        id: String,
        /// The requested target version's native spelling.
        target: String,
    },

    /// The pin target carries no toride install record: pin operates on
    /// what the manifest knows toride installed, exactly like update.
    #[error("cannot pin `{id}`: toride has no install record for it — ensure_installed it first")]
    UnrecordedPin {
        /// Canonical toride id of the app.
        id: String,
    },

    /// The unpin target carries no toride install record — the mirror of
    /// [`AppsError::UnrecordedPin`].
    #[error("cannot unpin `{id}`: toride has no install record for it — ensure_installed it first")]
    UnrecordedUnpin {
        /// Canonical toride id of the app.
        id: String,
    },

    /// The blocking facade was asked to resolve an id through the registry.
    /// Registry adapters are async, so the blocking surface cannot resolve:
    /// pass the resolved registry app (`AppsBlocking::ensure_installed` /
    /// `AppsBlocking::uninstall_app`) or use the async facade.
    #[error(
        "cannot resolve `{id}` on the blocking facade: registry adapters are async — pass the resolved app or use the async facade"
    )]
    BlockingResolveRequired {
        /// Canonical toride id of the app.
        id: String,
    },
}

// ---------------------------------------------------------------------------
// Options and outcomes
// ---------------------------------------------------------------------------

/// Options for [`Apps::ensure_installed`].
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AppInstallOptions {
    /// Elevation grant: `true` only when the caller has arranged root
    /// privileges. Distro plans require it; the facade never acquires
    /// elevation itself (the no-auto-sudo contract — a requiring plan
    /// without the grant is refused before any dispatch).
    pub elevated: bool,
    /// The exact thing to install (`None` = whatever the manager considers
    /// current). Spelled into the plan's native addressing — see
    /// [`InstallOptions::version`]. Presence at another version does not
    /// satisfy a request carrying one: the facade installs at the
    /// requested version instead of answering
    /// [`EnsureAppOutcome::AlreadyPresent`]. Distro methods cannot express
    /// a version; the request is refused at plan time.
    pub version: Option<Version>,
}

impl AppInstallOptions {
    /// All-default options (no elevation grant, the manager's current
    /// version).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            elevated: false,
            version: None,
        }
    }

    /// Assert that elevation has been arranged — consume-and-return, the
    /// same fluent spelling [`InstallRequest::elevated`] uses.
    ///
    /// [`InstallRequest::elevated`]: crate::InstallRequest::elevated
    #[must_use]
    pub const fn elevated(mut self, elevated: bool) -> Self {
        self.elevated = elevated;
        self
    }

    /// Select an exact version to install — consume-and-return; `None`
    /// takes whatever the manager considers current.
    #[must_use]
    pub fn version(mut self, version: Option<Version>) -> Self {
        self.version = version;
        self
    }
}

/// Options for [`Apps::uninstall`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AppUninstallOptions {
    /// Casks only: also remove shared preferences and caches
    /// (`brew uninstall --zap`). Ignored for formulae and non-homebrew
    /// methods — the same rule the planner applies.
    pub zap: bool,
    /// Elevation grant — see [`AppInstallOptions::elevated`]; distro
    /// uninstalls require it.
    pub elevated: bool,
    /// Allow removing a **Foreign** install (present, but no toride
    /// record). Without this the facade refuses with
    /// [`AppsError::ForeignNotManaged`]; with it the removal is an
    /// explicit, typed decision the caller owns.
    pub force: bool,
}

impl AppUninstallOptions {
    /// All-default options (no zap, no elevation grant, no force).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            zap: false,
            elevated: false,
            force: false,
        }
    }

    /// Toggle the cask zap flag — consume-and-return.
    #[must_use]
    pub const fn zap(mut self, zap: bool) -> Self {
        self.zap = zap;
        self
    }

    /// Assert that elevation has been arranged — consume-and-return.
    #[must_use]
    pub const fn elevated(mut self, elevated: bool) -> Self {
        self.elevated = elevated;
        self
    }

    /// Allow removing a Foreign install — consume-and-return.
    #[must_use]
    pub const fn force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }
}

/// Options for [`Apps::update`].
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct AppUpdateOptions {
    /// Elevation grant — see [`AppInstallOptions::elevated`]; distro
    /// updates require it.
    pub elevated: bool,
    /// Preview the update instead of executing it: no command runs, the
    /// manifest is untouched, and the outcome is
    /// [`UpdateOutcome::Preview`].
    pub dry_run: bool,
    /// Target version to update to; `None` = whatever the manager
    /// considers current. A `Some` target is refused while pinning is
    /// unimplemented ([`AppsError::UpdateTargetNotPinnable`]).
    pub target: Option<Version>,
}

impl AppUpdateOptions {
    /// All-default options (no elevation grant, no dry run, manager's
    /// current version).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            elevated: false,
            dry_run: false,
            target: None,
        }
    }

    /// Assert that elevation has been arranged — consume-and-return.
    #[must_use]
    pub const fn elevated(mut self, elevated: bool) -> Self {
        self.elevated = elevated;
        self
    }

    /// Preview instead of executing — consume-and-return.
    #[must_use]
    pub const fn dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    /// Pin the update to a target version — consume-and-return.
    #[must_use]
    pub fn target(mut self, target: Option<Version>) -> Self {
        self.target = target;
        self
    }
}

/// Outcome of [`Apps::update`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum UpdateOutcome {
    /// The manager already reports the app current (its stale signal
    /// excludes the id, or installed equals available); nothing ran.
    UpToDate,
    /// The upgrade ran; `from`/`to` are the versions probed before and
    /// after, `None` where the backend cannot report one (flatpak apps
    /// without appdata metadata, apk's version-less listing).
    Updated {
        /// Version before the upgrade, when a probe reported one.
        from: Option<Version>,
        /// Version after the upgrade, when a probe reported one.
        to: Option<Version>,
    },
    /// A dry run: nothing executed, nothing recorded — the argv that would
    /// run plus the resolved versions.
    Preview(UpdatePreview),
}

/// What a dry-run [`Apps::update`] would run — a thin render over the
/// [`UpdatePlan`] plus the two resolved versions.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UpdatePreview {
    /// The canonical argv the update would execute.
    pub argv: Vec<String>,
    /// The currently installed version, when a probe reported one.
    pub from: Option<Version>,
    /// The version the manager offers now, when a probe reported one.
    pub to: Option<Version>,
}

/// What [`Apps::adopt`] claims: the backend-native identifiers of the
/// detected install, plus the install time when the detection knows one
/// (the adoption moment otherwise).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AdoptProvenance {
    /// The detected install's backend-native identifiers — the identity
    /// every later uninstall/update replays, exactly like an executed
    /// record's.
    pub ids: NativeIds,
    /// When the claimed install happened, when the caller knows it (a
    /// mirrored receipt's stamp); `None` stamps the adoption moment.
    pub installed_at: Option<u64>,
}

impl AdoptProvenance {
    /// Claim `ids`, installed at an unknown time.
    #[must_use]
    pub fn new(ids: NativeIds) -> Self {
        Self {
            ids,
            installed_at: None,
        }
    }
}

/// Outcome of [`Apps::ensure_installed`] — the toride-installer
/// `EnsureOutcome` semantics on this crate's seams: an already-satisfying
/// state is kept with zero resolve/plan/execute work; a true miss is
/// installed, recorded, and post-verified.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum EnsureAppOutcome {
    /// The app already satisfies the request and nothing ran — no adapter
    /// was consulted, no plan built, no command dispatched. The carried
    /// [`AppStatus`] says which case held:
    /// [`AppStatus::Installed`] (the manifest record's backend confirmed
    /// the recorded identifiers, reporting the *current* version), or
    /// [`AppStatus::Foreign`] (a backend reports the app's native
    /// identifiers present, but toride never recorded installing it — the
    /// copy is kept as-is, exactly like toride-installer keeps a
    /// satisfying on-`$PATH` copy). When the options requested an exact
    /// [`version`](AppInstallOptions::version), this arm fires only when
    /// the record answers at exactly that version (brew's probed version
    /// equals it; the recorded flatpak ref's branch equals it) — presence
    /// at another version falls through and installs at the requested
    /// one, and a Foreign copy never vouches for a version it did not
    /// report.
    AlreadyPresent(AppStatus),

    /// Installed now. The identifiers are the **executed** ones (the
    /// manifest record's payload), the version is what the post-verify
    /// probe reported (falling back to the backend's own post-install
    /// report), and `warning` carries every degraded-but-real condition —
    /// the install succeeded even when one is present.
    Installed {
        /// Backend that performed the install.
        backend: BackendId,
        /// The actually-installed identifiers, recorded in the manifest.
        ids: NativeIds,
        /// Verified version when the probes report one (`None` = installed
        /// without an observable version — legitimate for flatpak apps
        /// without appdata metadata — or unverified, see `warning`).
        version: Option<String>,
        /// Whether the facade's own post-install probe confirmed presence.
        verified: bool,
        /// Non-fatal degraded conditions, human-readable (post-verify
        /// could not confirm; the manifest failed to save). `None` when
        /// everything verified and persisted cleanly.
        warning: Option<String>,
    },
}

/// Outcome of [`Apps::uninstall`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum UninstallAppOutcome {
    /// Nothing to remove: no manifest record and no backend reports the
    /// app's identifiers present. Nothing was dispatched.
    AlreadyAbsent,

    /// Removed. Carries a `warning` when execution succeeded but the
    /// facade's post-uninstall probe could not confirm absence (or the
    /// manifest failed to save — the record was removed in memory either
    /// way).
    Removed {
        /// Backend that performed the uninstall.
        backend: BackendId,
        /// The identifiers the removal ran against — the manifest record's
        /// own for toride installs, the registry-derived ones for a forced
        /// Foreign removal.
        ids: NativeIds,
        /// Non-fatal degraded conditions, human-readable. `None` when
        /// removal verified clean and the manifest persisted.
        warning: Option<String>,
    },
}

// ---------------------------------------------------------------------------
// The facade
// ---------------------------------------------------------------------------

/// The backends this facade instance holds — one optional slot per install
/// technology, long-lived (detected once, reused per query). The borrowed
/// [`BackendSet`] the status layer consumes is built from these per query.
#[derive(Default)]
struct AttachedBackends {
    /// Homebrew backend, when brew is usable on this host.
    homebrew: Option<HomebrewBackend>,
    /// Flatpak backend, when flatpak is usable on this host.
    flatpak: Option<FlatpakBackend>,
    /// Distro backend, when a family manager is usable on this host.
    distro: Option<DistroBackend>,
    /// Direct-download backend, when attached (the `direct` feature).
    #[cfg(feature = "direct")]
    direct: Option<DirectBackend>,
}

/// The app install/uninstall front door: registry adapters for resolve,
/// the planner for exact operations, the attached backends for execution,
/// and a [`RecordStore`] as the durable record of what toride did (the
/// default is the crate's JSON manifest).
///
/// Build one with [`Apps::builder`]; mutating operations take `&mut self`
/// (the in-memory records are single-owner by design — see the module
/// docs), while [`Apps::status`] and [`Apps::search`] take `&self`.
pub struct Apps {
    /// The seam every attached backend executes through (each backend
    /// carries its own clone; this handle is the canonical one for the
    /// facade instance, exposed for callers building further backends).
    runner: CommandRunner,
    /// The host target plans are derived for.
    target: Target,
    /// The long-lived backends, one optional slot per technology.
    backends: AttachedBackends,
    /// The durable ledger persistence — loaded once at build, saved after
    /// each successful mutation.
    store: Arc<dyn RecordStore>,
    /// The working records, loaded from the store at build (missing
    /// store = empty; corrupt prior state = quarantined, see the module
    /// docs).
    records: BTreeMap<TorideId, InstallRecord>,
    /// Where a corrupt prior store document was quarantined at build;
    /// `None` when the store loaded cleanly.
    quarantined: Option<Utf8PathBuf>,
    registry: Registry,
}

impl Apps {
    /// Start building a facade — see [`AppsBuilder`].
    #[must_use]
    pub fn builder() -> AppsBuilder {
        AppsBuilder::new()
    }

    /// Wrap this facade in its blocking spelling — [`AppsBlocking`], the
    /// sync twin sharing this instance's records, store, and backends.
    #[must_use]
    pub fn blocking(self) -> AppsBlocking {
        AppsBlocking::new(self)
    }

    /// The host target this facade plans for.
    #[must_use]
    pub fn target(&self) -> Target {
        self.target
    }

    /// The runner seam this facade was built over.
    #[must_use]
    pub fn runner(&self) -> &CommandRunner {
        &self.runner
    }

    /// The working records this facade holds, each paired with its app
    /// id and ordered by id (loaded from the store at build; mutated by
    /// [`Apps::ensure_installed`] / [`Apps::uninstall`] /
    /// [`Apps::adopt`]). The id is the key every record-sourced verb
    /// takes; adopted records carry no plan to read it from, so the pair
    /// is the only way to recover theirs.
    #[must_use]
    pub fn records(&self) -> Vec<(&TorideId, &InstallRecord)> {
        self.records.iter().collect()
    }

    /// Where a corrupt prior store document was quarantined at build, when
    /// recovery moved one aside — `None` when the store loaded cleanly.
    #[must_use]
    pub fn quarantined(&self) -> Option<&Utf8PathBuf> {
        self.quarantined.as_ref()
    }

    /// Ensure `id` is installed on the host, installing it when missing.
    ///
    /// The pipeline, in order:
    ///
    /// 1. **Detect before resolve** — with zero adapter calls: when the
    ///    manifest records the app and the recorded backend still confirms
    ///    the recorded identifiers, return
    ///    [`EnsureAppOutcome::AlreadyPresent`] with the current-version
    ///    [`AppStatus::Installed`] (one confirming probe, no plan, no
    ///    execution — a stale record whose backend no longer reports the
    ///    app falls through and re-installs). A requested version gates
    ///    this arm: only a record answering at exactly that version
    ///    (brew's probed version, the recorded flatpak ref's branch)
    ///    satisfies; anything else falls through and installs at the
    ///    requested version.
    /// 2. **Resolve** — ask each adapter, in registration order, to look
    ///    up its source-native id equal to the canonical slug; the first
    ///    hit wins ([`AppsError::Unresolved`] otherwise).
    /// 3. **Foreign check** — when toride has no record, a backend
    ///    reporting the app's native identifiers present means someone
    ///    else installed it: keep it and return
    ///    [`EnsureAppOutcome::AlreadyPresent`] with
    ///    [`AppStatus::Foreign`], exactly like toride-installer keeps a
    ///    satisfying on-`$PATH` copy — but only for a version-less
    ///    request: a Foreign copy reports no version to vouch with, so an
    ///    exact-version request falls through and installs.
    /// 4. **Plan and execute** — [`plan_install`] derives the exact
    ///    operation for [`Apps::target`], spelling a requested
    ///    [`AppInstallOptions::version`] into the method's native
    ///    addressing; when nothing is present and the backend's own
    ///    offering equals the request, the manager's current installs
    ///    instead (it lands exactly the requested thing where a pin could
    ///    address a spelling the manager does not resolve); the routed
    ///    backend executes it with the caller's elevation grant (distro
    ///    plans without one are refused before any dispatch).
    /// 5. **Post-verify and record** — the facade's own kind-aware probe
    ///    (brew `list <kind> --versions`, the flatpak scoped listing, the
    ///    distro package query) confirms presence and reads the version;
    ///    the manifest record is built from the **executed** operation and
    ///    saved atomically. A probe that cannot confirm, or a failed save,
    ///    lands in the outcome's `warning` — the install itself succeeded.
    ///
    /// # Errors
    ///
    /// [`AppsError::Unresolved`] when no adapter knows the id;
    /// [`AppsError::Backend`] for plan-stage refusals (including a
    /// requested version a distro method cannot express), elevation/
    /// dry-run guards, and command failures; [`AppsError::BackendUnavailable`]
    /// when the plan routes to an unattached backend;
    /// [`AppsError::Registry`] when an adapter fails; probe failures
    /// degrade to warnings, not errors.
    pub async fn ensure_installed(
        &mut self,
        id: &TorideId,
        options: AppInstallOptions,
    ) -> AppsResult<EnsureAppOutcome> {
        // 1. Detect before resolve: the manifest record plus one
        //    confirming backend probe, zero adapter calls — gated on the
        //    requested version when one is named.
        let mut present = false;
        let recorded = app_status(self.records.get(id), None, &self.backend_set()).await?;
        if matches!(recorded, AppStatus::Installed { .. }) {
            present = true;
            let satisfies = self.records.get(id).is_some_and(|record| {
                requested_version_satisfied(&record.ids, &recorded, options.version.as_ref())
            });
            if satisfies {
                return Ok(EnsureAppOutcome::AlreadyPresent(recorded));
            }
        }
        // 2. Resolve through the registry adapters.
        let app = self.resolve(id).await?;
        // 3. Foreign presence (only meaningful without a record — a record
        //    that failed confirmation in step 1 re-installs below); a
        //    Foreign copy satisfies only a version-less request.
        if !self.records.contains_key(id) {
            let native = self.native_ids_for(&app);
            let status = app_status(None, native.as_ref(), &self.backend_set()).await?;
            if let AppStatus::Foreign { .. } = status {
                if options.version.is_none() {
                    return Ok(EnsureAppOutcome::AlreadyPresent(status));
                }
                present = true;
            }
        }
        // 4. Plan, then derive the record identity from the EXECUTED
        //    operation (before any mutation, so a malformed plan fails
        //    with nothing dispatched).
        let version = if present {
            options.version.clone()
        } else {
            self.version_for_plan(&app, options.version.clone()).await
        };
        let plan = plan_install(&app, &self.target, &InstallOptions { version })?;
        let backend = self.backend_for(plan.backend)?;
        let ids = self.native_ids_from_executed(&plan)?;
        let outcome = backend
            .install(InstallRequest::new(&plan, &self.target).elevated(options.elevated))
            .await?;
        // 5. Post-verify through the kind-aware probes, then record.
        let verification = self.verify_presence(&ids).await;
        let verified = matches!(verification, Ok(Presence::Present(_)));
        let subject = native_subject(&ids);
        let mut warning = match &verification {
            Ok(Presence::Present(_)) => None,
            Ok(Presence::Absent) => Some(format!(
                "installed, but the post-install verify no longer reports {subject} — recorded unverified"
            )),
            Err(error) => Some(format!(
                "installed, but the post-install verify probe failed: {error} — recorded unverified"
            )),
        };
        let verified_version = match verification {
            Ok(Presence::Present(version)) => version,
            _ => None,
        };
        let recorded_version = verified_version.or(outcome.version);
        let record_key = plan.app.clone();
        self.records.insert(
            record_key,
            InstallRecord::new(plan, ids.clone(), recorded_version.clone()),
        );
        if let Err(error) = self.save_records().await {
            push_warning(
                &mut warning,
                format!("installed, but saving the install manifest failed: {error}"),
            );
        }
        Ok(EnsureAppOutcome::Installed {
            backend: ids.backend(),
            version: recorded_version,
            ids,
            verified,
            warning,
        })
    }

    /// Uninstall `id`: read the manifest record back, plan the removal
    /// from the **record's own identifiers** (the source of truth — never
    /// re-planned), execute it (zap plumbed for casks), post-verify the
    /// app is gone, and remove the record.
    ///
    /// Without a record the flow is an explicit, typed decision: the
    /// facade resolves the app and asks the backends whether anything is
    /// present. Nothing present → [`UninstallAppOutcome::AlreadyAbsent`].
    /// Present but foreign → [`AppsError::ForeignNotManaged`] unless the
    /// options carry `force`, in which case the removal plans from the
    /// registry app (the only identity available) and runs the same
    /// execute → verify path; no manifest record is fabricated.
    ///
    /// # Errors
    ///
    /// [`AppsError::ForeignNotManaged`] for an unforced Foreign removal;
    /// [`AppsError::Unresolved`] / [`AppsError::Registry`] when no record
    /// exists and resolution fails; [`AppsError::Backend`] for guard
    /// refusals and command failures (an absent-target uninstall diverges
    /// by backend — brew errors, flatpak answers idempotently, distro
    /// errors — so this facade always post-verifies and trusts no single
    /// classification); verification and save failures degrade to
    /// warnings.
    pub async fn uninstall(
        &mut self,
        id: &TorideId,
        options: AppUninstallOptions,
    ) -> AppsResult<UninstallAppOutcome> {
        let Some(record) = self.records.get(id).cloned() else {
            return self.uninstall_unrecorded(id, options).await;
        };
        // Plan from the record's ids — the executed install's own
        // identifiers, replayed verbatim.
        let plan = uninstall_plan_from_record(id, &record, options.zap)?;
        let backend = self.backend_for(plan.backend)?;
        backend
            .uninstall(UninstallRequest::new(&plan, &self.target).elevated(options.elevated))
            .await?;
        let mut warning = self.verify_absence(&record.ids).await;
        self.records.remove(id);
        if let Err(error) = self.save_records().await {
            push_warning(
                &mut warning,
                format!(
                    "uninstalled, but saving the install manifest failed: {error} \
                     (the record was removed in memory)"
                ),
            );
        }
        Ok(UninstallAppOutcome::Removed {
            backend: record.backend,
            ids: record.ids,
            warning,
        })
    }

    /// The Foreign/absent arm of [`Apps::uninstall`] — no manifest record.
    async fn uninstall_unrecorded(
        &mut self,
        id: &TorideId,
        options: AppUninstallOptions,
    ) -> AppsResult<UninstallAppOutcome> {
        let app = self.resolve(id).await?;
        // Planning first refuses what cannot run (a Direct method's
        // uninstall replays a record, never registry data) before anything
        // is probed.
        let plan = plan_uninstall(&app, &self.target, &UninstallOptions { zap: options.zap })?;
        let Some(native) = self.native_ids_for(&app) else {
            // Unreachable behind a successful plan (every manager method
            // maps to ids); defense, not a silent skip.
            return Err(AppsError::UnrecordableOperation {
                app: id.as_str().to_owned(),
                operation: format!("{:?} carries no native identity", app.install),
            });
        };
        let status = app_status(None, Some(&native), &self.backend_set()).await?;
        let present_detail = match status {
            AppStatus::NotInstalled => return Ok(UninstallAppOutcome::AlreadyAbsent),
            AppStatus::Foreign { detail, .. } => detail,
            // Defensive: `Installed` requires a manifest record and there
            // is none — refuse through the same gate rather than act on a
            // contradictory answer.
            AppStatus::Installed { backend, .. } => format!(
                "a {backend} probe reports the app present, though toride has no record for it"
            ),
        };
        if !options.force {
            return Err(AppsError::ForeignNotManaged {
                id: id.as_str().to_owned(),
                detail: present_detail,
            });
        }
        let backend = self.backend_for(plan.backend)?;
        backend
            .uninstall(UninstallRequest::new(&plan, &self.target).elevated(options.elevated))
            .await?;
        let warning = self.verify_absence(&native).await;
        Ok(UninstallAppOutcome::Removed {
            backend: plan.backend,
            ids: native,
            warning,
        })
    }

    /// Update `id` to its manager's current version: read the manifest
    /// record, plan the upgrade from the **record's own identifiers**
    /// (never re-resolved through the adapters — zero registry round
    /// trips), resolve installed versus available, and — unless the
    /// manager already reports the app current — execute, re-probe the
    /// installed version, and rewrite it into the record.
    ///
    /// The currency decision is the manager's own stale signal where one
    /// exists — brew's kind-scoped `outdated` verdict alone, with an
    /// absent token never counting as current — and falls back to
    /// installed-equals-available (opaque strings, never semver) for
    /// backends without a signal. A dry run executes nothing and touches
    /// no state: it answers [`UpdateOutcome::Preview`] with the argv that
    /// would run. A post-upgrade probe that fails degrades to
    /// `to: None` (the upgrade itself succeeded), matching the
    /// post-verify degradation of [`Apps::ensure_installed`].
    ///
    /// # Errors
    ///
    /// [`AppsError::UnrecordedUpdate`] when toride has no record for `id`;
    /// [`AppsError::UpdateTargetNotPinnable`] when the options carry a
    /// target version; [`AppsError::BackendUnavailable`] when the record's
    /// backend is not attached; [`AppsError::Backend`] for guard refusals
    /// and command failures; [`AppsError::Manifest`] when persisting the
    /// rewritten record fails (the upgrade itself already succeeded).
    pub async fn update(
        &mut self,
        id: &TorideId,
        options: &AppUpdateOptions,
    ) -> AppsResult<UpdateOutcome> {
        if let Some(target) = &options.target {
            return Err(AppsError::UpdateTargetNotPinnable {
                id: id.as_str().to_owned(),
                target: target.to_string(),
            });
        }
        let Some(record) = self.records.get(id).cloned() else {
            return Err(AppsError::UnrecordedUpdate {
                id: id.as_str().to_owned(),
            });
        };
        let plan = update_plan_from_record(id, &record)?.dry_run(options.dry_run);
        let backend = self.backend_for(plan.backend)?;
        let native = native_id(&record.ids);
        let from = self.record_installed_version(&record.ids).await?;
        if options.dry_run {
            let to = self.record_available_version(&record.ids).await?;
            return Ok(UpdateOutcome::Preview(UpdatePreview {
                argv: plan.operation.argv(),
                from,
                to,
            }));
        }
        if self
            .record_is_current(&record.ids, backend, from.as_ref(), native)
            .await?
        {
            return Ok(UpdateOutcome::UpToDate);
        }
        backend
            .update(UpdateRequest::new(&plan, &self.target).elevated(options.elevated))
            .await?;
        let to = self
            .record_installed_version(&record.ids)
            .await
            .ok()
            .flatten();
        self.records.insert(
            id.clone(),
            record.with_version(to.as_ref().map(|version| version.as_str().to_owned())),
        );
        self.save_records().await?;
        Ok(UpdateOutcome::Updated { from, to })
    }

    /// Claim a detected-but-unrecorded install: record `id` as
    /// toride-managed under the backend-native identifiers `provenance`
    /// asserts, after one confirming presence probe supplies the version.
    /// Zero adapter calls and zero mutating commands run — adoption is
    /// bookkeeping over a detection, so the record carries no source
    /// plan, and later uninstalls/updates replay the adopted identifiers
    /// exactly like executed ones.
    ///
    /// # Errors
    ///
    /// [`AppsError::AlreadyRecorded`] when toride already holds a record
    /// for `id`; [`AppsError::AdoptionAbsent`] when the probe cannot
    /// confirm the asserted identifiers; [`AppsError::BackendUnavailable`]
    /// when their backend is not attached; [`AppsError::Backend`] when
    /// the confirming probe itself fails; [`AppsError::Manifest`] when
    /// persisting the record fails — the claim is rolled back, so nothing
    /// stays recorded and a retry starts clean.
    pub async fn adopt(
        &mut self,
        id: &TorideId,
        provenance: AdoptProvenance,
    ) -> AppsResult<InstallRecord> {
        if self.records.contains_key(id) {
            return Err(AppsError::AlreadyRecorded {
                id: id.as_str().to_owned(),
            });
        }
        let ids = provenance.ids;
        let version = match self.verify_presence(&ids).await? {
            Presence::Present(version) => version,
            Presence::Absent => {
                return Err(AppsError::AdoptionAbsent {
                    id: id.as_str().to_owned(),
                    detail: format!("{} is not present", native_subject(&ids)),
                });
            }
        };
        let mut record = InstallRecord::adopted(ids, version);
        if let Some(installed_at) = provenance.installed_at {
            record = record.with_installed_at(installed_at);
        }
        self.records.insert(id.clone(), record.clone());
        if let Err(error) = self.save_records().await {
            self.records.remove(id);
            return Err(error.into());
        }
        Ok(record)
    }

    /// Whether the record's manager already reports it current — brew's
    /// kind-scoped stale signal answers alone (an absent token is never
    /// current); signal-less backends compare installed against available.
    async fn record_is_current(
        &self,
        ids: &NativeIds,
        backend: &dyn Backend,
        from: Option<&Version>,
        native: &str,
    ) -> AppsResult<bool> {
        if let NativeIds::Homebrew { token, cask } = ids {
            let scope = if *cask {
                OutdatedScope::Casks
            } else {
                OutdatedScope::Formulae
            };
            Ok(from.is_some()
                && !self
                    .homebrew_backend()?
                    .outdated(scope)
                    .await?
                    .iter()
                    .any(|entry| entry.id == token.as_str()))
        } else {
            let to = backend.available_version(native).await?;
            Ok(from.is_some() && from == to.as_ref())
        }
    }

    /// The record's installed version through the kind-aware presence
    /// probes (the recorded brew kind, flatpak installation, distro
    /// family), `None` covering absent and present-without-a-version
    /// alike.
    async fn record_installed_version(&self, ids: &NativeIds) -> AppsResult<Option<Version>> {
        Ok(match self.verify_presence(ids).await? {
            Presence::Present(version) => version.map(Version::new),
            Presence::Absent => None,
        })
    }

    /// The version the record's backend offers today — the brew ask
    /// carries the recorded kind, so a dual-kind token answers for the
    /// kind the record upgrades; kind-less backends keep the trait default.
    async fn record_available_version(&self, ids: &NativeIds) -> AppsResult<Option<Version>> {
        match ids {
            NativeIds::Homebrew { token, cask } => {
                let kind = if *cask {
                    BrewKind::Cask
                } else {
                    BrewKind::Formula
                };
                Ok(self
                    .homebrew_backend()?
                    .available_version(kind, token)
                    .await?)
            }
            _ => Ok(self
                .backend_for(ids.backend())?
                .available_version(native_id(ids))
                .await?),
        }
    }

    /// The versions the record's backend can install today — the same
    /// kind- and scope-aware routing as [`Apps::record_available_version`]
    /// over the listing probe: brew answers per recorded kind, flatpak per
    /// recorded installation against the flathub remote, distro keeps the
    /// trait default (none reported).
    async fn record_available_versions(&self, ids: &NativeIds) -> AppsResult<Vec<Version>> {
        match ids {
            NativeIds::Homebrew { token, cask } => {
                let kind = if *cask {
                    BrewKind::Cask
                } else {
                    BrewKind::Formula
                };
                Ok(self
                    .homebrew_backend()?
                    .available_versions(kind, token)
                    .await?)
            }
            NativeIds::Flatpak {
                app_id,
                installation,
                ..
            } => Ok(self
                .flatpak_backend()?
                .available_versions(app_id, *installation)
                .await?),
            NativeIds::Distro { .. } => Ok(self
                .backend_for(ids.backend())?
                .available_versions(native_id(ids))
                .await?),
            #[cfg(feature = "direct")]
            NativeIds::Direct { .. } => Ok(self
                .backend_for(ids.backend())?
                .available_versions(native_id(ids))
                .await?),
        }
    }

    /// The version to pin into an install plan for a requested one, when
    /// nothing is present yet: `None` while the backend's own offering
    /// already equals the request — installing the manager's current lands
    /// exactly the requested thing, where a pin would address a spelling
    /// the manager may not resolve (brew only resolves `token@<v>` for
    /// separately versioned tokens). The requested version otherwise; a
    /// failing offering probe degrades to it and the manager classifies.
    async fn version_for_plan(&self, app: &App, requested: Option<Version>) -> Option<Version> {
        let requested = requested?;
        let Some(native) = self.native_ids_for(app) else {
            return Some(requested);
        };
        match self.record_available_version(&native).await {
            Ok(Some(offered)) if offered == requested => None,
            _ => Some(requested),
        }
    }

    /// The versions `id` can be installed at: record-first (the recorded
    /// backend's listing probe, zero adapter calls), resolved through the
    /// registry otherwise — the same shape as [`Apps::status`].
    ///
    /// # Errors
    ///
    /// [`AppsError::Unresolved`] when toride has no record and no adapter
    /// knows the id; [`AppsError::Backend`] wrapping
    /// [`Error::UnsupportedMethod`](crate::Error::UnsupportedMethod) when
    /// the resolved method has no backend to list versions through, and
    /// for probe failures; [`AppsError::BackendUnavailable`] when the
    /// routed backend is not attached.
    pub async fn available_versions(&self, id: &TorideId) -> AppsResult<Vec<Version>> {
        if let Some(record) = self.records.get(id) {
            return self.record_available_versions(&record.ids).await;
        }
        let app = self.resolve(id).await?;
        let Some(native) = self.native_ids_for(&app) else {
            return Err(AppsError::Backend(BackendError::UnsupportedMethod {
                app: id.as_str().to_owned(),
                method: format!("{:?}", app.install),
                target: format!("{:?}", self.target),
                reason: "the method has no backend to list versions through".to_owned(),
            }));
        };
        Ok(self
            .backend_for(native.backend())?
            .available_versions(native_id(&native))
            .await?)
    }

    /// Hold `id` back from upgrades (`brew pin`): the record's backend
    /// runs its own pin against the recorded identifiers. The manifest is
    /// untouched — pinned state lives with the manager and surfaces
    /// through the outdated probe's `pinned` flag.
    ///
    /// # Errors
    ///
    /// [`AppsError::UnrecordedPin`] when toride has no record for `id`;
    /// [`AppsError::BackendUnavailable`] when the record's backend is not
    /// attached; [`AppsError::Backend`] wrapping
    /// [`Error::PinUnsupported`](crate::Error::PinUnsupported) for
    /// backends without a pin concept, and for command failures.
    pub async fn pin(&self, id: &TorideId) -> AppsResult<()> {
        self.set_pin_state(id, true).await
    }

    /// Release a pin — the mirror of [`Apps::pin`] on the same record.
    ///
    /// # Errors
    ///
    /// Same contract as [`Apps::pin`], with [`AppsError::UnrecordedUnpin`]
    /// for an unrecorded id.
    pub async fn unpin(&self, id: &TorideId) -> AppsResult<()> {
        self.set_pin_state(id, false).await
    }

    /// The shared body of [`Apps::pin`] / [`Apps::unpin`]: record-required,
    /// kind-aware for brew, the trait method (and its honest refusal)
    /// otherwise.
    async fn set_pin_state(&self, id: &TorideId, pin: bool) -> AppsResult<()> {
        let Some(record) = self.records.get(id) else {
            return Err(if pin {
                AppsError::UnrecordedPin {
                    id: id.as_str().to_owned(),
                }
            } else {
                AppsError::UnrecordedUnpin {
                    id: id.as_str().to_owned(),
                }
            });
        };
        match &record.ids {
            NativeIds::Homebrew { token, cask } => {
                let backend = self.homebrew_backend()?;
                let kind = if *cask {
                    BrewKind::Cask
                } else {
                    BrewKind::Formula
                };
                let result = if pin {
                    backend.pin(kind, token).await
                } else {
                    backend.unpin(kind, token).await
                };
                result.map_err(AppsError::from)
            }
            other => {
                let backend = self.backend_for(other.backend())?;
                let result = if pin {
                    backend.pin(native_id(other)).await
                } else {
                    backend.unpin(native_id(other)).await
                };
                result.map_err(AppsError::from)
            }
        }
    }

    /// Where `id` stands on this host — the A5 status layer, delegated to.
    ///
    /// Manifest-first, per this facade's detect-before-resolve principle:
    /// a record hit is answered entirely from local state (the record's
    /// own identifiers against its backend) — the registry is never
    /// consulted, so a record hit costs no adapter round trip whose
    /// result would only be discarded. Only without a record does a
    /// best-effort registry resolve supply the native identifiers for
    /// `Foreign` detection — and a resolve failure degrades to the
    /// record-based answer instead of failing the query (a registry
    /// outage says nothing about the host).
    ///
    /// # Errors
    ///
    /// [`AppsError::Backend`] when a present backend fails its probe;
    /// never for an absent backend.
    pub async fn status(&self, id: &TorideId) -> AppsResult<AppStatus> {
        if let Some(record) = self.records.get(id) {
            return Ok(app_status(Some(record), None, &self.backend_set()).await?);
        }
        let native = self
            .resolve(id)
            .await
            .ok()
            .and_then(|app| self.native_ids_for(&app));
        Ok(app_status(None, native.as_ref(), &self.backend_set()).await?)
    }

    /// Free-text search fanned out across every registered adapter,
    /// hits in registration order; a failing source is skipped, its hits
    /// lost, the rest kept. Errors: [`AppsError::Registry`] only when
    /// every registered source fails.
    pub async fn search(&self, query: &str) -> AppsResult<Vec<App>> {
        let outcome = self.registry.search(query).await?;
        Ok(outcome.apps)
    }

    /// Resolve `id` to a registry [`App`]: each adapter, in registration
    /// order, is asked to look up its source-native id equal to the
    /// canonical slug (the ref is built with the adapter's own
    /// [`Adapter::source`], so no adapter ever sees a foreign ref). The
    /// first `Some` wins; the resolved app's own id becomes the manifest
    /// key downstream.
    async fn resolve(&self, id: &TorideId) -> AppsResult<App> {
        for adapter in self.registry.adapters() {
            let reference = SourceRef {
                source: adapter.source(),
                id: id.as_str().to_owned(),
                repo: None,
                version: None,
                provisional: false,
            };
            if let Some(app) = adapter.lookup(&reference).await? {
                return Ok(app);
            }
        }
        Err(AppsError::Unresolved {
            id: id.as_str().to_owned(),
        })
    }

    /// The borrowed backend set the status layer consumes, built from the
    /// long-lived attached backends per query.
    fn backend_set(&self) -> BackendSet<'_> {
        let mut set = BackendSet::new();
        if let Some(backend) = &self.backends.homebrew {
            set = set.homebrew(backend);
        }
        if let Some(backend) = &self.backends.flatpak {
            set = set.flatpak(backend);
        }
        if let Some(backend) = &self.backends.distro {
            set = set.distro(backend);
        }
        #[cfg(feature = "direct")]
        if let Some(backend) = &self.backends.direct {
            set = set.direct(backend);
        }
        set
    }

    /// The attached backend a plan's routing selects, as its trait object.
    fn backend_for(&self, backend: BackendId) -> AppsResult<&dyn Backend> {
        let routed: Option<&dyn Backend> = match backend {
            BackendId::Homebrew => self.backends.homebrew.as_ref().map(|b| b as &dyn Backend),
            BackendId::Flatpak => self.backends.flatpak.as_ref().map(|b| b as &dyn Backend),
            // The family is carried by the attached backend itself; a
            // family mismatch surfaces at execution (the distro backend's
            // executor check), not here.
            BackendId::Distro(_) => self.backends.distro.as_ref().map(|b| b as &dyn Backend),
            #[cfg(feature = "direct")]
            BackendId::Direct => self.backends.direct.as_ref().map(|b| b as &dyn Backend),
            BackendId::Npm | BackendId::Cargo | BackendId::Pipx | BackendId::Uv => None,
            #[cfg(feature = "mise")]
            BackendId::Mise => None,
        };
        routed.ok_or(AppsError::BackendUnavailable { backend })
    }

    /// The attached direct backend's install dir, when one is attached —
    /// the base direct records resolve their binary paths against.
    #[cfg(feature = "direct")]
    fn direct_install_dir(&self) -> Option<&Utf8PathBuf> {
        self.backends
            .direct
            .as_ref()
            .map(DirectBackend::install_dir)
    }

    /// The attached homebrew backend, for kind-aware probes.
    fn homebrew_backend(&self) -> AppsResult<&HomebrewBackend> {
        self.backends
            .homebrew
            .as_ref()
            .ok_or(AppsError::BackendUnavailable {
                backend: BackendId::Homebrew,
            })
    }

    /// The attached flatpak backend, for scoped listing probes.
    fn flatpak_backend(&self) -> AppsResult<&FlatpakBackend> {
        self.backends
            .flatpak
            .as_ref()
            .ok_or(AppsError::BackendUnavailable {
                backend: BackendId::Flatpak,
            })
    }

    /// Confirm presence through the kind-aware probes the A2–A4 interface
    /// notes bind this facade to: brew's kind-scoped `list --versions`
    /// (a present item always carries a version), the flatpak **scoped
    /// listing** (an app without appdata metadata reports an empty version
    /// cell, so `installed_version`'s `Ok(None)` cannot distinguish absent
    /// from present-without-version), and the distro presence status
    /// (apk reports a present package with no version at all, so the
    /// distro arm cannot ride `installed_version` either).
    async fn verify_presence(&self, ids: &NativeIds) -> AppsResult<Presence> {
        match ids {
            NativeIds::Homebrew { token, cask } => {
                let backend = self.homebrew_backend()?;
                let kind = if *cask {
                    BrewKind::Cask
                } else {
                    BrewKind::Formula
                };
                match backend.installed_version(kind, token).await? {
                    Some(version) => Ok(Presence::Present(Some(version))),
                    None => Ok(Presence::Absent),
                }
            }
            NativeIds::Flatpak {
                app_id,
                installation,
                ..
            } => {
                let backend = self.flatpak_backend()?;
                let entries = backend
                    .list_entries(FlatpakListScope::from(*installation))
                    .await?;
                match entries.iter().find(|entry| entry.application == *app_id) {
                    // The row is the presence answer; its version cell may
                    // legitimately be empty.
                    Some(entry) => Ok(Presence::Present(entry.version.clone())),
                    None => Ok(Presence::Absent),
                }
            }
            NativeIds::Distro { package, family } => {
                let Some(backend) = self.backends.distro.as_ref() else {
                    // Unreachable in practice — presence is verified right
                    // after executing through this very backend — but a
                    // probe without its backend is an error, not a guess.
                    return Err(AppsError::BackendUnavailable {
                        backend: BackendId::Distro(*family),
                    });
                };
                // A foreign-family backend cannot have the package — the
                // same gate the A5 status layer applies.
                if backend.family() != *family {
                    return Ok(Presence::Absent);
                }
                match backend.status(StatusQuery::new(package)).await? {
                    BackendStatus::Installed { version } => Ok(Presence::Present(version)),
                    BackendStatus::NotInstalled => Ok(Presence::Absent),
                }
            }
            #[cfg(feature = "direct")]
            NativeIds::Direct { bin_path, .. } => {
                let backend = self.backend_for(BackendId::Direct)?;
                Ok(direct_presence(
                    backend.status(StatusQuery::new(bin_path)).await?,
                ))
            }
        }
    }

    /// Post-uninstall verification: `None` when the probes confirm the
    /// identifiers are gone, a human-readable warning otherwise. The
    /// absent-target uninstall behavior diverges by backend (brew errors,
    /// flatpak answers idempotently, distro errors), so the facade probes
    /// after every removal and trusts no single classification.
    async fn verify_absence(&self, ids: &NativeIds) -> Option<String> {
        match self.verify_presence(ids).await {
            Ok(Presence::Absent) => None,
            Ok(Presence::Present(version)) => Some(match version {
                Some(version) => format!(
                    "uninstalled, but the backend still reports {} at version {version}",
                    native_subject(ids)
                ),
                None => format!(
                    "uninstalled, but the backend still reports {} present",
                    native_subject(ids)
                ),
            }),
            Err(error) => Some(format!(
                "uninstalled, but the post-uninstall verify probe failed: {error}"
            )),
        }
    }

    /// Persist the working records through the store, off the async
    /// runtime when the `tokio` feature supplies one to offload to.
    ///
    /// [`RecordStore::save`] is synchronous IO (the JSON store's create
    /// parent dirs, write temp, rename) and must not run on an async
    /// worker — the standing don't-block rule; under the `tokio` feature
    /// the save is dispatched through
    /// `tokio::task::spawn_blocking` (the crate-family precedent:
    /// toride-installer's extraction and detect) with the snapshot and
    /// the store's `Arc` cloned into the task, so no borrow is held
    /// across the await and a join failure (the blocking task was
    /// cancelled or panicked) maps to [`ManifestError::Io`] so callers'
    /// warning paths stay uniform. Without the feature there is no
    /// runtime to offload to: the save runs in-line (see `persist`),
    /// exactly the path `save_records_sync` always takes. Error
    /// semantics are the store's own.
    async fn save_records(&self) -> ManifestResult<()> {
        let snapshot = RecordSnapshot {
            records: self.records.clone(),
        };
        self.persist(snapshot).await
    }

    /// Persist the working records through the store, in-line on the
    /// calling thread — the path [`AppsBlocking`] mutations take after
    /// every successful operation.
    fn save_records_sync(&self) -> ManifestResult<()> {
        let snapshot = RecordSnapshot {
            records: self.records.clone(),
        };
        self.store.save(&snapshot)
    }

    #[cfg(feature = "tokio")]
    async fn persist(&self, snapshot: RecordSnapshot) -> ManifestResult<()> {
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || store.save(&snapshot))
            .await
            .map_err(|error| {
                ManifestError::Io(std::io::Error::other(format!(
                    "record store save task failed to join: {error}"
                )))
            })?
    }

    #[cfg(not(feature = "tokio"))]
    #[expect(clippy::unused_async, clippy::unused_async_trait_impl)]
    async fn persist(&self, snapshot: RecordSnapshot) -> ManifestResult<()> {
        self.store.save(&snapshot)
    }

    /// The sync twin of [`Apps::record_is_current`]: brew's kind-scoped
    /// stale signal answers alone; signal-less backends compare installed
    /// against available.
    fn record_is_current_sync(
        &self,
        ids: &NativeIds,
        backend: &dyn Backend,
        from: Option<&Version>,
        native: &str,
    ) -> AppsResult<bool> {
        if let NativeIds::Homebrew { token, cask } = ids {
            let scope = if *cask {
                OutdatedScope::Casks
            } else {
                OutdatedScope::Formulae
            };
            Ok(from.is_some()
                && !self
                    .homebrew_backend()?
                    .outdated_sync(scope)?
                    .iter()
                    .any(|entry| entry.id == token.as_str()))
        } else {
            let to = backend.available_version_sync(native)?;
            Ok(from.is_some() && from == to.as_ref())
        }
    }

    /// The sync twin of [`Apps::record_installed_version`].
    fn record_installed_version_sync(&self, ids: &NativeIds) -> AppsResult<Option<Version>> {
        Ok(match self.verify_presence_sync(ids)? {
            Presence::Present(version) => version.map(Version::new),
            Presence::Absent => None,
        })
    }

    /// The sync twin of [`Apps::record_available_version`].
    fn record_available_version_sync(&self, ids: &NativeIds) -> AppsResult<Option<Version>> {
        match ids {
            NativeIds::Homebrew { token, cask } => {
                let kind = if *cask {
                    BrewKind::Cask
                } else {
                    BrewKind::Formula
                };
                Ok(self
                    .homebrew_backend()?
                    .available_version_sync(kind, token)?)
            }
            _ => Ok(self
                .backend_for(ids.backend())?
                .available_version_sync(native_id(ids))?),
        }
    }

    /// The sync twin of [`Apps::record_available_versions`].
    fn record_available_versions_sync(&self, ids: &NativeIds) -> AppsResult<Vec<Version>> {
        match ids {
            NativeIds::Homebrew { token, cask } => {
                let kind = if *cask {
                    BrewKind::Cask
                } else {
                    BrewKind::Formula
                };
                Ok(self
                    .homebrew_backend()?
                    .available_versions_sync(kind, token)?)
            }
            NativeIds::Flatpak {
                app_id,
                installation,
                ..
            } => Ok(self
                .flatpak_backend()?
                .available_versions_sync(app_id, *installation)?),
            NativeIds::Distro { .. } => Ok(self
                .backend_for(ids.backend())?
                .available_versions_sync(native_id(ids))?),
            #[cfg(feature = "direct")]
            NativeIds::Direct { .. } => Ok(self
                .backend_for(ids.backend())?
                .available_versions_sync(native_id(ids))?),
        }
    }

    /// The sync twin of [`Apps::version_for_plan`].
    fn version_for_plan_sync(&self, app: &App, requested: Option<Version>) -> Option<Version> {
        let requested = requested?;
        let Some(native) = self.native_ids_for(app) else {
            return Some(requested);
        };
        match self.record_available_version_sync(&native) {
            Ok(Some(offered)) if offered == requested => None,
            _ => Some(requested),
        }
    }

    /// The sync twin of [`Apps::set_pin_state`].
    fn set_pin_state_sync(&self, id: &TorideId, pin: bool) -> AppsResult<()> {
        let Some(record) = self.records.get(id) else {
            return Err(if pin {
                AppsError::UnrecordedPin {
                    id: id.as_str().to_owned(),
                }
            } else {
                AppsError::UnrecordedUnpin {
                    id: id.as_str().to_owned(),
                }
            });
        };
        match &record.ids {
            NativeIds::Homebrew { token, cask } => {
                let backend = self.homebrew_backend()?;
                let kind = if *cask {
                    BrewKind::Cask
                } else {
                    BrewKind::Formula
                };
                let result = if pin {
                    backend.pin_sync(kind, token)
                } else {
                    backend.unpin_sync(kind, token)
                };
                result.map_err(AppsError::from)
            }
            other => {
                let backend = self.backend_for(other.backend())?;
                let result = if pin {
                    backend.pin_sync(native_id(other))
                } else {
                    backend.unpin_sync(native_id(other))
                };
                result.map_err(AppsError::from)
            }
        }
    }

    /// The sync twin of [`Apps::verify_presence`].
    fn verify_presence_sync(&self, ids: &NativeIds) -> AppsResult<Presence> {
        match ids {
            NativeIds::Homebrew { token, cask } => {
                let backend = self.homebrew_backend()?;
                let kind = if *cask {
                    BrewKind::Cask
                } else {
                    BrewKind::Formula
                };
                match backend.installed_version_sync(kind, token)? {
                    Some(version) => Ok(Presence::Present(Some(version))),
                    None => Ok(Presence::Absent),
                }
            }
            NativeIds::Flatpak {
                app_id,
                installation,
                ..
            } => {
                let backend = self.flatpak_backend()?;
                let entries = backend.list_entries_sync(FlatpakListScope::from(*installation))?;
                match entries.iter().find(|entry| entry.application == *app_id) {
                    Some(entry) => Ok(Presence::Present(entry.version.clone())),
                    None => Ok(Presence::Absent),
                }
            }
            NativeIds::Distro { package, family } => {
                let Some(backend) = self.backends.distro.as_ref() else {
                    return Err(AppsError::BackendUnavailable {
                        backend: BackendId::Distro(*family),
                    });
                };
                if backend.family() != *family {
                    return Ok(Presence::Absent);
                }
                match backend.status_sync(StatusQuery::new(package))? {
                    BackendStatus::Installed { version } => Ok(Presence::Present(version)),
                    BackendStatus::NotInstalled => Ok(Presence::Absent),
                }
            }
            #[cfg(feature = "direct")]
            NativeIds::Direct { bin_path, .. } => {
                let backend = self.backend_for(BackendId::Direct)?;
                Ok(direct_presence(
                    backend.status_sync(StatusQuery::new(bin_path))?,
                ))
            }
        }
    }

    /// The sync twin of [`Apps::verify_absence`].
    fn verify_absence_sync(&self, ids: &NativeIds) -> Option<String> {
        match self.verify_presence_sync(ids) {
            Ok(Presence::Absent) => None,
            Ok(Presence::Present(version)) => Some(match version {
                Some(version) => format!(
                    "uninstalled, but the backend still reports {} at version {version}",
                    native_subject(ids)
                ),
                None => format!(
                    "uninstalled, but the backend still reports {} present",
                    native_subject(ids)
                ),
            }),
            Err(error) => Some(format!(
                "uninstalled, but the post-uninstall verify probe failed: {error}"
            )),
        }
    }
}

/// What a presence probe answered.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Presence {
    /// Confirmed present; the reported version, when the probe carries one
    /// (flatpak rows may not).
    Present(Option<String>),
    /// The probe answered definitively: not present.
    Absent,
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder for [`Apps`], mirroring toride-mise's `MiseBuilder` shape:
/// consume-and-return setters, everything optional, [`AppsBuilder::build`]
/// loading the record store (missing file = empty; corrupt prior state =
/// quarantined, see [`crate::store`]).
///
/// Backends are attached pre-built so both sanctioned constructions work:
/// `detect()` in production (PATH checks), `new()` under a fake runner in
/// tests — [`AppsBuilder::detect_backends`] wires the production arm in
/// one call.
#[derive(Default)]
pub struct AppsBuilder {
    /// The seam every attached backend executes through; defaults to a
    /// fresh [`DuctRunner`](toride_runner::DuctRunner)-backed seam when
    /// unset.
    runner: Option<CommandRunner>,
    /// Host target; defaults to the host bootstrap —
    /// `Target::host()` with the distro family filled in from the
    /// os-release(5) locations when detection succeeds (an unknown family
    /// stays `None` and distro plans fail loudly at plan time).
    target: Option<Target>,
    /// The homebrew backend, when brew is usable on this host.
    homebrew: Option<HomebrewBackend>,
    /// The flatpak backend, when flatpak is usable on this host.
    flatpak: Option<FlatpakBackend>,
    /// The distro backend, when a family manager is usable on this host.
    distro: Option<DistroBackend>,
    /// The direct-download backend, when attached (the `direct` feature).
    #[cfg(feature = "direct")]
    direct: Option<DirectBackend>,
    /// Caller-supplied record-store persistence; takes precedence over
    /// `manifest_path` (which then names nothing).
    record_store: Option<Arc<dyn RecordStore>>,
    /// Where the default JSON store's manifest loads from and saves to;
    /// defaults to [`InstallManifest::default_path`].
    manifest_path: Option<Utf8PathBuf>,
    /// Registry adapters for resolve/search, consulted in order.
    adapters: Vec<Arc<dyn Adapter>>,
}

impl AppsBuilder {
    /// Create a builder with all defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the command-execution seam — consume-and-return.
    #[must_use]
    pub fn runner(mut self, runner: CommandRunner) -> Self {
        self.runner = Some(runner);
        self
    }

    /// Set the host target plans derive for — consume-and-return.
    #[must_use]
    pub fn target(mut self, target: Target) -> Self {
        self.target = Some(target);
        self
    }

    /// Attach the homebrew backend — consume-and-return.
    #[must_use]
    pub fn homebrew(mut self, backend: HomebrewBackend) -> Self {
        self.homebrew = Some(backend);
        self
    }

    /// Attach the flatpak backend — consume-and-return.
    #[must_use]
    pub fn flatpak(mut self, backend: FlatpakBackend) -> Self {
        self.flatpak = Some(backend);
        self
    }

    /// Attach the distro backend — consume-and-return.
    #[must_use]
    pub fn distro(mut self, backend: DistroBackend) -> Self {
        self.distro = Some(backend);
        self
    }

    /// Attach the direct-download backend — consume-and-return (the
    /// `direct` feature). Without one attached, direct methods still
    /// plan, but installs and the record-replaying uninstalls of direct
    /// records answer [`AppsError::BackendUnavailable`]; an unrecorded
    /// direct app's uninstall never consults a backend at all (a direct
    /// removal replays a record, so it refuses at plan time — or earlier
    /// with [`AppsError::Unresolved`] / [`AppsError::Registry`] when the
    /// id does not resolve), a direct record's update refuses with
    /// [`AppsError::UnrecordableOperation`], and `status` degrades to
    /// [`AppStatus::NotInstalled`] — no backend, no probe.
    #[cfg(feature = "direct")]
    #[must_use]
    pub fn direct(mut self, backend: DirectBackend) -> Self {
        self.direct = Some(backend);
        self
    }

    /// Replace the JSON-manifest persistence with a caller-supplied
    /// record store — consume-and-return. An embedder keeping its own
    /// receipts as source of truth supplies or mirrors them here. Takes
    /// precedence over [`AppsBuilder::manifest_path`]: a custom store
    /// needs no path at all, so
    /// [`AppsError::NoManifestPath`] cannot fire when one is set.
    #[must_use]
    pub fn with_record_store(mut self, store: Arc<dyn RecordStore>) -> Self {
        self.record_store = Some(store);
        self
    }

    /// Set the manifest location the default JSON store loads from and
    /// saves to (a missing file is an empty store) — consume-and-return.
    #[must_use]
    pub fn manifest_path(mut self, path: impl Into<Utf8PathBuf>) -> Self {
        self.manifest_path = Some(path.into());
        self
    }

    /// Register one registry adapter — consume-and-return.
    #[must_use]
    pub fn adapter(mut self, adapter: Arc<dyn Adapter>) -> Self {
        self.adapters.push(adapter);
        self
    }

    /// Register several registry adapters — consume-and-return.
    #[must_use]
    pub fn adapters<I>(mut self, adapters: I) -> Self
    where
        I: IntoIterator<Item = Arc<dyn Adapter>>,
    {
        self.adapters.extend(adapters);
        self
    }

    /// Attach every backend this host supports: homebrew and flatpak via
    /// their PATH checks, distro via os-release(5) detection plus its PATH
    /// checks. A backend whose binary is simply absent is skipped (no
    /// brew on a Linux box is normal, not an error); a distro host with
    /// no known family is skipped the same way. No command executes.
    ///
    /// The seam the detection shares is kept as the builder's runner, so
    /// the built facade and its backends ride one seam.
    ///
    /// # Errors
    ///
    /// [`AppsError::Backend`] when a detection fails for a reason other
    /// than the skip modes above (absent binary, unknown family).
    pub fn detect_backends(self) -> AppsResult<Self> {
        let runner = self
            .runner
            .clone()
            .unwrap_or_else(|| CommandRunner::builder().build());
        let mut builder = self;
        match HomebrewBackend::detect(runner.clone()) {
            Ok(backend) => builder = builder.homebrew(backend),
            // Absent binary: this host simply has no brew — skip.
            Err(BackendError::Command(toride_runner::Error::BinaryNotFound(_))) => {}
            Err(error) => return Err(error.into()),
        }
        match FlatpakBackend::detect(runner.clone()) {
            Ok(backend) => builder = builder.flatpak(backend),
            Err(BackendError::Command(toride_runner::Error::BinaryNotFound(_))) => {}
            Err(error) => return Err(error.into()),
        }
        match DistroBackend::detect(runner.clone()) {
            Ok(backend) => builder = builder.distro(backend),
            // Absent binaries or no known family on this host — every mode
            // here is "this host has no distro backend to attach", not a
            // failure worth surfacing.
            Err(BackendError::Command(
                toride_runner::Error::BinaryNotFound(_) | toride_runner::Error::Other(_),
            )) => {}
            Err(error) => return Err(error.into()),
        }
        #[cfg(feature = "direct")]
        match DirectBackend::detect() {
            Ok(backend) => builder = builder.direct(backend),
            // No resolvable home dir — this host has no direct install
            // dir to write into; the same skip mode as an absent manager
            // binary.
            Err(BackendError::Command(toride_runner::Error::Other(_))) => {}
            Err(error) => return Err(error.into()),
        }
        builder.runner = Some(runner);
        Ok(builder)
    }

    /// Consume the builder and produce the facade. The record store loads
    /// here — a missing document is an empty ledger, and a corrupt one
    /// (including one written by a newer toride) is **quarantined aside,
    /// never a fatal stop**: the facade starts from empty and
    /// [`Apps::quarantined`] names the moved file.
    ///
    /// # Errors
    ///
    /// [`AppsError::Manifest`] when the store cannot be loaded (or its
    /// corrupt prior state cannot be quarantined);
    /// [`AppsError::NoManifestPath`] when no store was supplied, no path
    /// was set, and the platform data directory did not resolve.
    pub fn build(self) -> AppsResult<Apps> {
        let store: Arc<dyn RecordStore> = if let Some(store) = self.record_store {
            store
        } else {
            let path = match self.manifest_path {
                Some(path) => path,
                None => InstallManifest::default_path().ok_or(AppsError::NoManifestPath)?,
            };
            Arc::new(JsonRecordStore::at(path))
        };
        let StoreLoad {
            snapshot,
            quarantined,
        } = store.load()?;
        Ok(Apps {
            runner: self
                .runner
                .unwrap_or_else(|| CommandRunner::builder().build()),
            // An explicitly attached target is honored verbatim; only the
            // default runs the host bootstrap (os-release detection).
            target: self.target.unwrap_or_else(default_target),
            backends: AttachedBackends {
                homebrew: self.homebrew,
                flatpak: self.flatpak,
                distro: self.distro,
                #[cfg(feature = "direct")]
                direct: self.direct,
            },
            records: snapshot.into_records(),
            store,
            quarantined,
            registry: Registry::new(self.adapters),
        })
    }
}

/// The host bootstrap target: `Target::host()` with the distro family
/// filled in from the os-release(5) locations when detection succeeds.
/// An undetectable family stays `None` — distro plans then fail loudly at
/// plan time instead of guessing.
fn default_target() -> Target {
    match detect_host_family() {
        Some(family) => Target::host().with_distro(family),
        None => Target::host(),
    }
}

/// The sync twin of the [`Apps`] facade: the same verbs, executed on the
/// calling thread through the backends' sync paths, with **in-line**
/// manifest persistence (no runtime, no offloading — the default-build
/// shape an all-sync embedder drives; the `tokio` feature only adds
/// offloading for the async facade, never for this one).
///
/// Build one from a built facade ([`Apps::blocking`], or
/// [`AppsBlocking::new`]); every outcome type, option, and error is shared
/// with the async facade. One arm is structurally out of reach: resolving a
/// bare [`TorideId`] through the registry adapters is async, so the
/// blocking surface takes the resolved registry [`App`] where the async
/// facade takes an id ([`AppsBlocking::ensure_installed`]); the
/// registry-dependent arms of the id-keyed verbs answer
/// [`AppsError::BlockingResolveRequired`], except [`AppsBlocking::status`],
/// which degrades to [`AppStatus::NotInstalled`] exactly like the async
/// facade's resolve-failure arm; and there is no `search`.
pub struct AppsBlocking {
    /// The wrapped facade — one record store, one target, one backend set.
    apps: Apps,
}

impl From<Apps> for AppsBlocking {
    fn from(apps: Apps) -> Self {
        Self::new(apps)
    }
}

impl AppsBlocking {
    /// Wrap a built facade.
    #[must_use]
    pub const fn new(apps: Apps) -> Self {
        Self { apps }
    }

    /// Unwrap back to the async facade (records, store, and backends carry
    /// over — both facades share one state).
    #[must_use]
    pub fn into_inner(self) -> Apps {
        self.apps
    }

    /// The host target this facade plans for.
    #[must_use]
    pub fn target(&self) -> Target {
        self.apps.target()
    }

    /// The working records this facade holds — see [`Apps::records`].
    #[must_use]
    pub fn records(&self) -> Vec<(&TorideId, &InstallRecord)> {
        self.apps.records()
    }

    /// Where a corrupt prior store document was quarantined at build —
    /// see [`Apps::quarantined`].
    #[must_use]
    pub fn quarantined(&self) -> Option<&Utf8PathBuf> {
        self.apps.quarantined()
    }

    /// Ensure the resolved registry `app` is installed, on the calling
    /// thread — the sync twin of [`Apps::ensure_installed`] with one
    /// contract difference: the app arrives resolved (the registry's
    /// adapter trait is async, so the blocking surface cannot resolve a
    /// bare id itself). The detect-first arm is unchanged: a manifest
    /// record the recorded backend still confirms answers
    /// [`EnsureAppOutcome::AlreadyPresent`] with zero dispatch.
    ///
    /// # Errors
    ///
    /// Same contract as [`Apps::ensure_installed`] minus
    /// [`AppsError::Unresolved`] / [`AppsError::Registry`] (nothing
    /// resolves here).
    pub fn ensure_installed(
        &mut self,
        app: &App,
        options: AppInstallOptions,
    ) -> AppsResult<EnsureAppOutcome> {
        let AppInstallOptions { elevated, version } = options;
        let id = app.id.clone();
        let mut present = false;
        let recorded = app_status_sync(self.apps.records.get(&id), None, &self.apps.backend_set())?;
        if matches!(recorded, AppStatus::Installed { .. }) {
            present = true;
            let satisfies = self.apps.records.get(&id).is_some_and(|record| {
                requested_version_satisfied(&record.ids, &recorded, version.as_ref())
            });
            if satisfies {
                return Ok(EnsureAppOutcome::AlreadyPresent(recorded));
            }
        }
        if !self.apps.records.contains_key(&id) {
            let native = self.apps.native_ids_for(app);
            let status = app_status_sync(None, native.as_ref(), &self.apps.backend_set())?;
            if let AppStatus::Foreign { .. } = status {
                if version.is_none() {
                    return Ok(EnsureAppOutcome::AlreadyPresent(status));
                }
                present = true;
            }
        }
        let version = if present {
            version
        } else {
            self.apps.version_for_plan_sync(app, version)
        };
        let plan = plan_install(app, &self.apps.target, &InstallOptions { version })?;
        let backend = self.apps.backend_for(plan.backend)?;
        let ids = self.apps.native_ids_from_executed(&plan)?;
        let outcome = backend
            .install_sync(InstallRequest::new(&plan, &self.apps.target).elevated(elevated))?;
        let verification = self.apps.verify_presence_sync(&ids);
        let verified = matches!(verification, Ok(Presence::Present(_)));
        let subject = native_subject(&ids);
        let mut warning = match &verification {
            Ok(Presence::Present(_)) => None,
            Ok(Presence::Absent) => Some(format!(
                "installed, but the post-install verify no longer reports {subject} — recorded unverified"
            )),
            Err(error) => Some(format!(
                "installed, but the post-install verify probe failed: {error} — recorded unverified"
            )),
        };
        let verified_version = match verification {
            Ok(Presence::Present(version)) => version,
            _ => None,
        };
        let recorded_version = verified_version.or(outcome.version);
        let record_key = plan.app.clone();
        self.apps.records.insert(
            record_key,
            InstallRecord::new(plan, ids.clone(), recorded_version.clone()),
        );
        if let Err(error) = self.apps.save_records_sync() {
            push_warning(
                &mut warning,
                format!("installed, but saving the install manifest failed: {error}"),
            );
        }
        Ok(EnsureAppOutcome::Installed {
            backend: ids.backend(),
            version: recorded_version,
            ids,
            verified,
            warning,
        })
    }

    /// Uninstall `id`, on the calling thread: the record-replay arm of
    /// [`Apps::uninstall`] verbatim (plan from the record's own
    /// identifiers, execute, post-verify, remove the record, save
    /// in-line). Without a record the blocking surface cannot probe for
    /// Foreign presence (that arm resolves through the registry), so it
    /// answers [`AppsError::BlockingResolveRequired`] — take the resolved
    /// app to [`AppsBlocking::uninstall_app`] instead.
    ///
    /// # Errors
    ///
    /// [`AppsError::BlockingResolveRequired`] when toride has no record
    /// for `id`; otherwise the same contract as [`Apps::uninstall`].
    pub fn uninstall(
        &mut self,
        id: &TorideId,
        options: AppUninstallOptions,
    ) -> AppsResult<UninstallAppOutcome> {
        let Some(record) = self.apps.records.get(id).cloned() else {
            return Err(AppsError::BlockingResolveRequired {
                id: id.as_str().to_owned(),
            });
        };
        let plan = uninstall_plan_from_record(id, &record, options.zap)?;
        let backend = self.apps.backend_for(plan.backend)?;
        backend.uninstall_sync(
            UninstallRequest::new(&plan, &self.apps.target).elevated(options.elevated),
        )?;
        let mut warning = self.apps.verify_absence_sync(&record.ids);
        self.apps.records.remove(id);
        if let Err(error) = self.apps.save_records_sync() {
            push_warning(
                &mut warning,
                format!(
                    "uninstalled, but saving the install manifest failed: {error} \
                     (the record was removed in memory)"
                ),
            );
        }
        Ok(UninstallAppOutcome::Removed {
            backend: record.backend,
            ids: record.ids,
            warning,
        })
    }

    /// Remove an unrecorded install, on the calling thread — the sync twin
    /// of the Foreign arm of [`Apps::uninstall`] over a caller-resolved
    /// app: nothing present answers
    /// [`UninstallAppOutcome::AlreadyAbsent`]; presence without a record
    /// is refused with [`AppsError::ForeignNotManaged`] unless the options
    /// carry `force`. No manifest record is fabricated.
    ///
    /// # Errors
    ///
    /// Same contract as [`Apps::uninstall`] minus
    /// [`AppsError::Unresolved`] / [`AppsError::Registry`].
    pub fn uninstall_app(
        &mut self,
        app: &App,
        options: AppUninstallOptions,
    ) -> AppsResult<UninstallAppOutcome> {
        let id = app.id.clone();
        let plan = plan_uninstall(
            app,
            &self.apps.target,
            &UninstallOptions { zap: options.zap },
        )?;
        let Some(native) = self.apps.native_ids_for(app) else {
            return Err(AppsError::UnrecordableOperation {
                app: id.as_str().to_owned(),
                operation: format!("{:?} carries no native identity", app.install),
            });
        };
        let status = app_status_sync(None, Some(&native), &self.apps.backend_set())?;
        let present_detail = match status {
            AppStatus::NotInstalled => return Ok(UninstallAppOutcome::AlreadyAbsent),
            AppStatus::Foreign { detail, .. } => detail,
            AppStatus::Installed { backend, .. } => format!(
                "a {backend} probe reports the app present, though toride has no record for it"
            ),
        };
        if !options.force {
            return Err(AppsError::ForeignNotManaged {
                id: id.as_str().to_owned(),
                detail: present_detail,
            });
        }
        let backend = self.apps.backend_for(plan.backend)?;
        backend.uninstall_sync(
            UninstallRequest::new(&plan, &self.apps.target).elevated(options.elevated),
        )?;
        let warning = self.apps.verify_absence_sync(&native);
        Ok(UninstallAppOutcome::Removed {
            backend: plan.backend,
            ids: native,
            warning,
        })
    }

    /// Update `id` to its manager's current version, on the calling
    /// thread — the exact sync twin of [`Apps::update`]: record-required,
    /// planned from the record's own identifiers with zero registry round
    /// trips, currency decided by the manager's stale signal, dry runs
    /// previewing instead of executing, and the record rewritten in-line
    /// after a successful upgrade.
    ///
    /// # Errors
    ///
    /// Same contract as [`Apps::update`].
    pub fn update(
        &mut self,
        id: &TorideId,
        options: &AppUpdateOptions,
    ) -> AppsResult<UpdateOutcome> {
        if let Some(target) = &options.target {
            return Err(AppsError::UpdateTargetNotPinnable {
                id: id.as_str().to_owned(),
                target: target.to_string(),
            });
        }
        let Some(record) = self.apps.records.get(id).cloned() else {
            return Err(AppsError::UnrecordedUpdate {
                id: id.as_str().to_owned(),
            });
        };
        let plan = update_plan_from_record(id, &record)?.dry_run(options.dry_run);
        let backend = self.apps.backend_for(plan.backend)?;
        let native = native_id(&record.ids);
        let from = self.apps.record_installed_version_sync(&record.ids)?;
        if options.dry_run {
            let to = self.apps.record_available_version_sync(&record.ids)?;
            return Ok(UpdateOutcome::Preview(UpdatePreview {
                argv: plan.operation.argv(),
                from,
                to,
            }));
        }
        if self
            .apps
            .record_is_current_sync(&record.ids, backend, from.as_ref(), native)?
        {
            return Ok(UpdateOutcome::UpToDate);
        }
        backend
            .update_sync(UpdateRequest::new(&plan, &self.apps.target).elevated(options.elevated))?;
        let to = self
            .apps
            .record_installed_version_sync(&record.ids)
            .ok()
            .flatten();
        self.apps.records.insert(
            id.clone(),
            record.with_version(to.as_ref().map(|version| version.as_str().to_owned())),
        );
        self.apps.save_records_sync()?;
        Ok(UpdateOutcome::Updated { from, to })
    }

    /// Claim a detected-but-unrecorded install, on the calling thread —
    /// the sync twin of [`Apps::adopt`], including the rollback when the
    /// in-line save fails.
    ///
    /// # Errors
    ///
    /// Same contract as [`Apps::adopt`].
    pub fn adopt(
        &mut self,
        id: &TorideId,
        provenance: AdoptProvenance,
    ) -> AppsResult<InstallRecord> {
        if self.apps.records.contains_key(id) {
            return Err(AppsError::AlreadyRecorded {
                id: id.as_str().to_owned(),
            });
        }
        let ids = provenance.ids;
        let version = match self.apps.verify_presence_sync(&ids)? {
            Presence::Present(version) => version,
            Presence::Absent => {
                return Err(AppsError::AdoptionAbsent {
                    id: id.as_str().to_owned(),
                    detail: format!("{} is not present", native_subject(&ids)),
                });
            }
        };
        let mut record = InstallRecord::adopted(ids, version);
        if let Some(installed_at) = provenance.installed_at {
            record = record.with_installed_at(installed_at);
        }
        self.apps.records.insert(id.clone(), record.clone());
        if let Err(error) = self.apps.save_records_sync() {
            self.apps.records.remove(id);
            return Err(error.into());
        }
        Ok(record)
    }

    /// Where `id` stands on this host, on the calling thread — the sync
    /// twin of [`Apps::status`]'s record arm: a record hit is answered
    /// from local state alone. Without a record the blocking surface
    /// cannot resolve native identifiers for `Foreign` detection, so it
    /// answers [`AppStatus::NotInstalled`] — the same degraded answer the
    /// async facade gives when a registry resolve fails.
    ///
    /// # Errors
    ///
    /// [`AppsError::Backend`] when a present backend fails its probe.
    pub fn status(&self, id: &TorideId) -> AppsResult<AppStatus> {
        match self.apps.records.get(id) {
            Some(record) => Ok(app_status_sync(
                Some(record),
                None,
                &self.apps.backend_set(),
            )?),
            None => Ok(AppStatus::NotInstalled),
        }
    }

    /// The versions `id` can be installed at, on the calling thread — the
    /// sync twin of [`Apps::available_versions`]'s record-first arm; an
    /// unrecorded id needs the registry and answers
    /// [`AppsError::BlockingResolveRequired`].
    ///
    /// # Errors
    ///
    /// [`AppsError::BlockingResolveRequired`] when toride has no record
    /// for `id`; otherwise the same contract as
    /// [`Apps::available_versions`].
    pub fn available_versions(&self, id: &TorideId) -> AppsResult<Vec<Version>> {
        if let Some(record) = self.apps.records.get(id) {
            return self.apps.record_available_versions_sync(&record.ids);
        }
        Err(AppsError::BlockingResolveRequired {
            id: id.as_str().to_owned(),
        })
    }

    /// Hold `id` back from upgrades, on the calling thread — the sync twin
    /// of [`Apps::pin`].
    ///
    /// # Errors
    ///
    /// Same contract as [`Apps::pin`].
    pub fn pin(&self, id: &TorideId) -> AppsResult<()> {
        self.apps.set_pin_state_sync(id, true)
    }

    /// Release a pin, on the calling thread — the sync twin of
    /// [`Apps::unpin`].
    ///
    /// # Errors
    ///
    /// Same contract as [`Apps::unpin`].
    pub fn unpin(&self, id: &TorideId) -> AppsResult<()> {
        self.apps.set_pin_state_sync(id, false)
    }
}

// ---------------------------------------------------------------------------
// Identity derivation
// ---------------------------------------------------------------------------

impl Apps {
    /// The backend-native identifiers a registry app's [`InstallMethod`]
    /// names — the caller-known spelling the status layer probes
    /// `Foreign` presence with (the flatpak arm carries no installed ref:
    /// only a record written at install time knows the ref that landed;
    /// `installation` is toride's planned scope, and the Foreign probe
    /// deliberately ignores it). `None` for a `Direct` method with no
    /// direct backend attached and for future methods.
    #[cfg_attr(not(feature = "direct"), allow(clippy::unused_self))]
    fn native_ids_for(&self, app: &App) -> Option<NativeIds> {
        match &app.install {
            InstallMethod::Homebrew { cask, token } => Some(NativeIds::Homebrew {
                token: token.clone(),
                cask: *cask,
            }),
            InstallMethod::Flatpak { app_id, .. } => Some(NativeIds::Flatpak {
                app_id: app_id.clone(),
                app_ref: None,
                installation: FlatpakInstallation::User,
            }),
            InstallMethod::Distro {
                family, package, ..
            } => Some(NativeIds::Distro {
                package: package.clone(),
                family: *family,
            }),
            #[cfg(feature = "direct")]
            InstallMethod::Direct { url, checksum, .. } => {
                let backend = self.backends.direct.as_ref()?;
                let bin_name =
                    crate::plan::direct_bin_name(app, url, crate::plan::direct_artifact(url))?;
                Some(NativeIds::Direct {
                    url: url.clone(),
                    checksum: crate::plan::direct_digest(checksum.as_ref()).ok().flatten(),
                    bin_path: backend.install_dir().join(&bin_name).to_string(),
                })
            }
            // `InstallMethod` is non_exhaustive upstream: unmapped future
            // variants carry no native identity to probe.
            _ => None,
        }
    }

    /// The record identity for a **successful** install, built from the
    /// EXECUTED plan — the binding A5 rule: the flatpak `app_ref` is the
    /// ref the backend ran (never re-derived from the registry app), the
    /// brew token + kind and the distro package + family come from the
    /// operation and the plan's backend routing, and a direct install
    /// records its provenance (URL, digest, and the install-dir path the
    /// attached direct backend resolves `bin_name` against).
    #[cfg_attr(not(feature = "direct"), allow(clippy::unused_self))]
    fn native_ids_from_executed(&self, plan: &InstallPlan) -> AppsResult<NativeIds> {
        match &plan.operation {
            Operation::BrewInstall { cask, token } => Ok(NativeIds::Homebrew {
                token: token.clone(),
                cask: *cask,
            }),
            Operation::FlatpakInstall {
                app_ref,
                installation,
                ..
            } => {
                // The ref's own id segment is the actually-installed app
                // id — parsed out of the executed ref, not re-derived.
                let Some(app_id) = app_id_from_ref(app_ref) else {
                    return Err(AppsError::UnrecordableOperation {
                        app: plan.app.as_str().to_owned(),
                        operation: format!("flatpak ref `{app_ref}` carries no app id segment"),
                    });
                };
                Ok(NativeIds::Flatpak {
                    app_id: app_id.to_owned(),
                    app_ref: Some(app_ref.clone()),
                    installation: *installation,
                })
            }
            Operation::DistroInstall { package, .. } => match plan.backend {
                BackendId::Distro(family) => Ok(NativeIds::Distro {
                    package: package.clone(),
                    family,
                }),
                backend => Err(AppsError::UnrecordableOperation {
                    app: plan.app.as_str().to_owned(),
                    operation: format!("distro install planned for backend {backend}"),
                }),
            },
            #[cfg(feature = "direct")]
            Operation::DirectInstall {
                url,
                checksum,
                bin_name,
            } => {
                let Some(dir) = self.direct_install_dir() else {
                    return Err(AppsError::UnrecordableOperation {
                        app: plan.app.as_str().to_owned(),
                        operation: format!(
                            "no direct backend is attached to resolve where `{bin_name}` lands"
                        ),
                    });
                };
                Ok(NativeIds::Direct {
                    url: url.clone(),
                    checksum: checksum.clone(),
                    bin_path: dir.join(bin_name).to_string(),
                })
            }
            other => Err(AppsError::UnrecordableOperation {
                app: plan.app.as_str().to_owned(),
                operation: format!("{other:?} is not an install operation"),
            }),
        }
    }
}

/// The uninstall plan for a toride-managed record: built from the
/// record's OWN identifiers — the source of truth, never re-planned (the
/// A1 round-1 flatpak finding: a re-planned ref guesses the planning
/// target's arch, not the installed one). `zap` mirrors the planner's
/// rule: casks only. The plan's app slot is the caller's `id` — adopted
/// records carry no plan to read it from.
fn uninstall_plan_from_record(
    id: &TorideId,
    record: &InstallRecord,
    zap: bool,
) -> AppsResult<UninstallPlan> {
    let backend = record.ids.backend();
    let operation = match &record.ids {
        NativeIds::Homebrew { token, cask } => Operation::BrewUninstall {
            token: token.clone(),
            cask: *cask,
            zap: zap && *cask,
        },
        NativeIds::Flatpak {
            app_id,
            installation,
            ..
        } => Operation::FlatpakUninstall {
            app_id: app_id.clone(),
            installation: *installation,
        },
        NativeIds::Distro { package, family } => {
            let manager = PackageManager::for_family(*family).ok_or_else(|| {
                AppsError::UnrecordableOperation {
                    app: id.as_str().to_owned(),
                    operation: format!("distro family {family:?} has no routed manager"),
                }
            })?;
            Operation::DistroUninstall {
                manager,
                package: package.clone(),
            }
        }
        #[cfg(feature = "direct")]
        NativeIds::Direct { bin_path, .. } => Operation::DirectUninstall {
            bin_path: bin_path.clone(),
        },
    };
    Ok(UninstallPlan {
        app: id.clone(),
        backend,
        operation,
        dry_run: false,
        // Distro managers require root for removal, exactly as for
        // install (the A4 contract); brew and flatpak (user scope) do not.
        requires_elevation: matches!(backend, BackendId::Distro(_)),
    })
}

/// The update plan for a toride-managed record — the update-path mirror
/// of [`uninstall_plan_from_record`]: built from the record's OWN
/// identifiers, never re-planned through the registry (the update path
/// makes zero adapter round trips).
fn update_plan_from_record(id: &TorideId, record: &InstallRecord) -> AppsResult<UpdatePlan> {
    let backend = record.ids.backend();
    let operation = match &record.ids {
        NativeIds::Homebrew { token, cask } => Operation::BrewUpgrade {
            token: token.clone(),
            cask: *cask,
        },
        NativeIds::Flatpak {
            app_id,
            installation,
            ..
        } => Operation::FlatpakUpdate {
            app_id: app_id.clone(),
            installation: *installation,
        },
        NativeIds::Distro { package, family } => {
            let manager = PackageManager::for_family(*family).ok_or_else(|| {
                AppsError::UnrecordableOperation {
                    app: id.as_str().to_owned(),
                    operation: format!("distro family {family:?} has no routed manager"),
                }
            })?;
            Operation::DistroUpdate {
                manager,
                package: package.clone(),
            }
        }
        #[cfg(feature = "direct")]
        NativeIds::Direct { bin_path, .. } => {
            return Err(AppsError::UnrecordableOperation {
                app: id.as_str().to_owned(),
                operation: format!(
                    "direct binary `{bin_path}` has no update verb — re-run ensure_installed to re-download"
                ),
            });
        }
    };
    Ok(UpdatePlan {
        app: id.clone(),
        backend,
        operation,
        dry_run: false,
        requires_elevation: matches!(backend, BackendId::Distro(_)),
    })
}

/// The backend-native id a record's identifiers key on — the join key the
/// trait's version probes take (brew token, flatpak app id, distro
/// package name).
fn native_id(ids: &NativeIds) -> &str {
    match ids {
        NativeIds::Homebrew { token, .. } => token,
        NativeIds::Flatpak { app_id, .. } => app_id,
        NativeIds::Distro { package, .. } => package,
        #[cfg(feature = "direct")]
        NativeIds::Direct { bin_path, .. } => bin_path,
    }
}

/// The app id segment of an install ref (`app/<id>/<arch>/<branch>` → the
/// id) — this facade's mirror of the flatpak backend's private derivation,
/// used to read the actually-installed id back out of the executed ref.
/// `None` for refs without the `app/` prefix (runtime refs, bare ids).
fn app_id_from_ref(app_ref: &str) -> Option<&str> {
    let mut parts = app_ref.split('/');
    if parts.next()? != "app" {
        return None;
    }
    parts.next().filter(|id| !id.is_empty())
}

/// Whether a confirming presence answer satisfies a requested install
/// version. `None` (the default) is satisfied by any presence. A named
/// version is judged by the record's own kind: brew by the probed version
/// (the listing always versions a present item), flatpak by the recorded
/// ref's branch — the version slot a flatpak request selects — never by
/// the appdata version the probe reports. Distro records never satisfy
/// one: distro methods cannot express a version, and the fall-through
/// plan refuses.
fn requested_version_satisfied(
    ids: &NativeIds,
    recorded: &AppStatus,
    requested: Option<&Version>,
) -> bool {
    let Some(requested) = requested else {
        return true;
    };
    match ids {
        NativeIds::Homebrew { .. } => match recorded {
            AppStatus::Installed { version, .. } => version.as_deref() == Some(requested.as_str()),
            AppStatus::Foreign { .. } | AppStatus::NotInstalled => false,
        },
        NativeIds::Flatpak { app_ref, .. } => {
            app_ref.as_deref().and_then(ref_branch) == Some(requested.as_str())
        }
        NativeIds::Distro { .. } => false,
        #[cfg(feature = "direct")]
        NativeIds::Direct { .. } => false,
    }
}

/// The branch segment of an install ref (`app/<id>/<arch>/<branch>` → the
/// branch). `None` for malformed or non-app refs.
fn ref_branch(app_ref: &str) -> Option<&str> {
    app_ref
        .split('/')
        .nth(3)
        .filter(|branch| !branch.is_empty())
}

/// The direct arm of both presence probes: the backend's own filesystem
/// probe is the one answer, so the facade and the status layer can never
/// drift apart.
#[cfg(feature = "direct")]
fn direct_presence(status: BackendStatus) -> Presence {
    match status {
        BackendStatus::Installed { version } => Presence::Present(version),
        BackendStatus::NotInstalled => Presence::Absent,
    }
}

/// A human-readable name for what a set of native identifiers addresses —
/// the subject of the facade's warnings.
fn native_subject(ids: &NativeIds) -> String {
    match ids {
        NativeIds::Homebrew { token, cask: true } => format!("cask `{token}`"),
        NativeIds::Homebrew {
            token, cask: false, ..
        } => format!("formula `{token}`"),
        NativeIds::Flatpak { app_id, .. } => format!("flatpak `{app_id}`"),
        NativeIds::Distro { package, .. } => format!("package `{package}`"),
        #[cfg(feature = "direct")]
        NativeIds::Direct { bin_path, .. } => format!("direct binary `{bin_path}`"),
    }
}

/// Append `text` to the outcome warning, joining any earlier one —
/// degraded conditions stack; none is dropped.
fn push_warning(warning: &mut Option<String>, text: String) {
    match warning {
        Some(existing) => {
            existing.push_str("; ");
            existing.push_str(&text);
        }
        None => *warning = Some(text),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::FlatpakInstallation;
    use toride_registry::{DistroFamily, SourceKind};

    /// An empty facade over a unique temp manifest, no backends attached.
    fn empty_apps() -> Apps {
        let path = std::env::temp_dir().join(format!(
            "toride-apps-unit-{}-{}.json",
            std::process::id(),
            line!()
        ));
        let path = Utf8PathBuf::from_path_buf(path).expect("system temp dir is valid UTF-8");
        Apps::builder().manifest_path(&path).build().unwrap()
    }

    // --- options -----------------------------------------------------------------

    #[test]
    fn install_options_default_off_and_elevated_is_fluent() {
        let options = AppInstallOptions::default();
        assert!(!options.elevated);
        assert!(options.version.is_none());
        assert!(AppInstallOptions::new().elevated(true).elevated);
        assert_eq!(AppInstallOptions::default(), AppInstallOptions::new());
    }

    #[test]
    fn install_options_select_a_version_fluently() {
        let pinned = AppInstallOptions::new()
            .elevated(true)
            .version(Some(Version::new("138.0.1")));
        assert!(pinned.elevated);
        assert_eq!(pinned.version, Some(Version::new("138.0.1")));
        assert_eq!(pinned.version(None).version, None);
    }

    #[test]
    fn uninstall_options_default_off_and_the_setters_are_fluent() {
        let options = AppUninstallOptions::default();
        assert!(!options.zap && !options.elevated && !options.force);
        let options = AppUninstallOptions::new()
            .zap(true)
            .elevated(true)
            .force(true);
        assert!(options.zap && options.elevated && options.force);
    }

    // --- error wording -----------------------------------------------------------

    #[test]
    fn foreign_not_managed_names_the_app_the_evidence_and_the_force_escape() {
        let error = AppsError::ForeignNotManaged {
            id: "brave".to_owned(),
            detail: "brew token `brave-browser` is installed".to_owned(),
        };
        let text = error.to_string();
        assert!(text.contains("`brave`"), "{text}");
        assert!(text.contains("not by toride"), "{text}");
        assert!(text.contains("brew token `brave-browser`"), "{text}");
        assert!(text.contains("force"), "{text}");
    }

    #[test]
    fn unresolved_names_the_app() {
        let error = AppsError::Unresolved {
            id: "ghost-app".to_owned(),
        };
        assert!(error.to_string().contains("`ghost-app`"), "{}", error);
    }

    #[test]
    fn backend_unavailable_names_the_backend() {
        let error = AppsError::BackendUnavailable {
            backend: BackendId::Homebrew,
        };
        assert!(error.to_string().contains("homebrew"), "{error}");
    }

    #[test]
    fn no_manifest_path_explains_the_escape() {
        let text = AppsError::NoManifestPath.to_string();
        assert!(text.contains("explicit path"), "{text}");
    }

    #[test]
    fn blocking_resolve_required_names_the_app_and_both_escapes() {
        let error = AppsError::BlockingResolveRequired {
            id: "brave".to_owned(),
        };
        let text = error.to_string();
        assert!(text.contains("`brave`"), "{text}");
        assert!(text.contains("adapters are async"), "{text}");
        assert!(text.contains("resolved app"), "{text}");
        assert!(text.contains("async facade"), "{text}");
    }

    #[test]
    fn apps_error_wraps_the_layer_errors_via_from() {
        let backend = AppsError::from(crate::Error::AppDisabled {
            app: "x".to_owned(),
        });
        assert!(matches!(backend, AppsError::Backend(_)));
        let registry = AppsError::from(toride_registry::Error::UnsupportedSource {
            kind: SourceKind::Flathub,
            id: "x".to_owned(),
        });
        assert!(matches!(registry, AppsError::Registry(_)));
        let manifest = AppsError::from(ManifestError::Io(std::io::Error::other("nope")));
        assert!(matches!(manifest, AppsError::Manifest(_)));
    }

    // --- native identity derivation ----------------------------------------------

    fn app_with_method(method: InstallMethod) -> App {
        App {
            id: TorideId::slugify("probe-app"),
            name: "Probe App".to_owned(),
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
            availability: toride_registry::Availability::Available,
        }
    }

    #[test]
    fn native_ids_for_maps_every_wave_one_method() {
        let apps = empty_apps();
        assert_eq!(
            apps.native_ids_for(&app_with_method(InstallMethod::Homebrew {
                cask: true,
                token: "firefox".to_owned(),
            })),
            Some(NativeIds::Homebrew {
                token: "firefox".to_owned(),
                cask: true,
            })
        );
        // Flatpak: the id without an installed ref, toride's planned scope.
        assert_eq!(
            apps.native_ids_for(&app_with_method(InstallMethod::Flatpak {
                app_id: "com.brave.Browser".to_owned(),
                remote: "flathub".to_owned(),
            })),
            Some(NativeIds::Flatpak {
                app_id: "com.brave.Browser".to_owned(),
                app_ref: None,
                installation: FlatpakInstallation::User,
            })
        );
        assert_eq!(
            apps.native_ids_for(&app_with_method(InstallMethod::Distro {
                family: DistroFamily::Debian,
                repo: None,
                package: "firefox".to_owned(),
            })),
            Some(NativeIds::Distro {
                package: "firefox".to_owned(),
                family: DistroFamily::Debian,
            })
        );
    }

    #[test]
    fn native_ids_for_direct_without_a_backend_is_none() {
        let apps = empty_apps();
        assert_eq!(
            apps.native_ids_for(&app_with_method(InstallMethod::Direct {
                url: "https://example.com".to_owned(),
                checksum: None,
                arch: None,
            })),
            None
        );
    }

    #[cfg(feature = "direct")]
    #[test]
    fn native_ids_for_direct_with_a_backend_resolves_the_install_dir_path() {
        let dir =
            std::env::temp_dir().join(format!("toride-apps-native-direct-{}", std::process::id()));
        let dir = Utf8PathBuf::from_path_buf(dir).expect("system temp dir is valid UTF-8");
        let apps = Apps::builder()
            .manifest_path(temp_manifest_path("native-direct"))
            .direct(DirectBackend::at(&dir))
            .build()
            .unwrap();
        let mut app = app_with_method(InstallMethod::Direct {
            url: "https://example.com/dist/rg-14.1.0".to_owned(),
            checksum: None,
            arch: None,
        });
        app.binaries = vec!["rg".to_owned()];
        assert_eq!(
            apps.native_ids_for(&app),
            Some(NativeIds::Direct {
                url: "https://example.com/dist/rg-14.1.0".to_owned(),
                checksum: None,
                bin_path: dir.join("rg").to_string(),
            })
        );
    }

    #[cfg(feature = "direct")]
    fn temp_manifest_path(label: &str) -> Utf8PathBuf {
        let path = std::env::temp_dir().join(format!(
            "toride-apps-unit-manifest-{}-{label}.json",
            std::process::id()
        ));
        Utf8PathBuf::from_path_buf(path).expect("system temp dir is valid UTF-8")
    }

    #[test]
    fn native_ids_from_executed_read_the_executed_operation() {
        let apps = empty_apps();
        let brew = InstallPlan {
            app: TorideId::slugify("brave"),
            backend: BackendId::Homebrew,
            operation: Operation::BrewInstall {
                cask: true,
                token: "brave-browser".to_owned(),
            },
            dry_run: false,
            requires_elevation: false,
        };
        assert_eq!(
            apps.native_ids_from_executed(&brew).unwrap(),
            NativeIds::Homebrew {
                token: "brave-browser".to_owned(),
                cask: true,
            }
        );
    }

    #[test]
    fn native_ids_from_executed_record_the_flatpak_ref_that_ran() {
        let apps = empty_apps();
        let plan = InstallPlan {
            app: TorideId::slugify("brave"),
            backend: BackendId::Flatpak,
            operation: Operation::FlatpakInstall {
                remote: "flathub".to_owned(),
                app_ref: "app/com.brave.Browser/x86_64/stable".to_owned(),
                installation: FlatpakInstallation::User,
            },
            dry_run: false,
            requires_elevation: false,
        };
        // The ref, verbatim — never re-derived — and its own id segment.
        assert_eq!(
            apps.native_ids_from_executed(&plan).unwrap(),
            NativeIds::Flatpak {
                app_id: "com.brave.Browser".to_owned(),
                app_ref: Some("app/com.brave.Browser/x86_64/stable".to_owned()),
                installation: FlatpakInstallation::User,
            }
        );
    }

    #[test]
    fn native_ids_from_executed_reject_a_ref_without_an_app_id_segment() {
        let apps = empty_apps();
        let plan = InstallPlan {
            app: TorideId::slugify("brave"),
            backend: BackendId::Flatpak,
            operation: Operation::FlatpakInstall {
                remote: "flathub".to_owned(),
                app_ref: "com.brave.Browser".to_owned(),
                installation: FlatpakInstallation::User,
            },
            dry_run: false,
            requires_elevation: false,
        };
        assert!(
            matches!(
                apps.native_ids_from_executed(&plan),
                Err(AppsError::UnrecordableOperation { .. })
            ),
            "a bare-id ref is not a recordable install identity"
        );
    }

    #[test]
    fn native_ids_from_executed_map_the_distro_family_from_the_plan_backend() {
        let apps = empty_apps();
        let plan = InstallPlan {
            app: TorideId::slugify("brave"),
            backend: BackendId::Distro(DistroFamily::Ubuntu),
            operation: Operation::DistroInstall {
                manager: PackageManager::Apt,
                package: "brave-browser".to_owned(),
            },
            dry_run: false,
            requires_elevation: true,
        };
        assert_eq!(
            apps.native_ids_from_executed(&plan).unwrap(),
            NativeIds::Distro {
                package: "brave-browser".to_owned(),
                family: DistroFamily::Ubuntu,
            }
        );
    }

    #[test]
    fn native_ids_from_executed_reject_non_install_operations() {
        let apps = empty_apps();
        let plan = InstallPlan {
            app: TorideId::slugify("brave"),
            backend: BackendId::Homebrew,
            operation: Operation::BrewUninstall {
                cask: true,
                token: "brave-browser".to_owned(),
                zap: false,
            },
            dry_run: false,
            requires_elevation: false,
        };
        assert!(apps.native_ids_from_executed(&plan).is_err());
    }

    // --- record-sourced uninstall plans ------------------------------------------

    fn record_for(operation: Operation, ids: NativeIds) -> InstallRecord {
        let backend = ids.backend();
        InstallRecord::new(
            InstallPlan {
                app: TorideId::slugify("brave"),
                backend,
                operation,
                dry_run: false,
                requires_elevation: matches!(backend, BackendId::Distro(_)),
            },
            ids,
            None,
        )
        .with_installed_at(1_700_000_000)
    }

    fn cask_record() -> InstallRecord {
        record_for(
            Operation::BrewInstall {
                cask: true,
                token: "brave-browser".to_owned(),
            },
            NativeIds::Homebrew {
                token: "brave-browser".to_owned(),
                cask: true,
            },
        )
    }

    fn formula_record() -> InstallRecord {
        record_for(
            Operation::BrewInstall {
                cask: false,
                token: "ripgrep".to_owned(),
            },
            NativeIds::Homebrew {
                token: "ripgrep".to_owned(),
                cask: false,
            },
        )
    }

    #[test]
    fn uninstall_plan_from_record_reads_the_record_ids_verbatim() {
        let record = record_for(
            Operation::FlatpakInstall {
                remote: "flathub".to_owned(),
                // The record's install plan spelled an x86_64 ref; the
                // uninstall must replay the RECORD's bare app id, never a
                // re-derived ref.
                app_ref: "app/com.brave.Browser/x86_64/stable".to_owned(),
                installation: FlatpakInstallation::System,
            },
            NativeIds::Flatpak {
                app_id: "com.brave.Browser".to_owned(),
                app_ref: Some("app/com.brave.Browser/x86_64/stable".to_owned()),
                installation: FlatpakInstallation::System,
            },
        );
        let plan = uninstall_plan_from_record(&TorideId::slugify("brave"), &record, false).unwrap();
        assert_eq!(
            plan.operation,
            Operation::FlatpakUninstall {
                app_id: "com.brave.Browser".to_owned(),
                installation: FlatpakInstallation::System,
            }
        );
        assert_eq!(plan.backend, BackendId::Flatpak);
        assert!(!plan.requires_elevation);
    }

    #[test]
    fn uninstall_plan_from_record_ands_zap_with_cask() {
        let zap = uninstall_plan_from_record(&TorideId::slugify("brave"), &cask_record(), true)
            .unwrap()
            .operation;
        assert_eq!(
            zap.argv(),
            ["brew", "uninstall", "--zap", "brave-browser"],
            "zap applies to the recorded cask"
        );
        let plain_formula =
            uninstall_plan_from_record(&TorideId::slugify("brave"), &formula_record(), true)
                .unwrap()
                .operation;
        assert_eq!(
            plain_formula.argv(),
            ["brew", "uninstall", "ripgrep"],
            "zap degrades to a plain uninstall for a recorded formula"
        );
        let plain_cask =
            uninstall_plan_from_record(&TorideId::slugify("brave"), &cask_record(), false)
                .unwrap()
                .operation;
        assert_eq!(
            plain_cask.argv(),
            ["brew", "uninstall", "--cask", "brave-browser"]
        );
    }

    #[test]
    fn uninstall_plan_from_record_requires_elevation_only_for_distro() {
        let distro = record_for(
            Operation::DistroInstall {
                manager: PackageManager::Apt,
                package: "brave-browser".to_owned(),
            },
            NativeIds::Distro {
                package: "brave-browser".to_owned(),
                family: DistroFamily::Debian,
            },
        );
        let plan = uninstall_plan_from_record(&TorideId::slugify("brave"), &distro, false).unwrap();
        assert!(plan.requires_elevation);
        assert_eq!(
            plan.operation,
            Operation::DistroUninstall {
                manager: PackageManager::Apt,
                package: "brave-browser".to_owned(),
            }
        );
        assert!(
            !uninstall_plan_from_record(&TorideId::slugify("brave"), &cask_record(), false)
                .unwrap()
                .requires_elevation
        );
    }

    #[test]
    fn update_options_default_off_and_the_setters_are_fluent() {
        let options = AppUpdateOptions::default();
        assert!(!options.elevated && !options.dry_run && options.target.is_none());
        assert_eq!(AppUpdateOptions::default(), AppUpdateOptions::new());
        let pinned = AppUpdateOptions::new()
            .elevated(true)
            .dry_run(true)
            .target(Some(Version::new("1.2.3")));
        assert!(pinned.elevated && pinned.dry_run);
        assert_eq!(pinned.target, Some(Version::new("1.2.3")));
        let cleared = pinned.target(None);
        assert!(cleared.target.is_none(), "the manager's current again");
    }

    #[test]
    fn unrecorded_update_names_the_app_and_the_escape() {
        let error = AppsError::UnrecordedUpdate {
            id: "ghost".to_owned(),
        };
        let text = error.to_string();
        assert!(text.contains("`ghost`"), "{text}");
        assert!(text.contains("ensure_installed"), "{text}");
    }

    #[test]
    fn update_target_not_pinnable_names_the_target() {
        let error = AppsError::UpdateTargetNotPinnable {
            id: "ghost".to_owned(),
            target: "2.0.0".to_owned(),
        };
        let text = error.to_string();
        assert!(text.contains("`ghost`"), "{text}");
        assert!(text.contains("2.0.0"), "{text}");
        assert!(text.contains("not implemented"), "{text}");
    }

    #[test]
    fn unrecorded_pin_and_unpin_name_the_app_and_the_escape() {
        let pin = AppsError::UnrecordedPin {
            id: "ghost".to_owned(),
        };
        let text = pin.to_string();
        assert!(text.contains("cannot pin"), "{text}");
        assert!(text.contains("`ghost`"), "{text}");
        assert!(text.contains("ensure_installed"), "{text}");
        let unpin = AppsError::UnrecordedUnpin {
            id: "ghost".to_owned(),
        };
        assert!(unpin.to_string().contains("cannot unpin"), "{unpin}");
    }

    fn update_plan_for_ids(ids: NativeIds) -> AppsResult<UpdatePlan> {
        let backend = ids.backend();
        update_plan_from_record(
            &TorideId::slugify("brave"),
            &InstallRecord::new(
                InstallPlan {
                    app: TorideId::slugify("brave"),
                    backend,
                    operation: Operation::BrewInstall {
                        cask: false,
                        token: "unused".to_owned(),
                    },
                    dry_run: false,
                    requires_elevation: false,
                },
                ids,
                None,
            ),
        )
    }

    #[test]
    fn update_plan_from_record_reads_the_record_ids_verbatim() {
        let brew = update_plan_for_ids(NativeIds::Homebrew {
            token: "brave-browser".to_owned(),
            cask: true,
        })
        .unwrap();
        assert_eq!(
            brew.operation.argv(),
            ["brew", "upgrade", "--cask", "brave-browser"]
        );
        assert_eq!(brew.backend, BackendId::Homebrew);
        assert!(!brew.requires_elevation);
        assert!(!brew.dry_run);

        let flatpak = update_plan_for_ids(NativeIds::Flatpak {
            app_id: "com.brave.Browser".to_owned(),
            app_ref: Some("app/com.brave.Browser/x86_64/stable".to_owned()),
            installation: FlatpakInstallation::System,
        })
        .unwrap();
        assert_eq!(
            flatpak.operation.argv(),
            ["flatpak", "update", "--system", "com.brave.Browser"]
        );

        let distro = update_plan_for_ids(NativeIds::Distro {
            package: "brave-browser".to_owned(),
            family: DistroFamily::Arch,
        })
        .unwrap();
        assert_eq!(
            distro.operation.argv(),
            ["pacman", "--sync", "--refresh", "brave-browser"]
        );
        assert_eq!(distro.backend, BackendId::Distro(DistroFamily::Arch));
        assert!(distro.requires_elevation, "distro updates need root");
    }

    #[test]
    fn native_id_keys_each_kind_on_its_backend_native_spelling() {
        assert_eq!(
            native_id(&NativeIds::Homebrew {
                token: "firefox".to_owned(),
                cask: true,
            }),
            "firefox"
        );
        assert_eq!(
            native_id(&NativeIds::Flatpak {
                app_id: "com.brave.Browser".to_owned(),
                app_ref: None,
                installation: FlatpakInstallation::User,
            }),
            "com.brave.Browser"
        );
        assert_eq!(
            native_id(&NativeIds::Distro {
                package: "brave-browser".to_owned(),
                family: DistroFamily::Debian,
            }),
            "brave-browser"
        );
    }

    // --- small helpers -------------------------------------------------------------

    #[test]
    fn app_id_from_ref_extracts_and_rejects() {
        assert_eq!(
            app_id_from_ref("app/com.brave.Browser/x86_64/stable"),
            Some("com.brave.Browser")
        );
        assert_eq!(
            app_id_from_ref("runtime/org.gnome.Platform/x86_64/48"),
            None
        );
        assert_eq!(app_id_from_ref("app//x86_64/stable"), None);
    }

    #[test]
    fn ref_branch_extracts_and_rejects() {
        assert_eq!(
            ref_branch("app/com.brave.Browser/x86_64/beta"),
            Some("beta")
        );
        assert_eq!(ref_branch("app/com.brave.Browser/x86_64"), None);
        assert_eq!(ref_branch("com.brave.Browser"), None);
        assert_eq!(ref_branch("app/com.brave.Browser/x86_64/"), None);
    }

    #[test]
    fn requested_version_none_is_satisfied_by_any_presence() {
        for ids in [
            NativeIds::Homebrew {
                token: "firefox".to_owned(),
                cask: true,
            },
            NativeIds::Distro {
                package: "firefox".to_owned(),
                family: DistroFamily::Debian,
            },
        ] {
            assert!(requested_version_satisfied(
                &ids,
                &AppStatus::Installed {
                    backend: ids.backend(),
                    version: None,
                },
                None
            ));
        }
    }

    #[test]
    fn brew_records_satisfy_a_version_by_the_probed_version() {
        let ids = NativeIds::Homebrew {
            token: "firefox@138.0.1".to_owned(),
            cask: true,
        };
        let probed = AppStatus::Installed {
            backend: BackendId::Homebrew,
            version: Some("138.0.1".to_owned()),
        };
        assert!(requested_version_satisfied(
            &ids,
            &probed,
            Some(&Version::new("138.0.1"))
        ));
        assert!(!requested_version_satisfied(
            &ids,
            &probed,
            Some(&Version::new("139.0"))
        ));
        assert!(!requested_version_satisfied(
            &ids,
            &AppStatus::Installed {
                backend: BackendId::Homebrew,
                version: None,
            },
            Some(&Version::new("138.0.1"))
        ));
    }

    #[test]
    fn flatpak_records_satisfy_a_version_by_the_recorded_branch() {
        let ids = NativeIds::Flatpak {
            app_id: "com.brave.Browser".to_owned(),
            app_ref: Some("app/com.brave.Browser/x86_64/beta".to_owned()),
            installation: FlatpakInstallation::User,
        };
        let probed = AppStatus::Installed {
            backend: BackendId::Flatpak,
            version: Some("1.2.3".to_owned()),
        };
        assert!(
            requested_version_satisfied(&ids, &probed, Some(&Version::new("beta"))),
            "the recorded branch satisfies, never the appdata version"
        );
        assert!(!requested_version_satisfied(
            &ids,
            &probed,
            Some(&Version::new("1.2.3")),
        ));
        assert!(!requested_version_satisfied(
            &ids,
            &probed,
            Some(&Version::new("stable"))
        ));
        let no_ref = NativeIds::Flatpak {
            app_id: "com.brave.Browser".to_owned(),
            app_ref: None,
            installation: FlatpakInstallation::User,
        };
        assert!(!requested_version_satisfied(
            &no_ref,
            &probed,
            Some(&Version::new("beta"))
        ));
    }

    #[test]
    fn distro_records_never_satisfy_a_named_version() {
        let ids = NativeIds::Distro {
            package: "firefox".to_owned(),
            family: DistroFamily::Debian,
        };
        assert!(!requested_version_satisfied(
            &ids,
            &AppStatus::Installed {
                backend: ids.backend(),
                version: Some("138.0".to_owned()),
            },
            Some(&Version::new("138.0"))
        ));
    }

    #[test]
    fn native_subject_names_each_kind() {
        assert_eq!(
            native_subject(&NativeIds::Homebrew {
                token: "firefox".to_owned(),
                cask: true,
            }),
            "cask `firefox`"
        );
        assert_eq!(
            native_subject(&NativeIds::Homebrew {
                token: "ripgrep".to_owned(),
                cask: false,
            }),
            "formula `ripgrep`"
        );
        assert_eq!(
            native_subject(&NativeIds::Flatpak {
                app_id: "com.brave.Browser".to_owned(),
                app_ref: None,
                installation: FlatpakInstallation::User,
            }),
            "flatpak `com.brave.Browser`"
        );
        assert_eq!(
            native_subject(&NativeIds::Distro {
                package: "brave-browser".to_owned(),
                family: DistroFamily::Debian,
            }),
            "package `brave-browser`"
        );
    }

    #[test]
    fn push_warning_joins_instead_of_dropping() {
        let mut warning = Some("first".to_owned());
        push_warning(&mut warning, "second".to_owned());
        assert_eq!(warning.as_deref(), Some("first; second"));
        let mut warning = None;
        push_warning(&mut warning, "only".to_owned());
        assert_eq!(warning.as_deref(), Some("only"));
    }

    // --- builder wiring -------------------------------------------------------------

    #[test]
    fn builder_preserves_the_target_and_loads_the_default_store_from_the_manifest_path() {
        use crate::{Arch, Os};
        let target = Target::new(Os::Linux, Arch::X86_64);
        let path = Utf8PathBuf::from_path_buf(
            std::env::temp_dir().join(format!("toride-apps-wiring-{}.json", std::process::id())),
        )
        .expect("system temp dir is valid UTF-8");
        let mut manifest = InstallManifest::at(&path);
        manifest.record(
            &TorideId::slugify("brave"),
            InstallRecord::adopted(
                NativeIds::Homebrew {
                    token: "brave-browser".to_owned(),
                    cask: true,
                },
                None,
            ),
        );
        manifest.save().expect("seed manifest saves");
        let apps = Apps::builder()
            .target(target)
            .manifest_path(&path)
            .build()
            .unwrap();
        assert_eq!(apps.target(), target);
        assert_eq!(apps.records().len(), 1, "the path feeds the default store");
        assert_eq!(apps.quarantined(), None);
    }

    #[test]
    fn builder_defaults_the_target_to_the_host_with_distro_detection() {
        let manifest_path = Utf8PathBuf::from_path_buf(
            std::env::temp_dir().join("toride-apps-default-target.json"),
        )
        .expect("system temp dir is valid UTF-8");
        let apps = Apps::builder()
            .manifest_path(&manifest_path)
            .build()
            .unwrap();
        assert_eq!(apps.target().os, Target::host().os);
        assert_eq!(apps.target().distro, detect_host_family());
    }

    #[test]
    fn builder_fails_when_no_manifest_path_resolves() {
        // No manifest_path set and the default data dir overridden away is
        // not constructible offline; pin the error shape directly instead.
        let error = AppsError::NoManifestPath;
        assert!(error.to_string().contains("data directory"), "{error}");
        assert!(error.to_string().contains("record store"), "{error}");
    }

    #[test]
    fn already_recorded_names_the_app() {
        let error = AppsError::AlreadyRecorded {
            id: "ghost".to_owned(),
        };
        let text = error.to_string();
        assert!(text.contains("cannot adopt"), "{text}");
        assert!(text.contains("`ghost`"), "{text}");
        assert!(text.contains("already has a record"), "{text}");
    }

    #[test]
    fn adoption_absent_names_the_app_and_the_absent_subject() {
        let error = AppsError::AdoptionAbsent {
            id: "ghost".to_owned(),
            detail: "formula `ripgrep` is not present".to_owned(),
        };
        let text = error.to_string();
        assert!(text.contains("cannot adopt"), "{text}");
        assert!(text.contains("`ghost`"), "{text}");
        assert!(text.contains("formula `ripgrep` is not present"), "{text}");
    }

    #[test]
    fn adopt_provenance_new_defaults_to_an_unknown_install_time() {
        let provenance = AdoptProvenance::new(NativeIds::Homebrew {
            token: "firefox".to_owned(),
            cask: true,
        });
        assert_eq!(provenance.installed_at, None);
        assert_eq!(provenance.ids.backend(), BackendId::Homebrew);
    }

    struct MapStore {
        snapshot: std::sync::Mutex<RecordSnapshot>,
    }

    impl crate::store::RecordStore for MapStore {
        fn load(&self) -> ManifestResult<crate::store::StoreLoad> {
            Ok(crate::store::StoreLoad {
                snapshot: self.snapshot.lock().expect("map store poisoned").clone(),
                quarantined: None,
            })
        }

        fn save(&self, snapshot: &RecordSnapshot) -> ManifestResult<()> {
            *self.snapshot.lock().expect("map store poisoned") = snapshot.clone();
            Ok(())
        }
    }

    #[test]
    fn builder_with_record_store_builds_without_any_manifest_path() {
        use crate::{Arch, Os};
        let mut records = std::collections::BTreeMap::new();
        records.insert(
            TorideId::slugify("brave"),
            InstallRecord::adopted(
                NativeIds::Distro {
                    package: "brave-browser".to_owned(),
                    family: toride_registry::DistroFamily::Debian,
                },
                None,
            ),
        );
        let store: std::sync::Arc<dyn RecordStore> = std::sync::Arc::new(MapStore {
            snapshot: std::sync::Mutex::new(RecordSnapshot::from(records)),
        });
        let apps = Apps::builder()
            .with_record_store(std::sync::Arc::clone(&store))
            .target(Target::new(Os::Linux, Arch::X86_64))
            .build()
            .unwrap();
        let listed = apps.records();
        assert_eq!(listed.len(), 1);
        assert_eq!(
            listed[0].0,
            &TorideId::slugify("brave"),
            "an adopted record's id stays recoverable — it carries no plan"
        );
        assert_eq!(listed[0].1.plan, None);
        assert_eq!(apps.quarantined(), None);
    }

    #[cfg(feature = "direct")]
    mod direct {
        use super::*;

        fn direct_record(bin_path: String) -> InstallRecord {
            let ids = NativeIds::Direct {
                url: "https://example.com/rg".to_owned(),
                checksum: None,
                bin_path,
            };
            InstallRecord::new(
                InstallPlan {
                    app: TorideId::slugify("ripgrep"),
                    backend: BackendId::Direct,
                    operation: Operation::DirectInstall {
                        url: "https://example.com/rg".to_owned(),
                        checksum: None,
                        bin_name: "rg".to_owned(),
                    },
                    dry_run: false,
                    requires_elevation: false,
                },
                ids,
                None,
            )
            .with_installed_at(1_700_000_000)
        }

        #[test]
        fn uninstall_plan_from_record_replays_the_recorded_binary_path() {
            let record = direct_record("/home/u/.local/bin/rg".to_owned());
            let plan =
                uninstall_plan_from_record(&TorideId::slugify("ripgrep"), &record, false).unwrap();
            assert_eq!(
                plan.operation,
                Operation::DirectUninstall {
                    bin_path: "/home/u/.local/bin/rg".to_owned()
                }
            );
            assert_eq!(plan.backend, BackendId::Direct);
            assert!(
                !plan.requires_elevation,
                "user-scope installs never need root"
            );
        }

        #[test]
        fn update_plan_from_record_refuses_a_direct_record() {
            let record = direct_record("/home/u/.local/bin/rg".to_owned());
            let error =
                update_plan_from_record(&TorideId::slugify("ripgrep"), &record).unwrap_err();
            assert!(
                matches!(error, AppsError::UnrecordableOperation { .. }),
                "{error:?}"
            );
            let text = error.to_string();
            assert!(text.contains("ripgrep"), "{text}");
            assert!(text.contains("ensure_installed"), "{text}");
        }

        #[test]
        fn direct_records_never_satisfy_a_named_install_version() {
            let ids = NativeIds::Direct {
                url: "https://example.com/rg".to_owned(),
                checksum: None,
                bin_path: "/home/u/.local/bin/rg".to_owned(),
            };
            assert!(!requested_version_satisfied(
                &ids,
                &AppStatus::Installed {
                    backend: BackendId::Direct,
                    version: None,
                },
                Some(&Version::new("14.1.0"))
            ));
            assert!(requested_version_satisfied(
                &ids,
                &AppStatus::Installed {
                    backend: BackendId::Direct,
                    version: None
                },
                None
            ));
        }

        #[test]
        fn native_subject_and_native_id_name_the_direct_binary_path() {
            let ids = NativeIds::Direct {
                url: "https://example.com/rg".to_owned(),
                checksum: None,
                bin_path: "/home/u/.local/bin/rg".to_owned(),
            };
            assert_eq!(
                native_subject(&ids),
                "direct binary `/home/u/.local/bin/rg`"
            );
            assert_eq!(native_id(&ids), "/home/u/.local/bin/rg");
        }
    }
}
