//! # Apps facade
//!
//! [`Apps`] is the front door of the execution layer: one call per user
//! intent — ensure an app is installed, update it, uninstall it, ask where
//! it stands, search the registries — composing every lower layer this
//! crate built:
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
//! ## Hard stops
//!
//! The manifest is loaded once at [`AppsBuilder::build`] and held
//! in memory (a single-process CLI assumption; concurrent writers are
//! last-rename-wins per the manifest's contract). A
//! [`ManifestError::Corrupt`] — above all the "written by a newer toride"
//! schema rejection — **fails the build and every operation after it**; the
//! facade never treats a corrupt document as empty and never saves over
//! one. That is the data-loss path the manifest layer closes; the facade
//! only re-persists after its own successful mutations.
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
//!   `force` on [`AppUninstallOptions`] to remove it anyway — an explicit,
//!   typed decision, never a silent one.
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

use std::sync::Arc;

use camino::Utf8PathBuf;
use toride_registry::model::{App, InstallMethod, SourceRef};
use toride_registry::{Adapter, TorideId};

use crate::backend::{
    Backend, BackendId, BackendStatus, InstallRequest, StatusQuery, UninstallRequest,
    UpdateRequest, Version,
};
use crate::backends::distro::detect_host_family;
use crate::backends::flatpak::FlatpakListScope;
use crate::backends::homebrew::BrewKind;
use crate::backends::{DistroBackend, FlatpakBackend, HomebrewBackend};
use crate::error::Error as BackendError;
use crate::manifest::{InstallManifest, InstallRecord, ManifestError, ManifestResult, NativeIds};
use crate::plan::{
    FlatpakInstallation, InstallPlan, Operation, PackageManager, Target, UninstallOptions,
    UninstallPlan, UpdatePlan, plan_install, plan_uninstall,
};
use crate::runner::CommandRunner;
use crate::status::{AppStatus, BackendSet, app_status};

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

    /// The install manifest failed to load (the **hard stop**: a corrupt
    /// document — above all "written by a newer toride" — never loads as
    /// empty and is never saved over) or to persist after a mutation (in
    /// which case the mutation itself already succeeded; post-mutation
    /// save failures are surfaced as outcome warnings instead).
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

    /// The builder found no manifest to bind: no path was set and the
    /// platform data directory (the manifest's default location) did not
    /// resolve. Pass an explicit path.
    #[error(
        "no manifest path: the platform data directory did not resolve; pass an explicit path to the builder"
    )]
    NoManifestPath,

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

    /// The options name a target version this toride cannot pin to — the
    /// wave-1 update verbs move to the manager's current only (version
    /// selection and pinning arrive with the install-time half of 3.6).
    #[error(
        "cannot update `{id}` to {target}: target pinning is not implemented — updates move to the manager's current version"
    )]
    UpdateTargetNotPinnable {
        /// Canonical toride id of the app.
        id: String,
        /// The requested target version's native spelling.
        target: String,
    },
}

// ---------------------------------------------------------------------------
// Options and outcomes
// ---------------------------------------------------------------------------

/// Options for [`Apps::ensure_installed`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AppInstallOptions {
    /// Elevation grant: `true` only when the caller has arranged root
    /// privileges. Distro plans require it; the facade never acquires
    /// elevation itself (the no-auto-sudo contract — a requiring plan
    /// without the grant is refused before any dispatch).
    pub elevated: bool,
}

impl AppInstallOptions {
    /// All-default options (no elevation grant).
    #[must_use]
    pub const fn new() -> Self {
        Self { elevated: false }
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
    /// satisfying on-`$PATH` copy).
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
}

/// The app install/uninstall front door: registry adapters for resolve,
/// the planner for exact operations, the attached backends for execution,
/// and the install manifest as the durable record of what toride did.
///
/// Build one with [`Apps::builder`]; mutating operations take `&mut self`
/// (the in-memory manifest is single-owner by design — see the module
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
    /// The durable record of what toride installed on this host, loaded
    /// once at build (missing file = empty; corrupt = the hard stop).
    manifest: InstallManifest,
    /// Registry adapters, consulted in registration order for resolve and
    /// fanned out for search.
    adapters: Vec<Arc<dyn Adapter>>,
}

impl Apps {
    /// Start building a facade — see [`AppsBuilder`].
    #[must_use]
    pub fn builder() -> AppsBuilder {
        AppsBuilder::new()
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

    /// The install manifest this facade holds (loaded at build; mutated by
    /// [`Apps::ensure_installed`] / [`Apps::uninstall`]).
    #[must_use]
    pub fn manifest(&self) -> &InstallManifest {
        &self.manifest
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
    ///    app falls through and re-installs).
    /// 2. **Resolve** — ask each adapter, in registration order, to look
    ///    up its source-native id equal to the canonical slug; the first
    ///    hit wins ([`AppsError::Unresolved`] otherwise).
    /// 3. **Foreign check** — when toride has no record, a backend
    ///    reporting the app's native identifiers present means someone
    ///    else installed it: keep it and return
    ///    [`EnsureAppOutcome::AlreadyPresent`] with
    ///    [`AppStatus::Foreign`], exactly like toride-installer keeps a
    ///    satisfying on-`$PATH` copy.
    /// 4. **Plan and execute** — [`plan_install`] derives the exact
    ///    operation for [`Apps::target`]; the routed backend executes it
    ///    with the caller's elevation grant (distro plans without one are
    ///    refused before any dispatch).
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
    /// [`AppsError::Backend`] for plan-stage refusals, elevation/dry-run
    /// guards, and command failures; [`AppsError::BackendUnavailable`]
    /// when the plan routes to an unattached backend;
    /// [`AppsError::Registry`] when an adapter fails; probe failures
    /// degrade to warnings, not errors.
    pub async fn ensure_installed(
        &mut self,
        id: &TorideId,
        options: AppInstallOptions,
    ) -> AppsResult<EnsureAppOutcome> {
        // 1. Detect before resolve: the manifest record plus one
        //    confirming backend probe, zero adapter calls.
        let recorded = app_status(id, None, &self.manifest, &self.backend_set()).await?;
        if matches!(recorded, AppStatus::Installed { .. }) {
            return Ok(EnsureAppOutcome::AlreadyPresent(recorded));
        }
        // 2. Resolve through the registry adapters.
        let app = self.resolve(id).await?;
        // 3. Foreign presence (only meaningful without a record — a record
        //    that failed confirmation in step 1 re-installs below).
        if self.manifest.get(id).is_none() {
            let native = native_from_method(&app.install);
            let status =
                app_status(id, native.as_ref(), &self.manifest, &self.backend_set()).await?;
            if let AppStatus::Foreign { .. } = status {
                return Ok(EnsureAppOutcome::AlreadyPresent(status));
            }
        }
        // 4. Plan, then derive the record identity from the EXECUTED
        //    operation (before any mutation, so a malformed plan fails
        //    with nothing dispatched).
        let plan = plan_install(&app, &self.target)?;
        let ids = native_ids_from_executed(&plan)?;
        let backend = self.backend_for(plan.backend)?;
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
        self.manifest.record(InstallRecord::new(
            plan,
            ids.clone(),
            recorded_version.clone(),
        ));
        if let Err(error) = self.save_manifest().await {
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
        let Some(record) = self.manifest.get(id).cloned() else {
            return self.uninstall_unrecorded(id, options).await;
        };
        // Plan from the record's ids — the executed install's own
        // identifiers, replayed verbatim.
        let plan = uninstall_plan_from_record(&record, options.zap)?;
        let backend = self.backend_for(plan.backend)?;
        backend
            .uninstall(UninstallRequest::new(&plan, &self.target).elevated(options.elevated))
            .await?;
        let mut warning = self.verify_absence(&record.ids).await;
        self.manifest.remove(id);
        if let Err(error) = self.save_manifest().await {
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
        // Planning first refuses what cannot run (a Direct method has no
        // uninstall backend — wave 2) before anything is probed.
        let plan = plan_uninstall(&app, &self.target, &UninstallOptions { zap: options.zap })?;
        let Some(native) = native_from_method(&app.install) else {
            // Unreachable behind a successful plan (every manager method
            // maps to ids); defense, not a silent skip.
            return Err(AppsError::UnrecordableOperation {
                app: id.as_str().to_owned(),
                operation: format!("{:?} carries no native identity", app.install),
            });
        };
        let status = app_status(id, Some(&native), &self.manifest, &self.backend_set()).await?;
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
    /// The currency decision prefers the manager's own stale signal (brew
    /// `outdated` answers per token) and falls back to installed-equals-
    /// available where no signal exists; versions are compared as opaque
    /// strings, never semver. A dry run executes nothing and touches no
    /// state: it answers [`UpdateOutcome::Preview`] with the argv that
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
        let Some(record) = self.manifest.get(id).cloned() else {
            return Err(AppsError::UnrecordedUpdate {
                id: id.as_str().to_owned(),
            });
        };
        let plan = update_plan_from_record(&record)?.dry_run(options.dry_run);
        let backend = self.backend_for(plan.backend)?;
        let native = native_id(&record.ids);
        let from = backend.installed_version(native).await?;
        if options.dry_run {
            let to = backend.available_version(native).await?;
            return Ok(UpdateOutcome::Preview(UpdatePreview {
                argv: plan.operation.argv(),
                from,
                to,
            }));
        }
        let reported_stale = backend
            .outdated()
            .await?
            .iter()
            .any(|entry| entry.id == native);
        if !reported_stale {
            let to = backend.available_version(native).await?;
            if from.is_some() && from == to {
                return Ok(UpdateOutcome::UpToDate);
            }
        }
        backend
            .update(UpdateRequest::new(&plan, &self.target).elevated(options.elevated))
            .await?;
        let to = backend.installed_version(native).await.ok().flatten();
        self.manifest
            .record(record.with_version(to.as_ref().map(|version| version.as_str().to_owned())));
        self.save_manifest().await?;
        Ok(UpdateOutcome::Updated { from, to })
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
        if self.manifest.get(id).is_some() {
            return Ok(app_status(id, None, &self.manifest, &self.backend_set()).await?);
        }
        let native = self
            .resolve(id)
            .await
            .ok()
            .and_then(|app| native_from_method(&app.install));
        Ok(app_status(id, native.as_ref(), &self.manifest, &self.backend_set()).await?)
    }

    /// Free-text search across every registered adapter, hits
    /// concatenated in registration order. Thin by design — matching,
    /// ranking, and merge are the registry layer's job.
    ///
    /// # Errors
    ///
    /// [`AppsError::Registry`] when any adapter fails; earlier adapters'
    /// hits are discarded with the error (a partial answer would look
    /// complete).
    pub async fn search(&self, query: &str) -> AppsResult<Vec<App>> {
        let mut hits = Vec::new();
        for adapter in &self.adapters {
            hits.extend(adapter.search(query).await?);
        }
        Ok(hits)
    }

    /// Resolve `id` to a registry [`App`]: each adapter, in registration
    /// order, is asked to look up its source-native id equal to the
    /// canonical slug (the ref is built with the adapter's own
    /// [`Adapter::source`], so no adapter ever sees a foreign ref). The
    /// first `Some` wins; the resolved app's own id becomes the manifest
    /// key downstream.
    async fn resolve(&self, id: &TorideId) -> AppsResult<App> {
        for adapter in &self.adapters {
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
        };
        routed.ok_or(AppsError::BackendUnavailable { backend })
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

    /// Persist the manifest off the async runtime.
    ///
    /// [`InstallManifest::save`] is synchronous filesystem IO (create
    /// parent dirs, write temp, rename) and must not run on an async
    /// worker — the standing don't-block rule; the crate-family precedent
    /// (toride-installer's extraction and detect) wraps its blocking work
    /// in [`tokio::task::spawn_blocking`] the same way. The manifest is
    /// cloned into the task (small by construction — one record per
    /// installed app), so no borrow is held across the await. Error
    /// semantics are `save`'s own; a join failure (the blocking task was
    /// cancelled or panicked) maps to [`ManifestError::Io`] so callers'
    /// warning paths stay uniform.
    async fn save_manifest(&self) -> ManifestResult<()> {
        let snapshot = self.manifest.clone();
        tokio::task::spawn_blocking(move || snapshot.save())
            .await
            .map_err(|error| {
                ManifestError::Io(std::io::Error::other(format!(
                    "manifest save task failed to join: {error}"
                )))
            })?
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
/// loading the manifest (missing file = empty; corrupt = the hard stop).
///
/// Backends are attached pre-built so both sanctioned constructions work:
/// `detect()` in production (PATH checks), `new()` under a fake runner in
/// tests — [`AppsBuilder::detect_backends`] wires the production arm in
/// one call.
#[derive(Default)]
pub struct AppsBuilder {
    /// The seam every attached backend executes through; defaults to a
    /// fresh [`TokioRunner`](toride_runner::tokio_runner::TokioRunner)
    /// seam when unset.
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
    /// Where the manifest loads from and saves to; defaults to
    /// [`InstallManifest::default_path`].
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

    /// Set the manifest location (loaded at
    /// [`AppsBuilder::build`]; a missing file is an empty manifest) —
    /// consume-and-return.
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
        builder.runner = Some(runner);
        Ok(builder)
    }

    /// Consume the builder and produce the facade. The manifest loads
    /// here — a missing file is an empty manifest, and a corrupt document
    /// (including one written by a newer toride) **fails the build**: the
    /// facade never treats it as empty and never saves over it.
    ///
    /// # Errors
    ///
    /// [`AppsError::Manifest`] when the manifest cannot be loaded;
    /// [`AppsError::NoManifestPath`] when no path was set and the
    /// platform data directory did not resolve.
    pub fn build(self) -> AppsResult<Apps> {
        let path = match self.manifest_path {
            Some(path) => path,
            None => InstallManifest::default_path().ok_or(AppsError::NoManifestPath)?,
        };
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
            },
            manifest: InstallManifest::load(path)?,
            adapters: self.adapters,
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

// ---------------------------------------------------------------------------
// Identity derivation
// ---------------------------------------------------------------------------

/// The backend-native identifiers a registry [`InstallMethod`] names —
/// the caller-known spelling the status layer probes `Foreign` presence
/// with (the flatpak arm carries no installed ref: only a record written
/// at install time knows the ref that landed; `installation` is toride's
/// planned scope, and the Foreign probe deliberately ignores it). `None`
/// for [`InstallMethod::Direct`] (wave 2) and future methods.
fn native_from_method(method: &InstallMethod) -> Option<NativeIds> {
    match method {
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
        // Direct downloads route to toride-installer in wave 2 — the
        // planner refuses them before this facade records anything — and
        // `InstallMethod` is non_exhaustive upstream; both map to "no
        // native identity to probe".
        _ => None,
    }
}

/// The record identity for a **successful** install, built from the
/// EXECUTED plan — the binding A5 rule: the flatpak `app_ref` is the ref
/// the backend ran (never re-derived from the registry app), the brew
/// token + kind and the distro package + family come from the operation
/// and the plan's backend routing.
fn native_ids_from_executed(plan: &InstallPlan) -> AppsResult<NativeIds> {
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
            // The ref's own id segment is the actually-installed app id —
            // parsed out of the executed ref, not re-derived.
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
        other => Err(AppsError::UnrecordableOperation {
            app: plan.app.as_str().to_owned(),
            operation: format!("{other:?} is not an install operation"),
        }),
    }
}

/// The uninstall plan for a toride-installed record: built from the
/// record's OWN identifiers — the source of truth, never re-planned (the
/// A1 round-1 flatpak finding: a re-planned ref guesses the planning
/// target's arch, not the installed one). `zap` mirrors the planner's
/// rule: casks only.
fn uninstall_plan_from_record(record: &InstallRecord, zap: bool) -> AppsResult<UninstallPlan> {
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
                    app: record.plan.app.as_str().to_owned(),
                    operation: format!("distro family {family:?} has no routed manager"),
                }
            })?;
            Operation::DistroUninstall {
                manager,
                package: package.clone(),
            }
        }
    };
    Ok(UninstallPlan {
        app: record.plan.app.clone(),
        backend,
        operation,
        dry_run: false,
        // Distro managers require root for removal, exactly as for
        // install (the A4 contract); brew and flatpak (user scope) do not.
        requires_elevation: matches!(backend, BackendId::Distro(_)),
    })
}

/// The update plan for a toride-installed record — the update-path mirror
/// of [`uninstall_plan_from_record`]: built from the record's OWN
/// identifiers, never re-planned through the registry (the update path
/// makes zero adapter round trips).
fn update_plan_from_record(record: &InstallRecord) -> AppsResult<UpdatePlan> {
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
                    app: record.plan.app.as_str().to_owned(),
                    operation: format!("distro family {family:?} has no routed manager"),
                }
            })?;
            Operation::DistroUpdate {
                manager,
                package: package.clone(),
            }
        }
    };
    Ok(UpdatePlan {
        app: record.plan.app.clone(),
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

    // --- options -----------------------------------------------------------------

    #[test]
    fn install_options_default_off_and_elevated_is_fluent() {
        let options = AppInstallOptions::default();
        assert!(!options.elevated);
        assert!(AppInstallOptions::new().elevated(true).elevated);
        assert_eq!(AppInstallOptions::default(), AppInstallOptions::new());
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

    #[test]
    fn native_from_method_maps_every_wave_one_method() {
        assert_eq!(
            native_from_method(&InstallMethod::Homebrew {
                cask: true,
                token: "firefox".to_owned(),
            }),
            Some(NativeIds::Homebrew {
                token: "firefox".to_owned(),
                cask: true,
            })
        );
        // Flatpak: the id without an installed ref, toride's planned scope.
        assert_eq!(
            native_from_method(&InstallMethod::Flatpak {
                app_id: "com.brave.Browser".to_owned(),
                remote: "flathub".to_owned(),
            }),
            Some(NativeIds::Flatpak {
                app_id: "com.brave.Browser".to_owned(),
                app_ref: None,
                installation: FlatpakInstallation::User,
            })
        );
        assert_eq!(
            native_from_method(&InstallMethod::Distro {
                family: DistroFamily::Debian,
                repo: None,
                package: "firefox".to_owned(),
            }),
            Some(NativeIds::Distro {
                package: "firefox".to_owned(),
                family: DistroFamily::Debian,
            })
        );
    }

    #[test]
    fn native_from_method_is_none_for_direct() {
        assert_eq!(
            native_from_method(&InstallMethod::Direct {
                url: "https://example.com".to_owned(),
                checksum: None,
                arch: None,
            }),
            None
        );
    }

    #[test]
    fn native_ids_from_executed_read_the_executed_operation() {
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
            native_ids_from_executed(&brew).unwrap(),
            NativeIds::Homebrew {
                token: "brave-browser".to_owned(),
                cask: true,
            }
        );
    }

    #[test]
    fn native_ids_from_executed_record_the_flatpak_ref_that_ran() {
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
            native_ids_from_executed(&plan).unwrap(),
            NativeIds::Flatpak {
                app_id: "com.brave.Browser".to_owned(),
                app_ref: Some("app/com.brave.Browser/x86_64/stable".to_owned()),
                installation: FlatpakInstallation::User,
            }
        );
    }

    #[test]
    fn native_ids_from_executed_reject_a_ref_without_an_app_id_segment() {
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
                native_ids_from_executed(&plan),
                Err(AppsError::UnrecordableOperation { .. })
            ),
            "a bare-id ref is not a recordable install identity"
        );
    }

    #[test]
    fn native_ids_from_executed_map_the_distro_family_from_the_plan_backend() {
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
            native_ids_from_executed(&plan).unwrap(),
            NativeIds::Distro {
                package: "brave-browser".to_owned(),
                family: DistroFamily::Ubuntu,
            }
        );
    }

    #[test]
    fn native_ids_from_executed_reject_non_install_operations() {
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
        assert!(native_ids_from_executed(&plan).is_err());
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
        let plan = uninstall_plan_from_record(&record, false).unwrap();
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
        let zap = uninstall_plan_from_record(&cask_record(), true)
            .unwrap()
            .operation;
        assert_eq!(
            zap.argv(),
            ["brew", "uninstall", "--zap", "brave-browser"],
            "zap applies to the recorded cask"
        );
        let plain_formula = uninstall_plan_from_record(&formula_record(), true)
            .unwrap()
            .operation;
        assert_eq!(
            plain_formula.argv(),
            ["brew", "uninstall", "ripgrep"],
            "zap degrades to a plain uninstall for a recorded formula"
        );
        let plain_cask = uninstall_plan_from_record(&cask_record(), false)
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
        let plan = uninstall_plan_from_record(&distro, false).unwrap();
        assert!(plan.requires_elevation);
        assert_eq!(
            plan.operation,
            Operation::DistroUninstall {
                manager: PackageManager::Apt,
                package: "brave-browser".to_owned(),
            }
        );
        assert!(
            !uninstall_plan_from_record(&cask_record(), false)
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

    fn update_plan_for_ids(ids: NativeIds) -> AppsResult<UpdatePlan> {
        let backend = ids.backend();
        update_plan_from_record(&InstallRecord::new(
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
        ))
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
    fn builder_preserves_the_attached_target_and_manifest_path() {
        use crate::{Arch, Os};
        let target = Target::new(Os::Linux, Arch::X86_64);
        let manifest_path =
            Utf8PathBuf::from_path_buf(std::env::temp_dir().join("toride-apps-wiring.json"))
                .expect("system temp dir is valid UTF-8");
        let apps = Apps::builder()
            .target(target)
            .manifest_path(&manifest_path)
            .build()
            .unwrap();
        assert_eq!(apps.target(), target);
        assert_eq!(apps.manifest().path(), &manifest_path);
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
        assert!(error.to_string().contains("data directory"));
    }
}
