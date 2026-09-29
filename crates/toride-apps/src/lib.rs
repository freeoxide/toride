//! # toride-apps
//!
//! The app install/uninstall **execution** layer: it consumes the normalized
//! [`App`](toride_registry::App) model from `toride-registry` (which
//! deliberately stops at *describing* what to run) and turns each
//! [`InstallMethod`] into a concrete, backend-routed operation that is
//! actually executed on the host — closing the gap the registry crate
//! documents as out of scope.
//!
//! ## Design
//!
//! The crate is split into:
//!
//! - a pure **planner** ([`plan_install`], [`plan_uninstall`], carried types
//!   [`InstallPlan`], [`UninstallPlan`], [`Operation`]) that derives exact
//!   manager argv from a registry `App` plus a host [`Target`] — no I/O, no
//!   clock, no processes, fully fixture-testable;
//! - the [`Backend`] trait — the contract one install technology (homebrew,
//!   flatpak, a distro manager) implements: install, uninstall,
//!   `list_installed`, status, plus an applicability probe;
//! - a thin **runner seam** ([`CommandRunner`]) over
//!   `toride_runner::AsyncRunner` so every backend command is constructed and
//!   executed through one injectable, fake-able choke point — backends never
//!   spawn processes directly;
//! - the [`Apps`] **facade** composing all of the above with the install
//!   manifest and the registry adapters into the user-facing operations
//!   (ensure-installed, uninstall, status, search).
//!
//! ## Pipeline
//!
//! 1. **Resolve** — the [`Apps`] facade resolves the [`TorideId`] through
//!    the registered registry adapters (each asked to look up the slug
//!    under its own source kind; the first hit wins), yielding a
//!    normalized registry `App`. (`status` short-circuits this: a manifest
//!    record is answered from local state alone.)
//! 2. **Plan** — [`plan_install`] / [`plan_uninstall`] match the app's
//!    [`InstallMethod`] against the host [`Target`], check platform claims
//!    (empty claims are skipped, per the model's contract), refuse disabled
//!    apps, and produce a plan naming the concrete [`BackendId`], the exact
//!    [`Operation`] argv, a `dry_run` slot, and — for distro managers — an
//!    explicit `requires_elevation` requirement (toride never auto-sudoes).
//! 3. **Route** — the plan's backend id selects the [`Backend`] impl that
//!    executes it.
//! 4. **Execute** — the backend runs the operation's commands through the
//!    shared [`CommandRunner`] seam, honoring the plan's `dry_run` and
//!    elevation requirements.
//! 5. **Record & verify** — post-install state is recorded and re-queried
//!    (manifest + status layers, built on top of this crate's
//!    [`Backend::list_installed`] / [`Backend::status`]).
//!
//! ## Quick start
//!
//! The [`Apps`] facade is the front door: registry adapters in, executed
//! operations out, every mutation recorded in the install manifest. This
//! example runs offline (no adapters, no backends attached) and still
//! exercises the real pipeline — a full build calls `.adapter(...)` per
//! registry source and `.detect_backends()` to wire whatever this host has:
//!
//! ```
//! use toride_apps::{AppInstallOptions, AppStatus, Apps, AppsError};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), AppsError> {
//! // A scratch manifest for the example; a real CLI drops the override
//! // and uses the default data-dir location.
//! let scratch = std::env::temp_dir()
//!     .join(format!("toride-apps-quickstart-{}.json", std::process::id()));
//! let manifest_path = scratch
//!     .to_str()
//! .ok_or(AppsError::NoManifestPath)?
//!     .to_owned();
//!
//! let id = toride_registry::TorideId::slugify("firefox");
//! let mut apps = Apps::builder().manifest_path(manifest_path.as_str()).build()?;
//!
//! // status() is manifest-first: no record, no adapters, no backends —
//! // an honest NotInstalled, with nothing executed to learn it.
//! assert_eq!(apps.status(&id).await?, AppStatus::NotInstalled);
//!
//! // ensure_installed() resolves through the registered adapters; with
//! // none registered, the id is Unresolved — never guessed at.
//! assert!(matches!(
//!     apps.ensure_installed(&id, AppInstallOptions::new()).await,
//!     Err(AppsError::Unresolved { .. })
//! ));
//! # Ok(())
//! # }
//! ```
//!
//! ## `InstallMethod` coverage (wave 1)
//!
//! - [`InstallMethod::Homebrew`] → [`Operation::BrewInstall`] /
//!   [`Operation::BrewUninstall`] (`--cask` vs plain token, `--zap` on
//!   request)
//! - [`InstallMethod::Flatpak`] → [`Operation::FlatpakInstall`] (remote +
//!   derived `app/<id>/<arch>/stable` ref + user installation) /
//!   [`Operation::FlatpakUninstall`] (bare app id flatpak resolves against
//!   installed refs + user installation)
//! - [`InstallMethod::Distro`] → [`Operation::DistroInstall`] /
//!   [`Operation::DistroUninstall`] with the family's manager verbs (apt,
//!   dnf, pacman, apk) and a mandatory elevation requirement
//! - [`InstallMethod::Direct`] is not yet executed here (wave 2: route it to
//!   `toride-installer`); the planner reports
//!   [`Error::UnsupportedMethod`] for it today.

#![deny(unsafe_code)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::return_self_not_must_use)]

pub mod apps;
pub mod backend;
pub mod backends;
pub mod error;
pub mod manifest;
pub mod plan;
pub mod runner;
pub mod status;

// Re-exports — the public API surface.
pub use apps::{
    AppInstallOptions, AppUninstallOptions, Apps, AppsBuilder, AppsError, AppsResult,
    EnsureAppOutcome, UninstallAppOutcome,
};
pub use backend::{
    Backend, BackendId, BackendStatus, InstallOutcome, InstallRequest, InstalledApp, ListQuery,
    StatusQuery, UninstallOutcome, UninstallRequest,
};
pub use error::{Error, Result};
pub use manifest::{InstallManifest, InstallRecord, ManifestError, ManifestResult, NativeIds};
pub use plan::{
    FlatpakInstallation, InstallPlan, Operation, PackageManager, Target, UninstallOptions,
    UninstallPlan, plan_install, plan_uninstall,
};
pub use runner::{CommandRunner, CommandRunnerBuilder, command};
pub use status::{AppStatus, BackendSet, app_status};

// Re-exported host-side contract types callers need beside the planner.
pub use toride_registry::{Arch, DistroFamily, InstallMethod, Os, TorideId};
