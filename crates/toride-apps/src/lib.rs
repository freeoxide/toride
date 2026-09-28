//! # toride-apps
//!
//! The app install/uninstall **execution** layer: it consumes the normalized
//! [`App`] model from `toride-registry` (which deliberately stops at
//! *describing* what to run) and turns each [`InstallMethod`] into a concrete,
//! backend-routed operation that is actually executed on the host — closing
//! the gap the registry crate documents as out of scope.
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
//!   spawn processes directly.
//!
//! ## Pipeline
//!
//! 1. **Resolve** — the caller resolves a [`TorideId`] to a registry `App`
//!    (the registry crate's job, not ours).
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
//! ```rust,ignore
//! use toride_apps::{plan_install, Target};
//! use toride_registry::{Arch, InstallMethod, Os, TorideId};
//!
//! # async fn run(app: toride_registry::App) -> toride_apps::Result<()> {
//! // Host: Linux x86_64 on a Debian-family distro.
//! let target = Target::new(Os::Linux, Arch::X86_64).with_distro(
//!     toride_registry::DistroFamily::Debian,
//! );
//!
//! // Pure planning: exact argv, no I/O.
//! let plan = plan_install(&app, &target)?;
//! assert_eq!(plan.operation.argv(), ["apt", "install", "firefox"]);
//! assert!(plan.requires_elevation); // never auto-sudoed
//!
//! // Execution: hand the plan to the routed backend through the seam.
//! let runner = toride_apps::CommandRunner::builder().build();
//! // let backend = ...; // A2+ wire the homebrew/flatpak/distro backends
//! # let _ = (runner, plan);
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

pub mod backend;
pub mod backends;
pub mod error;
pub mod plan;
pub mod runner;

// Re-exports — the public API surface.
pub use backend::{
    Backend, BackendId, BackendStatus, InstallOutcome, InstallRequest, InstalledApp, ListQuery,
    StatusQuery, UninstallOutcome, UninstallRequest,
};
pub use error::{Error, Result};
pub use plan::{
    FlatpakInstallation, InstallPlan, Operation, PackageManager, Target, UninstallOptions,
    UninstallPlan, plan_install, plan_uninstall,
};
pub use runner::{CommandRunner, CommandRunnerBuilder, command};

// Re-exported host-side contract types callers need beside the planner.
pub use toride_registry::{Arch, DistroFamily, InstallMethod, Os, TorideId};
