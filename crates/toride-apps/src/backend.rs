//! # Backend boundary
//!
//! The [`Backend`] trait is the seam between a planned operation and one
//! install technology (homebrew, flatpak, a distro manager): every
//! technology-specific concern — binary detection, JSON list parsing, argv
//! quirks — lives behind it, in the implementing module. Callers see only
//! plan types ([`InstallPlan`], [`UninstallPlan`]), typed requests, and
//! plain outcome records.
//!
//! Contract every implementation must honor:
//!
//! - **Dry-run refusal** — a plan marked `dry_run` is never executed.
//!   This is convention, not compiler enforcement: implementations MUST
//!   call [`ensure_install_allowed`] / [`ensure_uninstall_allowed`] /
//!   [`ensure_update_allowed`] as their first statement (see
//!   [`Backend::install`]), and every backend round must carry the two
//!   refusal tests against a fake runner.
//! - **No auto-sudo** — when a plan `requires_elevation` and the request
//!   does not carry `elevated: true`, the backend returns
//!   [`Error::ElevationRequired`]; backends never invoke `sudo` themselves
//!   (enforced by the same guard call).
//! - **Seam-only execution** — all commands go through
//!   [`CommandRunner`](crate::CommandRunner); backends never spawn processes
//!   directly.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use toride_registry::DistroFamily;

use crate::error::{Error, Result};
use crate::plan::{InstallPlan, Target, UninstallPlan, UpdatePlan};

/// Identifies the install technology a plan routes to. One variant per
/// backend family; distro managers are keyed by their family so the id
/// carries the manager choice (Debian/Ubuntu → apt, Fedora → dnf, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum BackendId {
    /// macOS Homebrew — casks and formulae (`brew`).
    Homebrew,
    /// Linux Flatpak — remotes and refs (`flatpak`).
    Flatpak,
    /// A distro's native package manager, selected by family (`apt`, `dnf`,
    /// `pacman`, `apk`).
    Distro(DistroFamily),
}

impl std::fmt::Display for BackendId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Homebrew => f.write_str("homebrew"),
            Self::Flatpak => f.write_str("flatpak"),
            // Families render lowercase (`distro-debian`); the wildcard keeps
            // future families displayable without touching this crate.
            Self::Distro(family) => {
                let slug = format!("distro-{family:?}").to_ascii_lowercase();
                f.write_str(&slug)
            }
        }
    }
}

/// Typed install request handed to [`Backend::install`].
#[derive(Debug, Clone, Copy)]
pub struct InstallRequest<'a> {
    /// The plan to execute. Its `dry_run` and `requires_elevation` slots are
    /// binding contracts (see the module docs).
    pub plan: &'a InstallPlan,
    /// Host target the plan was derived for — context for backend decisions
    /// beyond the plan's argv (e.g. picking a user vs system scope).
    pub target: &'a Target,
    /// Elevation grant: `true` only when the caller has arranged root
    /// privileges for this operation. Backends must not acquire elevation
    /// themselves; a `requires_elevation` plan without this grant is refused
    /// with [`Error::ElevationRequired`].
    pub elevated: bool,
}

impl<'a> InstallRequest<'a> {
    /// Create a request for `plan` on `target` without an elevation grant.
    #[must_use]
    pub const fn new(plan: &'a InstallPlan, target: &'a Target) -> Self {
        Self {
            plan,
            target,
            elevated: false,
        }
    }

    /// Assert that elevation has been arranged for this request.
    #[must_use]
    pub const fn elevated(mut self, elevated: bool) -> Self {
        self.elevated = elevated;
        self
    }
}

/// Typed uninstall request handed to [`Backend::uninstall`].
#[derive(Debug, Clone, Copy)]
pub struct UninstallRequest<'a> {
    /// The plan to execute. Its `dry_run` and `requires_elevation` slots are
    /// binding contracts (see the module docs).
    pub plan: &'a UninstallPlan,
    /// Host target the plan was derived for.
    pub target: &'a Target,
    /// Elevation grant — see [`InstallRequest::elevated`].
    pub elevated: bool,
}

impl<'a> UninstallRequest<'a> {
    /// Create a request for `plan` on `target` without an elevation grant.
    #[must_use]
    pub const fn new(plan: &'a UninstallPlan, target: &'a Target) -> Self {
        Self {
            plan,
            target,
            elevated: false,
        }
    }

    /// Assert that elevation has been arranged — consume-and-return.
    #[must_use]
    pub const fn elevated(mut self, elevated: bool) -> Self {
        self.elevated = elevated;
        self
    }
}

/// Typed update request handed to [`Backend::update`].
#[derive(Debug, Clone, Copy)]
pub struct UpdateRequest<'a> {
    /// The plan to execute. Its `dry_run` and `requires_elevation` slots
    /// are binding contracts (see the module docs).
    pub plan: &'a UpdatePlan,
    /// Host target the plan was derived for.
    pub target: &'a Target,
    /// Elevation grant — see [`InstallRequest::elevated`].
    pub elevated: bool,
}

impl<'a> UpdateRequest<'a> {
    /// Create a request for `plan` on `target` without an elevation grant.
    #[must_use]
    pub const fn new(plan: &'a UpdatePlan, target: &'a Target) -> Self {
        Self {
            plan,
            target,
            elevated: false,
        }
    }

    /// Assert that elevation has been arranged — consume-and-return.
    #[must_use]
    pub const fn elevated(mut self, elevated: bool) -> Self {
        self.elevated = elevated;
        self
    }
}

/// Query for [`Backend::list_installed`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListQuery {
    /// Restrict the listing to these backend-native identifiers (cask
    /// tokens, flatpak refs, package names). Empty lists everything the
    /// backend manages. Backends may implement the restriction by listing
    /// and filtering — the semantics, not the mechanism, are the contract.
    pub ids: Vec<String>,
}

impl ListQuery {
    /// Query that lists everything the backend manages.
    #[must_use]
    pub fn all() -> Self {
        Self::default()
    }

    /// Query restricted to one backend-native identifier.
    #[must_use]
    pub fn id(id: impl Into<String>) -> Self {
        Self {
            ids: vec![id.into()],
        }
    }
}

/// Query for [`Backend::status`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusQuery<'a> {
    /// Backend-native identifier to look up (cask token, flatpak ref,
    /// package name).
    pub id: &'a str,
}

impl<'a> StatusQuery<'a> {
    /// Look up one backend-native identifier.
    #[must_use]
    pub const fn new(id: &'a str) -> Self {
        Self { id }
    }
}

/// One app a backend currently manages, as its `list_installed` reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledApp {
    /// Backend-native identifier (cask token, flatpak ref, package name) —
    /// the join key against plan operations and manifest records.
    pub id: String,
    /// Installed version, when the backend's listing reports one.
    pub version: Option<String>,
}

/// Opaque newtype over the manager's native version spelling — a wrapped
/// string, not semver, because distro and flatpak versions are not
/// semver-ordered; ordering questions go to the manager's stale signal.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Version(String);

impl Version {
    /// Wrap the manager's native version spelling verbatim.
    #[must_use]
    pub fn new(version: impl Into<String>) -> Self {
        Self(version.into())
    }

    /// The wrapped native spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// One stale item the backend's manager reports (brew's `outdated`
/// entries; managers with no such probe report none).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutdatedEntry {
    /// Backend-native identifier — the join key against manifest records.
    pub id: String,
    /// All installed (stale) versions.
    pub installed_versions: Vec<String>,
    /// The version the manager would move to, when reported.
    pub current_version: Option<String>,
    /// Whether the manager is holding the item back (brew pins).
    pub pinned: bool,
}

/// Per-backend status of one app id — the primitive the cross-backend
/// status layer (A5) combines with the manifest into `Installed` /
/// `Foreign` / `NotInstalled`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackendStatus {
    /// The backend manages the id, at this version when known.
    Installed {
        /// Version the backend reports, when it reports one.
        version: Option<String>,
    },
    /// The backend does not manage the id.
    NotInstalled,
}

/// Outcome of a successful install.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallOutcome {
    /// Version the backend observed after installing, when it can report
    /// one (used by the facade's post-verify and the manifest record).
    pub version: Option<String>,
    /// Human-readable summary of what happened (`"installed cask
    /// firefox"`).
    pub detail: String,
}

/// Outcome of a successful uninstall.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UninstallOutcome {
    /// Human-readable summary of what happened (`"removed package
    /// firefox"`).
    pub detail: String,
}

/// One install technology executing planned operations.
///
/// Implementations live behind this seam with all their technology-specific
/// knowledge (binary detection, JSON shapes, argv quirks). The trait's
/// mutating operations take typed requests (never raw strings) and return
/// plain records; see the [module docs](self) for the dry-run and elevation
/// contracts every implementation must honor.
#[async_trait]
pub trait Backend: Send + Sync {
    /// Stable identity of this backend — matches the routing slot on plan
    /// types (`InstallPlan::backend`).
    fn id(&self) -> BackendId;

    /// Coarse applicability probe: can this backend operate on the host
    /// `target` at all (e.g. homebrew on macOS or Linux, flatpak on Linux)?
    /// Finer-grained rules (a cask needing macOS, a distro family match)
    /// live in the planner, which refuses to route inapplicable methods
    /// before a backend is ever selected.
    fn supports(&self, target: &Target) -> bool;

    /// Execute an install plan.
    ///
    /// **Binding convention on every implementation:** the first statement
    /// of an implementation MUST be
    /// `ensure_install_allowed(&request)?` — the trait cannot enforce this
    /// structurally, so the shared guard is how dry-run refusal and
    /// no-auto-sudo stay uniform across backends. Review rounds verify each
    /// backend by testing both refusals against a fake runner.
    ///
    /// # Errors
    ///
    /// [`Error::DryRun`] when the plan is marked dry-run;
    /// [`Error::ElevationRequired`] when the plan needs root and the request
    /// carries no elevation grant; [`Error::Command`] when the manager
    /// command fails.
    async fn install(&self, request: InstallRequest<'_>) -> Result<InstallOutcome>;

    /// Execute an uninstall plan.
    ///
    /// **Binding convention on every implementation:** the first statement
    /// of an implementation MUST be
    /// `ensure_uninstall_allowed(&request)?` — same rationale as
    /// [`Backend::install`].
    ///
    /// # Errors
    ///
    /// Same contract as [`Backend::install`].
    async fn uninstall(&self, request: UninstallRequest<'_>) -> Result<UninstallOutcome>;

    /// List the apps this backend manages on the host.
    ///
    /// # Errors
    ///
    /// [`Error::Command`] when the manager's listing command fails or its
    /// output cannot be parsed.
    async fn list_installed(&self, query: ListQuery) -> Result<Vec<InstalledApp>>;

    /// Report the status of one backend-native id.
    ///
    /// The default derives the answer from [`Backend::list_installed`]
    /// (restricted to the queried id); implementations with a cheaper
    /// direct probe override it.
    ///
    /// # Errors
    ///
    /// [`Error::Command`] when the underlying listing fails.
    async fn status(&self, query: StatusQuery<'_>) -> Result<BackendStatus> {
        let apps = self
            .list_installed(ListQuery::id(query.id))
            .await?
            .into_iter()
            .find(|app| app.id == query.id);
        Ok(match apps {
            Some(InstalledApp { version, .. }) => BackendStatus::Installed { version },
            None => BackendStatus::NotInstalled,
        })
    }

    /// Execute an update plan.
    ///
    /// **Binding convention on every implementation:** the first statement
    /// of an implementation MUST be `ensure_update_allowed(&request)?` —
    /// same rationale as [`Backend::install`].
    ///
    /// # Errors
    ///
    /// Same contract as [`Backend::install`].
    async fn update(&self, request: UpdateRequest<'_>) -> Result<()>;

    /// Report every stale item this backend's manager flags. Backends
    /// whose manager has no such probe keep the default: none reported.
    ///
    /// # Errors
    ///
    /// [`Error::Command`] when the manager's stale probe fails or its
    /// output cannot be parsed.
    async fn outdated(&self) -> Result<Vec<OutdatedEntry>> {
        Ok(Vec::new())
    }

    /// The version the manager would install for `id` today; `Ok(None)` is
    /// *unknown*, never "up to date". The default derives from
    /// [`Backend::status`]; backends with a direct availability probe
    /// override it.
    ///
    /// # Errors
    ///
    /// [`Error::Command`] when the underlying listing fails.
    async fn installed_version(&self, id: &str) -> Result<Option<Version>> {
        Ok(match self.status(StatusQuery::new(id)).await? {
            BackendStatus::Installed { version } => version.map(Version::new),
            BackendStatus::NotInstalled => None,
        })
    }

    /// The version the manager currently offers for `id`; `Ok(None)` is
    /// *unknown*, never "up to date".
    ///
    /// # Errors
    ///
    /// [`Error::Command`] when the backend's availability probe fails.
    async fn available_version(&self, _id: &str) -> Result<Option<Version>> {
        Ok(None)
    }
}

/// Shared precondition check every [`Backend::install`] implementation must
/// run before mutating anything: refuse dry-run plans, then refuse
/// elevation-requiring plans without a grant. Public so out-of-crate
/// implementors honor the same contract as the built-in backends.
///
/// # Errors
///
/// [`Error::DryRun`] / [`Error::ElevationRequired`] per the module-level
/// contract.
pub fn ensure_install_allowed(request: &InstallRequest<'_>) -> Result<()> {
    ensure_execution_allowed(
        request.plan.dry_run,
        request.plan.requires_elevation,
        request.elevated,
        request.plan.backend,
        "install",
        &request.plan.app,
    )
}

/// Shared precondition check every [`Backend::uninstall`] implementation
/// must run before mutating anything — same contract as
/// [`ensure_install_allowed`].
///
/// # Errors
///
/// [`Error::DryRun`] / [`Error::ElevationRequired`] per the module-level
/// contract.
pub fn ensure_uninstall_allowed(request: &UninstallRequest<'_>) -> Result<()> {
    ensure_execution_allowed(
        request.plan.dry_run,
        request.plan.requires_elevation,
        request.elevated,
        request.plan.backend,
        "uninstall",
        &request.plan.app,
    )
}

/// Shared precondition check every [`Backend::update`] implementation must
/// run before mutating anything — same contract as
/// [`ensure_install_allowed`].
///
/// # Errors
///
/// [`Error::DryRun`] / [`Error::ElevationRequired`] per the module-level
/// contract.
pub fn ensure_update_allowed(request: &UpdateRequest<'_>) -> Result<()> {
    ensure_execution_allowed(
        request.plan.dry_run,
        request.plan.requires_elevation,
        request.elevated,
        request.plan.backend,
        "update",
        &request.plan.app,
    )
}

/// The common guard behind both precondition checks.
fn ensure_execution_allowed(
    dry_run: bool,
    requires_elevation: bool,
    elevated: bool,
    backend: BackendId,
    operation: &'static str,
    app: &toride_registry::TorideId,
) -> Result<()> {
    if dry_run {
        return Err(Error::DryRun {
            app: app.as_str().to_owned(),
        });
    }
    if requires_elevation && !elevated {
        return Err(Error::ElevationRequired { backend, operation });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{Operation, UninstallOptions, UpdatePlan, plan_install, plan_uninstall};
    use crate::runner::CommandRunner;
    use std::sync::Arc;
    use toride_registry::{App, Arch, DistroFamily, InstallMethod, Os, TorideId};
    use toride_runner::fake::FakeRunner;

    /// Minimal real backend proving the trait is implementable and object
    /// safe: runs the plan's canonical argv through the seam after the
    /// shared guards, lists from a canned table.
    struct ProbeBackend {
        runner: CommandRunner,
        installed: Vec<InstalledApp>,
    }

    impl ProbeBackend {
        fn new(runner: CommandRunner, installed: Vec<InstalledApp>) -> Self {
            Self { runner, installed }
        }
    }

    #[async_trait]
    impl Backend for ProbeBackend {
        fn id(&self) -> BackendId {
            BackendId::Homebrew
        }

        fn supports(&self, target: &Target) -> bool {
            matches!(target.os, Os::MacOs | Os::Linux)
        }

        async fn install(&self, request: InstallRequest<'_>) -> Result<InstallOutcome> {
            ensure_install_allowed(&request)?;
            self.runner
                .run_checked(request.plan.operation.command_spec())
                .await?;
            Ok(InstallOutcome {
                version: None,
                detail: format!("installed via {}", self.id()),
            })
        }

        async fn uninstall(&self, request: UninstallRequest<'_>) -> Result<UninstallOutcome> {
            ensure_uninstall_allowed(&request)?;
            Ok(UninstallOutcome {
                detail: format!("uninstalled via {}", self.id()),
            })
        }

        async fn update(&self, request: UpdateRequest<'_>) -> Result<()> {
            ensure_update_allowed(&request)?;
            self.runner
                .run_checked(request.plan.operation.command_spec())
                .await?;
            Ok(())
        }

        async fn list_installed(&self, query: ListQuery) -> Result<Vec<InstalledApp>> {
            Ok(self
                .installed
                .iter()
                .filter(|app| query.ids.is_empty() || query.ids.contains(&app.id))
                .cloned()
                .collect())
        }
    }

    /// A registry `App` fixture with the given install method and no
    /// platform claims (claim check skipped).
    fn app_with(method: InstallMethod) -> App {
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

    fn linux_target() -> Target {
        Target::new(Os::Linux, Arch::X86_64).with_distro(DistroFamily::Debian)
    }

    #[tokio::test]
    async fn install_refuses_dry_run_plans_without_touching_the_runner() {
        let runner = CommandRunner::builder()
            .runner(Arc::new(FakeRunner::new().strict()))
            .build();
        let backend = ProbeBackend::new(runner, Vec::new());
        let app = app_with(InstallMethod::Distro {
            family: DistroFamily::Debian,
            repo: None,
            package: "probe".to_owned(),
        });
        let plan = plan_install(&app, &linux_target()).unwrap().dry_run(true);
        let target = linux_target();
        let error = backend
            .install(InstallRequest::new(&plan, &target))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::DryRun { .. }), "{error:?}");
    }

    #[tokio::test]
    async fn install_refuses_elevation_requiring_plans_without_a_grant() {
        let runner = CommandRunner::builder()
            .runner(Arc::new(FakeRunner::new().strict()))
            .build();
        let backend = ProbeBackend::new(runner, Vec::new());
        let app = app_with(InstallMethod::Distro {
            family: DistroFamily::Debian,
            repo: None,
            package: "probe".to_owned(),
        });
        let plan = plan_install(&app, &linux_target()).unwrap();
        assert!(plan.requires_elevation);
        let target = linux_target();
        let error = backend
            .install(InstallRequest::new(&plan, &target))
            .await
            .unwrap_err();
        assert!(
            matches!(error, Error::ElevationRequired { .. }),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn install_executes_the_planned_argv_when_preconditions_hold() {
        let spec = crate::runner::command("apt", ["install", "probe"]);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::from_stdout("ok"),
        );
        let runner = CommandRunner::builder()
            .runner(Arc::new(fake.clone()))
            .build();
        let backend = ProbeBackend::new(runner, Vec::new());
        let app = app_with(InstallMethod::Distro {
            family: DistroFamily::Debian,
            repo: None,
            package: "probe".to_owned(),
        });
        let plan = plan_install(&app, &linux_target()).unwrap();
        let target = linux_target();
        backend
            .install(InstallRequest::new(&plan, &target).elevated(true))
            .await
            .unwrap();
        // The load-bearing assertion: the planned argv reached the seam.
        // (No assert on the fake's own `detail` string — that would only
        // test the fake against itself.)
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn uninstall_refuses_elevation_requiring_plans_without_a_grant() {
        let backend = ProbeBackend::new(
            CommandRunner::builder()
                .runner(Arc::new(FakeRunner::new().strict()))
                .build(),
            Vec::new(),
        );
        let app = app_with(InstallMethod::Distro {
            family: DistroFamily::Debian,
            repo: None,
            package: "probe".to_owned(),
        });
        let plan = plan_uninstall(&app, &linux_target(), &UninstallOptions::default()).unwrap();
        let target = linux_target();
        let error = backend
            .uninstall(UninstallRequest::new(&plan, &target))
            .await
            .unwrap_err();
        assert!(
            matches!(error, Error::ElevationRequired { .. }),
            "{error:?}"
        );
    }

    fn apt_update_plan(dry_run: bool) -> UpdatePlan {
        UpdatePlan {
            app: TorideId::slugify("probe-app"),
            backend: BackendId::Distro(DistroFamily::Debian),
            operation: Operation::DistroUpdate {
                manager: crate::plan::PackageManager::Apt,
                package: "probe".to_owned(),
            },
            dry_run,
            requires_elevation: true,
        }
    }

    #[tokio::test]
    async fn update_refuses_dry_run_plans_without_touching_the_runner() {
        let runner = CommandRunner::builder()
            .runner(Arc::new(FakeRunner::new().strict()))
            .build();
        let backend = ProbeBackend::new(runner, Vec::new());
        let plan = apt_update_plan(true);
        let target = linux_target();
        let error = backend
            .update(UpdateRequest::new(&plan, &target).elevated(true))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::DryRun { .. }), "{error:?}");
    }

    #[tokio::test]
    async fn update_refuses_elevation_requiring_plans_without_a_grant() {
        let runner = CommandRunner::builder()
            .runner(Arc::new(FakeRunner::new().strict()))
            .build();
        let backend = ProbeBackend::new(runner, Vec::new());
        let plan = apt_update_plan(false);
        let target = linux_target();
        let error = backend
            .update(UpdateRequest::new(&plan, &target))
            .await
            .unwrap_err();
        assert!(
            matches!(error, Error::ElevationRequired { .. }),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn update_executes_the_planned_argv_when_preconditions_hold() {
        let spec = crate::runner::command("apt", ["install", "--only-upgrade", "probe"]);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::from_stdout("ok"),
        );
        let runner = CommandRunner::builder()
            .runner(Arc::new(fake.clone()))
            .build();
        let backend = ProbeBackend::new(runner, Vec::new());
        let plan = apt_update_plan(false);
        let target = linux_target();
        backend
            .update(UpdateRequest::new(&plan, &target).elevated(true))
            .await
            .unwrap();
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn default_status_derives_installed_from_the_listing() {
        let backend = ProbeBackend::new(
            CommandRunner::builder()
                .runner(Arc::new(FakeRunner::new().strict()))
                .build(),
            vec![
                InstalledApp {
                    id: "firefox".to_owned(),
                    version: Some("138.0".to_owned()),
                },
                InstalledApp {
                    id: "ripgrep".to_owned(),
                    version: None,
                },
            ],
        );
        let status = backend.status(StatusQuery::new("firefox")).await.unwrap();
        assert_eq!(
            status,
            BackendStatus::Installed {
                version: Some("138.0".to_owned())
            }
        );
    }

    #[tokio::test]
    async fn default_status_derives_not_installed_for_unknown_ids() {
        let backend = ProbeBackend::new(
            CommandRunner::builder()
                .runner(Arc::new(FakeRunner::new().strict()))
                .build(),
            vec![InstalledApp {
                id: "firefox".to_owned(),
                version: None,
            }],
        );
        let status = backend.status(StatusQuery::new("nope")).await.unwrap();
        assert_eq!(status, BackendStatus::NotInstalled);
    }

    #[tokio::test]
    async fn default_installed_version_derives_from_the_listing() {
        let backend = ProbeBackend::new(
            CommandRunner::builder()
                .runner(Arc::new(FakeRunner::new().strict()))
                .build(),
            vec![InstalledApp {
                id: "firefox".to_owned(),
                version: Some("138.0".to_owned()),
            }],
        );
        assert_eq!(
            backend.installed_version("firefox").await.unwrap(),
            Some(Version::new("138.0"))
        );
        assert_eq!(backend.installed_version("nope").await.unwrap(), None);
    }

    #[tokio::test]
    async fn default_outdated_and_available_version_report_nothing() {
        let backend = ProbeBackend::new(
            CommandRunner::builder()
                .runner(Arc::new(FakeRunner::new().strict()))
                .build(),
            Vec::new(),
        );
        assert!(backend.outdated().await.unwrap().is_empty());
        assert_eq!(backend.available_version("firefox").await.unwrap(), None);
    }

    #[test]
    fn version_wraps_displays_and_round_trips_as_a_bare_string() {
        let version = Version::new("1:9.20.23-1~deb13u1");
        assert_eq!(version.as_str(), "1:9.20.23-1~deb13u1");
        assert_eq!(version.to_string(), "1:9.20.23-1~deb13u1");
        assert_eq!(version, Version::new("1:9.20.23-1~deb13u1"));
        let json = serde_json::to_string(&version).unwrap();
        assert_eq!(json, r#""1:9.20.23-1~deb13u1""#);
    }

    #[tokio::test]
    async fn trait_is_object_safe_behind_a_box() {
        let backend: Box<dyn Backend> = Box::new(ProbeBackend::new(
            CommandRunner::builder()
                .runner(Arc::new(FakeRunner::new().strict()))
                .build(),
            Vec::new(),
        ));
        assert_eq!(backend.id(), BackendId::Homebrew);
        assert!(backend.supports(&linux_target()));
    }

    #[test]
    fn backend_id_displays_stable_lowercase_slugs() {
        assert_eq!(BackendId::Homebrew.to_string(), "homebrew");
        assert_eq!(BackendId::Flatpak.to_string(), "flatpak");
        assert_eq!(
            BackendId::Distro(DistroFamily::Debian).to_string(),
            "distro-debian"
        );
    }
}
