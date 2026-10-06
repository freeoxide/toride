//! # Adapter boundary
//!
//! The [`Adapter`] trait is the seam between the external world and the
//! normalized model (DESIGN.md §3): every source-specific concern — wire
//! structs, endpoints, quirk handling, fetch clients — lives behind it, in
//! the per-source modules under [`sources`](crate::sources). Callers see
//! only [`App`] and [`SourceRef`].
//!
//! House async style (`#[async_trait::async_trait]` + `Send + Sync`,
//! like toride-installer's `ReleaseResolver`); [`Registry`] (DESIGN.md
//! §3.3) is the search/resolve/lifecycle-plan facade over the adapters.

use std::sync::{Arc, Mutex, PoisonError};

use crate::alias::{self, AliasIndex};
use crate::error::{Error, Result, SourceFailure};
use crate::model::{
    App, Checksum, DistroFamily, InstallMethod, Os, Platform, SourceKind, SourceRef,
};

/// Normalizes one external repository into [`App`]s.
///
/// Contract: ALL source-specific knowledge lives in the implementing
/// module — wire structs, endpoints, quirk handling. Callers see only
/// `App` and [`SourceRef`]. Each adapter additionally keeps its parse and
/// fetch halves strictly separated (DESIGN.md §3.1): only the fetch half
/// touches the network; only the parse half is fixture-tested offline.
#[allow(clippy::double_must_use)]
#[async_trait::async_trait]
pub trait Adapter: Send + Sync {
    /// Which source this adapter normalizes.
    fn source(&self) -> SourceKind;

    /// Look up one app by its source-native id (cask token, formula
    /// name, flatpak app id, distro package + repo). `Ok(None)` = the
    /// source has no such entry.
    ///
    /// # Errors
    ///
    /// Transport or payload-parse failures
    /// ([`Error::Http`], [`Error::Parse`]).
    async fn lookup(&self, id: &SourceRef) -> Result<Option<App>>;

    /// Free-text search. Returns normalized stubs — enough for a result
    /// list (`id`, `name`, `summary`, `install`, `platforms`); heavy
    /// fields (`artifacts`, full `description`) may require
    /// [`Adapter::lookup`].
    ///
    /// # Errors
    ///
    /// Transport or payload-parse failures
    /// ([`Error::Http`], [`Error::Parse`]).
    async fn search(&self, query: &str) -> Result<Vec<App>>;
}

/// The registry facade: search, resolve, and plan over every registered
/// [`Adapter`] (DESIGN.md §3.3). Build one with
/// [`Registry::builder`] or [`Registry::new`].
pub struct Registry {
    adapters: Vec<Arc<dyn Adapter>>,
    aliases: Mutex<AliasIndex>,
}

/// The result of a [`Registry::search`] fan-out: every surviving source's
/// hits plus one row per source that failed.
#[derive(Debug)]
pub struct SearchOutcome {
    /// Hits from every adapter that answered, in registration order.
    pub apps: Vec<App>,
    /// One entry per adapter whose search failed, in registration order.
    pub failures: Vec<SourceFailure>,
}

/// Builds a [`Registry`] — consume-and-return adapter registration.
#[derive(Default)]
pub struct RegistryBuilder {
    adapters: Vec<Arc<dyn Adapter>>,
    aliases: AliasIndex,
}

impl RegistryBuilder {
    /// A builder with no adapters registered.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register one adapter (an owned `Arc` or `Box`; a box is converted)
    /// — consume-and-return.
    #[must_use]
    pub fn with_adapter(mut self, adapter: impl Into<Arc<dyn Adapter>>) -> Self {
        self.adapters.push(adapter.into());
        self
    }

    /// Preload a persisted [`AliasIndex`] (DESIGN.md §5's JSON cache) so
    /// resolve can answer ids no primary lookup knows.
    #[must_use]
    pub fn with_alias_index(mut self, index: AliasIndex) -> Self {
        self.aliases = index;
        self
    }

    /// Consume the builder and produce the facade.
    #[must_use]
    pub fn build(self) -> Registry {
        Registry {
            adapters: self.adapters,
            aliases: Mutex::new(self.aliases),
        }
    }
}

impl Registry {
    /// A facade over `adapters` (each an owned `Arc` or `Box`), starting
    /// from an empty [`AliasIndex`].
    #[must_use]
    pub fn new(adapters: impl IntoIterator<Item = impl Into<Arc<dyn Adapter>>>) -> Self {
        Self {
            adapters: adapters.into_iter().map(Into::into).collect(),
            aliases: Mutex::new(AliasIndex::new()),
        }
    }

    /// Start building a facade — see [`RegistryBuilder`].
    #[must_use]
    pub fn builder() -> RegistryBuilder {
        RegistryBuilder::new()
    }

    /// The registered adapters, in registration order.
    #[must_use]
    pub fn adapters(&self) -> &[Arc<dyn Adapter>] {
        &self.adapters
    }

    /// A snapshot of the alias index as it stands — every search-merged
    /// row and resolve hit recorded so far, plus anything preloaded
    /// through [`RegistryBuilder::with_alias_index`].
    #[must_use]
    pub fn alias_index(&self) -> AliasIndex {
        self.locked_aliases().clone()
    }

    /// Fan `query` out to every adapter; failures land in
    /// [`SearchOutcome::failures`], same-app hits across adapters merge
    /// into one row. Errors: [`Error::AllSourcesFailed`] on total failure.
    pub async fn search(&self, query: &str) -> Result<SearchOutcome> {
        let mut buckets: Vec<Vec<App>> = Vec::new();
        let mut failures = Vec::new();
        for adapter in &self.adapters {
            match adapter.search(query).await {
                Ok(hits) => buckets.push(hits),
                Err(error) => failures.push(SourceFailure {
                    source: adapter.source(),
                    error,
                }),
            }
        }
        let failures = all_failed(self.adapters.len(), query.to_owned(), failures)?;
        let apps = alias::merge_hits(buckets);
        self.record_aliases(&apps);
        Ok(SearchOutcome { apps, failures })
    }

    /// Resolve `id` per adapter keyed on the slug, merging `sources` rows
    /// deduped; a total miss consults the alias index (DESIGN.md §5).
    /// Errors: [`Error::AllSourcesFailed`] when every source fails.
    pub async fn resolve(&self, id: &crate::model::TorideId) -> Result<Vec<SourceRef>> {
        let mut rows: Vec<SourceRef> = Vec::new();
        let mut failures = Vec::new();
        for adapter in &self.adapters {
            let reference = SourceRef {
                source: adapter.source(),
                id: id.as_str().to_owned(),
                repo: None,
                version: None,
                provisional: false,
            };
            match adapter.lookup(&reference).await {
                Ok(Some(app)) => alias::union_rows(&mut rows, app.sources),
                Ok(None) => {}
                Err(error) => failures.push(SourceFailure {
                    source: adapter.source(),
                    error,
                }),
            }
        }
        let _ = all_failed(self.adapters.len(), id.as_str().to_owned(), failures)?;
        let mut index = self.locked_aliases();
        if rows.is_empty() {
            rows = index.get(id).to_vec();
        } else {
            index.insert(id, rows.iter().cloned());
        }
        Ok(rows)
    }

    fn locked_aliases(&self) -> std::sync::MutexGuard<'_, AliasIndex> {
        self.aliases.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn record_aliases(&self, apps: &[App]) {
        let mut index = self.locked_aliases();
        for app in apps {
            index.record(app);
        }
    }

    /// Render `app`'s install descriptor for `host` (DESIGN.md §3.3):
    /// native argv, direct-download fallback, or [`PlannedOp::Unsupported`];
    /// empty `platforms` skip claims; `min_release` stays unenforced.
    #[must_use]
    pub fn plan(app: &App, host: &Platform) -> PlannedOp {
        if gates_pass(app, host)
            && let Some(op) = manager_op(&app.install, Lifecycle::Install)
        {
            return op;
        }
        match app.direct_fallback(host.os, host.arch) {
            Some(InstallMethod::Direct { url, checksum, .. }) => {
                PlannedOp::DirectDownload { url, checksum }
            }
            _ => PlannedOp::Unsupported,
        }
    }

    /// Render `app`'s update argv for `host`: [`Registry::plan`]'s gates
    /// minus the direct-download fallback; methods with no upgrade
    /// spelling (Direct) are [`PlannedOp::Unsupported`].
    #[must_use]
    pub fn plan_update(app: &App, host: &Platform) -> PlannedOp {
        gates_pass(app, host)
            .then(|| manager_op(&app.install, Lifecycle::Update))
            .flatten()
            .unwrap_or(PlannedOp::Unsupported)
    }

    /// Render `app`'s uninstall argv for `host`: only the manager's OS
    /// coverage gates — claims are install-only. Direct methods
    /// uninstall by replaying a manifest record, never registry data.
    #[must_use]
    pub fn plan_uninstall(app: &App, host: &Platform) -> PlannedOp {
        method_covers_os(&app.install, host.os)
            .then(|| manager_op(&app.install, Lifecycle::Uninstall))
            .flatten()
            .unwrap_or(PlannedOp::Unsupported)
    }
}

/// What [`Registry::plan`], [`Registry::plan_update`], and
/// [`Registry::plan_uninstall`] say to do for one app on one host
/// platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlannedOp {
    /// argv for the native manager (`brew`, `flatpak`, `apt`, …) —
    /// program first, the lifecycle argv only: no suppression flags or
    /// one-time setup; the executor layers those.
    Command {
        /// The manager binary to run.
        program: String,
        /// Its arguments for the rendered lifecycle verb.
        args: Vec<String>,
    },
    /// The native method cannot serve the host, but a checksummed
    /// artifact matched it — hand the url+checksum to a direct
    /// downloader (toride-installer's shape).
    DirectDownload {
        /// The matched artifact's download URL.
        url: String,
        /// The artifact's published checksum, when it carries one.
        checksum: Option<Checksum>,
    },
    /// Nothing installable for this host: the claims exclude it (or the
    /// method's platform set does) and no checksummed artifact matches.
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lifecycle {
    Install,
    Update,
    Uninstall,
}

fn gates_pass(app: &App, host: &Platform) -> bool {
    (app.platforms.is_empty() || app.platforms.iter().any(|claim| claim_matches(claim, host)))
        && method_covers_os(&app.install, host.os)
}

fn manager_op(method: &InstallMethod, lifecycle: Lifecycle) -> Option<PlannedOp> {
    match method {
        InstallMethod::Homebrew { cask, token } => Some(brew_op(*cask, token, lifecycle)),
        InstallMethod::Flatpak { app_id, remote } => Some(flatpak_op(app_id, remote, lifecycle)),
        InstallMethod::Distro {
            family, package, ..
        } => Some(distro_op(*family, package, lifecycle)),
        InstallMethod::Direct { url, checksum, .. } => match lifecycle {
            Lifecycle::Install => Some(PlannedOp::DirectDownload {
                url: url.clone(),
                checksum: checksum.clone(),
            }),
            Lifecycle::Update | Lifecycle::Uninstall => None,
        },
        InstallMethod::Npm { package, version } => {
            Some(npm_op(package, version.as_deref(), lifecycle))
        }
        InstallMethod::Cargo { crate_, version } => {
            Some(cargo_op(crate_, version.as_deref(), lifecycle))
        }
        InstallMethod::Pipx { package } => Some(simple_op("pipx", package, lifecycle)),
        InstallMethod::Uv { package, version } => {
            Some(uv_op(package, version.as_deref(), lifecycle))
        }
        InstallMethod::Mise { tool, version } => Some(mise_op(tool, version.as_deref(), lifecycle)),
    }
}

fn lifecycle_verb(lifecycle: Lifecycle) -> &'static str {
    match lifecycle {
        Lifecycle::Install => "install",
        Lifecycle::Update => "upgrade",
        Lifecycle::Uninstall => "uninstall",
    }
}

fn brew_op(cask: bool, token: &str, lifecycle: Lifecycle) -> PlannedOp {
    let mut args = vec![lifecycle_verb(lifecycle).to_owned()];
    if cask {
        args.push("--cask".to_owned());
    }
    args.push(token.to_owned());
    PlannedOp::Command {
        program: "brew".to_owned(),
        args,
    }
}

fn flatpak_op(app_id: &str, remote: &str, lifecycle: Lifecycle) -> PlannedOp {
    let args = match lifecycle {
        Lifecycle::Install => {
            vec![
                "install".to_owned(),
                "--user".to_owned(),
                remote.to_owned(),
                app_id.to_owned(),
            ]
        }
        Lifecycle::Update => vec!["update".to_owned(), "--user".to_owned(), app_id.to_owned()],
        Lifecycle::Uninstall => vec![
            "uninstall".to_owned(),
            "--user".to_owned(),
            app_id.to_owned(),
        ],
    };
    PlannedOp::Command {
        program: "flatpak".to_owned(),
        args,
    }
}

fn distro_op(family: DistroFamily, package: &str, lifecycle: Lifecycle) -> PlannedOp {
    let (program, verbs) = distro_verbs(family, lifecycle);
    let mut args: Vec<String> = verbs.iter().map(|verb| (*verb).to_owned()).collect();
    args.push(package.to_owned());
    PlannedOp::Command { program, args }
}

fn npm_op(package: &str, version: Option<&str>, lifecycle: Lifecycle) -> PlannedOp {
    let args = match lifecycle {
        Lifecycle::Install => vec![
            "install".to_owned(),
            "-g".to_owned(),
            joined_spec(package, version, "@"),
        ],
        Lifecycle::Update => npm_scoped("update", package),
        Lifecycle::Uninstall => npm_scoped("uninstall", package),
    };
    PlannedOp::Command {
        program: "npm".to_owned(),
        args,
    }
}

fn npm_scoped(verb: &str, package: &str) -> Vec<String> {
    vec![verb.to_owned(), "-g".to_owned(), package.to_owned()]
}

fn cargo_op(crate_: &str, version: Option<&str>, lifecycle: Lifecycle) -> PlannedOp {
    let args = match lifecycle {
        Lifecycle::Install => {
            let mut args = vec!["install".to_owned()];
            if let Some(version) = version {
                args.push("--version".to_owned());
                args.push(version.to_owned());
            }
            args.push(crate_.to_owned());
            args
        }
        Lifecycle::Update => vec![
            "install".to_owned(),
            "--force".to_owned(),
            crate_.to_owned(),
        ],
        Lifecycle::Uninstall => vec!["uninstall".to_owned(), crate_.to_owned()],
    };
    PlannedOp::Command {
        program: "cargo".to_owned(),
        args,
    }
}

fn simple_op(program: &str, package: &str, lifecycle: Lifecycle) -> PlannedOp {
    PlannedOp::Command {
        program: program.to_owned(),
        args: vec![lifecycle_verb(lifecycle).to_owned(), package.to_owned()],
    }
}

fn uv_op(package: &str, version: Option<&str>, lifecycle: Lifecycle) -> PlannedOp {
    let mut args = vec!["tool".to_owned(), lifecycle_verb(lifecycle).to_owned()];
    if lifecycle == Lifecycle::Install {
        args.push(joined_spec(package, version, "=="));
    } else {
        args.push(package.to_owned());
    }
    PlannedOp::Command {
        program: "uv".to_owned(),
        args,
    }
}

fn mise_op(tool: &str, version: Option<&str>, lifecycle: Lifecycle) -> PlannedOp {
    let operand = if lifecycle == Lifecycle::Install {
        mise_spec(tool, version)
    } else {
        tool.to_owned()
    };
    PlannedOp::Command {
        program: "mise".to_owned(),
        args: vec![lifecycle_verb(lifecycle).to_owned(), operand],
    }
}

fn distro_verbs(family: DistroFamily, lifecycle: Lifecycle) -> (String, &'static [&'static str]) {
    let (program, verbs): (&str, &'static [&'static str]) = match (family, lifecycle) {
        (DistroFamily::Debian | DistroFamily::Ubuntu, Lifecycle::Install) => ("apt", &["install"]),
        (DistroFamily::Debian | DistroFamily::Ubuntu, Lifecycle::Update) => {
            ("apt", &["install", "--only-upgrade"])
        }
        (DistroFamily::Debian | DistroFamily::Ubuntu, Lifecycle::Uninstall) => ("apt", &["remove"]),
        (DistroFamily::Fedora, Lifecycle::Install) => ("dnf", &["install"]),
        (DistroFamily::Fedora, Lifecycle::Update) => ("dnf", &["upgrade"]),
        (DistroFamily::Fedora, Lifecycle::Uninstall) => ("dnf", &["remove"]),
        (DistroFamily::Arch, Lifecycle::Install) => ("pacman", &["--sync"]),
        (DistroFamily::Arch, Lifecycle::Update) => ("pacman", &["--sync", "--refresh"]),
        (DistroFamily::Arch, Lifecycle::Uninstall) => ("pacman", &["--remove"]),
        (DistroFamily::Alpine, Lifecycle::Install) => ("apk", &["add"]),
        (DistroFamily::Alpine, Lifecycle::Update) => ("apk", &["upgrade"]),
        (DistroFamily::Alpine, Lifecycle::Uninstall) => ("apk", &["del"]),
    };
    (program.to_owned(), verbs)
}

fn all_failed(
    total: usize,
    context: String,
    failures: Vec<SourceFailure>,
) -> std::result::Result<Vec<SourceFailure>, Error> {
    if total > 0 && failures.len() == total {
        Err(Error::AllSourcesFailed { context, failures })
    } else {
        Ok(failures)
    }
}

fn claim_matches(claim: &Platform, host: &Platform) -> bool {
    claim.os == host.os && (claim.arch.is_none() || host.arch.is_none() || claim.arch == host.arch)
}

fn method_covers_os(method: &InstallMethod, os: Os) -> bool {
    match method {
        InstallMethod::Homebrew { cask: true, .. } => os == Os::MacOs,
        InstallMethod::Homebrew { cask: false, .. } => matches!(os, Os::MacOs | Os::Linux),
        InstallMethod::Flatpak { .. } | InstallMethod::Distro { .. } => os == Os::Linux,
        InstallMethod::Direct { .. }
        | InstallMethod::Npm { .. }
        | InstallMethod::Cargo { .. }
        | InstallMethod::Pipx { .. }
        | InstallMethod::Uv { .. }
        | InstallMethod::Mise { .. } => true,
    }
}

/// `<name><sep><version>` when a pin exists, the bare name otherwise.
fn joined_spec(name: &str, version: Option<&str>, sep: &str) -> String {
    version.map_or_else(
        || name.to_owned(),
        |version| format!("{name}{sep}{version}"),
    )
}

/// The mise-native spec: `tool@latest` is the manager's current, a pin is
/// the `@`-joined spelling.
fn mise_spec(tool: &str, version: Option<&str>) -> String {
    version.map_or_else(
        || format!("{tool}@latest"),
        |version| joined_spec(tool, Some(version), "@"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Arch, Artifact, ArtifactKind, Availability, TorideId};

    struct StubAdapter {
        source: SourceKind,
        apps: Vec<App>,
        fail: bool,
    }

    impl StubAdapter {
        fn up(source: SourceKind, apps: Vec<App>) -> Arc<dyn Adapter> {
            Arc::new(Self {
                source,
                apps,
                fail: false,
            })
        }

        fn down(source: SourceKind) -> Arc<dyn Adapter> {
            Arc::new(Self {
                source,
                apps: Vec::new(),
                fail: true,
            })
        }
    }

    #[async_trait::async_trait]
    impl Adapter for StubAdapter {
        fn source(&self) -> SourceKind {
            self.source
        }

        async fn lookup(&self, id: &SourceRef) -> Result<Option<App>> {
            if self.fail {
                return Err(outage());
            }
            Ok(self
                .apps
                .iter()
                .find(|app| app.id.as_str() == id.id)
                .cloned())
        }

        async fn search(&self, _query: &str) -> Result<Vec<App>> {
            if self.fail {
                return Err(outage());
            }
            Ok(self.apps.clone())
        }
    }

    fn outage() -> Error {
        Error::Http {
            url: "https://source.example".to_owned(),
            message: "down".to_owned(),
        }
    }

    fn stub_app(slug: &str, source: SourceKind) -> App {
        App {
            id: TorideId::slugify(slug),
            name: slug.to_owned(),
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
            install: InstallMethod::Homebrew {
                cask: false,
                token: slug.to_owned(),
            },
            sources: vec![SourceRef {
                source,
                id: slug.to_owned(),
                repo: None,
                version: None,
                provisional: false,
            }],
            availability: Availability::Available,
        }
    }

    fn host(os: Os, arch: Option<Arch>) -> Platform {
        Platform {
            os,
            arch,
            min_release: None,
        }
    }

    #[test]
    fn builder_accepts_boxed_and_arced_adapters() {
        let boxed: Box<dyn Adapter> = Box::new(StubAdapter {
            source: SourceKind::HomebrewCask,
            apps: Vec::new(),
            fail: false,
        });
        let registry = Registry::builder()
            .with_adapter(boxed)
            .with_adapter(StubAdapter::up(SourceKind::Flathub, Vec::new()))
            .build();
        assert_eq!(registry.adapters().len(), 2);
        assert_eq!(registry.adapters()[0].source(), SourceKind::HomebrewCask);
        assert_eq!(registry.adapters()[1].source(), SourceKind::Flathub);
    }

    #[test]
    fn new_accepts_an_adapter_collection() {
        let registry = Registry::new(vec![
            StubAdapter::up(SourceKind::Flathub, Vec::new()),
            StubAdapter::up(SourceKind::Distro, Vec::new()),
        ]);
        assert_eq!(registry.adapters().len(), 2);
    }

    #[tokio::test]
    async fn search_merges_hits_in_registration_order() {
        let registry = Registry::new(vec![
            StubAdapter::up(
                SourceKind::HomebrewCask,
                vec![stub_app("firefox", SourceKind::HomebrewCask)],
            ),
            StubAdapter::up(
                SourceKind::Flathub,
                vec![stub_app("org.mozilla.firefox", SourceKind::Flathub)],
            ),
        ]);
        let outcome = registry.search("firefox").await.expect("fan-out merges");
        let names: Vec<&str> = outcome.apps.iter().map(|app| app.name.as_str()).collect();
        assert_eq!(names, ["firefox", "org.mozilla.firefox"]);
        assert!(outcome.failures.is_empty());
    }

    #[tokio::test]
    async fn search_keeps_hits_when_one_source_fails() {
        let registry = Registry::new(vec![
            StubAdapter::up(
                SourceKind::HomebrewCask,
                vec![stub_app("firefox", SourceKind::HomebrewCask)],
            ),
            StubAdapter::down(SourceKind::Flathub),
        ]);
        let outcome = registry.search("firefox").await.expect("tolerated failure");
        assert_eq!(outcome.apps.len(), 1, "the healthy source's hits survive");
        assert_eq!(outcome.failures.len(), 1);
        assert_eq!(outcome.failures[0].source, SourceKind::Flathub);
        assert!(outcome.failures[0].to_string().contains("down"));
    }

    #[tokio::test]
    async fn search_errors_only_when_every_source_fails() {
        let registry = Registry::new(vec![
            StubAdapter::down(SourceKind::HomebrewCask),
            StubAdapter::down(SourceKind::Flathub),
        ]);
        let error = registry
            .search("firefox")
            .await
            .expect_err("total failure must error");
        match error {
            Error::AllSourcesFailed { context, failures } => {
                assert_eq!(context, "firefox");
                assert_eq!(failures.len(), 2);
            }
            other => panic!("expected AllSourcesFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn search_without_adapters_is_an_empty_ok() {
        let registry = Registry::new(Vec::<Arc<dyn Adapter>>::new());
        let outcome = registry.search("anything").await.expect("nothing to fail");
        assert_eq!(outcome.apps, Vec::new());
        assert!(outcome.failures.is_empty());
    }

    #[tokio::test]
    async fn resolve_merges_source_refs_across_adapters() {
        let mut flathub_row = stub_app("brave", SourceKind::Flathub);
        flathub_row.sources = vec![
            SourceRef {
                source: SourceKind::Flathub,
                id: "com.brave.Browser".to_owned(),
                repo: None,
                version: None,
                provisional: false,
            },
            SourceRef {
                source: SourceKind::Repology,
                id: "brave-browser".to_owned(),
                repo: Some("homebrew".to_owned()),
                version: None,
                provisional: false,
            },
        ];
        let mut cask_row = stub_app("brave", SourceKind::HomebrewCask);
        cask_row.sources = vec![
            SourceRef {
                source: SourceKind::HomebrewCask,
                id: "brave".to_owned(),
                repo: None,
                version: None,
                provisional: false,
            },
            SourceRef {
                source: SourceKind::Flathub,
                id: "com.brave.Browser".to_owned(),
                repo: None,
                version: None,
                provisional: false,
            },
        ];
        let registry = Registry::new(vec![
            StubAdapter::up(SourceKind::Flathub, vec![flathub_row]),
            StubAdapter::up(SourceKind::HomebrewCask, vec![cask_row]),
            StubAdapter::up(SourceKind::Distro, Vec::new()),
        ]);
        let rows = registry
            .resolve(&TorideId::slugify("brave"))
            .await
            .expect("resolve merges");
        let ids: Vec<(&SourceKind, &str)> = rows
            .iter()
            .map(|row| (&row.source, row.id.as_str()))
            .collect();
        assert_eq!(
            ids,
            [
                (&SourceKind::Flathub, "com.brave.Browser"),
                (&SourceKind::Repology, "brave-browser"),
                (&SourceKind::HomebrewCask, "brave"),
            ],
            "both hits' rows merged, the duplicate flathub row deduped"
        );
    }

    #[tokio::test]
    async fn resolve_returns_empty_for_an_unknown_id_and_tolerates_failures() {
        let registry = Registry::new(vec![
            StubAdapter::up(SourceKind::HomebrewCask, Vec::new()),
            StubAdapter::down(SourceKind::Flathub),
        ]);
        let rows = registry
            .resolve(&TorideId::slugify("unknown-app"))
            .await
            .expect("a failing source is skipped, not fatal");
        assert_eq!(rows, Vec::new());
    }

    #[tokio::test]
    async fn resolve_errors_when_every_source_fails() {
        let registry = Registry::new(vec![StubAdapter::down(SourceKind::Flathub)]);
        let error = registry
            .resolve(&TorideId::slugify("brave"))
            .await
            .expect_err("total failure must error");
        assert!(matches!(
            error,
            Error::AllSourcesFailed { context, .. } if context == "brave"
        ));
    }

    struct NativeStubAdapter {
        source: SourceKind,
        apps: Vec<App>,
    }

    impl NativeStubAdapter {
        fn up(source: SourceKind, apps: Vec<App>) -> Arc<dyn Adapter> {
            Arc::new(Self { source, apps })
        }
    }

    #[async_trait::async_trait]
    impl Adapter for NativeStubAdapter {
        fn source(&self) -> SourceKind {
            self.source
        }

        async fn lookup(&self, id: &SourceRef) -> Result<Option<App>> {
            Ok(self
                .apps
                .iter()
                .find(|app| app.sources.iter().any(|row| row.id == id.id))
                .cloned())
        }

        async fn search(&self, _query: &str) -> Result<Vec<App>> {
            Ok(self.apps.clone())
        }
    }

    fn brave_cask_row() -> App {
        let mut app = stub_app("brave-browser", SourceKind::HomebrewCask);
        app.name = "Brave Browser".to_owned();
        app.homepage = Some("https://brave.com/".to_owned());
        app.install = InstallMethod::Homebrew {
            cask: true,
            token: "brave-browser".to_owned(),
        };
        app
    }

    fn brave_flathub_row() -> App {
        let mut app = stub_app("com-brave-browser", SourceKind::Flathub);
        app.name = "Brave Browser".to_owned();
        app.install = InstallMethod::Flatpak {
            app_id: "com.brave.Browser".to_owned(),
            remote: "flathub".to_owned(),
        };
        app.sources = vec![SourceRef {
            source: SourceKind::Flathub,
            id: "com.brave.Browser".to_owned(),
            repo: None,
            version: None,
            provisional: false,
        }];
        app
    }

    #[tokio::test]
    async fn search_merges_same_app_hits_across_adapters_into_one_row() {
        let registry = Registry::new(vec![
            NativeStubAdapter::up(SourceKind::Flathub, vec![brave_flathub_row()]),
            NativeStubAdapter::up(SourceKind::HomebrewCask, vec![brave_cask_row()]),
        ]);
        let outcome = registry
            .search("brave browser")
            .await
            .expect("fan-out merges same-app hits");
        assert_eq!(outcome.apps.len(), 1);
        let merged = &outcome.apps[0];
        assert_eq!(
            merged.id.as_str(),
            "com-brave-browser",
            "the registration-first row's id is the canonical one"
        );
        assert_eq!(merged.name, "Brave Browser");
        assert_eq!(
            merged
                .sources
                .iter()
                .map(|row| (row.source, row.id.as_str()))
                .collect::<Vec<_>>(),
            [
                (SourceKind::Flathub, "com.brave.Browser"),
                (SourceKind::HomebrewCask, "brave-browser"),
            ],
            "one row carries both sources' refs"
        );
        assert_eq!(
            merged.homepage.as_deref(),
            Some("https://brave.com/"),
            "the cask hit's homepage backfills the hit that carried none"
        );
    }

    #[tokio::test]
    async fn search_records_merged_rows_into_the_alias_index() {
        let registry = Registry::new(vec![
            NativeStubAdapter::up(SourceKind::Flathub, vec![brave_flathub_row()]),
            NativeStubAdapter::up(SourceKind::HomebrewCask, vec![brave_cask_row()]),
        ]);
        assert!(registry.alias_index().is_empty());
        registry
            .search("brave browser")
            .await
            .expect("search populates the index");
        let index = registry.alias_index();
        assert_eq!(index.len(), 1);
        assert_eq!(
            index
                .get(&TorideId::slugify("com-brave-browser"))
                .iter()
                .map(|row| (row.source, row.id.as_str()))
                .collect::<Vec<_>>(),
            [
                (SourceKind::Flathub, "com.brave.Browser"),
                (SourceKind::HomebrewCask, "brave-browser"),
            ]
        );
    }

    #[tokio::test]
    async fn search_keeps_rows_apart_when_identities_conflict() {
        let mut flathub = brave_flathub_row();
        flathub.homepage = Some("https://flathub.example".to_owned());
        let mut cask = brave_cask_row();
        cask.homepage = Some("https://brave.com/".to_owned());
        let registry = Registry::new(vec![
            NativeStubAdapter::up(SourceKind::Flathub, vec![flathub]),
            NativeStubAdapter::up(SourceKind::HomebrewCask, vec![cask]),
        ]);
        let outcome = registry
            .search("brave browser")
            .await
            .expect("conflicting identities still answer");
        assert_eq!(
            outcome.apps.len(),
            2,
            "a homepage conflict keeps rows apart"
        );
    }

    #[tokio::test]
    async fn search_suffixes_same_slug_conflicts_and_resolve_stays_unambiguous() {
        let mut cask = stub_app("notes", SourceKind::HomebrewCask);
        cask.name = "Notes".to_owned();
        cask.homepage = Some("https://notes.a/".to_owned());
        let mut flathub = stub_app("notes", SourceKind::Flathub);
        flathub.name = "Notes".to_owned();
        flathub.homepage = Some("https://notes.b/".to_owned());
        flathub.install = InstallMethod::Flatpak {
            app_id: "com.example.Notes".to_owned(),
            remote: "flathub".to_owned(),
        };
        flathub.sources = vec![SourceRef {
            source: SourceKind::Flathub,
            id: "com.example.Notes".to_owned(),
            repo: None,
            version: None,
            provisional: false,
        }];
        let registry = Registry::new(vec![
            NativeStubAdapter::up(SourceKind::HomebrewCask, vec![cask]),
            NativeStubAdapter::up(SourceKind::Flathub, vec![flathub]),
        ]);
        let outcome = registry
            .search("notes")
            .await
            .expect("conflicting same-slug hits still answer");
        assert_eq!(
            outcome
                .apps
                .iter()
                .map(|app| app.id.as_str())
                .collect::<Vec<_>>(),
            ["notes", "notes-flathub"],
            "no two result rows share one TorideId (DESIGN.md §5's suffix branch)"
        );
        let flathub_rows = registry
            .resolve(&TorideId::slugify("notes-flathub"))
            .await
            .expect("the index answers the suffixed id");
        assert_eq!(
            flathub_rows
                .iter()
                .map(|row| (row.source, row.id.as_str()))
                .collect::<Vec<_>>(),
            [(SourceKind::Flathub, "com.example.Notes")],
            "the index fallback names one app's refs, never both conflicting apps' merged"
        );
        let cask_rows = registry
            .resolve(&TorideId::slugify("notes"))
            .await
            .expect("the canonical id stays the cask row's");
        assert_eq!(
            cask_rows
                .iter()
                .map(|row| (row.source, row.id.as_str()))
                .collect::<Vec<_>>(),
            [(SourceKind::HomebrewCask, "notes")]
        );
    }

    #[tokio::test]
    async fn search_keeps_same_named_hits_from_one_adapter_apart() {
        let mut left = stub_app("notes-a", SourceKind::HomebrewCask);
        left.name = "Notes".to_owned();
        let mut right = stub_app("notes-b", SourceKind::HomebrewCask);
        right.name = "Notes".to_owned();
        let registry = Registry::new(vec![NativeStubAdapter::up(
            SourceKind::HomebrewCask,
            vec![left, right],
        )]);
        let outcome = registry
            .search("notes")
            .await
            .expect("one adapter answering");
        assert_eq!(
            outcome
                .apps
                .iter()
                .map(|app| app.id.as_str())
                .collect::<Vec<_>>(),
            ["notes-a", "notes-b"],
            "the merge joins hits across adapters, never one adapter's own hits"
        );
    }

    #[tokio::test]
    async fn resolve_answers_from_the_alias_index_when_primary_lookups_miss() {
        let registry = Registry::new(vec![
            NativeStubAdapter::up(SourceKind::Flathub, vec![brave_flathub_row()]),
            NativeStubAdapter::up(SourceKind::HomebrewCask, vec![brave_cask_row()]),
        ]);
        registry
            .search("brave browser")
            .await
            .expect("search seeds the index");
        let rows = registry
            .resolve(&TorideId::slugify("com-brave-browser"))
            .await
            .expect("the index answers what the primary fan-out cannot");
        assert_eq!(
            rows.iter()
                .map(|row| (row.source, row.id.as_str()))
                .collect::<Vec<_>>(),
            [
                (SourceKind::Flathub, "com.brave.Browser"),
                (SourceKind::HomebrewCask, "brave-browser"),
            ],
            "the slug names no source-native id, so only the index knows it"
        );
    }

    #[tokio::test]
    async fn resolve_prefers_primary_hits_over_the_alias_index() {
        let mut index = AliasIndex::new();
        index.insert(
            &TorideId::slugify("brave"),
            vec![SourceRef {
                source: SourceKind::Flathub,
                id: "com.brave.Browser".to_owned(),
                repo: None,
                version: None,
                provisional: false,
            }],
        );
        let registry = Registry::builder()
            .with_adapter(StubAdapter::up(
                SourceKind::HomebrewCask,
                vec![stub_app("brave", SourceKind::HomebrewCask)],
            ))
            .with_alias_index(index)
            .build();
        let rows = registry
            .resolve(&TorideId::slugify("brave"))
            .await
            .expect("the primary lookup wins");
        assert_eq!(
            rows.iter()
                .map(|row| (row.source, row.id.as_str()))
                .collect::<Vec<_>>(),
            [(SourceKind::HomebrewCask, "brave")]
        );
    }

    #[tokio::test]
    async fn builder_preloads_the_alias_index_for_resolve() {
        let mut index = AliasIndex::new();
        index.insert(
            &TorideId::slugify("brave-browser"),
            vec![SourceRef {
                source: SourceKind::HomebrewCask,
                id: "brave-browser".to_owned(),
                repo: None,
                version: None,
                provisional: false,
            }],
        );
        let registry = Registry::builder()
            .with_adapter(StubAdapter::up(SourceKind::Flathub, Vec::new()))
            .with_alias_index(index)
            .build();
        let rows = registry
            .resolve(&TorideId::slugify("brave-browser"))
            .await
            .expect("the preloaded index answers the miss");
        assert_eq!(
            rows.iter()
                .map(|row| (row.source, row.id.as_str()))
                .collect::<Vec<_>>(),
            [(SourceKind::HomebrewCask, "brave-browser")]
        );
    }

    fn plannable(mut app: App, platforms: Vec<Platform>, artifacts: Vec<Artifact>) -> App {
        app.platforms = platforms;
        app.artifacts = artifacts;
        app
    }

    fn checksummed(url: &str, os: Option<Os>, arch: Option<Arch>) -> Artifact {
        Artifact {
            url: url.to_owned(),
            checksum: Some(Checksum {
                algo: crate::model::ChecksumAlgo::Sha256,
                digest: "digest".to_owned(),
            }),
            os,
            arch,
            kind: ArtifactKind::Package,
        }
    }

    #[test]
    fn plan_renders_the_native_manager_argv_per_method() {
        let mut cask = stub_app("brave-browser", SourceKind::HomebrewCask);
        cask.install = InstallMethod::Homebrew {
            cask: true,
            token: "brave-browser".to_owned(),
        };
        assert_eq!(
            Registry::plan(&cask, &host(Os::MacOs, Some(Arch::Aarch64))),
            PlannedOp::Command {
                program: "brew".to_owned(),
                args: vec![
                    "install".to_owned(),
                    "--cask".to_owned(),
                    "brave-browser".to_owned()
                ],
            }
        );

        let mut formula = stub_app("ripgrep", SourceKind::HomebrewFormula);
        formula.install = InstallMethod::Homebrew {
            cask: false,
            token: "ripgrep".to_owned(),
        };
        assert_eq!(
            Registry::plan(&formula, &host(Os::Linux, Some(Arch::X86_64))),
            PlannedOp::Command {
                program: "brew".to_owned(),
                args: vec!["install".to_owned(), "ripgrep".to_owned()],
            }
        );

        let mut flatpak = stub_app("brave", SourceKind::Flathub);
        flatpak.install = InstallMethod::Flatpak {
            app_id: "com.brave.Browser".to_owned(),
            remote: "flathub".to_owned(),
        };
        flatpak.platforms = vec![Platform {
            os: Os::Linux,
            arch: None,
            min_release: None,
        }];
        assert_eq!(
            Registry::plan(&flatpak, &host(Os::Linux, Some(Arch::X86_64))),
            PlannedOp::Command {
                program: "flatpak".to_owned(),
                args: vec![
                    "install".to_owned(),
                    "--user".to_owned(),
                    "flathub".to_owned(),
                    "com.brave.Browser".to_owned(),
                ],
            }
        );

        for (family, program, verb) in [
            (DistroFamily::Debian, "apt", "install"),
            (DistroFamily::Ubuntu, "apt", "install"),
            (DistroFamily::Fedora, "dnf", "install"),
            (DistroFamily::Arch, "pacman", "--sync"),
            (DistroFamily::Alpine, "apk", "add"),
        ] {
            let mut distro = stub_app("gitg", SourceKind::Distro);
            distro.install = InstallMethod::Distro {
                family,
                repo: Some("suite-main".to_owned()),
                package: "gitg".to_owned(),
            };
            distro.platforms = vec![Platform {
                os: Os::Linux,
                arch: Some(Arch::X86_64),
                min_release: None,
            }];
            assert_eq!(
                Registry::plan(&distro, &host(Os::Linux, Some(Arch::X86_64))),
                PlannedOp::Command {
                    program: program.to_owned(),
                    args: vec![verb.to_owned(), "gitg".to_owned()],
                },
                "family {family:?}"
            );
        }

        let mut direct = stub_app("tool", SourceKind::Flathub);
        direct.install = InstallMethod::Direct {
            url: "https://example.com/tool".to_owned(),
            checksum: None,
            arch: Some(Arch::X86_64),
        };
        assert_eq!(
            Registry::plan(&direct, &host(Os::Linux, Some(Arch::X86_64))),
            PlannedOp::DirectDownload {
                url: "https://example.com/tool".to_owned(),
                checksum: None,
            }
        );
    }

    #[test]
    fn plan_renders_the_language_manager_argv_per_method() {
        let mut npm = stub_app("typescript", SourceKind::Distro);
        npm.install = InstallMethod::Npm {
            package: "typescript".to_owned(),
            version: Some("5.4.5".to_owned()),
        };
        assert_eq!(
            Registry::plan(&npm, &host(Os::MacOs, None)),
            PlannedOp::Command {
                program: "npm".to_owned(),
                args: vec![
                    "install".to_owned(),
                    "-g".to_owned(),
                    "typescript@5.4.5".to_owned(),
                ],
            }
        );

        let mut cargo = stub_app("ripgrep", SourceKind::Distro);
        cargo.install = InstallMethod::Cargo {
            crate_: "ripgrep".to_owned(),
            version: Some("14.1.0".to_owned()),
        };
        assert_eq!(
            Registry::plan(&cargo, &host(Os::Linux, None)),
            PlannedOp::Command {
                program: "cargo".to_owned(),
                args: vec![
                    "install".to_owned(),
                    "--version".to_owned(),
                    "14.1.0".to_owned(),
                    "ripgrep".to_owned(),
                ],
            },
            "the cargo arm renders the install verb like every sibling"
        );

        let mut pipx = stub_app("black", SourceKind::Distro);
        pipx.install = InstallMethod::Pipx {
            package: "black".to_owned(),
        };
        assert_eq!(
            Registry::plan(&pipx, &host(Os::Linux, None)),
            PlannedOp::Command {
                program: "pipx".to_owned(),
                args: vec!["install".to_owned(), "black".to_owned()],
            }
        );

        let mut uv = stub_app("ruff", SourceKind::Distro);
        uv.install = InstallMethod::Uv {
            package: "ruff".to_owned(),
            version: None,
        };
        assert_eq!(
            Registry::plan(&uv, &host(Os::Linux, None)),
            PlannedOp::Command {
                program: "uv".to_owned(),
                args: vec!["tool".to_owned(), "install".to_owned(), "ruff".to_owned()],
            }
        );

        let mut mise = stub_app("node", SourceKind::Distro);
        mise.install = InstallMethod::Mise {
            tool: "node".to_owned(),
            version: None,
        };
        assert_eq!(
            Registry::plan(&mise, &host(Os::MacOs, None)),
            PlannedOp::Command {
                program: "mise".to_owned(),
                args: vec!["install".to_owned(), "node@latest".to_owned()],
            },
            "the language managers cover every OS — no platform gate applies"
        );
    }

    #[test]
    fn plan_falls_back_to_direct_download_when_claims_exclude_the_host() {
        let mut app = stub_app("brave-browser", SourceKind::HomebrewCask);
        app.install = InstallMethod::Homebrew {
            cask: true,
            token: "brave-browser".to_owned(),
        };
        app = plannable(
            app,
            vec![Platform {
                os: Os::MacOs,
                arch: None,
                min_release: None,
            }],
            vec![checksummed(
                "https://example.com/brave.dmg",
                Some(Os::MacOs),
                None,
            )],
        );
        assert_eq!(
            Registry::plan(&app, &host(Os::MacOs, Some(Arch::X86_64))),
            PlannedOp::Command {
                program: "brew".to_owned(),
                args: vec![
                    "install".to_owned(),
                    "--cask".to_owned(),
                    "brave-browser".to_owned()
                ],
            },
            "a claimed host plans the native method, artifacts unused"
        );
        assert_eq!(
            Registry::plan(&app, &host(Os::Linux, Some(Arch::X86_64))),
            PlannedOp::Unsupported,
            "Linux is unclaimed and no artifact matches it"
        );

        let mut linux_capable = app.clone();
        linux_capable.artifacts = vec![checksummed(
            "https://example.com/brave-linux.tar.gz",
            Some(Os::Linux),
            Some(Arch::X86_64),
        )];
        assert_eq!(
            Registry::plan(&linux_capable, &host(Os::Linux, Some(Arch::X86_64))),
            PlannedOp::DirectDownload {
                url: "https://example.com/brave-linux.tar.gz".to_owned(),
                checksum: linux_capable.artifacts[0].checksum.clone(),
            },
            "the unclaimed host still gets the checksummed artifact"
        );
    }

    #[test]
    fn plan_skips_the_claim_check_when_platforms_are_empty() {
        let mut flatpak = stub_app("brave", SourceKind::Flathub);
        flatpak.install = InstallMethod::Flatpak {
            app_id: "com.brave.Browser".to_owned(),
            remote: "flathub".to_owned(),
        };
        let app = plannable(flatpak, Vec::new(), Vec::new());
        assert_eq!(
            Registry::plan(&app, &host(Os::Linux, Some(Arch::X86_64))),
            PlannedOp::Command {
                program: "flatpak".to_owned(),
                args: vec![
                    "install".to_owned(),
                    "--user".to_owned(),
                    "flathub".to_owned(),
                    "com.brave.Browser".to_owned(),
                ],
            },
            "empty platforms mean unknown, not universal-refusal"
        );
    }

    #[test]
    fn plan_uses_the_direct_fallback_when_the_method_has_no_manager_on_the_os() {
        let mut flatpak = stub_app("brave", SourceKind::Flathub);
        flatpak.install = InstallMethod::Flatpak {
            app_id: "com.brave.Browser".to_owned(),
            remote: "flathub".to_owned(),
        };
        let app = plannable(
            flatpak,
            Vec::new(),
            vec![checksummed(
                "https://example.com/brave.pkg",
                Some(Os::MacOs),
                None,
            )],
        );
        assert_eq!(
            Registry::plan(&app, &host(Os::MacOs, Some(Arch::Aarch64))),
            PlannedOp::DirectDownload {
                url: "https://example.com/brave.pkg".to_owned(),
                checksum: app.artifacts[0].checksum.clone(),
            },
            "flatpak serves Linux only; the macOS artifact is the fallback"
        );

        let bare = plannable(app.clone(), Vec::new(), Vec::new());
        assert_eq!(
            Registry::plan(&bare, &host(Os::MacOs, Some(Arch::Aarch64))),
            PlannedOp::Unsupported
        );
    }

    #[test]
    fn plan_matches_undeclared_claim_arch_against_a_declared_host() {
        let mut app = stub_app("tool", SourceKind::Flathub);
        app.install = InstallMethod::Flatpak {
            app_id: "org.example.Tool".to_owned(),
            remote: "flathub".to_owned(),
        };
        app = plannable(
            app,
            vec![Platform {
                os: Os::Linux,
                arch: None,
                min_release: None,
            }],
            Vec::new(),
        );
        assert_eq!(
            Registry::plan(&app, &host(Os::Linux, Some(Arch::Aarch64))),
            PlannedOp::Command {
                program: "flatpak".to_owned(),
                args: vec![
                    "install".to_owned(),
                    "--user".to_owned(),
                    "flathub".to_owned(),
                    "org.example.Tool".to_owned(),
                ],
            },
            "an arch-independent claim matches any host arch"
        );
    }

    #[test]
    fn plan_ignores_min_release_claims_and_host_release_slots_for_now() {
        let mut app = stub_app("brave-browser", SourceKind::HomebrewCask);
        app.install = InstallMethod::Homebrew {
            cask: true,
            token: "brave-browser".to_owned(),
        };
        app.platforms = vec![
            Platform {
                os: Os::MacOs,
                arch: Some(Arch::X86_64),
                min_release: Some("13".to_owned()),
            },
            Platform {
                os: Os::MacOs,
                arch: Some(Arch::Aarch64),
                min_release: Some("13".to_owned()),
            },
        ];
        let mut host_below_the_floor = host(Os::MacOs, Some(Arch::Aarch64));
        host_below_the_floor.min_release = Some("11".to_owned());
        let mut host_above_the_floor = host(Os::MacOs, Some(Arch::Aarch64));
        host_above_the_floor.min_release = Some("15".to_owned());
        let native = PlannedOp::Command {
            program: "brew".to_owned(),
            args: vec![
                "install".to_owned(),
                "--cask".to_owned(),
                "brave-browser".to_owned(),
            ],
        };
        assert_eq!(
            Registry::plan(&app, &host_below_the_floor),
            native,
            "a host below the claim floor still plans — min_release is the toride-apps-planner-aligned not-yet-enforced claim"
        );
        assert_eq!(
            Registry::plan(&app, &host_above_the_floor),
            native.clone(),
            "the host's release slot never gates either — comparison is not implemented, matching the apps planner's documented punt"
        );
        assert_eq!(
            Registry::plan(&app, &host(Os::MacOs, Some(Arch::Aarch64))),
            native,
            "a host that declares no release at all — today's every caller — plans the native method"
        );
    }

    #[test]
    fn plan_update_renders_the_native_manager_upgrade_argv_per_method() {
        let mut cask = stub_app("brave-browser", SourceKind::HomebrewCask);
        cask.install = InstallMethod::Homebrew {
            cask: true,
            token: "brave-browser".to_owned(),
        };
        assert_eq!(
            Registry::plan_update(&cask, &host(Os::MacOs, Some(Arch::Aarch64))),
            PlannedOp::Command {
                program: "brew".to_owned(),
                args: vec![
                    "upgrade".to_owned(),
                    "--cask".to_owned(),
                    "brave-browser".to_owned()
                ],
            }
        );

        let mut formula = stub_app("ripgrep", SourceKind::HomebrewFormula);
        formula.install = InstallMethod::Homebrew {
            cask: false,
            token: "ripgrep".to_owned(),
        };
        assert_eq!(
            Registry::plan_update(&formula, &host(Os::Linux, Some(Arch::X86_64))),
            PlannedOp::Command {
                program: "brew".to_owned(),
                args: vec!["upgrade".to_owned(), "ripgrep".to_owned()],
            }
        );

        let mut flatpak = stub_app("brave", SourceKind::Flathub);
        flatpak.install = InstallMethod::Flatpak {
            app_id: "com.brave.Browser".to_owned(),
            remote: "flathub".to_owned(),
        };
        assert_eq!(
            Registry::plan_update(&flatpak, &host(Os::Linux, Some(Arch::X86_64))),
            PlannedOp::Command {
                program: "flatpak".to_owned(),
                args: vec![
                    "update".to_owned(),
                    "--user".to_owned(),
                    "com.brave.Browser".to_owned(),
                ],
            }
        );

        for (family, program, verbs) in [
            (
                DistroFamily::Debian,
                "apt",
                vec!["install", "--only-upgrade"],
            ),
            (
                DistroFamily::Ubuntu,
                "apt",
                vec!["install", "--only-upgrade"],
            ),
            (DistroFamily::Fedora, "dnf", vec!["upgrade"]),
            (DistroFamily::Arch, "pacman", vec!["--sync", "--refresh"]),
            (DistroFamily::Alpine, "apk", vec!["upgrade"]),
        ] {
            let mut distro = stub_app("gitg", SourceKind::Distro);
            distro.install = InstallMethod::Distro {
                family,
                repo: Some("suite-main".to_owned()),
                package: "gitg".to_owned(),
            };
            assert_eq!(
                Registry::plan_update(&distro, &host(Os::Linux, Some(Arch::X86_64))),
                PlannedOp::Command {
                    program: program.to_owned(),
                    args: verbs
                        .into_iter()
                        .map(str::to_owned)
                        .chain(["gitg".to_owned()])
                        .collect(),
                },
                "family {family:?}"
            );
        }
    }

    #[test]
    fn plan_update_renders_the_language_manager_upgrade_argv_per_method() {
        let mut npm = stub_app("typescript", SourceKind::Distro);
        npm.install = InstallMethod::Npm {
            package: "typescript".to_owned(),
            version: Some("5.4.5".to_owned()),
        };
        assert_eq!(
            Registry::plan_update(&npm, &host(Os::MacOs, None)),
            PlannedOp::Command {
                program: "npm".to_owned(),
                args: vec![
                    "update".to_owned(),
                    "-g".to_owned(),
                    "typescript".to_owned()
                ],
            },
            "the update verb takes the bare package — the pin is an install-only spelling"
        );

        let mut cargo = stub_app("ripgrep", SourceKind::Distro);
        cargo.install = InstallMethod::Cargo {
            crate_: "ripgrep".to_owned(),
            version: Some("14.1.0".to_owned()),
        };
        assert_eq!(
            Registry::plan_update(&cargo, &host(Os::Linux, None)),
            PlannedOp::Command {
                program: "cargo".to_owned(),
                args: vec![
                    "install".to_owned(),
                    "--force".to_owned(),
                    "ripgrep".to_owned(),
                ],
            },
            "cargo has no upgrade verb — re-install at latest under --force"
        );

        let mut pipx = stub_app("black", SourceKind::Distro);
        pipx.install = InstallMethod::Pipx {
            package: "black".to_owned(),
        };
        assert_eq!(
            Registry::plan_update(&pipx, &host(Os::Linux, None)),
            PlannedOp::Command {
                program: "pipx".to_owned(),
                args: vec!["upgrade".to_owned(), "black".to_owned()],
            }
        );

        let mut uv = stub_app("ruff", SourceKind::Distro);
        uv.install = InstallMethod::Uv {
            package: "ruff".to_owned(),
            version: None,
        };
        assert_eq!(
            Registry::plan_update(&uv, &host(Os::Linux, None)),
            PlannedOp::Command {
                program: "uv".to_owned(),
                args: vec!["tool".to_owned(), "upgrade".to_owned(), "ruff".to_owned()],
            }
        );

        let mut mise = stub_app("node", SourceKind::Distro);
        mise.install = InstallMethod::Mise {
            tool: "node".to_owned(),
            version: None,
        };
        assert_eq!(
            Registry::plan_update(&mise, &host(Os::MacOs, None)),
            PlannedOp::Command {
                program: "mise".to_owned(),
                args: vec!["upgrade".to_owned(), "node".to_owned()],
            },
            "mise's own upgrade verb — not the install-time @latest spec"
        );
    }

    #[test]
    fn plan_uninstall_renders_the_native_manager_removal_argv_per_method() {
        let mut cask = stub_app("brave-browser", SourceKind::HomebrewCask);
        cask.install = InstallMethod::Homebrew {
            cask: true,
            token: "brave-browser".to_owned(),
        };
        assert_eq!(
            Registry::plan_uninstall(&cask, &host(Os::MacOs, Some(Arch::Aarch64))),
            PlannedOp::Command {
                program: "brew".to_owned(),
                args: vec![
                    "uninstall".to_owned(),
                    "--cask".to_owned(),
                    "brave-browser".to_owned()
                ],
            }
        );

        let mut formula = stub_app("ripgrep", SourceKind::HomebrewFormula);
        formula.install = InstallMethod::Homebrew {
            cask: false,
            token: "ripgrep".to_owned(),
        };
        assert_eq!(
            Registry::plan_uninstall(&formula, &host(Os::MacOs, Some(Arch::Aarch64))),
            PlannedOp::Command {
                program: "brew".to_owned(),
                args: vec!["uninstall".to_owned(), "ripgrep".to_owned()],
            }
        );

        let mut flatpak = stub_app("brave", SourceKind::Flathub);
        flatpak.install = InstallMethod::Flatpak {
            app_id: "com.brave.Browser".to_owned(),
            remote: "flathub".to_owned(),
        };
        assert_eq!(
            Registry::plan_uninstall(&flatpak, &host(Os::Linux, Some(Arch::X86_64))),
            PlannedOp::Command {
                program: "flatpak".to_owned(),
                args: vec![
                    "uninstall".to_owned(),
                    "--user".to_owned(),
                    "com.brave.Browser".to_owned(),
                ],
            }
        );

        for (family, program, verb) in [
            (DistroFamily::Debian, "apt", "remove"),
            (DistroFamily::Ubuntu, "apt", "remove"),
            (DistroFamily::Fedora, "dnf", "remove"),
            (DistroFamily::Arch, "pacman", "--remove"),
            (DistroFamily::Alpine, "apk", "del"),
        ] {
            let mut distro = stub_app("gitg", SourceKind::Distro);
            distro.install = InstallMethod::Distro {
                family,
                repo: Some("suite-main".to_owned()),
                package: "gitg".to_owned(),
            };
            assert_eq!(
                Registry::plan_uninstall(&distro, &host(Os::Linux, Some(Arch::X86_64))),
                PlannedOp::Command {
                    program: program.to_owned(),
                    args: vec![verb.to_owned(), "gitg".to_owned()],
                },
                "family {family:?}"
            );
        }
    }

    #[test]
    fn plan_uninstall_renders_the_language_manager_removal_argv_per_method() {
        let mut npm = stub_app("typescript", SourceKind::Distro);
        npm.install = InstallMethod::Npm {
            package: "typescript".to_owned(),
            version: Some("5.4.5".to_owned()),
        };
        assert_eq!(
            Registry::plan_uninstall(&npm, &host(Os::MacOs, None)),
            PlannedOp::Command {
                program: "npm".to_owned(),
                args: vec![
                    "uninstall".to_owned(),
                    "-g".to_owned(),
                    "typescript".to_owned()
                ],
            }
        );

        let mut cargo = stub_app("ripgrep", SourceKind::Distro);
        cargo.install = InstallMethod::Cargo {
            crate_: "ripgrep".to_owned(),
            version: None,
        };
        assert_eq!(
            Registry::plan_uninstall(&cargo, &host(Os::Linux, None)),
            PlannedOp::Command {
                program: "cargo".to_owned(),
                args: vec!["uninstall".to_owned(), "ripgrep".to_owned()],
            }
        );

        let mut pipx = stub_app("black", SourceKind::Distro);
        pipx.install = InstallMethod::Pipx {
            package: "black".to_owned(),
        };
        assert_eq!(
            Registry::plan_uninstall(&pipx, &host(Os::Linux, None)),
            PlannedOp::Command {
                program: "pipx".to_owned(),
                args: vec!["uninstall".to_owned(), "black".to_owned()],
            }
        );

        let mut uv = stub_app("ruff", SourceKind::Distro);
        uv.install = InstallMethod::Uv {
            package: "ruff".to_owned(),
            version: None,
        };
        assert_eq!(
            Registry::plan_uninstall(&uv, &host(Os::Linux, None)),
            PlannedOp::Command {
                program: "uv".to_owned(),
                args: vec!["tool".to_owned(), "uninstall".to_owned(), "ruff".to_owned()],
            }
        );

        let mut mise = stub_app("node", SourceKind::Distro);
        mise.install = InstallMethod::Mise {
            tool: "node".to_owned(),
            version: None,
        };
        assert_eq!(
            Registry::plan_uninstall(&mise, &host(Os::MacOs, None)),
            PlannedOp::Command {
                program: "mise".to_owned(),
                args: vec!["uninstall".to_owned(), "node".to_owned()],
            }
        );
    }

    #[test]
    fn plan_update_refuses_hosts_the_manager_cannot_serve() {
        let mut flatpak = stub_app("brave", SourceKind::Flathub);
        flatpak.install = InstallMethod::Flatpak {
            app_id: "com.brave.Browser".to_owned(),
            remote: "flathub".to_owned(),
        };
        let claimed_linux_only = plannable(
            flatpak.clone(),
            vec![Platform {
                os: Os::Linux,
                arch: None,
                min_release: None,
            }],
            Vec::new(),
        );
        assert_eq!(
            Registry::plan_update(&claimed_linux_only, &host(Os::Linux, Some(Arch::X86_64))),
            PlannedOp::Command {
                program: "flatpak".to_owned(),
                args: vec![
                    "update".to_owned(),
                    "--user".to_owned(),
                    "com.brave.Browser".to_owned(),
                ],
            },
            "empty-claims skip aside, a claimed host updates"
        );
        assert_eq!(
            Registry::plan_update(&claimed_linux_only, &host(Os::MacOs, Some(Arch::Aarch64))),
            PlannedOp::Unsupported,
            "the claims exclude macOS and no download fallback exists for an update"
        );
        let macos_host_claimed = plannable(
            flatpak,
            vec![Platform {
                os: Os::MacOs,
                arch: None,
                min_release: None,
            }],
            vec![checksummed(
                "https://example.com/brave.pkg",
                Some(Os::MacOs),
                None,
            )],
        );
        assert_eq!(
            Registry::plan_update(&macos_host_claimed, &host(Os::MacOs, Some(Arch::Aarch64))),
            PlannedOp::Unsupported,
            "unlike install, an update never falls back to a direct download"
        );
    }

    #[test]
    fn plan_uninstall_skips_the_install_only_claim_gate() {
        let mut formula = stub_app("ripgrep", SourceKind::HomebrewFormula);
        formula.install = InstallMethod::Homebrew {
            cask: false,
            token: "ripgrep".to_owned(),
        };
        let macos_only = plannable(
            formula,
            vec![Platform {
                os: Os::MacOs,
                arch: None,
                min_release: None,
            }],
            Vec::new(),
        );
        assert_eq!(
            Registry::plan_uninstall(&macos_only, &host(Os::Linux, Some(Arch::X86_64))),
            PlannedOp::Command {
                program: "brew".to_owned(),
                args: vec!["uninstall".to_owned(), "ripgrep".to_owned()],
            },
            "claims gate installs, not removals — Linuxbrew serves formulae"
        );
        assert_eq!(
            Registry::plan(&macos_only, &host(Os::Linux, Some(Arch::X86_64))),
            PlannedOp::Unsupported,
            "the install on the same unclaimed host stays refused"
        );

        let mut flatpak = stub_app("brave", SourceKind::Flathub);
        flatpak.install = InstallMethod::Flatpak {
            app_id: "com.brave.Browser".to_owned(),
            remote: "flathub".to_owned(),
        };
        assert_eq!(
            Registry::plan_uninstall(&flatpak, &host(Os::MacOs, Some(Arch::Aarch64))),
            PlannedOp::Unsupported,
            "only the manager's OS coverage gates — flatpak has none on macOS"
        );
    }

    #[test]
    fn cask_methods_are_macos_only_across_the_lifecycle() {
        let mut cask = stub_app("brave-browser", SourceKind::HomebrewCask);
        cask.install = InstallMethod::Homebrew {
            cask: true,
            token: "brave-browser".to_owned(),
        };
        let linux_host = host(Os::Linux, Some(Arch::X86_64));
        assert_eq!(
            Registry::plan_update(&cask, &linux_host),
            PlannedOp::Unsupported,
            "casks are macOS-only — Linuxbrew serves formulae only"
        );
        assert_eq!(
            Registry::plan_uninstall(&cask, &linux_host),
            PlannedOp::Unsupported
        );
        let with_linux_artifact = plannable(
            cask.clone(),
            Vec::new(),
            vec![checksummed(
                "https://example.com/brave-linux.tar.gz",
                Some(Os::Linux),
                Some(Arch::X86_64),
            )],
        );
        assert_eq!(
            Registry::plan(&with_linux_artifact, &linux_host),
            PlannedOp::DirectDownload {
                url: "https://example.com/brave-linux.tar.gz".to_owned(),
                checksum: with_linux_artifact.artifacts[0].checksum.clone(),
            },
            "the install routes to the checksummed artifact instead of a cask argv Linuxbrew rejects"
        );
        assert_eq!(
            Registry::plan_update(&with_linux_artifact, &linux_host),
            PlannedOp::Unsupported,
            "unlike install, an update never falls back to a direct download"
        );
        let macos_host = host(Os::MacOs, Some(Arch::Aarch64));
        for op in [
            Registry::plan(&cask, &macos_host),
            Registry::plan_update(&cask, &macos_host),
            Registry::plan_uninstall(&cask, &macos_host),
        ] {
            assert!(
                matches!(&op, PlannedOp::Command { program, args }
                    if program == "brew"
                        && args.last().map(String::as_str) == Some("brave-browser")
                        && args.contains(&"--cask".to_owned())),
                "every lifecycle renders the cask argv on macOS: {op:?}"
            );
        }
    }

    #[test]
    fn direct_methods_have_no_update_or_uninstall_spelling() {
        let mut direct = stub_app("tool", SourceKind::Flathub);
        direct.install = InstallMethod::Direct {
            url: "https://example.com/tool".to_owned(),
            checksum: None,
            arch: Some(Arch::X86_64),
        };
        let host = host(Os::Linux, Some(Arch::X86_64));
        assert_eq!(
            Registry::plan_update(&direct, &host),
            PlannedOp::Unsupported,
            "a direct update is a fresh install decision, not a manager verb"
        );
        assert_eq!(
            Registry::plan_uninstall(&direct, &host),
            PlannedOp::Unsupported,
            "a direct uninstall replays the manifest record's installed path"
        );
        assert_eq!(
            Registry::plan(&direct, &host),
            PlannedOp::DirectDownload {
                url: "https://example.com/tool".to_owned(),
                checksum: None,
            },
            "the install render is unchanged"
        );
    }
}
