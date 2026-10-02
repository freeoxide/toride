//! # Adapter boundary
//!
//! The [`Adapter`] trait is the seam between the external world and the
//! normalized model (DESIGN.md §3): every source-specific concern — wire
//! structs, endpoints, quirk handling, fetch clients — lives behind it, in
//! the per-source modules under [`sources`](crate::sources). Callers see
//! only [`App`] and [`SourceRef`].
//!
//! The trait follows the house async style:
//! `#[async_trait::async_trait]` + `Send + Sync` supertraits, matching
//! toride-installer's `ReleaseResolver`. [`Registry`] (DESIGN.md §3.3) is
//! the facade over `Vec<Arc<dyn Adapter>>`: error-tolerant search
//! fan-out, resolve merging sources, and [`Registry::plan`].

use std::sync::Arc;

use crate::error::{Error, Result, SourceFailure};
use crate::model::{
    App, Checksum, DistroFamily, InstallMethod, Os, Platform, SourceKind, SourceRef,
};

/// Normalizes one external repository into [`App`](crate::App)s.
///
/// Contract: ALL source-specific knowledge lives in the implementing
/// module — wire structs, endpoints, quirk handling. Callers see only
/// `App` and [`SourceRef`]. Each adapter additionally keeps its parse and
/// fetch halves strictly separated (DESIGN.md §3.1): only the fetch half
/// touches the network; only the parse half is fixture-tested offline.
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

    /// Consume the builder and produce the facade.
    #[must_use]
    pub fn build(self) -> Registry {
        Registry {
            adapters: self.adapters,
        }
    }
}

impl Registry {
    /// A facade over `adapters` (each an owned `Arc` or `Box`).
    #[must_use]
    pub fn new(adapters: impl IntoIterator<Item = impl Into<Arc<dyn Adapter>>>) -> Self {
        Self {
            adapters: adapters.into_iter().map(Into::into).collect(),
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

    /// Fan `query` out to every adapter; a failing source is recorded in
    /// [`SearchOutcome::failures`] without discarding the other sources'
    /// hits. Errors: [`Error::AllSourcesFailed`] when every registered
    /// source failed.
    pub async fn search(&self, query: &str) -> Result<SearchOutcome> {
        let mut apps = Vec::new();
        let mut failures = Vec::new();
        for adapter in &self.adapters {
            match adapter.search(query).await {
                Ok(hits) => apps.extend(hits),
                Err(error) => failures.push(SourceFailure {
                    source: adapter.source(),
                    error,
                }),
            }
        }
        all_failed(self.adapters.len(), query.to_owned(), failures)
            .map(|failures| SearchOutcome { apps, failures })
    }

    /// Resolve `id` through every adapter, merging the `sources` rows of
    /// every hit into one deduplicated list (empty = no source knows the
    /// id). Errors: [`Error::AllSourcesFailed`] when every registered
    /// source failed.
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
                Ok(Some(app)) => {
                    for row in app.sources {
                        let known = rows.iter().any(|existing| {
                            existing.source == row.source
                                && existing.id == row.id
                                && existing.repo == row.repo
                        });
                        if !known {
                            rows.push(row);
                        }
                    }
                }
                Ok(None) => {}
                Err(error) => failures.push(SourceFailure {
                    source: adapter.source(),
                    error,
                }),
            }
        }
        all_failed(self.adapters.len(), id.as_str().to_owned(), failures).map(|_| rows)
    }

    /// Render `app`'s install descriptor for `host` (DESIGN.md §3.3) —
    /// native-manager argv, checksummed direct-download fallback, or
    /// [`PlannedOp::Unsupported`]; empty `platforms` skip the claim check.
    #[must_use]
    pub fn plan(app: &App, host: &Platform) -> PlannedOp {
        let claimed = app.platforms.is_empty()
            || app.platforms.iter().any(|claim| claim_matches(claim, host));
        if claimed && method_covers_os(&app.install, host.os) {
            match &app.install {
                InstallMethod::Homebrew { cask, token } => {
                    let mut args = vec!["install".to_owned()];
                    if *cask {
                        args.push("--cask".to_owned());
                    }
                    args.push(token.clone());
                    PlannedOp::Command {
                        program: "brew".to_owned(),
                        args,
                    }
                }
                InstallMethod::Flatpak { app_id, remote } => PlannedOp::Command {
                    program: "flatpak".to_owned(),
                    args: vec![
                        "install".to_owned(),
                        "--user".to_owned(),
                        remote.clone(),
                        app_id.clone(),
                    ],
                },
                InstallMethod::Distro {
                    family, package, ..
                } => {
                    let (program, verb) = distro_install(*family);
                    PlannedOp::Command {
                        program,
                        args: vec![verb.to_owned(), package.to_owned()],
                    }
                }
                InstallMethod::Direct { url, checksum, .. } => PlannedOp::DirectDownload {
                    url: url.clone(),
                    checksum: checksum.clone(),
                },
            }
        } else {
            match app.direct_fallback(host.os, host.arch) {
                Some(InstallMethod::Direct { url, checksum, .. }) => {
                    PlannedOp::DirectDownload { url, checksum }
                }
                _ => PlannedOp::Unsupported,
            }
        }
    }
}

/// What [`Registry::plan`] says to do for one app on one host platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlannedOp {
    /// argv for the native manager (`brew`, `flatpak`, `apt`, …) —
    /// program first, the install argv only (no suppression flags; the
    /// executor layers those).
    Command {
        /// The manager binary to run.
        program: String,
        /// Its install arguments.
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
        InstallMethod::Homebrew { .. } => matches!(os, Os::MacOs | Os::Linux),
        InstallMethod::Flatpak { .. } | InstallMethod::Distro { .. } => os == Os::Linux,
        InstallMethod::Direct { .. } => true,
    }
}

fn distro_install(family: DistroFamily) -> (String, &'static str) {
    let (program, verb) = match family {
        DistroFamily::Debian | DistroFamily::Ubuntu => ("apt", "install"),
        DistroFamily::Fedora => ("dnf", "install"),
        DistroFamily::Arch => ("pacman", "--sync"),
        DistroFamily::Alpine => ("apk", "add"),
    };
    (program.to_owned(), verb)
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
        assert!(outcome.apps.is_empty());
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
        assert!(rows.is_empty());
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
}
