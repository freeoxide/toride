//! Integration tests for the [`Apps`] facade — end-to-end
//! resolve → plan → execute → record → verify per backend kind, entirely
//! offline: a strict [`FakeRunner`] scripts every backend command, a
//! fixture-backed [`Adapter`] plays the registry, and manifests live under
//! unique temp-dir paths. No network, no real commands.
//!
//! The fixture adapter's runtime reads follow the house convention
//! (conventions.md §7): everything is built in memory here — the adapters'
//! real fixture payloads live with their own crates/modules; these tests
//! exercise the FACADE's wiring, not the parsers.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use camino::Utf8PathBuf;
use toride_apps::apps::{
    AdoptProvenance, AppInstallOptions, AppUninstallOptions, AppUpdateOptions, Apps, AppsError,
    EnsureAppOutcome, UninstallAppOutcome, UpdateOutcome,
};
use toride_apps::backends::flatpak::FLATHUB_REPO_URL;
use toride_apps::backends::{DistroBackend, FlatpakBackend, HomebrewBackend};
use toride_apps::manifest::{
    InstallManifest, InstallRecord, ManifestError, ManifestResult, NativeIds, RecordSnapshot,
};
use toride_apps::runner::{CommandRunner, command};
use toride_apps::store::{RecordStore, StoreLoad};
use toride_apps::{AppStatus, BackendId, Target, Version};
use toride_registry::model::{App, InstallMethod, SourceKind, SourceRef};
use toride_registry::{Adapter, Availability, DistroFamily, TorideId};
use toride_runner::CommandOutput;
use toride_runner::CommandSpec;
use toride_runner::fake::FakeRunner;

// ---------------------------------------------------------------------------
// Fixture registry adapter
// ---------------------------------------------------------------------------

/// A fixture-backed registry adapter: resolves a lookup by exact app-id
/// match, searches by display-name substring, and records every lookup ref
/// so tests can pin exactly what the facade asked (source kind + slug).
struct FixtureAdapter {
    /// The source this adapter claims (drives the refs it receives).
    source: SourceKind,
    /// The adapter's catalog.
    apps: Vec<App>,
    /// Every lookup ref the adapter has seen, in order.
    seen: Mutex<Vec<SourceRef>>,
}

impl FixtureAdapter {
    /// An adapter over `apps` claiming `source`.
    fn new(source: SourceKind, apps: Vec<App>) -> Arc<Self> {
        Arc::new(Self {
            source,
            apps,
            seen: Mutex::new(Vec::new()),
        })
    }

    /// The lookup refs the facade has passed, in order.
    fn lookups(&self) -> Vec<SourceRef> {
        self.seen
            .lock()
            .expect("fixture adapter state poisoned")
            .clone()
    }
}

#[async_trait]
impl Adapter for FixtureAdapter {
    fn source(&self) -> SourceKind {
        self.source
    }

    async fn lookup(&self, id: &SourceRef) -> toride_registry::Result<Option<App>> {
        self.seen
            .lock()
            .expect("fixture adapter state poisoned")
            .push(id.clone());
        Ok(self
            .apps
            .iter()
            .find(|app| app.id.as_str() == id.id)
            .cloned())
    }

    async fn search(&self, query: &str) -> toride_registry::Result<Vec<App>> {
        let needle = query.to_lowercase();
        Ok(self
            .apps
            .iter()
            .filter(|app| app.name.to_lowercase().contains(&needle))
            .cloned()
            .collect())
    }
}

// ---------------------------------------------------------------------------
// Fixtures and helpers
// ---------------------------------------------------------------------------

/// Distinguishes test temp dirs within one process.
static DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A unique, never-before-used manifest path under the system temp dir,
/// with its parent directory created (the manifest's save creates parents
/// itself, but pre-seeding tests want the dir to exist).
fn temp_manifest_path(label: &str) -> Utf8PathBuf {
    let unique = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "toride-apps-facade-{}-{unique}-{label}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("unique temp dir is creatable");
    Utf8PathBuf::from_path_buf(dir.join("apps-manifest.json"))
        .expect("system temp dir is valid UTF-8")
}

/// A registry `App` fixture: id slug + display name + install method, no
/// platform claims (claim check skipped), available.
fn app(id: &str, name: &str, method: InstallMethod) -> App {
    App {
        id: TorideId::slugify(id),
        name: name.to_owned(),
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

fn id(slug: &str) -> TorideId {
    TorideId::slugify(slug)
}

/// Build a facade over the fake runner's seam, all three backends attached
/// (`new()` under fakes per the A2–A4 contract), the given target,
/// manifest path, and adapters.
fn facade(
    fake: &FakeRunner,
    target: Target,
    manifest_path: &Utf8PathBuf,
    adapters: Vec<Arc<dyn Adapter>>,
) -> Apps {
    let seam = CommandRunner::new(Arc::new(fake.clone()));
    Apps::builder()
        .runner(seam.clone())
        .target(target)
        .manifest_path(manifest_path)
        .homebrew(HomebrewBackend::new(seam.clone()))
        .flatpak(FlatpakBackend::new(seam.clone()))
        .distro(DistroBackend::new(DistroFamily::Debian, seam))
        .adapters(adapters)
        .build()
        .expect("facade builds over the fake seam")
}

/// A macOS target (cask country).
fn macos() -> Target {
    Target::macos(toride_apps::Arch::Aarch64)
}

/// A Linux target on `family`.
fn linux(family: DistroFamily) -> Target {
    Target::linux(toride_apps::Arch::X86_64, family)
}

// --- exact command specs (mirroring the backends' construction) ---------------

/// `brew info --json=v2 --installed` — the kind-agnostic presence listing
/// (trait-default status) the Foreign check rides.
fn brew_info_installed_spec() -> CommandSpec {
    command("brew", ["info", "--json=v2", "--installed"])
}

/// The kind-scoped version probe: `brew list --cask|--formula --versions`.
fn brew_versions_spec(kind_flag: &str, token: &str) -> CommandSpec {
    command("brew", ["list", kind_flag, "--versions", token])
}

fn brew_install_cask_spec(token: &str) -> CommandSpec {
    command("brew", ["install", "--cask", token])
}

fn brew_install_formula_spec(token: &str) -> CommandSpec {
    command("brew", ["install", token])
}

fn brew_uninstall_cask_spec(token: &str) -> CommandSpec {
    command("brew", ["uninstall", "--cask", token])
}

fn brew_uninstall_zap_spec(token: &str) -> CommandSpec {
    command("brew", ["uninstall", "--zap", token])
}

fn brew_uninstall_formula_spec(token: &str) -> CommandSpec {
    command("brew", ["uninstall", token])
}

/// The flatpak listing for a scope; `flag` is `None` for the unscoped
/// all-installations listing.
fn flatpak_list_spec(flag: Option<&str>) -> CommandSpec {
    let mut args = vec!["list"];
    if let Some(flag) = flag {
        args.push(flag);
    }
    args.push("--app");
    args.push("--columns=application,version,origin,installation");
    command("flatpak", args)
}

fn flatpak_remotes_spec() -> CommandSpec {
    command("flatpak", ["remotes", "--user", "--columns=name"])
}

fn flatpak_remote_add_spec() -> CommandSpec {
    command(
        "flatpak",
        [
            "remote-add",
            "--user",
            "--if-not-exists",
            "flathub",
            FLATHUB_REPO_URL,
        ],
    )
}

fn flatpak_install_user_spec(app_ref: &str) -> CommandSpec {
    command(
        "flatpak",
        [
            "install",
            "--user",
            "--or-update",
            "--noninteractive",
            "flathub",
            app_ref,
        ],
    )
}

fn flatpak_uninstall_user_spec(app_id: &str) -> CommandSpec {
    command(
        "flatpak",
        ["uninstall", "--user", "--noninteractive", app_id],
    )
}

fn apt_get_spec(verb: &str, package: &str) -> CommandSpec {
    command("apt-get", [verb, "-y", package]).env("DEBIAN_FRONTEND", "noninteractive")
}

fn dnf_spec(verb: &str, package: &str) -> CommandSpec {
    command("dnf", [verb, "-y", package])
}

fn dpkg_query_spec(package: &str) -> CommandSpec {
    command(
        "dpkg-query",
        [
            "--show",
            // The format escapes travel literally (dpkg-query expands
            // them) — the same bytes the backend's spec carries.
            "--showformat=${db:Status-Abbrev}${Package}\\t${Version}\\n",
            package,
        ],
    )
    .env("LC_ALL", "C")
}

fn rpm_query_spec(package: &str) -> CommandSpec {
    command(
        "rpm",
        [
            "--query",
            "--queryformat",
            "%{NAME}\\t%{VERSION}\\n",
            package,
        ],
    )
    .env("LC_ALL", "C")
}

fn pacman_spec(verb: &str, package: &str) -> CommandSpec {
    command("pacman", [verb, "--noconfirm", package])
}

fn pacman_query_spec(package: &str) -> CommandSpec {
    command("pacman", ["--query", package]).env("LC_ALL", "C")
}

fn apk_spec(verb: &str, package: &str) -> CommandSpec {
    command("apk", [verb, package])
}

fn apk_query_spec(package: &str) -> CommandSpec {
    command("apk", ["list", "--installed", "--quiet", package]).env("LC_ALL", "C")
}

fn brew_outdated_spec(scope_flag: &str) -> CommandSpec {
    command("brew", ["outdated", scope_flag, "--json=v2"])
}

fn brew_upgrade_cask_spec(token: &str) -> CommandSpec {
    command("brew", ["upgrade", "--cask", token])
}

fn brew_info_token_spec(token: &str) -> CommandSpec {
    command("brew", ["info", "--json=v2", token])
}

fn apt_get_update_spec(package: &str) -> CommandSpec {
    command("apt-get", ["install", "--only-upgrade", "-y", package])
        .env("DEBIAN_FRONTEND", "noninteractive")
}

fn flatpak_update_user_spec(app_id: &str) -> CommandSpec {
    command("flatpak", ["update", "--user", "--noninteractive", app_id])
}

// --- canned outputs -------------------------------------------------------------

/// An empty `brew info --json=v2 --installed` envelope: nothing installed.
const EMPTY_BREW_INFO: &str = r#"{"formulae":[],"casks":[]}"#;

/// The same envelope carrying the firefox cask, installed.
const FIREFOX_CASK_INFO: &str =
    r#"{"formulae":[],"casks":[{"token":"firefox","version":"138.0","installed":"138.0"}]}"#;

/// brew's silent absent-token signal: exit 1, empty stdout and stderr.
fn brew_silent_absent() -> CommandOutput {
    CommandOutput::from_stderr("", 1)
}

/// dpkg-query's not-found answer: exit 1 + its marker line on stderr.
fn dpkg_not_found(package: &str) -> CommandOutput {
    CommandOutput::from_stderr(
        format!("dpkg-query: no packages found matching {package}"),
        1,
    )
}

/// rpm's not-found answer: a nonzero exit + the marker line on stderr.
fn rpm_not_found(package: &str) -> CommandOutput {
    CommandOutput::from_stderr(format!("package {package} is not installed"), 1)
}

/// pacman's not-found answer: exit 1 + `error: package '<pkg>' was not
/// found` on stderr (`src/pacman/query.c`).
fn pacman_not_found(package: &str) -> CommandOutput {
    CommandOutput::from_stderr(format!("error: package '{package}' was not found"), 1)
}

/// apk's not-found answer: an empty exit-0 listing (`src/app_list.c`).
fn apk_not_found() -> CommandOutput {
    CommandOutput::from_stdout("")
}

/// flatpak's typed absent-uninstall answer for an app id: exit 1 + the
/// `error:` line with the curly-quoted id.
fn flatpak_not_installed_error(app_id: &str) -> CommandOutput {
    CommandOutput::from_stderr(
        format!("error: No installed refs found for \u{2018}{app_id}\u{2019}"),
        1,
    )
}

/// One installed flatpak app row (tab-separated, headerless).
fn flatpak_row(app_id: &str, version: &str) -> String {
    format!("{app_id}\t{version}\tflathub\tuser\n")
}

/// A `brew outdated --json=v2` envelope listing the firefox cask stale at
/// `installed` with `current` available.
fn firefox_cask_outdated(installed: &str, current: &str) -> String {
    format!(
        r#"{{"formulae":[],"casks":[{{"name":"firefox","installed_versions":["{installed}"],"current_version":"{current}"}}]}}"#
    )
}

/// A `brew info --json=v2 firefox` envelope as brew emits it for an
/// installed token: `installed` is what brew has on disk, `version` the
/// cask's offered version — the available probe must answer with the
/// latter.
fn firefox_cask_available(installed: &str, offered: &str) -> String {
    format!(
        r#"{{"formulae":[],"casks":[{{"token":"firefox","version":"{offered}","installed":"{installed}"}}]}}"#
    )
}

/// Assert a recorded call matches `expected` on program + args
/// (`CommandSpec` carries no `PartialEq`; these scripted probes are all
/// env-less, so argv equality is the exact-match dimension that matters).
fn assert_call_is(call: &CommandSpec, expected: &CommandSpec) {
    assert_eq!(call.program, expected.program, "{call:?}");
    assert_eq!(call.args, expected.args, "{call:?}");
}

// ---------------------------------------------------------------------------
// Homebrew cask — install, record, re-ensure
// ---------------------------------------------------------------------------

/// The world after one successful cask install of firefox: facade, fake,
/// manifest path, and the adapter (for lookup-ref pins). Asserts the
/// install itself took the Installed path with a verified version.
async fn cask_installed_world() -> (Apps, FakeRunner, Utf8PathBuf, Arc<FixtureAdapter>) {
    let path = temp_manifest_path("cask-installed");
    let fake = FakeRunner::new()
        .strict()
        .respond(
            brew_info_installed_spec(),
            CommandOutput::from_stdout(EMPTY_BREW_INFO),
        )
        .respond(
            brew_install_cask_spec("firefox"),
            CommandOutput::from_stdout(""),
        )
        // The backend's own post-install probe, then the facade's verify.
        .respond(
            brew_versions_spec("--cask", "firefox"),
            CommandOutput::from_stdout("firefox 138.0.1"),
        )
        .respond(
            brew_versions_spec("--cask", "firefox"),
            CommandOutput::from_stdout("firefox 138.0.1"),
        );
    let adapter = FixtureAdapter::new(
        SourceKind::HomebrewCask,
        vec![app(
            "firefox",
            "Firefox",
            InstallMethod::Homebrew {
                cask: true,
                token: "firefox".to_owned(),
            },
        )],
    );
    let mut apps = facade(&fake, macos(), &path, vec![adapter.clone()]);
    let outcome = apps
        .ensure_installed(&id("firefox"), AppInstallOptions::new())
        .await
        .expect("cask install succeeds");
    assert!(
        matches!(
            &outcome,
            EnsureAppOutcome::Installed {
                backend: BackendId::Homebrew,
                verified: true,
                warning: None,
                ..
            }
        ),
        "{outcome:?}"
    );
    (apps, fake, path, adapter)
}

#[tokio::test]
async fn ensure_installed_brew_cask_installs_records_and_persists_the_manifest() {
    let (_apps, fake, path, adapter) = cask_installed_world().await;

    // The facade asked the adapter for its OWN source kind + the slug.
    let lookups = adapter.lookups();
    assert_eq!(lookups.len(), 1, "{lookups:?}");
    assert_eq!(lookups[0].source, SourceKind::HomebrewCask);
    assert_eq!(lookups[0].id, "firefox");

    // The planned install argv reached the seam, exactly once.
    fake.assert_called_with(&brew_install_cask_spec("firefox"));
    fake.assert_no_unmatched_calls();

    // The manifest FILE carries token + kind + verified version, keyed by
    // the app id, under the homebrew backend.
    let document: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(path.as_std_path()).expect("manifest file written"),
    )
    .expect("manifest file is JSON");
    assert_eq!(document["version"], serde_json::json!(1));
    assert_eq!(
        document["apps"]["firefox"]["ids"]["Homebrew"]["token"],
        serde_json::json!("firefox")
    );
    assert_eq!(
        document["apps"]["firefox"]["ids"]["Homebrew"]["cask"],
        serde_json::json!(true)
    );
    assert_eq!(
        document["apps"]["firefox"]["version"],
        serde_json::json!("138.0.1")
    );

    // And it reloads through the strict loader with the same story.
    let reloaded = InstallManifest::load(&path).expect("manifest reloads");
    let record = reloaded
        .get(&id("firefox"))
        .expect("record keyed by app id");
    assert_eq!(
        record.ids,
        NativeIds::Homebrew {
            token: "firefox".to_owned(),
            cask: true,
        }
    );
    assert_eq!(record.backend, BackendId::Homebrew);
    assert_eq!(record.version.as_deref(), Some("138.0.1"));
}

#[tokio::test]
async fn a_second_ensure_installed_is_already_present_with_no_new_mutating_calls() {
    let path = temp_manifest_path("second-ensure");
    // The install flow's four responses, plus ONE more for the second
    // call's confirming probe (exact responses are consumed once each).
    let fake = FakeRunner::new()
        .strict()
        .respond(
            brew_info_installed_spec(),
            CommandOutput::from_stdout(EMPTY_BREW_INFO),
        )
        .respond(
            brew_install_cask_spec("firefox"),
            CommandOutput::from_stdout(""),
        )
        .respond(
            brew_versions_spec("--cask", "firefox"),
            CommandOutput::from_stdout("firefox 138.0.1"),
        )
        .respond(
            brew_versions_spec("--cask", "firefox"),
            CommandOutput::from_stdout("firefox 138.0.1"),
        )
        .respond(
            brew_versions_spec("--cask", "firefox"),
            CommandOutput::from_stdout("firefox 138.0.1"),
        );
    let adapter = FixtureAdapter::new(
        SourceKind::HomebrewCask,
        vec![app(
            "firefox",
            "Firefox",
            InstallMethod::Homebrew {
                cask: true,
                token: "firefox".to_owned(),
            },
        )],
    );
    let mut apps = facade(&fake, macos(), &path, vec![adapter.clone()]);
    apps.ensure_installed(&id("firefox"), AppInstallOptions::new())
        .await
        .expect("first install succeeds");
    let calls_after_install = fake.calls().len();
    let adapter_lookups_after_install = adapter.lookups().len();

    let outcome = apps
        .ensure_installed(&id("firefox"), AppInstallOptions::new())
        .await
        .expect("second ensure succeeds");

    // AlreadyPresent, at the freshly probed version.
    assert_eq!(
        outcome,
        EnsureAppOutcome::AlreadyPresent(AppStatus::Installed {
            backend: BackendId::Homebrew,
            version: Some("138.0.1".to_owned()),
        })
    );
    // Exactly ONE new runner call — the kind-scoped confirming probe — and
    // zero mutating ones (the detect-before-resolve path reuses local
    // state only).
    let calls = fake.calls();
    assert_eq!(calls.len(), calls_after_install + 1, "{calls:?}");
    assert_call_is(
        calls.last().expect("one new call"),
        &brew_versions_spec("--cask", "firefox"),
    );
    // And ZERO registry adapter calls: the AlreadyPresent path answers
    // from the manifest + probe alone, never re-consulting the registry
    // (the doc's "zero registry adapter calls" claim, pinned).
    assert_eq!(
        adapter.lookups().len(),
        adapter_lookups_after_install,
        "the AlreadyPresent path must not resolve through the registry"
    );
    fake.assert_no_unmatched_calls();
}

#[tokio::test]
async fn ensure_installed_brew_formula_installs_records_and_persists_the_manifest() {
    // The formula half of the brew matrix: no `--cask` anywhere, the
    // kind-scoped probes carry `--formula`, and the record's cask flag
    // reads false.
    let path = temp_manifest_path("formula-installed");
    let fake = FakeRunner::new()
        .strict()
        .respond(
            brew_info_installed_spec(),
            CommandOutput::from_stdout(EMPTY_BREW_INFO),
        )
        .respond(
            brew_install_formula_spec("ripgrep"),
            CommandOutput::from_stdout(""),
        )
        // The backend's own post-install probe, then the facade's verify.
        .respond(
            brew_versions_spec("--formula", "ripgrep"),
            CommandOutput::from_stdout("ripgrep 14.1.0"),
        )
        .respond(
            brew_versions_spec("--formula", "ripgrep"),
            CommandOutput::from_stdout("ripgrep 14.1.0"),
        );
    let adapter = FixtureAdapter::new(
        SourceKind::HomebrewFormula,
        vec![app(
            "ripgrep",
            "ripgrep",
            InstallMethod::Homebrew {
                cask: false,
                token: "ripgrep".to_owned(),
            },
        )],
    );
    let mut apps = facade(&fake, macos(), &path, vec![adapter]);

    let outcome = apps
        .ensure_installed(&id("ripgrep"), AppInstallOptions::new())
        .await
        .expect("formula install succeeds");

    let EnsureAppOutcome::Installed {
        backend,
        ids,
        version,
        verified,
        warning,
    } = outcome
    else {
        panic!("expected Installed, got {outcome:?}");
    };
    assert_eq!(backend, BackendId::Homebrew);
    assert_eq!(
        ids,
        NativeIds::Homebrew {
            token: "ripgrep".to_owned(),
            cask: false,
        }
    );
    assert_eq!(version.as_deref(), Some("14.1.0"));
    assert!(verified);
    assert_eq!(warning, None);

    fake.assert_called_with(&brew_install_formula_spec("ripgrep"));
    fake.assert_no_unmatched_calls();

    // The manifest FILE records the FORMULA kind (cask: false) and the
    // verified version.
    let document: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(path.as_std_path()).expect("manifest file written"),
    )
    .expect("manifest file is JSON");
    assert_eq!(
        document["apps"]["ripgrep"]["ids"]["Homebrew"]["token"],
        serde_json::json!("ripgrep")
    );
    assert_eq!(
        document["apps"]["ripgrep"]["ids"]["Homebrew"]["cask"],
        serde_json::json!(false),
        "the record names the formula kind"
    );
    assert_eq!(
        document["apps"]["ripgrep"]["version"],
        serde_json::json!("14.1.0")
    );
}

// ---------------------------------------------------------------------------
// Flatpak — remote ensure, install, scope recorded
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ensure_installed_flatpak_ensures_the_flathub_remote_then_installs_and_records_the_scope() {
    let path = temp_manifest_path("flatpak-install");
    // The Foreign check rides the unscoped all-installations listing.
    let fake = FakeRunner::new()
        .strict()
        .respond(flatpak_list_spec(None), CommandOutput::from_stdout(""))
        // Remote ensure: remotes probe says flathub is absent → remote-add.
        .respond(flatpak_remotes_spec(), CommandOutput::from_stdout(""))
        .respond(flatpak_remote_add_spec(), CommandOutput::from_stdout(""))
        .respond(
            flatpak_install_user_spec("app/com.brave.Browser/x86_64/stable"),
            CommandOutput::from_stdout(""),
        )
        // Backend post-verify + facade verify (both the user-scoped list).
        .respond(
            flatpak_list_spec(Some("--user")),
            CommandOutput::from_stdout(flatpak_row("com.brave.Browser", "1.2.3")),
        )
        .respond(
            flatpak_list_spec(Some("--user")),
            CommandOutput::from_stdout(flatpak_row("com.brave.Browser", "1.2.3")),
        );
    let adapter = FixtureAdapter::new(
        SourceKind::Flathub,
        vec![app(
            "brave",
            "Brave Browser",
            InstallMethod::Flatpak {
                app_id: "com.brave.Browser".to_owned(),
                remote: "flathub".to_owned(),
            },
        )],
    );
    let mut apps = facade(&fake, linux(DistroFamily::Debian), &path, vec![adapter]);

    let outcome = apps
        .ensure_installed(&id("brave"), AppInstallOptions::new())
        .await
        .expect("flatpak install succeeds");

    let EnsureAppOutcome::Installed {
        backend,
        ids,
        version,
        verified,
        warning,
    } = outcome
    else {
        panic!("expected Installed, got {outcome:?}");
    };
    assert_eq!(backend, BackendId::Flatpak);
    assert_eq!(
        ids,
        NativeIds::Flatpak {
            app_id: "com.brave.Browser".to_owned(),
            // The EXECUTED ref, verbatim — never re-derived.
            app_ref: Some("app/com.brave.Browser/x86_64/stable".to_owned()),
            installation: toride_apps::FlatpakInstallation::User,
        }
    );
    assert_eq!(version.as_deref(), Some("1.2.3"));
    assert!(verified);
    assert_eq!(warning, None);

    // Both remote-ensure commands and the install reached the seam.
    fake.assert_called_with(&flatpak_remote_add_spec());
    fake.assert_called_with(&flatpak_install_user_spec(
        "app/com.brave.Browser/x86_64/stable",
    ));
    fake.assert_no_unmatched_calls();

    // The persisted record carries the user scope.
    let reloaded = InstallManifest::load(&path).expect("manifest reloads");
    let record = reloaded.get(&id("brave")).expect("record keyed by app id");
    let NativeIds::Flatpak {
        installation,
        app_ref,
        ..
    } = &record.ids
    else {
        panic!("flatpak record: {:?}", record.ids);
    };
    assert_eq!(*installation, toride_apps::FlatpakInstallation::User);
    assert_eq!(
        app_ref.as_deref(),
        Some("app/com.brave.Browser/x86_64/stable")
    );
}

#[tokio::test]
async fn ensure_installed_flatpak_skips_the_remote_add_when_flathub_is_configured() {
    let path = temp_manifest_path("flatpak-remote-present");
    let fake = FakeRunner::new()
        .strict()
        .respond(flatpak_list_spec(None), CommandOutput::from_stdout(""))
        // The remotes probe already lists flathub → no remote-add.
        .respond(
            flatpak_remotes_spec(),
            CommandOutput::from_stdout("flathub\n"),
        )
        .respond(
            flatpak_install_user_spec("app/com.brave.Browser/x86_64/stable"),
            CommandOutput::from_stdout(""),
        )
        .respond(
            flatpak_list_spec(Some("--user")),
            CommandOutput::from_stdout(flatpak_row("com.brave.Browser", "1.2.3")),
        )
        .respond(
            flatpak_list_spec(Some("--user")),
            CommandOutput::from_stdout(flatpak_row("com.brave.Browser", "1.2.3")),
        );
    let adapter = FixtureAdapter::new(
        SourceKind::Flathub,
        vec![app(
            "brave",
            "Brave Browser",
            InstallMethod::Flatpak {
                app_id: "com.brave.Browser".to_owned(),
                remote: "flathub".to_owned(),
            },
        )],
    );
    let mut apps = facade(&fake, linux(DistroFamily::Debian), &path, vec![adapter]);

    let outcome = apps
        .ensure_installed(&id("brave"), AppInstallOptions::new())
        .await
        .expect("flatpak install succeeds");
    assert!(matches!(outcome, EnsureAppOutcome::Installed { .. }));

    let calls = fake.calls();
    let remote_adds = calls.iter().filter(|call| {
        call.program == "flatpak" && call.args.first().is_some_and(|a| a == "remote-add")
    });
    assert_eq!(remote_adds.count(), 0, "no remote-add may run");
    fake.assert_no_unmatched_calls();
}

// ---------------------------------------------------------------------------
// Distro — elevation refusal, grant, dpkg/rpm post-verify
// ---------------------------------------------------------------------------

fn brave_distro_app(family: DistroFamily) -> App {
    app(
        "brave",
        "Brave Browser",
        InstallMethod::Distro {
            family,
            repo: None,
            package: "brave-browser".to_owned(),
        },
    )
}

#[tokio::test]
async fn ensure_installed_distro_refuses_without_an_elevation_grant_and_never_dispatches() {
    let path = temp_manifest_path("distro-refusal");
    let fake = FakeRunner::new()
        .strict()
        // The Foreign check's dpkg-query: not found → NotInstalled.
        .respond(
            dpkg_query_spec("brave-browser"),
            dpkg_not_found("brave-browser"),
        );
    let adapter = FixtureAdapter::new(
        SourceKind::Distro,
        vec![brave_distro_app(DistroFamily::Debian)],
    );
    let mut apps = facade(&fake, linux(DistroFamily::Debian), &path, vec![adapter]);

    let error = apps
        .ensure_installed(&id("brave"), AppInstallOptions::new())
        .await
        .expect_err("distro installs require an elevation grant");
    assert!(
        matches!(
            error,
            AppsError::Backend(ref inner) if matches!(inner, toride_apps::Error::ElevationRequired { .. })
        ),
        "{error:?}"
    );

    // Exactly one call ran — the Foreign-check query. No manager command.
    let calls = fake.calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert_call_is(&calls[0], &dpkg_query_spec("brave-browser"));
    fake.assert_no_unmatched_calls();
}

#[tokio::test]
async fn ensure_installed_distro_with_the_grant_installs_and_post_verifies_via_dpkg_query() {
    let path = temp_manifest_path("distro-grant");
    let fake = FakeRunner::new()
        .strict()
        .respond(
            dpkg_query_spec("brave-browser"),
            dpkg_not_found("brave-browser"),
        )
        .respond(
            apt_get_spec("install", "brave-browser"),
            CommandOutput::from_stdout(""),
        )
        // Backend post-verify + facade verify.
        .respond(
            dpkg_query_spec("brave-browser"),
            CommandOutput::from_stdout("ii brave-browser\t1.4.2\n"),
        )
        .respond(
            dpkg_query_spec("brave-browser"),
            CommandOutput::from_stdout("ii brave-browser\t1.4.2\n"),
        );
    let adapter = FixtureAdapter::new(
        SourceKind::Distro,
        vec![brave_distro_app(DistroFamily::Debian)],
    );
    let mut apps = facade(&fake, linux(DistroFamily::Debian), &path, vec![adapter]);

    let outcome = apps
        .ensure_installed(&id("brave"), AppInstallOptions::new().elevated(true))
        .await
        .expect("granted distro install succeeds");

    let EnsureAppOutcome::Installed {
        backend,
        ids,
        version,
        verified,
        warning,
    } = outcome
    else {
        panic!("expected Installed, got {outcome:?}");
    };
    assert_eq!(backend, BackendId::Distro(DistroFamily::Debian));
    assert_eq!(
        ids,
        NativeIds::Distro {
            package: "brave-browser".to_owned(),
            family: DistroFamily::Debian,
        }
    );
    assert_eq!(version.as_deref(), Some("1.4.2"));
    assert!(verified);
    assert_eq!(warning, None);

    fake.assert_called_with(&apt_get_spec("install", "brave-browser"));
    fake.assert_no_unmatched_calls();

    // The persisted record keeps the elevation requirement the plan
    // carried (the record's source note).
    let reloaded = InstallManifest::load(&path).expect("manifest reloads");
    let record = reloaded.get(&id("brave")).expect("record present");
    assert!(
        record
            .plan
            .as_ref()
            .is_some_and(|plan| plan.requires_elevation)
    );
    assert_eq!(record.version.as_deref(), Some("1.4.2"));
}

#[tokio::test]
async fn ensure_installed_dnf_with_the_grant_installs_and_post_verifies_via_rpm() {
    let path = temp_manifest_path("dnf-grant");
    let fake = FakeRunner::new()
        .strict()
        .respond(
            rpm_query_spec("brave-browser"),
            rpm_not_found("brave-browser"),
        )
        .respond(
            dnf_spec("install", "brave-browser"),
            CommandOutput::from_stdout(""),
        )
        .respond(
            rpm_query_spec("brave-browser"),
            CommandOutput::from_stdout("brave-browser\t1.4.2\n"),
        )
        .respond(
            rpm_query_spec("brave-browser"),
            CommandOutput::from_stdout("brave-browser\t1.4.2\n"),
        );
    let adapter = FixtureAdapter::new(
        SourceKind::Distro,
        vec![brave_distro_app(DistroFamily::Fedora)],
    );
    // A Fedora-family distro backend executes dnf + rpm.
    let seam = CommandRunner::new(Arc::new(fake.clone()));
    let mut apps = Apps::builder()
        .runner(seam.clone())
        .target(linux(DistroFamily::Fedora))
        .manifest_path(&path)
        .homebrew(HomebrewBackend::new(seam.clone()))
        .flatpak(FlatpakBackend::new(seam.clone()))
        .distro(DistroBackend::new(DistroFamily::Fedora, seam))
        .adapter(adapter)
        .build()
        .expect("facade builds");

    let outcome = apps
        .ensure_installed(&id("brave"), AppInstallOptions::new().elevated(true))
        .await
        .expect("granted dnf install succeeds");
    let EnsureAppOutcome::Installed {
        backend,
        version,
        verified,
        ..
    } = outcome
    else {
        panic!("expected Installed, got {outcome:?}");
    };
    assert_eq!(backend, BackendId::Distro(DistroFamily::Fedora));
    assert_eq!(version.as_deref(), Some("1.4.2"));
    assert!(verified);
    fake.assert_called_with(&dnf_spec("install", "brave-browser"));
    fake.assert_no_unmatched_calls();
}

#[tokio::test]
async fn ensure_installed_pacman_with_the_grant_installs_and_post_verifies_via_pacman_query() {
    let path = temp_manifest_path("pacman-grant");
    let fake = FakeRunner::new()
        .strict()
        .respond(
            pacman_query_spec("brave-browser"),
            pacman_not_found("brave-browser"),
        )
        .respond(
            pacman_spec("--sync", "brave-browser"),
            CommandOutput::from_stdout(""),
        )
        // Backend post-verify + facade verify.
        .respond(
            pacman_query_spec("brave-browser"),
            CommandOutput::from_stdout("brave-browser 1.4.2-1\n"),
        )
        .respond(
            pacman_query_spec("brave-browser"),
            CommandOutput::from_stdout("brave-browser 1.4.2-1\n"),
        );
    let adapter = FixtureAdapter::new(
        SourceKind::Distro,
        vec![brave_distro_app(DistroFamily::Arch)],
    );
    let seam = CommandRunner::new(Arc::new(fake.clone()));
    let mut apps = Apps::builder()
        .runner(seam.clone())
        .target(linux(DistroFamily::Arch))
        .manifest_path(&path)
        .homebrew(HomebrewBackend::new(seam.clone()))
        .flatpak(FlatpakBackend::new(seam.clone()))
        .distro(DistroBackend::new(DistroFamily::Arch, seam))
        .adapter(adapter)
        .build()
        .expect("facade builds");

    let outcome = apps
        .ensure_installed(&id("brave"), AppInstallOptions::new().elevated(true))
        .await
        .expect("granted pacman install succeeds");
    let EnsureAppOutcome::Installed {
        backend,
        ids,
        version,
        verified,
        warning,
    } = outcome
    else {
        panic!("expected Installed, got {outcome:?}");
    };
    assert_eq!(backend, BackendId::Distro(DistroFamily::Arch));
    assert_eq!(
        ids,
        NativeIds::Distro {
            package: "brave-browser".to_owned(),
            family: DistroFamily::Arch,
        }
    );
    assert_eq!(version.as_deref(), Some("1.4.2-1"));
    assert!(verified);
    assert_eq!(warning, None);
    fake.assert_called_with(&pacman_spec("--sync", "brave-browser"));
    fake.assert_no_unmatched_calls();
}

#[tokio::test]
async fn ensure_installed_apk_with_the_grant_installs_and_records_without_a_version() {
    let path = temp_manifest_path("apk-grant");
    let fake = FakeRunner::new()
        .strict()
        .respond(apk_query_spec("brave-browser"), apk_not_found())
        .respond(
            apk_spec("add", "brave-browser"),
            CommandOutput::from_stdout(""),
        )
        .respond(
            apk_query_spec("brave-browser"),
            CommandOutput::from_stdout("brave-browser\n"),
        )
        .respond(
            apk_query_spec("brave-browser"),
            CommandOutput::from_stdout("brave-browser\n"),
        );
    let adapter = FixtureAdapter::new(
        SourceKind::Distro,
        vec![brave_distro_app(DistroFamily::Alpine)],
    );
    let seam = CommandRunner::new(Arc::new(fake.clone()));
    let mut apps = Apps::builder()
        .runner(seam.clone())
        .target(linux(DistroFamily::Alpine))
        .manifest_path(&path)
        .homebrew(HomebrewBackend::new(seam.clone()))
        .flatpak(FlatpakBackend::new(seam.clone()))
        .distro(DistroBackend::new(DistroFamily::Alpine, seam))
        .adapter(adapter)
        .build()
        .expect("facade builds");

    let outcome = apps
        .ensure_installed(&id("brave"), AppInstallOptions::new().elevated(true))
        .await
        .expect("granted apk install succeeds");
    let EnsureAppOutcome::Installed {
        backend,
        version,
        verified,
        ..
    } = outcome
    else {
        panic!("expected Installed, got {outcome:?}");
    };
    assert_eq!(backend, BackendId::Distro(DistroFamily::Alpine));
    assert_eq!(
        version, None,
        "apk's listing carries no version — present, not failed"
    );
    assert!(
        verified,
        "the post-verify confirms presence even without a version"
    );
    fake.assert_called_with(&apk_spec("add", "brave-browser"));
    fake.assert_no_unmatched_calls();
}

// ---------------------------------------------------------------------------
// Uninstall — record-sourced, zap, Foreign refusal + force, absent
// ---------------------------------------------------------------------------

/// Seed a manifest file with a toride-style cask install record for
/// firefox, and return the path.
fn seed_cask_record(path: &Utf8PathBuf, token: &str) {
    let mut manifest = InstallManifest::at(path);
    manifest.record(
        &id("firefox"),
        InstallRecord::new(
            toride_apps::InstallPlan {
                app: id("firefox"),
                backend: BackendId::Homebrew,
                operation: toride_apps::Operation::BrewInstall {
                    cask: true,
                    token: token.to_owned(),
                },
                dry_run: false,
                requires_elevation: false,
            },
            NativeIds::Homebrew {
                token: token.to_owned(),
                cask: true,
            },
            Some("138.0.1".to_owned()),
        )
        .with_installed_at(1_700_000_000),
    );
    manifest.save().expect("seed manifest saves");
}

/// Seed a formula record for ripgrep.
fn seed_formula_record(path: &Utf8PathBuf, token: &str) {
    let mut manifest = InstallManifest::at(path);
    manifest.record(
        &id("ripgrep"),
        InstallRecord::new(
            toride_apps::InstallPlan {
                app: id("ripgrep"),
                backend: BackendId::Homebrew,
                operation: toride_apps::Operation::BrewInstall {
                    cask: false,
                    token: token.to_owned(),
                },
                dry_run: false,
                requires_elevation: false,
            },
            NativeIds::Homebrew {
                token: token.to_owned(),
                cask: false,
            },
            None,
        )
        .with_installed_at(1_700_000_000),
    );
    manifest.save().expect("seed manifest saves");
}

/// Seed a distro record: the brave-browser apt package on Debian, with
/// the elevation requirement every distro plan carries.
fn seed_distro_record(path: &Utf8PathBuf) {
    let mut manifest = InstallManifest::at(path);
    manifest.record(
        &id("brave"),
        InstallRecord::new(
            toride_apps::InstallPlan {
                app: id("brave"),
                backend: BackendId::Distro(DistroFamily::Debian),
                operation: toride_apps::Operation::DistroInstall {
                    manager: toride_apps::PackageManager::Apt,
                    package: "brave-browser".to_owned(),
                },
                dry_run: false,
                requires_elevation: true,
            },
            NativeIds::Distro {
                package: "brave-browser".to_owned(),
                family: DistroFamily::Debian,
            },
            Some("1.4.2".to_owned()),
        )
        .with_installed_at(1_700_000_000),
    );
    manifest.save().expect("seed manifest saves");
}

#[tokio::test]
async fn uninstall_runs_the_record_ids_removes_and_clears_the_manifest_record() {
    let path = temp_manifest_path("uninstall-cask");
    seed_cask_record(&path, "firefox");
    let fake = FakeRunner::new()
        .strict()
        .respond(
            brew_uninstall_cask_spec("firefox"),
            CommandOutput::from_stdout(""),
        )
        // Post-uninstall verify: the silent absent signal.
        .respond(
            brew_versions_spec("--cask", "firefox"),
            brew_silent_absent(),
        );
    let adapter = FixtureAdapter::new(SourceKind::HomebrewCask, Vec::new());
    let mut apps = facade(&fake, macos(), &path, vec![adapter]);

    let outcome = apps
        .uninstall(&id("firefox"), AppUninstallOptions::new())
        .await
        .expect("record-sourced uninstall succeeds");

    assert_eq!(
        outcome,
        UninstallAppOutcome::Removed {
            backend: BackendId::Homebrew,
            ids: NativeIds::Homebrew {
                token: "firefox".to_owned(),
                cask: true,
            },
            warning: None,
        }
    );
    fake.assert_called_with(&brew_uninstall_cask_spec("firefox"));
    fake.assert_no_unmatched_calls();

    // The record is gone from the FILE (not just memory).
    let reloaded = InstallManifest::load(&path).expect("manifest reloads");
    assert!(
        reloaded.get(&id("firefox")).is_none(),
        "the record must be removed"
    );
}

#[tokio::test]
async fn uninstall_with_zap_runs_the_zap_argv_for_a_recorded_cask_only() {
    let path = temp_manifest_path("uninstall-zap");
    seed_cask_record(&path, "firefox");
    let fake = FakeRunner::new()
        .strict()
        .respond(
            brew_uninstall_zap_spec("firefox"),
            CommandOutput::from_stdout(""),
        )
        .respond(
            brew_versions_spec("--cask", "firefox"),
            brew_silent_absent(),
        );
    let adapter = FixtureAdapter::new(SourceKind::HomebrewCask, Vec::new());
    let mut apps = facade(&fake, macos(), &path, vec![adapter]);

    let outcome = apps
        .uninstall(&id("firefox"), AppUninstallOptions::new().zap(true))
        .await
        .expect("zap uninstall succeeds");
    assert!(matches!(
        outcome,
        UninstallAppOutcome::Removed { warning: None, .. }
    ));
    fake.assert_called_with(&brew_uninstall_zap_spec("firefox"));
    fake.assert_no_unmatched_calls();

    // The formula counterpart: zap degrades to a plain uninstall.
    let path = temp_manifest_path("uninstall-zap-formula");
    seed_formula_record(&path, "ripgrep");
    let fake = FakeRunner::new()
        .strict()
        .respond(
            brew_uninstall_formula_spec("ripgrep"),
            CommandOutput::from_stdout(""),
        )
        .respond(
            brew_versions_spec("--formula", "ripgrep"),
            brew_silent_absent(),
        );
    let adapter = FixtureAdapter::new(SourceKind::HomebrewFormula, Vec::new());
    let mut apps = facade(&fake, macos(), &path, vec![adapter]);
    apps.uninstall(&id("ripgrep"), AppUninstallOptions::new().zap(true))
        .await
        .expect("formula zap degrades to plain uninstall");
    fake.assert_called_with(&brew_uninstall_formula_spec("ripgrep"));
    fake.assert_no_unmatched_calls();
}

#[tokio::test]
async fn uninstall_of_a_flatpak_record_survives_an_already_absent_target() {
    // flatpak's absent-target uninstall is an idempotent Ok, unlike
    // brew's error — the facade post-verifies either way.
    let path = temp_manifest_path("uninstall-flatpak");
    let mut manifest = InstallManifest::at(&path);
    manifest.record(
        &id("brave"),
        InstallRecord::new(
            toride_apps::InstallPlan {
                app: id("brave"),
                backend: BackendId::Flatpak,
                operation: toride_apps::Operation::FlatpakInstall {
                    remote: "flathub".to_owned(),
                    app_ref: "app/com.brave.Browser/x86_64/stable".to_owned(),
                    installation: toride_apps::FlatpakInstallation::User,
                },
                dry_run: false,
                requires_elevation: false,
            },
            NativeIds::Flatpak {
                app_id: "com.brave.Browser".to_owned(),
                app_ref: Some("app/com.brave.Browser/x86_64/stable".to_owned()),
                installation: toride_apps::FlatpakInstallation::User,
            },
            None,
        )
        .with_installed_at(1_700_000_000),
    );
    manifest.save().expect("seed manifest saves");

    let fake = FakeRunner::new()
        .strict()
        .respond(
            flatpak_uninstall_user_spec("com.brave.Browser"),
            flatpak_not_installed_error("com.brave.Browser"),
        )
        // Verify-gone: the user-scoped listing without the app.
        .respond(
            flatpak_list_spec(Some("--user")),
            CommandOutput::from_stdout(""),
        );
    let adapter = FixtureAdapter::new(SourceKind::Flathub, Vec::new());
    let mut apps = facade(&fake, linux(DistroFamily::Debian), &path, vec![adapter]);

    let outcome = apps
        .uninstall(&id("brave"), AppUninstallOptions::new())
        .await
        .expect("flatpak record uninstall succeeds");
    // The idempotent already-absent answer + a clean absence verify = a
    // warning-free removal.
    assert_eq!(
        outcome,
        UninstallAppOutcome::Removed {
            backend: BackendId::Flatpak,
            ids: NativeIds::Flatpak {
                app_id: "com.brave.Browser".to_owned(),
                app_ref: Some("app/com.brave.Browser/x86_64/stable".to_owned()),
                installation: toride_apps::FlatpakInstallation::User,
            },
            warning: None,
        }
    );
    assert!(InstallManifest::load(&path).expect("reload").is_empty());
}

#[tokio::test]
async fn uninstall_distro_record_refuses_without_an_elevation_grant_and_never_dispatches() {
    let path = temp_manifest_path("uninstall-distro-refusal");
    seed_distro_record(&path);
    // Strict with NO responses: any dispatch would fail the test loudly,
    // so reaching the refusal proves nothing ran.
    let fake = FakeRunner::new().strict();
    let adapter = FixtureAdapter::new(SourceKind::Distro, Vec::new());
    let mut apps = facade(&fake, linux(DistroFamily::Debian), &path, vec![adapter]);

    let error = apps
        .uninstall(&id("brave"), AppUninstallOptions::new())
        .await
        .expect_err("distro removals require an elevation grant");
    assert!(
        matches!(
            error,
            AppsError::Backend(ref inner)
                if matches!(inner, toride_apps::Error::ElevationRequired { .. })
        ),
        "{error:?}"
    );
    assert!(
        fake.calls().is_empty(),
        "the refusal fires before any command is built"
    );
    // The record stays: a refused uninstall mutates nothing.
    assert!(
        InstallManifest::load(&path)
            .expect("reload")
            .get(&id("brave"))
            .is_some()
    );
}

#[tokio::test]
async fn uninstall_distro_record_with_the_grant_removes_and_verifies_via_dpkg_query() {
    let path = temp_manifest_path("uninstall-distro-grant");
    seed_distro_record(&path);
    let fake = FakeRunner::new()
        .strict()
        .respond(
            apt_get_spec("remove", "brave-browser"),
            CommandOutput::from_stdout(""),
        )
        // Verify-gone: dpkg-query's not-found answer.
        .respond(
            dpkg_query_spec("brave-browser"),
            dpkg_not_found("brave-browser"),
        );
    let adapter = FixtureAdapter::new(SourceKind::Distro, Vec::new());
    let mut apps = facade(&fake, linux(DistroFamily::Debian), &path, vec![adapter]);

    let outcome = apps
        .uninstall(&id("brave"), AppUninstallOptions::new().elevated(true))
        .await
        .expect("granted distro removal succeeds");

    assert_eq!(
        outcome,
        UninstallAppOutcome::Removed {
            backend: BackendId::Distro(DistroFamily::Debian),
            ids: NativeIds::Distro {
                package: "brave-browser".to_owned(),
                family: DistroFamily::Debian,
            },
            warning: None,
        }
    );
    // The removal argv — apt-get (not the plan's canonical `apt`), -y,
    // and the DEBIAN_FRONTEND env the exact-match fake compares.
    fake.assert_called_with(&apt_get_spec("remove", "brave-browser"));
    fake.assert_no_unmatched_calls();
    assert!(InstallManifest::load(&path).expect("reload").is_empty());
}

#[tokio::test]
async fn uninstall_refuses_a_foreign_install_without_force_and_dispatches_nothing_mutating() {
    let path = temp_manifest_path("uninstall-foreign-refused");
    // No manifest record; the registry knows firefox as a cask; brew
    // reports it installed (by someone else).
    let fake = FakeRunner::new().strict().respond(
        brew_info_installed_spec(),
        CommandOutput::from_stdout(FIREFOX_CASK_INFO),
    );
    let adapter = FixtureAdapter::new(
        SourceKind::HomebrewCask,
        vec![app(
            "firefox",
            "Firefox",
            InstallMethod::Homebrew {
                cask: true,
                token: "firefox".to_owned(),
            },
        )],
    );
    let mut apps = facade(&fake, macos(), &path, vec![adapter]);

    let error = apps
        .uninstall(&id("firefox"), AppUninstallOptions::new())
        .await
        .expect_err("a Foreign install is refused without force");
    assert!(
        matches!(error, AppsError::ForeignNotManaged { .. }),
        "{error:?}"
    );
    let text = error.to_string();
    assert!(text.contains("not by toride"), "{text}");
    assert!(text.contains("force"), "{text}");

    // Only the presence probe ran — no uninstall dispatch.
    let calls = fake.calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert_call_is(&calls[0], &brew_info_installed_spec());
    fake.assert_no_unmatched_calls();
    assert!(InstallManifest::load(&path).expect("reload").is_empty());
}

#[tokio::test]
async fn uninstall_with_force_removes_a_foreign_install_and_fabricates_no_record() {
    let path = temp_manifest_path("uninstall-foreign-forced");
    let fake = FakeRunner::new()
        .strict()
        .respond(
            brew_info_installed_spec(),
            CommandOutput::from_stdout(FIREFOX_CASK_INFO),
        )
        .respond(
            brew_uninstall_cask_spec("firefox"),
            CommandOutput::from_stdout(""),
        )
        .respond(
            brew_versions_spec("--cask", "firefox"),
            brew_silent_absent(),
        );
    let adapter = FixtureAdapter::new(
        SourceKind::HomebrewCask,
        vec![app(
            "firefox",
            "Firefox",
            InstallMethod::Homebrew {
                cask: true,
                token: "firefox".to_owned(),
            },
        )],
    );
    let mut apps = facade(&fake, macos(), &path, vec![adapter]);

    let outcome = apps
        .uninstall(&id("firefox"), AppUninstallOptions::new().force(true))
        .await
        .expect("forced Foreign removal runs");
    assert!(matches!(
        outcome,
        UninstallAppOutcome::Removed { warning: None, .. }
    ));
    fake.assert_called_with(&brew_uninstall_cask_spec("firefox"));
    fake.assert_no_unmatched_calls();

    // No record was fabricated for the foreign removal.
    assert!(InstallManifest::load(&path).expect("reload").is_empty());
}

#[tokio::test]
async fn uninstall_of_an_app_with_nothing_installed_is_already_absent() {
    let path = temp_manifest_path("uninstall-absent");
    let fake = FakeRunner::new().strict().respond(
        brew_info_installed_spec(),
        CommandOutput::from_stdout(EMPTY_BREW_INFO),
    );
    let adapter = FixtureAdapter::new(
        SourceKind::HomebrewCask,
        vec![app(
            "firefox",
            "Firefox",
            InstallMethod::Homebrew {
                cask: true,
                token: "firefox".to_owned(),
            },
        )],
    );
    let mut apps = facade(&fake, macos(), &path, vec![adapter]);

    let outcome = apps
        .uninstall(&id("firefox"), AppUninstallOptions::new())
        .await
        .expect("nothing to remove is not an error");
    assert_eq!(outcome, UninstallAppOutcome::AlreadyAbsent);
    // One presence probe, zero mutations.
    assert_eq!(fake.calls().len(), 1);
    fake.assert_no_unmatched_calls();
}

#[tokio::test]
async fn a_corrupt_newer_toride_manifest_is_quarantined_the_build_recovers_and_saves_fresh() {
    let path = temp_manifest_path("corrupt-newer");
    let future_doc = r#"{"version":99,"entries":{"brave":{"something":"new"}}}"#;
    std::fs::write(path.as_std_path(), future_doc).expect("seed the future manifest");

    let apps = Apps::builder()
        .manifest_path(&path)
        .build()
        .expect("a corrupt manifest is quarantined, never a fatal stop");
    assert!(apps.records().is_empty(), "the facade starts from empty");
    let quarantined = apps
        .quarantined()
        .expect("the recovery is surfaced")
        .clone();
    assert_ne!(quarantined, path);
    assert!(
        quarantined
            .file_name()
            .is_some_and(|name| name.contains(".corrupt-")),
        "recognizable quarantine name: {quarantined}"
    );
    assert_eq!(
        std::fs::read_to_string(quarantined.as_std_path()).unwrap(),
        future_doc,
        "the unreadable bytes stay on disk for inspection"
    );
    assert!(
        !path.as_std_path().exists(),
        "the original slot is free for the fresh document"
    );

    let fake = FakeRunner::new()
        .strict()
        .respond(
            brew_info_installed_spec(),
            CommandOutput::from_stdout(EMPTY_BREW_INFO),
        )
        .respond(
            brew_install_cask_spec("firefox"),
            CommandOutput::from_stdout(""),
        )
        .respond(
            brew_versions_spec("--cask", "firefox"),
            CommandOutput::from_stdout("firefox 138.0.1"),
        )
        .respond(
            brew_versions_spec("--cask", "firefox"),
            CommandOutput::from_stdout("firefox 138.0.1"),
        );
    let adapter = FixtureAdapter::new(
        SourceKind::HomebrewCask,
        vec![app(
            "firefox",
            "Firefox",
            InstallMethod::Homebrew {
                cask: true,
                token: "firefox".to_owned(),
            },
        )],
    );
    let mut apps = Apps::builder()
        .runner(CommandRunner::new(std::sync::Arc::new(fake.clone())))
        .target(macos())
        .manifest_path(&path)
        .homebrew(HomebrewBackend::new(CommandRunner::new(
            std::sync::Arc::new(fake.clone()),
        )))
        .flatpak(FlatpakBackend::new(CommandRunner::new(
            std::sync::Arc::new(fake.clone()),
        )))
        .distro(DistroBackend::new(
            DistroFamily::Debian,
            CommandRunner::new(std::sync::Arc::new(fake.clone())),
        ))
        .adapter(adapter)
        .build()
        .expect("the recovered path builds");
    assert!(
        matches!(
            apps.ensure_installed(&id("firefox"), AppInstallOptions::new())
                .await,
            Ok(EnsureAppOutcome::Installed { .. })
        ),
        "the facade operates after the recovery"
    );
    fake.assert_no_unmatched_calls();
    let reloaded = InstallManifest::load(&path).expect("the fresh document loads");
    assert_eq!(
        reloaded
            .get(&id("firefox"))
            .expect("record present")
            .version,
        Some("138.0.1".to_owned())
    );
    assert_eq!(
        std::fs::read_to_string(quarantined.as_std_path()).unwrap(),
        future_doc,
        "the quarantined bytes survive the fresh save"
    );
}

// ---------------------------------------------------------------------------
// Honest degradation — post-verify failure, save failure
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_failed_post_install_verify_records_unverified_with_a_typed_warning() {
    let path = temp_manifest_path("verify-failed");
    let fake = FakeRunner::new()
        .strict()
        .respond(
            brew_info_installed_spec(),
            CommandOutput::from_stdout(EMPTY_BREW_INFO),
        )
        .respond(
            brew_install_cask_spec("firefox"),
            CommandOutput::from_stdout(""),
        )
        // The backend's own post-install probe sees the version…
        .respond(
            brew_versions_spec("--cask", "firefox"),
            CommandOutput::from_stdout("firefox 138.0.1"),
        )
        // …but the facade's verify probe fails as a REAL error (exit 2,
        // stderr that is neither a marker line nor the silent signal).
        .respond(
            brew_versions_spec("--cask", "firefox"),
            CommandOutput::from_stderr("Error: brew exploded", 2),
        );
    let adapter = FixtureAdapter::new(
        SourceKind::HomebrewCask,
        vec![app(
            "firefox",
            "Firefox",
            InstallMethod::Homebrew {
                cask: true,
                token: "firefox".to_owned(),
            },
        )],
    );
    let mut apps = facade(&fake, macos(), &path, vec![adapter]);

    let outcome = apps
        .ensure_installed(&id("firefox"), AppInstallOptions::new())
        .await
        .expect("the install itself succeeded");
    let EnsureAppOutcome::Installed {
        version,
        verified,
        warning,
        ..
    } = outcome
    else {
        panic!("expected Installed, got {outcome:?}");
    };
    assert!(!verified, "the facade's verify did not confirm");
    let warning = warning.expect("the degraded condition is surfaced");
    assert!(
        warning.contains("post-install verify"),
        "typed warning: {warning}"
    );
    // The backend's own report is kept as the unverified version.
    assert_eq!(version.as_deref(), Some("138.0.1"));

    // The record still landed (so a later uninstall works), unverified.
    let reloaded = InstallManifest::load(&path).expect("manifest reloads");
    assert_eq!(
        reloaded
            .get(&id("firefox"))
            .expect("record present")
            .version
            .as_deref(),
        Some("138.0.1")
    );
}

#[tokio::test]
async fn a_manifest_save_failure_after_a_successful_install_is_a_warning_not_a_failure() {
    let path = temp_manifest_path("save-failed");
    let fake = FakeRunner::new()
        .strict()
        .respond(
            brew_info_installed_spec(),
            CommandOutput::from_stdout(EMPTY_BREW_INFO),
        )
        .respond(
            brew_install_cask_spec("firefox"),
            CommandOutput::from_stdout(""),
        )
        .respond(
            brew_versions_spec("--cask", "firefox"),
            CommandOutput::from_stdout("firefox 138.0.1"),
        )
        .respond(
            brew_versions_spec("--cask", "firefox"),
            CommandOutput::from_stdout("firefox 138.0.1"),
        );
    let adapter = FixtureAdapter::new(
        SourceKind::HomebrewCask,
        vec![app(
            "firefox",
            "Firefox",
            InstallMethod::Homebrew {
                cask: true,
                token: "firefox".to_owned(),
            },
        )],
    );
    let mut apps = facade(&fake, macos(), &path, vec![adapter]);

    // After the (absent-file) load at build, occupy the manifest path
    // with a directory: the save's temp-then-rename then fails (a file
    // never renames onto a directory) — deterministic, and the A5
    // save-failure precedent.
    std::fs::create_dir_all(path.as_std_path()).expect("occupy the manifest path");

    let outcome = apps
        .ensure_installed(&id("firefox"), AppInstallOptions::new())
        .await
        .expect("the install succeeded — the save failure must not claim otherwise");
    let EnsureAppOutcome::Installed {
        verified,
        warning,
        version,
        ..
    } = outcome
    else {
        panic!("expected Installed, got {outcome:?}");
    };
    assert!(verified, "the install and verify were clean");
    assert_eq!(version.as_deref(), Some("138.0.1"));
    let warning = warning.expect("the save failure is surfaced");
    assert!(
        warning.contains("saving the install manifest failed"),
        "{warning}"
    );
}

/// Seed a flatpak record: brave as the com.brave.Browser app in the user
/// installation.
fn seed_flatpak_record(path: &Utf8PathBuf) {
    let mut manifest = InstallManifest::at(path);
    manifest.record(
        &id("brave"),
        InstallRecord::new(
            toride_apps::InstallPlan {
                app: id("brave"),
                backend: BackendId::Flatpak,
                operation: toride_apps::Operation::FlatpakInstall {
                    remote: "flathub".to_owned(),
                    app_ref: "app/com.brave.Browser/x86_64/stable".to_owned(),
                    installation: toride_apps::FlatpakInstallation::User,
                },
                dry_run: false,
                requires_elevation: false,
            },
            NativeIds::Flatpak {
                app_id: "com.brave.Browser".to_owned(),
                app_ref: Some("app/com.brave.Browser/x86_64/stable".to_owned()),
                installation: toride_apps::FlatpakInstallation::User,
            },
            None,
        )
        .with_installed_at(1_700_000_000),
    );
    manifest.save().expect("seed manifest saves");
}

#[tokio::test]
async fn update_without_a_record_is_a_typed_error_and_consults_nothing() {
    let path = temp_manifest_path("update-unrecorded");
    let fake = FakeRunner::new().strict();
    let adapter = FixtureAdapter::new(SourceKind::HomebrewCask, Vec::new());
    let mut apps = facade(&fake, macos(), &path, vec![adapter.clone()]);

    let error = apps
        .update(&id("firefox"), &AppUpdateOptions::new())
        .await
        .expect_err("update replays the record — no record, no update");
    assert!(
        matches!(error, AppsError::UnrecordedUpdate { .. }),
        "{error:?}"
    );
    assert!(error.to_string().contains("ensure_installed"), "{error}");
    assert!(fake.calls().is_empty(), "no probe may run");
    assert_eq!(
        adapter.lookups().len(),
        0,
        "the update path never resolves through the registry"
    );
}

#[tokio::test]
async fn update_with_a_target_version_refuses_before_anything_runs() {
    let path = temp_manifest_path("update-target-pinning");
    seed_cask_record(&path, "firefox");
    let fake = FakeRunner::new().strict();
    let adapter = FixtureAdapter::new(SourceKind::HomebrewCask, Vec::new());
    let mut apps = facade(&fake, macos(), &path, vec![adapter]);

    let error = apps
        .update(
            &id("firefox"),
            &AppUpdateOptions::new().target(Some(Version::new("139.0"))),
        )
        .await
        .expect_err("wave-1 updates cannot pin a target version");
    assert!(
        matches!(error, AppsError::UpdateTargetNotPinnable { .. }),
        "{error:?}"
    );
    assert!(fake.calls().is_empty(), "no probe may run");
}

#[tokio::test]
async fn update_brew_cask_stale_runs_the_upgrade_and_rewrites_the_manifest_version() {
    let path = temp_manifest_path("update-cask-stale");
    seed_cask_record(&path, "firefox");
    let fake = FakeRunner::new()
        .strict()
        .respond(
            brew_versions_spec("--cask", "firefox"),
            CommandOutput::from_stdout("firefox 138.0.1\n"),
        )
        .respond(
            brew_outdated_spec("--cask"),
            CommandOutput::from_stdout(firefox_cask_outdated("138.0.1", "139.0")),
        )
        .respond(
            brew_upgrade_cask_spec("firefox"),
            CommandOutput::from_stdout(""),
        )
        .respond(
            brew_versions_spec("--cask", "firefox"),
            CommandOutput::from_stdout("firefox 139.0\n"),
        );
    let adapter = FixtureAdapter::new(SourceKind::HomebrewCask, Vec::new());
    let mut apps = facade(&fake, macos(), &path, vec![adapter.clone()]);

    let outcome = apps
        .update(&id("firefox"), &AppUpdateOptions::new())
        .await
        .expect("stale cask updates");

    assert_eq!(
        outcome,
        UpdateOutcome::Updated {
            from: Some(Version::new("138.0.1")),
            to: Some(Version::new("139.0")),
        }
    );
    fake.assert_called_with(&brew_upgrade_cask_spec("firefox"));
    fake.assert_no_unmatched_calls();
    assert_eq!(
        adapter.lookups().len(),
        0,
        "the record's identifiers plan the update — zero adapter calls"
    );

    let reloaded = InstallManifest::load(&path).expect("manifest reloads");
    let record = reloaded.get(&id("firefox")).expect("record survives");
    assert_eq!(record.version.as_deref(), Some("139.0"));
    assert_eq!(
        record.ids,
        NativeIds::Homebrew {
            token: "firefox".to_owned(),
            cask: true,
        }
    );
    assert!(
        record.plan.as_ref().is_some_and(|plan| matches!(
            plan.operation,
            toride_apps::Operation::BrewInstall { .. }
        ))
    );
}

#[tokio::test]
async fn update_brew_reported_current_by_the_scoped_stale_signal_is_up_to_date() {
    let path = temp_manifest_path("update-cask-current");
    seed_cask_record(&path, "firefox");
    let fake = FakeRunner::new()
        .strict()
        .respond(
            brew_versions_spec("--cask", "firefox"),
            CommandOutput::from_stdout("firefox 138.0.1\n"),
        )
        .respond(
            brew_outdated_spec("--cask"),
            CommandOutput::from_stdout(r#"{"formulae":[],"casks":[]}"#),
        );
    let adapter = FixtureAdapter::new(SourceKind::HomebrewCask, Vec::new());
    let mut apps = facade(&fake, macos(), &path, vec![adapter]);

    let outcome = apps
        .update(&id("firefox"), &AppUpdateOptions::new())
        .await
        .expect("an up-to-date app answers, not errors");
    assert_eq!(outcome, UpdateOutcome::UpToDate);
    fake.assert_called_with(&brew_outdated_spec("--cask"));
    fake.assert_no_unmatched_calls();
    let calls = fake.calls();
    assert_eq!(
        calls.len(),
        2,
        "the kind-scoped manager verdict alone decides — no availability probe, no upgrade: {calls:?}"
    );

    let reloaded = InstallManifest::load(&path).expect("manifest reloads");
    assert_eq!(
        reloaded
            .get(&id("firefox"))
            .expect("record survives")
            .version
            .as_deref(),
        Some("138.0.1")
    );
}

#[tokio::test]
async fn update_brew_an_absent_token_is_never_up_to_date_and_the_upgrade_errors_honestly() {
    let path = temp_manifest_path("update-cask-absent");
    seed_cask_record(&path, "firefox");
    let fake = FakeRunner::new()
        .strict()
        .respond(
            brew_versions_spec("--cask", "firefox"),
            brew_silent_absent(),
        )
        .respond(
            brew_upgrade_cask_spec("firefox"),
            CommandOutput::from_stderr("Error: Cask 'firefox' is not installed.", 1),
        );
    let adapter = FixtureAdapter::new(SourceKind::HomebrewCask, Vec::new());
    let mut apps = facade(&fake, macos(), &path, vec![adapter]);

    let error = apps
        .update(&id("firefox"), &AppUpdateOptions::new())
        .await
        .expect_err("an absent install is not up to date; the manager classifies");
    assert!(
        matches!(error, AppsError::Backend(ref inner) if matches!(inner, toride_apps::Error::Command(_))),
        "{error:?}"
    );
    fake.assert_no_unmatched_calls();
    assert_eq!(
        InstallManifest::load(&path)
            .expect("reload")
            .get(&id("firefox"))
            .expect("record untouched by the failed upgrade")
            .version
            .as_deref(),
        Some("138.0.1")
    );
}

#[tokio::test]
async fn update_dry_run_previews_the_argv_and_versions_without_executing() {
    let path = temp_manifest_path("update-dry-run");
    seed_cask_record(&path, "firefox");
    let fake = FakeRunner::new()
        .strict()
        .respond(
            brew_versions_spec("--cask", "firefox"),
            CommandOutput::from_stdout("firefox 138.0.1\n"),
        )
        .respond(
            brew_info_token_spec("firefox"),
            CommandOutput::from_stdout(firefox_cask_available("138.0.1", "139.0")),
        );
    let adapter = FixtureAdapter::new(SourceKind::HomebrewCask, Vec::new());
    let mut apps = facade(&fake, macos(), &path, vec![adapter]);

    let outcome = apps
        .update(&id("firefox"), &AppUpdateOptions::new().dry_run(true))
        .await
        .expect("a dry run answers");

    let toride_apps::apps::UpdateOutcome::Preview(preview) = &outcome else {
        panic!("expected Preview, got {outcome:?}");
    };
    assert_eq!(preview.argv, ["brew", "upgrade", "--cask", "firefox"]);
    assert_eq!(preview.from, Some(Version::new("138.0.1")));
    assert_eq!(
        preview.to,
        Some(Version::new("139.0")),
        "the OFFERED version — the same document carries installed 138.0.1"
    );
    fake.assert_no_unmatched_calls();

    let calls = fake.calls();
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert!(
        calls
            .iter()
            .all(|call| call.args.first().is_some_and(|a| a != "upgrade")),
        "no upgrade may run: {calls:?}"
    );
    let reloaded = InstallManifest::load(&path).expect("manifest reloads");
    assert_eq!(
        reloaded
            .get(&id("firefox"))
            .expect("record survives")
            .version
            .as_deref(),
        Some("138.0.1")
    );
}

#[tokio::test]
async fn update_distro_record_with_the_grant_runs_only_upgrade_and_rewrites_the_version() {
    let path = temp_manifest_path("update-distro-grant");
    seed_distro_record(&path);
    let fake = FakeRunner::new()
        .strict()
        .respond(
            dpkg_query_spec("brave-browser"),
            CommandOutput::from_stdout("ii brave-browser\t1.4.2\n"),
        )
        .respond(
            apt_get_update_spec("brave-browser"),
            CommandOutput::from_stdout(""),
        )
        .respond(
            dpkg_query_spec("brave-browser"),
            CommandOutput::from_stdout("ii brave-browser\t1.5.0\n"),
        );
    let adapter = FixtureAdapter::new(SourceKind::Distro, Vec::new());
    let mut apps = facade(&fake, linux(DistroFamily::Debian), &path, vec![adapter]);

    let outcome = apps
        .update(&id("brave"), &AppUpdateOptions::new().elevated(true))
        .await
        .expect("granted distro update succeeds");

    assert_eq!(
        outcome,
        UpdateOutcome::Updated {
            from: Some(Version::new("1.4.2")),
            to: Some(Version::new("1.5.0")),
        }
    );
    fake.assert_called_with(&apt_get_update_spec("brave-browser"));
    fake.assert_no_unmatched_calls();

    let reloaded = InstallManifest::load(&path).expect("manifest reloads");
    let record = reloaded.get(&id("brave")).expect("record survives");
    assert_eq!(record.version.as_deref(), Some("1.5.0"));
    assert!(
        record
            .plan
            .as_ref()
            .is_some_and(|plan| plan.requires_elevation),
        "the record keeps its original install plan"
    );
}

#[tokio::test]
async fn update_distro_record_refuses_without_an_elevation_grant_and_never_mutates() {
    let path = temp_manifest_path("update-distro-refusal");
    seed_distro_record(&path);
    let fake = FakeRunner::new().strict().respond(
        dpkg_query_spec("brave-browser"),
        CommandOutput::from_stdout("ii brave-browser\t1.4.2\n"),
    );
    let adapter = FixtureAdapter::new(SourceKind::Distro, Vec::new());
    let mut apps = facade(&fake, linux(DistroFamily::Debian), &path, vec![adapter]);

    let error = apps
        .update(&id("brave"), &AppUpdateOptions::new())
        .await
        .expect_err("distro updates require an elevation grant");
    assert!(
        matches!(
            error,
            AppsError::Backend(ref inner)
                if matches!(inner, toride_apps::Error::ElevationRequired { .. })
        ),
        "{error:?}"
    );
    let calls = fake.calls();
    assert_eq!(calls.len(), 1, "only the read-only probe ran: {calls:?}");
    assert_call_is(&calls[0], &dpkg_query_spec("brave-browser"));
    fake.assert_no_unmatched_calls();
    assert_eq!(
        InstallManifest::load(&path)
            .expect("reload")
            .get(&id("brave"))
            .expect("record untouched")
            .version
            .as_deref(),
        Some("1.4.2")
    );
}

#[tokio::test]
async fn update_flatpak_record_runs_flatpak_update_and_reports_both_versions() {
    let path = temp_manifest_path("update-flatpak");
    seed_flatpak_record(&path);
    let fake = FakeRunner::new()
        .strict()
        .respond(
            flatpak_list_spec(Some("--user")),
            CommandOutput::from_stdout(flatpak_row("com.brave.Browser", "1.2.3")),
        )
        .respond(
            flatpak_update_user_spec("com.brave.Browser"),
            CommandOutput::from_stdout(""),
        )
        .respond(
            flatpak_list_spec(Some("--user")),
            CommandOutput::from_stdout(flatpak_row("com.brave.Browser", "1.3.0")),
        );
    let adapter = FixtureAdapter::new(SourceKind::Flathub, Vec::new());
    let mut apps = facade(&fake, linux(DistroFamily::Debian), &path, vec![adapter]);

    let outcome = apps
        .update(&id("brave"), &AppUpdateOptions::new())
        .await
        .expect("flatpak update succeeds");
    assert_eq!(
        outcome,
        UpdateOutcome::Updated {
            from: Some(Version::new("1.2.3")),
            to: Some(Version::new("1.3.0")),
        }
    );
    fake.assert_called_with(&flatpak_update_user_spec("com.brave.Browser"));
    fake.assert_no_unmatched_calls();
    assert_eq!(
        InstallManifest::load(&path)
            .expect("reload")
            .get(&id("brave"))
            .expect("record survives")
            .version
            .as_deref(),
        Some("1.3.0")
    );
}

#[tokio::test]
async fn update_flatpak_without_appdata_reports_none_to_none_and_records_a_null_version() {
    let path = temp_manifest_path("update-flatpak-no-version");
    seed_flatpak_record(&path);
    let empty_cell = flatpak_row("com.brave.Browser", "");
    let fake = FakeRunner::new()
        .strict()
        .respond(
            flatpak_list_spec(Some("--user")),
            CommandOutput::from_stdout(empty_cell.clone()),
        )
        .respond(
            flatpak_update_user_spec("com.brave.Browser"),
            CommandOutput::from_stdout(""),
        )
        .respond(
            flatpak_list_spec(Some("--user")),
            CommandOutput::from_stdout(empty_cell),
        );
    let adapter = FixtureAdapter::new(SourceKind::Flathub, Vec::new());
    let mut apps = facade(&fake, linux(DistroFamily::Debian), &path, vec![adapter]);

    let outcome = apps
        .update(&id("brave"), &AppUpdateOptions::new())
        .await
        .expect("an app without appdata metadata still updates");
    assert_eq!(
        outcome,
        UpdateOutcome::Updated {
            from: None,
            to: None,
        },
        "present-without-a-version on both probes — the Option shape plan 4.1 exists for"
    );
    fake.assert_called_with(&flatpak_update_user_spec("com.brave.Browser"));
    fake.assert_no_unmatched_calls();
    assert_eq!(
        InstallManifest::load(&path)
            .expect("reload")
            .get(&id("brave"))
            .expect("record survives")
            .version,
        None
    );
}

#[tokio::test]
async fn a_failed_post_upgrade_probe_degrades_to_no_version_without_failing_the_update() {
    let path = temp_manifest_path("update-reprobe-failed");
    seed_cask_record(&path, "firefox");
    let fake = FakeRunner::new()
        .strict()
        .respond(
            brew_versions_spec("--cask", "firefox"),
            CommandOutput::from_stdout("firefox 138.0.1\n"),
        )
        .respond(
            brew_outdated_spec("--cask"),
            CommandOutput::from_stdout(firefox_cask_outdated("138.0.1", "139.0")),
        )
        .respond(
            brew_upgrade_cask_spec("firefox"),
            CommandOutput::from_stdout(""),
        )
        .respond(
            brew_versions_spec("--cask", "firefox"),
            CommandOutput::from_stderr("Error: brew exploded", 2),
        );
    let adapter = FixtureAdapter::new(SourceKind::HomebrewCask, Vec::new());
    let mut apps = facade(&fake, macos(), &path, vec![adapter]);

    let outcome = apps
        .update(&id("firefox"), &AppUpdateOptions::new())
        .await
        .expect("the upgrade itself succeeded");
    assert_eq!(
        outcome,
        UpdateOutcome::Updated {
            from: Some(Version::new("138.0.1")),
            to: None,
        }
    );
    fake.assert_called_with(&brew_upgrade_cask_spec("firefox"));
    fake.assert_no_unmatched_calls();
    assert_eq!(
        InstallManifest::load(&path)
            .expect("reload")
            .get(&id("firefox"))
            .expect("record survives")
            .version,
        None,
        "no version observable after the upgrade, per the record field's contract"
    );
}

// ---------------------------------------------------------------------------
// Version selection, available-version listing, pin/unpin
// ---------------------------------------------------------------------------

fn brew_pin_spec(kind_flag: &str, verb: &str, token: &str) -> CommandSpec {
    command("brew", [verb, kind_flag, token])
}

fn flatpak_remote_ls_spec(flag: &str) -> CommandSpec {
    command(
        "flatpak",
        [
            "remote-ls",
            flag,
            "--app",
            "--columns=application,branch",
            "flathub",
        ],
    )
}

#[tokio::test]
async fn ensure_installed_with_a_version_installs_the_versioned_token_and_records_it() {
    let path = temp_manifest_path("install-versioned-cask");
    let fake = FakeRunner::new()
        .strict()
        .respond(
            brew_info_installed_spec(),
            CommandOutput::from_stdout(EMPTY_BREW_INFO),
        )
        // The offering probe: brew offers 137.0, not the requested 138.0.1,
        // so the request pins instead of riding the manager's current.
        .respond(
            brew_info_token_spec("firefox"),
            CommandOutput::from_stdout(firefox_cask_available("137.0", "137.0")),
        )
        .respond(
            brew_install_cask_spec("firefox@138.0.1"),
            CommandOutput::from_stdout(""),
        )
        // The backend's post-install probe, then the facade's verify — both
        // address the joined token, because that is the identity brew
        // manages for a versioned install.
        .respond(
            brew_versions_spec("--cask", "firefox@138.0.1"),
            CommandOutput::from_stdout("firefox@138.0.1 138.0.1\n"),
        )
        .respond(
            brew_versions_spec("--cask", "firefox@138.0.1"),
            CommandOutput::from_stdout("firefox@138.0.1 138.0.1\n"),
        );
    let adapter = FixtureAdapter::new(
        SourceKind::HomebrewCask,
        vec![app(
            "firefox",
            "Firefox",
            InstallMethod::Homebrew {
                cask: true,
                token: "firefox".to_owned(),
            },
        )],
    );
    let mut apps = facade(&fake, macos(), &path, vec![adapter]);

    let outcome = apps
        .ensure_installed(
            &id("firefox"),
            AppInstallOptions::new().version(Some(Version::new("138.0.1"))),
        )
        .await
        .expect("versioned cask install succeeds");

    let EnsureAppOutcome::Installed { ids, version, .. } = outcome else {
        panic!("expected Installed, got {outcome:?}");
    };
    assert_eq!(
        ids,
        NativeIds::Homebrew {
            token: "firefox@138.0.1".to_owned(),
            cask: true,
        },
        "the recorded identity is the versioned token brew manages"
    );
    assert_eq!(version.as_deref(), Some("138.0.1"));
    fake.assert_called_with(&brew_install_cask_spec("firefox@138.0.1"));
    fake.assert_no_unmatched_calls();

    let reloaded = InstallManifest::load(&path).expect("manifest reloads");
    assert_eq!(
        reloaded.get(&id("firefox")).expect("record present").ids,
        NativeIds::Homebrew {
            token: "firefox@138.0.1".to_owned(),
            cask: true,
        }
    );
}

#[tokio::test]
async fn ensure_installed_at_the_offered_version_installs_the_managers_current() {
    let path = temp_manifest_path("install-version-offered");
    let fake = FakeRunner::new()
        .strict()
        .respond(
            brew_info_installed_spec(),
            CommandOutput::from_stdout(EMPTY_BREW_INFO),
        )
        // The offering probe answers 139.0 — exactly the request.
        .respond(
            brew_info_token_spec("firefox"),
            CommandOutput::from_stdout(firefox_cask_available("138.0.1", "139.0")),
        )
        .respond(
            brew_install_cask_spec("firefox"),
            CommandOutput::from_stdout(""),
        )
        .respond(
            brew_versions_spec("--cask", "firefox"),
            CommandOutput::from_stdout("firefox 139.0\n"),
        )
        .respond(
            brew_versions_spec("--cask", "firefox"),
            CommandOutput::from_stdout("firefox 139.0\n"),
        );
    let adapter = FixtureAdapter::new(
        SourceKind::HomebrewCask,
        vec![app(
            "firefox",
            "Firefox",
            InstallMethod::Homebrew {
                cask: true,
                token: "firefox".to_owned(),
            },
        )],
    );
    let mut apps = facade(&fake, macos(), &path, vec![adapter]);

    let outcome = apps
        .ensure_installed(
            &id("firefox"),
            AppInstallOptions::new().version(Some(Version::new("139.0"))),
        )
        .await
        .expect("a request equal to the offering rides the manager's current");

    let EnsureAppOutcome::Installed { ids, version, .. } = outcome else {
        panic!("expected Installed, got {outcome:?}");
    };
    assert_eq!(
        ids,
        NativeIds::Homebrew {
            token: "firefox".to_owned(),
            cask: true,
        },
        "the plain token — the current lands exactly the requested version"
    );
    assert_eq!(version.as_deref(), Some("139.0"));
    fake.assert_called_with(&brew_info_token_spec("firefox"));
    fake.assert_called_with(&brew_install_cask_spec("firefox"));
    assert!(
        !fake
            .calls()
            .iter()
            .any(|call| call.args.contains(&"firefox@139.0".to_owned())),
        "no @-joined spelling may run: {:?}",
        fake.calls()
    );
    fake.assert_no_unmatched_calls();
}

#[tokio::test]
async fn a_failing_offering_probe_degrades_to_the_pinned_spelling() {
    let path = temp_manifest_path("install-version-offer-failed");
    let fake = FakeRunner::new()
        .strict()
        .respond(
            brew_info_installed_spec(),
            CommandOutput::from_stdout(EMPTY_BREW_INFO),
        )
        // The offering probe fails outright — the pin proceeds and the
        // manager classifies the joined name.
        .respond(
            brew_info_token_spec("firefox"),
            CommandOutput::from_stderr("Error: brew exploded", 2),
        )
        .respond(
            brew_install_cask_spec("firefox@138.0.1"),
            CommandOutput::from_stdout(""),
        )
        .respond(
            brew_versions_spec("--cask", "firefox@138.0.1"),
            CommandOutput::from_stdout("firefox@138.0.1 138.0.1\n"),
        )
        .respond(
            brew_versions_spec("--cask", "firefox@138.0.1"),
            CommandOutput::from_stdout("firefox@138.0.1 138.0.1\n"),
        );
    let adapter = FixtureAdapter::new(
        SourceKind::HomebrewCask,
        vec![app(
            "firefox",
            "Firefox",
            InstallMethod::Homebrew {
                cask: true,
                token: "firefox".to_owned(),
            },
        )],
    );
    let mut apps = facade(&fake, macos(), &path, vec![adapter]);

    let outcome = apps
        .ensure_installed(
            &id("firefox"),
            AppInstallOptions::new().version(Some(Version::new("138.0.1"))),
        )
        .await
        .expect("the offering probe degrades, never fails the install");
    assert!(matches!(outcome, EnsureAppOutcome::Installed { .. }));
    fake.assert_called_with(&brew_install_cask_spec("firefox@138.0.1"));
    fake.assert_no_unmatched_calls();
}

#[tokio::test]
async fn ensure_installed_flatpak_with_a_version_selects_the_ref_branch() {
    let path = temp_manifest_path("install-version-flatpak");
    let fake = FakeRunner::new()
        .strict()
        .respond(flatpak_list_spec(None), CommandOutput::from_stdout(""))
        .respond(
            flatpak_remotes_spec(),
            CommandOutput::from_stdout("flathub\n"),
        )
        .respond(
            flatpak_install_user_spec("app/com.brave.Browser/x86_64/beta"),
            CommandOutput::from_stdout(""),
        )
        .respond(
            flatpak_list_spec(Some("--user")),
            CommandOutput::from_stdout(flatpak_row("com.brave.Browser", "1.2.3")),
        )
        .respond(
            flatpak_list_spec(Some("--user")),
            CommandOutput::from_stdout(flatpak_row("com.brave.Browser", "1.2.3")),
        );
    let adapter = FixtureAdapter::new(
        SourceKind::Flathub,
        vec![app(
            "brave",
            "Brave Browser",
            InstallMethod::Flatpak {
                app_id: "com.brave.Browser".to_owned(),
                remote: "flathub".to_owned(),
            },
        )],
    );
    let mut apps = facade(&fake, linux(DistroFamily::Debian), &path, vec![adapter]);

    let outcome = apps
        .ensure_installed(
            &id("brave"),
            AppInstallOptions::new().version(Some(Version::new("beta"))),
        )
        .await
        .expect("branch-pinned flatpak install succeeds");
    assert!(matches!(outcome, EnsureAppOutcome::Installed { .. }));

    fake.assert_called_with(&flatpak_install_user_spec(
        "app/com.brave.Browser/x86_64/beta",
    ));
    fake.assert_no_unmatched_calls();
    let reloaded = InstallManifest::load(&path).expect("manifest reloads");
    let NativeIds::Flatpak { app_ref, .. } =
        &reloaded.get(&id("brave")).expect("record present").ids
    else {
        panic!("flatpak record");
    };
    assert_eq!(
        app_ref.as_deref(),
        Some("app/com.brave.Browser/x86_64/beta"),
        "the executed branch ref, never re-derived"
    );
}

#[tokio::test]
async fn ensure_installed_distro_with_a_version_is_refused_at_plan_time() {
    let path = temp_manifest_path("install-version-distro");
    let fake = FakeRunner::new()
        .strict()
        // The Foreign check's dpkg-query: not found → NotInstalled.
        .respond(
            dpkg_query_spec("brave-browser"),
            dpkg_not_found("brave-browser"),
        );
    let adapter = FixtureAdapter::new(
        SourceKind::Distro,
        vec![brave_distro_app(DistroFamily::Debian)],
    );
    let mut apps = facade(&fake, linux(DistroFamily::Debian), &path, vec![adapter]);

    let error = apps
        .ensure_installed(
            &id("brave"),
            AppInstallOptions::new()
                .elevated(true)
                .version(Some(Version::new("1.4.2"))),
        )
        .await
        .expect_err("distro methods take no version operand");
    assert!(
        matches!(
            error,
            AppsError::Backend(ref inner)
                if matches!(inner, toride_apps::Error::VersionNotSelectable { .. })
        ),
        "{error:?}"
    );
    let calls = fake.calls();
    assert_eq!(
        calls.len(),
        1,
        "only the Foreign-check probe ran: {calls:?}"
    );
    assert_call_is(&calls[0], &dpkg_query_spec("brave-browser"));
    fake.assert_no_unmatched_calls();
    assert!(InstallManifest::load(&path).expect("reload").is_empty());
}

#[tokio::test]
async fn available_versions_answers_from_the_record_without_resolving() {
    let path = temp_manifest_path("available-record");
    seed_formula_record(&path, "ripgrep");
    let fake = FakeRunner::new().strict().respond(
        brew_info_token_spec("ripgrep"),
        CommandOutput::from_stdout(
            r#"{"formulae":[{"name":"ripgrep","versions":{"stable":"14.1.0"},"installed":[{"version":"14.1.0"}]}],"casks":[]}"#,
        ),
    );
    let adapter = FixtureAdapter::new(SourceKind::HomebrewFormula, Vec::new());
    let apps = facade(&fake, macos(), &path, vec![adapter.clone()]);

    let versions = apps
        .available_versions(&id("ripgrep"))
        .await
        .expect("the recorded backend lists its offering");
    assert_eq!(versions, vec![Version::new("14.1.0")]);
    assert_eq!(
        adapter.lookups().len(),
        0,
        "a record hit must not resolve through the registry"
    );
    fake.assert_no_unmatched_calls();
}

#[tokio::test]
async fn available_versions_resolves_through_the_registry_when_unrecorded() {
    let path = temp_manifest_path("available-resolve");
    let fake = FakeRunner::new().strict().respond(
        flatpak_remote_ls_spec("--user"),
        CommandOutput::from_stdout(
            "com.brave.Browser\tstable\ncom.brave.Browser\tbeta\norg.mozilla.firefox\tstable\n",
        ),
    );
    let adapter = FixtureAdapter::new(
        SourceKind::Flathub,
        vec![app(
            "brave",
            "Brave Browser",
            InstallMethod::Flatpak {
                app_id: "com.brave.Browser".to_owned(),
                remote: "flathub".to_owned(),
            },
        )],
    );
    let apps = facade(&fake, linux(DistroFamily::Debian), &path, vec![adapter]);

    let versions = apps
        .available_versions(&id("brave"))
        .await
        .expect("the resolved backend lists the remote's branches");
    assert_eq!(
        versions,
        vec![Version::new("stable"), Version::new("beta")],
        "the installable branches, remote order"
    );
    fake.assert_no_unmatched_calls();
}

#[tokio::test]
async fn available_versions_of_an_unresolvable_app_is_the_typed_unresolved_error() {
    let path = temp_manifest_path("available-unresolved");
    let fake = FakeRunner::new().strict();
    let adapter = FixtureAdapter::new(SourceKind::HomebrewCask, Vec::new());
    let apps = facade(&fake, macos(), &path, vec![adapter]);

    let error = apps
        .available_versions(&id("ghost"))
        .await
        .expect_err("nothing resolves the id");
    assert!(matches!(error, AppsError::Unresolved { .. }), "{error:?}");
    assert!(fake.calls().is_empty());
}

#[tokio::test]
async fn pin_and_unpin_run_the_recorded_tokens_argv_and_touch_no_manifest() {
    let path = temp_manifest_path("pin-unpin");
    seed_formula_record(&path, "ripgrep");
    let fake = FakeRunner::new()
        .strict()
        .respond(
            brew_pin_spec("--formula", "pin", "ripgrep"),
            CommandOutput::from_stdout(""),
        )
        .respond(
            brew_pin_spec("--formula", "unpin", "ripgrep"),
            CommandOutput::from_stdout(""),
        );
    let adapter = FixtureAdapter::new(SourceKind::HomebrewFormula, Vec::new());
    let apps = facade(&fake, macos(), &path, vec![adapter]);

    apps.pin(&id("ripgrep")).await.expect("formula pin runs");
    fake.assert_called_with(&brew_pin_spec("--formula", "pin", "ripgrep"));
    apps.unpin(&id("ripgrep"))
        .await
        .expect("formula unpin runs");
    fake.assert_called_with(&brew_pin_spec("--formula", "unpin", "ripgrep"));
    fake.assert_no_unmatched_calls();

    let reloaded = InstallManifest::load(&path).expect("manifest reloads");
    assert!(
        reloaded.get(&id("ripgrep")).is_some(),
        "pin state lives with brew, never in the manifest"
    );
}

#[tokio::test]
async fn pin_scopes_the_recorded_cask_kind() {
    let path = temp_manifest_path("pin-cask");
    seed_cask_record(&path, "firefox");
    let fake = FakeRunner::new().strict().respond(
        brew_pin_spec("--cask", "pin", "firefox"),
        CommandOutput::from_stdout(""),
    );
    let adapter = FixtureAdapter::new(SourceKind::HomebrewCask, Vec::new());
    let apps = facade(&fake, macos(), &path, vec![adapter]);

    apps.pin(&id("firefox"))
        .await
        .expect("the recorded kind scopes the pin argv");
    fake.assert_called_with(&brew_pin_spec("--cask", "pin", "firefox"));
    fake.assert_no_unmatched_calls();
}

#[tokio::test]
async fn pin_without_a_record_is_a_typed_error_and_dispatches_nothing() {
    let path = temp_manifest_path("pin-unrecorded");
    let fake = FakeRunner::new().strict();
    let adapter = FixtureAdapter::new(SourceKind::HomebrewCask, Vec::new());
    let apps = facade(&fake, macos(), &path, vec![adapter]);

    let error = apps
        .pin(&id("firefox"))
        .await
        .expect_err("pin operates on what the manifest recorded");
    assert!(
        matches!(error, AppsError::UnrecordedPin { .. }),
        "{error:?}"
    );
    assert!(error.to_string().contains("ensure_installed"), "{error}");
    let error = apps
        .unpin(&id("firefox"))
        .await
        .expect_err("unpin mirrors the record requirement");
    assert!(
        matches!(error, AppsError::UnrecordedUnpin { .. }),
        "{error:?}"
    );
    assert!(fake.calls().is_empty());
}

#[tokio::test]
async fn pin_on_a_flatpak_record_surfaces_the_backend_refusal() {
    let path = temp_manifest_path("pin-flatpak");
    seed_flatpak_record(&path);
    let fake = FakeRunner::new().strict();
    let adapter = FixtureAdapter::new(SourceKind::Flathub, Vec::new());
    let apps = facade(&fake, linux(DistroFamily::Debian), &path, vec![adapter]);

    let error = apps
        .pin(&id("brave"))
        .await
        .expect_err("flatpak has no pin concept");
    assert!(
        matches!(
            error,
            AppsError::Backend(ref inner)
                if matches!(inner, toride_apps::Error::PinUnsupported { .. })
        ),
        "{error:?}"
    );
    assert!(fake.calls().is_empty(), "the refusal dispatches nothing");
}

#[tokio::test]
async fn ensure_installed_at_the_requested_version_on_a_matching_record_is_already_present() {
    let path = temp_manifest_path("version-present-match");
    seed_cask_record(&path, "firefox");
    let fake = FakeRunner::new().strict().respond(
        brew_versions_spec("--cask", "firefox"),
        CommandOutput::from_stdout("firefox 138.0.1\n"),
    );
    let adapter = FixtureAdapter::new(SourceKind::HomebrewCask, Vec::new());
    let mut apps = facade(&fake, macos(), &path, vec![adapter.clone()]);

    let outcome = apps
        .ensure_installed(
            &id("firefox"),
            AppInstallOptions::new().version(Some(Version::new("138.0.1"))),
        )
        .await
        .expect("the record answers at exactly the requested version");

    assert_eq!(
        outcome,
        EnsureAppOutcome::AlreadyPresent(AppStatus::Installed {
            backend: BackendId::Homebrew,
            version: Some("138.0.1".to_owned()),
        })
    );
    let calls = fake.calls();
    assert_eq!(
        calls.len(),
        1,
        "one confirming probe, nothing else: {calls:?}"
    );
    assert_call_is(&calls[0], &brew_versions_spec("--cask", "firefox"));
    assert_eq!(
        adapter.lookups().len(),
        0,
        "the version-matched record answers without resolving"
    );
    fake.assert_no_unmatched_calls();
}

#[tokio::test]
async fn ensure_installed_at_another_version_than_the_record_installs_the_requested_one() {
    let path = temp_manifest_path("version-present-mismatch");
    seed_cask_record(&path, "firefox");
    let fake = FakeRunner::new()
        .strict()
        // Step 1's confirming probe: present, at 138.0.1 — not 139.0.
        .respond(
            brew_versions_spec("--cask", "firefox"),
            CommandOutput::from_stdout("firefox 138.0.1\n"),
        )
        .respond(
            brew_install_cask_spec("firefox@139.0"),
            CommandOutput::from_stdout(""),
        )
        // The backend's post-install probe, then the facade's verify.
        .respond(
            brew_versions_spec("--cask", "firefox@139.0"),
            CommandOutput::from_stdout("firefox@139.0 139.0\n"),
        )
        .respond(
            brew_versions_spec("--cask", "firefox@139.0"),
            CommandOutput::from_stdout("firefox@139.0 139.0\n"),
        );
    let adapter = FixtureAdapter::new(
        SourceKind::HomebrewCask,
        vec![app(
            "firefox",
            "Firefox",
            InstallMethod::Homebrew {
                cask: true,
                token: "firefox".to_owned(),
            },
        )],
    );
    let mut apps = facade(&fake, macos(), &path, vec![adapter]);

    let outcome = apps
        .ensure_installed(
            &id("firefox"),
            AppInstallOptions::new().version(Some(Version::new("139.0"))),
        )
        .await
        .expect("presence at another version installs the requested one");

    let EnsureAppOutcome::Installed { ids, version, .. } = outcome else {
        panic!("expected Installed, got {outcome:?}");
    };
    assert_eq!(
        ids,
        NativeIds::Homebrew {
            token: "firefox@139.0".to_owned(),
            cask: true,
        },
        "the record is replaced by the versioned identity that ran"
    );
    assert_eq!(version.as_deref(), Some("139.0"));
    fake.assert_called_with(&brew_install_cask_spec("firefox@139.0"));
    fake.assert_no_unmatched_calls();
    let reloaded = InstallManifest::load(&path).expect("manifest reloads");
    assert_eq!(
        reloaded.get(&id("firefox")).expect("record present").ids,
        NativeIds::Homebrew {
            token: "firefox@139.0".to_owned(),
            cask: true,
        }
    );
}

#[tokio::test]
async fn ensure_installed_at_the_recorded_flatpak_branch_is_already_present() {
    let path = temp_manifest_path("version-branch-match");
    let mut manifest = InstallManifest::at(&path);
    manifest.record(
        &id("brave"),
        InstallRecord::new(
            toride_apps::InstallPlan {
                app: id("brave"),
                backend: BackendId::Flatpak,
                operation: toride_apps::Operation::FlatpakInstall {
                    remote: "flathub".to_owned(),
                    app_ref: "app/com.brave.Browser/x86_64/beta".to_owned(),
                    installation: toride_apps::FlatpakInstallation::User,
                },
                dry_run: false,
                requires_elevation: false,
            },
            NativeIds::Flatpak {
                app_id: "com.brave.Browser".to_owned(),
                app_ref: Some("app/com.brave.Browser/x86_64/beta".to_owned()),
                installation: toride_apps::FlatpakInstallation::User,
            },
            None,
        )
        .with_installed_at(1_700_000_000),
    );
    manifest.save().expect("seed manifest saves");
    let fake = FakeRunner::new().strict().respond(
        flatpak_list_spec(Some("--user")),
        CommandOutput::from_stdout(flatpak_row("com.brave.Browser", "1.2.3")),
    );
    let adapter = FixtureAdapter::new(SourceKind::Flathub, Vec::new());
    let mut apps = facade(&fake, linux(DistroFamily::Debian), &path, vec![adapter]);

    let outcome = apps
        .ensure_installed(
            &id("brave"),
            AppInstallOptions::new().version(Some(Version::new("beta"))),
        )
        .await
        .expect("the recorded branch satisfies the request");
    assert!(matches!(
        outcome,
        EnsureAppOutcome::AlreadyPresent(AppStatus::Installed { .. })
    ));
    let calls = fake.calls();
    assert_eq!(
        calls.len(),
        1,
        "one confirming listing, nothing else: {calls:?}"
    );
    assert_call_is(&calls[0], &flatpak_list_spec(Some("--user")));
    fake.assert_no_unmatched_calls();
}

#[tokio::test]
async fn ensure_installed_at_another_flatpak_branch_installs_that_branch() {
    let path = temp_manifest_path("version-branch-mismatch");
    seed_flatpak_record(&path);
    let fake = FakeRunner::new()
        .strict()
        // Step 1's confirming listing: present (the record is stable).
        .respond(
            flatpak_list_spec(Some("--user")),
            CommandOutput::from_stdout(flatpak_row("com.brave.Browser", "1.2.3")),
        )
        .respond(
            flatpak_remotes_spec(),
            CommandOutput::from_stdout("flathub\n"),
        )
        .respond(
            flatpak_install_user_spec("app/com.brave.Browser/x86_64/beta"),
            CommandOutput::from_stdout(""),
        )
        // Backend post-verify + facade verify (both the user-scoped list).
        .respond(
            flatpak_list_spec(Some("--user")),
            CommandOutput::from_stdout(flatpak_row("com.brave.Browser", "1.3.0-beta")),
        )
        .respond(
            flatpak_list_spec(Some("--user")),
            CommandOutput::from_stdout(flatpak_row("com.brave.Browser", "1.3.0-beta")),
        );
    let adapter = FixtureAdapter::new(
        SourceKind::Flathub,
        vec![app(
            "brave",
            "Brave Browser",
            InstallMethod::Flatpak {
                app_id: "com.brave.Browser".to_owned(),
                remote: "flathub".to_owned(),
            },
        )],
    );
    let mut apps = facade(&fake, linux(DistroFamily::Debian), &path, vec![adapter]);

    let outcome = apps
        .ensure_installed(
            &id("brave"),
            AppInstallOptions::new().version(Some(Version::new("beta"))),
        )
        .await
        .expect("a stable-branch record does not satisfy a beta request");
    assert!(matches!(outcome, EnsureAppOutcome::Installed { .. }));
    fake.assert_called_with(&flatpak_install_user_spec(
        "app/com.brave.Browser/x86_64/beta",
    ));
    fake.assert_no_unmatched_calls();
    let reloaded = InstallManifest::load(&path).expect("manifest reloads");
    let NativeIds::Flatpak { app_ref, .. } =
        &reloaded.get(&id("brave")).expect("record present").ids
    else {
        panic!("flatpak record");
    };
    assert_eq!(
        app_ref.as_deref(),
        Some("app/com.brave.Browser/x86_64/beta")
    );
}

#[tokio::test]
async fn a_foreign_presence_does_not_vouch_for_a_requested_version() {
    let path = temp_manifest_path("version-foreign");
    let fake = FakeRunner::new()
        .strict()
        // The Foreign check: someone else's firefox is installed.
        .respond(
            brew_info_installed_spec(),
            CommandOutput::from_stdout(FIREFOX_CASK_INFO),
        )
        .respond(
            brew_install_cask_spec("firefox@138.0.1"),
            CommandOutput::from_stdout(""),
        )
        // The backend's post-install probe, then the facade's verify.
        .respond(
            brew_versions_spec("--cask", "firefox@138.0.1"),
            CommandOutput::from_stdout("firefox@138.0.1 138.0.1\n"),
        )
        .respond(
            brew_versions_spec("--cask", "firefox@138.0.1"),
            CommandOutput::from_stdout("firefox@138.0.1 138.0.1\n"),
        );
    let adapter = FixtureAdapter::new(
        SourceKind::HomebrewCask,
        vec![app(
            "firefox",
            "Firefox",
            InstallMethod::Homebrew {
                cask: true,
                token: "firefox".to_owned(),
            },
        )],
    );
    let mut apps = facade(&fake, macos(), &path, vec![adapter]);

    let outcome = apps
        .ensure_installed(
            &id("firefox"),
            AppInstallOptions::new().version(Some(Version::new("138.0.1"))),
        )
        .await
        .expect("a version-less Foreign state satisfies; a named version installs");
    assert!(
        matches!(outcome, EnsureAppOutcome::Installed { .. }),
        "{outcome:?}"
    );
    fake.assert_called_with(&brew_install_cask_spec("firefox@138.0.1"));
    fake.assert_no_unmatched_calls();
}

#[tokio::test]
async fn a_distro_record_with_a_version_request_falls_through_to_the_plan_refusal() {
    let path = temp_manifest_path("version-distro-record");
    seed_distro_record(&path);
    let fake = FakeRunner::new().strict().respond(
        dpkg_query_spec("brave-browser"),
        CommandOutput::from_stdout("ii brave-browser\t1.4.2\n"),
    );
    let adapter = FixtureAdapter::new(
        SourceKind::Distro,
        vec![brave_distro_app(DistroFamily::Debian)],
    );
    let mut apps = facade(&fake, linux(DistroFamily::Debian), &path, vec![adapter]);

    let error = apps
        .ensure_installed(
            &id("brave"),
            AppInstallOptions::new()
                .elevated(true)
                .version(Some(Version::new("1.5.0"))),
        )
        .await
        .expect_err("a distro record cannot satisfy or express a version");
    assert!(
        matches!(
            error,
            AppsError::Backend(ref inner)
                if matches!(inner, toride_apps::Error::VersionNotSelectable { .. })
        ),
        "{error:?}"
    );
    let calls = fake.calls();
    assert_eq!(calls.len(), 1, "only the confirming probe ran: {calls:?}");
    fake.assert_no_unmatched_calls();
}

// ---------------------------------------------------------------------------
// Status and search
// ---------------------------------------------------------------------------

#[tokio::test]
async fn status_reports_installed_from_the_record_and_a_fresh_probe() {
    let path = temp_manifest_path("status-installed");
    seed_cask_record(&path, "firefox");
    let fake = FakeRunner::new().strict().respond(
        brew_versions_spec("--cask", "firefox"),
        CommandOutput::from_stdout("firefox 138.0.1"),
    );
    let adapter = FixtureAdapter::new(SourceKind::HomebrewCask, Vec::new());
    let apps = facade(&fake, macos(), &path, vec![adapter.clone()]);

    let status = apps
        .status(&id("firefox"))
        .await
        .expect("status is a pure query");
    assert_eq!(
        status,
        AppStatus::Installed {
            backend: BackendId::Homebrew,
            version: Some("138.0.1".to_owned()),
        }
    );
    // Manifest-first: a record hit never consults the registry — the
    // resolve the old ordering performed (and discarded) is gone.
    assert_eq!(
        adapter.lookups().len(),
        0,
        "a record hit must be answered without an adapter round trip"
    );
    fake.assert_no_unmatched_calls();
}

#[tokio::test]
async fn status_reports_foreign_from_the_registry_identity() {
    let path = temp_manifest_path("status-foreign");
    let fake = FakeRunner::new().strict().respond(
        brew_info_installed_spec(),
        CommandOutput::from_stdout(FIREFOX_CASK_INFO),
    );
    let adapter = FixtureAdapter::new(
        SourceKind::HomebrewCask,
        vec![app(
            "firefox",
            "Firefox",
            InstallMethod::Homebrew {
                cask: true,
                token: "firefox".to_owned(),
            },
        )],
    );
    let apps = facade(&fake, macos(), &path, vec![adapter]);

    let status = apps
        .status(&id("firefox"))
        .await
        .expect("status resolves best-effort for the Foreign check");
    let AppStatus::Foreign { backend, detail } = status else {
        panic!("expected Foreign, got {status:?}");
    };
    assert_eq!(backend, BackendId::Homebrew);
    assert!(
        detail.contains("not by toride"),
        "the someone-else-installed-this note: {detail}"
    );
}

#[tokio::test]
async fn search_fans_out_across_the_registered_adapters_in_order() {
    let path = temp_manifest_path("search");
    let fake = FakeRunner::new().strict();
    let adapters: Vec<Arc<dyn Adapter>> = vec![
        FixtureAdapter::new(
            SourceKind::HomebrewCask,
            vec![app(
                "firefox",
                "Firefox Browser",
                InstallMethod::Homebrew {
                    cask: true,
                    token: "firefox".to_owned(),
                },
            )],
        ),
        FixtureAdapter::new(
            SourceKind::Flathub,
            vec![app(
                "firefox-flatpak",
                "Firefox Browser (Flathub)",
                InstallMethod::Flatpak {
                    app_id: "org.mozilla.firefox".to_owned(),
                    remote: "flathub".to_owned(),
                },
            )],
        ),
    ];
    let apps = facade(&fake, macos(), &path, adapters);

    let hits = apps
        .search("firefox browser")
        .await
        .expect("search fans out");
    let names: Vec<&str> = hits.iter().map(|hit| hit.name.as_str()).collect();
    assert_eq!(
        names,
        ["Firefox Browser", "Firefox Browser (Flathub)"],
        "registration order, both sources"
    );
    // Search is registry-only: zero runner calls.
    assert!(fake.calls().is_empty());
}

#[tokio::test]
async fn adopt_claims_a_foreign_install_and_the_uninstall_stops_refusing() {
    let path = temp_manifest_path("adopt-foreign");
    let fake = FakeRunner::new()
        .strict()
        .respond(
            brew_versions_spec("--cask", "firefox"),
            CommandOutput::from_stdout("firefox 138.0.1\n"),
        )
        .respond(
            brew_uninstall_cask_spec("firefox"),
            CommandOutput::from_stdout(""),
        )
        .respond(
            brew_versions_spec("--cask", "firefox"),
            brew_silent_absent(),
        );
    let adapter = FixtureAdapter::new(SourceKind::HomebrewCask, Vec::new());
    let mut apps = facade(&fake, macos(), &path, vec![adapter.clone()]);

    let record = apps
        .adopt(
            &id("firefox"),
            AdoptProvenance::new(NativeIds::Homebrew {
                token: "firefox".to_owned(),
                cask: true,
            }),
        )
        .await
        .expect("a detected cask is claimable");
    assert_eq!(record.plan, None, "adoption executed no plan");
    assert_eq!(record.backend, BackendId::Homebrew);
    assert_eq!(record.version.as_deref(), Some("138.0.1"));
    assert_eq!(
        adapter.lookups().len(),
        0,
        "adoption is bookkeeping — zero adapter calls"
    );

    let document: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(path.as_std_path()).expect("manifest file written"),
    )
    .expect("manifest file is JSON");
    assert_eq!(document["apps"]["firefox"]["plan"], serde_json::json!(null));
    assert_eq!(
        document["apps"]["firefox"]["version"],
        serde_json::json!("138.0.1")
    );

    let outcome = apps
        .uninstall(&id("firefox"), AppUninstallOptions::new())
        .await
        .expect("an adopted install is toride-managed");
    assert!(matches!(
        outcome,
        UninstallAppOutcome::Removed {
            backend: BackendId::Homebrew,
            warning: None,
            ..
        }
    ));
    fake.assert_called_with(&brew_uninstall_cask_spec("firefox"));
    fake.assert_no_unmatched_calls();
    assert!(InstallManifest::load(&path).expect("reload").is_empty());
}

#[tokio::test]
async fn adopt_honors_a_callers_install_stamp() {
    let path = temp_manifest_path("adopt-stamp");
    let fake = FakeRunner::new().strict().respond(
        flatpak_list_spec(Some("--user")),
        CommandOutput::from_stdout(flatpak_row("com.brave.Browser", "1.2.3")),
    );
    let adapter = FixtureAdapter::new(SourceKind::Flathub, Vec::new());
    let mut apps = facade(&fake, linux(DistroFamily::Debian), &path, vec![adapter]);

    let mut provenance = AdoptProvenance::new(NativeIds::Flatpak {
        app_id: "com.brave.Browser".to_owned(),
        app_ref: None,
        installation: toride_apps::FlatpakInstallation::User,
    });
    provenance.installed_at = Some(1_600_000_000);
    let record = apps
        .adopt(&id("brave"), provenance)
        .await
        .expect("a detected flatpak is claimable");
    assert_eq!(record.installed_at, 1_600_000_000);
    assert_eq!(record.plan, None);
    assert_eq!(record.version.as_deref(), Some("1.2.3"));
    fake.assert_no_unmatched_calls();
}

#[tokio::test]
async fn adopt_on_an_already_recorded_app_is_a_typed_error_and_dispatches_nothing() {
    let path = temp_manifest_path("adopt-recorded");
    seed_cask_record(&path, "firefox");
    let fake = FakeRunner::new().strict();
    let adapter = FixtureAdapter::new(SourceKind::HomebrewCask, Vec::new());
    let mut apps = facade(&fake, macos(), &path, vec![adapter]);

    let error = apps
        .adopt(
            &id("firefox"),
            AdoptProvenance::new(NativeIds::Homebrew {
                token: "firefox".to_owned(),
                cask: true,
            }),
        )
        .await
        .expect_err("a managed app is not adoptable");
    assert!(
        matches!(error, AppsError::AlreadyRecorded { .. }),
        "{error:?}"
    );
    assert!(fake.calls().is_empty(), "no probe may run");
    assert!(
        InstallManifest::load(&path)
            .expect("reload")
            .get(&id("firefox"))
            .is_some()
    );
}

#[tokio::test]
async fn adopt_of_an_absent_install_is_a_typed_error_and_records_nothing() {
    let path = temp_manifest_path("adopt-absent");
    let fake = FakeRunner::new().strict().respond(
        brew_versions_spec("--cask", "firefox"),
        brew_silent_absent(),
    );
    let adapter = FixtureAdapter::new(SourceKind::HomebrewCask, Vec::new());
    let mut apps = facade(&fake, macos(), &path, vec![adapter]);

    let error = apps
        .adopt(
            &id("firefox"),
            AdoptProvenance::new(NativeIds::Homebrew {
                token: "firefox".to_owned(),
                cask: true,
            }),
        )
        .await
        .expect_err("adoption claims an install that exists");
    assert!(
        matches!(error, AppsError::AdoptionAbsent { .. }),
        "{error:?}"
    );
    let text = error.to_string();
    assert!(text.contains("cask `firefox` is not present"), "{text}");
    fake.assert_no_unmatched_calls();
    assert!(apps.records().is_empty(), "nothing was recorded");
    assert!(
        !path.as_std_path().exists(),
        "no manifest document was written"
    );
}

#[tokio::test]
async fn adopt_on_a_distro_package_probes_the_recorded_family_and_persists() {
    let path = temp_manifest_path("adopt-distro");
    let fake = FakeRunner::new().strict().respond(
        dpkg_query_spec("brave-browser"),
        CommandOutput::from_stdout("ii brave-browser\t1.4.2\n"),
    );
    let adapter = FixtureAdapter::new(SourceKind::Distro, Vec::new());
    let mut apps = facade(&fake, linux(DistroFamily::Debian), &path, vec![adapter]);

    let record = apps
        .adopt(
            &id("brave"),
            AdoptProvenance::new(NativeIds::Distro {
                package: "brave-browser".to_owned(),
                family: DistroFamily::Debian,
            }),
        )
        .await
        .expect("a detected package is claimable");
    assert_eq!(record.backend, BackendId::Distro(DistroFamily::Debian));
    assert_eq!(record.version.as_deref(), Some("1.4.2"));
    fake.assert_no_unmatched_calls();
    assert_eq!(
        InstallManifest::load(&path)
            .expect("reload")
            .get(&id("brave"))
            .expect("record persisted")
            .plan,
        None
    );
}

struct MapStore {
    snapshot: Mutex<RecordSnapshot>,
    saves: Mutex<usize>,
    fail_saves: Mutex<bool>,
}

impl MapStore {
    fn new() -> Self {
        Self {
            snapshot: Mutex::new(RecordSnapshot::empty()),
            saves: Mutex::new(0),
            fail_saves: Mutex::new(false),
        }
    }

    fn save_count(&self) -> usize {
        *self.saves.lock().expect("map store poisoned")
    }

    fn set_fail_saves(&self, fail: bool) {
        *self.fail_saves.lock().expect("map store poisoned") = fail;
    }
}

impl RecordStore for MapStore {
    fn load(&self) -> ManifestResult<StoreLoad> {
        Ok(StoreLoad {
            snapshot: self.snapshot.lock().expect("map store poisoned").clone(),
            quarantined: None,
        })
    }

    fn save(&self, snapshot: &RecordSnapshot) -> ManifestResult<()> {
        if *self.fail_saves.lock().expect("map store poisoned") {
            return Err(ManifestError::Io(std::io::Error::other(
                "map store write refused",
            )));
        }
        *self.snapshot.lock().expect("map store poisoned") = snapshot.clone();
        *self.saves.lock().expect("map store poisoned") += 1;
        Ok(())
    }
}

#[tokio::test]
async fn a_custom_record_store_replaces_the_manifest_and_needs_no_path() {
    let map = Arc::new(MapStore::new());
    let store: Arc<dyn RecordStore> = map.clone();
    let fake = FakeRunner::new()
        .strict()
        .respond(
            brew_info_installed_spec(),
            CommandOutput::from_stdout(EMPTY_BREW_INFO),
        )
        .respond(
            brew_install_cask_spec("firefox"),
            CommandOutput::from_stdout(""),
        )
        .respond(
            brew_versions_spec("--cask", "firefox"),
            CommandOutput::from_stdout("firefox 138.0.1"),
        )
        .respond(
            brew_versions_spec("--cask", "firefox"),
            CommandOutput::from_stdout("firefox 138.0.1"),
        );
    let adapter = FixtureAdapter::new(
        SourceKind::HomebrewCask,
        vec![app(
            "firefox",
            "Firefox",
            InstallMethod::Homebrew {
                cask: true,
                token: "firefox".to_owned(),
            },
        )],
    );
    let seam = CommandRunner::new(Arc::new(fake.clone()));
    let mut apps = Apps::builder()
        .runner(seam.clone())
        .target(macos())
        .with_record_store(Arc::clone(&store))
        .homebrew(HomebrewBackend::new(seam.clone()))
        .flatpak(FlatpakBackend::new(seam.clone()))
        .distro(DistroBackend::new(DistroFamily::Debian, seam))
        .adapter(adapter)
        .build()
        .expect("a custom store needs no manifest path");
    assert_eq!(apps.quarantined(), None);

    apps.ensure_installed(&id("firefox"), AppInstallOptions::new())
        .await
        .expect("the install flows through the custom store");
    let snapshot = store.load().unwrap().snapshot;
    assert_eq!(snapshot.records.len(), 1, "the record landed in the store");
    assert_eq!(
        snapshot.records[&id("firefox")].version.as_deref(),
        Some("138.0.1")
    );
    assert!(map.save_count() > 0);
    fake.assert_no_unmatched_calls();

    let fake = FakeRunner::new().strict().respond(
        brew_versions_spec("--cask", "firefox"),
        CommandOutput::from_stdout("firefox 138.0.1\n"),
    );
    let seam = CommandRunner::new(Arc::new(fake.clone()));
    let apps = Apps::builder()
        .runner(seam.clone())
        .target(macos())
        .with_record_store(Arc::clone(&store))
        .homebrew(HomebrewBackend::new(seam.clone()))
        .flatpak(FlatpakBackend::new(seam.clone()))
        .distro(DistroBackend::new(DistroFamily::Debian, seam))
        .build()
        .expect("the second facade builds over the same store");
    assert_eq!(apps.records().len(), 1);
    assert_eq!(
        apps.status(&id("firefox")).await.unwrap(),
        AppStatus::Installed {
            backend: BackendId::Homebrew,
            version: Some("138.0.1".to_owned()),
        }
    );
    fake.assert_no_unmatched_calls();
}

#[tokio::test]
async fn the_custom_store_receives_whole_snapshots_on_every_mutation() {
    let map = Arc::new(MapStore::new());
    let store: Arc<dyn RecordStore> = map.clone();
    let fake = FakeRunner::new().strict().respond(
        brew_versions_spec("--cask", "firefox"),
        CommandOutput::from_stdout("firefox 138.0.1\n"),
    );
    let seam = CommandRunner::new(Arc::new(fake.clone()));
    let mut apps = Apps::builder()
        .runner(seam.clone())
        .target(macos())
        .with_record_store(Arc::clone(&store))
        .homebrew(HomebrewBackend::new(seam.clone()))
        .build()
        .expect("facade builds");

    apps.adopt(
        &id("firefox"),
        AdoptProvenance::new(NativeIds::Homebrew {
            token: "firefox".to_owned(),
            cask: true,
        }),
    )
    .await
    .expect("adoption persists through the store");
    let snapshot = store.load().unwrap().snapshot;
    assert_eq!(snapshot.records.len(), 1);
    assert_eq!(snapshot.records[&id("firefox")].plan, None);
    assert_eq!(map.save_count(), 1, "one save per mutation");
    fake.assert_no_unmatched_calls();
}

#[tokio::test]
async fn update_replays_an_adopted_records_identifiers_and_keeps_it_plan_less() {
    let path = temp_manifest_path("adopt-update");
    let fake = FakeRunner::new()
        .strict()
        .respond(
            brew_versions_spec("--cask", "firefox"),
            CommandOutput::from_stdout("firefox 138.0.1\n"),
        )
        .respond(
            brew_versions_spec("--cask", "firefox"),
            CommandOutput::from_stdout("firefox 138.0.1\n"),
        )
        .respond(
            brew_outdated_spec("--cask"),
            CommandOutput::from_stdout(firefox_cask_outdated("138.0.1", "139.0")),
        )
        .respond(
            brew_upgrade_cask_spec("firefox"),
            CommandOutput::from_stdout(""),
        )
        .respond(
            brew_versions_spec("--cask", "firefox"),
            CommandOutput::from_stdout("firefox 139.0\n"),
        );
    let adapter = FixtureAdapter::new(SourceKind::HomebrewCask, Vec::new());
    let mut apps = facade(&fake, macos(), &path, vec![adapter]);

    apps.adopt(
        &id("firefox"),
        AdoptProvenance::new(NativeIds::Homebrew {
            token: "firefox".to_owned(),
            cask: true,
        }),
    )
    .await
    .expect("claim the detected cask");
    let outcome = apps
        .update(&id("firefox"), &AppUpdateOptions::new())
        .await
        .expect("an adopted record updates like an executed one");
    assert_eq!(
        outcome,
        UpdateOutcome::Updated {
            from: Some(Version::new("138.0.1")),
            to: Some(Version::new("139.0")),
        }
    );
    fake.assert_no_unmatched_calls();
    let reloaded = InstallManifest::load(&path).expect("manifest reloads");
    let record = reloaded.get(&id("firefox")).expect("record survives");
    assert_eq!(record.version.as_deref(), Some("139.0"));
    assert_eq!(record.plan, None, "still plan-less after the upgrade");
}

#[tokio::test]
async fn a_failed_adopt_save_rolls_the_claim_back_and_a_retry_succeeds() {
    let map = Arc::new(MapStore::new());
    map.set_fail_saves(true);
    let store: Arc<dyn RecordStore> = map.clone();
    let fake = FakeRunner::new()
        .strict()
        .respond(
            brew_versions_spec("--cask", "firefox"),
            CommandOutput::from_stdout("firefox 138.0.1\n"),
        )
        .respond(
            brew_versions_spec("--cask", "firefox"),
            CommandOutput::from_stdout("firefox 138.0.1\n"),
        );
    let seam = CommandRunner::new(Arc::new(fake.clone()));
    let mut apps = Apps::builder()
        .runner(seam.clone())
        .target(macos())
        .with_record_store(Arc::clone(&store))
        .homebrew(HomebrewBackend::new(seam))
        .build()
        .expect("facade builds");

    let error = apps
        .adopt(
            &id("firefox"),
            AdoptProvenance::new(NativeIds::Homebrew {
                token: "firefox".to_owned(),
                cask: true,
            }),
        )
        .await
        .expect_err("a store that cannot persist refuses the claim");
    assert!(
        matches!(error, AppsError::Manifest(ManifestError::Io(_))),
        "{error:?}"
    );
    assert!(
        apps.records().is_empty(),
        "the in-memory claim is rolled back — no AlreadyRecorded ghost"
    );
    assert!(
        map.snapshot
            .lock()
            .expect("map store poisoned")
            .records
            .is_empty(),
        "nothing was persisted"
    );

    map.set_fail_saves(false);
    let record = apps
        .adopt(
            &id("firefox"),
            AdoptProvenance::new(NativeIds::Homebrew {
                token: "firefox".to_owned(),
                cask: true,
            }),
        )
        .await
        .expect("the retry claims cleanly once the store recovers");
    assert_eq!(record.version.as_deref(), Some("138.0.1"));
    assert_eq!(
        map.snapshot
            .lock()
            .expect("map store poisoned")
            .records
            .len(),
        1
    );
    fake.assert_no_unmatched_calls();
}
