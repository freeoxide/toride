//! Live integration tests for toride-apps — real host PATH, real network.
//!
//! Gated behind `TORIDE_APPS_INTEGRATION=1` (the toride-installer
//! `TORIDE_INSTALLER_INTEGRATION` precedent) so the normal gate run stays
//! offline and side-effect-free, and compiled only with the
//! `registry-http` feature (the registry's fetch engine is opt-in):
//!
//! ```text
//! TORIDE_APPS_INTEGRATION=1 cargo test -p toride-apps --test live --features registry-http
//! ```

#![cfg(feature = "registry-http")]
//!
//! What runs when the gate is open (and what deliberately does not):
//!
//! - the `detect()` seams of all three backends against the REAL host PATH
//!   and `/etc/os-release` — brew and flatpak are expected to be absent on
//!   this Linux host, dpkg present, but every assertion branches on what
//!   the host actually has, so nothing is assumed either way;
//! - the real toride-registry fetch layers through this crate's public
//!   surface: the Homebrew and Flathub adapters resolving live apps into
//!   planner input (pure `plan_install` afterward — no execution), the
//!   DEP-11 appstream fetch (a multi-megabyte catalog download into a
//!   scratch cache dir; the slowest test here), and one read-only
//!   end-to-end facade `status` composing a real adapter with real
//!   backend detection;
//! - NO install/uninstall probe anywhere: every mutating operation would
//!   change the host (brew/flatpak/apt installs are exactly what the
//!   offline suites pin with fakes), so none is attempted even under the
//!   gate.

use std::sync::Arc;

use toride_apps::backends::distro::detect_host_family;
use toride_apps::backends::{DistroBackend, FlatpakBackend, HomebrewBackend};
use toride_apps::runner::CommandRunner;
use toride_apps::{
    AppStatus, Apps, Backend, BackendId, BackendStatus, InstallOptions, StatusQuery, Target,
    plan_install,
};
use toride_registry::sources::appstream::{AppstreamAdapter, AppstreamClient, DEBIAN_BASE_URL};
use toride_registry::sources::flathub::FlathubAdapter;
use toride_registry::sources::homebrew::HomebrewAdapter;
use toride_registry::{
    Adapter, Arch, DistroFamily, InstallMethod, SourceKind, SourceRef, TorideId,
};
use toride_runner::discovery::find_binary;

/// The env gate — matches the installer precedent (`Ok("1")` exactly, not
/// merely "set").
fn integration_enabled() -> bool {
    matches!(std::env::var("TORIDE_APPS_INTEGRATION").as_deref(), Ok("1"))
}

/// A unique scratch path under the system temp dir (the facade test's
/// manifest never actually gets written — every operation in this file is
/// read-only — but the path must not collide with a real manifest).
fn scratch_path(label: &str) -> camino::Utf8PathBuf {
    let dir = std::env::temp_dir().join(format!("toride-apps-live-{}-{label}", std::process::id()));
    camino::Utf8PathBuf::from_path_buf(dir)
        .expect("system temp dir is valid UTF-8")
        .join("scratch")
}

/// A lookup reference for one source-native id, the shape the facade
/// itself builds when resolving a slug.
fn reference(source: SourceKind, id: &str) -> SourceRef {
    SourceRef {
        source,
        id: id.to_owned(),
        repo: None,
        version: None,
        provisional: false,
    }
}

// ---------------------------------------------------------------------------
// detect() seams — the real host PATH and /etc/os-release
// ---------------------------------------------------------------------------

/// brew/flatpak `detect()` is a real PATH check; on this Linux host both
/// binaries are absent, so both must refuse with `BinaryNotFound` naming
/// the binary. On a host that does carry them, the same call must succeed
/// — the test asserts whichever reality holds, never a hard-coded one.
#[test]
fn brew_and_flatpak_detect_track_the_real_host_path() {
    if !integration_enabled() {
        eprintln!("TORIDE_APPS_INTEGRATION not set; skipping live test");
        return;
    }
    let runner = CommandRunner::builder().build();

    match find_binary("brew") {
        Ok(_) => assert!(
            HomebrewBackend::detect(runner.clone()).is_ok(),
            "brew is on PATH; detect must succeed"
        ),
        Err(_) => match HomebrewBackend::detect(runner.clone()) {
            Err(toride_apps::Error::Command(toride_runner::Error::BinaryNotFound(name))) => {
                assert_eq!(name, "brew");
            }
            Ok(_) => panic!("brew absent from PATH; detect must refuse"),
            Err(other) => panic!(
                "brew absent from PATH; detect must refuse with BinaryNotFound, got {other:?}"
            ),
        },
    }

    match find_binary("flatpak") {
        Ok(_) => assert!(
            FlatpakBackend::detect(runner.clone()).is_ok(),
            "flatpak is on PATH; detect must succeed"
        ),
        Err(_) => match FlatpakBackend::detect(runner) {
            Err(toride_apps::Error::Command(toride_runner::Error::BinaryNotFound(name))) => {
                assert_eq!(name, "flatpak");
            }
            Ok(_) => panic!("flatpak absent from PATH; detect must refuse"),
            Err(other) => panic!(
                "flatpak absent from PATH; detect must refuse with BinaryNotFound, got {other:?}"
            ),
        },
    }
}

/// The distro seam reads the real `/etc/os-release` and probes the
/// family's executor on the real PATH. On this Debian host that means
/// `detect()` succeeds with family Debian and the dpkg-backed probes
/// answer live queries: an absent package is `NotInstalled` (dpkg-query's
/// documented exit-1 shape), a package every Debian host carries (`dpkg`
/// itself) reports a version. Both apt families qualify — ubuntu-latest
/// detects as Ubuntu, and Mint and kin reach Ubuntu through `ID_LIKE` —
/// so the dpkg probes run there too; hosts outside the apt family only
/// get the detect smoke assert, honestly labeled.
#[tokio::test]
async fn distro_detect_probes_this_host_through_its_real_package_manager() {
    if !integration_enabled() {
        eprintln!("TORIDE_APPS_INTEGRATION not set; skipping live test");
        return;
    }
    let family = detect_host_family();
    let backend = DistroBackend::detect(CommandRunner::builder().build())
        .expect("this host's family is detectable and its executor is on PATH");

    match family {
        Some(DistroFamily::Debian | DistroFamily::Ubuntu) => {
            let absent = backend
                .status(StatusQuery::new("toride-live-absent-package"))
                .await
                .expect("an absent package is an answer, never an error");
            assert_eq!(absent, BackendStatus::NotInstalled);

            let present = backend
                .installed_version("dpkg")
                .await
                .expect("dpkg-query itself must be runnable on a Debian host");
            assert!(present.is_some(), "dpkg is installed on every Debian host");
        }
        other => {
            eprintln!(
                "host is not Debian-family (os-release says {other:?}); skipping dpkg probes"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Real registry adapters — the live fetch layers behind the facade's resolve
// ---------------------------------------------------------------------------

/// The Flathub adapter resolves a well-known app id over the real v2 API
/// and normalizes it into planner input; the pure planner then derives the
/// canonical install argv from the LIVE app (no execution anywhere).
#[tokio::test]
async fn flathub_adapter_resolves_a_live_app_into_a_plannable_operation() {
    if !integration_enabled() {
        eprintln!("TORIDE_APPS_INTEGRATION not set; skipping live test");
        return;
    }
    let app = FlathubAdapter::default()
        .lookup(&reference(SourceKind::Flathub, "org.mozilla.firefox"))
        .await
        .expect("flathub.org must be reachable")
        .expect("org.mozilla.firefox exists on Flathub");
    assert!(matches!(app.install, InstallMethod::Flatpak { .. }));

    // Pure planning against a Linux target — the host never needs flatpak.
    let plan = plan_install(
        &app,
        &Target::linux(Arch::X86_64, DistroFamily::Debian),
        &InstallOptions::default(),
    )
    .expect("a live flatpak app plans for a linux target");
    assert_eq!(plan.backend, BackendId::Flatpak);
    let owned = plan.operation.argv();
    let argv: Vec<&str> = owned.iter().map(String::as_str).collect();
    assert_eq!(argv[..4], ["flatpak", "install", "--user", "flathub"]);
    assert!(
        argv[4].starts_with("app/org.mozilla.firefox/"),
        "ref derives from the live app id: {argv:?}"
    );
}

/// The Homebrew adapter is pure HTTP — formulae.brew.sh's API — so it
/// resolves on a host without brew installed (this one); the live formula
/// then plans to the exact Linuxbrew argv.
#[tokio::test]
async fn homebrew_adapter_resolves_a_live_formula_without_brew_installed() {
    if !integration_enabled() {
        eprintln!("TORIDE_APPS_INTEGRATION not set; skipping live test");
        return;
    }
    let app = HomebrewAdapter::new()
        .lookup(&reference(SourceKind::HomebrewFormula, "ripgrep"))
        .await
        .expect("formulae.brew.sh must be reachable")
        .expect("the ripgrep formula exists");
    assert!(matches!(
        app.install,
        InstallMethod::Homebrew { cask: false, .. }
    ));

    // Formulae plan on Linux too (Linuxbrew); no brew binary is involved.
    let plan = plan_install(
        &app,
        &Target::linux(Arch::X86_64, DistroFamily::Debian),
        &InstallOptions::default(),
    )
    .expect("a live formula plans for a linux target");
    assert_eq!(plan.backend, BackendId::Homebrew);
    let owned = plan.operation.argv();
    let argv: Vec<&str> = owned.iter().map(String::as_str).collect();
    assert_eq!(argv, ["brew", "install", "ripgrep"]);
}

/// The appstream fetch layer — the heaviest live surface: Debian's DEP-11
/// catalog for stable/main streams through the disk cache and parses into
/// the adapter, which must normalize a well-known package into the distro
/// install method and plan the apt argv.
#[tokio::test]
async fn appstream_fetch_normalizes_the_live_debian_catalog() {
    if !integration_enabled() {
        eprintln!("TORIDE_APPS_INTEGRATION not set; skipping live test");
        return;
    }
    let cache = scratch_path("appstream-cache");
    std::fs::create_dir_all(&cache).expect("scratch cache dir is creatable");
    let text = AppstreamClient::new(&cache)
        .fetch_catalog(DEBIAN_BASE_URL, "bookworm", "main", "amd64")
        .await
        .expect("deb.debian.org must be reachable");
    let adapter =
        AppstreamAdapter::from_text(&text, Some(Arch::X86_64)).expect("the live catalog parses");

    // gitg, not a household name like firefox-esr: bookworm's dep11
    // catalog ships 0 firefox-esr components (132 for gitg), so probing
    // firefox-esr here fails the lookup confusingly — do not "fix" this
    // back to firefox-esr without checking the catalog first.
    let app = adapter
        .lookup(&reference(SourceKind::Distro, "gitg"))
        .await
        .expect("the in-memory catalog never fails a lookup")
        .expect("gitg is a desktop application in Debian main");
    assert!(matches!(
        app.install,
        InstallMethod::Distro {
            family: DistroFamily::Debian,
            ..
        }
    ));

    let plan = plan_install(
        &app,
        &Target::linux(Arch::X86_64, DistroFamily::Debian),
        &InstallOptions::default(),
    )
    .expect("a live distro app plans for its own family");
    assert_eq!(plan.backend, BackendId::Distro(DistroFamily::Debian));
    assert!(plan.requires_elevation, "distro plans never auto-sudo");
    let owned = plan.operation.argv();
    let argv: Vec<&str> = owned.iter().map(String::as_str).collect();
    assert_eq!(argv, ["apt", "install", "gitg"]);
}

// ---------------------------------------------------------------------------
// Facade end-to-end — one read-only status probe
// ---------------------------------------------------------------------------

/// One guarded facade probe (the only one that is safe): a real Flathub
/// adapter resolves the id live and `detect_backends()` wires whatever
/// this host actually has, then `status` must answer honestly. On this
/// flatpak-less host the resolution succeeds but the flatpak backend slot
/// is absent, so the answer is `NotInstalled`; on a host carrying flatpak
/// the app may genuinely be present, and `Foreign`/`Installed` are then
/// the honest answers too — only a flatpak-less host answering anything
/// but `NotInstalled` is a bug.
#[tokio::test]
async fn facade_status_composes_a_real_adapter_with_real_backend_detection() {
    if !integration_enabled() {
        eprintln!("TORIDE_APPS_INTEGRATION not set; skipping live test");
        return;
    }
    let apps = Apps::builder()
        .adapter(Arc::new(FlathubAdapter::default()))
        .detect_backends()
        .expect("detect skips absent backends; it cannot fail on a healthy host")
        .manifest_path(scratch_path("facade-manifest"))
        .build()
        .expect("the scratch manifest path always builds");

    let status = apps
        .status(&TorideId::slugify("org.mozilla.firefox"))
        .await
        .expect("status degrades resolve failures; it cannot fail here");
    match status {
        AppStatus::NotInstalled => {}
        other => {
            assert!(
                find_binary("flatpak").is_ok(),
                "no flatpak on this host; NotInstalled was the only honest answer, got {other:?}"
            );
        }
    }
}
