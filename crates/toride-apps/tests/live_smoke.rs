//! Mutating live smoke for the language/distro facade wiring — real
//! managers, real network, throwaway state only.
//!
//! Gated behind `TORIDE_APPS_INTEGRATION=1` (the `tests/live.rs` env-gate
//! precedent), and every manager leg self-skips when its manager — or,
//! for the linuxbrew leg, `git` — is absent from the PATH, so the plain
//! gate run stays side-effect-free (the direct leg has no manager: it
//! needs the network and fails without it):
//!
//! ```text
//! TORIDE_APPS_INTEGRATION=1 cargo test -p toride-apps --all-features --all-targets
//! ```
//!
//! Each test drives the NEW facade path end to end — resolve (async
//! facade) or the resolved app (blocking facade), `ensure_installed` ->
//! installed-version probe -> `update` -> re-probe -> `uninstall` —
//! asserting the outcome taxonomy (`Installed`/`AlreadyPresent`/
//! `Updated`/`UpToDate`/`Removed`/`NotInstalled`) and that each probe
//! read the real manager's own output shape.
//!
//! Throwaway state only, never the user's real tool config, and every
//! scratch dir self-deletes on exit: npm `-g` into a scratch
//! `npm_config_prefix`, `cargo install` into a scratch
//! `CARGO_INSTALL_ROOT` (the shared crates.io registry cache stays
//! read-mostly, like any build), mise against isolated `MISE_DATA_DIR` /
//! `MISE_CONFIG_FILE`, uv/pipx into scratch `UV_TOOL_DIR`/`PIPX_HOME`,
//! the direct leg's release artifact into a scratch install dir. On
//! macOS the brew legs pour obscure tokens into the host's own Homebrew
//! under `HOMEBREW_NO_AUTO_UPDATE=1` and remove them again, self-skipping
//! when the token is already installed (cask legs additionally require
//! macOS, since `brew install --cask` refuses elsewhere); on Linux the
//! formula leg pours into a scratch-prefix Homebrew — a shallow `git
//! clone` whose `HOMEBREW_CACHE`/`TEMP`/`LOGS`, `HOME`, and
//! `XDG_CONFIG_HOME` all point into the scratch dir, never the host's
//! brew state.
//! pacman/apk mutate the host's package database — never throwaway on a
//! real machine — so they demand a second explicit opt-in,
//! `TORIDE_APPS_DISTRO_SMOKE=1`, that only the CI archlinux/alpine
//! container jobs set; on any long-lived Arch/Alpine host both legs skip.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use camino::Utf8PathBuf;
#[cfg(feature = "mise")]
use toride_apps::MiseBackend;
use toride_apps::apps::{
    AppInstallOptions, AppUninstallOptions, AppUpdateOptions, Apps, AppsBuilder, EnsureAppOutcome,
    UninstallAppOutcome, UpdateOutcome,
};
#[cfg(all(feature = "direct", target_os = "linux"))]
use toride_apps::backends::DirectBackend;
use toride_apps::backends::distro::detect_host_family;
use toride_apps::backends::homebrew::{BrewKind, HomebrewBackend};
use toride_apps::backends::{CargoBackend, DistroBackend, NpmBackend, PipxBackend, UvBackend};
use toride_apps::manifest::{InstallRecord, NativeIds};
use toride_apps::runner::CommandRunner;
use toride_apps::{AppStatus, AppsError, BackendId, Version};
use toride_registry::model::{App, InstallMethod, SourceKind, SourceRef};
#[cfg(all(feature = "direct", target_os = "linux"))]
use toride_registry::model::{Checksum, ChecksumAlgo};
use toride_registry::{Adapter, Availability, DistroFamily, TorideId};

static DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

fn integration_enabled() -> bool {
    matches!(std::env::var("TORIDE_APPS_INTEGRATION").as_deref(), Ok("1"))
}

fn distro_smoke_enabled() -> bool {
    matches!(
        std::env::var("TORIDE_APPS_DISTRO_SMOKE").as_deref(),
        Ok("1")
    )
}

fn skip(manager: &str) {
    eprintln!("{manager} absent from PATH; skipping live smoke test");
}

fn manager_on_path(binary: &str) -> bool {
    toride_runner::discovery::find_binary(binary).is_ok()
}

struct ScratchDir {
    path: Utf8PathBuf,
}

impl ScratchDir {
    fn new(label: &str) -> Self {
        let unique = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "toride-apps-smoke-{}-{unique}-{label}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("scratch dir is creatable");
        Self {
            path: Utf8PathBuf::from_path_buf(path).expect("system temp dir is valid UTF-8"),
        }
    }

    #[cfg(target_os = "linux")]
    fn short(label: &str) -> Self {
        let mut unique = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        loop {
            let candidate =
                std::env::temp_dir().join(format!("{label}{}{unique}", std::process::id()));
            match std::fs::create_dir(&candidate) {
                Ok(()) => {
                    return Self {
                        path: Utf8PathBuf::from_path_buf(candidate)
                            .expect("system temp dir is valid UTF-8"),
                    };
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => unique += 1,
                Err(error) => panic!("reserving the short scratch dir failed: {error}"),
            }
        }
    }

    fn path(&self) -> &Utf8PathBuf {
        &self.path
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn language_app(id: &TorideId, name: &str, method: InstallMethod) -> App {
    App {
        id: id.clone(),
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

struct ResolvedAppAdapter {
    app: App,
}

#[async_trait]
impl Adapter for ResolvedAppAdapter {
    fn source(&self) -> SourceKind {
        SourceKind::Repology
    }

    async fn lookup(&self, id: &SourceRef) -> toride_registry::Result<Option<App>> {
        Ok(if self.app.id.as_str() == id.id {
            Some(self.app.clone())
        } else {
            None
        })
    }

    async fn search(&self, _query: &str) -> toride_registry::Result<Vec<App>> {
        Ok(Vec::new())
    }
}

fn facade_base(runner: CommandRunner, manifest: Utf8PathBuf, app: App) -> AppsBuilder {
    Apps::builder()
        .runner(runner)
        .manifest_path(manifest)
        .adapter(Arc::new(ResolvedAppAdapter { app }))
}

fn only_record(apps: &Apps) -> &InstallRecord {
    let (_, record) = apps
        .records()
        .pop()
        .expect("the install wrote a manifest record");
    record
}

fn assert_installed(
    outcome: &EnsureAppOutcome,
    backend: BackendId,
    ids: &NativeIds,
) -> Option<String> {
    let EnsureAppOutcome::Installed {
        backend: actual_backend,
        ids: actual_ids,
        version,
        verified,
        warning,
    } = outcome
    else {
        panic!("expected Installed, got {outcome:?}");
    };
    assert_eq!(actual_backend, &backend);
    assert_eq!(actual_ids, ids);
    assert!(verified, "the facade's own probe must confirm the install");
    assert_eq!(warning, &None, "nothing degraded may hide in the outcome");
    version.clone()
}

fn assert_already_present_at(outcome: &EnsureAppOutcome, backend: BackendId) -> Option<String> {
    match outcome {
        EnsureAppOutcome::AlreadyPresent(AppStatus::Installed {
            backend: probed,
            version,
        }) => {
            assert_eq!(probed, &backend);
            version.clone()
        }
        other => panic!("expected AlreadyPresent(Installed), got {other:?}"),
    }
}

fn assert_updated(outcome: &UpdateOutcome, from: Option<&str>) -> Option<String> {
    match outcome {
        UpdateOutcome::Updated { from: actual, to } => {
            assert_eq!(
                actual.as_ref().map(Version::as_str),
                from,
                "from is the pre-upgrade probe"
            );
            to.as_ref().map(Version::as_str).map(str::to_owned)
        }
        other => panic!("expected Updated, got {other:?}"),
    }
}

fn assert_removed(outcome: &UninstallAppOutcome, backend: BackendId) {
    assert!(matches!(
        outcome,
        UninstallAppOutcome::Removed {
            backend: removed_backend,
            warning: None,
            ..
        } if *removed_backend == backend
    ));
}

async fn assert_reensure_at(
    apps: &mut Apps,
    id: &TorideId,
    backend: BackendId,
    version: Option<&str>,
) {
    if let Some(version) = version {
        let again = apps
            .ensure_installed(
                id,
                AppInstallOptions::new().version(Some(Version::new(version))),
            )
            .await
            .expect("pinned re-ensure probes, never re-installs");
        assert_eq!(
            assert_already_present_at(&again, backend).as_deref(),
            Some(version),
            "a record at the requested pin must answer AlreadyPresent at that version"
        );
    }
    let unversioned = apps
        .ensure_installed(id, AppInstallOptions::new())
        .await
        .expect("unversioned ensure probes");
    assert_eq!(
        assert_already_present_at(&unversioned, backend).as_deref(),
        version,
        "a version-less request must answer AlreadyPresent at the recorded version"
    );
}

async fn assert_update_to_current(apps: &mut Apps, id: &TorideId, backend: BackendId, from: &str) {
    let updated = apps
        .update(id, &AppUpdateOptions::new())
        .await
        .expect("npm update -g succeeds");
    let to = assert_updated(&updated, Some(from));
    assert_ne!(
        to.as_deref(),
        Some(from),
        "npm update -g moves the pinned install to the registry current: {to:?}"
    );
    let status = apps.status(id).await.expect("post-update status");
    assert_eq!(
        status,
        AppStatus::Installed {
            backend,
            version: to,
        },
        "the update leg rewrote the record at the re-probed version"
    );
}

#[tokio::test]
async fn npm_facade_installs_probes_updates_and_uninstalls_a_real_global_package() {
    if !integration_enabled() {
        eprintln!("TORIDE_APPS_INTEGRATION not set; skipping live smoke test");
        return;
    }
    if !manager_on_path("npm") {
        skip("npm");
        return;
    }
    let scratch = ScratchDir::new("npm");
    let prefix = scratch.path().join("npm-prefix");
    std::fs::create_dir_all(&prefix).expect("scratch npm prefix is creatable");
    let runner = CommandRunner::builder()
        .env("npm_config_prefix", prefix.as_str())
        .build();
    let id = TorideId::slugify("cowsay");
    let app = language_app(
        &id,
        "cowsay",
        InstallMethod::Npm {
            package: "cowsay".to_owned(),
            version: None,
        },
    );
    let mut apps = facade_base(
        runner.clone(),
        scratch.path().join("apps-manifest.json"),
        app,
    )
    .npm(NpmBackend::detect(runner).expect("npm was just found on PATH"))
    .build()
    .expect("facade builds over the scratch manifest");

    let pinned = AppInstallOptions::new().version(Some(Version::new("1.5.0")));
    let version = assert_installed(
        &apps
            .ensure_installed(&id, pinned)
            .await
            .expect("npm install -g at a pinned version succeeds"),
        BackendId::Npm,
        &NativeIds::Npm {
            package: "cowsay".to_owned(),
        },
    );
    assert_eq!(
        version.as_deref(),
        Some("1.5.0"),
        "the probe read the version out of npm's own global listing"
    );
    assert_eq!(
        only_record(&apps).version.as_deref(),
        Some("1.5.0"),
        "the record carries the probed version"
    );
    assert!(
        matches!(
            only_record(&apps)
                .plan
                .as_ref()
                .expect("recorded plan")
                .operation,
            toride_apps::Operation::NpmInstall {
                version: Some(_),
                global: true,
                ..
            }
        ),
        "the executed plan pinned the version (the registry offers a newer current)"
    );

    assert_reensure_at(&mut apps, &id, BackendId::Npm, Some("1.5.0")).await;
    let status = apps.status(&id).await.expect("status probes the record");
    assert_eq!(
        status,
        AppStatus::Installed {
            backend: BackendId::Npm,
            version: Some("1.5.0".to_owned()),
        },
        "status re-read the real npm listing"
    );

    assert_update_to_current(&mut apps, &id, BackendId::Npm, "1.5.0").await;

    assert_removed(
        &apps
            .uninstall(&id, AppUninstallOptions::new())
            .await
            .expect("npm uninstall -g succeeds"),
        BackendId::Npm,
    );
    let after = apps.status(&id).await.expect("post-uninstall status");
    assert_eq!(after, AppStatus::NotInstalled);
}

#[tokio::test]
async fn cargo_facade_installs_probes_updates_and_uninstalls_a_real_crate() {
    if !integration_enabled() {
        eprintln!("TORIDE_APPS_INTEGRATION not set; skipping live smoke test");
        return;
    }
    if !manager_on_path("cargo") {
        skip("cargo");
        return;
    }
    let scratch = ScratchDir::new("cargo");
    let install_root = scratch.path().join("cargo-root");
    let runner = CommandRunner::builder()
        .env("CARGO_INSTALL_ROOT", install_root.as_str())
        .build();
    let id = TorideId::slugify("leave");
    let app = language_app(
        &id,
        "leave",
        InstallMethod::Cargo {
            crate_: "leave".to_owned(),
            version: None,
        },
    );
    let mut apps = facade_base(
        runner.clone(),
        scratch.path().join("apps-manifest.json"),
        app,
    )
    .cargo(CargoBackend::detect(runner).expect("cargo was just found on PATH"))
    .build()
    .expect("facade builds over the scratch manifest");

    let pinned = AppInstallOptions::new().version(Some(Version::new("0.1.0")));
    let version = assert_installed(
        &apps
            .ensure_installed(&id, pinned)
            .await
            .expect("cargo install into the scratch root succeeds"),
        BackendId::Cargo,
        &NativeIds::Cargo {
            crate_: "leave".to_owned(),
        },
    );
    assert_eq!(
        version.as_deref(),
        Some("0.1.0"),
        "the probe read the version out of cargo install --list"
    );
    assert!(
        matches!(
            only_record(&apps)
                .plan
                .as_ref()
                .expect("recorded plan")
                .operation,
            toride_apps::Operation::CargoInstall { version: None, .. }
        ),
        "the offering equals the request, so the plan installs the manager's current"
    );

    assert_reensure_at(&mut apps, &id, BackendId::Cargo, Some("0.1.0")).await;
    assert_eq!(
        apps.update(&id, &AppUpdateOptions::new())
            .await
            .expect("the currency probe itself must succeed"),
        UpdateOutcome::UpToDate,
        "the registry's only version is installed, so update answers UpToDate without running"
    );

    assert_removed(
        &apps
            .uninstall(&id, AppUninstallOptions::new())
            .await
            .expect("cargo uninstall from the scratch root succeeds"),
        BackendId::Cargo,
    );
    let after = apps.status(&id).await.expect("post-uninstall status");
    assert_eq!(after, AppStatus::NotInstalled);
}

#[cfg(feature = "mise")]
#[test]
fn mise_facade_installs_probes_updates_and_uninstalls_a_real_tool() {
    if !integration_enabled() {
        eprintln!("TORIDE_APPS_INTEGRATION not set; skipping live smoke test");
        return;
    }
    if !manager_on_path("mise") {
        skip("mise");
        return;
    }
    let scratch = ScratchDir::new("mise");
    let data_dir = scratch.path().join("mise-data");
    std::fs::create_dir_all(&data_dir).expect("scratch mise data dir is creatable");
    let runner = CommandRunner::builder()
        .env("MISE_DATA_DIR", data_dir.as_str())
        .env(
            "MISE_CONFIG_FILE",
            scratch.path().join("mise.toml").as_str(),
        )
        .build();
    let id = TorideId::slugify("bat");
    let app = language_app(
        &id,
        "bat",
        InstallMethod::Mise {
            tool: "bat".to_owned(),
            version: None,
        },
    );
    let mut apps = facade_base(
        runner.clone(),
        scratch.path().join("apps-manifest.json"),
        app.clone(),
    )
    .mise(MiseBackend::detect(runner).expect("mise was just found on PATH"))
    .build()
    .expect("facade builds over the scratch manifest")
    .blocking();

    let pinned = AppInstallOptions::new().version(Some(Version::new("0.25.0")));
    let version = assert_installed(
        &apps
            .ensure_installed(&app, pinned)
            .expect("mise install + use --global at a pin into the scratch dirs succeeds"),
        BackendId::Mise,
        &NativeIds::Mise {
            tool: "bat".to_owned(),
        },
    );
    assert_eq!(
        version.as_deref(),
        Some("0.25.0"),
        "the probe read the pinned version out of mise ls --installed --json"
    );

    let again = apps
        .ensure_installed(&app, AppInstallOptions::new())
        .expect("unversioned re-ensure probes");
    assert_eq!(
        assert_already_present_at(&again, BackendId::Mise).as_deref(),
        Some("0.25.0"),
        "a record the backend confirms must answer AlreadyPresent at the recorded version"
    );
    let updated = apps
        .update(&id, &AppUpdateOptions::new())
        .expect("mise upgrade bat succeeds");
    let to = assert_updated(&updated, Some("0.25.0"));
    assert_eq!(
        to.as_deref(),
        Some("0.25.0"),
        "mise upgrade answers within the requested spec (config-pinned), so from == to"
    );

    assert_removed(
        &apps
            .uninstall(&id, AppUninstallOptions::new())
            .expect("mise uninstall from the scratch data dir succeeds"),
        BackendId::Mise,
    );
    let after = apps.status(&id).expect("post-uninstall status");
    assert_eq!(after, AppStatus::NotInstalled);
}

#[tokio::test]
async fn uv_facade_installs_probes_updates_and_uninstalls_a_real_tool() {
    if !integration_enabled() {
        eprintln!("TORIDE_APPS_INTEGRATION not set; skipping live smoke test");
        return;
    }
    if !manager_on_path("uv") {
        skip("uv");
        return;
    }
    let scratch = ScratchDir::new("uv");
    let tool_dir = scratch.path().join("uv-tools");
    std::fs::create_dir_all(&tool_dir).expect("scratch uv tool dir is creatable");
    let runner = CommandRunner::builder()
        .env("UV_TOOL_DIR", tool_dir.as_str())
        .env("UV_TOOL_BIN_DIR", scratch.path().join("uv-bin").as_str())
        .build();
    let id = TorideId::slugify("pycowsay");
    let app = language_app(
        &id,
        "pycowsay",
        InstallMethod::Uv {
            package: "pycowsay".to_owned(),
            version: None,
        },
    );
    let mut apps = facade_base(
        runner.clone(),
        scratch.path().join("apps-manifest.json"),
        app,
    )
    .uv(UvBackend::detect(runner).expect("uv was just found on PATH"))
    .build()
    .expect("facade builds over the scratch manifest");

    let version = assert_installed(
        &apps
            .ensure_installed(&id, AppInstallOptions::new())
            .await
            .expect("uv tool install into the scratch dirs succeeds"),
        BackendId::Uv,
        &NativeIds::Uv {
            package: "pycowsay".to_owned(),
        },
    );
    assert!(
        version
            .as_deref()
            .is_some_and(|version| !version.is_empty()),
        "the probe read the version out of uv tool list: {version:?}"
    );
    let reported = version.clone().unwrap_or_default();

    assert_reensure_at(&mut apps, &id, BackendId::Uv, Some(reported.as_str())).await;
    let updated = apps
        .update(&id, &AppUpdateOptions::new())
        .await
        .expect("uv tool upgrade succeeds");
    assert!(
        assert_updated(&updated, Some(reported.as_str())).is_some(),
        "uv exposes no availability probe, so update always dispatches and re-probes"
    );

    assert_removed(
        &apps
            .uninstall(&id, AppUninstallOptions::new())
            .await
            .expect("uv tool uninstall from the scratch dirs succeeds"),
        BackendId::Uv,
    );
    let after = apps.status(&id).await.expect("post-uninstall status");
    assert_eq!(after, AppStatus::NotInstalled);
}

#[tokio::test]
async fn pipx_facade_installs_probes_updates_and_uninstalls_a_real_tool() {
    if !integration_enabled() {
        eprintln!("TORIDE_APPS_INTEGRATION not set; skipping live smoke test");
        return;
    }
    if !manager_on_path("pipx") {
        skip("pipx");
        return;
    }
    let scratch = ScratchDir::new("pipx");
    let home = scratch.path().join("pipx-home");
    std::fs::create_dir_all(&home).expect("scratch pipx home is creatable");
    let runner = CommandRunner::builder()
        .env("PIPX_HOME", home.as_str())
        .env("PIPX_BIN_DIR", scratch.path().join("pipx-bin").as_str())
        .build();
    let id = TorideId::slugify("pycowsay");
    let app = language_app(
        &id,
        "pycowsay",
        InstallMethod::Pipx {
            package: "pycowsay".to_owned(),
        },
    );
    let mut apps = facade_base(
        runner.clone(),
        scratch.path().join("apps-manifest.json"),
        app,
    )
    .pipx(PipxBackend::detect(runner).expect("pipx was just found on PATH"))
    .build()
    .expect("facade builds over the scratch manifest");

    let version = assert_installed(
        &apps
            .ensure_installed(&id, AppInstallOptions::new())
            .await
            .expect("pipx install into the scratch home succeeds"),
        BackendId::Pipx,
        &NativeIds::Pipx {
            package: "pycowsay".to_owned(),
        },
    );
    assert!(
        version
            .as_deref()
            .is_some_and(|version| !version.is_empty()),
        "the probe read the version out of pipx list --json: {version:?}"
    );
    let reported = version.clone().unwrap_or_default();

    assert_reensure_at(&mut apps, &id, BackendId::Pipx, Some(reported.as_str())).await;
    let updated = apps
        .update(&id, &AppUpdateOptions::new())
        .await
        .expect("pipx upgrade succeeds");
    assert!(
        assert_updated(&updated, Some(reported.as_str())).is_some(),
        "pipx exposes no availability probe, so update always dispatches and re-probes"
    );

    assert_removed(
        &apps
            .uninstall(&id, AppUninstallOptions::new())
            .await
            .expect("pipx uninstall from the scratch home succeeds"),
        BackendId::Pipx,
    );
    let after = apps.status(&id).await.expect("post-uninstall status");
    assert_eq!(after, AppStatus::NotInstalled);
}

#[cfg(all(feature = "direct", target_os = "linux"))]
#[tokio::test]
async fn direct_facade_downloads_verifies_extracts_and_uninstalls_a_real_release_artifact() {
    const URL: &str = "https://github.com/BurntSushi/ripgrep/releases/download/14.1.0/\
                       ripgrep-14.1.0-x86_64-unknown-linux-musl.tar.gz";
    const SHA256: &str = "f84757b07f425fe5cf11d87df6644691c644a5cd2348a2c670894272999d3ba7";
    if !integration_enabled() {
        eprintln!("TORIDE_APPS_INTEGRATION not set; skipping live smoke test");
        return;
    }
    let scratch = ScratchDir::new("direct");
    let install_dir = scratch.path().join("bin");
    std::fs::create_dir_all(&install_dir).expect("scratch direct install dir is creatable");
    let id = TorideId::slugify("ripgrep");
    let mut app = language_app(
        &id,
        "Ripgrep",
        InstallMethod::Direct {
            url: URL.to_owned(),
            checksum: Some(Checksum {
                algo: ChecksumAlgo::Sha256,
                digest: SHA256.to_owned(),
            }),
            arch: None,
        },
    );
    app.binaries = vec!["rg".to_owned()];
    let mut apps = facade_base(
        CommandRunner::builder().build(),
        scratch.path().join("apps-manifest.json"),
        app,
    )
    .direct(DirectBackend::at(install_dir.clone()))
    .build()
    .expect("facade builds over the scratch manifest");

    let rg = install_dir.join("rg");
    assert!(
        !rg.exists(),
        "the scratch install dir starts empty, so nothing foreign can be clobbered"
    );
    let version = assert_installed(
        &apps
            .ensure_installed(&id, AppInstallOptions::new())
            .await
            .expect("the real download → sha256 verify → tarball extract → install succeeds"),
        BackendId::Direct,
        &NativeIds::Direct {
            url: URL.to_owned(),
            checksum: Some(SHA256.to_owned()),
            bin_path: rg.to_string(),
        },
    );
    assert_eq!(version, None, "a direct binary reports no version");
    assert!(
        matches!(
            only_record(&apps)
                .plan
                .as_ref()
                .expect("recorded plan")
                .operation,
            toride_apps::Operation::DirectInstall { ref bin_name, .. } if bin_name == "rg"
        ),
        "the executed plan installed the tarball's real entry name"
    );

    assert_installed_release_binary_runs(&rg);

    assert_reensure_at(&mut apps, &id, BackendId::Direct, None).await;
    assert_eq!(
        apps.status(&id).await.expect("status probes the record"),
        AppStatus::Installed {
            backend: BackendId::Direct,
            version: None,
        },
        "status re-read the installed file"
    );

    assert_removed(
        &apps
            .uninstall(&id, AppUninstallOptions::new())
            .await
            .expect("the recorded binary removal succeeds"),
        BackendId::Direct,
    );
    assert!(!rg.exists());
    let after = apps.status(&id).await.expect("post-uninstall status");
    assert_eq!(after, AppStatus::NotInstalled);
}

#[cfg(all(feature = "direct", target_os = "linux"))]
fn assert_installed_release_binary_runs(rg: &Utf8PathBuf) {
    let bytes = std::fs::read(rg.as_std_path()).expect("the installed artifact is readable");
    assert!(
        bytes.starts_with(b"\x7fELF"),
        "the extracted entry is the real ELF binary, not a sibling doc file"
    );
    let mode = std::fs::metadata(rg.as_std_path())
        .expect("the installed artifact is statable")
        .permissions();
    assert_eq!(
        std::os::unix::fs::PermissionsExt::mode(&mode) & 0o777,
        0o755,
        "the atomic install write made the binary executable"
    );
    #[cfg(target_arch = "x86_64")]
    {
        let run = std::process::Command::new(rg.as_std_path())
            .arg("--version")
            .output()
            .expect("the downloaded musl binary executes on this host");
        assert!(run.status.success(), "rg --version must exit 0");
        let stdout = String::from_utf8_lossy(&run.stdout);
        assert!(
            stdout.contains("ripgrep 14.1.0"),
            "the binary reports its own release: {stdout}"
        );
    }
}

#[tokio::test]
async fn pacman_facade_installs_probes_updates_and_uninstalls_a_real_package() {
    if !integration_enabled() || !distro_smoke_enabled() {
        eprintln!(
            "TORIDE_APPS_INTEGRATION/TORIDE_APPS_DISTRO_SMOKE not both set; skipping \
             distro-db smoke test (throwaway containers only)"
        );
        return;
    }
    if detect_host_family() != Some(DistroFamily::Arch) || !manager_on_path("pacman") {
        skip("pacman (host is not Arch family)");
        return;
    }
    let runner = CommandRunner::builder().build();
    let id = TorideId::slugify("tree");
    let app = language_app(
        &id,
        "tree",
        InstallMethod::Distro {
            family: DistroFamily::Arch,
            repo: None,
            package: "tree".to_owned(),
        },
    );
    let scratch = ScratchDir::new("pacman");
    let mut apps = facade_base(
        runner.clone(),
        scratch.path().join("apps-manifest.json"),
        app,
    )
    .distro(DistroBackend::detect(runner).expect("pacman was just found on PATH"))
    .build()
    .expect("facade builds over the scratch manifest");

    let version = assert_installed(
        &apps
            .ensure_installed(&id, AppInstallOptions::new().elevated(true))
            .await
            .expect("pacman --sync --noconfirm tree succeeds in the container"),
        BackendId::Distro(DistroFamily::Arch),
        &NativeIds::Distro {
            package: "tree".to_owned(),
            family: DistroFamily::Arch,
        },
    );
    assert!(
        version
            .as_deref()
            .is_some_and(|version| !version.is_empty()),
        "the probe read the version out of pacman --query: {version:?}"
    );

    let again = apps
        .ensure_installed(&id, AppInstallOptions::new())
        .await
        .expect("unversioned re-ensure probes");
    assert_eq!(
        assert_already_present_at(&again, BackendId::Distro(DistroFamily::Arch)).as_deref(),
        version.as_deref(),
        "a version-less request must answer AlreadyPresent at the recorded version"
    );
    let refused = apps
        .ensure_installed(
            &id,
            AppInstallOptions::new().version(Some(Version::new(version.as_deref().unwrap_or("0")))),
        )
        .await
        .expect_err("distro methods are pin-less, so a versioned request refuses at plan time");
    assert!(
        matches!(
            refused,
            AppsError::Backend(ref inner)
                if matches!(inner, toride_apps::Error::VersionNotSelectable { .. })
        ),
        "{refused:?}"
    );
    let updated = apps
        .update(&id, &AppUpdateOptions::new().elevated(true))
        .await
        .expect("pacman --sync --refresh --noconfirm tree succeeds in the container");
    assert!(
        assert_updated(&updated, version.as_deref()).is_some(),
        "distro exposes no availability probe, so update always dispatches and re-probes"
    );

    assert_removed(
        &apps
            .uninstall(&id, AppUninstallOptions::new().elevated(true))
            .await
            .expect("pacman --remove --noconfirm tree succeeds in the container"),
        BackendId::Distro(DistroFamily::Arch),
    );
    let after = apps.status(&id).await.expect("post-uninstall status");
    assert_eq!(after, AppStatus::NotInstalled);
}

#[tokio::test]
async fn apk_facade_installs_probes_updates_and_uninstalls_a_real_package() {
    if !integration_enabled() || !distro_smoke_enabled() {
        eprintln!(
            "TORIDE_APPS_INTEGRATION/TORIDE_APPS_DISTRO_SMOKE not both set; skipping \
             distro-db smoke test (throwaway containers only)"
        );
        return;
    }
    if detect_host_family() != Some(DistroFamily::Alpine) || !manager_on_path("apk") {
        skip("apk (host is not Alpine family)");
        return;
    }
    let runner = CommandRunner::builder().build();
    let id = TorideId::slugify("tree");
    let app = language_app(
        &id,
        "tree",
        InstallMethod::Distro {
            family: DistroFamily::Alpine,
            repo: None,
            package: "tree".to_owned(),
        },
    );
    let scratch = ScratchDir::new("apk");
    let mut apps = facade_base(
        runner.clone(),
        scratch.path().join("apps-manifest.json"),
        app,
    )
    .distro(DistroBackend::detect(runner).expect("apk was just found on PATH"))
    .build()
    .expect("facade builds over the scratch manifest");

    let version = assert_installed(
        &apps
            .ensure_installed(&id, AppInstallOptions::new().elevated(true))
            .await
            .expect("apk add tree succeeds in the container"),
        BackendId::Distro(DistroFamily::Alpine),
        &NativeIds::Distro {
            package: "tree".to_owned(),
            family: DistroFamily::Alpine,
        },
    );
    assert_eq!(
        version, None,
        "apk's quiet listing reports presence without a version — the documented row shape"
    );

    assert_reensure_at(
        &mut apps,
        &id,
        BackendId::Distro(DistroFamily::Alpine),
        None,
    )
    .await;
    let updated = apps
        .update(&id, &AppUpdateOptions::new().elevated(true))
        .await
        .expect("apk upgrade tree succeeds in the container");
    assert_eq!(
        assert_updated(&updated, None),
        None,
        "the version-less row shape holds through the update leg's re-probe"
    );

    assert_removed(
        &apps
            .uninstall(&id, AppUninstallOptions::new().elevated(true))
            .await
            .expect("apk del tree succeeds in the container"),
        BackendId::Distro(DistroFamily::Alpine),
    );
    let after = apps.status(&id).await.expect("post-uninstall status");
    assert_eq!(after, AppStatus::NotInstalled);
}

fn brew_runner() -> CommandRunner {
    CommandRunner::builder()
        .env("HOMEBREW_NO_AUTO_UPDATE", "1")
        .build()
}

#[cfg(target_os = "linux")]
fn scratch_linuxbrew_runner() -> (ScratchDir, CommandRunner) {
    let root = ScratchDir::short("tb");
    let prefix = root.path().join("pfx");
    assert!(
        prefix.as_str().len() <= 26,
        "linuxbrew bottles relocate only into prefixes of at most 26 characters: {}",
        prefix.as_str()
    );
    let state = root.path().join("s");
    for dir in ["cache", "tmp", "home", "xdg"] {
        std::fs::create_dir_all(state.join(dir))
            .expect("the scratch linuxbrew state dirs are creatable");
    }
    let clone = std::process::Command::new("git")
        .args(["clone", "--depth=1", "--quiet"])
        .arg("https://github.com/Homebrew/brew")
        .arg(prefix.as_str())
        .output()
        .expect("git spawns for the scratch linuxbrew clone");
    assert!(
        clone.status.success(),
        "the shallow Homebrew clone into the scratch prefix failed: {}",
        String::from_utf8_lossy(&clone.stderr)
    );
    let runner = CommandRunner::builder()
        .env(
            "PATH",
            format!(
                "{}:{}",
                prefix.join("bin"),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .env("HOMEBREW_PREFIX", prefix.as_str())
        .env("HOMEBREW_CACHE", state.join("cache").as_str())
        .env("HOMEBREW_TEMP", state.join("tmp").as_str())
        .env("HOMEBREW_LOGS", state.join("logs").as_str())
        .env("XDG_CONFIG_HOME", state.join("xdg").as_str())
        .env("HOME", state.join("home").as_str())
        .env("HOMEBREW_NO_AUTO_UPDATE", "1")
        .build();
    runner
        .run_checked_sync(runner.command("brew", ["config"]))
        .expect("the scratch linuxbrew bootstraps (portable ruby + API data)");
    (root, runner)
}

fn macos_host() -> bool {
    cfg!(target_os = "macos")
}

#[tokio::test]
async fn brew_cask_facade_installs_probes_updates_and_uninstalls_a_real_cask() {
    if !integration_enabled() {
        eprintln!("TORIDE_APPS_INTEGRATION not set; skipping live smoke test");
        return;
    }
    if !manager_on_path("brew") {
        skip("brew");
        return;
    }
    if !macos_host() {
        skip("brew cask (host is not macOS)");
        return;
    }
    let scratch = ScratchDir::new("brew-cask");
    let runner = brew_runner();
    let backend = HomebrewBackend::detect(runner.clone()).expect("brew was just found on PATH");
    if backend
        .installed_version(BrewKind::Cask, "stats")
        .await
        .expect("the cask presence probe succeeds")
        .is_some()
    {
        skip("brew cask `stats` (already installed on this host)");
        return;
    }
    let offered = backend
        .available_version(BrewKind::Cask, "stats")
        .await
        .expect("the offering probe succeeds")
        .expect("the tap knows the `stats` cask");
    let id = TorideId::slugify("stats");
    let app = language_app(
        &id,
        "Stats",
        InstallMethod::Homebrew {
            cask: true,
            token: "stats".to_owned(),
        },
    );
    let mut apps = facade_base(runner, scratch.path().join("apps-manifest.json"), app)
        .homebrew(backend)
        .build()
        .expect("facade builds over the scratch manifest");

    let version = assert_installed(
        &apps
            .ensure_installed(&id, AppInstallOptions::new())
            .await
            .expect("brew install --cask stats succeeds"),
        BackendId::Homebrew,
        &NativeIds::Homebrew {
            token: "stats".to_owned(),
            cask: true,
        },
    );
    assert_eq!(
        version.as_deref(),
        Some(offered.as_str()),
        "the probe read the poured version out of brew's own cask listing"
    );
    assert!(
        matches!(
            only_record(&apps)
                .plan
                .as_ref()
                .expect("recorded plan")
                .operation,
            toride_apps::Operation::BrewInstall {
                cask: true,
                ref token,
            } if token == "stats"
        ),
        "the executed plan addressed the unversioned cask token"
    );

    assert_reensure_at(&mut apps, &id, BackendId::Homebrew, Some(offered.as_str())).await;
    let status = apps.status(&id).await.expect("status probes the record");
    assert_eq!(
        status,
        AppStatus::Installed {
            backend: BackendId::Homebrew,
            version: Some(offered.as_str().to_owned()),
        },
        "status re-read the real cask listing"
    );
    assert_eq!(
        apps.update(&id, &AppUpdateOptions::new())
            .await
            .expect("the kind-scoped stale probe succeeds"),
        UpdateOutcome::UpToDate,
        "a freshly poured cask is current, so update answers UpToDate without running"
    );

    assert_removed(
        &apps
            .uninstall(&id, AppUninstallOptions::new())
            .await
            .expect("brew uninstall --cask stats succeeds"),
        BackendId::Homebrew,
    );
    let after = apps.status(&id).await.expect("post-uninstall status");
    assert_eq!(after, AppStatus::NotInstalled);
}

#[tokio::test]
async fn brew_formula_facade_installs_pins_updates_and_uninstalls_a_real_formula() {
    if !integration_enabled() {
        eprintln!("TORIDE_APPS_INTEGRATION not set; skipping live smoke test");
        return;
    }
    #[cfg(target_os = "linux")]
    {
        if !manager_on_path("git") {
            skip("linuxbrew (git is absent, so no scratch prefix can be cloned)");
            return;
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        if !manager_on_path("brew") {
            skip("brew");
            return;
        }
    }
    let scratch = ScratchDir::new("brew-formula");
    #[cfg(target_os = "linux")]
    let (_linuxbrew_state, runner) = scratch_linuxbrew_runner();
    #[cfg(not(target_os = "linux"))]
    let runner = brew_runner();
    let backend = HomebrewBackend::new(runner.clone());
    if backend
        .installed_version(BrewKind::Formula, "sl")
        .await
        .expect("the formula presence probe succeeds")
        .is_some()
    {
        skip("brew formula `sl` (already installed on this host)");
        return;
    }
    let id = TorideId::slugify("sl");
    let app = language_app(
        &id,
        "sl",
        InstallMethod::Homebrew {
            cask: false,
            token: "sl".to_owned(),
        },
    );
    let mut apps = facade_base(runner, scratch.path().join("apps-manifest.json"), app)
        .homebrew(backend)
        .build()
        .expect("facade builds over the scratch manifest");

    let version = assert_installed(
        &apps
            .ensure_installed(&id, AppInstallOptions::new())
            .await
            .expect("brew install sl succeeds"),
        BackendId::Homebrew,
        &NativeIds::Homebrew {
            token: "sl".to_owned(),
            cask: false,
        },
    );
    assert!(
        version
            .as_deref()
            .is_some_and(|version| !version.is_empty()),
        "the probe read the version out of brew's own formula listing: {version:?}"
    );

    apps.pin(&id)
        .await
        .expect("brew pin sl succeeds through the facade");
    apps.unpin(&id)
        .await
        .expect("brew unpin sl succeeds through the facade");
    assert_eq!(
        apps.update(&id, &AppUpdateOptions::new())
            .await
            .expect("the kind-scoped stale probe succeeds"),
        UpdateOutcome::UpToDate,
        "a freshly poured, unpinned formula is current, so update answers UpToDate without running"
    );

    assert_removed(
        &apps
            .uninstall(&id, AppUninstallOptions::new())
            .await
            .expect("brew uninstall sl succeeds"),
        BackendId::Homebrew,
    );
    let after = apps.status(&id).await.expect("post-uninstall status");
    assert_eq!(after, AppStatus::NotInstalled);
}

#[tokio::test]
async fn brew_cask_requesting_the_offering_over_a_foreign_pour_dispatches_an_argv_brew_accepts() {
    if !integration_enabled() {
        eprintln!("TORIDE_APPS_INTEGRATION not set; skipping live smoke test");
        return;
    }
    if !manager_on_path("brew") {
        skip("brew");
        return;
    }
    if !macos_host() {
        skip("brew cask (host is not macOS)");
        return;
    }
    let scratch = ScratchDir::new("brew-foreign");
    let runner = brew_runner();
    let backend = HomebrewBackend::detect(runner.clone()).expect("brew was just found on PATH");
    let offered = backend
        .available_version(BrewKind::Cask, "rectangle")
        .await
        .expect("the offering probe succeeds")
        .expect("the tap knows the `rectangle` cask");
    let id = TorideId::slugify("rectangle");
    let app = language_app(
        &id,
        "Rectangle",
        InstallMethod::Homebrew {
            cask: true,
            token: "rectangle".to_owned(),
        },
    );
    let mut setup = facade_base(
        runner.clone(),
        scratch.path().join("setup-manifest.json"),
        app.clone(),
    )
    .homebrew(HomebrewBackend::new(runner.clone()))
    .build()
    .expect("setup facade builds over the scratch manifest");
    assert_installed(
        &setup
            .ensure_installed(&id, AppInstallOptions::new())
            .await
            .expect("the foreign pour itself succeeds"),
        BackendId::Homebrew,
        &NativeIds::Homebrew {
            token: "rectangle".to_owned(),
            cask: true,
        },
    );

    let mut apps = facade_base(runner, scratch.path().join("apps-manifest.json"), app)
        .homebrew(backend)
        .build()
        .expect("facade builds over the scratch manifest");
    let outcome = apps
        .ensure_installed(&id, AppInstallOptions::new().version(Some(offered.clone())))
        .await
        .expect(
            "requesting the current offering over a foreign pour dispatches an argv brew accepts",
        );
    let version = assert_installed(
        &outcome,
        BackendId::Homebrew,
        &NativeIds::Homebrew {
            token: "rectangle".to_owned(),
            cask: true,
        },
    );
    assert_eq!(
        version.as_deref(),
        Some(offered.as_str()),
        "the recorded identity is the unversioned token — the pre-fix code dispatched \
         `rectangle@{offered}`, the spelling brew refuses for unversioned cask tokens"
    );

    assert_removed(
        &apps
            .uninstall(&id, AppUninstallOptions::new())
            .await
            .expect("brew uninstall --cask rectangle succeeds"),
        BackendId::Homebrew,
    );
    let after = apps.status(&id).await.expect("post-uninstall status");
    assert_eq!(after, AppStatus::NotInstalled);
}
