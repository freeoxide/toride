//! Mutating live smoke for the language/distro facade wiring — real
//! managers, real network, throwaway state only.
//!
//! Gated behind `TORIDE_APPS_INTEGRATION=1` (the `tests/live.rs` env-gate
//! precedent), and every test additionally self-skips when its manager is
//! absent from the PATH, so the plain gate run — and any host — stays
//! side-effect-free:
//!
//! ```text
//! TORIDE_APPS_INTEGRATION=1 cargo test -p toride-apps --all-features --all-targets
//! ```
//!
//! Each test drives the NEW facade path end to end — resolve (async
//! facade) or the resolved app (blocking facade), `ensure_installed` ->
//! installed-version probe -> `uninstall` — asserting the outcome
//! taxonomy (`Installed`/`AlreadyPresent`/`Removed`/`NotInstalled`) and
//! that each probe read the real manager's own output shape.
//!
//! Throwaway state only, never the user's real tool config: npm `-g`
//! into a scratch `npm_config_prefix`, `cargo install` into a scratch
//! `CARGO_INSTALL_ROOT` (the shared crates.io registry cache stays
//! read-mostly, like any build), mise against isolated `MISE_DATA_DIR` /
//! `MISE_CONFIG_FILE`, uv/pipx into scratch `UV_TOOL_DIR`/`PIPX_HOME`.
//! pacman/apk mutate the host's package database and therefore run only
//! inside the CI archlinux/alpine container jobs, which are themselves
//! throwaway.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use camino::Utf8PathBuf;
#[cfg(feature = "mise")]
use toride_apps::MiseBackend;
use toride_apps::apps::{
    AppInstallOptions, AppUninstallOptions, Apps, AppsBuilder, EnsureAppOutcome,
    UninstallAppOutcome,
};
use toride_apps::backends::distro::detect_host_family;
use toride_apps::backends::{CargoBackend, DistroBackend, NpmBackend, PipxBackend, UvBackend};
use toride_apps::manifest::NativeIds;
use toride_apps::runner::CommandRunner;
use toride_apps::{AppStatus, BackendId, Version};
use toride_registry::model::{App, InstallMethod, SourceKind, SourceRef};
use toride_registry::{Adapter, Availability, DistroFamily, TorideId};

static DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

fn integration_enabled() -> bool {
    matches!(std::env::var("TORIDE_APPS_INTEGRATION").as_deref(), Ok("1"))
}

fn skip(manager: &str) {
    eprintln!("{manager} absent from PATH; skipping live smoke test");
}

fn manager_on_path(binary: &str) -> bool {
    toride_runner::discovery::find_binary(binary).is_ok()
}

fn scratch_dir(label: &str) -> Utf8PathBuf {
    let unique = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "toride-apps-smoke-{}-{unique}-{label}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("scratch dir is creatable");
    Utf8PathBuf::from_path_buf(dir).expect("system temp dir is valid UTF-8")
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

fn facade_base(runner: CommandRunner, label: &str, app: App) -> AppsBuilder {
    Apps::builder()
        .runner(runner)
        .manifest_path(scratch_dir(label).join("apps-manifest.json"))
        .adapter(Arc::new(ResolvedAppAdapter { app }))
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

#[tokio::test]
async fn npm_facade_installs_probes_and_uninstalls_a_real_global_package() {
    if !integration_enabled() {
        eprintln!("TORIDE_APPS_INTEGRATION not set; skipping live smoke test");
        return;
    }
    if !manager_on_path("npm") {
        skip("npm");
        return;
    }
    let scratch = scratch_dir("npm");
    let prefix = scratch.join("npm-prefix");
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
    let mut apps = facade_base(runner.clone(), "npm", app)
        .npm(NpmBackend::detect(runner).expect("npm was just found on PATH"))
        .build()
        .expect("facade builds over the scratch manifest");

    let pinned = AppInstallOptions::new().version(Some(Version::new("1.5.0")));
    let version = assert_installed(
        &apps
            .ensure_installed(&id, pinned.clone())
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
    let (_, record) = apps
        .records()
        .pop()
        .expect("the install wrote a manifest record");
    assert_eq!(
        record.version.as_deref(),
        Some("1.5.0"),
        "the record carries the probed version"
    );
    assert!(
        matches!(
            record.plan.as_ref().expect("recorded plan").operation,
            toride_apps::Operation::NpmInstall {
                version: Some(_),
                global: true,
                ..
            }
        ),
        "the executed plan pinned the version (the registry offers a newer current)"
    );

    let again = apps
        .ensure_installed(&id, pinned)
        .await
        .expect("re-ensure probes, never re-installs");
    assert_eq!(
        assert_already_present_at(&again, BackendId::Npm).as_deref(),
        Some("1.5.0"),
        "a record at the requested pin must answer AlreadyPresent at that version"
    );
    let unversioned = apps
        .ensure_installed(&id, AppInstallOptions::new())
        .await
        .expect("unversioned ensure probes");
    assert_eq!(
        assert_already_present_at(&unversioned, BackendId::Npm).as_deref(),
        Some("1.5.0"),
        "a version-less request must answer AlreadyPresent at the recorded version"
    );
    let status = apps.status(&id).await.expect("status probes the record");
    assert_eq!(
        status,
        AppStatus::Installed {
            backend: BackendId::Npm,
            version: Some("1.5.0".to_owned()),
        },
        "status re-read the real npm listing"
    );

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
async fn cargo_facade_installs_probes_and_uninstalls_a_real_crate() {
    if !integration_enabled() {
        eprintln!("TORIDE_APPS_INTEGRATION not set; skipping live smoke test");
        return;
    }
    if !manager_on_path("cargo") {
        skip("cargo");
        return;
    }
    let scratch = scratch_dir("cargo");
    let install_root = scratch.join("cargo-root");
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
    let mut apps = facade_base(runner.clone(), "cargo", app)
        .cargo(CargoBackend::detect(runner).expect("cargo was just found on PATH"))
        .build()
        .expect("facade builds over the scratch manifest");

    let pinned = AppInstallOptions::new().version(Some(Version::new("0.1.0")));
    let version = assert_installed(
        &apps
            .ensure_installed(&id, pinned.clone())
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
    let (_, record) = apps
        .records()
        .pop()
        .expect("the install wrote a manifest record");
    assert!(
        matches!(
            record.plan.as_ref().expect("recorded plan").operation,
            toride_apps::Operation::CargoInstall { version: None, .. }
        ),
        "the offering equals the request, so the plan installs the manager's current"
    );

    let again = apps
        .ensure_installed(&id, pinned)
        .await
        .expect("re-ensure probes, never re-installs");
    assert_eq!(
        assert_already_present_at(&again, BackendId::Cargo).as_deref(),
        Some("0.1.0"),
        "a record at the requested pin must answer AlreadyPresent at that version"
    );
    let status = apps.status(&id).await.expect("status probes the record");
    assert_eq!(
        status,
        AppStatus::Installed {
            backend: BackendId::Cargo,
            version: Some("0.1.0".to_owned()),
        },
        "status re-read the real cargo listing"
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
fn mise_facade_installs_probes_and_uninstalls_a_real_tool() {
    if !integration_enabled() {
        eprintln!("TORIDE_APPS_INTEGRATION not set; skipping live smoke test");
        return;
    }
    if !manager_on_path("mise") {
        skip("mise");
        return;
    }
    let scratch = scratch_dir("mise");
    let data_dir = scratch.join("mise-data");
    std::fs::create_dir_all(&data_dir).expect("scratch mise data dir is creatable");
    let runner = CommandRunner::builder()
        .env("MISE_DATA_DIR", data_dir.as_str())
        .env("MISE_CONFIG_FILE", scratch.join("mise.toml").as_str())
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
    let mut apps = facade_base(runner.clone(), "mise", app.clone())
        .mise(MiseBackend::detect(runner).expect("mise was just found on PATH"))
        .build()
        .expect("facade builds over the scratch manifest")
        .blocking();

    let version = assert_installed(
        &apps
            .ensure_installed(&app, AppInstallOptions::new())
            .expect("mise install + use --global into the scratch dirs succeeds"),
        BackendId::Mise,
        &NativeIds::Mise {
            tool: "bat".to_owned(),
        },
    );
    assert!(
        version
            .as_deref()
            .is_some_and(|version| !version.is_empty()),
        "the probe read the version out of mise ls --installed --json: {version:?}"
    );
    let reported = version.clone().unwrap_or_default();

    let again = apps
        .ensure_installed(&app, AppInstallOptions::new())
        .expect("re-ensure probes, never re-installs");
    assert_eq!(
        assert_already_present_at(&again, BackendId::Mise).as_deref(),
        Some(reported.as_str()),
        "a record the backend confirms must answer AlreadyPresent at the reported version"
    );
    let status = apps.status(&id).expect("status probes the record");
    assert_eq!(
        status,
        AppStatus::Installed {
            backend: BackendId::Mise,
            version: Some(reported.clone()),
        },
        "status re-read the real mise listing"
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
async fn uv_facade_installs_probes_and_uninstalls_a_real_tool() {
    if !integration_enabled() {
        eprintln!("TORIDE_APPS_INTEGRATION not set; skipping live smoke test");
        return;
    }
    if !manager_on_path("uv") {
        skip("uv");
        return;
    }
    let scratch = scratch_dir("uv");
    let tool_dir = scratch.join("uv-tools");
    std::fs::create_dir_all(&tool_dir).expect("scratch uv tool dir is creatable");
    let runner = CommandRunner::builder()
        .env("UV_TOOL_DIR", tool_dir.as_str())
        .env("UV_TOOL_BIN_DIR", scratch.join("uv-bin").as_str())
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
    let mut apps = facade_base(runner.clone(), "uv", app)
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

    let again = apps
        .ensure_installed(&id, AppInstallOptions::new())
        .await
        .expect("re-ensure probes, never re-installs");
    assert!(
        assert_already_present_at(&again, BackendId::Uv).is_some(),
        "a record the backend confirms must answer AlreadyPresent with a version"
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
async fn pipx_facade_installs_probes_and_uninstalls_a_real_tool() {
    if !integration_enabled() {
        eprintln!("TORIDE_APPS_INTEGRATION not set; skipping live smoke test");
        return;
    }
    if !manager_on_path("pipx") {
        skip("pipx");
        return;
    }
    let scratch = scratch_dir("pipx");
    let home = scratch.join("pipx-home");
    std::fs::create_dir_all(&home).expect("scratch pipx home is creatable");
    let runner = CommandRunner::builder()
        .env("PIPX_HOME", home.as_str())
        .env("PIPX_BIN_DIR", scratch.join("pipx-bin").as_str())
        .build();
    let id = TorideId::slugify("pycowsay");
    let app = language_app(
        &id,
        "pycowsay",
        InstallMethod::Pipx {
            package: "pycowsay".to_owned(),
        },
    );
    let mut apps = facade_base(runner.clone(), "pipx", app)
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

    let again = apps
        .ensure_installed(&id, AppInstallOptions::new())
        .await
        .expect("re-ensure probes, never re-installs");
    assert!(
        assert_already_present_at(&again, BackendId::Pipx).is_some(),
        "a record the backend confirms must answer AlreadyPresent with a version"
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

#[tokio::test]
async fn pacman_facade_installs_probes_and_uninstalls_a_real_package() {
    if !integration_enabled() {
        eprintln!("TORIDE_APPS_INTEGRATION not set; skipping live smoke test");
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
    let mut apps = facade_base(runner.clone(), "pacman", app)
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
        .ensure_installed(&id, AppInstallOptions::new().elevated(true))
        .await
        .expect("re-ensure probes, never re-installs");
    assert!(
        assert_already_present_at(&again, BackendId::Distro(DistroFamily::Arch)).is_some(),
        "pacman's query row always carries a version"
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
async fn apk_facade_installs_probes_and_uninstalls_a_real_package() {
    if !integration_enabled() {
        eprintln!("TORIDE_APPS_INTEGRATION not set; skipping live smoke test");
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
    let mut apps = facade_base(runner.clone(), "apk", app)
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

    let again = apps
        .ensure_installed(&id, AppInstallOptions::new().elevated(true))
        .await
        .expect("re-ensure probes, never re-installs");
    assert!(
        assert_already_present_at(&again, BackendId::Distro(DistroFamily::Alpine)).is_none(),
        "apk's quiet listing reports presence without a version — the documented row shape"
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
