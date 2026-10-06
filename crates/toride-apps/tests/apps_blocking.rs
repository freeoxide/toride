//! Integration tests for the [`AppsBlocking`] facade — the sync twin of the
//! [`Apps`] facade, end to end on the calling thread: a strict
//! [`FakeRunner`] scripts every backend command, manifests live under
//! unique temp-dir paths, and the tests assert both the dispatched argv and
//! the in-line persisted manifest. No network, no real commands, no async
//! runtime anywhere in this file.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use camino::Utf8PathBuf;
use toride_apps::apps::{
    AdoptProvenance, AppInstallOptions, AppUninstallOptions, AppUpdateOptions, Apps, AppsBlocking,
    AppsError, EnsureAppOutcome, UninstallAppOutcome, UpdateOutcome,
};
use toride_apps::backends::{DistroBackend, FlatpakBackend, HomebrewBackend};
use toride_apps::manifest::{
    InstallManifest, InstallRecord, ManifestError, ManifestResult, NativeIds, RecordSnapshot,
};
use toride_apps::runner::{CommandRunner, command};
use toride_apps::store::{RecordStore, StoreLoad};
use toride_apps::{AppStatus, BackendId, Target, Version};
use toride_registry::model::{App, InstallMethod};
use toride_registry::{Availability, DistroFamily, TorideId};
use toride_runner::CommandOutput;
use toride_runner::CommandSpec;
use toride_runner::fake::FakeRunner;

static DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_manifest_path(label: &str) -> Utf8PathBuf {
    let unique = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "toride-apps-blocking-{}-{unique}-{label}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("unique temp dir is creatable");
    Utf8PathBuf::from_path_buf(dir.join("apps-manifest.json"))
        .expect("system temp dir is valid UTF-8")
}

fn app(id: &str, method: InstallMethod) -> App {
    App {
        id: TorideId::slugify(id),
        name: id.to_owned(),
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

fn cask_app() -> App {
    app(
        "brave-browser",
        InstallMethod::Homebrew {
            cask: true,
            token: "brave-browser".to_owned(),
        },
    )
}

fn id(slug: &str) -> TorideId {
    TorideId::slugify(slug)
}

fn blocking(fake: &FakeRunner, manifest_path: &Utf8PathBuf) -> AppsBlocking {
    blocking_over(
        fake,
        manifest_path,
        Target::macos(toride_apps::Arch::X86_64),
    )
}

fn blocking_over(fake: &FakeRunner, manifest_path: &Utf8PathBuf, target: Target) -> AppsBlocking {
    let seam = CommandRunner::new(Arc::new(fake.clone()));
    Apps::builder()
        .runner(seam.clone())
        .target(target)
        .manifest_path(manifest_path)
        .homebrew(HomebrewBackend::new(seam.clone()))
        .flatpak(FlatpakBackend::new(seam.clone()))
        .distro(DistroBackend::new(DistroFamily::Debian, seam))
        .build()
        .expect("facade builds over the fake seam")
        .blocking()
}

fn cask_record(version: Option<&str>) -> InstallRecord {
    InstallRecord::new(
        toride_apps::InstallPlan {
            app: id("brave-browser"),
            backend: BackendId::Homebrew,
            operation: toride_apps::Operation::BrewInstall {
                cask: true,
                token: "brave-browser".to_owned(),
            },
            dry_run: false,
            requires_elevation: false,
        },
        NativeIds::Homebrew {
            token: "brave-browser".to_owned(),
            cask: true,
        },
        version.map(str::to_owned),
    )
    .with_installed_at(1_700_000_000)
}

fn seed_manifest(path: &Utf8PathBuf, record: InstallRecord) {
    let mut manifest = InstallManifest::at(path);
    manifest.record(&id("brave-browser"), record);
    manifest.save().expect("seed manifest saves");
}

fn brew_info_installed_spec() -> CommandSpec {
    command("brew", ["info", "--json=v2", "--installed"])
}

fn brew_install_cask_spec() -> CommandSpec {
    command("brew", ["install", "--cask", "brave-browser"])
}

fn brew_uninstall_cask_spec() -> CommandSpec {
    command("brew", ["uninstall", "--cask", "brave-browser"])
}

fn brew_versions_cask_spec() -> CommandSpec {
    command("brew", ["list", "--cask", "--versions", "brave-browser"])
}

fn brew_outdated_casks_spec() -> CommandSpec {
    command("brew", ["outdated", "--cask", "--json=v2"])
}

fn brew_upgrade_cask_spec() -> CommandSpec {
    command("brew", ["upgrade", "--cask", "brave-browser"])
}

fn brew_info_token_spec() -> CommandSpec {
    command("brew", ["info", "--json=v2", "brave-browser"])
}

fn flatpak_list_all_spec() -> CommandSpec {
    let mut args = vec!["list"];
    args.push("--app");
    args.push("--columns=application,version,origin,installation");
    command("flatpak", args)
}

fn flatpak_uninstall_user_spec() -> CommandSpec {
    command(
        "flatpak",
        [
            "uninstall",
            "--user",
            "--noninteractive",
            "com.brave.Browser",
        ],
    )
}

fn empty_brew_document() -> String {
    r#"{"formulae":[],"casks":[]}"#.to_owned()
}

fn installed_cask_document(token: &str, version: &str) -> String {
    format!(
        r#"{{"formulae":[],"casks":[{{"token":"{token}","name":["Cask"],"version":"{version}","installed":"{version}"}}]}}"#
    )
}

#[test]
fn ensure_installed_installs_verifies_records_and_answers_present_twice() {
    let fake = FakeRunner::new().strict();
    let fake = fake
        .respond(
            brew_info_installed_spec(),
            CommandOutput::from_stdout(empty_brew_document()),
        )
        .respond(brew_install_cask_spec(), CommandOutput::from_stdout(""))
        .respond(
            brew_versions_cask_spec(),
            CommandOutput::from_stdout("brave-browser 1.96.59\n"),
        )
        .respond(
            brew_versions_cask_spec(),
            CommandOutput::from_stdout("brave-browser 1.96.59\n"),
        )
        .respond(
            brew_versions_cask_spec(),
            CommandOutput::from_stdout("brave-browser 1.96.59\n"),
        );
    let path = temp_manifest_path("ensure-installed");
    let mut apps = blocking(&fake, &path);

    match apps
        .ensure_installed(&cask_app(), AppInstallOptions::new())
        .unwrap()
    {
        EnsureAppOutcome::Installed {
            backend,
            version,
            verified,
            warning,
            ..
        } => {
            assert_eq!(backend, BackendId::Homebrew);
            assert_eq!(version.as_deref(), Some("1.96.59"));
            assert!(verified, "the post-install probe confirmed presence");
            assert!(warning.is_none(), "{warning:?}");
        }
        other @ EnsureAppOutcome::AlreadyPresent(_) => panic!("expected Installed, got {other:?}"),
    }
    assert!(
        std::fs::read_to_string(path.as_std_path())
            .expect("in-line save wrote the manifest")
            .contains("brave-browser"),
        "the record persisted synchronously"
    );

    let second = apps
        .ensure_installed(&cask_app(), AppInstallOptions::new())
        .unwrap();
    assert!(
        matches!(
            second,
            EnsureAppOutcome::AlreadyPresent(AppStatus::Installed { .. })
        ),
        "{second:?}"
    );
    assert_eq!(
        fake.calls()
            .iter()
            .filter(|call| call.program == "brew"
                && call.args == ["install", "--cask", "brave-browser"])
            .count(),
        1,
        "the confirming second call never installs again"
    );
}

#[test]
fn ensure_installed_keeps_a_foreign_install_as_is() {
    let fake = FakeRunner::new().strict().respond(
        brew_info_installed_spec(),
        CommandOutput::from_stdout(installed_cask_document("brave-browser", "1.90.0")),
    );
    let path = temp_manifest_path("foreign-keep");
    let mut apps = blocking(&fake, &path);

    let outcome = apps
        .ensure_installed(&cask_app(), AppInstallOptions::new())
        .unwrap();
    assert!(
        matches!(
            outcome,
            EnsureAppOutcome::AlreadyPresent(AppStatus::Foreign { .. })
        ),
        "{outcome:?}"
    );
    assert!(apps.records().is_empty(), "nothing was recorded");
    assert!(
        !path.as_std_path().exists(),
        "the store was never saved over"
    );
}

#[test]
fn ensure_installed_at_the_requested_version_on_a_matching_record_is_already_present() {
    let fake = FakeRunner::new().strict().respond(
        brew_versions_cask_spec(),
        CommandOutput::from_stdout("brave-browser 1.96.59\n"),
    );
    let path = temp_manifest_path("version-present-match");
    seed_manifest(&path, cask_record(Some("1.96.59")));
    let mut apps = blocking(&fake, &path);

    let outcome = apps
        .ensure_installed(
            &cask_app(),
            AppInstallOptions::new().version(Some(Version::new("1.96.59"))),
        )
        .unwrap();
    assert_eq!(
        outcome,
        EnsureAppOutcome::AlreadyPresent(AppStatus::Installed {
            backend: BackendId::Homebrew,
            version: Some("1.96.59".to_owned()),
        })
    );
    let calls = fake.calls();
    assert_eq!(
        calls.len(),
        1,
        "one confirming probe, nothing else: {calls:?}"
    );
    assert!(
        calls[0].program == "brew"
            && calls[0].args == ["list", "--cask", "--versions", "brave-browser"],
        "{calls:?}"
    );
}

#[test]
fn ensure_installed_with_a_version_pins_the_versioned_token_when_the_offering_differs() {
    let versioned_install_spec = command("brew", ["install", "--cask", "brave-browser@1.90.0"]);
    let versioned_probe_spec = command(
        "brew",
        ["list", "--cask", "--versions", "brave-browser@1.90.0"],
    );
    let fake = FakeRunner::new().strict();
    let fake = fake
        .respond(
            brew_info_installed_spec(),
            CommandOutput::from_stdout(empty_brew_document()),
        )
        .respond(
            brew_info_token_spec(),
            CommandOutput::from_stdout(installed_cask_document("brave-browser", "1.96.59")),
        )
        .respond(
            versioned_install_spec.clone(),
            CommandOutput::from_stdout(""),
        )
        .respond(
            versioned_probe_spec.clone(),
            CommandOutput::from_stdout("brave-browser@1.90.0 1.90.0\n"),
        )
        .respond(
            versioned_probe_spec.clone(),
            CommandOutput::from_stdout("brave-browser@1.90.0 1.90.0\n"),
        );
    let path = temp_manifest_path("version-pin");
    let mut apps = blocking(&fake, &path);

    let outcome = apps
        .ensure_installed(
            &cask_app(),
            AppInstallOptions::new().version(Some(Version::new("1.90.0"))),
        )
        .unwrap();
    match outcome {
        EnsureAppOutcome::Installed { ids, version, .. } => {
            assert_eq!(
                ids,
                NativeIds::Homebrew {
                    token: "brave-browser@1.90.0".to_owned(),
                    cask: true,
                },
                "the recorded identity is the versioned token brew manages"
            );
            assert_eq!(version.as_deref(), Some("1.90.0"));
        }
        other @ EnsureAppOutcome::AlreadyPresent(_) => panic!("expected Installed, got {other:?}"),
    }
    fake.assert_called_with(&versioned_install_spec);
    fake.assert_no_unmatched_calls();
    assert!(
        std::fs::read_to_string(path.as_std_path())
            .unwrap()
            .contains("brave-browser@1.90.0"),
        "the versioned identity persisted"
    );
}

#[test]
fn ensure_installed_at_the_offered_version_over_a_stale_record_rides_the_managers_current() {
    let versioned_probe_spec = command("brew", ["list", "--cask", "--versions", "brave-browser"]);
    let fake = FakeRunner::new().strict();
    let fake = fake
        .respond(
            brew_versions_cask_spec(),
            CommandOutput::from_stdout("brave-browser 1.90.0\n"),
        )
        .respond(
            brew_info_token_spec(),
            CommandOutput::from_stdout(installed_cask_document("brave-browser", "1.96.59")),
        )
        .respond(brew_install_cask_spec(), CommandOutput::from_stdout(""))
        .respond(
            versioned_probe_spec.clone(),
            CommandOutput::from_stdout("brave-browser 1.96.59\n"),
        )
        .respond(
            versioned_probe_spec.clone(),
            CommandOutput::from_stdout("brave-browser 1.96.59\n"),
        );
    let path = temp_manifest_path("version-present-offered");
    seed_manifest(&path, cask_record(Some("1.90.0")));
    let mut apps = blocking(&fake, &path);

    let outcome = apps
        .ensure_installed(
            &cask_app(),
            AppInstallOptions::new().version(Some(Version::new("1.96.59"))),
        )
        .unwrap();
    match outcome {
        EnsureAppOutcome::Installed { ids, version, .. } => {
            assert_eq!(
                ids,
                NativeIds::Homebrew {
                    token: "brave-browser".to_owned(),
                    cask: true,
                },
                "the plain token — no @-joined spelling may run on a re-install"
            );
            assert_eq!(version.as_deref(), Some("1.96.59"));
        }
        other @ EnsureAppOutcome::AlreadyPresent(_) => panic!("expected Installed, got {other:?}"),
    }
    fake.assert_called_with(&brew_info_token_spec());
    fake.assert_called_with(&brew_install_cask_spec());
    assert!(
        !fake
            .calls()
            .iter()
            .any(|call| call.args.contains(&"brave-browser@1.96.59".to_owned())),
        "no @-joined spelling may run: {:?}",
        fake.calls()
    );
    fake.assert_no_unmatched_calls();
}

#[test]
fn cargo_installs_records_and_reports_status_in_line() {
    let list_spec = command("cargo", ["install", "--list"]);
    let install_spec = command("cargo", ["install", "ripgrep"]);
    let installed_list = "ripgrep v14.1.0:\n    rg\n";
    let fake = FakeRunner::new().strict();
    let fake = fake
        .respond(list_spec.clone(), CommandOutput::from_stdout(""))
        .respond(install_spec.clone(), CommandOutput::from_stdout(""))
        .respond(
            list_spec.clone(),
            CommandOutput::from_stdout(installed_list),
        )
        .respond(
            list_spec.clone(),
            CommandOutput::from_stdout(installed_list),
        );
    let path = temp_manifest_path("cargo-install");
    let seam = CommandRunner::new(Arc::new(fake.clone()));
    let mut apps = Apps::builder()
        .runner(seam.clone())
        .target(Target::linux(
            toride_apps::Arch::X86_64,
            DistroFamily::Debian,
        ))
        .manifest_path(&path)
        .cargo(toride_apps::CargoBackend::new(seam))
        .build()
        .expect("facade builds with the cargo backend attached")
        .blocking();

    let cargo_app = app(
        "ripgrep",
        InstallMethod::Cargo {
            crate_: "ripgrep".to_owned(),
            version: None,
        },
    );
    match apps
        .ensure_installed(&cargo_app, AppInstallOptions::new())
        .unwrap()
    {
        EnsureAppOutcome::Installed {
            backend,
            ids,
            version,
            ..
        } => {
            assert_eq!(backend, BackendId::Cargo);
            assert_eq!(
                ids,
                NativeIds::Cargo {
                    crate_: "ripgrep".to_owned()
                }
            );
            assert_eq!(version.as_deref(), Some("14.1.0"));
        }
        other @ EnsureAppOutcome::AlreadyPresent(_) => panic!("expected Installed, got {other:?}"),
    }
    fake.assert_called_with(&install_spec);

    assert_eq!(
        apps.status(&id("ripgrep")).unwrap(),
        AppStatus::Installed {
            backend: BackendId::Cargo,
            version: Some("14.1.0".to_owned()),
        },
        "status answers from the record through the listing probe"
    );
    assert_eq!(
        apps.available_versions(&id("ripgrep")).unwrap(),
        Vec::<Version>::new(),
        "cargo reports no version listing — its offering probe is singular"
    );
    assert!(
        std::fs::read_to_string(path.as_std_path())
            .unwrap()
            .contains("\"Cargo\""),
        "the record persisted with the Cargo ids shape"
    );
    fake.assert_no_unmatched_calls();
}

#[test]
fn cargo_records_update_and_uninstall_replay_the_recorded_crate() {
    let list_spec = command("cargo", ["install", "--list"]);
    let info_spec = command("cargo", ["info", "--color", "never", "ripgrep"]);
    let force_spec = command("cargo", ["install", "--force", "ripgrep"]);
    let uninstall_spec = command("cargo", ["uninstall", "ripgrep"]);
    let installed_list = "ripgrep v14.1.0:\n    rg\n";
    let upgraded_list = "ripgrep v15.2.0:\n    rg\n";
    let fake = FakeRunner::new().strict();
    let fake = fake
        .respond(
            list_spec.clone(),
            CommandOutput::from_stdout(installed_list),
        )
        .respond(
            info_spec.clone(),
            CommandOutput::from_stdout(
                "ripgrep #regex #grep #egrep #search #pattern\nripgrep is a line-oriented search tool\nversion: 15.2.0\n",
            ),
        )
        .respond(force_spec.clone(), CommandOutput::from_stdout(""))
        .respond(list_spec.clone(), CommandOutput::from_stdout(upgraded_list))
        .respond(uninstall_spec.clone(), CommandOutput::from_stdout(""))
        .respond(list_spec.clone(), CommandOutput::from_stdout(""));
    let path = temp_manifest_path("cargo-lifecycle");
    let mut manifest = toride_apps::InstallManifest::at(&path);
    manifest.record(
        &id("ripgrep"),
        InstallRecord::new(
            toride_apps::InstallPlan {
                app: id("ripgrep"),
                backend: BackendId::Cargo,
                operation: toride_apps::Operation::CargoInstall {
                    crate_: "ripgrep".to_owned(),
                    version: None,
                },
                dry_run: false,
                requires_elevation: false,
            },
            NativeIds::Cargo {
                crate_: "ripgrep".to_owned(),
            },
            Some("14.1.0".to_owned()),
        )
        .with_installed_at(1_700_000_000),
    );
    manifest.save().expect("seed manifest saves");
    let seam = CommandRunner::new(Arc::new(fake.clone()));
    let mut apps = Apps::builder()
        .runner(seam.clone())
        .target(Target::linux(
            toride_apps::Arch::X86_64,
            DistroFamily::Debian,
        ))
        .manifest_path(&path)
        .cargo(toride_apps::CargoBackend::new(seam))
        .build()
        .expect("facade builds with the cargo backend attached")
        .blocking();

    assert_eq!(
        apps.update(&id("ripgrep"), &AppUpdateOptions::new())
            .unwrap(),
        UpdateOutcome::Updated {
            from: Some(Version::new("14.1.0")),
            to: Some(Version::new("15.2.0")),
        }
    );
    fake.assert_called_with(&force_spec);
    let on_disk = std::fs::read_to_string(path.as_std_path()).unwrap();
    assert!(on_disk.contains("15.2.0"), "{on_disk}");

    match apps
        .uninstall(&id("ripgrep"), AppUninstallOptions::new())
        .unwrap()
    {
        UninstallAppOutcome::Removed {
            backend, warning, ..
        } => {
            assert_eq!(backend, BackendId::Cargo);
            assert!(warning.is_none(), "{warning:?}");
        }
        other @ UninstallAppOutcome::AlreadyAbsent => panic!("expected Removed, got {other:?}"),
    }
    fake.assert_called_with(&uninstall_spec);
    assert_eq!(
        apps.records(),
        [] as [(&toride_apps::TorideId, &toride_apps::InstallRecord); 0]
    );
    fake.assert_no_unmatched_calls();
}

#[test]
fn update_refuses_a_target_version_before_anything_runs() {
    let fake = FakeRunner::new().strict();
    let path = temp_manifest_path("update-target-refused");
    seed_manifest(&path, cask_record(Some("1.96.59")));
    let before = std::fs::read_to_string(path.as_std_path()).unwrap();
    let mut apps = blocking(&fake, &path);

    let error = apps
        .update(
            &id("brave-browser"),
            &AppUpdateOptions::new().target(Some(Version::new("1.90.0"))),
        )
        .unwrap_err();
    assert!(
        matches!(error, AppsError::UpdateTargetNotPinnable { .. }),
        "{error:?}"
    );
    assert!(error.to_string().contains("1.90.0"), "{error}");
    assert!(fake.calls().is_empty(), "nothing was dispatched");
    assert_eq!(
        std::fs::read_to_string(path.as_std_path()).unwrap(),
        before,
        "the manifest is untouched"
    );
}

#[test]
fn uninstall_replays_the_record_and_saves_the_removal_in_line() {
    let fake = FakeRunner::new().strict();
    let fake = fake
        .respond(brew_uninstall_cask_spec(), CommandOutput::from_stdout(""))
        .respond(brew_versions_cask_spec(), CommandOutput::from_stderr("", 1));
    let path = temp_manifest_path("uninstall-record");
    seed_manifest(&path, cask_record(Some("1.96.59")));
    let mut apps = blocking(&fake, &path);

    let outcome = apps
        .uninstall(&id("brave-browser"), AppUninstallOptions::new())
        .unwrap();
    match outcome {
        UninstallAppOutcome::Removed {
            backend, warning, ..
        } => {
            assert_eq!(backend, BackendId::Homebrew);
            assert!(warning.is_none(), "{warning:?}");
        }
        other @ UninstallAppOutcome::AlreadyAbsent => panic!("expected Removed, got {other:?}"),
    }
    assert_eq!(
        apps.records(),
        [] as [(&toride_apps::TorideId, &toride_apps::InstallRecord); 0]
    );
    let on_disk = std::fs::read_to_string(path.as_std_path()).unwrap();
    assert!(!on_disk.contains("brave-browser"), "{on_disk}");
}

#[test]
fn uninstall_without_a_record_needs_the_resolved_app() {
    let fake = FakeRunner::new().strict();
    let path = temp_manifest_path("uninstall-unrecorded");
    let mut apps = blocking(&fake, &path);

    let error = apps
        .uninstall(&id("brave-browser"), AppUninstallOptions::new())
        .unwrap_err();
    assert!(
        matches!(error, AppsError::BlockingResolveRequired { .. }),
        "{error:?}"
    );
    assert!(
        error.to_string().contains("adapters are async"),
        "{}",
        error
    );
    assert!(fake.calls().is_empty(), "nothing was dispatched");
}

#[test]
fn uninstall_app_answers_absent_refuses_foreign_and_forces_removal() {
    let absent_fake = FakeRunner::new()
        .strict()
        .respond(flatpak_list_all_spec(), CommandOutput::from_stdout(""));
    let path = temp_manifest_path("uninstall-app-absent");
    let mut apps = blocking_over(
        &absent_fake,
        &path,
        Target::linux(toride_apps::Arch::X86_64, DistroFamily::Debian),
    );
    let flatpak_app = app(
        "brave-browser",
        InstallMethod::Flatpak {
            app_id: "com.brave.Browser".to_owned(),
            remote: "flathub".to_owned(),
        },
    );
    assert_eq!(
        apps.uninstall_app(&flatpak_app, AppUninstallOptions::new())
            .unwrap(),
        UninstallAppOutcome::AlreadyAbsent
    );

    let foreign_fake = FakeRunner::new().strict().respond(
        flatpak_list_all_spec(),
        CommandOutput::from_stdout("com.brave.Browser\t1.96.59\tflathub\tuser\n"),
    );
    let path = temp_manifest_path("uninstall-app-foreign");
    let mut apps = blocking_over(
        &foreign_fake,
        &path,
        Target::linux(toride_apps::Arch::X86_64, DistroFamily::Debian),
    );
    let error = apps
        .uninstall_app(&flatpak_app, AppUninstallOptions::new())
        .unwrap_err();
    assert!(
        matches!(error, AppsError::ForeignNotManaged { .. }),
        "{error:?}"
    );

    let forced_fake = FakeRunner::new().strict();
    let forced_fake = forced_fake
        .respond(
            flatpak_list_all_spec(),
            CommandOutput::from_stdout("com.brave.Browser\t1.96.59\tflathub\tuser\n"),
        )
        .respond(
            flatpak_uninstall_user_spec(),
            CommandOutput::from_stdout(""),
        )
        .respond(flatpak_list_all_spec(), CommandOutput::from_stdout(""));
    let path = temp_manifest_path("uninstall-app-forced");
    let mut apps = blocking_over(
        &forced_fake,
        &path,
        Target::linux(toride_apps::Arch::X86_64, DistroFamily::Debian),
    );
    let outcome = apps
        .uninstall_app(&flatpak_app, AppUninstallOptions::new().force(true))
        .unwrap();
    assert!(
        matches!(outcome, UninstallAppOutcome::Removed { .. }),
        "{outcome:?}"
    );
    assert!(apps.records().is_empty(), "no record is fabricated");
}

#[test]
fn update_upgrades_rewrites_the_record_and_answers_updated() {
    let outdated = r#"{"formulae":[],"casks":[{"name":"brave-browser","installed_versions":["1.90.0"],"current_version":"1.96.59","pinned":false}]}"#;
    let fake = FakeRunner::new().strict();
    let fake = fake
        .respond(
            brew_versions_cask_spec(),
            CommandOutput::from_stdout("brave-browser 1.90.0\n"),
        )
        .respond(
            brew_outdated_casks_spec(),
            CommandOutput::from_stdout(outdated),
        )
        .respond(brew_upgrade_cask_spec(), CommandOutput::from_stdout(""))
        .respond(
            brew_versions_cask_spec(),
            CommandOutput::from_stdout("brave-browser 1.96.59\n"),
        );
    let path = temp_manifest_path("update");
    seed_manifest(&path, cask_record(Some("1.90.0")));
    let mut apps = blocking(&fake, &path);

    assert_eq!(
        apps.update(&id("brave-browser"), &AppUpdateOptions::new())
            .unwrap(),
        UpdateOutcome::Updated {
            from: Some(Version::new("1.90.0")),
            to: Some(Version::new("1.96.59")),
        }
    );
    let on_disk = std::fs::read_to_string(path.as_std_path()).unwrap();
    assert!(on_disk.contains("1.96.59"), "{on_disk}");
    assert!(!on_disk.contains("1.90.0"), "{on_disk}");
}

#[test]
fn update_answers_up_to_date_when_the_stale_signal_excludes_the_token() {
    let outdated = r#"{"formulae":[],"casks":[]}"#;
    let fake = FakeRunner::new().strict();
    let fake = fake
        .respond(
            brew_versions_cask_spec(),
            CommandOutput::from_stdout("brave-browser 1.96.59\n"),
        )
        .respond(
            brew_outdated_casks_spec(),
            CommandOutput::from_stdout(outdated),
        );
    let path = temp_manifest_path("update-current");
    seed_manifest(&path, cask_record(Some("1.90.0")));
    let mut apps = blocking(&fake, &path);

    assert_eq!(
        apps.update(&id("brave-browser"), &AppUpdateOptions::new())
            .unwrap(),
        UpdateOutcome::UpToDate
    );
    fake.assert_called_with(&brew_outdated_casks_spec());
    assert!(
        fake.calls()
            .iter()
            .all(|call| call.program != "brew" || !call.args.contains(&"upgrade".to_owned())),
        "no upgrade ran"
    );
}

#[test]
fn update_dry_run_previews_without_dispatching_or_touching_the_manifest() {
    let offered = installed_cask_document("brave-browser", "1.96.59");
    let fake = FakeRunner::new().strict();
    let fake = fake
        .respond(
            brew_versions_cask_spec(),
            CommandOutput::from_stdout("brave-browser 1.90.0\n"),
        )
        .respond(brew_info_token_spec(), CommandOutput::from_stdout(offered));
    let path = temp_manifest_path("update-dry-run");
    seed_manifest(&path, cask_record(Some("1.90.0")));
    let before = std::fs::read_to_string(path.as_std_path()).unwrap();
    let mut apps = blocking(&fake, &path);

    let outcome = apps
        .update(&id("brave-browser"), &AppUpdateOptions::new().dry_run(true))
        .unwrap();
    match outcome {
        UpdateOutcome::Preview(preview) => {
            assert_eq!(preview.argv, ["brew", "upgrade", "--cask", "brave-browser"]);
            assert_eq!(preview.from, Some(Version::new("1.90.0")));
            assert_eq!(preview.to, Some(Version::new("1.96.59")));
        }
        other => panic!("expected Preview, got {other:?}"),
    }
    assert!(
        fake.calls().iter().all(|call| call.args
            != [
                "upgrade".to_owned(),
                "--cask".to_owned(),
                "brave-browser".to_owned()
            ]),
        "no upgrade dispatched"
    );
    assert_eq!(
        std::fs::read_to_string(path.as_std_path()).unwrap(),
        before,
        "the manifest is untouched"
    );
}

#[test]
fn update_without_a_record_is_an_unrecorded_update() {
    let fake = FakeRunner::new().strict();
    let path = temp_manifest_path("update-unrecorded");
    let mut apps = blocking(&fake, &path);
    let error = apps
        .update(&id("brave-browser"), &AppUpdateOptions::new())
        .unwrap_err();
    assert!(
        matches!(error, AppsError::UnrecordedUpdate { .. }),
        "{error:?}"
    );
}

#[test]
fn adopt_claims_a_detected_install_and_persists_in_line() {
    let fake = FakeRunner::new().strict().respond(
        brew_versions_cask_spec(),
        CommandOutput::from_stdout("brave-browser 1.96.59\n"),
    );
    let path = temp_manifest_path("adopt");
    let mut apps = blocking(&fake, &path);

    let record = apps
        .adopt(
            &id("brave-browser"),
            AdoptProvenance::new(NativeIds::Homebrew {
                token: "brave-browser".to_owned(),
                cask: true,
            }),
        )
        .unwrap();
    assert_eq!(record.version.as_deref(), Some("1.96.59"));
    assert!(
        std::fs::read_to_string(path.as_std_path())
            .unwrap()
            .contains("brave-browser"),
        "the claim persisted synchronously"
    );

    let error = apps
        .adopt(
            &id("brave-browser"),
            AdoptProvenance::new(NativeIds::Homebrew {
                token: "brave-browser".to_owned(),
                cask: true,
            }),
        )
        .unwrap_err();
    assert!(
        matches!(error, AppsError::AlreadyRecorded { .. }),
        "{error:?}"
    );
}

struct FailingStore {
    snapshot: RecordSnapshot,
}

impl RecordStore for FailingStore {
    fn load(&self) -> ManifestResult<StoreLoad> {
        Ok(StoreLoad {
            snapshot: self.snapshot.clone(),
            quarantined: None,
        })
    }

    fn save(&self, _snapshot: &RecordSnapshot) -> ManifestResult<()> {
        Err(ManifestError::Io(std::io::Error::other("disk full")))
    }
}

#[test]
fn adopt_rolls_back_when_the_in_line_save_fails() {
    let fake = FakeRunner::new().strict().respond(
        brew_versions_cask_spec(),
        CommandOutput::from_stdout("brave-browser 1.96.59\n"),
    );
    let seam = CommandRunner::new(Arc::new(fake.clone()));
    let mut apps = Apps::builder()
        .runner(seam.clone())
        .target(Target::macos(toride_apps::Arch::X86_64))
        .with_record_store(Arc::new(FailingStore {
            snapshot: RecordSnapshot::empty(),
        }))
        .homebrew(HomebrewBackend::new(seam))
        .build()
        .unwrap()
        .blocking();

    let error = apps
        .adopt(
            &id("brave-browser"),
            AdoptProvenance::new(NativeIds::Homebrew {
                token: "brave-browser".to_owned(),
                cask: true,
            }),
        )
        .unwrap_err();
    assert!(error.to_string().contains("disk full"), "{error}");
    assert!(apps.records().is_empty(), "the claim was rolled back");
}

#[test]
fn update_surfaces_a_failed_save_after_the_upgrade_itself_succeeded() {
    let outdated = r#"{"formulae":[],"casks":[{"name":"brave-browser","installed_versions":["1.90.0"],"current_version":"1.96.59","pinned":false}]}"#;
    let fake = FakeRunner::new().strict();
    let fake = fake
        .respond(
            brew_versions_cask_spec(),
            CommandOutput::from_stdout("brave-browser 1.90.0\n"),
        )
        .respond(
            brew_outdated_casks_spec(),
            CommandOutput::from_stdout(outdated),
        )
        .respond(brew_upgrade_cask_spec(), CommandOutput::from_stdout(""))
        .respond(
            brew_versions_cask_spec(),
            CommandOutput::from_stdout("brave-browser 1.96.59\n"),
        );
    let seam = CommandRunner::new(Arc::new(fake.clone()));
    let mut apps = Apps::builder()
        .runner(seam.clone())
        .target(Target::macos(toride_apps::Arch::X86_64))
        .with_record_store(Arc::new(FailingStore {
            snapshot: RecordSnapshot::from(std::collections::BTreeMap::from([(
                id("brave-browser"),
                cask_record(Some("1.90.0")),
            )])),
        }))
        .homebrew(HomebrewBackend::new(seam))
        .build()
        .unwrap()
        .blocking();

    let error = apps
        .update(&id("brave-browser"), &AppUpdateOptions::new())
        .unwrap_err();
    assert!(matches!(error, AppsError::Manifest(_)), "{error:?}");
    assert!(error.to_string().contains("disk full"), "{error}");
    fake.assert_called_with(&brew_upgrade_cask_spec());
    fake.assert_no_unmatched_calls();
    assert_eq!(
        apps.records()
            .iter()
            .find(|(record_id, _)| *record_id == &id("brave-browser"))
            .and_then(|(_, record)| record.version.as_deref()),
        Some("1.96.59"),
        "the upgrade already succeeded — the in-memory record is rewritten"
    );
}

#[test]
fn status_answers_from_the_record_and_degrades_without_one() {
    let fake = FakeRunner::new().strict().respond(
        brew_versions_cask_spec(),
        CommandOutput::from_stdout("brave-browser 1.96.59\n"),
    );
    let path = temp_manifest_path("status");
    seed_manifest(&path, cask_record(Some("1.90.0")));
    let apps = blocking(&fake, &path);

    assert_eq!(
        apps.status(&id("brave-browser")).unwrap(),
        AppStatus::Installed {
            backend: BackendId::Homebrew,
            version: Some("1.96.59".to_owned()),
        },
        "the live probe's version, not the recorded one"
    );
    assert_eq!(
        apps.status(&id("ghost")).unwrap(),
        AppStatus::NotInstalled,
        "no registry to resolve with degrades to the local answer"
    );
}

#[test]
fn available_versions_reads_the_record_and_requires_resolution_without_one() {
    let offered = installed_cask_document("brave-browser", "1.96.59");
    let fake = FakeRunner::new()
        .strict()
        .respond(brew_info_token_spec(), CommandOutput::from_stdout(offered));
    let path = temp_manifest_path("available-versions");
    seed_manifest(&path, cask_record(Some("1.90.0")));
    let apps = blocking(&fake, &path);

    assert_eq!(
        apps.available_versions(&id("brave-browser")).unwrap(),
        [Version::new("1.96.59")]
    );
    let error = apps.available_versions(&id("ghost")).unwrap_err();
    assert!(
        matches!(error, AppsError::BlockingResolveRequired { .. }),
        "{error:?}"
    );
}

#[test]
fn pin_and_unpin_run_the_kind_scoped_argv_and_refuse_unrecorded_ids() {
    let pin_spec = command("brew", ["pin", "--cask", "brave-browser"]);
    let unpin_spec = command("brew", ["unpin", "--cask", "brave-browser"]);
    let fake = FakeRunner::new().strict();
    let fake = fake
        .respond(pin_spec.clone(), CommandOutput::from_stdout(""))
        .respond(unpin_spec.clone(), CommandOutput::from_stdout(""));
    let path = temp_manifest_path("pin");
    seed_manifest(&path, cask_record(None));
    let apps = blocking(&fake, &path);

    apps.pin(&id("brave-browser")).unwrap();
    apps.unpin(&id("brave-browser")).unwrap();
    fake.assert_called_with(&pin_spec);
    fake.assert_called_with(&unpin_spec);

    let error = apps.pin(&id("ghost")).unwrap_err();
    assert!(
        matches!(error, AppsError::UnrecordedPin { .. }),
        "{error:?}"
    );
    let error = apps.unpin(&id("ghost")).unwrap_err();
    assert!(
        matches!(error, AppsError::UnrecordedUnpin { .. }),
        "{error:?}"
    );
}

#[test]
fn blocking_wraps_and_unwraps_sharing_one_state() {
    let fake = FakeRunner::new().strict();
    let fake = fake
        .respond(
            brew_info_installed_spec(),
            CommandOutput::from_stdout(empty_brew_document()),
        )
        .respond(brew_install_cask_spec(), CommandOutput::from_stdout(""))
        .respond(
            brew_versions_cask_spec(),
            CommandOutput::from_stdout("brave-browser 1.96.59\n"),
        )
        .respond(
            brew_versions_cask_spec(),
            CommandOutput::from_stdout("brave-browser 1.96.59\n"),
        );
    let path = temp_manifest_path("wrap");
    let apps = {
        let mut blocking_facade = blocking(&fake, &path);
        blocking_facade
            .ensure_installed(&cask_app(), AppInstallOptions::new())
            .unwrap();
        blocking_facade.into_inner()
    };
    assert_eq!(apps.records().len(), 1, "the record survives the unwrap");
    assert_eq!(apps.target().os, toride_apps::Os::MacOs);
    assert_eq!(
        AppsBlocking::from(apps).records().len(),
        1,
        "the From wrap shares the same state"
    );
}

// ---------------------------------------------------------------------------
// detect_backends auto-attach — mise (the sync listing rides the seam)
// ---------------------------------------------------------------------------

#[cfg(feature = "mise")]
#[test]
fn detect_backends_auto_attaches_a_discoverable_mise_backend() {
    if !toride_runner::discovery::binary_exists("mise") {
        return;
    }
    let path = temp_manifest_path("detect-mise");
    let mut manifest = InstallManifest::at(&path);
    manifest.record(
        &id("node"),
        InstallRecord::new(
            toride_apps::InstallPlan {
                app: id("node"),
                backend: BackendId::Mise,
                operation: toride_apps::Operation::MiseInstall {
                    tool: "node".to_owned(),
                    version: None,
                },
                dry_run: false,
                requires_elevation: false,
            },
            NativeIds::Mise {
                tool: "node".to_owned(),
            },
            Some("22.1.0".to_owned()),
        )
        .with_installed_at(1_700_000_000),
    );
    manifest.save().expect("seed manifest saves");
    let fake = FakeRunner::new().strict().respond(
        command("mise", ["ls", "--installed", "--json"]),
        CommandOutput::from_stdout(r#"{"node": [{"version": "22.1.0", "active": true}]}"#),
    );
    let seam = CommandRunner::new(Arc::new(fake.clone()));
    let blocking = Apps::builder()
        .runner(seam)
        .manifest_path(&path)
        .detect_backends()
        .expect("detection skips absent binaries, never errors")
        .build()
        .expect("facade builds from the detected backends")
        .blocking();

    assert_eq!(
        blocking
            .status(&id("node"))
            .expect("the recorded status probes the backend"),
        AppStatus::Installed {
            backend: BackendId::Mise,
            version: Some("22.1.0".to_owned()),
        }
    );
    fake.assert_no_unmatched_calls();
}

// ---------------------------------------------------------------------------
// Batch verbs — the sync twins
// ---------------------------------------------------------------------------

fn brew_install_cask_for(token: &str) -> CommandSpec {
    command("brew", ["install", "--cask", token])
}

fn brew_versions_cask_for(token: &str) -> CommandSpec {
    command("brew", ["list", "--cask", "--versions", token])
}

fn cask_app_with(slug: &str, token: &str) -> App {
    app(
        slug,
        InstallMethod::Homebrew {
            cask: true,
            token: token.to_owned(),
        },
    )
}

#[test]
fn ensure_installed_many_attempts_every_app_and_reports_per_item_outcomes() {
    let path = temp_manifest_path("batch-install");
    let fake = FakeRunner::new()
        .strict()
        .respond(
            brew_info_installed_spec(),
            CommandOutput::from_stdout(empty_brew_document()),
        )
        .respond(brew_install_cask_spec(), CommandOutput::from_stdout(""))
        .respond(
            brew_versions_cask_spec(),
            CommandOutput::from_stdout("brave-browser 1.96.59\n"),
        )
        .respond(
            brew_info_installed_spec(),
            CommandOutput::from_stdout(empty_brew_document()),
        )
        .respond(
            brew_install_cask_for("ghost-cask"),
            CommandOutput::from_stderr("Error: cask not found", 1),
        )
        .respond(
            brew_info_installed_spec(),
            CommandOutput::from_stdout(empty_brew_document()),
        )
        .respond(
            brew_install_cask_for("firefox"),
            CommandOutput::from_stdout(""),
        )
        .respond(
            brew_versions_cask_for("firefox"),
            CommandOutput::from_stdout("firefox 138.0\n"),
        );
    let mut blocking = blocking(&fake, &path);
    let brave = cask_app_with("brave-browser", "brave-browser");
    let ghost = cask_app_with("ghost-app", "ghost-cask");
    let firefox = cask_app_with("firefox", "firefox");

    let outcomes =
        blocking.ensure_installed_many([&brave, &ghost, &firefox], &AppInstallOptions::new());

    assert_eq!(outcomes.len(), 3, "{outcomes:?}");
    assert_eq!(outcomes[0].id, id("brave-browser"));
    assert!(
        matches!(
            outcomes[0].result.as_ref().expect("first app installs"),
            EnsureAppOutcome::Installed {
                backend: BackendId::Homebrew,
                ..
            }
        ),
        "{:?}",
        outcomes[0].result
    );
    assert_eq!(outcomes[1].id, id("ghost-app"));
    assert!(
        matches!(&outcomes[1].result, Err(AppsError::Backend(_))),
        "{:?}",
        outcomes[1].result
    );
    assert_eq!(outcomes[2].id, id("firefox"));
    assert!(
        matches!(
            outcomes[2]
                .result
                .as_ref()
                .expect("third app installs after the failure"),
            EnsureAppOutcome::Installed {
                backend: BackendId::Homebrew,
                ..
            }
        ),
        "{:?}",
        outcomes[2].result
    );
    fake.assert_no_unmatched_calls();
}

#[test]
fn uninstall_many_attempts_every_id_and_reports_per_item_outcomes() {
    let path = temp_manifest_path("batch-uninstall");
    seed_manifest(&path, cask_record(Some("1.96.59")));
    let fake = FakeRunner::new()
        .strict()
        .respond(brew_uninstall_cask_spec(), CommandOutput::from_stdout(""))
        .respond(brew_versions_cask_spec(), CommandOutput::from_stderr("", 1));
    let mut blocking = blocking(&fake, &path);

    let outcomes = blocking.uninstall_many(
        [id("brave-browser"), id("ghost-app")],
        AppUninstallOptions::new(),
    );

    assert_eq!(outcomes.len(), 2, "{outcomes:?}");
    assert_eq!(outcomes[0].id, id("brave-browser"));
    assert!(
        matches!(
            outcomes[0]
                .result
                .as_ref()
                .expect("the recorded app removes"),
            UninstallAppOutcome::Removed {
                backend: BackendId::Homebrew,
                ..
            }
        ),
        "{:?}",
        outcomes[0].result
    );
    assert_eq!(outcomes[1].id, id("ghost-app"));
    assert!(
        matches!(
            &outcomes[1].result,
            Err(AppsError::BlockingResolveRequired { .. })
        ),
        "{:?}",
        outcomes[1].result
    );
    assert!(blocking.records().is_empty(), "the record was removed");
    fake.assert_no_unmatched_calls();
}
