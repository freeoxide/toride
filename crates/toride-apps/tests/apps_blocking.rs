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
        .ensure_installed(&cask_app(), &AppInstallOptions::new())
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
        .ensure_installed(&cask_app(), &AppInstallOptions::new())
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
        .ensure_installed(&cask_app(), &AppInstallOptions::new())
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
    assert!(apps.records().is_empty());
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

/// A store whose saves always fail — the adopt rollback proof.
struct FailingStore;

impl RecordStore for FailingStore {
    fn load(&self) -> ManifestResult<StoreLoad> {
        Ok(StoreLoad {
            snapshot: RecordSnapshot::empty(),
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
        .with_record_store(Arc::new(FailingStore))
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
            .ensure_installed(&cask_app(), &AppInstallOptions::new())
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
