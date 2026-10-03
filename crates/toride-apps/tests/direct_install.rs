//! Integration tests for the `direct` feature — direct downloads over
//! toride-installer's pipeline, end to end through both facades: a
//! one-shot loopback HTTP server serves the artifact (no external
//! network), a fixture adapter plays the registry, manifests live under
//! unique temp-dir paths, and the sha256 is pinned to a known vector. No
//! package managers, no `FakeRunner` scripts (the direct backend executes
//! no commands at all).

#![cfg(feature = "direct")]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use camino::Utf8PathBuf;
use toride_apps::apps::{
    AppInstallOptions, AppUninstallOptions, AppUpdateOptions, Apps, AppsBlocking, AppsError,
    EnsureAppOutcome, UninstallAppOutcome,
};
use toride_apps::backends::DirectBackend;
use toride_apps::manifest::NativeIds;
use toride_apps::{AppStatus, BackendId, Target};
use toride_registry::model::{App, InstallMethod, SourceRef};
use toride_registry::{Adapter, Availability, Checksum, ChecksumAlgo, SourceKind, TorideId};

/// sha256("hello") — the served artifact is `b"hello"` verbatim.
const HELLO_SHA256: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

static DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_dir(label: &str) -> Utf8PathBuf {
    let unique = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "toride-apps-direct-it-{}-{unique}-{label}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("unique temp dir is creatable");
    Utf8PathBuf::from_path_buf(dir).expect("system temp dir is valid UTF-8")
}

/// A one-shot loopback HTTP/1.0 server serving `body` to the next GET —
/// a second fetch would find nothing listening, so tests that must not
/// download again fail loudly if they do.
async fn serve_body_once(body: Vec<u8>) -> String {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}/rg-14.1.0-x86_64");
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let response = format!(
                "HTTP/1.0 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(response.as_bytes()).await;
            let _ = sock.write_all(&body).await;
            let _ = sock.flush().await;
        }
    });
    url
}

/// The std-thread spelling, for the blocking facade — no runtime anywhere.
fn serve_body_once_sync(body: Vec<u8>) -> String {
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}/rg-14.1.0-x86_64");
    std::thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf);
            let response = format!(
                "HTTP/1.0 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(response.as_bytes());
            let _ = sock.write_all(&body);
            let _ = sock.flush();
        }
    });
    url
}

struct FixtureAdapter {
    apps: Vec<App>,
}

#[async_trait]
impl Adapter for FixtureAdapter {
    fn source(&self) -> SourceKind {
        SourceKind::HomebrewFormula
    }

    async fn lookup(&self, id: &SourceRef) -> toride_registry::Result<Option<App>> {
        Ok(self
            .apps
            .iter()
            .find(|app| app.id.as_str() == id.id)
            .cloned())
    }

    async fn search(&self, _query: &str) -> toride_registry::Result<Vec<App>> {
        Ok(Vec::new())
    }
}

/// A direct-method registry app for `url`, verified against `digest`,
/// declaring `binaries` as its executable names.
fn direct_app(url: &str, digest: Option<&str>, binaries: &[&str]) -> App {
    App {
        id: TorideId::slugify("ripgrep"),
        name: "Ripgrep".to_owned(),
        aliases: Vec::new(),
        summary: None,
        description: None,
        homepage: None,
        license: None,
        developer: None,
        binaries: binaries.iter().map(|bin| (*bin).to_owned()).collect(),
        latest: None,
        platforms: Vec::new(),
        artifacts: Vec::new(),
        install: InstallMethod::Direct {
            url: url.to_owned(),
            checksum: digest.map(|digest| Checksum {
                algo: ChecksumAlgo::Sha256,
                digest: digest.to_owned(),
            }),
            arch: None,
        },
        sources: Vec::new(),
        availability: Availability::Available,
    }
}

fn facade(install_dir: &Utf8PathBuf, manifest_dir: &Utf8PathBuf, app: App) -> Apps {
    Apps::builder()
        .target(Target::linux(
            toride_apps::Arch::X86_64,
            toride_registry::DistroFamily::Debian,
        ))
        .manifest_path(manifest_dir.join("apps-manifest.json"))
        .direct(DirectBackend::at(install_dir))
        .adapter(Arc::new(FixtureAdapter { apps: vec![app] }))
        .build()
        .expect("facade builds")
}

fn id() -> TorideId {
    TorideId::slugify("ripgrep")
}

#[tokio::test]
async fn ensure_installed_downloads_verifies_and_records_the_provenance() {
    let install_dir = temp_dir("install");
    let manifest_dir = temp_dir("install-manifest");
    let url = serve_body_once(b"hello".to_vec()).await;
    let mut apps = facade(
        &install_dir,
        &manifest_dir,
        direct_app(&url, Some(HELLO_SHA256), &["rg"]),
    );

    let outcome = apps
        .ensure_installed(&id(), AppInstallOptions::new())
        .await
        .unwrap();
    let EnsureAppOutcome::Installed {
        backend,
        ids,
        version,
        verified,
        warning,
    } = outcome
    else {
        panic!("a true miss installs: {outcome:?}");
    };
    assert_eq!(backend, BackendId::Direct);
    assert!(verified, "the fs post-verify confirms the binary");
    assert_eq!(version, None, "a direct binary reports no version");
    assert_eq!(warning, None, "nothing degraded along the way");
    assert_eq!(
        ids,
        NativeIds::Direct {
            url: url.clone(),
            checksum: Some(HELLO_SHA256.to_owned()),
            bin_path: install_dir.join("rg").to_string(),
        },
        "the record carries the download provenance"
    );

    assert_eq!(
        std::fs::read(install_dir.join("rg").as_std_path()).unwrap(),
        b"hello"
    );
    let records = apps.records();
    assert_eq!(records.len(), 1);
    let record = records[0].1;
    assert_eq!(record.backend, BackendId::Direct);
    assert_eq!(record.ids, ids);
    assert!(
        record.plan.is_some(),
        "an executed install records its source plan"
    );
}

#[tokio::test]
async fn re_ensure_answers_already_present_from_local_state_alone() {
    let install_dir = temp_dir("reensure");
    let manifest_dir = temp_dir("reensure-manifest");
    let url = serve_body_once(b"hello".to_vec()).await;
    let mut apps = facade(
        &install_dir,
        &manifest_dir,
        direct_app(&url, Some(HELLO_SHA256), &["rg"]),
    );
    apps.ensure_installed(&id(), AppInstallOptions::new())
        .await
        .unwrap();

    // The one-shot server is gone: any second download would fail loudly.
    let second = apps
        .ensure_installed(&id(), AppInstallOptions::new())
        .await
        .unwrap();
    assert_eq!(
        second,
        EnsureAppOutcome::AlreadyPresent(AppStatus::Installed {
            backend: BackendId::Direct,
            version: None,
        })
    );
}

#[tokio::test]
async fn a_foreign_direct_binary_is_kept_as_is() {
    let install_dir = temp_dir("foreign");
    let manifest_dir = temp_dir("foreign-manifest");
    std::fs::write(install_dir.join("rg").as_std_path(), b"someone-elses-rg").unwrap();
    let mut apps = facade(
        &install_dir,
        &manifest_dir,
        direct_app("https://example.com/rg", None, &["rg"]),
    );

    let outcome = apps
        .ensure_installed(&id(), AppInstallOptions::new())
        .await
        .unwrap();
    match outcome {
        EnsureAppOutcome::AlreadyPresent(AppStatus::Foreign { backend, detail }) => {
            assert_eq!(backend, BackendId::Direct);
            assert!(detail.contains("rg"), "{detail}");
            assert!(detail.contains("not by toride"), "{detail}");
        }
        other => panic!("a present foreign binary is kept: {other:?}"),
    }
    assert_eq!(
        std::fs::read(install_dir.join("rg").as_std_path()).unwrap(),
        b"someone-elses-rg",
        "nothing overwrote the foreign binary"
    );
}

#[tokio::test]
async fn ensure_installed_without_the_direct_backend_answers_backend_unavailable() {
    let install_dir = temp_dir("no-backend");
    let manifest_dir = temp_dir("no-backend-manifest");
    let mut apps = Apps::builder()
        .target(Target::linux(
            toride_apps::Arch::X86_64,
            toride_registry::DistroFamily::Debian,
        ))
        .manifest_path(manifest_dir.join("apps-manifest.json"))
        .adapter(Arc::new(FixtureAdapter {
            apps: vec![direct_app(
                "https://never-contacted.invalid/rg",
                Some(HELLO_SHA256),
                &["rg"],
            )],
        }))
        .build()
        .unwrap();
    let error = apps
        .ensure_installed(&id(), AppInstallOptions::new())
        .await
        .unwrap_err();
    assert!(
        matches!(error, AppsError::BackendUnavailable { backend } if backend == BackendId::Direct),
        "{error:?}"
    );
    assert!(
        !install_dir.join("rg").exists(),
        "nothing was downloaded by a facade with no direct backend"
    );
}

#[tokio::test]
async fn ensure_installed_surfaces_a_checksum_mismatch_as_a_typed_backend_error() {
    let install_dir = temp_dir("mismatch");
    let manifest_dir = temp_dir("mismatch-manifest");
    let url = serve_body_once(b"tampered".to_vec()).await;
    let mut apps = facade(
        &install_dir,
        &manifest_dir,
        direct_app(&url, Some(HELLO_SHA256), &["rg"]),
    );
    let error = apps
        .ensure_installed(&id(), AppInstallOptions::new())
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            AppsError::Backend(toride_apps::Error::Direct(
                toride_installer::Error::ChecksumMismatch { .. }
            ))
        ),
        "{error:?}"
    );
    assert!(
        !install_dir.join("rg").exists(),
        "a mismatched download never lands"
    );
    assert!(apps.records().is_empty(), "nothing is recorded on failure");
}

#[tokio::test]
async fn uninstall_replays_the_record_and_removes_only_that_binary() {
    let install_dir = temp_dir("uninstall");
    let manifest_dir = temp_dir("uninstall-manifest");
    let url = serve_body_once(b"hello".to_vec()).await;
    let mut apps = facade(
        &install_dir,
        &manifest_dir,
        direct_app(&url, Some(HELLO_SHA256), &["rg"]),
    );
    apps.ensure_installed(&id(), AppInstallOptions::new())
        .await
        .unwrap();
    std::fs::write(install_dir.join("neighbor").as_std_path(), b"keep-me").unwrap();

    let outcome = apps
        .uninstall(&id(), AppUninstallOptions::new())
        .await
        .unwrap();
    assert_eq!(
        outcome,
        UninstallAppOutcome::Removed {
            backend: BackendId::Direct,
            ids: NativeIds::Direct {
                url,
                checksum: Some(HELLO_SHA256.to_owned()),
                bin_path: install_dir.join("rg").to_string(),
            },
            warning: None,
        }
    );
    assert!(!install_dir.join("rg").exists());
    assert!(install_dir.join("neighbor").exists());
    assert!(
        apps.records().is_empty(),
        "the record is gone with the binary"
    );
}

#[tokio::test]
async fn unrecorded_uninstall_of_a_direct_app_refuses_at_plan_time() {
    let install_dir = temp_dir("unrecorded");
    let manifest_dir = temp_dir("unrecorded-manifest");
    std::fs::write(install_dir.join("rg").as_std_path(), b"someone-elses").unwrap();
    let mut apps = facade(
        &install_dir,
        &manifest_dir,
        direct_app("https://example.com/rg", None, &["rg"]),
    );
    let error = apps
        .uninstall(&id(), AppUninstallOptions::new().force(true))
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            AppsError::Backend(toride_apps::Error::UnsupportedMethod { .. })
        ),
        "a direct uninstall cannot be planned from registry data: {error:?}"
    );
    assert!(
        install_dir.join("rg").exists(),
        "the forced removal never ran"
    );
}

#[tokio::test]
async fn update_on_a_direct_record_refuses_with_the_unrecordable_operation_error() {
    let install_dir = temp_dir("update");
    let manifest_dir = temp_dir("update-manifest");
    let url = serve_body_once(b"hello".to_vec()).await;
    let mut apps = facade(
        &install_dir,
        &manifest_dir,
        direct_app(&url, Some(HELLO_SHA256), &["rg"]),
    );
    apps.ensure_installed(&id(), AppInstallOptions::new())
        .await
        .unwrap();
    let error = apps
        .update(&id(), &AppUpdateOptions::new())
        .await
        .unwrap_err();
    assert!(
        matches!(error, AppsError::UnrecordableOperation { .. }),
        "{error:?}"
    );
}

#[tokio::test]
async fn pin_on_a_direct_record_hits_the_default_pin_refusal() {
    let install_dir = temp_dir("pin");
    let manifest_dir = temp_dir("pin-manifest");
    let url = serve_body_once(b"hello".to_vec()).await;
    let mut apps = facade(
        &install_dir,
        &manifest_dir,
        direct_app(&url, Some(HELLO_SHA256), &["rg"]),
    );
    apps.ensure_installed(&id(), AppInstallOptions::new())
        .await
        .unwrap();
    let error = apps.pin(&id()).await.unwrap_err();
    assert!(
        matches!(
            error,
            AppsError::Backend(toride_apps::Error::PinUnsupported { .. })
        ),
        "{error:?}"
    );
}

#[tokio::test]
async fn status_answers_from_the_record_and_the_file_for_a_direct_install() {
    let install_dir = temp_dir("status");
    let manifest_dir = temp_dir("status-manifest");
    let url = serve_body_once(b"hello".to_vec()).await;
    let mut apps = facade(
        &install_dir,
        &manifest_dir,
        direct_app(&url, Some(HELLO_SHA256), &["rg"]),
    );
    apps.ensure_installed(&id(), AppInstallOptions::new())
        .await
        .unwrap();
    assert_eq!(
        apps.status(&id()).await.unwrap(),
        AppStatus::Installed {
            backend: BackendId::Direct,
            version: None,
        }
    );
    std::fs::remove_file(install_dir.join("rg").as_std_path()).unwrap();
    assert_eq!(apps.status(&id()).await.unwrap(), AppStatus::NotInstalled);
}

#[test]
fn the_blocking_facade_installs_and_uninstalls_direct_downloads() {
    let install_dir = temp_dir("blocking");
    let manifest_dir = temp_dir("blocking-manifest");
    let url = serve_body_once_sync(b"hello".to_vec());
    let mut blocking = AppsBlocking::new(facade(
        &install_dir,
        &manifest_dir,
        direct_app(&url, Some(HELLO_SHA256), &["rg"]),
    ));

    let outcome = blocking
        .ensure_installed(
            &direct_app(&url, Some(HELLO_SHA256), &["rg"]),
            AppInstallOptions::new(),
        )
        .unwrap();
    assert!(
        matches!(outcome, EnsureAppOutcome::Installed { verified: true, .. }),
        "{outcome:?}"
    );
    assert_eq!(
        std::fs::read(install_dir.join("rg").as_std_path()).unwrap(),
        b"hello"
    );

    let outcome = blocking
        .uninstall(&id(), AppUninstallOptions::new())
        .unwrap();
    assert!(matches!(outcome, UninstallAppOutcome::Removed { .. }));
    assert!(!install_dir.join("rg").exists());
    assert_eq!(
        blocking.records(),
        [] as [(&toride_apps::TorideId, &toride_apps::InstallRecord); 0]
    );
}
