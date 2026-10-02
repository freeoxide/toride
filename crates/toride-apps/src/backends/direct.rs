//! # Direct-download backend
//!
//! [`DirectBackend`] executes [`Operation::DirectInstall`] /
//! [`Operation::DirectUninstall`] over toride-installer's verified
//! pipeline: a capped, time-boxed download; a sha256 check under
//! [`Verifier::Strict`] ([`Verifier::Lenient`] only behind an explicit
//! [`DirectBackend::with_verifier`] opt); tarball extraction for archive
//! URLs; and the atomic `0o755` install write. No package manager is
//! involved — this is the one backend every platform shares.
//!
//! The manifest is the ledger: `list_installed` reports nothing (a
//! directory listing cannot attribute binaries to toride), presence rides
//! the filesystem probe behind [`Backend::status`], and uninstalls replay
//! the record's installed path — deleting only the canonicalized
//! install-dir binary, never anything else.
//!
//! The async operations await toride-installer's pipeline directly; the
//! `_sync` twins drive the same code through a current-thread tokio
//! runtime created per call (the `direct` feature necessarily pulls tokio
//! in), so an all-sync embedder gets direct downloads too — never call
//! the sync twins from inside an async context.

use std::path::Path;

use async_trait::async_trait;
use camino::Utf8PathBuf;
pub use toride_installer::Verifier;
use toride_installer::tool::{ArtifactKind, Checksum, ReleaseResolver, Tool};
use toride_installer::{Installer, Target as ArtifactTarget};

use crate::backend::{
    Backend, BackendId, BackendStatus, InstallOutcome, InstallRequest, InstalledApp, ListQuery,
    StatusQuery, UninstallOutcome, UninstallRequest, UpdateRequest, ensure_install_allowed,
    ensure_uninstall_allowed, ensure_update_allowed,
};
use crate::error::{Error, Result};
use crate::plan::{
    DirectArtifact, Operation, Target, direct_artifact, is_single_path_component, url_asset_name,
};

/// Direct-download installs over toride-installer's verified pipeline.
///
/// Construct with [`DirectBackend::at`] (an explicit install dir, the
/// test-friendly spelling), [`DirectBackend::new`]
/// (`~/.local/bin`, matching toride-installer's default), or
/// [`DirectBackend::detect`] (the
/// [`detect_backends`](crate::apps::AppsBuilder::detect_backends) wiring
/// name — there is no manager binary to detect, so it never probes).
/// [`DirectBackend::install_dir`] is the directory records resolve their
/// binary paths against.
pub struct DirectBackend {
    install_dir: Utf8PathBuf,
    installer: Installer,
}

impl DirectBackend {
    /// The backend over the default install dir (`~/.local/bin`),
    /// verifying strictly.
    ///
    /// # Errors
    ///
    /// [`Error::Command`] when no home directory resolves.
    pub fn new() -> Result<Self> {
        let home = dirs::home_dir().ok_or_else(|| {
            Error::Command(toride_runner::Error::Other(
                "no home directory for the default direct install dir".to_owned(),
            ))
        })?;
        let dir = Utf8PathBuf::from_path_buf(home.join(".local/bin")).map_err(|_| {
            Error::Command(toride_runner::Error::Other(
                "the home directory is not valid UTF-8".to_owned(),
            ))
        })?;
        Ok(Self::at(dir))
    }

    /// The backend over `install_dir`, verifying strictly — the injectable
    /// spelling tests and embedders pin the install location with.
    #[must_use]
    pub fn at(install_dir: impl Into<Utf8PathBuf>) -> Self {
        Self {
            install_dir: install_dir.into(),
            installer: Installer::new().with_verifier(Verifier::Strict),
        }
    }

    /// The host wiring — [`DirectBackend::new`] under the name the
    /// builder's detect pass calls; nothing to detect (no manager binary).
    ///
    /// # Errors
    ///
    /// Same contract as [`DirectBackend::new`].
    pub fn detect() -> Result<Self> {
        Self::new()
    }

    /// The directory direct installs write into — the base every recorded
    /// binary path resolves against.
    #[must_use]
    pub const fn install_dir(&self) -> &Utf8PathBuf {
        &self.install_dir
    }

    /// Set the verification policy — the explicit opt-in
    /// [`Verifier::Lenient`] (size-floor sanity check only) replaces the
    /// strict default; consume-and-return.
    #[must_use]
    pub fn with_verifier(mut self, verifier: Verifier) -> Self {
        self.installer = self.installer.clone().with_verifier(verifier);
        self
    }

    /// The shared install body both spellings dispatch through.
    async fn install_inner(&self, request: &InstallRequest<'_>) -> Result<InstallOutcome> {
        let Operation::DirectInstall {
            url,
            checksum,
            bin_name,
        } = &request.plan.operation
        else {
            return Err(misrouted_operation(&request.plan.operation));
        };
        if !is_single_path_component(bin_name) {
            return Err(Error::Command(toride_runner::Error::Other(format!(
                "the direct bin_name `{bin_name}` is not a single path component — \
                 refusing a destination outside the install dir"
            ))));
        }
        let artifact = match direct_artifact(url) {
            DirectArtifact::Binary => ArtifactKind::Binary,
            DirectArtifact::TarballGz => ArtifactKind::tarball_gz(),
            DirectArtifact::TarballXz => ArtifactKind::tarball_xz(),
            DirectArtifact::Unsupported => {
                return Err(unsupported_archive(url));
            }
        };
        let tool = Tool::builder()
            .name(bin_name.clone())
            .artifact(artifact)
            .bin_path(bin_name.clone())
            .bin_name(bin_name.clone())
            .checksum(checksum.clone().map_or(Checksum::None, Checksum::Digest))
            .default_install_dir(self.install_dir.clone())
            .build()?;
        let resolver = UrlResolver { url: url.clone() };
        self.installer
            .install_with_resolver(
                &tool,
                artifact_target(*request.target),
                url_asset_name(url).unwrap_or("direct"),
                Some(&self.install_dir),
                &resolver,
            )
            .await?;
        Ok(InstallOutcome {
            version: None,
            detail: format!("installed `{bin_name}` from {url}"),
        })
    }

    /// Delete the recorded install-dir binary, and nothing else: the path
    /// is canonicalized, must resolve inside the backend's own install
    /// dir, and must be a regular file. An absent target is a successful
    /// no-op (the facade post-verifies absence regardless).
    fn remove_binary(&self, bin_path: &str) -> Result<UninstallOutcome> {
        let target = Utf8PathBuf::from(bin_path);
        let canonical = match std::fs::canonicalize(target.as_std_path()) {
            Ok(canonical) => canonical,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(UninstallOutcome {
                    detail: format!("`{bin_path}` was already absent"),
                });
            }
            Err(error) => {
                return Err(Error::DirectUninstallFailed {
                    path: bin_path.to_owned(),
                    reason: error.to_string(),
                });
            }
        };
        let dir = std::fs::canonicalize(self.install_dir.as_std_path()).map_err(|error| {
            Error::DirectUninstallFailed {
                path: bin_path.to_owned(),
                reason: format!(
                    "the install dir {} could not be resolved: {error}",
                    self.install_dir
                ),
            }
        })?;
        if canonical.parent() != Some(dir.as_path()) {
            return Err(Error::DirectUninstallFailed {
                path: bin_path.to_owned(),
                reason: format!(
                    "it does not live in the install dir {} — only the canonicalized \
                     install-dir binary is removed",
                    self.install_dir
                ),
            });
        }
        if !canonical.is_file() {
            return Err(Error::DirectUninstallFailed {
                path: bin_path.to_owned(),
                reason: "the canonicalized target is not a regular file".to_owned(),
            });
        }
        std::fs::remove_file(&canonical).map_err(|error| Error::DirectUninstallFailed {
            path: bin_path.to_owned(),
            reason: error.to_string(),
        })?;
        Ok(UninstallOutcome {
            detail: format!("removed `{bin_path}`"),
        })
    }
}

#[async_trait]
impl Backend for DirectBackend {
    fn id(&self) -> BackendId {
        BackendId::Direct
    }

    fn supports(&self, _target: &Target) -> bool {
        true
    }

    async fn install(&self, request: InstallRequest<'_>) -> Result<InstallOutcome> {
        ensure_install_allowed(&request)?;
        self.install_inner(&request).await
    }

    async fn uninstall(&self, request: UninstallRequest<'_>) -> Result<UninstallOutcome> {
        ensure_uninstall_allowed(&request)?;
        let Operation::DirectUninstall { bin_path } = &request.plan.operation else {
            return Err(misrouted_operation(&request.plan.operation));
        };
        self.remove_binary(bin_path)
    }

    async fn update(&self, request: UpdateRequest<'_>) -> Result<()> {
        ensure_update_allowed(&request)?;
        Err(direct_update_refused())
    }

    async fn list_installed(&self, _query: ListQuery) -> Result<Vec<InstalledApp>> {
        Ok(Vec::new())
    }

    async fn status(&self, query: StatusQuery<'_>) -> Result<BackendStatus> {
        Ok(probe(query.id))
    }

    fn install_sync(&self, request: InstallRequest<'_>) -> Result<InstallOutcome> {
        ensure_install_allowed(&request)?;
        start_runtime()?.block_on(self.install_inner(&request))
    }

    fn uninstall_sync(&self, request: UninstallRequest<'_>) -> Result<UninstallOutcome> {
        ensure_uninstall_allowed(&request)?;
        let Operation::DirectUninstall { bin_path } = &request.plan.operation else {
            return Err(misrouted_operation(&request.plan.operation));
        };
        self.remove_binary(bin_path)
    }

    fn update_sync(&self, request: UpdateRequest<'_>) -> Result<()> {
        ensure_update_allowed(&request)?;
        Err(direct_update_refused())
    }

    fn list_installed_sync(&self, _query: ListQuery) -> Result<Vec<InstalledApp>> {
        Ok(Vec::new())
    }

    fn status_sync(&self, query: StatusQuery<'_>) -> Result<BackendStatus> {
        Ok(probe(query.id))
    }
}

/// A resolver that answers with the URL the plan already carries — the
/// direct method's URL is the fully-resolved artifact address, so there is
/// nothing to resolve.
struct UrlResolver {
    url: String,
}

#[async_trait]
impl ReleaseResolver for UrlResolver {
    async fn resolve(
        &self,
        _target: ArtifactTarget,
        _version: &str,
    ) -> toride_installer::Result<(String, String)> {
        Ok((
            url_asset_name(&self.url).unwrap_or("direct").to_owned(),
            self.url.clone(),
        ))
    }
}

/// The presence probe: an existing file at the recorded path, version
/// unknown (a direct binary's version is only knowable by executing it,
/// which this backend never does).
fn probe(id: &str) -> BackendStatus {
    if Path::new(id).is_file() {
        BackendStatus::Installed { version: None }
    } else {
        BackendStatus::NotInstalled
    }
}

/// Forward the planning target to the installer's target type — inert for
/// a fixed-URL resolver, but the honest relay of the request's context.
fn artifact_target(target: Target) -> ArtifactTarget {
    ArtifactTarget {
        os: match target.os {
            toride_registry::Os::MacOs => toride_installer::Os::Macos,
            toride_registry::Os::Windows => toride_installer::Os::Windows,
            _ => toride_installer::Os::Linux,
        },
        arch: match target.arch {
            toride_registry::Arch::Aarch64 => toride_installer::Arch::Arm64,
            _ => toride_installer::Arch::X64,
        },
    }
}

/// The runtime the sync twin blocks on — current-thread, I/O and time
/// enabled (reqwest needs both; the installer's blocking steps ride its
/// dedicated blocking pool). Created per call and dropped on the calling
/// (sync) thread, so nothing ever drops a runtime from async context.
fn start_runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            Error::Command(toride_runner::Error::Other(format!(
                "the direct backend's runtime failed to start: {error}"
            )))
        })
}

fn misrouted_operation(operation: &Operation) -> Error {
    Error::Command(toride_runner::Error::Other(format!(
        "direct backend cannot execute non-direct operation: {operation:?}"
    )))
}

fn unsupported_archive(url: &str) -> Error {
    Error::Command(toride_runner::Error::Other(format!(
        "the direct pipeline cannot extract the archive at {url} — \
         it installs single binaries and tar.gz/tar.xz tarballs only"
    )))
}

fn direct_update_refused() -> Error {
    Error::Command(toride_runner::Error::Other(
        "direct records have no update verb — re-run ensure_installed to re-download".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::InstallPlan;
    use sha2::{Digest, Sha256};
    use toride_registry::{Arch, TorideId};

    /// sha256("hello"), the same known vector toride-installer's own
    /// engine tests pin — no hashing dependency needed for it.
    const HELLO_SHA256: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    fn temp_dir(label: &str) -> camino::Utf8PathBuf {
        let dir =
            std::env::temp_dir().join(format!("toride-apps-direct-{}-{label}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("unique temp dir is creatable");
        Utf8PathBuf::from_path_buf(dir).expect("system temp dir is valid UTF-8")
    }

    fn install_plan(url: &str, checksum: Option<String>, bin_name: &str) -> InstallPlan {
        InstallPlan {
            app: TorideId::slugify("ripgrep"),
            backend: BackendId::Direct,
            operation: Operation::DirectInstall {
                url: url.to_owned(),
                checksum,
                bin_name: bin_name.to_owned(),
            },
            dry_run: false,
            requires_elevation: false,
        }
    }

    fn uninstall_plan(bin_path: String) -> crate::plan::UninstallPlan {
        crate::plan::UninstallPlan {
            app: TorideId::slugify("ripgrep"),
            backend: BackendId::Direct,
            operation: Operation::DirectUninstall { bin_path },
            dry_run: false,
            requires_elevation: false,
        }
    }

    fn host_target() -> Target {
        Target::new(toride_registry::Os::Linux, Arch::X86_64)
    }

    /// A single-shot HTTP/1.0 server for the async install tests — the
    /// same shape toride-installer's engine tests use, so the pipeline is
    /// exercised against a real socket with no external network. `name`
    /// is the served path (its extension drives artifact-kind inference).
    async fn serve_body_once(body: Vec<u8>, name: &str) -> String {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}/{name}");
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let header = format!(
                    "HTTP/1.0 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(header.as_bytes()).await;
                let _ = sock.write_all(&body).await;
                let _ = sock.flush().await;
            }
        });
        url
    }

    /// The std-thread spelling of [`serve_body_once`], for the sync-twin
    /// test — no async runtime anywhere near it.
    fn serve_body_once_sync(body: Vec<u8>, name: &str) -> String {
        use std::io::{Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}/{name}");
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf);
                let header = format!(
                    "HTTP/1.0 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(header.as_bytes());
                let _ = sock.write_all(&body);
                let _ = sock.flush();
            }
        });
        url
    }

    fn gzipped_tarball(entry_path: &str, entry_bytes: &[u8]) -> Vec<u8> {
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            let mut header = tar::Header::new_gnu();
            header.set_size(entry_bytes.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, entry_path, entry_bytes)
                .unwrap();
            builder.finish().unwrap();
        }
        let mut gz_bytes = Vec::new();
        let mut encoder =
            flate2::write::GzEncoder::new(&mut gz_bytes, flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, &tar_bytes).unwrap();
        encoder.finish().unwrap();
        gz_bytes
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        let digest = Sha256::digest(bytes);
        let mut out = String::with_capacity(digest.len() * 2);
        for byte in digest {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    #[test]
    fn artifact_target_forwards_the_planning_target() {
        let linux = artifact_target(Target::new(toride_registry::Os::Linux, Arch::Aarch64));
        assert_eq!(linux.keyword(), "linux-arm64");
        let macos = artifact_target(Target::macos(Arch::X86_64));
        assert_eq!(macos.keyword(), "macos-x64");
    }

    #[tokio::test]
    async fn install_writes_the_verified_binary_into_the_install_dir() {
        let dir = temp_dir("verified-write");
        let url = serve_body_once(b"hello".to_vec(), "rg").await;
        let backend = DirectBackend::at(&dir);
        let plan = install_plan(&url, Some(HELLO_SHA256.to_owned()), "rg");
        let outcome = backend
            .install(InstallRequest::new(&plan, &host_target()))
            .await
            .unwrap();
        assert_eq!(
            outcome.detail,
            format!("installed `rg` from {url}"),
            "the outcome names the binary and its source"
        );
        assert_eq!(outcome.version, None);
        assert_eq!(
            std::fs::read(dir.join("rg").as_std_path()).unwrap(),
            b"hello",
            "the verified bytes landed verbatim"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let mode = std::fs::metadata(dir.join("rg")).unwrap().mode() & 0o777;
            assert_eq!(mode, 0o755);
        }
    }

    #[tokio::test]
    async fn install_rejects_a_checksum_mismatch_without_writing() {
        let dir = temp_dir("mismatch");
        let url = serve_body_once(b"hello".to_vec(), "rg").await;
        let backend = DirectBackend::at(&dir);
        let plan = install_plan(
            &url,
            Some("0000000000000000000000000000000000000000000000000000000000000000".to_owned()),
            "rg",
        );
        let error = backend
            .install(InstallRequest::new(&plan, &host_target()))
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                Error::Direct(toride_installer::Error::ChecksumMismatch { .. })
            ),
            "{error:?}"
        );
        assert!(!dir.join("rg").exists(), "nothing is written on mismatch");
    }

    #[tokio::test]
    async fn strict_install_refuses_a_checksumless_artifact() {
        let dir = temp_dir("strict");
        let url = serve_body_once(b"hello".to_vec(), "rg").await;
        let backend = DirectBackend::at(&dir);
        let plan = install_plan(&url, None, "rg");
        let error = backend
            .install(InstallRequest::new(&plan, &host_target()))
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                Error::Direct(toride_installer::Error::NoChecksum { .. })
            ),
            "{error:?}"
        );
        assert!(!dir.join("rg").exists());
    }

    #[tokio::test]
    async fn lenient_install_accepts_a_checksumless_artifact_above_the_floor() {
        let dir = temp_dir("lenient");
        let body = vec![0xA5; usize::try_from(toride_installer::DEFAULT_MIN_BYTES).unwrap()];
        let url = serve_body_once(body.clone(), "rg").await;
        let backend = DirectBackend::at(&dir).with_verifier(Verifier::Lenient);
        let plan = install_plan(&url, None, "rg");
        backend
            .install(InstallRequest::new(&plan, &host_target()))
            .await
            .unwrap();
        assert_eq!(std::fs::read(dir.join("rg").as_std_path()).unwrap(), body);
    }

    #[tokio::test]
    async fn install_extracts_the_named_entry_from_a_gzip_tarball() {
        let dir = temp_dir("tarball");
        let archive = gzipped_tarball("ripgrep-14.1.0/bin/rg", b"TAR-RG-BYTES");
        let digest = sha256_hex(&archive);
        let url = serve_body_once(archive, "rg.tar.gz").await;
        let backend = DirectBackend::at(&dir);
        let plan = install_plan(&url, Some(digest), "rg");
        backend
            .install(InstallRequest::new(&plan, &host_target()))
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(dir.join("rg").as_std_path()).unwrap(),
            b"TAR-RG-BYTES",
            "the entry lands under its bare name, stripped of the archive prefix"
        );
    }

    #[tokio::test]
    async fn install_refuses_a_bin_name_that_escapes_the_install_dir() {
        let dir = temp_dir("escape");
        let backend = DirectBackend::at(&dir);
        for bin_name in ["sub/rg", "/etc/evil", ".."] {
            let plan = install_plan("https://never-contacted.invalid/rg", None, bin_name);
            let error = backend
                .install(InstallRequest::new(&plan, &host_target()))
                .await
                .unwrap_err();
            assert!(matches!(error, Error::Command(_)), "{bin_name}: {error:?}");
            assert!(
                error.to_string().contains("single path component"),
                "{error}"
            );
        }
        assert!(
            !dir.join("..").join("evil").exists(),
            "nothing was written outside the install dir"
        );
    }

    #[tokio::test]
    async fn install_refuses_an_archive_the_pipeline_cannot_extract() {
        let dir = temp_dir("zip-refusal");
        let backend = DirectBackend::at(&dir);
        for url in [
            "https://never-contacted.invalid/rg.zip",
            "https://never-contacted.invalid/rg.tar.bz2",
        ] {
            let plan = install_plan(url, None, "rg");
            let error = backend
                .install(InstallRequest::new(&plan, &host_target()))
                .await
                .unwrap_err();
            assert!(matches!(error, Error::Command(_)), "{url}: {error:?}");
            assert!(error.to_string().contains("cannot extract"), "{error}");
        }
        assert!(!dir.join("rg").exists());
    }

    #[tokio::test]
    async fn install_refuses_a_dry_run_plan_without_downloading() {
        let dir = temp_dir("dry-run");
        let backend = DirectBackend::at(&dir);
        let plan = install_plan("https://never-contacted.invalid/rg", None, "rg").dry_run(true);
        let error = backend
            .install(InstallRequest::new(&plan, &host_target()))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::DryRun { .. }), "{error:?}");
    }

    #[tokio::test]
    async fn install_refuses_a_misrouted_operation() {
        let dir = temp_dir("misrouted");
        let backend = DirectBackend::at(&dir);
        let plan = InstallPlan {
            app: TorideId::slugify("ripgrep"),
            backend: BackendId::Direct,
            operation: Operation::BrewInstall {
                cask: true,
                token: "firefox".to_owned(),
            },
            dry_run: false,
            requires_elevation: false,
        };
        let error = backend
            .install(InstallRequest::new(&plan, &host_target()))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::Command(_)), "{error:?}");
    }

    #[test]
    fn install_sync_writes_the_binary_on_the_calling_thread() {
        let dir = temp_dir("sync-write");
        let url = serve_body_once_sync(b"hello".to_vec(), "rg");
        let backend = DirectBackend::at(&dir);
        let plan = install_plan(&url, Some(HELLO_SHA256.to_owned()), "rg");
        backend
            .install_sync(InstallRequest::new(&plan, &host_target()))
            .unwrap();
        assert_eq!(
            std::fs::read(dir.join("rg").as_std_path()).unwrap(),
            b"hello"
        );
    }

    #[test]
    fn uninstall_removes_only_the_recorded_binary() {
        let dir = temp_dir("uninstall");
        std::fs::write(dir.join("rg").as_std_path(), b"x").unwrap();
        std::fs::write(dir.join("sibling").as_std_path(), b"y").unwrap();
        let backend = DirectBackend::at(&dir);
        backend
            .uninstall_sync(UninstallRequest::new(
                &uninstall_plan(dir.join("rg").to_string()),
                &host_target(),
            ))
            .unwrap();
        assert!(!dir.join("rg").exists());
        assert!(dir.join("sibling").exists(), "nothing but the binary goes");
    }

    #[test]
    fn uninstall_canonicalizes_the_recorded_path() {
        let dir = temp_dir("canonical");
        std::fs::create_dir_all(dir.join("nested").as_std_path()).unwrap();
        std::fs::write(dir.join("rg").as_std_path(), b"x").unwrap();
        let backend = DirectBackend::at(&dir);
        let traversed = format!("{dir}/nested/../rg");
        backend
            .uninstall_sync(UninstallRequest::new(
                &uninstall_plan(traversed),
                &host_target(),
            ))
            .unwrap();
        assert!(!dir.join("rg").exists());
    }

    #[test]
    fn uninstall_refuses_a_path_outside_the_install_dir() {
        let install_dir = temp_dir("inside");
        let outside = temp_dir("outside");
        std::fs::write(outside.join("rg").as_std_path(), b"precious").unwrap();
        let backend = DirectBackend::at(&install_dir);
        let error = backend
            .uninstall_sync(UninstallRequest::new(
                &uninstall_plan(outside.join("rg").to_string()),
                &host_target(),
            ))
            .unwrap_err();
        assert!(
            matches!(error, Error::DirectUninstallFailed { .. }),
            "{error:?}"
        );
        assert!(outside.join("rg").exists(), "the refused target survives");
    }

    #[test]
    fn uninstall_refuses_a_directory_at_the_recorded_path() {
        let dir = temp_dir("dir-target");
        std::fs::create_dir_all(dir.join("rg")).unwrap();
        let backend = DirectBackend::at(&dir);
        let error = backend
            .uninstall_sync(UninstallRequest::new(
                &uninstall_plan(dir.join("rg").to_string()),
                &host_target(),
            ))
            .unwrap_err();
        assert!(
            matches!(error, Error::DirectUninstallFailed { .. }),
            "{error:?}"
        );
        assert!(dir.join("rg").is_dir(), "the directory survives");
    }

    #[test]
    fn uninstall_of_an_absent_binary_is_a_clean_no_op() {
        let dir = temp_dir("absent");
        let backend = DirectBackend::at(&dir);
        let outcome = backend
            .uninstall_sync(UninstallRequest::new(
                &uninstall_plan(dir.join("rg").to_string()),
                &host_target(),
            ))
            .unwrap();
        assert!(outcome.detail.contains("already absent"), "{outcome:?}");
    }

    #[test]
    fn uninstall_honors_the_dry_run_guard() {
        let dir = temp_dir("uninstall-dry");
        std::fs::write(dir.join("rg").as_std_path(), b"x").unwrap();
        let backend = DirectBackend::at(&dir);
        let plan = uninstall_plan(dir.join("rg").to_string()).dry_run(true);
        let error = backend
            .uninstall_sync(UninstallRequest::new(&plan, &host_target()))
            .unwrap_err();
        assert!(matches!(error, Error::DryRun { .. }), "{error:?}");
        assert!(dir.join("rg").exists());
    }

    #[test]
    fn update_refuses_with_a_typed_command_error() {
        let dir = temp_dir("update");
        let backend = DirectBackend::at(&dir);
        let plan = crate::plan::UpdatePlan {
            app: TorideId::slugify("ripgrep"),
            backend: BackendId::Direct,
            operation: Operation::DirectInstall {
                url: "https://x.test/rg".to_owned(),
                checksum: None,
                bin_name: "rg".to_owned(),
            },
            dry_run: false,
            requires_elevation: false,
        };
        let error = backend
            .update_sync(UpdateRequest::new(&plan, &host_target()))
            .unwrap_err();
        assert!(matches!(error, Error::Command(_)), "{error:?}");
        assert!(error.to_string().contains("update verb"), "{error}");
    }

    #[test]
    fn status_reports_file_presence_with_an_unknown_version() {
        let dir = temp_dir("status");
        std::fs::write(dir.join("rg").as_std_path(), b"x").unwrap();
        assert_eq!(
            probe(dir.join("rg").as_str()),
            BackendStatus::Installed { version: None }
        );
        assert_eq!(
            probe(dir.join("missing").as_str()),
            BackendStatus::NotInstalled
        );
    }

    #[test]
    fn list_installed_reports_nothing_by_design() {
        let dir = temp_dir("list");
        let backend = DirectBackend::at(&dir);
        assert!(
            backend
                .list_installed_sync(ListQuery::all())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn constructors_default_to_the_default_install_dir_when_home_resolves() {
        let Some(home) = dirs::home_dir() else {
            return;
        };
        let backend = DirectBackend::new().unwrap();
        assert_eq!(
            backend.install_dir().as_std_path(),
            home.join(".local/bin"),
            "toride-installer's default install dir"
        );
        assert_eq!(DirectBackend::detect().unwrap().id(), BackendId::Direct);
        assert!(backend.supports(&host_target()));
    }
}
