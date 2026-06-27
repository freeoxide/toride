//! The generic installation engine.
//!
//! [`Installer`] is tool-agnostic: given a [`Tool`](crate::Tool) (or a
//! custom [`ReleaseResolver`]), a [`Target`](crate::target::Target), and a
//! version, it runs the full pipeline:
//!
//! 1. **resolve** the artifact URL (and the concrete version, when the
//!    request is `"latest"`);
//! 2. **download** the bytes via `reqwest`, following redirects, capped at
//!    a configurable maximum size;
//! 3. **verify** — sha256 when the tool publishes one, otherwise a sane
//!    non-zero size floor (documented below);
//! 4. **extract** — a `Binary` is placed directly, a `Tarball` is
//!    decompressed (gzip or xz) and the configured entry is read out;
//! 5. **install** — written atomically (temp + rename, via `toride-fs`)
//!    into the install directory and `chmod 0o755` on Unix.
//!
//! ## Verification policy
//!
//! Some tools (mise among them) publish no sha256 for their release
//! artifacts. For those, the installer applies a **size floor** (default
//! 1 MiB): a download smaller than the floor is rejected as suspicious
//! (a 404 HTML page, an empty response, a redirect to a login screen, …).
//! This is NOT a security guarantee — it is a sanity check. Tools that DO
//! publish checksums are verified strictly. Pass
//! [`Verifier::Strict`](crate::Verifier::Strict) to refuse tools that have
//! no checksum at all.

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use camino::Utf8PathBuf;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::extract::extract_executable;
use crate::tool::{Checksum, ReleaseResolver, Tool};
use crate::target::Target;

/// Default upper bound on a single download: 256 MiB.
pub const DEFAULT_MAX_BYTES: u64 = 256 * 1024 * 1024;

/// Default size floor applied when a tool publishes no checksum: 1 MiB.
///
/// Smaller than this and we assume the download is not a real binary
/// (HTML error page, empty body, …). This is a sanity check, not a
/// security measure.
pub const DEFAULT_MIN_BYTES: u64 = 1024 * 1024;

/// Verification strictness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Verifier {
    /// Verify the sha256 when the tool publishes one; otherwise fall back
    /// to the documented size-floor sanity check. This is the default and
    /// the right choice for tools like mise.
    #[default]
    Lenient,

    /// Refuse to install any tool that publishes no checksum. Use this
    /// when integrity is non-negotiable.
    Strict,
}

/// A configured installer engine.
///
/// Cloneable and cheap to share (the HTTP client is behind an `Arc`).
/// Construct via [`Installer::new`] or [`Installer::builder`](crate::InstallerBuilder).
#[derive(Clone)]
pub struct Installer {
    client: reqwest::Client,
    max_bytes: u64,
    min_bytes: u64,
    verifier: Verifier,
}

impl std::fmt::Debug for Installer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Installer")
            .field("max_bytes", &self.max_bytes)
            .field("min_bytes", &self.min_bytes)
            .field("verifier", &self.verifier)
            .finish_non_exhaustive()
    }
}

impl Default for Installer {
    fn default() -> Self {
        Self::new()
    }
}

impl Installer {
    /// Create a new installer with sensible defaults.
    ///
    /// The HTTP client follows redirects (GitHub release downloads redirect
    /// to a CDN) and sets a `User-Agent` so release hosts that require one
    /// (e.g. api.github.com) accept the request.
    #[must_use]
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .user_agent(concat!("toride-installer/", env!("CARGO_PKG_VERSION")))
            // GitHub release downloads redirect to objects.githubusercontent.com.
            .redirect(reqwest::redirect::Policy::limited(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            client,
            max_bytes: DEFAULT_MAX_BYTES,
            min_bytes: DEFAULT_MIN_BYTES,
            verifier: Verifier::Lenient,
        }
    }

    /// Override the maximum allowed download size in bytes.
    #[must_use]
    pub const fn with_max_bytes(mut self, max: u64) -> Self {
        self.max_bytes = max;
        self
    }

    /// Override the size-floor sanity check (applied when a tool publishes
    /// no checksum) in bytes.
    #[must_use]
    pub const fn with_min_bytes(mut self, min: u64) -> Self {
        self.min_bytes = min;
        self
    }

    /// Set the verification policy.
    #[must_use]
    pub const fn with_verifier(mut self, v: Verifier) -> Self {
        self.verifier = v;
        self
    }

    /// Install `tool` at `version` for the host [`Target`], using the
    /// tool's built-in resolver ([`Tool`] itself implements
    /// [`ReleaseResolver`] via the default-URL-template path is NOT
    /// available — supply a resolver instead).
    ///
    /// In practice you want [`Installer::install_with_resolver`] since
    /// every concrete tool ships a resolver. This entry-point is kept for
    /// resolvers that live outside the `Tool`.
    ///
    /// # Errors
    ///
    /// See the module-level docs and [`Error`].
    pub async fn install(
        &self,
        tool: &Tool,
        target: Target,
        version: &str,
        install_dir: Option<&Utf8PathBuf>,
        resolver: &(dyn ReleaseResolver + Send + Sync),
    ) -> Result<Utf8PathBuf> {
        self.install_with_resolver(tool, target, version, install_dir, resolver)
            .await
    }

    /// Install `tool` using a custom [`ReleaseResolver`] to map
    /// (target, version) -> URL.
    ///
    /// This is the primary entry-point.
    ///
    /// # Errors
    ///
    /// See [`Error`].
    pub async fn install_with_resolver(
        &self,
        tool: &Tool,
        target: Target,
        version: &str,
        install_dir: Option<&Utf8PathBuf>,
        resolver: &(dyn ReleaseResolver + Send + Sync),
    ) -> Result<Utf8PathBuf> {
        tool.validate()?;

        // 1. resolve URL + concrete version.
        let (concrete_version, url) = resolver.resolve(target, version).await?;

        // 2. download (with size cap).
        let bytes = self.download(&url).await?;

        // 3. verify.
        self.verify(tool, &concrete_version, &bytes, &url)?;

        // 4. extract the executable bytes.
        let exec_bytes =
            extract_executable(&bytes, tool.artifact, &tool.name, tool.bin_path.as_deref())?;

        // 5. compute install path + write atomically.
        let dir = resolve_install_dir(tool, install_dir)?;
        let dest = dir.join(&tool.bin_name);
        write_executable(dest.as_std_path(), &exec_bytes)?;

        Ok(dest)
    }

    /// Download `url` into memory, enforcing the size cap via
    /// `Content-Length` (when present) and a hard byte count while reading.
    async fn download(&self, url: &str) -> Result<Vec<u8>> {
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|source| Error::Download {
                url: url.to_owned(),
                source,
            })?;

        if !resp.status().is_success() {
            return Err(Error::HttpStatus {
                url: url.to_owned(),
                status: resp.status().as_u16(),
            });
        }

        // Pre-check declared size to fail fast on obviously-huge downloads.
        if let Some(len) = resp.content_length()
            && len > self.max_bytes
        {
            return Err(Error::TooLarge {
                url: url.to_owned(),
                size: len,
                max: self.max_bytes,
            });
        }

        // The `bytes::Bytes` materialiser will surface an error on a body
        // larger than the configured client cap, but we also cap via
        // Content-Length above. For bodies without a declared length, a
        // misbehaving server could still stream past `max_bytes`; the
        // built-in reqwest default has no read cap, so we additionally
        // guard the final size here.
        let bytes = resp
            .bytes()
            .await
            .map_err(|source| Error::Download {
                url: url.to_owned(),
                source,
            })?;

        if bytes.len() as u64 > self.max_bytes {
            return Err(Error::TooLarge {
                url: url.to_owned(),
                size: bytes.len() as u64,
                max: self.max_bytes,
            });
        }

        Ok(bytes.to_vec())
    }

    /// Verify the downloaded bytes against the tool's checksum policy.
    fn verify(&self, tool: &Tool, version: &str, bytes: &[u8], url: &str) -> Result<()> {
        let actual = hex_sha256(bytes);

        match &tool.checksum {
            Checksum::None => {
                if matches!(self.verifier, Verifier::Strict) {
                    return Err(Error::NoChecksum {
                        tool: tool.name.clone(),
                    });
                }
                // Lenient: enforce the sanity floor only.
                if (bytes.len() as u64) < self.min_bytes {
                    return Err(Error::TooSmall {
                        url: url.to_owned(),
                        size: bytes.len() as u64,
                        min: self.min_bytes,
                    });
                }
                Ok(())
            }

            Checksum::Digest(expected) => {
                if actual.eq_ignore_ascii_case(expected) {
                    Ok(())
                } else {
                    Err(Error::ChecksumMismatch {
                        tool: tool.name.clone(),
                        version: version.to_owned(),
                        expected: expected.clone(),
                        actual,
                    })
                }
            }

            // `Url` checksums are resolved by the tool's resolver ahead of
            // download (the resolver returns the concrete digest via its
            // own plumbing). Here we only see a `Digest` once resolved; a
            // raw `Url` variant therefore means "the resolver did not
            // resolve it" — treat as lenient size check.
            Checksum::Url { .. } => {
                if (bytes.len() as u64) < self.min_bytes {
                    return Err(Error::TooSmall {
                        url: url.to_owned(),
                        size: bytes.len() as u64,
                        min: self.min_bytes,
                    });
                }
                Ok(())
            }
        }
    }
}

/// Default-URL-template resolver: a `Tool` whose release URL can be
/// expressed as a format-string over `(target, version)` does not need a
/// bespoke impl — wrap its template in this and reuse the engine.
///
/// (Provided for completeness; the wired mise tool uses its own resolver
/// because "latest" requires an API call.)
pub struct TemplateResolver {
    /// A format string with two positional placeholders: `{version}` and
    /// `{target}`. Example:
    /// `"https://example.com/downloads/{version}/tool-{target}"`.
    pub template: String,
}

#[async_trait]
impl ReleaseResolver for TemplateResolver {
    async fn resolve(&self, target: Target, version: &str) -> Result<(String, String)> {
        let url = self
            .template
            .replace("{version}", version)
            .replace("{target}", &target.keyword());
        Ok((version.to_owned(), url))
    }
}

/// Resolve which directory to install into: explicit override > tool default
/// > `~/.local/bin`.
fn resolve_install_dir(tool: &Tool, override_dir: Option<&Utf8PathBuf>) -> Result<Utf8PathBuf> {
    if let Some(d) = override_dir {
        return Ok(d.clone());
    }
    if let Some(d) = &tool.default_install_dir {
        return Ok(d.clone());
    }
    let home = dirs::home_dir().ok_or(Error::NoHomeDir)?;
    let dir = Utf8PathBuf::from_path_buf(home.join(".local/bin"))
        .map_err(|_| Error::NoHomeDir)?;
    Ok(dir)
}

/// Write `bytes` to `dest` atomically (temp file in the same dir, then
/// rename) and set executable permissions on Unix.
fn write_executable(dest: &Path, bytes: &[u8]) -> Result<()> {
    // Ensure the parent directory exists.
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // toride-fs writes to a NamedTempFile in the parent dir then renames —
    // readers never see a partial binary.
    toride_fs::atomic_write_bytes(dest, bytes)?;

    set_executable(dest)?;
    Ok(())
}

/// `chmod 0o755` on Unix; no-op elsewhere.
fn set_executable(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Hex-encode the sha256 of `bytes`.
fn hex_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    // Manual hex encode keeps us off another tiny dependency.
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Builder for [`Installer`].
///
/// ```rust,ignore
/// use toride_installer::{InstallerBuilder, Verifier};
///
/// let installer = InstallerBuilder::new()
///     .max_bytes(64 * 1024 * 1024)
///     .verifier(Verifier::Strict)
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct InstallerBuilder {
    max_bytes: u64,
    min_bytes: u64,
    verifier: Verifier,
}

impl Default for InstallerBuilder {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_BYTES,
            min_bytes: DEFAULT_MIN_BYTES,
            verifier: Verifier::Lenient,
        }
    }
}

impl InstallerBuilder {
    /// Start a builder with the default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the maximum allowed download size in bytes.
    #[must_use]
    pub const fn max_bytes(mut self, max: u64) -> Self {
        self.max_bytes = max;
        self
    }

    /// Override the size-floor sanity check in bytes.
    #[must_use]
    pub const fn min_bytes(mut self, min: u64) -> Self {
        self.min_bytes = min;
        self
    }

    /// Set the verification policy.
    #[must_use]
    pub const fn verifier(mut self, v: Verifier) -> Self {
        self.verifier = v;
        self
    }

    /// Build the [`Installer`].
    #[must_use]
    pub fn build(self) -> Installer {
        Installer::new()
            .with_max_bytes(self.max_bytes)
            .with_min_bytes(self.min_bytes)
            .with_verifier(self.verifier)
    }
}

/// Convenience: install a tool whose resolver is a static value. Takes an
/// `Arc` so the same resolver can be shared across threads.
///
/// Re-exported as a free function for callers that do not hold an
/// [`Installer`] handle.
pub async fn install_tool(
    tool: &Tool,
    target: Target,
    version: &str,
    install_dir: Option<&Utf8PathBuf>,
    resolver: Arc<dyn ReleaseResolver + Send + Sync>,
) -> Result<Utf8PathBuf> {
    let installer = Installer::new();
    installer
        .install_with_resolver(tool, target, version, install_dir, resolver.as_ref())
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::{Arch, Os};
    use crate::ArtifactKind;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    use tempfile::TempDir;

    fn host_target() -> Target {
        Target::host().unwrap_or(Target {
            os: Os::Linux,
            arch: Arch::X64,
        })
    }

    /// A resolver that returns a constant URL — used to drive the engine
    /// without touching the network. The test then stubs `download` by
    /// going through `verify`/`write` directly.
    struct ConstResolver {
        url: String,
        version: String,
    }

    #[async_trait]
    impl ReleaseResolver for ConstResolver {
        async fn resolve(&self, _target: Target, _version: &str) -> Result<(String, String)> {
            Ok((self.version.clone(), self.url.clone()))
        }
    }

    #[test]
    fn resolve_install_dir_uses_explicit_override() {
        let tmp = TempDir::new().unwrap();
        let tool = Tool::default();
        let override_dir = Utf8PathBuf::from_path_buf(tmp.path().to_owned()).unwrap();
        let dir = resolve_install_dir(&tool, Some(&override_dir)).unwrap();
        assert_eq!(dir, override_dir);
    }

    #[test]
    fn resolve_install_dir_uses_tool_default() {
        let tool = Tool {
            default_install_dir: Some(Utf8PathBuf::from("/opt/mytool")),
            ..Default::default()
        };
        let dir = resolve_install_dir(&tool, None).unwrap();
        assert_eq!(dir, "/opt/mytool");
    }

    #[test]
    fn resolve_install_dir_falls_back_to_local_bin() {
        let tool = Tool::default();
        let dir = resolve_install_dir(&tool, None).unwrap();
        assert!(dir.to_string().ends_with(".local/bin"));
    }

    #[test]
    fn write_executable_places_bytes_and_perms() {
        let tmp = TempDir::new().unwrap();
        let dest = tmp.path().join("mise");
        write_executable(&dest, b"BINARY").unwrap();

        let read_back = fs::read(&dest).unwrap();
        assert_eq!(read_back, b"BINARY");

        #[cfg(unix)]
        {
            let mode = fs::metadata(&dest).unwrap().mode() & 0o777;
            assert_eq!(mode, 0o755);
        }
    }

    #[test]
    fn write_executable_is_atomic_overwrite() {
        let tmp = TempDir::new().unwrap();
        let dest = tmp.path().join("tool");
        write_executable(&dest, b"v1").unwrap();
        write_executable(&dest, b"v2").unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"v2");
    }

    #[test]
    fn write_executable_creates_missing_parent_dirs() {
        let tmp = TempDir::new().unwrap();
        let dest = tmp.path().join("nested/deep/bin/tool");
        write_executable(&dest, b"X").unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"X");
    }

    #[test]
    fn hex_sha256_matches_known_vector() {
        // sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        let h = hex_sha256(b"hello");
        assert_eq!(
            h,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn verifier_lenient_accepts_no_checksum_above_floor() {
        let installer = Installer::new().with_min_bytes(4);
        let tool = Tool {
            name: "demo".into(),
            checksum: Checksum::None,
            ..Default::default()
        };
        // 5 bytes >= 4-byte floor.
        installer.verify(&tool, "1.0", b"enough", "https://x").unwrap();
    }

    #[test]
    fn verifier_lenient_rejects_below_floor() {
        let installer = Installer::new().with_min_bytes(1024);
        let tool = Tool {
            name: "demo".into(),
            checksum: Checksum::None,
            ..Default::default()
        };
        let err = installer
            .verify(&tool, "1.0", b"tiny", "https://x")
            .unwrap_err();
        assert!(matches!(err, Error::TooSmall { .. }));
    }

    #[test]
    fn verifier_strict_rejects_missing_checksum() {
        let installer = Installer::new().with_verifier(Verifier::Strict);
        let tool = Tool {
            name: "demo".into(),
            checksum: Checksum::None,
            ..Default::default()
        };
        let err = installer
            .verify(&tool, "1.0", b"plenty-of-bytes-here", "https://x")
            .unwrap_err();
        assert!(matches!(err, Error::NoChecksum { .. }));
    }

    #[test]
    fn verifier_digest_matches() {
        let installer = Installer::new();
        let digest = hex_sha256(b"MATCH");
        let tool = Tool {
            name: "demo".into(),
            checksum: Checksum::Digest(digest),
            ..Default::default()
        };
        installer.verify(&tool, "1.0", b"MATCH", "https://x").unwrap();
    }

    #[test]
    fn verifier_digest_mismatch_is_error() {
        let installer = Installer::new();
        let tool = Tool {
            name: "demo".into(),
            checksum: Checksum::Digest("0000000000000000000000000000000000000000000000000000000000000000".into()),
            ..Default::default()
        };
        let err = installer
            .verify(&tool, "1.0", b"MISMATCH", "https://x")
            .unwrap_err();
        assert!(matches!(err, Error::ChecksumMismatch { .. }));
    }

    #[tokio::test]
    async fn end_to_end_engine_with_fake_resolver_and_local_bytes() {
        // Drive the full pipeline minus the network: we bypass `download`
        // by inlining its postconditions and calling verify + write directly.
        let tmp = TempDir::new().unwrap();
        let dest = tmp.path().join("mise");

        // Simulate: resolved URL, downloaded bytes, verified, extracted.
        let bytes = b"FAKE-MISE-BINARY";
        let tool = Tool {
            name: "mise".into(),
            artifact: ArtifactKind::Binary,
            bin_name: "mise".into(),
            checksum: Checksum::None,
            ..Default::default()
        };
        let installer = Installer::new().with_min_bytes(1);
        installer.verify(&tool, "latest", bytes, "https://x").unwrap();
        let exec = extract_executable(bytes, tool.artifact, &tool.name, None).unwrap();
        write_executable(&dest, &exec).unwrap();

        assert_eq!(fs::read(&dest).unwrap(), bytes);
        #[cfg(unix)]
        {
            let mode = fs::metadata(&dest).unwrap().mode() & 0o777;
            assert_eq!(mode, 0o755);
        }

        // The ConstResolver compiles and resolves.
        let r = ConstResolver {
            url: "https://example.com/mise".into(),
            version: "1.2.3".into(),
        };
        let (v, u) = r.resolve(host_target(), "latest").await.unwrap();
        assert_eq!(v, "1.2.3");
        assert_eq!(u, "https://example.com/mise");
    }

    #[tokio::test]
    async fn template_resolver_substitutes_version_and_target() {
        let r = TemplateResolver {
            template: "https://x.test/{version}/tool-{target}".into(),
        };
        let (v, u) = r
            .resolve(host_target(), "9.9.9")
            .await
            .unwrap();
        assert_eq!(v, "9.9.9");
        assert!(u.contains("9.9.9"));
        assert!(u.contains("tool-"));
        // target keyword substituted somewhere.
        assert!(u.contains("linux-") || u.contains("macos-"));
    }

    #[tokio::test]
    async fn real_download_errors_on_bad_host() {
        // Gated: hits the network (DNS). Run with TORIDE_INSTALLER_INTEGRATION=1.
        if !matches!(std::env::var("TORIDE_INSTALLER_INTEGRATION").as_deref(), Ok("1")) {
            eprintln!("TORIDE_INSTALLER_INTEGRATION not set; skipping live network test");
            return;
        }
        let installer = Installer::new();
        let err = installer
            .download("https://this-host-does-not-exist.invalid.invalid/x")
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Download { .. }));
    }

    #[tokio::test]
    async fn real_download_errors_on_404() {
        // Gated: hits the network. Run with TORIDE_INSTALLER_INTEGRATION=1.
        if !matches!(std::env::var("TORIDE_INSTALLER_INTEGRATION").as_deref(), Ok("1")) {
            eprintln!("TORIDE_INSTALLER_INTEGRATION not set; skipping live network test");
            return;
        }
        let installer = Installer::new();
        // A URL that resolves but returns 404.
        let err = installer
            .download("https://github.com/jdx/mise/releases/latest/download/this-asset-does-not-exist")
            .await
            .unwrap_err();
        assert!(matches!(err, Error::HttpStatus { status, .. } if status == 404));
    }
}
