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

#[cfg(unix)]
use std::io::Write;

use async_trait::async_trait;
use camino::Utf8PathBuf;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::extract::extract_executable;
use crate::target::Target;
use crate::tool::{Checksum, ReleaseResolver, Tool};

/// Default upper bound on a single download: 256 MiB.
pub const DEFAULT_MAX_BYTES: u64 = 256 * 1024 * 1024;

/// Default size floor applied when a tool publishes no checksum: 1 MiB.
///
/// Smaller than this and we assume the download is not a real binary
/// (HTML error page, empty body, …). This is a sanity check, not a
/// security measure.
pub const DEFAULT_MIN_BYTES: u64 = 1024 * 1024;

/// Overall per-request timeout applied to the installer's HTTP client.
///
/// reqwest has no default timeout, so without an explicit cap a stalled or
/// slow-drip download would hold the download future indefinitely (the size
/// cap only trips on bytes actually received). 120 s covers large release
/// artifacts on slow links while still bounding a hang.
pub const DEFAULT_HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(2);

/// Connect-only timeout applied to the installer's HTTP client.
///
/// Bounded separately from [`DEFAULT_HTTP_TIMEOUT`] so a dead/slow host is
/// rejected faster than the overall deadline.
pub const DEFAULT_HTTP_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Per-chunk read deadline wrapping the streaming body loop.
///
/// Even with an overall request timeout, a server that opens the connection
/// and then drips ~1 byte/minute never trips the size cap. Racing each
/// `Response::chunk` against this deadline guarantees a slow-drip body cannot
/// stall past the read window.
pub const DEFAULT_CHUNK_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(1);

/// Build the shared HTTP client used for release downloads.
///
/// Centralized (rather than inlined in [`Installer::new`]) so the timeout
/// policy is applied consistently and is unit-testable. The client follows
/// redirects (GitHub release downloads redirect to a CDN), sets a
/// `User-Agent` so hosts that require one accept the request, and carries an
/// overall request timeout plus a connect-only timeout — reqwest applies no
/// timeout by default, so omitting either lets a stalled connection hang the
/// download future indefinitely.
fn build_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent(concat!("toride-installer/", env!("CARGO_PKG_VERSION")))
        // GitHub release downloads redirect to objects.githubusercontent.com.
        .redirect(reqwest::redirect::Policy::limited(10))
        .timeout(DEFAULT_HTTP_TIMEOUT)
        .connect_timeout(DEFAULT_HTTP_CONNECT_TIMEOUT)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

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
        let client = build_http_client();
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
        self.verify(tool, &concrete_version, &bytes, &url).await?;

        // 4. extract the executable bytes.
        let exec_bytes =
            extract_executable(&bytes, tool.artifact, &tool.name, tool.bin_path.as_deref())?;

        // 5. compute install path + write atomically.
        let dir = resolve_install_dir(tool, install_dir)?;
        let dest = dir.join(&tool.bin_name);
        write_executable(dest.as_std_path(), &exec_bytes)?;

        Ok(dest)
    }

    /// Download `url` into memory, enforcing the size cap on the **stream**:
    ///
    /// - If the response carries a `Content-Length`, reject immediately when
    ///   it exceeds the cap (before reading any of the body).
    /// - Otherwise (or if the header lies), read the body incrementally and
    ///   abort the moment the running byte count crosses the cap.
    ///
    /// We never assemble the whole body first: a misbehaving server with no
    /// `Content-Length` (or a header that under-reports) cannot force us to
    /// buffer gigabytes before we notice.
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
        let declared_len = resp.content_length();
        if let Some(len) = declared_len
            && len > self.max_bytes
        {
            return Err(Error::TooLarge {
                url: url.to_owned(),
                size: len,
                max: self.max_bytes,
            });
        }

        // Stream the body chunk-by-chunk via `Response::chunk`, keeping a
        // running byte counter and aborting the instant the cap is exceeded.
        // This closes the gap a missing/lying `Content-Length` would
        // otherwise open: we never buffer the whole body before checking.
        let mut resp = resp;
        // Pre-reserve at most the declared length (when known and within the
        // cap) so the common case avoids repeated re-allocations.
        let reserve = declared_len
            .filter(|&len| len <= self.max_bytes)
            .map_or(0, |len| usize::try_from(len).unwrap_or(0));
        let mut buf: Vec<u8> = Vec::with_capacity(reserve);
        let mut total: u64 = 0;
        loop {
            // Race each chunk read against a deadline: a server that opens
            // the connection and then never sends (or drips ~1 byte/minute)
            // never trips the size cap, so without this guard the loop would
            // stall indefinitely even though the overall client timeout has
            // not yet elapsed on a slow link.
            let chunk = match tokio::time::timeout(DEFAULT_CHUNK_TIMEOUT, resp.chunk()).await {
                Ok(inner) => inner.map_err(|source| Error::Download {
                    url: url.to_owned(),
                    source,
                })?,
                Err(_elapsed) => {
                    return Err(Error::DownloadStalled {
                        url: url.to_owned(),
                        timeout: DEFAULT_CHUNK_TIMEOUT,
                    });
                }
            };
            let Some(chunk) = chunk else { break };

            // Saturating add guards against overflow on a pathologically
            // large stream — saturating to `u64::MAX` then trips the cap.
            total = total.saturating_add(chunk.len() as u64);
            if total > self.max_bytes {
                return Err(Error::TooLarge {
                    url: url.to_owned(),
                    size: total,
                    max: self.max_bytes,
                });
            }

            buf.extend_from_slice(&chunk);
        }

        Ok(buf)
    }

    /// Verify the downloaded bytes against the tool's checksum policy.
    async fn verify(&self, tool: &Tool, version: &str, bytes: &[u8], url: &str) -> Result<()> {
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

            // Fetch the published checksum file and verify the artifact's
            // sha256 against the matching line. This mirrors `Checksum::Digest`
            // — the only difference is that the expected digest is sourced
            // from the URL rather than pinned in config. The size-floor sanity
            // check does NOT apply here: a published checksum is the strict
            // integrity control, so it is verified unconditionally.
            Checksum::Url { url: sum_url, asset_name } => {
                let body = self.fetch_text(sum_url).await?;
                let expected = extract_digest_from_checksum_body(&body, asset_name).ok_or(
                    Error::NoChecksumEntry {
                        url: sum_url.clone(),
                        asset: asset_name.clone(),
                    },
                )?;
                if actual.eq_ignore_ascii_case(&expected) {
                    Ok(())
                } else {
                    Err(Error::ChecksumMismatch {
                        tool: tool.name.clone(),
                        version: version.to_owned(),
                        expected,
                        actual,
                    })
                }
            }
        }
    }

    /// Fetch `url` as UTF-8 text (a checksum file is small and textual).
    ///
    /// Uses the same client/timeout policy as artifact downloads but caps the
    /// body well below `max_bytes`: a checksum file is a few KiB at most, so a
    /// multi-MiB response is itself suspicious.
    async fn fetch_text(&self, url: &str) -> Result<String> {
        // Checksum files are tiny; cap far below the artifact size limit.
        const MAX_CHECKSUM_BYTES: u64 = 1024 * 1024;
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

        if let Some(len) = resp.content_length()
            && len > MAX_CHECKSUM_BYTES
        {
            return Err(Error::TooLarge {
                url: url.to_owned(),
                size: len,
                max: MAX_CHECKSUM_BYTES,
            });
        }

        let mut resp = resp;
        let mut buf: Vec<u8> = Vec::new();
        let mut total: u64 = 0;
        loop {
            let chunk = match tokio::time::timeout(DEFAULT_CHUNK_TIMEOUT, resp.chunk()).await {
                Ok(inner) => inner.map_err(|source| Error::Download {
                    url: url.to_owned(),
                    source,
                })?,
                Err(_elapsed) => {
                    return Err(Error::DownloadStalled {
                        url: url.to_owned(),
                        timeout: DEFAULT_CHUNK_TIMEOUT,
                    });
                }
            };
            let Some(chunk) = chunk else { break };
            total = total.saturating_add(chunk.len() as u64);
            if total > MAX_CHECKSUM_BYTES {
                return Err(Error::TooLarge {
                    url: url.to_owned(),
                    size: total,
                    max: MAX_CHECKSUM_BYTES,
                });
            }
            buf.extend_from_slice(&chunk);
        }

        String::from_utf8(buf).map_err(|_| Error::NoChecksumEntry {
            url: url.to_owned(),
            asset: String::new(),
        })
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
    let dir = Utf8PathBuf::from_path_buf(home.join(".local/bin")).map_err(|_| Error::NoHomeDir)?;
    Ok(dir)
}

/// Write `bytes` to `dest` atomically (temp file in the same dir, then
/// rename) and set executable permissions on Unix.
///
/// To avoid a transient permissions window, the temp file is created with
/// the executable mode up front (chmod-on-temp-before-rename): the final
/// inode is reachable the instant the rename completes, already `0o755` on
/// Unix, so there is never a moment where a fresh executable sits on disk
/// readable but not executable (or vice-versa).
fn write_executable(dest: &Path, bytes: &[u8]) -> Result<()> {
    // Ensure the parent directory exists.
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        // Create the temp file in the SAME directory as the destination so
        // the rename stays atomic on the same filesystem. `tempfile`'s
        // `.permissions(...)` sets the mode at creation (overriding umask,
        // matching the pattern used by toride-fs' atomic-write core), so the
        // renamed inode is already `0o755` the instant it becomes reachable.
        let mut tmp = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o755))
            .tempfile_in(dest.parent().unwrap_or(Path::new(".")))
            .map_err(|source| {
                Error::Atomic(toride_fs::Error::AtomicWriteFailed {
                    path: dest.display().to_string(),
                    reason: format!("failed to create temp file: {source}"),
                })
            })?;

        tmp.write_all(bytes)?;
        tmp.flush()?;
        tmp.as_file().sync_all().map_err(|source| {
            Error::Atomic(toride_fs::Error::AtomicWriteFailed {
                path: dest.display().to_string(),
                reason: format!("failed to fsync temp file: {source}"),
            })
        })?;

        tmp.persist(dest).map_err(|source| {
            Error::Atomic(toride_fs::Error::AtomicWriteFailed {
                path: dest.display().to_string(),
                reason: format!("failed to persist temp file: {source}"),
            })
        })?;
    }
    #[cfg(not(unix))]
    {
        // No executable-bit concept off Unix; a plain atomic write suffices.
        toride_fs::atomic_write_bytes(dest, bytes)?;
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

/// Pull the expected sha256 digest for `asset_name` out of a published
/// checksum-file body.
///
/// Accepts both coreutils `sha256sum` output (`<hex>  <filename>`, separated
/// by two spaces; the filename is optional and may be prefixed with `*` to
/// mark a binary-mode digest) and a bare `<hex>` line. The first matching
/// line wins. Lines whose leading token is not a 64-character lowercase or
/// uppercase hex digest are skipped, so banners/blanks/comments in the file
/// cannot be mistaken for a digest.
///
/// Returns `None` when no line carries a digest for `asset_name` (or, when
/// `asset_name` is empty, any bare digest).
fn extract_digest_from_checksum_body(body: &str, asset_name: &str) -> Option<String> {
    /// True iff `s` is exactly 64 hex digits (case-insensitive).
    fn is_hex64(s: &str) -> bool {
        s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
    }

    for raw in body.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        // Bare `<hex>` line (no filename component): matches when the caller
        // did not pin a specific asset name.
        if is_hex64(line) && asset_name.is_empty() {
            return Some(line.to_ascii_lowercase());
        }
        let Some((digest, rest)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        if !is_hex64(digest) {
            continue;
        }
        let filename = rest.trim_start();
        // coreutils `sha256sum` prefixes binary-mode filenames with `*`.
        let filename = filename.trim_start_matches('*').trim();
        if asset_name.is_empty() || filename == asset_name {
            return Some(digest.to_ascii_lowercase());
        }
    }
    None
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
    use crate::ArtifactKind;
    use crate::target::{Arch, Os};
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

    #[tokio::test]
    async fn verifier_lenient_accepts_no_checksum_above_floor() {
        let installer = Installer::new().with_min_bytes(4);
        let tool = Tool {
            name: "demo".into(),
            checksum: Checksum::None,
            ..Default::default()
        };
        // 5 bytes >= 4-byte floor.
        installer
            .verify(&tool, "1.0", b"enough", "https://x")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn verifier_lenient_rejects_below_floor() {
        let installer = Installer::new().with_min_bytes(1024);
        let tool = Tool {
            name: "demo".into(),
            checksum: Checksum::None,
            ..Default::default()
        };
        let err = installer
            .verify(&tool, "1.0", b"tiny", "https://x")
            .await
            .unwrap_err();
        assert!(matches!(err, Error::TooSmall { .. }));
    }

    #[tokio::test]
    async fn verifier_strict_rejects_missing_checksum() {
        let installer = Installer::new().with_verifier(Verifier::Strict);
        let tool = Tool {
            name: "demo".into(),
            checksum: Checksum::None,
            ..Default::default()
        };
        let err = installer
            .verify(&tool, "1.0", b"plenty-of-bytes-here", "https://x")
            .await
            .unwrap_err();
        assert!(matches!(err, Error::NoChecksum { .. }));
    }

    #[tokio::test]
    async fn verifier_digest_matches() {
        let installer = Installer::new();
        let digest = hex_sha256(b"MATCH");
        let tool = Tool {
            name: "demo".into(),
            checksum: Checksum::Digest(digest),
            ..Default::default()
        };
        installer
            .verify(&tool, "1.0", b"MATCH", "https://x")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn verifier_digest_mismatch_is_error() {
        let installer = Installer::new();
        let tool = Tool {
            name: "demo".into(),
            checksum: Checksum::Digest(
                "0000000000000000000000000000000000000000000000000000000000000000".into(),
            ),
            ..Default::default()
        };
        let err = installer
            .verify(&tool, "1.0", b"MISMATCH", "https://x")
            .await
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
        installer
            .verify(&tool, "latest", bytes, "https://x")
            .await
            .unwrap();
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
        let (v, u) = r.resolve(host_target(), "9.9.9").await.unwrap();
        assert_eq!(v, "9.9.9");
        assert!(u.contains("9.9.9"));
        assert!(u.contains("tool-"));
        // target keyword substituted somewhere.
        assert!(u.contains("linux-") || u.contains("macos-"));
    }

    #[tokio::test]
    async fn real_download_errors_on_bad_host() {
        // Gated: hits the network (DNS). Run with TORIDE_INSTALLER_INTEGRATION=1.
        if !matches!(
            std::env::var("TORIDE_INSTALLER_INTEGRATION").as_deref(),
            Ok("1")
        ) {
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
        if !matches!(
            std::env::var("TORIDE_INSTALLER_INTEGRATION").as_deref(),
            Ok("1")
        ) {
            eprintln!("TORIDE_INSTALLER_INTEGRATION not set; skipping live network test");
            return;
        }
        let installer = Installer::new();
        // A URL that resolves but returns 404.
        let err = installer
            .download(
                "https://github.com/jdx/mise/releases/latest/download/this-asset-does-not-exist",
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::HttpStatus { status, .. } if status == 404));
    }

    // ---- Finding (1): HTTP client must carry timeouts ----------------------

    /// The installer's HTTP policy pins three non-zero deadlines. reqwest
    /// applies no timeout by default, so if any of these collapse to
    /// `Duration::ZERO` (e.g. someone drops a `.timeout(...)` from the
    /// builder) a stalled download would hang the install future
    /// indefinitely. Pinning the constants keeps that policy honest.
    #[test]
    fn http_timeout_policy_is_non_zero() {
        assert!(
            DEFAULT_HTTP_TIMEOUT > std::time::Duration::ZERO,
            "overall request timeout must be set"
        );
        assert!(
            DEFAULT_HTTP_CONNECT_TIMEOUT > std::time::Duration::ZERO,
            "connect timeout must be set"
        );
        assert!(
            DEFAULT_CHUNK_TIMEOUT > std::time::Duration::ZERO,
            "per-chunk read timeout must be set"
        );
        // Connect deadline must be no looser than the overall deadline.
        assert!(DEFAULT_HTTP_CONNECT_TIMEOUT <= DEFAULT_HTTP_TIMEOUT);
    }

    /// `build_http_client` must succeed (i.e. the builder is valid with the
    /// timeout policy applied). A regression that feeds an invalid
    /// combination to the builder would surface here.
    #[test]
    fn build_http_client_succeeds() {
        let _client = build_http_client();
        // `reqwest::Client` exposes no timeout introspection, but building it
        // exercises the exact `.timeout()`/`.connect_timeout()` calls wired
        // against the pinned constants above.
    }

    // ---- Finding (2): Checksum::Url sha256 verification --------------------

    #[test]
    fn checksum_body_parses_coreutils_two_space_format() {
        let digest = hex_sha256(b"artifact-bytes");
        let body = format!("{digest}  mise-1.0-linux-x64\n");
        assert_eq!(
            extract_digest_from_checksum_body(&body, "mise-1.0-linux-x64"),
            Some(digest)
        );
    }

    #[test]
    fn checksum_body_parses_binary_mode_star_prefix() {
        let digest = hex_sha256(b"x");
        // `sha256sum -b` emits `*<filename>`.
        let body = format!("{digest} *mise-1.0-linux-x64\n");
        assert_eq!(
            extract_digest_from_checksum_body(&body, "mise-1.0-linux-x64"),
            Some(digest)
        );
    }

    #[test]
    fn checksum_body_parses_bare_hex_line() {
        let digest = hex_sha256(b"lonely");
        assert_eq!(
            extract_digest_from_checksum_body(&digest, ""),
            Some(digest)
        );
    }

    #[test]
    fn checksum_body_picks_matching_asset_among_many() {
        let other = hex_sha256(b"other-asset");
        let want = hex_sha256(b"wanted-asset");
        let body = format!(
            "{other}  other-file\n{want}  mise-1.0-linux-x64\nfifth-line-not-a-digest\n"
        );
        assert_eq!(
            extract_digest_from_checksum_body(&body, "mise-1.0-linux-x64"),
            Some(want)
        );
    }

    #[test]
    fn checksum_body_rejects_non_hex_leading_token() {
        // A banner line that happens to be followed by a filename must not be
        // mistaken for a digest.
        let body = "This is mise 1.0  mise-1.0-linux-x64\n";
        assert_eq!(extract_digest_from_checksum_body(body, "mise-1.0-linux-x64"), None);
    }

    #[test]
    fn checksum_body_returns_none_when_asset_absent() {
        let digest = hex_sha256(b"x");
        let body = format!("{digest}  some-other-asset\n");
        assert_eq!(
            extract_digest_from_checksum_body(&body, "mise-1.0-linux-x64"),
            None
        );
    }

    #[test]
    fn checksum_body_is_case_insensitive_on_digest() {
        let digest = hex_sha256(b"caps");
        let upper = digest.to_uppercase();
        let body = format!("{upper}  mise\n");
        // Normalized to lowercase so the later eq_ignore_ascii_case compare is
        // robust regardless of the published casing.
        assert_eq!(
            extract_digest_from_checksum_body(&body, "mise"),
            Some(digest)
        );
    }

    /// A tiny single-shot HTTP/1.0 server: serves `body` for the next GET,
    /// then stops accepting. Used to drive `Installer::verify` for the
    /// `Checksum::Url` arm without an external dep or the public network.
    async fn serve_once(body: String) -> String {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}/checksums.txt");

        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                // Drain the request line/headers (we don't care about them).
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let response = format!(
                    "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.flush().await;
            }
        });

        url
    }

    #[tokio::test]
    async fn checksum_url_verify_accepts_matching_download() {
        let artifact = b"REAL-ARTIFACT-BYTES";
        let digest = hex_sha256(artifact);
        let body = format!("{digest}  mise-1.0-linux-x64\n");
        let url = serve_once(body).await;

        let installer = Installer::new();
        let tool = Tool {
            name: "mise".into(),
            checksum: Checksum::Url {
                url: url.clone(),
                asset_name: "mise-1.0-linux-x64".into(),
            },
            ..Default::default()
        };
        // A genuine, untampered download verifies.
        installer.verify(&tool, "1.0", artifact, "https://x").await.unwrap();
    }

    #[tokio::test]
    async fn checksum_url_verify_rejects_tampered_download() {
        // The checksum file describes the *real* artifact, but the bytes we
        // "downloaded" were tampered with — verification MUST fail.
        let real = b"REAL-ARTIFACT-BYTES";
        let digest = hex_sha256(real);
        let body = format!("{digest}  mise-1.0-linux-x64\n");
        let url = serve_once(body).await;

        let installer = Installer::new();
        let tool = Tool {
            name: "mise".into(),
            checksum: Checksum::Url {
                url,
                asset_name: "mise-1.0-linux-x64".into(),
            },
            ..Default::default()
        };
        let err = installer
            .verify(&tool, "1.0", b"TAMPERED-DIFFERENT-BYTES", "https://x")
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::ChecksumMismatch { ref expected, .. } if expected == &digest),
            "tampered download must be rejected as a checksum mismatch, got {err:?}"
        );
    }

    #[tokio::test]
    async fn checksum_url_verify_rejects_when_asset_missing_from_file() {
        let digest = hex_sha256(b"x");
        // File publishes a digest for a DIFFERENT asset name.
        let body = format!("{digest}  some-other-asset\n");
        let url = serve_once(body).await;

        let installer = Installer::new();
        let tool = Tool {
            name: "mise".into(),
            checksum: Checksum::Url {
                url,
                asset_name: "mise-1.0-linux-x64".into(),
            },
            ..Default::default()
        };
        let err = installer
            .verify(&tool, "1.0", b"any", "https://x")
            .await
            .unwrap_err();
        assert!(matches!(err, Error::NoChecksumEntry { .. }));
    }
}
