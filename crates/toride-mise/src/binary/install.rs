//! Mise binary bootstrap / installation support.
//!
//! Provides types and helpers for ensuring the `mise` binary is available on
//! the host. The primary entry-point is [`MiseBinary::ensure_installed`].

use camino::Utf8PathBuf;

use super::discovery::MiseBinary;
use crate::error::{MiseError, MiseResult};

/// Options controlling how the `mise` binary should be installed.
#[derive(Debug, Clone, Default)]
pub struct BootstrapOptions {
    /// Directory where the binary should be placed.
    ///
    /// When `None`, the default discovery locations are used
    /// (e.g. `~/.local/bin`).
    pub target_dir: Option<Utf8PathBuf>,

    /// Specific version to install (e.g. `"2025.4.0"`).
    ///
    /// When `None`, the latest release is implied.
    pub version: Option<String>,
}

/// Strategy for obtaining the `mise` binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapMethod {
    /// Download a release tarball from GitHub.
    GithubRelease,
    /// Do not attempt installation; return a hint instead.
    HintOnly,
}

/// Return the asset name substring used to find the right GitHub release asset.
///
/// Maps the current OS/arch to the naming convention used by mise releases:
/// `mise-{os}-{arch}.tar.gz` (e.g. `mise-macos-arm64`, `mise-linux-x64`).
#[cfg_attr(not(feature = "bootstrap"), allow(dead_code))]
fn platform_asset_keyword() -> Option<String> {
    let os = if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        return None;
    };

    let arch = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else if cfg!(target_arch = "x86_64") {
        "x64"
    } else {
        return None;
    };

    Some(format!("{os}-{arch}"))
}

/// Attempt to install the `mise` binary using the given method.
///
/// # Errors
///
/// - [`MiseError::BootstrapHint`] when `method` is [`BootstrapMethod::HintOnly`].
/// - [`MiseError::BootstrapFailed`] when the chosen method cannot complete.
pub async fn install_mise(
    method: BootstrapMethod,
    opts: BootstrapOptions,
) -> MiseResult<Utf8PathBuf> {
    match method {
        BootstrapMethod::GithubRelease => install_from_github(&opts).await,
        BootstrapMethod::HintOnly => Err(MiseError::BootstrapHint {
            message: format!(
                "mise is not installed.\n\
                 \n\
                 Install it with one of:\n\
                 \n\
                   curl -fsSL https://mise.run | sh\n\
                   brew install mise\n\
                   cargo install mise\n\
                 \n\
                 Or visit https://mise.jdx.dev/getting-started.html for more options.{}",
                opts.version
                    .as_deref()
                    .map(|v| format!("\n\nRequested version: {v}"))
                    .unwrap_or_default()
            ),
        }),
    }
}

#[cfg(feature = "bootstrap")]
mod github {
    use super::{BootstrapOptions, platform_asset_keyword};
    use crate::error::{MiseError, MiseResult};
    use camino::Utf8PathBuf;

    /// GitHub API base URL for mise releases.
    const GITHUB_API: &str = "https://api.github.com/repos/jdx/mise/releases";

    /// File-name substrings that identify a published sha256 checksum file
    /// inside a mise GitHub release (checked case-insensitively).
    ///
    /// mise publishes `SHASUMS256.txt`; the broader alternatives keep this
    /// working across minor upstream naming changes.
    const CHECKSUM_FILE_KEYWORDS: [&str; 3] = ["shasums256", "sha256sums", "checksums"];

    /// Cap on any single bootstrap download (release JSON, checksum file, or
    /// tarball), shared with the installer engine's download bound.
    const MAX_DOWNLOAD_BYTES: u64 = toride_installer::installer::DEFAULT_MAX_BYTES;

    /// Build the bootstrap HTTP client with the installer engine's policy:
    /// a `User-Agent` (api.github.com rejects UA-less clients with 403),
    /// bounded redirects, and the engine's overall and connect timeouts.
    fn build_bootstrap_client() -> MiseResult<reqwest::Client> {
        reqwest::Client::builder()
            .user_agent(concat!("toride-mise/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::limited(10))
            .timeout(toride_installer::installer::DEFAULT_HTTP_TIMEOUT)
            .connect_timeout(toride_installer::installer::DEFAULT_HTTP_CONNECT_TIMEOUT)
            .build()
            .map_err(|e| MiseError::BootstrapFailed {
                reason: format!("failed to build HTTP client: {e}"),
            })
    }

    /// Read a response body, refusing anything larger than
    /// [`MAX_DOWNLOAD_BYTES`].
    async fn read_body_capped(resp: reqwest::Response, what: &str) -> MiseResult<Vec<u8>> {
        let mut resp = resp;
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| MiseError::BootstrapFailed {
            reason: format!("failed to read {what} body: {e}"),
        })? {
            let cap = usize::try_from(MAX_DOWNLOAD_BYTES).unwrap_or(usize::MAX);
            if body.len() + chunk.len() > cap {
                return Err(MiseError::BootstrapFailed {
                    reason: format!("{what} exceeded the {cap} byte download cap"),
                });
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    /// Fetch the download URL, asset name, checksum-file URL, and tag for the
    /// latest (or specific) mise release.
    ///
    /// The checksum-file URL is `None` only when the release carries no
    /// recognizable checksum asset; in that case [`download_and_extract`] will
    /// refuse the download (fail closed) rather than proceed unverified.
    async fn fetch_release_info(
        client: &reqwest::Client,
        version: Option<&str>,
    ) -> MiseResult<(String, String, Option<String>, String)> {
        let url = match version {
            Some(v) => format!("{GITHUB_API}/tags/v{v}"),
            None => format!("{GITHUB_API}/latest"),
        };

        let resp = client
            .get(&url)
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
            .map_err(|e| MiseError::BootstrapFailed {
                reason: format!("failed to contact GitHub API: {e}"),
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = read_body_capped(resp, "GitHub API response").await?;
            return Err(MiseError::BootstrapFailed {
                reason: format!(
                    "GitHub API returned {status}: {}",
                    String::from_utf8_lossy(&body)
                ),
            });
        }

        let body = read_body_capped(resp, "GitHub API response").await?;
        let release: serde_json::Value =
            serde_json::from_slice(&body).map_err(|e| MiseError::BootstrapFailed {
                reason: format!("failed to parse GitHub release JSON: {e}"),
            })?;

        let tag = release["tag_name"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();

        let keyword = platform_asset_keyword().ok_or_else(|| MiseError::BootstrapFailed {
            reason: "unsupported platform for GitHub release download".into(),
        })?;

        let assets = release["assets"]
            .as_array()
            .ok_or_else(|| MiseError::BootstrapFailed {
                reason: "no assets found in GitHub release".into(),
            })?;

        let asset = assets
            .iter()
            .find(|a| {
                a["name"]
                    .as_str()
                    .is_some_and(|n| n.contains(&keyword) && n.ends_with(".tar.gz"))
            })
            .ok_or_else(|| MiseError::BootstrapFailed {
                reason: format!(
                    "no suitable asset found for platform '{keyword}' in release {tag}"
                ),
            })?;

        let asset_name = asset["name"]
            .as_str()
            .ok_or_else(|| MiseError::BootstrapFailed {
                reason: "asset has no name".into(),
            })?
            .to_string();

        let download_url = asset["browser_download_url"]
            .as_str()
            .ok_or_else(|| MiseError::BootstrapFailed {
                reason: "asset has no download URL".into(),
            })?
            .to_string();

        // mise publishes a single `SHASUMS256.txt` covering every asset.
        let checksum_url = assets.iter().find_map(|a| {
            let name = a["name"].as_str()?;
            let lower = name.to_ascii_lowercase();
            let has_checksum_extension = lower == "checksums"
                || lower.ends_with(".sha256")
                || std::path::Path::new(&lower)
                    .extension()
                    .is_some_and(|ext| ext == "txt");
            let is_checksum = has_checksum_extension
                && CHECKSUM_FILE_KEYWORDS.iter().any(|kw| lower.contains(kw));
            if is_checksum {
                a["browser_download_url"].as_str().map(str::to_owned)
            } else {
                None
            }
        });

        Ok((download_url, asset_name, checksum_url, tag))
    }

    /// Hex-encode the sha256 of `bytes`.
    ///
    /// Kept allocation-light and dependency-free (no extra `hex` crate) by
    /// formatting each byte manually.
    fn hex_sha256(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let digest = hasher.finalize();
        let mut out = String::with_capacity(digest.len() * 2);
        for b in digest {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02x}");
        }
        out
    }

    /// Pull the expected sha256 digest for the asset named `asset_name`.
    ///
    /// `checksum_url` is the published checksum file (e.g. `SHASUMS256.txt`).
    /// When the URL is missing the release publishes no checksum and we fail
    /// closed rather than proceed with an unverified download.
    async fn resolve_expected_digest(
        client: &reqwest::Client,
        checksum_url: Option<&str>,
        asset_name: &str,
    ) -> MiseResult<String> {
        let Some(url) = checksum_url else {
            return Err(MiseError::BootstrapFailed {
                reason: format!(
                    "release does not publish a checksum file; refusing to \
                     install unverified mise tarball (asset `{asset_name}`)"
                ),
            });
        };

        let resp = client
            .get(url)
            .send()
            .await
            .map_err(|e| MiseError::BootstrapFailed {
                reason: format!("failed to download checksum file: {e}"),
            })?;

        if !resp.status().is_success() {
            return Err(MiseError::BootstrapFailed {
                reason: format!(
                    "checksum file download failed with status {}",
                    resp.status()
                ),
            });
        }

        let body = read_body_capped(resp, "checksum file").await?;
        let body = String::from_utf8_lossy(&body);

        toride_installer::extract_digest_from_checksum_body(&body, asset_name).ok_or_else(|| {
            MiseError::BootstrapFailed {
                reason: format!(
                    "checksum file did not contain a sha256 entry for asset `{asset_name}`"
                ),
            }
        })
    }

    /// Verify `bytes` against the expected sha256 `digest`, failing closed on
    /// any mismatch. The comparison is case-insensitive to tolerate either
    /// case in the published file.
    fn verify_sha256(bytes: &[u8], digest: &str) -> MiseResult<()> {
        let actual = hex_sha256(bytes);
        if actual.eq_ignore_ascii_case(digest) {
            Ok(())
        } else {
            Err(MiseError::ChecksumMismatch {
                expected: digest.to_ascii_lowercase(),
                actual,
            })
        }
    }

    /// Download a tar.gz archive and extract the `mise` binary to `target_dir`.
    ///
    /// `expected_digest` is the published sha256 of the tarball; the download
    /// is verified against it before any extraction happens. A missing or
    /// mismatching digest fails closed: the binary is never unpacked.
    async fn download_and_extract(
        client: &reqwest::Client,
        url: &str,
        expected_digest: &str,
        target_dir: &camino::Utf8Path,
    ) -> MiseResult<Utf8PathBuf> {
        let resp = client
            .get(url)
            .send()
            .await
            .map_err(|e| MiseError::BootstrapFailed {
                reason: format!("failed to download archive: {e}"),
            })?;

        if !resp.status().is_success() {
            return Err(MiseError::BootstrapFailed {
                reason: format!("download failed with status {}", resp.status()),
            });
        }

        let bytes = read_body_capped(resp, "archive").await?;

        // Verify the tarball BEFORE touching disk so a tampered or truncated
        // download can never reach the extraction path.
        verify_sha256(&bytes, expected_digest)?;

        fs_err::create_dir_all(target_dir).map_err(|e| MiseError::BootstrapFailed {
            reason: format!("failed to create directory {target_dir}: {e}"),
        })?;

        let decoder = flate2::read::GzDecoder::new(bytes.as_slice());
        let mut archive = tar::Archive::new(decoder);

        let mut found_path: Option<Utf8PathBuf> = None;
        for entry in archive.entries().map_err(|e| MiseError::BootstrapFailed {
            reason: format!("failed to enumerate tar entries: {e}"),
        })? {
            let mut entry = entry.map_err(|e| MiseError::BootstrapFailed {
                reason: format!("failed to read tar entry: {e}"),
            })?;

            let path = entry.path().map_err(|e| MiseError::BootstrapFailed {
                reason: format!("failed to read entry path: {e}"),
            })?;

            let file_name = path.file_name().unwrap_or_default().to_string_lossy();

            if file_name == toride_installer::tools::mise::MISE_BIN_NAME {
                let dest = target_dir.join(toride_installer::tools::mise::MISE_BIN_NAME);
                entry
                    .unpack(&dest)
                    .map_err(|e| MiseError::BootstrapFailed {
                        reason: format!("failed to extract mise binary: {e}"),
                    })?;
                found_path = Some(dest);
                break;
            }
        }

        let bin_path = found_path.ok_or_else(|| MiseError::BootstrapFailed {
            reason: format!(
                "archive did not contain a '{}' binary",
                toride_installer::tools::mise::MISE_BIN_NAME
            ),
        })?;

        // Set executable permissions on unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o755);
            fs_err::set_permissions(&bin_path, perms).map_err(|e| MiseError::BootstrapFailed {
                reason: format!("failed to set executable permissions: {e}"),
            })?;
        }

        Ok(bin_path)
    }

    /// Full GitHub release bootstrap pipeline.
    pub async fn install_from_github(opts: &BootstrapOptions) -> MiseResult<Utf8PathBuf> {
        let client = build_bootstrap_client()?;

        let (download_url, asset_name, checksum_url, tag) =
            fetch_release_info(&client, opts.version.as_deref()).await?;

        // Resolve the published digest BEFORE downloading the tarball so an
        // unchecksummed release is refused cheaply.
        let expected_digest =
            resolve_expected_digest(&client, checksum_url.as_deref(), &asset_name).await?;

        let target_dir = match &opts.target_dir {
            Some(d) => d.clone(),
            None => dirs::home_dir()
                .map(|h| Utf8PathBuf::from_path_buf(h.join(".local/bin")).unwrap_or_default())
                .ok_or_else(|| MiseError::BootstrapFailed {
                    reason: "cannot determine home directory for default target".into(),
                })?,
        };

        let bin_path =
            download_and_extract(&client, &download_url, &expected_digest, &target_dir).await?;

        let _ = tag;

        Ok(bin_path)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn hex_sha256_matches_known_vector() {
            assert_eq!(
                hex_sha256(b""),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            );
            assert_eq!(
                hex_sha256(b"abc"),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            );
        }

        #[test]
        fn digest_parser_handles_live_shasums256_shape() {
            // mise's published SHASUMS256.txt lists `./`-prefixed names
            // (verified live against v2026.9.15); the parser must strip the
            // prefix and still match the asset.
            let body = "1111111111111111111111111111111111111111111111111111111111111111  ./mise-linux-x64.tar.gz\n\
                        2222222222222222222222222222222222222222222222222222222222222222  ./mise-macos-arm64.tar.gz\n";
            assert_eq!(
                toride_installer::extract_digest_from_checksum_body(body, "mise-linux-x64.tar.gz")
                    .as_deref(),
                Some("1111111111111111111111111111111111111111111111111111111111111111")
            );
        }

        #[test]
        fn digest_parser_accepts_bare_hex_when_asset_unpinned() {
            let body = "cafef00d00000000000000000000000000000000000000000000000000000001";
            assert_eq!(
                toride_installer::extract_digest_from_checksum_body(body, "").as_deref(),
                Some("cafef00d00000000000000000000000000000000000000000000000000000001")
            );
        }

        #[test]
        fn bootstrap_client_builds() {
            build_bootstrap_client().expect("policy client must build");
        }

        #[test]
        fn verify_sha256_passes_on_match_case_insensitive() {
            let bytes = b"hello world";
            let digest = hex_sha256(bytes);
            assert!(verify_sha256(bytes, &digest).is_ok());
            assert!(verify_sha256(bytes, &digest.to_uppercase()).is_ok());
        }

        #[test]
        fn verify_sha256_fails_closed_on_mismatch() {
            let bytes = b"hello world";
            let wrong = "0000000000000000000000000000000000000000000000000000000000000000";
            let err = verify_sha256(bytes, wrong).unwrap_err();
            let MiseError::ChecksumMismatch { expected, actual } = err else {
                panic!("expected ChecksumMismatch, got {err:?}");
            };
            assert_eq!(expected, wrong);
            assert_ne!(actual, wrong);
        }
    }
}

#[cfg(feature = "bootstrap")]
use github::install_from_github;

#[cfg(not(feature = "bootstrap"))]
#[expect(
    clippy::unused_async,
    reason = "kept async to match the bootstrap-enabled variant's signature at shared `.await` call sites"
)]
async fn install_from_github(_opts: &BootstrapOptions) -> MiseResult<Utf8PathBuf> {
    Err(MiseError::BootstrapFailed {
        reason: "GitHub release download requires the 'bootstrap' feature. \
                 Enable it in Cargo.toml or use --features bootstrap."
            .into(),
    })
}

impl MiseBinary {
    /// Ensure that the `mise` binary is available on the host.
    ///
    /// This first attempts normal discovery via
    /// [`MiseBinary::discover_async`]: the same offline cascade as
    /// [`MiseBinary::discover`], run on tokio's blocking pool because the
    /// detector's `mise --version` / `-V` probes are sync subprocess work
    /// and must not occupy an async runtime worker. If the binary is found,
    /// it is returned immediately.  Otherwise a
    /// [`MiseError::BootstrapHint`] error is returned with installation
    /// instructions.
    ///
    /// Discovery is offline and never installs: it consults `MISE_BIN`, then
    /// `toride_installer`'s `Detector` over the real `$PATH` and the managed
    /// install location (`~/.local/bin`: where the installer's checksum-
    /// verified install path writes), then the system-wide and app-bundled
    /// fallbacks. A true miss is reported as the hint below rather than
    /// triggering a download, so the meaning of the user-facing outcome is
    /// unchanged: only the probe behind it is shared with the installer.
    ///
    /// For automated bootstrapping, match on [`MiseError::BootstrapHint`]
    /// and call [`install_mise`] with the desired [`BootstrapMethod`].
    pub async fn ensure_installed() -> MiseResult<Self> {
        match Self::discover_async().await {
            Ok(bin) => Ok(bin),
            Err(MiseError::BinaryNotFound) => Err(MiseError::BootstrapHint {
                message: String::from(
                    "mise is not installed.\n\
                     \n\
                     Install it with one of:\n\
                     \n\
                       curl -fsSL https://mise.run | sh\n\
                       brew install mise\n\
                       cargo install mise\n\
                     \n\
                     Or visit https://mise.jdx.dev/getting-started.html for more options.",
                ),
            }),
            Err(other) => Err(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_options_default_has_none_fields() {
        let opts = BootstrapOptions::default();
        assert!(opts.target_dir.is_none());
        assert!(opts.version.is_none());
    }

    /// Environmental (agrees with the host either way): `ensure_installed`
    /// passes the discovered binary through unchanged, and reports the
    /// bootstrap hint exactly when the offline cascade misses.
    #[tokio::test]
    async fn ensure_installed_matches_discovery() {
        match MiseBinary::discover() {
            Ok(expected) => match MiseBinary::ensure_installed().await {
                Ok(found) => assert_eq!(found, expected),
                other => panic!("expected {expected:?}, got {other:?}"),
            },
            Err(MiseError::BinaryNotFound) => {
                let Err(MiseError::BootstrapHint { .. }) = MiseBinary::ensure_installed().await
                else {
                    panic!("expected BootstrapHint when discovery misses");
                };
            }
            Err(other) => panic!("unexpected discovery error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn install_mise_hint_only_returns_hint_error() {
        let result = install_mise(BootstrapMethod::HintOnly, BootstrapOptions::default()).await;
        let Err(MiseError::BootstrapHint { .. }) = result else {
            panic!("expected BootstrapHint error, got {result:?}");
        };
    }

    #[tokio::test]
    async fn install_mise_hint_includes_requested_version() {
        let opts = BootstrapOptions {
            version: Some("2025.4.0".into()),
            ..Default::default()
        };
        let result = install_mise(BootstrapMethod::HintOnly, opts).await;
        let Err(MiseError::BootstrapHint { message }) = result else {
            panic!("expected BootstrapHint error");
        };
        assert!(message.contains("2025.4.0"));
    }

    #[test]
    fn platform_asset_keyword_returns_some_on_supported() {
        // Verifies the function returns Some on the current
        // platform if it is one of the supported ones.
        let kw = platform_asset_keyword();
        // On CI or dev machines this is usually macos-arm64 or linux-x64.
        if cfg!(target_os = "macos") || cfg!(target_os = "linux") {
            assert!(kw.is_some());
            let kw = kw.unwrap();
            if cfg!(target_arch = "aarch64") {
                assert!(kw.contains("arm64"));
            } else if cfg!(target_arch = "x86_64") {
                assert!(kw.contains("x64"));
            }
        }
    }
}
