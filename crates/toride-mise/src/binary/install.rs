//! Mise binary bootstrap / installation support.
//!
//! Provides types and helpers for ensuring the `mise` binary is available on
//! the host. The primary entry-point is [`MiseBinary::ensure_installed`].

use camino::Utf8PathBuf;

use super::discovery::MiseBinary;
use crate::error::{MiseError, MiseResult};

// ---------------------------------------------------------------------------
// BootstrapOptions
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// BootstrapMethod
// ---------------------------------------------------------------------------

/// Strategy for obtaining the `mise` binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapMethod {
    /// Download a release tarball from GitHub.
    GithubRelease,
    /// Do not attempt installation; return a hint instead.
    HintOnly,
}

// ---------------------------------------------------------------------------
// Platform detection
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// install_mise
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// GitHub release implementation
// ---------------------------------------------------------------------------

#[cfg(feature = "bootstrap")]
mod github {
    use super::{platform_asset_keyword, BootstrapOptions};
    use crate::error::{MiseError, MiseResult};
    use camino::Utf8PathBuf;

    /// GitHub API base URL for mise releases.
    const GITHUB_API: &str = "https://api.github.com/repos/jdx/mise/releases";

    /// File-name substrings that identify a published sha256 checksum file
    /// inside a mise GitHub release (checked case-insensitively).
    ///
    /// mise publishes `SHASUMS256.txt`; the broader alternatives keep this
    /// robust against minor upstream naming changes.
    const CHECKSUM_FILE_KEYWORDS: [&str; 3] =
        ["shasums256", "sha256sums", "checksums"];

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
            let body = resp.text().await.unwrap_or_default();
            return Err(MiseError::BootstrapFailed {
                reason: format!("GitHub API returned {status}: {body}"),
            });
        }

        let release: serde_json::Value =
            resp.json().await.map_err(|e| MiseError::BootstrapFailed {
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

        // Locate the published checksum file. mise publishes a single
        // `SHASUMS256.txt` covering every release asset.
        let checksum_url = assets.iter().find_map(|a| {
            let name = a["name"].as_str()?;
            let lower = name.to_ascii_lowercase();
            // The keyword check (already lower-cased) confirms this is a
            // checksum manifest; the extension/name gate avoids matching an
            // unrelated file that merely contains the word "sha256".
            let has_checksum_extension = lower == "checksums"
                || lower.ends_with(".sha256")
                || std::path::Path::new(&lower)
                    .extension()
                    .is_some_and(|ext| ext == "txt");
            let is_checksum =
                has_checksum_extension && CHECKSUM_FILE_KEYWORDS.iter().any(|kw| lower.contains(kw));
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

    /// Pull the expected sha256 digest for `asset_name` out of a published
    /// checksum-file body.
    ///
    /// Accepts both coreutils `sha256sum` output (`<hex>  <filename>`,
    /// separated by whitespace; the filename is optional and may be prefixed
    /// with `*` to mark a binary-mode digest) and a bare `<hex>` line. The
    /// first line whose digest matches and whose filename matches
    /// `asset_name` (when given) wins.
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
            // Bare `<hex>` line with no filename — only accept when the caller
            // has not pinned a specific asset name.
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

    /// Resolve the expected sha256 digest for the asset named `asset_name`.
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

        let resp = client.get(url).send().await.map_err(|e| {
            MiseError::BootstrapFailed {
                reason: format!("failed to download checksum file: {e}"),
            }
        })?;

        if !resp.status().is_success() {
            return Err(MiseError::BootstrapFailed {
                reason: format!(
                    "checksum file download failed with status {}",
                    resp.status()
                ),
            });
        }

        let body = resp.text().await.map_err(|e| MiseError::BootstrapFailed {
            reason: format!("failed to read checksum file body: {e}"),
        })?;

        extract_digest_from_checksum_body(&body, asset_name).ok_or_else(|| MiseError::BootstrapFailed {
            reason: format!(
                "checksum file did not contain a sha256 entry for asset `{asset_name}`"
            ),
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
    /// mismatching digest fails closed — the binary is never unpacked.
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

        let bytes = resp.bytes().await.map_err(|e| MiseError::BootstrapFailed {
            reason: format!("failed to read download body: {e}"),
        })?;

        // Integrity gate: verify the tarball BEFORE touching disk so a tampered
        // or truncated download can never reach the extraction path.
        verify_sha256(&bytes, expected_digest)?;

        // Ensure the target directory exists.
        fs_err::create_dir_all(target_dir).map_err(|e| MiseError::BootstrapFailed {
            reason: format!("failed to create directory {target_dir}: {e}"),
        })?;

        // Extract the `mise` binary from the tar.gz archive.
        let decoder = flate2::read::GzDecoder::new(bytes.as_ref());
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

            if file_name == "mise" {
                let dest = target_dir.join("mise");
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
            reason: "archive did not contain a 'mise' binary".into(),
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
        let client = reqwest::Client::new();

        let (download_url, asset_name, checksum_url, tag) =
            fetch_release_info(&client, opts.version.as_deref()).await?;

        // Resolve the published digest BEFORE downloading the (potentially
        // large) tarball so an unchecksummed release is refused cheaply.
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

        let _ = tag; // available for logging if needed

        Ok(bin_path)
    }

    // -----------------------------------------------------------------------
    // Tests (integrity verification — pure, no network)
    // -----------------------------------------------------------------------

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn hex_sha256_matches_known_vector() {
            // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
            assert_eq!(
                hex_sha256(b""),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            );
            // sha256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
            assert_eq!(
                hex_sha256(b"abc"),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            );
        }

        #[test]
        fn extract_digest_parses_coreutils_format() {
            let body = "\
                1111111111111111111111111111111111111111111111111111111111111111  mise-linux-x64.tar.gz\n\
                2222222222222222222222222222222222222222222222222222222222222222  mise-macos-arm64.tar.gz\n";
            let digest = extract_digest_from_checksum_body(body, "mise-linux-x64.tar.gz");
            assert_eq!(
                digest.as_deref(),
                Some(
                    "1111111111111111111111111111111111111111111111111111111111111111"
                )
            );
        }

        #[test]
        fn extract_digest_handles_binary_star_prefix() {
            let body = "deadbeef00000000000000000000000000000000000000000000000000000001 *mise-linux-x64.tar.gz";
            let digest = extract_digest_from_checksum_body(body, "mise-linux-x64.tar.gz");
            assert_eq!(
                digest.as_deref(),
                Some("deadbeef00000000000000000000000000000000000000000000000000000001")
            );
        }

        #[test]
        fn extract_digest_skips_non_hex_and_returns_none_when_absent() {
            let body = "\
                # mise release checksums\n\
                not-a-digest  mise-linux-x64.tar.gz\n\
                1234567890abcdef  mise-macos-arm64.tar.gz\n";
            assert_eq!(
                extract_digest_from_checksum_body(body, "mise-linux-x64.tar.gz"),
                None
            );
        }

        #[test]
        fn extract_digest_accepts_bare_hex_when_asset_unpinned() {
            let body = "cafef00d00000000000000000000000000000000000000000000000000000001";
            assert_eq!(
                extract_digest_from_checksum_body(body, "").as_deref(),
                Some("cafef00d00000000000000000000000000000000000000000000000000000001")
            );
        }

        #[test]
        fn verify_sha256_passes_on_match_case_insensitive() {
            let bytes = b"hello world";
            let digest = hex_sha256(bytes); // lowercase
            assert!(verify_sha256(bytes, &digest).is_ok());
            // Uppercase variant must also be accepted.
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

// ---------------------------------------------------------------------------
// MiseBinary::ensure_installed (impl block)
// ---------------------------------------------------------------------------

impl MiseBinary {
    /// Ensure that the `mise` binary is available on the host.
    ///
    /// This first attempts normal discovery via [`MiseBinary::discover`].
    /// If the binary is found, it is returned immediately.  Otherwise a
    /// [`MiseError::BootstrapHint`] error is returned with installation
    /// instructions.
    ///
    /// For automated bootstrapping, match on [`MiseError::BootstrapHint`]
    /// and call [`install_mise`] with the desired [`BootstrapMethod`].
    #[allow(clippy::unused_async)]
    pub async fn ensure_installed() -> MiseResult<Self> {
        match Self::discover() {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_options_default_has_none_fields() {
        let opts = BootstrapOptions::default();
        assert!(opts.target_dir.is_none());
        assert!(opts.version.is_none());
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
        // This test simply verifies the function returns Some on the current
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
