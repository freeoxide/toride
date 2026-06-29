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
    use super::*;

    /// GitHub API base URL for mise releases.
    const GITHUB_API: &str = "https://api.github.com/repos/jdx/mise/releases";

    /// Fetch the download URL and tag for the latest (or specific) mise release.
    async fn fetch_release_info(
        client: &reqwest::Client,
        version: Option<&str>,
    ) -> MiseResult<(String, String)> {
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

        let download_url = asset["browser_download_url"]
            .as_str()
            .ok_or_else(|| MiseError::BootstrapFailed {
                reason: "asset has no download URL".into(),
            })?
            .to_string();

        Ok((download_url, tag))
    }

    /// Download a tar.gz archive and extract the `mise` binary to `target_dir`.
    async fn download_and_extract(
        client: &reqwest::Client,
        url: &str,
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

        // Ensure the target directory exists.
        fs_err::create_dir_all(target_dir).map_err(|e| MiseError::BootstrapFailed {
            reason: format!("failed to create directory {}: {e}", target_dir),
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

        let (download_url, tag) = fetch_release_info(&client, opts.version.as_deref()).await?;

        let target_dir = match &opts.target_dir {
            Some(d) => d.clone(),
            None => dirs::home_dir()
                .map(|h| Utf8PathBuf::from_path_buf(h.join(".local/bin")).unwrap_or_default())
                .ok_or_else(|| MiseError::BootstrapFailed {
                    reason: "cannot determine home directory for default target".into(),
                })?,
        };

        let bin_path = download_and_extract(&client, &download_url, &target_dir).await?;

        let _ = tag; // available for logging if needed

        Ok(bin_path)
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
