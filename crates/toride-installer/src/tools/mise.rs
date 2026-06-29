//! Mise — the wired concrete tool.
//!
//! Resolves the single static `mise` binary from
//! <https://github.com/jdx/mise/releases>. mise publishes a raw
//! executable asset named `mise-v<VERSION>-<os>-<arch>` (no extension,
//! no tarball) for each release, plus glibc/musl tarballs; we use the raw
//! binary so the framework's `Binary` artifact path is exercised end-to-end.
//!
//! mise publishes **no sha256 checksum** for its release artifacts, so the
//! tool is configured with [`Checksum::None`](crate::tool::Checksum::None)
//! and relies on the engine's documented size-floor sanity check. (A future
//! mise release adding a checksum would only require swapping the variant.)
//!
//! # Quick start
//!
//! ```rust,ignore
//! use toride_installer::tools::mise;
//!
//! # async fn run() -> toride_installer::Result<()> {
//! let dest = mise::install_mise("latest", None).await?;
//! println!("installed mise to {dest}");
//! # Ok(())
//! # }
//! ```

use async_trait::async_trait;
use camino::Utf8PathBuf;

use crate::error::{Error, Result};
use crate::installer::Installer;
use crate::target::Target;
use crate::tool::{ArtifactKind, Checksum, ReleaseResolver, Tool};

/// The GitHub owner/repo slug for mise.
pub const MISE_REPO: &str = "jdx/mise";

/// The GitHub releases API base for mise.
const MISE_API: &str = "https://api.github.com/repos/jdx/mise/releases";

/// The on-disk binary name installed by mise.
pub const MISE_BIN_NAME: &str = "mise";

/// User-Agent string sent to GitHub (api.github.com requires one).
const USER_AGENT: &str = concat!("toride-installer/", env!("CARGO_PKG_VERSION"));

/// Build the [`Tool`] descriptor for mise.
///
/// mise is a `Binary` artifact with no published checksum; the default
/// install dir is `~/.local/bin` (handled by the engine when
/// `default_install_dir` is `None`).
#[must_use]
pub fn mise_tool() -> Tool {
    Tool {
        name: "mise".into(),
        artifact: ArtifactKind::Binary,
        bin_path: None,
        bin_name: MISE_BIN_NAME.into(),
        checksum: Checksum::None,
        default_install_dir: None,
    }
}

/// Mise's release resolver.
///
/// For a pinned version (e.g. `"2026.6.14"`) the asset URL is constructed
/// directly from the version — no API call is needed. For `"latest"` the
/// GitHub `releases/latest` endpoint is queried to learn the newest tag,
/// then the versioned asset URL is built from it.
///
/// (`releases/latest/download/mise-linux-x64` returns 404 because mise's
/// asset filenames embed the version, e.g. `mise-v2026.6.14-linux-x64`.)
#[derive(Debug, Clone, Default)]
pub struct MiseResolver {
    /// Optional injected HTTP client (e.g. for a shared connection pool or
    /// a mock in tests). When `None`, a fresh client is built per lookup.
    pub client: Option<reqwest::Client>,
}

impl MiseResolver {
    /// Create a new resolver with a default HTTP client.
    #[must_use]
    pub fn new() -> Self {
        Self { client: None }
    }

    /// The asset filename for a given (version, target), e.g.
    /// `mise-v2026.6.14-linux-x64`.
    fn asset_name(version: &str, target: Target) -> String {
        // The asset filename always prefixes `v`; strip any caller-supplied
        // one first so we don't double it up.
        let trimmed = version.strip_prefix('v').unwrap_or(version);
        format!("mise-v{trimmed}-{}", target.keyword())
    }

    fn client(&self) -> reqwest::Client {
        self.client.clone().unwrap_or_default()
    }

    /// Query GitHub for the latest mise release version (without the
    /// leading `v`).
    async fn fetch_latest_version(&self) -> Result<String> {
        let url = format!("{MISE_API}/latest");
        let client = self.client();
        let resp = client
            .get(&url)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", USER_AGENT)
            .send()
            .await
            .map_err(|source| Error::Download {
                url: url.clone(),
                source,
            })?;

        if !resp.status().is_success() {
            return Err(Error::HttpStatus {
                url,
                status: resp.status().as_u16(),
            });
        }

        let body: LatestRelease = resp
            .json()
            .await
            .map_err(|source| Error::Download { url, source })?;

        // Tags look like `v2026.6.14`; the version proper is without the `v`.
        Ok(body
            .tag_name
            .strip_prefix('v')
            .unwrap_or(&body.tag_name)
            .to_owned())
    }
}

impl MiseResolver {
    /// Build the versioned download URL for (concrete version, target).
    fn download_url(version: &str, target: Target) -> String {
        let asset = Self::asset_name(version, target);
        format!("https://github.com/{MISE_REPO}/releases/download/v{version}/{asset}")
    }
}

#[async_trait]
impl ReleaseResolver for MiseResolver {
    async fn resolve(&self, target: Target, version: &str) -> Result<(String, String)> {
        let concrete = if version == "latest" {
            self.fetch_latest_version().await?
        } else {
            version.strip_prefix('v').unwrap_or(version).to_owned()
        };
        Ok((concrete.clone(), Self::download_url(&concrete, target)))
    }
}

/// The subset of a GitHub release we need from `releases/latest`.
#[derive(Debug, serde::Deserialize)]
struct LatestRelease {
    /// The git tag, e.g. `v2026.6.14`.
    tag_name: String,
}

/// Convenience: install the latest (or a pinned) mise to `~/.local/bin/mise`
/// (or `install_dir` when provided).
///
/// # Errors
///
/// See [`Error`]. Most commonly [`Error::Download`] on network failure or
/// [`Error::HttpStatus`] if GitHub rate-limits the latest-version lookup.
pub async fn install_mise(version: &str, install_dir: Option<&Utf8PathBuf>) -> Result<Utf8PathBuf> {
    let tool = mise_tool();
    let resolver = MiseResolver::new();
    let target = Target::host()?;
    Installer::new()
        .install_with_resolver(&tool, target, version, install_dir, &resolver)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::{Arch, Os};

    #[test]
    fn asset_name_format_linux_x64() {
        let t = Target {
            os: Os::Linux,
            arch: Arch::X64,
        };
        assert_eq!(
            MiseResolver::asset_name("2026.6.14", t),
            "mise-v2026.6.14-linux-x64"
        );
    }

    #[test]
    fn asset_name_format_macos_arm64() {
        let t = Target {
            os: Os::Macos,
            arch: Arch::Arm64,
        };
        assert_eq!(
            MiseResolver::asset_name("2026.6.14", t),
            "mise-v2026.6.14-macos-arm64"
        );
    }

    #[test]
    fn asset_name_format_linux_arm64() {
        let t = Target {
            os: Os::Linux,
            arch: Arch::Arm64,
        };
        assert_eq!(
            MiseResolver::asset_name("2026.6.14", t),
            "mise-v2026.6.14-linux-arm64"
        );
    }

    #[test]
    fn asset_name_format_macos_x64() {
        let t = Target {
            os: Os::Macos,
            arch: Arch::X64,
        };
        assert_eq!(
            MiseResolver::asset_name("2026.6.14", t),
            "mise-v2026.6.14-macos-x64"
        );
    }

    #[test]
    fn asset_name_strips_leading_v_from_version() {
        let t = Target {
            os: Os::Macos,
            arch: Arch::Arm64,
        };
        assert_eq!(
            MiseResolver::asset_name("v2026.6.14", t),
            "mise-v2026.6.14-macos-arm64"
        );
    }

    #[test]
    fn download_url_format() {
        let t = Target {
            os: Os::Linux,
            arch: Arch::X64,
        };
        let url = MiseResolver::download_url("2026.6.14", t);
        assert_eq!(
            url,
            "https://github.com/jdx/mise/releases/download/v2026.6.14/mise-v2026.6.14-linux-x64"
        );
    }

    #[test]
    fn mise_tool_descriptor() {
        let tool = mise_tool();
        assert_eq!(tool.name, "mise");
        assert_eq!(tool.bin_name, "mise");
        assert_eq!(tool.artifact, ArtifactKind::Binary);
        assert_eq!(tool.checksum, Checksum::None);
        assert!(tool.bin_path.is_none());
        assert!(tool.default_install_dir.is_none());
        tool.validate().unwrap();
    }

    #[tokio::test]
    async fn pinned_version_resolves_to_direct_url_no_network() {
        // Pinned versions are resolved offline — no HTTP call is made.
        let r = MiseResolver::new();
        let t = Target {
            os: Os::Linux,
            arch: Arch::X64,
        };
        let (v, u) = r.resolve(t, "2026.6.14").await.unwrap();
        assert_eq!(v, "2026.6.14");
        assert_eq!(
            u,
            "https://github.com/jdx/mise/releases/download/v2026.6.14/mise-v2026.6.14-linux-x64"
        );
    }

    #[tokio::test]
    async fn pinned_version_normalizes_leading_v_no_network() {
        let r = MiseResolver::new();
        let t = Target {
            os: Os::Macos,
            arch: Arch::Arm64,
        };
        let (v, u) = r.resolve(t, "v2026.6.14").await.unwrap();
        assert_eq!(v, "2026.6.14"); // concrete version without the v
        assert!(u.contains("/v2026.6.14/"));
        assert!(u.ends_with("mise-v2026.6.14-macos-arm64"));
    }

    #[tokio::test]
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    async fn host_target_on_ci_is_linux_x64() {
        let t = Target::host().unwrap();
        let r = MiseResolver::new();
        let (_, u) = r.resolve(t, "1.0.0").await.unwrap();
        assert!(u.contains("linux-x64"));
    }

    #[test]
    fn latest_release_deserializes_tag_name() {
        let json = r#"{"tag_name":"v2026.6.14","assets":[]}"#;
        let parsed: LatestRelease = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.tag_name, "v2026.6.14");
    }
}
