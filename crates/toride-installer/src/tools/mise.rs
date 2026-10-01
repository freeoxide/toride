//! Mise — the wired concrete tool.
//!
//! Resolves the single static `mise` binary from
//! <https://github.com/jdx/mise/releases>. mise publishes a raw
//! executable asset named `mise-v<VERSION>-<os>-<arch>` (no extension,
//! no tarball) for each release, plus glibc/musl tarballs; we use the raw
//! binary so the framework's `Binary` artifact path is exercised end-to-end.
//! On Windows the raw asset carries an `.exe` suffix —
//! `mise-v<VERSION>-windows-x64.exe`, with a `.zip` bundle published
//! alongside that we do not use — verified against the live v2026.9.15
//! release (asset list and `SHASUMS256.txt`); the descriptor installs the
//! binary as `mise.exe` there (see [`MISE_BIN_NAME`]).
//!
//! Every mise release also publishes a `SHASUMS256.txt` covering its
//! assets (coreutils `sha256sum` format with `./`-prefixed filenames —
//! verified live against v2026.9.15). The static [`Tool`] descriptor
//! carries [`Checksum::None`] only because the checksum-file URL embeds
//! the concrete version; the install paths pin [`Checksum::Url`] for that
//! version (see `checksum_pinned_tool`), so mise installs are
//! checksum-verified, never size-floor-only.
//!
//! # Quick start
//!
//! ```rust,ignore
//! use toride_installer::tools::mise;
//!
//! # async fn run() -> toride_installer::Result<()> {
//! // Detect-first: installs only when no satisfying copy already runs.
//! let outcome = mise::ensure_mise("latest", None).await?;
//! // Or install unconditionally:
//! let dest = mise::install_mise("latest", None).await?;
//! println!("installed mise to {dest}");
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "http")]
use async_trait::async_trait;
#[cfg(feature = "http")]
use camino::Utf8PathBuf;

#[cfg(feature = "http")]
use crate::error::{Error, Result};
#[cfg(feature = "http")]
use crate::installer::Installer;
#[cfg(feature = "http")]
use crate::status::{Detector, EnsureOutcome, version_satisfied};
#[cfg(feature = "http")]
use crate::target::{Os, Target};
#[cfg(feature = "http")]
use crate::tool::ReleaseResolver;
use crate::tool::{ArtifactKind, Checksum, Tool};

/// The GitHub owner/repo slug for mise.
pub const MISE_REPO: &str = "jdx/mise";

/// The on-disk binary name the mise descriptor installs as on the compile
/// target: `mise.exe` under `cfg(windows)` — the managed install lands at
/// `<dir>/<bin_name>` and the published Windows raw asset is an `.exe`
/// executable (verified against the live v2026.9.15 release) — `mise`
/// everywhere else.
#[cfg(windows)]
pub const MISE_BIN_NAME: &str = "mise.exe";

/// [`MISE_BIN_NAME`] on non-Windows targets, where the raw asset has no
/// extension. Split per target so exactly one definition compiles.
#[cfg(not(windows))]
pub const MISE_BIN_NAME: &str = "mise";

/// The GitHub releases API base for mise.
#[cfg(feature = "http")]
const MISE_API: &str = "https://api.github.com/repos/jdx/mise/releases";

/// The sha256 checksum file mise publishes with every release.
#[cfg(feature = "http")]
const SHASUMS_FILE: &str = "SHASUMS256.txt";

/// User-Agent string sent to GitHub (api.github.com requires one).
#[cfg(feature = "http")]
const USER_AGENT: &str = concat!("toride-installer/", env!("CARGO_PKG_VERSION"));

/// Build the [`Tool`] descriptor for mise.
///
/// mise is a `Binary` artifact. The descriptor carries [`Checksum::None`]
/// only because the release's `SHASUMS_FILE` URL embeds the concrete
/// version — the install paths pin [`Checksum::Url`] for that version once
/// it is known (see `checksum_pinned_tool`). The default install dir is
/// `~/.local/bin` (handled by the engine when `default_install_dir` is
/// `None`), and `bin_name` follows the compile target: `mise.exe` under
/// `cfg(windows)` ([`MISE_BIN_NAME`]), `mise` elsewhere.
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
#[cfg(feature = "http")]
#[derive(Debug, Clone, Default)]
pub struct MiseResolver {
    /// Optional injected HTTP client (e.g. for a shared connection pool or
    /// a mock in tests). When `None`, a fresh client is built per lookup.
    pub client: Option<reqwest::Client>,
}

#[cfg(feature = "http")]
impl MiseResolver {
    /// Create a new resolver with a default HTTP client.
    #[must_use]
    pub fn new() -> Self {
        Self { client: None }
    }

    /// The asset filename for a given (version, target), e.g.
    /// `mise-v2026.6.14-linux-x64`, or `mise-v2026.6.14-windows-x64.exe`
    /// on Windows targets — the raw Windows asset carries an `.exe`
    /// extension, verified against the live v2026.9.15 release whose
    /// `SHASUMS256.txt` lists `./mise-v2026.9.15-windows-x64.exe`.
    fn asset_name(version: &str, target: Target) -> String {
        // The asset filename always prefixes `v`; strip any caller-supplied
        // one first so we don't double it up.
        let trimmed = version.strip_prefix('v').unwrap_or(version);
        let mut name = format!("mise-v{trimmed}-{}", target.keyword());
        if matches!(target.os, Os::Windows) {
            name.push_str(".exe");
        }
        name
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

#[cfg(feature = "http")]
impl MiseResolver {
    /// Build the versioned download URL for (concrete version, target).
    fn download_url(version: &str, target: Target) -> String {
        let asset = Self::asset_name(version, target);
        format!("https://github.com/{MISE_REPO}/releases/download/v{version}/{asset}")
    }
}

#[cfg(feature = "http")]
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
#[cfg(feature = "http")]
#[derive(Debug, serde::Deserialize)]
struct LatestRelease {
    /// The git tag, e.g. `v2026.6.14`.
    tag_name: String,
}

/// The versioned [`SHASUMS_FILE`] URL for a concrete mise release, e.g.
/// `https://github.com/jdx/mise/releases/download/v2026.9.15/SHASUMS256.txt`.
#[cfg(feature = "http")]
fn shasums256_url(version: &str) -> String {
    format!("https://github.com/{MISE_REPO}/releases/download/v{version}/{SHASUMS_FILE}")
}

/// [`mise_tool`] with the release's [`SHASUMS_FILE`] pinned for the concrete
/// `version` — the descriptor [`install_mise`] actually installs.
///
/// [`Checksum::Url`] makes the engine fetch the checksum file and verify the
/// asset's sha256 strictly, so the size-floor policy never applies to a mise
/// install. The parser accepts the file's coreutils format, including its
/// `./`-prefixed filenames.
#[cfg(feature = "http")]
fn checksum_pinned_tool(version: &str, target: Target) -> Tool {
    let mut tool = mise_tool();
    tool.checksum = Checksum::Url {
        url: shasums256_url(version),
        asset_name: MiseResolver::asset_name(version, target),
    };
    tool
}

/// Convenience: checksum-verified install of the latest (or a pinned) mise
/// to `~/.local/bin/mise` (or `install_dir` when provided).
///
/// The concrete version is resolved first — zero network for a pinned
/// request; for `"latest"` it is the one API call the install needed anyway
/// — then `checksum_pinned_tool` pins the release's `SHASUMS_FILE` on
/// the descriptor and the engine verifies the downloaded asset against it
/// strictly. The engine re-resolves the now-concrete version off its pinned
/// (pure string-formatting) path, so nothing is fetched twice.
///
/// # Errors
///
/// See [`Error`]. Most commonly [`Error::Download`] on network failure,
/// [`Error::HttpStatus`] if GitHub rate-limits the latest-version lookup or
/// the checksum fetch, and [`Error::NoChecksumEntry`] if the published
/// checksum file stops listing the asset.
#[cfg(feature = "http")]
pub async fn install_mise(version: &str, install_dir: Option<&Utf8PathBuf>) -> Result<Utf8PathBuf> {
    let target = Target::host()?;
    let resolver = MiseResolver::new();
    let (concrete, _url) = resolver.resolve(target, version).await?;
    let tool = checksum_pinned_tool(&concrete, target);
    Installer::new()
        .install_with_resolver(&tool, target, &concrete, install_dir, &resolver)
        .await
}

/// Detect-first mise install: the
/// [`ensure_installed`](crate::status::ensure_installed) decision flow with
/// the miss routed through [`install_mise`] so the install is
/// checksum-verified.
///
/// A copy that already runs is kept with **zero network** — neither the
/// detect probe nor the satisfaction check consults the resolver.
/// `"latest"` always keeps an installed copy (deciding whether a newer
/// release exists needs network by definition); a pinned semver keeps it
/// when the detected version meets the pin. Only a true miss routes into
/// [`install_mise`], which pins the release's `SHASUMS_FILE` (see the
/// module-level note) and installs under strict sha256 verification.
///
/// The detect → keep/miss → re-detect flow mirrors
/// `ensure_with_detector` in [`crate::status`] step for step; the split
/// exists only so the miss can pass through the version-resolving,
/// checksum-pinning [`install_mise`] instead of the raw engine entry.
///
/// # Example
///
/// ```rust,ignore
/// use toride_installer::status::EnsureOutcome;
///
/// # async fn run() -> toride_installer::Result<()> {
/// match mise::ensure_mise("latest", None).await? {
///     EnsureOutcome::AlreadyPresent(status) => println!("already running: {status:?}"),
///     EnsureOutcome::Installed { path, .. } => println!("installed: {path}"),
/// }
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// [`Error::UnsupportedTarget`] when [`Target::host`] cannot classify this
/// platform, plus everything [`install_mise`] can return.
#[cfg(feature = "http")]
pub async fn ensure_mise(
    version: &str,
    install_dir: Option<&Utf8PathBuf>,
) -> Result<EnsureOutcome> {
    let tool = mise_tool();
    // The detector must look in the same directory the install writes to,
    // so "where we look" cannot drift from "where we install".
    let mut builder = Detector::builder();
    if let Some(dir) = install_dir {
        builder = builder.install_dir(dir);
    }
    let detector = builder.build();

    // 1. detect first — offline, never errors, and via `detect_async`: the
    //    version probe spawns subprocesses and must not block an async
    //    runtime worker.
    let status = detector.detect_async(&tool).await;

    // 2. a copy that satisfies the request is kept as-is, zero network.
    if status.is_installed() && version_satisfied(&status, version) {
        return Ok(EnsureOutcome::AlreadyPresent(status));
    }

    // 3. a true miss: install checksum-verified, then re-detect for the
    //    freshly installed version. In a shadowed environment the re-probe
    //    reports whichever copy `detect` classifies (the same one a
    //    subsequent ensure would keep).
    let path = install_mise(version, install_dir).await?;
    let version = detector.detect_async(&tool).await.version().cloned();
    Ok(EnsureOutcome::Installed { path, version })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mise_tool_descriptor() {
        let tool = mise_tool();
        assert_eq!(tool.name, "mise");
        // MISE_BIN_NAME is cfg-split (mise.exe under cfg(windows));
        // asserting against it keeps the test true on every compile target.
        assert_eq!(tool.bin_name, MISE_BIN_NAME);
        assert_eq!(tool.artifact, ArtifactKind::Binary);
        // The static descriptor stays checksum-free (the checksum-file URL
        // is version-dependent); installs pin `Checksum::Url` — see
        // `checksum_pinned_tool_names_the_release_checksum_file`.
        assert_eq!(tool.checksum, Checksum::None);
        assert!(tool.bin_path.is_none());
        assert!(tool.default_install_dir.is_none());
        tool.validate().unwrap();
    }
}

/// Resolver/install tests: they exercise the `http`-gated engine paths and
/// ride behind the same feature.
#[cfg(all(test, feature = "http"))]
mod resolver_tests {
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
    fn download_url_format_linux_x64() {
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
    fn download_url_format_macos_arm64() {
        let t = Target {
            os: Os::Macos,
            arch: Arch::Arm64,
        };
        let url = MiseResolver::download_url("2026.6.14", t);
        assert_eq!(
            url,
            "https://github.com/jdx/mise/releases/download/v2026.6.14/mise-v2026.6.14-macos-arm64"
        );
    }

    #[test]
    fn download_url_format_linux_arm64() {
        let t = Target {
            os: Os::Linux,
            arch: Arch::Arm64,
        };
        let url = MiseResolver::download_url("2026.6.14", t);
        assert_eq!(
            url,
            "https://github.com/jdx/mise/releases/download/v2026.6.14/mise-v2026.6.14-linux-arm64"
        );
    }

    #[test]
    fn download_url_format_macos_x64() {
        let t = Target {
            os: Os::Macos,
            arch: Arch::X64,
        };
        let url = MiseResolver::download_url("2026.6.14", t);
        assert_eq!(
            url,
            "https://github.com/jdx/mise/releases/download/v2026.6.14/mise-v2026.6.14-macos-x64"
        );
    }

    #[test]
    fn asset_name_format_windows_x64() {
        let t = Target {
            os: Os::Windows,
            arch: Arch::X64,
        };
        assert_eq!(
            MiseResolver::asset_name("2026.6.14", t),
            "mise-v2026.6.14-windows-x64.exe"
        );
    }

    #[test]
    fn asset_name_format_windows_arm64() {
        let t = Target {
            os: Os::Windows,
            arch: Arch::Arm64,
        };
        assert_eq!(
            MiseResolver::asset_name("2026.6.14", t),
            "mise-v2026.6.14-windows-arm64.exe"
        );
    }

    #[test]
    fn download_url_format_windows_x64() {
        let t = Target {
            os: Os::Windows,
            arch: Arch::X64,
        };
        let url = MiseResolver::download_url("2026.6.14", t);
        // The full literal is one char over the 100-column budget, so it is
        // assembled from two pieces (concat!, not runtime formatting).
        assert_eq!(
            url,
            concat!(
                "https://github.com/jdx/mise/releases/download/",
                "v2026.6.14/mise-v2026.6.14-windows-x64.exe"
            )
        );
    }

    #[test]
    fn shasums256_url_format() {
        assert_eq!(
            shasums256_url("2026.9.15"),
            "https://github.com/jdx/mise/releases/download/v2026.9.15/SHASUMS256.txt"
        );
    }

    #[test]
    fn checksum_pinned_tool_names_the_release_checksum_file() {
        let t = Target {
            os: Os::Linux,
            arch: Arch::X64,
        };
        let tool = checksum_pinned_tool("2026.9.15", t);
        assert_eq!(
            tool.checksum,
            Checksum::Url {
                url: "https://github.com/jdx/mise/releases/download/v2026.9.15/SHASUMS256.txt"
                    .into(),
                asset_name: "mise-v2026.9.15-linux-x64".into(),
            }
        );
        // The rest of the descriptor is unchanged and still validates.
        assert_eq!(tool.name, "mise");
        assert_eq!(tool.artifact, ArtifactKind::Binary);
        assert!(tool.bin_path.is_none());
        tool.validate().unwrap();
    }

    #[test]
    fn checksum_pinned_tool_names_the_windows_asset() {
        let t = Target {
            os: Os::Windows,
            arch: Arch::X64,
        };
        let tool = checksum_pinned_tool("2026.9.15", t);
        assert_eq!(
            tool.checksum,
            Checksum::Url {
                url: "https://github.com/jdx/mise/releases/download/v2026.9.15/SHASUMS256.txt"
                    .into(),
                // Must byte-match the SHASUMS256.txt entry after the parser
                // strips its `./` prefix — including the `.exe` (live-
                // verified against v2026.9.15:
                // `./mise-v2026.9.15-windows-x64.exe`).
                asset_name: "mise-v2026.9.15-windows-x64.exe".into(),
            }
        );
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
