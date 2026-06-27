//! The `Tool` abstraction.
//!
//! A [`Tool`] is a *declarative* description of how to install a single
//! release-publishing tool. It is deliberately a plain data struct (not a
//! trait): almost every tool differs only in the values of its fields
//! (name, URL template, binary path), so a config struct is the most
//! ergonomic fit and is trivially constructible from a TOML/JSON file if
//! that is ever desired.
//!
//! For tools whose release layout cannot be captured by a static template
//! (e.g. an asset name that depends on a server-side lookup), implement the
//! [`ReleaseResolver`] trait instead and pass it to
//! [`Installer::install_with_resolver`](crate::Installer::install_with_resolver).

use crate::error::{Error, Result};
use crate::target::Target;

/// What kind of release artifact a [`Tool`] publishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactKind {
    /// A single pre-built executable file downloaded directly and placed at
    /// the install path verbatim (e.g. `mise-v2026.6.14-linux-x64`).
    Binary,

    /// A compressed tarball containing one or more files, from which the
    /// executable at [`Tool::bin_path`] is extracted.
    Tarball(Tarball),
}

/// The compression applied to a [`ArtifactKind::Tarball`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tarball {
    /// gzip (`.tar.gz` / `.tgz`).
    Gz,
    /// xz (`.tar.xz` / `.txz`).
    Xz,
}

impl Tarball {
    /// Map a tarball kind to its conventional file extension (without the
    /// leading dot), e.g. `Gz` -> `"tar.gz"`.
    #[must_use]
    pub const fn extension(self) -> &'static str {
        match self {
            Self::Gz => "tar.gz",
            Self::Xz => "tar.xz",
        }
    }
}

impl ArtifactKind {
    /// A gzip-compressed tarball (`.tar.gz`).
    #[must_use]
    pub const fn tarball_gz() -> Self {
        Self::Tarball(Tarball::Gz)
    }

    /// An xz-compressed tarball (`.tar.xz`).
    #[must_use]
    pub const fn tarball_xz() -> Self {
        Self::Tarball(Tarball::Xz)
    }
}

/// How the sha256 digest of an artifact is obtained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Checksum {
    /// The tool publishes no checksum. The installer falls back to a sane
    /// minimum-size check only (see [`Installer`](crate::Installer)
    /// docs for the rationale).
    None,

    /// A fixed hex digest known ahead of time (e.g. pinned in config).
    Digest(String),

    /// A URL whose body is the checksum file. The installer fetches it and
    /// looks for a line whose filename component matches `asset_name`.
    ///
    /// The body may be either `<hex>  <filename>` (coreutils `sha256sum`
    /// format) or a bare `<hex>` line.
    Url { url: String, asset_name: String },
}

/// A checksum resolver decouples the *source* of a checksum from the
/// installer. The default [`Checksum`] type implements this; tools with
/// exotic schemes (e.g. a checksum embedded in a JSON manifest) can supply
/// their own.
#[async_trait::async_trait]
pub trait ReleaseResolver: Send + Sync {
    /// Resolve the absolute download URL for `version` on `target`.
    ///
    /// `version == "latest"` requests the resolver's notion of the newest
    /// release (typically a redirect or an API lookup).
    ///
    /// Returns the resolved concrete version string (e.g. `"2026.6.14"`,
    /// NOT `"latest"`) and the download URL.
    async fn resolve(
        &self,
        target: Target,
        version: &str,
    ) -> Result<(String, String)>;
}

/// Declarative description of an installable tool.
///
/// Construct via [`Tool::builder`](crate::ToolBuilder) for ergonomics, or
/// `Tool { .. }` directly.
///
/// # Example (mise, the wired concrete tool)
///
/// ```rust,ignore
/// use toride_installer::{Tool, ArtifactKind};
///
/// let mise = Tool::builder()
///     .name("mise")
///     .artifact(ArtifactKind::Binary)
///     .bin_name("mise")
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct Tool {
    /// Human-readable tool name, used in errors and log messages.
    pub name: String,

    /// The kind of release artifact this tool publishes.
    pub artifact: ArtifactKind,

    /// The path of the executable *inside* a tarball (relative to the
    /// archive root). Ignored for [`ArtifactKind::Binary`].
    pub bin_path: Option<String>,

    /// The file name of the installed executable on disk (e.g. `"mise"`).
    pub bin_name: String,

    /// How to obtain the sha256 checksum, if at all.
    pub checksum: Checksum,

    /// Default install directory. When `None`, the installer falls back to
    /// `~/.local/bin`.
    pub default_install_dir: Option<camino::Utf8PathBuf>,
}

impl Tool {
    /// Begin a [`ToolBuilder`].
    #[must_use]
    pub fn builder() -> ToolBuilder {
        ToolBuilder::default()
    }

    /// Validate that the tool is internally consistent for installation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingConfig`] if a tarball tool has no `bin_path`.
    pub fn validate(&self) -> Result<()> {
        if matches!(self.artifact, ArtifactKind::Tarball(_)) && self.bin_path.is_none() {
            return Err(Error::MissingConfig {
                tool: self.name.clone(),
                field: "bin_path".into(),
            });
        }
        Ok(())
    }
}

impl Default for Tool {
    fn default() -> Self {
        Self {
            name: String::new(),
            artifact: ArtifactKind::Binary,
            bin_path: None,
            bin_name: String::new(),
            checksum: Checksum::None,
            default_install_dir: None,
        }
    }
}

/// Builder for [`Tool`].
#[derive(Debug, Clone, Default)]
pub struct ToolBuilder {
    tool: Tool,
}

impl ToolBuilder {
    /// Set the tool name.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.tool.name = name.into();
        self
    }

    /// Set the artifact kind.
    #[must_use]
    pub fn artifact(mut self, artifact: ArtifactKind) -> Self {
        self.tool.artifact = artifact;
        self
    }

    /// Set the executable path inside a tarball.
    #[must_use]
    pub fn bin_path(mut self, path: impl Into<String>) -> Self {
        self.tool.bin_path = Some(path.into());
        self
    }

    /// Set the on-disk installed binary name.
    #[must_use]
    pub fn bin_name(mut self, name: impl Into<String>) -> Self {
        self.tool.bin_name = name.into();
        self
    }

    /// Set the checksum source.
    #[must_use]
    pub fn checksum(mut self, checksum: Checksum) -> Self {
        self.tool.checksum = checksum;
        self
    }

    /// Override the default install directory.
    #[must_use]
    pub fn default_install_dir(mut self, dir: impl Into<camino::Utf8PathBuf>) -> Self {
        self.tool.default_install_dir = Some(dir.into());
        self
    }

    /// Build the [`Tool`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingConfig`] if the combination of fields is
    /// inconsistent (see [`Tool::validate`]).
    pub fn build(self) -> Result<Tool> {
        self.tool.validate()?;
        Ok(self.tool)
    }
}
