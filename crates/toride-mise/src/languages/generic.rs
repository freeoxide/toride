//! Generic tool helper for mise.
//!
//! [`GenericHelper`] wraps a [`Mise`](crate::Mise) reference and a tool name
//! string, providing async methods for installing, and setting global/local
//! defaults for any mise-managed tool that does not have a dedicated helper.

use camino::Utf8PathBuf;

use crate::client::Mise;
use crate::error::MiseResult;

// ---------------------------------------------------------------------------
// GenericHelper
// ---------------------------------------------------------------------------

/// Typed helper for interacting with an arbitrary mise tool.
///
/// Unlike the language-specific helpers, [`GenericHelper`] carries a `tool`
/// name as a `String` field alongside the [`Mise`](crate::Mise) reference,
/// allowing it to work with any tool known to mise (e.g. `"terraform"`,
/// `"jq"`, `"ripgrep"`, `"uv"`).
///
/// Borrows a [`Mise`](crate::Mise) client so it can be used without taking
/// ownership.
///
/// # Example
///
/// ```rust,ignore
/// use toride_mise::Mise;
/// use toride_mise::languages::generic::GenericHelper;
///
/// let mise = Mise::builder().build()?;
/// let terraform = GenericHelper::new(&mise, "terraform");
/// terraform.install("1.8").await?;
/// terraform.use_global("1.8").await?;
/// ```
pub struct GenericHelper<'a> {
    mise: &'a Mise,
    tool: String,
}

impl<'a> GenericHelper<'a> {
    /// Create a new [`GenericHelper`] for the given tool name.
    ///
    /// `tool` should be a bare tool name recognised by mise (e.g. `"terraform"`,
    /// `"jq"`, `"ripgrep"`). It should **not** include a version or backend
    /// prefix.
    pub fn new(mise: &'a Mise, tool: impl Into<String>) -> Self {
        Self {
            mise,
            tool: tool.into(),
        }
    }

    /// Return the tool name this helper was created for.
    #[must_use]
    pub fn tool(&self) -> &str {
        &self.tool
    }

    /// Install a version of the tool.
    ///
    /// `version` may be a prefix, exact version, or alias such as `"latest"`.
    ///
    /// Invokes `mise install <tool>@<version>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the installation command exits non-zero.
    pub async fn install(&self, version: &str) -> MiseResult<()> {
        self.mise
            .run_checked(["install", &format!("{}@{version}", self.tool)])
            .await?;
        Ok(())
    }

    /// Set the global version of the tool.
    ///
    /// Invokes `mise use --global <tool>@<version>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero.
    pub async fn use_global(&self, version: &str) -> MiseResult<()> {
        self.mise
            .run_checked(["use", "--global", &format!("{}@{version}", self.tool)])
            .await?;
        Ok(())
    }

    /// Set the local (project-level) version of the tool.
    ///
    /// Invokes `mise use <tool>@<version>` in the configured working directory.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero.
    pub async fn use_local(&self, version: &str) -> MiseResult<()> {
        self.mise
            .run_checked(["use", &format!("{}@{version}", self.tool)])
            .await?;
        Ok(())
    }

    /// List available versions of the tool.
    ///
    /// Invokes `mise ls-remote <tool>` and returns the raw output lines.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero.
    pub async fn list_versions(&self) -> MiseResult<Vec<String>> {
        let output = self.mise.run_checked(["ls-remote", &self.tool]).await?;
        let versions = output
            .stdout_trimmed()
            .lines()
            .map(|l| l.trim().to_owned())
            .filter(|l| !l.is_empty())
            .collect();
        Ok(versions)
    }

    /// Resolve the path to a binary provided by this tool.
    ///
    /// Invokes `mise which <bin>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero or the binary cannot be resolved.
    pub async fn resolve_bin(&self, bin: &str) -> MiseResult<Utf8PathBuf> {
        let output = self.mise.run_checked(["which", bin]).await?;
        Ok(Utf8PathBuf::from(output.stdout_trimmed()))
    }
}
