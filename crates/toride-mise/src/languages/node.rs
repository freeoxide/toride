//! Node.js helper for mise.
//!
//! [`NodeHelper`] wraps a [`Mise`](crate::Mise) reference and provides async
//! methods for installing Node.js versions, setting global/local defaults,
//! listing available versions, and resolving the `node` binary path.

use camino::Utf8PathBuf;

use crate::error::MiseResult;
use crate::client::Mise;

// ---------------------------------------------------------------------------
// NodeHelper
// ---------------------------------------------------------------------------

/// Typed helper for interacting with Node.js via mise.
///
/// Borrows a [`Mise`](crate::Mise) client so it can be used without taking
/// ownership.
///
/// # Example
///
/// ```rust,ignore
/// use toride_mise::Mise;
/// use toride_mise::languages::node::NodeHelper;
///
/// let mise = Mise::builder().build()?;
/// let node = NodeHelper::new(&mise);
/// node.install("22").await?;
/// ```
pub struct NodeHelper<'a> {
    mise: &'a Mise,
}

impl<'a> NodeHelper<'a> {
    /// Create a new [`NodeHelper`] borrowing the given [`Mise`](crate::Mise) client.
    pub fn new(mise: &'a Mise) -> Self {
        Self { mise }
    }

    /// Install a Node.js version.
    ///
    /// `version` may be a prefix (`"22"`), exact version (`"22.1.0"`), or an
    /// alias such as `"lts"`.
    ///
    /// Invokes `mise install node@<version>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the installation command exits non-zero.
    pub async fn install(&self, version: &str) -> MiseResult<()> {
        self.mise
            .run_checked(["install", &format!("node@{version}")])
            .await?;
        Ok(())
    }

    /// Set the global Node.js version.
    ///
    /// Invokes `mise use --global node@<version>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero.
    pub async fn use_global(&self, version: &str) -> MiseResult<()> {
        self.mise
            .run_checked(["use", "--global", &format!("node@{version}")])
            .await?;
        Ok(())
    }

    /// Set the local (project-level) Node.js version.
    ///
    /// Invokes `mise use node@<version>` in the configured working directory.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero.
    pub async fn use_local(&self, version: &str) -> MiseResult<()> {
        self.mise
            .run_checked(["use", &format!("node@{version}")])
            .await?;
        Ok(())
    }

    /// List available Node.js versions.
    ///
    /// Invokes `mise ls-remote node` and returns the raw output lines.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero.
    pub async fn list_versions(&self) -> MiseResult<Vec<String>> {
        let output = self.mise.run_checked(["ls-remote", "node"]).await?;
        let versions = output
            .stdout_trimmed()
            .lines()
            .map(|l| l.trim().to_owned())
            .filter(|l| !l.is_empty())
            .collect();
        Ok(versions)
    }

    /// Resolve the path to the `node` binary for the active version.
    ///
    /// Invokes `mise which node`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero or the binary cannot be resolved.
    pub async fn resolve_bin(&self) -> MiseResult<Utf8PathBuf> {
        let output = self.mise.run_checked(["which", "node"]).await?;
        Ok(Utf8PathBuf::from(output.stdout_trimmed()))
    }

    /// Pin Node.js to the latest LTS version and npm to the latest version.
    ///
    /// Invokes `mise use --pin node@lts` followed by `mise use --pin npm@latest`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// either command exits non-zero.
    pub async fn pin_lts_with_npm_latest(&self) -> MiseResult<()> {
        self.mise
            .run_checked(["use", "--pin", "node@lts"])
            .await?;
        self.mise
            .run_checked(["use", "--pin", "npm@latest"])
            .await?;
        Ok(())
    }

    /// Resolve the path to the `npm` binary for the active version.
    ///
    /// Invokes `mise which npm`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero or the binary cannot be resolved.
    pub async fn resolve_npm(&self) -> MiseResult<Utf8PathBuf> {
        let output = self.mise.run_checked(["which", "npm"]).await?;
        Ok(Utf8PathBuf::from(output.stdout_trimmed()))
    }

    /// Resolve the path to the `npx` binary for the active version.
    ///
    /// Invokes `mise which npx`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero or the binary cannot be resolved.
    pub async fn resolve_npx(&self) -> MiseResult<Utf8PathBuf> {
        let output = self.mise.run_checked(["which", "npx"]).await?;
        Ok(Utf8PathBuf::from(output.stdout_trimmed()))
    }

    /// Resolve the path to the `corepack` binary for the active version.
    ///
    /// Invokes `mise which corepack`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero or the binary cannot be resolved.
    pub async fn resolve_corepack(&self) -> MiseResult<Utf8PathBuf> {
        let output = self.mise.run_checked(["which", "corepack"]).await?;
        Ok(Utf8PathBuf::from(output.stdout_trimmed()))
    }
}
