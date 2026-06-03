//! Bun helper for mise.
//!
//! [`BunHelper`] wraps a [`Mise`](crate::Mise) reference and provides async
//! methods for installing Bun versions, setting global/local defaults,
//! listing available versions, and resolving the `bun` binary path.

use camino::Utf8PathBuf;

use crate::client::Mise;
use crate::error::MiseResult;

// ---------------------------------------------------------------------------
// BunHelper
// ---------------------------------------------------------------------------

/// Typed helper for interacting with Bun via mise.
///
/// Borrows a [`Mise`](crate::Mise) client so it can be used without taking
/// ownership.
///
/// # Example
///
/// ```rust,ignore
/// use toride_mise::Mise;
/// use toride_mise::languages::bun::BunHelper;
///
/// let mise = Mise::builder().build()?;
/// let bun = BunHelper::new(&mise);
/// bun.install("latest").await?;
/// ```
pub struct BunHelper<'a> {
    mise: &'a Mise,
}

impl<'a> BunHelper<'a> {
    /// Create a new [`BunHelper`] borrowing the given [`Mise`](crate::Mise) client.
    pub fn new(mise: &'a Mise) -> Self {
        Self { mise }
    }

    /// Install a Bun version.
    ///
    /// `version` may be a prefix (`"1"`), exact version (`"1.1.0"`), or an
    /// alias such as `"latest"`.
    ///
    /// Invokes `mise install bun@<version>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the installation command exits non-zero.
    pub async fn install(&self, version: &str) -> MiseResult<()> {
        self.mise
            .run_checked(["install", &format!("bun@{version}")])
            .await?;
        Ok(())
    }

    /// Set the global Bun version.
    ///
    /// Invokes `mise use --global bun@<version>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero.
    pub async fn use_global(&self, version: &str) -> MiseResult<()> {
        self.mise
            .run_checked(["use", "--global", &format!("bun@{version}")])
            .await?;
        Ok(())
    }

    /// Set the local (project-level) Bun version.
    ///
    /// Invokes `mise use bun@<version>` in the configured working directory.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero.
    pub async fn use_local(&self, version: &str) -> MiseResult<()> {
        self.mise
            .run_checked(["use", &format!("bun@{version}")])
            .await?;
        Ok(())
    }

    /// List available Bun versions.
    ///
    /// Invokes `mise ls-remote bun` and returns the raw output lines.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero.
    pub async fn list_versions(&self) -> MiseResult<Vec<String>> {
        let output = self.mise.run_checked(["ls-remote", "bun"]).await?;
        let versions = output
            .stdout_trimmed()
            .lines()
            .map(|l| l.trim().to_owned())
            .filter(|l| !l.is_empty())
            .collect();
        Ok(versions)
    }

    /// Resolve the path to a binary for the active Bun version.
    ///
    /// When called without arguments (or with `"bun"`), resolves the main `bun`
    /// binary. Pass a specific binary name to resolve other binaries shipped
    /// with the Bun installation.
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
