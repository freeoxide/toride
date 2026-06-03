//! Deno helper for mise.
//!
//! [`DenoHelper`] wraps a [`Mise`](crate::Mise) reference and provides async
//! methods for installing Deno versions, setting global/local defaults,
//! listing available versions, and resolving the `deno` binary path.

use camino::Utf8PathBuf;

use crate::client::Mise;
use crate::error::MiseResult;

// ---------------------------------------------------------------------------
// DenoHelper
// ---------------------------------------------------------------------------

/// Typed helper for interacting with Deno via mise.
///
/// Borrows a [`Mise`](crate::Mise) client so it can be used without taking
/// ownership.
///
/// # Example
///
/// ```rust,ignore
/// use toride_mise::Mise;
/// use toride_mise::languages::deno::DenoHelper;
///
/// let mise = Mise::builder().build()?;
/// let deno = DenoHelper::new(&mise);
/// deno.install("latest").await?;
/// ```
pub struct DenoHelper<'a> {
    mise: &'a Mise,
}

impl<'a> DenoHelper<'a> {
    /// Create a new [`DenoHelper`] borrowing the given [`Mise`](crate::Mise) client.
    pub fn new(mise: &'a Mise) -> Self {
        Self { mise }
    }

    /// Install a Deno version.
    ///
    /// `version` may be a prefix (`"2"`), exact version (`"2.0.0"`), or an
    /// alias such as `"latest"`.
    ///
    /// Invokes `mise install deno@<version>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the installation command exits non-zero.
    pub async fn install(&self, version: &str) -> MiseResult<()> {
        self.mise
            .run_checked(["install", &format!("deno@{version}")])
            .await?;
        Ok(())
    }

    /// Set the global Deno version.
    ///
    /// Invokes `mise use --global deno@<version>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero.
    pub async fn use_global(&self, version: &str) -> MiseResult<()> {
        self.mise
            .run_checked(["use", "--global", &format!("deno@{version}")])
            .await?;
        Ok(())
    }

    /// Set the local (project-level) Deno version.
    ///
    /// Invokes `mise use deno@<version>` in the configured working directory.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero.
    pub async fn use_local(&self, version: &str) -> MiseResult<()> {
        self.mise
            .run_checked(["use", &format!("deno@{version}")])
            .await?;
        Ok(())
    }

    /// List available Deno versions.
    ///
    /// Invokes `mise ls-remote deno` and returns the raw output lines.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero.
    pub async fn list_versions(&self) -> MiseResult<Vec<String>> {
        let output = self.mise.run_checked(["ls-remote", "deno"]).await?;
        let versions = output
            .stdout_trimmed()
            .lines()
            .map(|l| l.trim().to_owned())
            .filter(|l| !l.is_empty())
            .collect();
        Ok(versions)
    }

    /// Resolve the path to a binary for the active Deno version.
    ///
    /// When called without arguments (or with `"deno"`), resolves the main `deno`
    /// binary. Pass a specific binary name to resolve other binaries shipped
    /// with the Deno installation.
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
