//! Ruby helper for mise.
//!
//! [`RubyHelper`] wraps a [`Mise`](crate::Mise) reference and provides async
//! methods for installing Ruby versions, setting global/local defaults,
//! listing available versions, resolving the `ruby` binary path, and
//! toggling precompiled binaries.

use camino::Utf8PathBuf;

use crate::client::Mise;
use crate::error::MiseResult;

// ---------------------------------------------------------------------------
// RubyHelper
// ---------------------------------------------------------------------------

/// Typed helper for interacting with Ruby via mise.
///
/// Borrows a [`Mise`](crate::Mise) client so it can be used without taking
/// ownership.
///
/// # Example
///
/// ```rust,ignore
/// use toride_mise::Mise;
/// use toride_mise::languages::ruby::RubyHelper;
///
/// let mise = Mise::builder().build()?;
/// let ruby = RubyHelper::new(&mise);
/// ruby.install("3.3").await?;
/// ruby.set_precompiled(true).await?;
/// ```
pub struct RubyHelper<'a> {
    mise: &'a Mise,
}

impl<'a> RubyHelper<'a> {
    /// Create a new [`RubyHelper`] borrowing the given [`Mise`](crate::Mise) client.
    pub fn new(mise: &'a Mise) -> Self {
        Self { mise }
    }

    /// Install a Ruby version.
    ///
    /// `version` may be a prefix (`"3.3"`), exact version (`"3.3.0"`), or an
    /// alias such as `"latest"`.
    ///
    /// Invokes `mise install ruby@<version>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the installation command exits non-zero.
    pub async fn install(&self, version: &str) -> MiseResult<()> {
        self.mise
            .run_checked(["install", &format!("ruby@{version}")])
            .await?;
        Ok(())
    }

    /// Set the global Ruby version.
    ///
    /// Invokes `mise use --global ruby@<version>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero.
    pub async fn use_global(&self, version: &str) -> MiseResult<()> {
        self.mise
            .run_checked(["use", "--global", &format!("ruby@{version}")])
            .await?;
        Ok(())
    }

    /// Set the local (project-level) Ruby version.
    ///
    /// Invokes `mise use ruby@<version>` in the configured working directory.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero.
    pub async fn use_local(&self, version: &str) -> MiseResult<()> {
        self.mise
            .run_checked(["use", &format!("ruby@{version}")])
            .await?;
        Ok(())
    }

    /// List available Ruby versions.
    ///
    /// Invokes `mise ls-remote ruby` and returns the raw output lines.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero.
    pub async fn list_versions(&self) -> MiseResult<Vec<String>> {
        let output = self.mise.run_checked(["ls-remote", "ruby"]).await?;
        let versions = output
            .stdout_trimmed()
            .lines()
            .map(|l| l.trim().to_owned())
            .filter(|l| !l.is_empty())
            .collect();
        Ok(versions)
    }

    /// Resolve the path to the `ruby` binary for the active version.
    ///
    /// Invokes `mise which ruby`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero or the binary cannot be resolved.
    pub async fn resolve_bin(&self) -> MiseResult<Utf8PathBuf> {
        let output = self.mise.run_checked(["which", "ruby"]).await?;
        Ok(Utf8PathBuf::from(output.stdout_trimmed()))
    }

    /// Set whether to prefer precompiled Ruby binaries.
    ///
    /// When `enabled` is `true`, configures mise to use precompiled Ruby
    /// binaries, which are faster to install than compiling from source.
    /// When `false`, disables the preference (mise may still use precompiled
    /// binaries if no source build is available, depending on configuration).
    ///
    /// Invokes `mise config set ruby.precompiled <bool>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero.
    pub async fn set_precompiled(&self, enabled: bool) -> MiseResult<()> {
        self.mise
            .run_checked(["config", "set", "ruby.precompiled", &enabled.to_string()])
            .await?;
        Ok(())
    }
}
