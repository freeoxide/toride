//! Python helper for mise.
//!
//! [`PythonHelper`] wraps a [`Mise`](crate::Mise) reference and provides async
//! methods for installing Python versions, setting global/local defaults,
//! listing available versions, resolving the `python` binary path, and setting
//! multiple global Python versions simultaneously.

use camino::Utf8PathBuf;

use crate::client::Mise;
use crate::error::MiseResult;

// ---------------------------------------------------------------------------
// PythonHelper
// ---------------------------------------------------------------------------

/// Typed helper for interacting with Python via mise.
///
/// Borrows a [`Mise`](crate::Mise) client so it can be used without taking
/// ownership.
///
/// # Example
///
/// ```rust,ignore
/// use toride_mise::Mise;
/// use toride_mise::languages::python::PythonHelper;
///
/// let mise = Mise::builder().build()?;
/// let python = PythonHelper::new(&mise);
/// python.install("3.12").await?;
/// python.use_multiple_global(&["3.12", "3.11"]).await?;
/// ```
pub struct PythonHelper<'a> {
    mise: &'a Mise,
}

impl<'a> PythonHelper<'a> {
    /// Create a new [`PythonHelper`] borrowing the given [`Mise`](crate::Mise) client.
    pub fn new(mise: &'a Mise) -> Self {
        Self { mise }
    }

    /// Install a Python version.
    ///
    /// `version` may be a prefix (`"3.12"`), exact version (`"3.12.1"`), or an
    /// alias such as `"latest"`.
    ///
    /// Invokes `mise install python@<version>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the installation command exits non-zero.
    pub async fn install(&self, version: &str) -> MiseResult<()> {
        self.mise
            .run_checked(["install", &format!("python@{version}")])
            .await?;
        Ok(())
    }

    /// Set the global Python version.
    ///
    /// Invokes `mise use --global python@<version>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero.
    pub async fn use_global(&self, version: &str) -> MiseResult<()> {
        self.mise
            .run_checked(["use", "--global", &format!("python@{version}")])
            .await?;
        Ok(())
    }

    /// Set the local (project-level) Python version.
    ///
    /// Invokes `mise use python@<version>` in the configured working directory.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero.
    pub async fn use_local(&self, version: &str) -> MiseResult<()> {
        self.mise
            .run_checked(["use", &format!("python@{version}")])
            .await?;
        Ok(())
    }

    /// Set multiple global Python versions at once.
    ///
    /// This is useful when you need several Python versions available globally
    /// (e.g. for `tox` or `nox` matrix testing). Each element in `versions` is
    /// passed as a separate `python@<version>` argument.
    ///
    /// Invokes `mise use --global python@<v1> python@<v2> …`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero.
    pub async fn use_multiple_global(&self, versions: &[&str]) -> MiseResult<()> {
        let mut args: Vec<String> = vec!["use".into(), "--global".into()];
        for v in versions {
            args.push(format!("python@{v}"));
        }
        self.mise.run_checked(args).await?;
        Ok(())
    }

    /// List available Python versions.
    ///
    /// Invokes `mise ls-remote python` and returns the raw output lines.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero.
    pub async fn list_versions(&self) -> MiseResult<Vec<String>> {
        let output = self.mise.run_checked(["ls-remote", "python"]).await?;
        let versions = output
            .stdout_trimmed()
            .lines()
            .map(|l| l.trim().to_owned())
            .filter(|l| !l.is_empty())
            .collect();
        Ok(versions)
    }

    /// Resolve the path to the `python` binary for the active version.
    ///
    /// Invokes `mise which python`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero or the binary cannot be resolved.
    pub async fn resolve_bin(&self) -> MiseResult<Utf8PathBuf> {
        let output = self.mise.run_checked(["which", "python"]).await?;
        Ok(Utf8PathBuf::from(output.stdout_trimmed()))
    }
}
