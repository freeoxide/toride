//! Java helper for mise.
//!
//! [`JavaHelper`] wraps a [`Mise`](crate::Mise) reference and provides async
//! methods for installing Java versions, setting global/local defaults,
//! listing available versions, resolving the `java` binary path, and
//! querying the `JAVA_HOME` directory.

use camino::Utf8PathBuf;

use crate::client::Mise;
use crate::error::MiseResult;

// ---------------------------------------------------------------------------
// JavaHelper
// ---------------------------------------------------------------------------

/// Typed helper for interacting with Java via mise.
///
/// Borrows a [`Mise`](crate::Mise) client so it can be used without taking
/// ownership.
///
/// # Example
///
/// ```rust,ignore
/// use toride_mise::Mise;
/// use toride_mise::languages::java::JavaHelper;
///
/// let mise = Mise::builder().build()?;
/// let java = JavaHelper::new(&mise);
/// java.install("21").await?;
/// let home = java.java_home().await?;
/// ```
pub struct JavaHelper<'a> {
    mise: &'a Mise,
}

impl<'a> JavaHelper<'a> {
    /// Create a new [`JavaHelper`] borrowing the given [`Mise`](crate::Mise) client.
    pub fn new(mise: &'a Mise) -> Self {
        Self { mise }
    }

    /// Install a Java version.
    ///
    /// `version` may be a prefix (`"21"`), exact version (`"21.0.1"`), a
    /// distribution-prefixed version (`"temurin-21"`), or an alias such as
    /// `"latest"`.
    ///
    /// Invokes `mise install java@<version>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the installation command exits non-zero.
    pub async fn install(&self, version: &str) -> MiseResult<()> {
        self.mise
            .run_checked(["install", &format!("java@{version}")])
            .await?;
        Ok(())
    }

    /// Set the global Java version.
    ///
    /// Invokes `mise use --global java@<version>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero.
    pub async fn use_global(&self, version: &str) -> MiseResult<()> {
        self.mise
            .run_checked(["use", "--global", &format!("java@{version}")])
            .await?;
        Ok(())
    }

    /// Set the local (project-level) Java version.
    ///
    /// Invokes `mise use java@<version>` in the configured working directory.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero.
    pub async fn use_local(&self, version: &str) -> MiseResult<()> {
        self.mise
            .run_checked(["use", &format!("java@{version}")])
            .await?;
        Ok(())
    }

    /// List available Java versions.
    ///
    /// Invokes `mise ls-remote java` and returns the raw output lines.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero.
    pub async fn list_versions(&self) -> MiseResult<Vec<String>> {
        let output = self.mise.run_checked(["ls-remote", "java"]).await?;
        let versions = output
            .stdout_trimmed()
            .lines()
            .map(|l| l.trim().to_owned())
            .filter(|l| !l.is_empty())
            .collect();
        Ok(versions)
    }

    /// Resolve the path to the `java` binary for the active version.
    ///
    /// Invokes `mise which java`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero or the binary cannot be resolved.
    pub async fn resolve_bin(&self) -> MiseResult<Utf8PathBuf> {
        let output = self.mise.run_checked(["which", "java"]).await?;
        Ok(Utf8PathBuf::from(output.stdout_trimmed()))
    }

    /// Resolve the `JAVA_HOME` directory for the active Java version.
    ///
    /// Invokes `mise java home` which prints the installation prefix for the
    /// currently active Java toolchain. This is the directory that should be
    /// set as the `JAVA_HOME` environment variable.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero or the home directory cannot be resolved.
    pub async fn java_home(&self) -> MiseResult<Utf8PathBuf> {
        let output = self.mise.run_checked(["java", "home"]).await?;
        Ok(Utf8PathBuf::from(output.stdout_trimmed()))
    }
}
