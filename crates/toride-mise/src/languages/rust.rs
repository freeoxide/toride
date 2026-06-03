//! Rust helper for mise.
//!
//! [`RustHelper`] wraps a [`Mise`](crate::Mise) reference and provides async
//! methods for installing Rust toolchains, setting global/local defaults,
//! listing available versions, resolving the `rustc` binary path, and
//! installing Rust with specific components.

use camino::Utf8PathBuf;

use crate::client::Mise;
use crate::error::MiseResult;

// ---------------------------------------------------------------------------
// RustHelper
// ---------------------------------------------------------------------------

/// Typed helper for interacting with Rust via mise.
///
/// Borrows a [`Mise`](crate::Mise) client so it can be used without taking
/// ownership.
///
/// # Example
///
/// ```rust,ignore
/// use toride_mise::Mise;
/// use toride_mise::languages::rust::RustHelper;
///
/// let mise = Mise::builder().build()?;
/// let rust = RustHelper::new(&mise);
/// rust.install("stable").await?;
/// rust.with_components("nightly", &["rustfmt", "clippy"]).await?;
/// ```
pub struct RustHelper<'a> {
    mise: &'a Mise,
}

impl<'a> RustHelper<'a> {
    /// Create a new [`RustHelper`] borrowing the given [`Mise`](crate::Mise) client.
    pub fn new(mise: &'a Mise) -> Self {
        Self { mise }
    }

    /// Install a Rust toolchain version.
    ///
    /// `version` may be a channel (`"stable"`, `"nightly"`, `"beta"`), a target
    /// triple suffix, or an exact version (`"1.78.0"`).
    ///
    /// Invokes `mise install rust@<version>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the installation command exits non-zero.
    pub async fn install(&self, version: &str) -> MiseResult<()> {
        self.mise
            .run_checked(["install", &format!("rust@{version}")])
            .await?;
        Ok(())
    }

    /// Set the global Rust toolchain version.
    ///
    /// Invokes `mise use --global rust@<version>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero.
    pub async fn use_global(&self, version: &str) -> MiseResult<()> {
        self.mise
            .run_checked(["use", "--global", &format!("rust@{version}")])
            .await?;
        Ok(())
    }

    /// Set the local (project-level) Rust toolchain version.
    ///
    /// Invokes `mise use rust@<version>` in the configured working directory.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero.
    pub async fn use_local(&self, version: &str) -> MiseResult<()> {
        self.mise
            .run_checked(["use", &format!("rust@{version}")])
            .await?;
        Ok(())
    }

    /// List available Rust toolchain versions.
    ///
    /// Invokes `mise ls-remote rust` and returns the raw output lines.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero.
    pub async fn list_versions(&self) -> MiseResult<Vec<String>> {
        let output = self.mise.run_checked(["ls-remote", "rust"]).await?;
        let versions = output
            .stdout_trimmed()
            .lines()
            .map(|l| l.trim().to_owned())
            .filter(|l| !l.is_empty())
            .collect();
        Ok(versions)
    }

    /// Resolve the path to a binary for the active Rust toolchain.
    ///
    /// When called with `"rustc"`, resolves the main compiler binary. Pass a
    /// specific binary name (e.g. `"cargo"`, `"rustfmt"`, `"rust-analyzer"`)
    /// to resolve other Rust toolchain binaries.
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

    /// Install a Rust toolchain with specific components.
    ///
    /// `version` is the toolchain version or channel. `components` is a slice of
    /// component names (e.g. `["rustfmt", "clippy", "rust-analyzer"]`).
    ///
    /// Invokes `mise install rust@<version>[extra_components=<c1>,<c2>,…]`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the installation command exits non-zero.
    pub async fn with_components(
        &self,
        version: &str,
        components: &[&str],
    ) -> MiseResult<()> {
        let joined = components.join(",");
        let spec = format!("rust@{version}[extra_components={joined}]");
        self.mise.run_checked(["install", &spec]).await?;
        Ok(())
    }
}
