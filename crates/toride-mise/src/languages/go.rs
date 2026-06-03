//! Go helper for mise.
//!
//! [`GoHelper`] wraps a [`Mise`](crate::Mise) reference and provides async
//! methods for installing Go versions, setting global/local defaults,
//! listing available versions, resolving the `go` binary path, and installing
//! CLI tools built from Go modules.

use camino::Utf8PathBuf;

use crate::client::Mise;
use crate::error::MiseResult;

// ---------------------------------------------------------------------------
// GoHelper
// ---------------------------------------------------------------------------

/// Typed helper for interacting with Go via mise.
///
/// Borrows a [`Mise`](crate::Mise) client so it can be used without taking
/// ownership.
///
/// # Example
///
/// ```rust,ignore
/// use toride_mise::Mise;
/// use toride_mise::languages::go::GoHelper;
///
/// let mise = Mise::builder().build()?;
/// let go = GoHelper::new(&mise);
/// go.install("1.23").await?;
/// go.install_cli("golang.org/x/tools/gopls@latest").await?;
/// ```
pub struct GoHelper<'a> {
    mise: &'a Mise,
}

impl<'a> GoHelper<'a> {
    /// Create a new [`GoHelper`] borrowing the given [`Mise`](crate::Mise) client.
    pub fn new(mise: &'a Mise) -> Self {
        Self { mise }
    }

    /// Install a Go version.
    ///
    /// `version` may be a prefix (`"1.23"`), exact version (`"1.23.0"`), or an
    /// alias such as `"latest"`.
    ///
    /// Invokes `mise install go@<version>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the installation command exits non-zero.
    pub async fn install(&self, version: &str) -> MiseResult<()> {
        self.mise
            .run_checked(["install", &format!("go@{version}")])
            .await?;
        Ok(())
    }

    /// Set the global Go version.
    ///
    /// Invokes `mise use --global go@<version>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero.
    pub async fn use_global(&self, version: &str) -> MiseResult<()> {
        self.mise
            .run_checked(["use", "--global", &format!("go@{version}")])
            .await?;
        Ok(())
    }

    /// Set the local (project-level) Go version.
    ///
    /// Invokes `mise use go@<version>` in the configured working directory.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero.
    pub async fn use_local(&self, version: &str) -> MiseResult<()> {
        self.mise
            .run_checked(["use", &format!("go@{version}")])
            .await?;
        Ok(())
    }

    /// List available Go versions.
    ///
    /// Invokes `mise ls-remote go` and returns the raw output lines.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the command exits non-zero.
    pub async fn list_versions(&self) -> MiseResult<Vec<String>> {
        let output = self.mise.run_checked(["ls-remote", "go"]).await?;
        let versions = output
            .stdout_trimmed()
            .lines()
            .map(|l| l.trim().to_owned())
            .filter(|l| !l.is_empty())
            .collect();
        Ok(versions)
    }

    /// Resolve the path to a binary for the active Go toolchain.
    ///
    /// When called with `"go"`, resolves the main `go` binary. Pass a specific
    /// binary name (e.g. `"gofmt"`, `"gopls"`) to resolve other Go toolchain
    /// binaries.
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

    /// Install a Go-based CLI tool via mise.
    ///
    /// `url` is the Go module path (e.g. `"github.com/jesseduffield/lazygit"`).
    /// `version` is the version tag or `"latest"`.
    ///
    /// Invokes `mise install go:<url>@<version>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed) if
    /// the installation command exits non-zero.
    pub async fn install_cli(&self, url: &str, version: &str) -> MiseResult<()> {
        let package = format!("{url}@{version}");
        self.mise
            .run_checked(["install", &format!("go:{package}")])
            .await?;
        Ok(())
    }
}
