//! Mise binary bootstrap / installation support.
//!
//! Provides types and helpers for ensuring the `mise` binary is available on
//! the host. The primary entry-point is [`MiseBinary::ensure_installed`].

use camino::Utf8PathBuf;

use super::discovery::MiseBinary;
use crate::error::{MiseError, MiseResult};

// ---------------------------------------------------------------------------
// BootstrapOptions
// ---------------------------------------------------------------------------

/// Options controlling how the `mise` binary should be installed.
#[derive(Debug, Clone, Default)]
pub struct BootstrapOptions {
    /// Directory where the binary should be placed.
    ///
    /// When `None`, the default discovery locations are used
    /// (e.g. `~/.local/bin`).
    pub target_dir: Option<Utf8PathBuf>,

    /// Specific version to install (e.g. `"2025.4.0"`).
    ///
    /// When `None`, the latest release is implied.
    pub version: Option<String>,
}

// ---------------------------------------------------------------------------
// BootstrapMethod
// ---------------------------------------------------------------------------

/// Strategy for obtaining the `mise` binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapMethod {
    /// Download a release tarball from GitHub.
    GithubRelease,
    /// Do not attempt installation; return a hint instead.
    HintOnly,
}

// ---------------------------------------------------------------------------
// install_mise
// ---------------------------------------------------------------------------

/// Attempt to install the `mise` binary using the given method.
///
/// # Errors
///
/// - [`MiseError::BootstrapHint`] when `method` is [`BootstrapMethod::HintOnly`].
/// - [`MiseError::BootstrapFailed`] when the chosen method cannot complete.
pub async fn install_mise(method: BootstrapMethod, opts: BootstrapOptions) -> MiseResult<Utf8PathBuf> {
    match method {
        BootstrapMethod::GithubRelease => Err(MiseError::BootstrapFailed {
            reason: "GitHub release download is not yet implemented. \
                     Install mise with your package manager or see \
                     https://mise.jdx.dev/getting-started.html"
                .into(),
        }),
        BootstrapMethod::HintOnly => Err(MiseError::BootstrapHint {
            message: format!(
                "mise is not installed.\n\
                 \n\
                 Install it with one of:\n\
                 \n\
                   curl -fsSL https://mise.run | sh\n\
                   brew install mise\n\
                   cargo install mise\n\
                 \n\
                 Or visit https://mise.jdx.dev/getting-started.html for more options.{}",
                opts.version
                    .as_deref()
                    .map(|v| format!("\n\nRequested version: {v}"))
                    .unwrap_or_default()
            ),
        }),
    }
}

// ---------------------------------------------------------------------------
// MiseBinary::ensure_installed (impl block)
// ---------------------------------------------------------------------------

impl MiseBinary {
    /// Ensure that the `mise` binary is available on the host.
    ///
    /// This first attempts normal discovery via [`MiseBinary::discover`].
    /// If the binary is found, it is returned immediately.  Otherwise a
    /// [`MiseError::BootstrapHint`] error is returned with installation
    /// instructions.
    ///
    /// For automated bootstrapping, match on [`MiseError::BootstrapHint`]
    /// and call [`install_mise`] with the desired [`BootstrapMethod`].
    #[allow(clippy::unused_async)]
    pub async fn ensure_installed() -> MiseResult<Self> {
        match Self::discover() {
            Ok(bin) => Ok(bin),
            Err(MiseError::BinaryNotFound) => Err(MiseError::BootstrapHint {
                message: String::from(
                    "mise is not installed.\n\
                     \n\
                     Install it with one of:\n\
                     \n\
                       curl -fsSL https://mise.run | sh\n\
                       brew install mise\n\
                       cargo install mise\n\
                     \n\
                     Or visit https://mise.jdx.dev/getting-started.html for more options.",
                ),
            }),
            Err(other) => Err(other),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_options_default_has_none_fields() {
        let opts = BootstrapOptions::default();
        assert!(opts.target_dir.is_none());
        assert!(opts.version.is_none());
    }

    #[tokio::test]
    async fn install_mise_hint_only_returns_hint_error() {
        let result = install_mise(BootstrapMethod::HintOnly, BootstrapOptions::default()).await;
        let Err(MiseError::BootstrapHint { .. }) = result else {
            panic!("expected BootstrapHint error, got {result:?}");
        };
    }

    #[tokio::test]
    async fn install_mise_github_release_returns_not_implemented() {
        let result = install_mise(BootstrapMethod::GithubRelease, BootstrapOptions::default()).await;
        let Err(MiseError::BootstrapFailed { reason }) = result else {
            panic!("expected BootstrapFailed error, got {result:?}");
        };
        assert!(reason.contains("not yet implemented"));
    }

    #[tokio::test]
    async fn install_mise_hint_includes_requested_version() {
        let opts = BootstrapOptions {
            version: Some("2025.4.0".into()),
            ..Default::default()
        };
        let result = install_mise(BootstrapMethod::HintOnly, opts).await;
        let Err(MiseError::BootstrapHint { message }) = result else {
            panic!("expected BootstrapHint error");
        };
        assert!(message.contains("2025.4.0"));
    }
}
