//! Cache management via `mise cache clear`, `mise cache path`, and `mise cache prune`.
//!
//! Provides [`CachePruneRequest`] for configuring prune operations and a
//! suite of methods on [`Mise`] for clearing, querying, and pruning the
//! mise cache.

use camino::Utf8PathBuf;

use crate::client::Mise;
use crate::error::MiseResult;

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

/// Parameters for a cache prune operation.
#[derive(Debug, Clone, Default)]
pub struct CachePruneRequest {
    /// Only prune cache entries for these tools. Empty means all tools.
    pub tools: Vec<String>,
    /// If `true`, show what would be removed without actually removing it.
    pub dry_run: bool,
    /// If `true`, print verbose output.
    pub verbose: bool,
}

// ---------------------------------------------------------------------------
// Mise methods
// ---------------------------------------------------------------------------

impl Mise {
    /// Clear the entire mise cache.
    ///
    /// Invokes `mise cache clear`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    pub async fn cache_clear(&self) -> MiseResult<()> {
        self.run_checked(["cache", "clear"]).await?;
        Ok(())
    }

    /// Clear the mise cache for specific tools only.
    ///
    /// Invokes `mise cache clear <tools...>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    pub async fn cache_clear_tools(&self, tools: Vec<String>) -> MiseResult<()> {
        let mut args: Vec<String> = vec!["cache".into(), "clear".into()];
        args.extend(tools);
        self.run_checked(args).await?;
        Ok(())
    }

    /// Return the filesystem path to the mise cache directory.
    ///
    /// Invokes `mise cache path`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    pub async fn cache_path(&self) -> MiseResult<Utf8PathBuf> {
        let output = self.run_checked(["cache", "path"]).await?;
        Ok(Utf8PathBuf::from(output.stdout_trimmed().to_owned()))
    }

    /// Prune stale or unused entries from the mise cache.
    ///
    /// Accepts a [`CachePruneRequest`] that controls which tools to prune
    /// and whether to run in dry-run or verbose mode.
    ///
    /// Invokes `mise cache prune [flags] [tools...]`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    pub async fn cache_prune(&self, req: CachePruneRequest) -> MiseResult<()> {
        let mut args: Vec<String> = vec!["cache".into(), "prune".into()];

        if req.dry_run {
            args.push("--dry-run".into());
        }
        if req.verbose {
            args.push("--verbose".into());
        }

        args.extend(req.tools);
        self.run_checked(args).await?;
        Ok(())
    }
}
