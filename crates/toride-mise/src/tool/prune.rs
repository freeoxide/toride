//! Prune unused tool installations via `mise prune`.
//!
//! Provides [`PruneRequest`], [`PrunePlan`], and [`Mise`] methods for removing
//! tool versions that are no longer referenced by any config file.

use camino::Utf8PathBuf;

use crate::client::Mise;
use crate::error::MiseResult;

// ---------------------------------------------------------------------------
// PrunePlan
// ---------------------------------------------------------------------------

/// A plan of paths that would be removed by a prune operation.
///
/// Returned by [`Mise::prune_dry_run`] so callers can inspect what would be
/// deleted before committing.
#[derive(Debug, Clone, Default)]
pub struct PrunePlan {
    /// Filesystem paths that would be removed.
    pub paths: Vec<Utf8PathBuf>,
}

impl PrunePlan {
    /// Create an empty prune plan.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a prune plan from a list of paths.
    pub fn from_paths(paths: impl IntoIterator<Item = impl Into<Utf8PathBuf>>) -> Self {
        Self {
            paths: paths.into_iter().map(Into::into).collect(),
        }
    }

    /// Return the number of paths that would be pruned.
    pub fn len(&self) -> usize {
        self.paths.len()
    }

    /// Return `true` if there are no paths to prune.
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }
}

// ---------------------------------------------------------------------------
// PruneRequest
// ---------------------------------------------------------------------------

/// Parameters for a `mise prune` invocation.
///
/// Construct with [`PruneRequest::new`] and chain builder methods.
#[derive(Debug, Clone, Default)]
pub struct PruneRequest {
    /// Only prune these specific tools. Empty means prune all unused tools.
    pub tools: Vec<String>,
    /// Perform a dry run without removing anything.
    pub dry_run: bool,
    /// Only prune tool installations (not config references).
    pub only_tools: bool,
    /// Only prune stale config references (not tool installations).
    pub only_configs: bool,
    /// Custom exit code to use when a dry-run reports changes (mise internal).
    pub dry_run_code: Option<i32>,
}

impl PruneRequest {
    /// Create a new `PruneRequest` for the given tools.
    ///
    /// Pass an empty iterator to prune all unused tools.
    pub fn new(tools: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            tools: tools.into_iter().map(Into::into).collect(),
            ..Self::default()
        }
    }

    /// Perform a dry run without removing anything.
    pub fn dry_run(mut self) -> Self {
        self.dry_run = true;
        self
    }

    /// Only prune tool installations.
    pub fn only_tools(mut self) -> Self {
        self.only_tools = true;
        self
    }

    /// Only prune stale config references.
    pub fn only_configs(mut self) -> Self {
        self.only_configs = true;
        self
    }

    /// Set a custom exit code for dry-run mode.
    pub fn dry_run_code(mut self, code: i32) -> Self {
        self.dry_run_code = Some(code);
        self
    }
}

// ---------------------------------------------------------------------------
// Mise methods
// ---------------------------------------------------------------------------

impl Mise {
    /// Prune unused tool installations (simple convenience wrapper).
    ///
    /// If `tools` is non-empty, only the named tools are pruned. Otherwise all
    /// unused installations are removed.
    ///
    /// Invokes `mise prune [tools…]`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the prune operation fails.
    pub async fn prune_tools(&self, tools: &[&str]) -> MiseResult<()> {
        let mut args: Vec<&str> = vec!["prune", "--only-tools"];
        args.extend_from_slice(tools);
        self.run_checked(args).await?;
        Ok(())
    }

    /// Prune stale config references.
    ///
    /// Invokes `mise prune --only-configs`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the prune operation fails.
    pub async fn prune_configs(&self) -> MiseResult<()> {
        self.run_checked(["prune", "--only-configs"]).await?;
        Ok(())
    }

    /// Prune unused tool installations (simple convenience wrapper).
    ///
    /// If `tools` is non-empty, only the named tools are pruned. Otherwise all
    /// unused installations are removed.
    ///
    /// Invokes `mise prune [tools…]`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the prune operation fails.
    pub async fn prune(&self, tools: &[&str]) -> MiseResult<()> {
        let mut args: Vec<&str> = vec!["prune"];
        args.extend_from_slice(tools);
        self.run_checked(args).await?;
        Ok(())
    }

    /// Prune unused tool installations using a full [`PruneRequest`].
    ///
    /// Builds the complete `mise prune` command with all flags from the
    /// request struct.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the prune operation fails.
    pub async fn prune_with(&self, req: &PruneRequest) -> MiseResult<()> {
        let mut args: Vec<String> = Vec::new();
        args.push("prune".into());

        if req.dry_run {
            args.push("--dry-run".into());
        }
        if req.only_tools {
            args.push("--only-tools".into());
        }
        if req.only_configs {
            args.push("--only-configs".into());
        }

        for tool in &req.tools {
            args.push(tool.clone());
        }

        self.run_checked(args).await?;
        Ok(())
    }

    /// Perform a dry-run prune and return the paths that would be removed.
    ///
    /// Invokes `mise prune --dry-run` and parses the output into a
    /// [`PrunePlan`].
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    pub async fn prune_dry_run(&self, tools: &[&str]) -> MiseResult<PrunePlan> {
        let mut args: Vec<&str> = vec!["prune", "--dry-run"];
        args.extend_from_slice(tools);

        let output = self.run_checked(args).await?;
        let paths: Vec<Utf8PathBuf> = output
            .stdout_trimmed()
            .lines()
            .filter(|line| !line.is_empty())
            .map(Utf8PathBuf::from)
            .collect();

        Ok(PrunePlan { paths })
    }
}
