//! Tool upgrade via `mise upgrade`.
//!
//! Provides [`UpgradeRequest`] and [`Mise`] methods for upgrading installed
//! tools to newer versions, plus enriched outdated-checking helpers.

use serde::Deserialize;

use crate::client::Mise;
use crate::error::MiseResult;

// ---------------------------------------------------------------------------
// JSON response types
// ---------------------------------------------------------------------------

/// A single outdated tool entry returned by `mise outdated --output=json`.
#[derive(Debug, Clone, Deserialize)]
pub struct OutdatedTool {
    /// The tool name (e.g. `"node"`).
    pub name: String,
    /// The plugin/backend providing the tool (e.g. `"core"`, `"npm"`).
    #[serde(default, alias = "plugin")]
    pub backend: Option<String>,
    /// The version string as requested in config (e.g. `"22"`).
    #[serde(default)]
    pub requested: Option<String>,
    /// The currently installed version.
    #[serde(default)]
    pub current: Option<String>,
    /// The latest available version.
    #[serde(default)]
    pub latest: Option<String>,
    /// The install path on disk.
    #[serde(default)]
    pub install_path: Option<String>,
}

// ---------------------------------------------------------------------------
// UpgradeRequest
// ---------------------------------------------------------------------------

/// Parameters for a `mise upgrade` invocation.
///
/// Construct with [`UpgradeRequest::new`] and chain builder methods.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default)]
pub struct UpgradeRequest {
    /// Tool spec strings to upgrade. Empty means upgrade all outdated tools.
    pub tools: Vec<String>,
    /// Bump the version in the config file to the latest after upgrade.
    pub bump: bool,
    /// Perform a dry run without actually upgrading.
    pub dry_run: bool,
    /// Also upgrade tools that are not currently active.
    pub inactive: bool,
    /// Only upgrade tools whose install directory is on the local machine.
    pub local_only: bool,
    /// Maximum number of parallel upgrade jobs.
    pub jobs: Option<usize>,
    /// Custom exit code to use when a dry-run reports changes (mise internal).
    pub dry_run_code: Option<i32>,
    /// Print raw output without formatting.
    pub raw: bool,
    /// Tool names to exclude from the upgrade.
    pub exclude: Vec<String>,
    /// Only consider releases published at least this long ago (e.g. `"7d"`).
    pub minimum_release_age: Option<String>,
}

impl UpgradeRequest {
    /// Create a new `UpgradeRequest` for the given tool specs.
    ///
    /// Pass an empty iterator to upgrade all outdated tools.
    pub fn new(tools: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            tools: tools.into_iter().map(Into::into).collect(),
            ..Self::default()
        }
    }

    /// Bump the version in the config file to the latest.
    pub fn bump(mut self) -> Self {
        self.bump = true;
        self
    }

    /// Perform a dry run without upgrading.
    pub fn dry_run(mut self) -> Self {
        self.dry_run = true;
        self
    }

    /// Also upgrade inactive tools.
    pub fn inactive(mut self) -> Self {
        self.inactive = true;
        self
    }

    /// Only upgrade locally-installed tools.
    pub fn local_only(mut self) -> Self {
        self.local_only = true;
        self
    }

    /// Set the maximum number of parallel upgrade jobs.
    pub fn jobs(mut self, n: usize) -> Self {
        self.jobs = Some(n);
        self
    }

    /// Set a custom exit code for dry-run mode.
    pub fn dry_run_code(mut self, code: i32) -> Self {
        self.dry_run_code = Some(code);
        self
    }

    /// Print raw output without formatting.
    pub fn raw(mut self) -> Self {
        self.raw = true;
        self
    }

    /// Exclude specific tools from the upgrade.
    pub fn exclude(mut self, tools: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.exclude.extend(tools.into_iter().map(Into::into));
        self
    }

    /// Only consider releases published at least this long ago (e.g. `"7d"`).
    pub fn minimum_release_age(mut self, age: impl Into<String>) -> Self {
        self.minimum_release_age = Some(age.into());
        self
    }
}

// ---------------------------------------------------------------------------
// Mise methods
// ---------------------------------------------------------------------------

impl Mise {
    /// Upgrade an installed tool to the latest available version (simple
    /// convenience wrapper).
    ///
    /// If `tool` is `None`, all installed tools are upgraded.
    ///
    /// Invokes `mise upgrade [tool]`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the upgrade fails.
    pub async fn upgrade(&self, tool: Option<&str>) -> MiseResult<()> {
        match tool {
            Some(t) => {
                self.run_checked(["upgrade", t]).await?;
            }
            None => {
                self.run_checked(["upgrade"]).await?;
            }
        }
        Ok(())
    }

    /// Upgrade tool versions using a full [`UpgradeRequest`].
    ///
    /// Builds the complete `mise upgrade` command with all flags from the
    /// request struct.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the upgrade fails.
    pub async fn upgrade_with(&self, req: &UpgradeRequest) -> MiseResult<()> {
        let mut args: Vec<String> = Vec::new();
        args.push("upgrade".into());

        if req.bump {
            args.push("--bump".into());
        }
        if req.dry_run {
            args.push("--dry-run".into());
        }
        if req.inactive {
            args.push("--inactive".into());
        }
        if req.local_only {
            args.push("--local-only".into());
        }
        if req.raw {
            args.push("--raw".into());
        }
        if let Some(ref age) = req.minimum_release_age {
            args.push("--minimum-release-age".into());
            args.push(age.clone());
        }
        if let Some(jobs) = req.jobs {
            args.push("--jobs".into());
            args.push(jobs.to_string());
        }

        for exc in &req.exclude {
            args.push("--exclude".into());
            args.push(exc.clone());
        }

        for tool in &req.tools {
            args.push(tool.clone());
        }

        self.run_checked(args).await?;
        Ok(())
    }

    /// List all installed tools that have newer versions available.
    ///
    /// Invokes `mise outdated --json` and returns structured results.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`] if the output cannot be deserialised.
    pub async fn outdated(&self) -> MiseResult<Vec<OutdatedTool>> {
        self.run_json(["outdated", "--json"]).await
    }

    /// Check whether a specific tool has a newer version available.
    ///
    /// Invokes `mise outdated <tool> --json`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`] if the output cannot be deserialised.
    pub async fn outdated_tool(&self, tool: &str) -> MiseResult<Vec<OutdatedTool>> {
        self.run_json(["outdated", tool, "--json"]).await
    }

    /// List outdated tools that are installed locally.
    ///
    /// Invokes `mise outdated --local --json`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`] if the output cannot be deserialised.
    pub async fn outdated_local(&self) -> MiseResult<Vec<OutdatedTool>> {
        self.run_json(["outdated", "--local", "--json"]).await
    }

    /// List outdated tools that are currently inactive.
    ///
    /// Invokes `mise outdated --inactive --json`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`] if the output cannot be deserialised.
    pub async fn outdated_inactive(&self) -> MiseResult<Vec<OutdatedTool>> {
        self.run_json(["outdated", "--inactive", "--json"]).await
    }

    /// Upgrade the given tools to their latest versions.
    ///
    /// Convenience wrapper that builds an [`UpgradeRequest`] from a list of
    /// tool spec strings and delegates to [`Mise::upgrade_with`].
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the upgrade fails.
    pub async fn upgrade_tools(&self, tools: Vec<String>) -> MiseResult<()> {
        let req = UpgradeRequest::new(tools);
        self.upgrade_with(&req).await
    }

    /// Upgrade all outdated tools and bump the version in the config file.
    ///
    /// Invokes `mise upgrade --bump`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the upgrade fails.
    pub async fn upgrade_bump(&self) -> MiseResult<()> {
        let req = UpgradeRequest::new([] as [String; 0]).bump();
        self.upgrade_with(&req).await
    }

    /// Perform a dry-run upgrade of all outdated tools.
    ///
    /// Invokes `mise upgrade --dry-run`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the upgrade fails.
    pub async fn upgrade_dry_run(&self) -> MiseResult<()> {
        let req = UpgradeRequest::new([] as [String; 0]).dry_run();
        self.upgrade_with(&req).await
    }
}
