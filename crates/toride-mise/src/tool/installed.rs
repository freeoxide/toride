//! Installed tool introspection via `mise ls` and related commands.
//!
//! Provides [`ToolStatus`], [`ListToolsRequest`], and a suite of methods on
//! [`Mise`] for listing, filtering, and inspecting installed tools.

use serde::Deserialize;

use crate::client::Mise;
use crate::error::MiseResult;

// ---------------------------------------------------------------------------
// JSON response types
// ---------------------------------------------------------------------------

/// Status of a single installed tool version as reported by `mise ls --json`.
#[derive(Debug, Clone, Deserialize)]
pub struct ToolStatus {
    /// The tool name (e.g. `"node"`).
    pub name: String,
    /// The installed version string (e.g. `"22.1.0"`).
    #[serde(default)]
    pub version: Option<String>,
    /// The source that requested this tool (e.g. `".mise.toml"`, `"~/.config/mise/config.toml"`).
    #[serde(default)]
    pub source: Option<SourceInfo>,
    /// Whether this version is the one currently in use / active.
    #[serde(default)]
    pub active: Option<bool>,
    /// The install path on disk.
    #[serde(default)]
    pub install_path: Option<String>,
    /// Whether the tool is installed on disk.
    #[serde(default)]
    pub installed: Option<bool>,
    /// Whether the tool is referenced in config but not yet installed.
    #[serde(default)]
    pub missing: Option<bool>,
    /// Whether a newer version is available.
    #[serde(default)]
    pub outdated: Option<bool>,
    /// The requested version string as written in the source config.
    #[serde(default)]
    pub requested: Option<String>,
}

/// Describes where a tool version requirement originated.
#[derive(Debug, Clone, Deserialize)]
pub struct SourceInfo {
    /// The file path of the source config.
    #[serde(default)]
    pub path: Option<String>,
    /// The raw version string as written in the source.
    #[serde(default)]
    pub requested: Option<String>,
}

// ---------------------------------------------------------------------------
// ListToolsRequest
// ---------------------------------------------------------------------------

/// Parameters for a `mise ls` invocation.
///
/// Construct with [`ListToolsRequest::new`] and chain builder methods to
/// control which tools are included in the listing.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default)]
pub struct ListToolsRequest {
    /// Only include tools that are installed on disk.
    pub installed_only: bool,
    /// Only include the currently active (resolved) version for each tool.
    pub current_only: bool,
    /// Only include tools from the global config.
    pub global_only: bool,
    /// Only include tools referenced in config but not yet installed.
    pub missing_only: bool,
    /// Include an outdated flag in results.
    pub outdated: bool,
    /// Filter results to tools whose name starts with this prefix.
    pub prefix: Option<String>,
    /// Only include tools whose install directory is on the local machine.
    pub local_only: bool,
    /// Include tools from all config sources (not just the current project).
    pub all_sources: bool,
    /// Only include tools that are safe to prune (unused / stale installs).
    pub prunable_only: bool,
}

impl ListToolsRequest {
    /// Create a new `ListToolsRequest` with default (no filter) settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Only include installed tools.
    pub fn installed_only(mut self) -> Self {
        self.installed_only = true;
        self
    }

    /// Only include the currently active version for each tool.
    pub fn current_only(mut self) -> Self {
        self.current_only = true;
        self
    }

    /// Only include tools from the global config.
    pub fn global_only(mut self) -> Self {
        self.global_only = true;
        self
    }

    /// Only include tools not yet installed.
    pub fn missing_only(mut self) -> Self {
        self.missing_only = true;
        self
    }

    /// Include outdated status in results.
    pub fn outdated(mut self) -> Self {
        self.outdated = true;
        self
    }

    /// Filter results to tools matching this name prefix.
    pub fn prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    /// Only include tools whose install directory is on the local machine.
    pub fn local_only(mut self) -> Self {
        self.local_only = true;
        self
    }

    /// Include tools from all config sources, not just the current project.
    pub fn all_sources(mut self) -> Self {
        self.all_sources = true;
        self
    }

    /// Only include tools that are safe to prune.
    pub fn prunable_only(mut self) -> Self {
        self.prunable_only = true;
        self
    }
}

// ---------------------------------------------------------------------------
// Mise methods
// ---------------------------------------------------------------------------

impl Mise {
    /// List all known tool versions (installed, missing, and active).
    ///
    /// Invokes `mise ls --json`. When mise returns `{}` (no tools installed),
    /// returns an empty vec.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`] if the output cannot be deserialised.
    pub async fn list(&self) -> MiseResult<Vec<ToolStatus>> {
        self.run_json_vec_safe(["ls", "--json"]).await
    }

    /// List tools using a full [`ListToolsRequest`].
    ///
    /// Builds the complete `mise ls` command with all filter flags from the
    /// request struct.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`] if the output cannot be deserialised.
    pub async fn list_with(&self, req: &ListToolsRequest) -> MiseResult<Vec<ToolStatus>> {
        let mut args: Vec<String> = Vec::new();
        args.push("ls".into());

        if req.installed_only {
            args.push("--installed".into());
        }
        if req.current_only {
            args.push("--current".into());
        }
        if req.global_only {
            args.push("--global".into());
        }
        if req.missing_only {
            args.push("--missing".into());
        }
        if req.outdated {
            args.push("--outdated".into());
        }
        if req.local_only {
            args.push("--local-only".into());
        }
        if req.all_sources {
            args.push("--all-sources".into());
        }
        if req.prunable_only {
            args.push("--prunable".into());
        }

        args.push("--json".into());

        // Optional tool name prefix filter.
        if let Some(ref prefix) = req.prefix {
            args.push(prefix.clone());
        }

        self.run_json_vec_safe(args).await
    }

    /// List only installed tool versions.
    ///
    /// Invokes `mise ls --installed --json`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`] if the output cannot be deserialised.
    pub async fn list_installed(&self) -> MiseResult<Vec<ToolStatus>> {
        self.run_json_vec_safe(["ls", "--installed", "--json"])
            .await
    }

    /// List currently active (resolved) tool versions.
    ///
    /// Invokes `mise ls --current --json`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`] if the output cannot be deserialised.
    pub async fn list_current(&self) -> MiseResult<Vec<ToolStatus>> {
        self.run_json_vec_safe(["ls", "--current", "--json"]).await
    }

    /// List tools that are referenced in config but not yet installed.
    ///
    /// Invokes `mise ls --missing --json`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`] if the output cannot be deserialised.
    pub async fn list_missing(&self) -> MiseResult<Vec<ToolStatus>> {
        self.run_json_vec_safe(["ls", "--missing", "--json"]).await
    }

    /// List installed tools that have newer versions available.
    ///
    /// Invokes `mise outdated --json`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`] if the output cannot be deserialised.
    pub async fn list_outdated(&self) -> MiseResult<Vec<ToolStatus>> {
        self.run_json_vec_safe(["outdated", "--json"]).await
    }

    /// List tools that are safe to prune (unused or stale installs).
    ///
    /// Invokes `mise ls --prunable --json`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`] if the output cannot be deserialised.
    pub async fn list_prunable(&self) -> MiseResult<Vec<ToolStatus>> {
        self.run_json_vec_safe(["ls", "--prunable", "--json"]).await
    }

    /// Return detailed status for a single tool.
    ///
    /// Invokes `mise ls <tool> --json`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`] if the output cannot be deserialised.
    pub async fn tool_info(&self, tool: &str) -> MiseResult<Vec<ToolStatus>> {
        self.run_json_vec_safe(["ls", tool, "--json"]).await
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use toride_runner::{CommandOutput, FakeRunner};

    use crate::client::Mise;

    fn build_mise(fake: Arc<FakeRunner>) -> Mise {
        Mise::builder()
            .runner(fake as Arc<dyn toride_runner::AsyncRunner>)
            .binary(crate::binary::MiseBinary::from_path("/usr/bin/mise"))
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn test_list_parses_json() {
        let json = r#"[{"name":"node","version":"22.1.0","source":{"path":".mise.toml","requested":"22"},"active":true,"install_path":"/home/user/.local/share/mise/installs/node/22.1.0"}]"#;
        let fake = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout(json)));
        let mise = build_mise(fake.clone());

        let tools = mise.list().await.unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "node");
        assert_eq!(tools[0].version.as_deref(), Some("22.1.0"));
        assert_eq!(tools[0].active, Some(true));
        assert!(tools[0].source.is_some());
        let src = tools[0].source.as_ref().unwrap();
        assert_eq!(src.path.as_deref(), Some(".mise.toml"));
        assert_eq!(src.requested.as_deref(), Some("22"));

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].args.contains(&"ls".to_string()));
        assert!(calls[0].args.contains(&"--json".to_string()));
    }

    #[tokio::test]
    async fn test_list_missing() {
        let json = r#"[{"name":"python","version":null,"source":null,"active":false,"install_path":null}]"#;
        let fake = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout(json)));
        let mise = build_mise(fake.clone());

        let tools = mise.list_missing().await.unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "python");

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].args.contains(&"ls".to_string()));
        assert!(calls[0].args.contains(&"--missing".to_string()));
        assert!(calls[0].args.contains(&"--json".to_string()));
    }
}
