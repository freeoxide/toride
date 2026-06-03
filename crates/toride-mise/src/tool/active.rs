//! Active (resolved) tool listing via `mise current`.
//!
//! Provides [`ActiveTool`], [`ListActiveRequest`], and [`Mise`] methods for
//! discovering which tool versions are currently in effect.

use serde::Deserialize;

use crate::client::Mise;
use crate::error::MiseResult;

// ---------------------------------------------------------------------------
// JSON response types
// ---------------------------------------------------------------------------

/// A single active tool version as reported by `mise current --output=json`.
#[derive(Debug, Clone, Deserialize)]
pub struct ActiveTool {
    /// The tool name (e.g. `"node"`).
    pub name: String,
    /// The version currently in use (e.g. `"22.1.0"`).
    pub version: String,
    /// The install path on disk.
    #[serde(default)]
    pub install_path: Option<String>,
    /// The source that resolved this version.
    #[serde(default)]
    pub source: Option<String>,
}

// ---------------------------------------------------------------------------
// ListActiveRequest
// ---------------------------------------------------------------------------

/// Parameters for a `mise current` invocation.
///
/// Construct with [`ListActiveRequest::new`] and chain builder methods.
#[derive(Debug, Clone, Default)]
pub struct ListActiveRequest {
    /// Only list the active version for this specific tool.
    pub tool: Option<String>,
    /// Include the source that resolved each tool version.
    pub show_source: bool,
}

impl ListActiveRequest {
    /// Create a new `ListActiveRequest` listing all active tools.
    pub fn new() -> Self {
        Self::default()
    }

    /// Only list the active version for a specific tool.
    pub fn tool(mut self, tool: impl Into<String>) -> Self {
        self.tool = Some(tool.into());
        self
    }

    /// Include the source that resolved each tool version.
    pub fn show_source(mut self) -> Self {
        self.show_source = true;
        self
    }
}

// ---------------------------------------------------------------------------
// Mise methods
// ---------------------------------------------------------------------------

impl Mise {
    /// List all currently active (resolved) tool versions.
    ///
    /// Invokes `mise current --output=json`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`] if the output cannot be deserialised.
    pub async fn list_active(&self) -> MiseResult<Vec<ActiveTool>> {
        self.run_json_vec_safe(["current", "--output=json"]).await
    }

    /// List active tools using a full [`ListActiveRequest`].
    ///
    /// Builds the complete `mise current` command with all flags from the
    /// request struct.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`] if the output cannot be deserialised.
    pub async fn list_active_with(&self, req: &ListActiveRequest) -> MiseResult<Vec<ActiveTool>> {
        let mut args: Vec<String> = Vec::new();
        args.push("current".into());

        if req.show_source {
            args.push("--source".into());
        }

        args.push("--output=json".into());

        if let Some(ref tool) = req.tool {
            args.push(tool.clone());
        }

        self.run_json_vec_safe(args).await
    }
}
