//! Active (resolved) tool listing via `mise current`.
//!
//! Provides [`ActiveTool`], [`ListActiveRequest`], and [`Mise`] methods for
//! discovering which tool versions are currently in effect.

use serde::Deserialize;

use crate::client::Mise;
use crate::error::MiseResult;

/// A single active tool version as reported by `mise current`.
#[derive(Debug, Clone, Deserialize)]
pub struct ActiveTool {
    /// The tool name (e.g. `"node"`).
    pub name: String,
    /// The version currently in use (e.g. `"22.1.0"`).
    pub version: String,
    /// The install path on disk. `mise current` does not report this, so it
    /// is `None` for every parsed row.
    #[serde(default)]
    pub install_path: Option<String>,
    /// The source that resolved this version. `mise current` does not report
    /// this, so it is `None` for every parsed row.
    #[serde(default)]
    pub source: Option<String>,
}

/// Parameters for a `mise current` invocation.
///
/// Construct with [`ListActiveRequest::new`] and chain builder methods.
#[derive(Debug, Clone, Default)]
pub struct ListActiveRequest {
    /// Only list the active version for this specific tool.
    pub tool: Option<String>,
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
}

fn parse_current_lines(stdout: &str) -> Vec<ActiveTool> {
    stdout
        .lines()
        .filter_map(|line| {
            let (name, version) = line.trim().split_once(char::is_whitespace)?;
            let version = version.trim();
            (!name.is_empty() && !version.is_empty()).then(|| ActiveTool {
                name: name.to_owned(),
                version: version.to_owned(),
                install_path: None,
                source: None,
            })
        })
        .collect()
}

impl Mise {
    /// List all currently active (resolved) tool versions.
    ///
    /// Invokes `mise current`, which prints one `<tool> <version>` line per
    /// active tool; each line becomes one [`ActiveTool`] row.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::error::MiseError::CommandFailed) if the command exits non-zero.
    pub async fn list_active(&self) -> MiseResult<Vec<ActiveTool>> {
        let output = self.run_checked(["current"]).await?;
        Ok(parse_current_lines(output.stdout_trimmed()))
    }

    /// List active tools using a full [`ListActiveRequest`].
    ///
    /// Invokes `mise current [tool]` and parses the plain `<tool> <version>`
    /// lines.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::error::MiseError::CommandFailed) if the command exits non-zero.
    pub async fn list_active_with(&self, req: &ListActiveRequest) -> MiseResult<Vec<ActiveTool>> {
        let mut args: Vec<String> = vec!["current".into()];
        if let Some(ref tool) = req.tool {
            args.push(tool.clone());
        }

        let output = self.run_checked(args).await?;
        Ok(parse_current_lines(output.stdout_trimmed()))
    }
}

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
    async fn list_active_parses_tool_version_lines() {
        let fake = Arc::new(
            FakeRunner::new()
                .push_response(CommandOutput::from_stdout("node 22.1.0\npython 3.12.5\n")),
        );
        let mise = build_mise(fake.clone());

        let tools = mise.list_active().await.unwrap();
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].name, "node");
        assert_eq!(tools[0].version, "22.1.0");
        assert_eq!(tools[1].name, "python");
        assert_eq!(tools[1].version, "3.12.5");

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].args, ["current"]);
    }

    #[tokio::test]
    async fn list_active_with_passes_the_tool_operand() {
        let fake =
            Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout("node 22.1.0\n")));
        let mise = build_mise(fake.clone());

        let tools = mise
            .list_active_with(&super::ListActiveRequest::new().tool("node"))
            .await
            .unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "node");

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].args, ["current", "node"]);
    }

    #[tokio::test]
    async fn list_active_skips_unparseable_lines() {
        let fake = Arc::new(
            FakeRunner::new()
                .push_response(CommandOutput::from_stdout("node 22.1.0\nno-version\n")),
        );
        let mise = build_mise(fake);

        let tools = mise.list_active().await.unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "node");
    }
}
