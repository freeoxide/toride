//! Remote tool version queries via `mise ls-remote` and `mise latest`.
//!
//! Provides [`ListRemoteRequest`], [`RemoteVersion`], and [`Mise`] methods for
//! discovering versions available in upstream registries or already fetched
//! locally.

use serde::Deserialize;

use crate::client::Mise;
use crate::error::MiseResult;

// ---------------------------------------------------------------------------
// JSON response types
// ---------------------------------------------------------------------------

/// A single version returned by `mise ls-remote --json`.
#[derive(Debug, Clone, Deserialize)]
pub struct RemoteVersion {
    /// The version string (e.g. `"22.1.0"`).
    pub version: String,
    /// The install status of this version (mise may report `"installed"`,
    /// `"not_installed"`, or similar).
    #[serde(default)]
    pub install_status: Option<String>,
    /// When this version was published (ISO 8601), if reported by mise.
    #[serde(default)]
    pub created_at: Option<String>,
}

// ---------------------------------------------------------------------------
// ListRemoteRequest
// ---------------------------------------------------------------------------

/// Parameters for a `mise ls-remote` invocation.
///
/// Construct with [`ListRemoteRequest::new`] and chain builder methods.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct ListRemoteRequest {
    /// The tool to query (e.g. `"node"`, `"python"`).
    pub tool: String,
    /// Only show versions matching this prefix (e.g. `"22"`).
    pub prefix: Option<String>,
    /// Show all versions including deprecated ones.
    pub all: bool,
    /// Include pre-release versions.
    pub prerelease: bool,
    /// Only consider releases published at least this long ago (e.g. `"7d"`).
    pub minimum_release_age: Option<String>,
    /// Fail if metadata for a tool cannot be fetched (strict mode).
    pub strict_metadata: bool,
    /// Do not query the versions host; use cached data only.
    pub no_versions_host: bool,
}

impl ListRemoteRequest {
    /// Create a new `ListRemoteRequest` for the given tool.
    pub fn new(tool: impl Into<String>) -> Self {
        Self {
            tool: tool.into(),
            prefix: None,
            all: false,
            prerelease: false,
            minimum_release_age: None,
            strict_metadata: false,
            no_versions_host: false,
        }
    }

    /// Filter results to versions matching this prefix.
    pub fn prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    /// Show all versions including deprecated ones.
    pub fn all(mut self) -> Self {
        self.all = true;
        self
    }

    /// Include pre-release versions.
    pub fn prerelease(mut self) -> Self {
        self.prerelease = true;
        self
    }

    /// Only consider releases published at least this long ago (e.g. `"7d"`).
    pub fn minimum_release_age(mut self, age: impl Into<String>) -> Self {
        self.minimum_release_age = Some(age.into());
        self
    }

    /// Fail if metadata for a tool cannot be fetched.
    pub fn strict_metadata(mut self) -> Self {
        self.strict_metadata = true;
        self
    }

    /// Do not query the versions host; use cached data only.
    pub fn no_versions_host(mut self) -> Self {
        self.no_versions_host = true;
        self
    }
}

// ---------------------------------------------------------------------------
// Mise methods
// ---------------------------------------------------------------------------

impl Mise {
    /// List all remote versions available for a tool (simple convenience
    /// wrapper).
    ///
    /// Invokes `mise ls-remote <tool> --json`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`] if the output cannot be deserialised.
    pub async fn list_remote(&self, tool: &str) -> MiseResult<Vec<RemoteVersion>> {
        self.run_json(["ls-remote", tool, "--json"]).await
    }

    /// List remote versions using a full [`ListRemoteRequest`].
    ///
    /// Builds the complete `mise ls-remote` command with all flags from the
    /// request struct.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`] if the output cannot be deserialised.
    pub async fn list_remote_with(
        &self,
        req: &ListRemoteRequest,
    ) -> MiseResult<Vec<RemoteVersion>> {
        let mut args: Vec<String> = Vec::new();
        args.push("ls-remote".into());

        if req.all {
            args.push("--all".into());
        }
        if req.prerelease {
            args.push("--prerelease".into());
        }
        if let Some(ref age) = req.minimum_release_age {
            args.push("--minimum-release-age".into());
            args.push(age.clone());
        }
        if req.strict_metadata {
            args.push("--strict".into());
        }
        if req.no_versions_host {
            args.push("--no-versions-host".into());
        }

        // Tool name with optional version prefix.
        if let Some(ref prefix) = req.prefix {
            args.push(format!("{}@{}", req.tool, prefix));
        } else {
            args.push(req.tool.clone());
        }

        args.push("--json".into());

        self.run_json(args).await
    }

    /// Return the latest available remote version for a tool.
    ///
    /// Invokes `mise latest <tool>` and returns the version string.
    /// Note: real mise `latest` does not support `--json`; it outputs plain text.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    pub async fn latest(&self, tool: &str) -> MiseResult<String> {
        let output = self.run_checked(["latest", tool]).await?;
        Ok(output.stdout_trimmed().to_owned())
    }

    /// Return the latest *installed* version for a tool.
    ///
    /// Invokes `mise latest --installed <tool>` and returns the version string.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    pub async fn latest_installed(&self, tool: &str) -> MiseResult<String> {
        let output = self.run_checked(["latest", "--installed", tool]).await?;
        Ok(output.stdout_trimmed().to_owned())
    }

    /// List remote versions matching a prefix for a tool.
    ///
    /// Convenience wrapper around [`Mise::list_remote_with`] that constructs a
    /// [`ListRemoteRequest`] with the given prefix.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`] if the output cannot be deserialised.
    pub async fn list_remote_prefix(
        &self,
        tool: &str,
        prefix: &str,
    ) -> MiseResult<Vec<RemoteVersion>> {
        let req = ListRemoteRequest::new(tool).prefix(prefix);
        self.list_remote_with(&req).await
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
    async fn test_list_remote() {
        let json = r#"[{"version":"22.1.0","install_status":"not_installed"},{"version":"21.0.0","install_status":"installed"}]"#;
        let fake = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout(json)));
        let mise = build_mise(fake.clone());

        let versions = mise.list_remote("node").await.unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].version, "22.1.0");
        assert_eq!(versions[0].install_status.as_deref(), Some("not_installed"));
        assert_eq!(versions[1].version, "21.0.0");
        assert_eq!(versions[1].install_status.as_deref(), Some("installed"));

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].args.contains(&"ls-remote".to_string()));
        assert!(calls[0].args.contains(&"node".to_string()));
        assert!(calls[0].args.contains(&"--json".to_string()));
    }

    #[tokio::test]
    async fn test_latest() {
        let fake = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout("22.1.0")));
        let mise = build_mise(fake.clone());

        let version = mise.latest("node").await.unwrap();
        assert_eq!(version, "22.1.0");

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].args.contains(&"latest".to_string()));
        assert!(calls[0].args.contains(&"node".to_string()));
    }
}
