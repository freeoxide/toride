//! Tool uninstallation and deactivation via `mise uninstall` / `mise unset`.
//!
//! Provides request structs and [`Mise`] methods for uninstalling tool versions
//! and removing tool activations from config files.

use camino::Utf8PathBuf;

use crate::client::Mise;
use crate::error::MiseResult;

use super::install::UseScope;

// ---------------------------------------------------------------------------
// UninstallRequest
// ---------------------------------------------------------------------------

/// Parameters for a `mise uninstall` invocation.
///
/// Construct with [`UninstallRequest::new`] and chain builder methods.
#[derive(Debug, Clone, Default)]
pub struct UninstallRequest {
    /// Tool spec strings to uninstall (e.g. `"node@22.1.0"`).
    pub tools: Vec<String>,
    /// Uninstall all tool versions.
    pub all: bool,
    /// Perform a dry run without actually removing anything.
    pub dry_run: bool,
    /// Custom exit code to use when a dry-run reports changes (mise internal).
    pub dry_run_code: Option<i32>,
}

impl UninstallRequest {
    /// Create a new `UninstallRequest` for the given tool specs.
    pub fn new(tools: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            tools: tools.into_iter().map(Into::into).collect(),
            ..Self::default()
        }
    }

    /// Uninstall all tool versions.
    pub fn all(mut self) -> Self {
        self.all = true;
        self
    }

    /// Perform a dry run without removing anything.
    pub fn dry_run(mut self) -> Self {
        self.dry_run = true;
        self
    }

    /// Set a custom exit code for dry-run mode.
    pub fn dry_run_code(mut self, code: i32) -> Self {
        self.dry_run_code = Some(code);
        self
    }
}

// ---------------------------------------------------------------------------
// UnuseRequest
// ---------------------------------------------------------------------------

/// Parameters for a `mise unset` (unuse) invocation.
///
/// Removes tool version entries from the active config file.
#[derive(Debug, Clone, Default)]
pub struct UnuseRequest {
    /// Tool names to remove from the config (e.g. `"node"`, `"python"`).
    pub tools: Vec<String>,
    /// Scope to remove the tool activation from.
    pub scope: UseScope,
    /// Do not prune unused installations after removing.
    pub no_prune: bool,
}

impl UnuseRequest {
    /// Create a new `UnuseRequest` for the given tool names.
    pub fn new(tools: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            tools: tools.into_iter().map(Into::into).collect(),
            ..Self::default()
        }
    }

    /// Set the scope to global.
    pub fn global(mut self) -> Self {
        self.scope = UseScope::Global;
        self
    }

    /// Set the scope to a specific config file path.
    pub fn scope_path(mut self, path: impl Into<Utf8PathBuf>) -> Self {
        self.scope = UseScope::Path(path.into());
        self
    }

    /// Set the scope to an environment variable.
    pub fn scope_env(mut self, var: impl Into<String>) -> Self {
        self.scope = UseScope::Env(var.into());
        self
    }

    /// Skip pruning unused installations after removal.
    pub fn no_prune(mut self) -> Self {
        self.no_prune = true;
        self
    }
}

// ---------------------------------------------------------------------------
// Mise methods
// ---------------------------------------------------------------------------

impl Mise {
    /// Uninstall a tool version (simple convenience wrapper).
    ///
    /// `tool_spec` should be a mise tool spec string such as `"node@22.1.0"`.
    ///
    /// Invokes `mise uninstall <tool_spec>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the uninstallation fails.
    pub async fn uninstall(&self, tool_spec: &str) -> MiseResult<()> {
        self.run_checked(["uninstall", tool_spec]).await?;
        Ok(())
    }

    /// Uninstall tool versions using a full [`UninstallRequest`].
    ///
    /// Builds the complete `mise uninstall` command with all flags from the
    /// request struct.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the uninstallation fails.
    pub async fn uninstall_with(&self, req: &UninstallRequest) -> MiseResult<()> {
        let mut args: Vec<String> = Vec::new();
        args.push("uninstall".into());

        if req.all {
            args.push("--all".into());
        }
        if req.dry_run {
            args.push("--dry-run".into());
        }

        for tool in &req.tools {
            args.push(tool.clone());
        }

        self.run_checked(args).await?;
        Ok(())
    }

    /// Remove tool activations from config using an [`UnuseRequest`].
    ///
    /// Builds the `mise unset` command with scope and prune flags.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command fails.
    pub async fn unuse(&self, req: &UnuseRequest) -> MiseResult<()> {
        let mut args: Vec<String> = Vec::new();
        args.push("unset".into());

        // Scope flags.
        match &req.scope {
            UseScope::Global => {
                args.push("--global".into());
            }
            UseScope::Path(p) => {
                args.push("--path".into());
                args.push(p.to_string());
            }
            UseScope::Env(var) => {
                args.push("--env".into());
                args.push(var.clone());
            }
            UseScope::Local => {}
        }

        if req.no_prune {
            args.push("--no-prune".into());
        }

        for tool in &req.tools {
            args.push(tool.clone());
        }

        self.run_checked(args).await?;
        Ok(())
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

    fn build_mise() -> (Mise, Arc<FakeRunner>) {
        let fake = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout("")));
        let mise = Mise::builder()
            .runner(fake.clone() as Arc<dyn toride_runner::AsyncRunner>)
            .binary(crate::binary::MiseBinary::from_path("/usr/bin/mise"))
            .build()
            .unwrap();
        (mise, fake)
    }

    #[tokio::test]
    async fn test_uninstall_builds_correct_command() {
        let (mise, fake) = build_mise();

        mise.uninstall("node@22.1.0").await.unwrap();

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].program, "/usr/bin/mise");
        assert!(calls[0].args.contains(&"uninstall".to_string()));
        assert!(calls[0].args.contains(&"node@22.1.0".to_string()));
    }

    #[tokio::test]
    async fn test_uninstall_all() {
        let (mise, fake) = build_mise();

        let req = super::UninstallRequest::new(["node@22.1.0"]).all();
        mise.uninstall_with(&req).await.unwrap();

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].args.contains(&"uninstall".to_string()));
        assert!(calls[0].args.contains(&"--all".to_string()));
        assert!(calls[0].args.contains(&"node@22.1.0".to_string()));
    }

    #[tokio::test]
    async fn test_unuse_builds_correct_command() {
        let (mise, fake) = build_mise();

        let req = super::UnuseRequest::new(["node", "python"]);
        mise.unuse(&req).await.unwrap();

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].args.contains(&"unset".to_string()));
        assert!(calls[0].args.contains(&"node".to_string()));
        assert!(calls[0].args.contains(&"python".to_string()));
    }

    #[tokio::test]
    async fn test_unuse_no_prune() {
        let (mise, fake) = build_mise();

        let req = super::UnuseRequest::new(["node"]).no_prune();
        mise.unuse(&req).await.unwrap();

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].args.contains(&"unset".to_string()));
        assert!(calls[0].args.contains(&"--no-prune".to_string()));
        assert!(calls[0].args.contains(&"node".to_string()));
    }

    // -----------------------------------------------------------------------
    // Strict-mode tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_uninstall_strict_mode() {
        let expected = toride_runner::CommandSpec::new("/usr/bin/mise")
            .arg("uninstall")
            .arg("node@22.1.0")
            .redact(true);
        let fake = Arc::new(
            FakeRunner::new()
                .strict()
                .respond(expected, CommandOutput::from_stdout("")),
        );
        let mise = Mise::builder()
            .runner(fake.clone() as Arc<dyn toride_runner::AsyncRunner>)
            .binary(crate::binary::MiseBinary::from_path("/usr/bin/mise"))
            .build()
            .unwrap();

        mise.uninstall("node@22.1.0").await.unwrap();

        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn test_uninstall_assert_called_with() {
        let expected = toride_runner::CommandSpec::new("/usr/bin/mise")
            .arg("uninstall")
            .arg("node@22.1.0")
            .redact(true);
        let fake = Arc::new(
            FakeRunner::new()
                .strict()
                .respond(expected, CommandOutput::from_stdout("")),
        );
        let mise = Mise::builder()
            .runner(fake.clone() as Arc<dyn toride_runner::AsyncRunner>)
            .binary(crate::binary::MiseBinary::from_path("/usr/bin/mise"))
            .build()
            .unwrap();

        mise.uninstall("node@22.1.0").await.unwrap();

        fake.assert_called_with(
            &toride_runner::CommandSpec::new("/usr/bin/mise")
                .arg("uninstall")
                .arg("node@22.1.0")
                .redact(true),
        );
    }

    #[tokio::test]
    async fn test_uninstall_with_all_strict() {
        let expected = toride_runner::CommandSpec::new("/usr/bin/mise")
            .arg("uninstall")
            .arg("--all")
            .arg("--dry-run")
            .arg("node@22.1.0")
            .redact(true);
        let fake = Arc::new(
            FakeRunner::new()
                .strict()
                .respond(expected, CommandOutput::from_stdout("")),
        );
        let mise = Mise::builder()
            .runner(fake.clone() as Arc<dyn toride_runner::AsyncRunner>)
            .binary(crate::binary::MiseBinary::from_path("/usr/bin/mise"))
            .build()
            .unwrap();

        let req = super::UninstallRequest::new(["node@22.1.0"])
            .all()
            .dry_run();
        mise.uninstall_with(&req).await.unwrap();

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].args.contains(&"uninstall".to_string()));
        assert!(calls[0].args.contains(&"--all".to_string()));
        assert!(calls[0].args.contains(&"--dry-run".to_string()));
        assert!(calls[0].args.contains(&"node@22.1.0".to_string()));
        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn test_unuse_global_strict() {
        let expected = toride_runner::CommandSpec::new("/usr/bin/mise")
            .arg("unset")
            .arg("--global")
            .arg("node")
            .redact(true);
        let fake = Arc::new(
            FakeRunner::new()
                .strict()
                .respond(expected, CommandOutput::from_stdout("")),
        );
        let mise = Mise::builder()
            .runner(fake.clone() as Arc<dyn toride_runner::AsyncRunner>)
            .binary(crate::binary::MiseBinary::from_path("/usr/bin/mise"))
            .build()
            .unwrap();

        let req = super::UnuseRequest::new(["node"]).global();
        mise.unuse(&req).await.unwrap();

        fake.assert_called_with(
            &toride_runner::CommandSpec::new("/usr/bin/mise")
                .arg("unset")
                .arg("--global")
                .arg("node")
                .redact(true),
        );
    }
}
