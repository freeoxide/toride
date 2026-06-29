//! Tool installation and activation via `mise install` / `mise use`.
//!
//! Provides request structs and [`Mise`] methods for installing, using, pinning,
//! and reshimming tool versions.

use camino::Utf8PathBuf;

use crate::client::Mise;
use crate::error::MiseResult;

// ---------------------------------------------------------------------------
// UseScope
// ---------------------------------------------------------------------------

/// Scope for `mise use` — controls where the tool activation is recorded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum UseScope {
    /// Write to the project-local `.mise.toml`.
    #[default]
    Local,
    /// Write to the global `~/.config/mise/config.toml`.
    Global,
    /// Write to an arbitrary config file at the given path.
    Path(Utf8PathBuf),
    /// Set the environment variable for the current session (`MISE_<TOOL>_VERSION`).
    Env(String),
}

// ---------------------------------------------------------------------------
// InstallRequest
// ---------------------------------------------------------------------------

/// Parameters for a `mise install` invocation.
///
/// Construct with [`InstallRequest::new`] and chain builder methods.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default)]
pub struct InstallRequest {
    /// Tool spec strings to install (e.g. `"node@22"`, `"python@3.12"`).
    pub tools: Vec<String>,
    /// Maximum number of parallel install jobs.
    pub jobs: Option<usize>,
    /// Force reinstall even if already installed.
    pub force: bool,
    /// Verbose output.
    pub verbose: bool,
    /// Print raw installation scripts.
    pub raw: bool,
    /// Install to a shared directory instead of the default location.
    pub shared: Option<Utf8PathBuf>,
    /// Install system-wide (may require elevated privileges).
    pub system: bool,
    /// Use the lockfile when resolving versions.
    pub locked: bool,
    /// Automatically answer yes to prompts.
    pub yes: bool,
    /// Perform a dry run without actually installing.
    pub dry_run: bool,
    /// Custom exit code to use when a dry-run reports changes (mise internal).
    pub dry_run_code: Option<i32>,
    /// Only consider releases published at least this long ago (e.g. `"7d"`).
    pub minimum_release_age: Option<String>,
}

impl InstallRequest {
    /// Create a new `InstallRequest` for the given tool specs.
    pub fn new(tools: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            tools: tools.into_iter().map(Into::into).collect(),
            ..Self::default()
        }
    }

    /// Set the maximum number of parallel install jobs.
    pub fn jobs(mut self, n: usize) -> Self {
        self.jobs = Some(n);
        self
    }

    /// Force reinstall even if already installed.
    pub fn force(mut self) -> Self {
        self.force = true;
        self
    }

    /// Enable verbose output.
    pub fn verbose(mut self) -> Self {
        self.verbose = true;
        self
    }

    /// Print raw installation scripts.
    pub fn raw(mut self) -> Self {
        self.raw = true;
        self
    }

    /// Install to a shared directory.
    pub fn shared(mut self, path: impl Into<Utf8PathBuf>) -> Self {
        self.shared = Some(path.into());
        self
    }

    /// Install system-wide.
    pub fn system(mut self) -> Self {
        self.system = true;
        self
    }

    /// Use the lockfile for version resolution.
    pub fn locked(mut self) -> Self {
        self.locked = true;
        self
    }

    /// Automatically answer yes to prompts.
    pub fn yes(mut self) -> Self {
        self.yes = true;
        self
    }

    /// Perform a dry run without actually installing.
    pub fn dry_run(mut self) -> Self {
        self.dry_run = true;
        self
    }

    /// Set a custom exit code for dry-run mode.
    pub fn dry_run_code(mut self, code: i32) -> Self {
        self.dry_run_code = Some(code);
        self
    }

    /// Only consider releases published at least this long ago (e.g. `"7d"`).
    pub fn minimum_release_age(mut self, age: impl Into<String>) -> Self {
        self.minimum_release_age = Some(age.into());
        self
    }
}

// ---------------------------------------------------------------------------
// UseRequest
// ---------------------------------------------------------------------------

/// Parameters for a `mise use` invocation.
///
/// Constructs with [`UseRequest::new`] and chain builder methods.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default)]
pub struct UseRequest {
    /// Tool spec strings to activate (e.g. `"node@22"`, `"python@3.12"`).
    pub tools: Vec<String>,
    /// Where to record the tool activation.
    pub scope: UseScope,
    /// Pin the tool to the resolved version so it does not auto-upgrade.
    pub pin: bool,
    /// Allow fuzzy version matching.
    pub fuzzy: bool,
    /// Force writing even if the version is already active.
    pub force: bool,
    /// Maximum number of parallel install jobs (installs missing tools).
    pub jobs: Option<usize>,
    /// Config file path override (supersedes `scope`).
    pub path: Option<Utf8PathBuf>,
    /// Perform a dry run without modifying config files.
    pub dry_run: bool,
    /// Environment variable name to set (e.g. `"NODE_VERSION"`).
    pub env_name: Option<String>,
    /// Custom exit code to use when a dry-run reports changes (mise internal).
    pub dry_run_code: Option<i32>,
    /// Print raw output without formatting.
    pub raw: bool,
    /// Only consider releases published at least this long ago (e.g. `"7d"`).
    pub minimum_release_age: Option<String>,
}

impl UseRequest {
    /// Create a new `UseRequest` for the given tool specs.
    pub fn new(tools: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            tools: tools.into_iter().map(Into::into).collect(),
            ..Self::default()
        }
    }

    /// Set the scope to local (project config).
    pub fn local(mut self) -> Self {
        self.scope = UseScope::Local;
        self
    }

    /// Set the scope to global (`~/.config/mise/config.toml`).
    pub fn global(mut self) -> Self {
        self.scope = UseScope::Global;
        self
    }

    /// Set the scope to a specific config file path.
    pub fn scope_path(mut self, path: impl Into<Utf8PathBuf>) -> Self {
        self.scope = UseScope::Path(path.into());
        self
    }

    /// Set the scope to an environment variable with the given name.
    pub fn scope_env(mut self, var: impl Into<String>) -> Self {
        self.scope = UseScope::Env(var.into());
        self
    }

    /// Pin the tool version so it does not auto-upgrade.
    pub fn pin(mut self) -> Self {
        self.pin = true;
        self
    }

    /// Allow fuzzy version matching.
    pub fn fuzzy(mut self) -> Self {
        self.fuzzy = true;
        self
    }

    /// Force writing even if already active.
    pub fn force(mut self) -> Self {
        self.force = true;
        self
    }

    /// Set the maximum number of parallel install jobs.
    pub fn jobs(mut self, n: usize) -> Self {
        self.jobs = Some(n);
        self
    }

    /// Override the config file path directly.
    pub fn path(mut self, p: impl Into<Utf8PathBuf>) -> Self {
        self.path = Some(p.into());
        self
    }

    /// Perform a dry run without modifying config files.
    pub fn dry_run(mut self) -> Self {
        self.dry_run = true;
        self
    }

    /// Set the environment variable name to write the version into.
    pub fn env_name(mut self, name: impl Into<String>) -> Self {
        self.env_name = Some(name.into());
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
    /// Install a tool version (simple convenience wrapper).
    ///
    /// `tool_spec` should be a mise tool spec string such as `"node@22"`,
    /// `"npm:prettier@latest"`, or `"python@3.12"`.
    ///
    /// Invokes `mise install <tool_spec>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the installation fails.
    pub async fn install(&self, tool_spec: &str) -> MiseResult<()> {
        self.run_checked(["install", tool_spec]).await?;
        Ok(())
    }

    /// Install tool versions using a full [`InstallRequest`].
    ///
    /// Builds the complete `mise install` command with all flags from the
    /// request struct.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the installation fails.
    pub async fn install_with(&self, req: &InstallRequest) -> MiseResult<()> {
        let mut args: Vec<String> = Vec::new();
        args.push("install".into());

        if req.force {
            args.push("--force".into());
        }
        if req.verbose {
            args.push("--verbose".into());
        }
        if req.raw {
            args.push("--raw".into());
        }
        if let Some(ref shared) = req.shared {
            args.push("--shared".into());
            args.push(shared.to_string());
        }
        if req.system {
            args.push("--system".into());
        }
        if req.locked {
            args.push("--locked".into());
        }
        if req.yes {
            args.push("--yes".into());
        }
        if req.dry_run {
            args.push("--dry-run".into());
        }
        if let Some(ref age) = req.minimum_release_age {
            args.push("--minimum-release-age".into());
            args.push(age.clone());
        }
        if let Some(jobs) = req.jobs {
            args.push("--jobs".into());
            args.push(jobs.to_string());
        }

        for tool in &req.tools {
            args.push(tool.clone());
        }

        self.run_checked(args).await?;
        Ok(())
    }

    /// Activate tool versions using a [`UseRequest`].
    ///
    /// Builds the complete `mise use` command with all flags from the request.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command fails.
    pub async fn use_tool(&self, req: &UseRequest) -> MiseResult<()> {
        let mut args: Vec<String> = Vec::new();
        args.push("use".into());

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
            UseScope::Local => {
                // Default scope — no flag needed.
            }
        }

        if req.pin {
            args.push("--pin".into());
        }
        if req.fuzzy {
            args.push("--fuzzy".into());
        }
        if req.force {
            args.push("--force".into());
        }
        if req.dry_run {
            args.push("--dry-run".into());
        }
        if req.raw {
            args.push("--raw".into());
        }
        // Only add --env from env_name when the scope is NOT already Env (which
        // adds its own --env flag above).  This avoids emitting two --env flags.
        if let Some(ref env_name) = req.env_name
            && !matches!(req.scope, UseScope::Env(_))
        {
            args.push("--env".into());
            args.push(env_name.clone());
        }
        if let Some(ref age) = req.minimum_release_age {
            args.push("--minimum-release-age".into());
            args.push(age.clone());
        }
        if let Some(jobs) = req.jobs {
            args.push("--jobs".into());
            args.push(jobs.to_string());
        }

        // Explicit path override supersedes scope-based path. Only emit one
        // --path flag to avoid passing two to mise.
        if let Some(ref path) = req.path
            && !matches!(req.scope, UseScope::Path(_))
        {
            args.push("--path".into());
            args.push(path.to_string());
        }

        for tool in &req.tools {
            args.push(tool.clone());
        }

        self.run_checked(args).await?;
        Ok(())
    }

    /// Pin one or more tool versions so they do not auto-upgrade.
    ///
    /// Invokes `mise use --pin <tools…>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command fails.
    pub async fn pin(&self, tools: &[&str]) -> MiseResult<()> {
        let mut args: Vec<String> = Vec::new();
        args.push("use".into());
        args.push("--pin".into());
        for tool in tools {
            args.push((*tool).to_owned());
        }
        self.run_checked(args).await?;
        Ok(())
    }

    /// Install a tool into a specific directory.
    ///
    /// Invokes `mise install-into <tool_spec> <dir>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the installation fails.
    pub async fn install_into(&self, tool_spec: &str, dir: &str) -> MiseResult<()> {
        self.run_checked(["install-into", tool_spec, dir]).await?;
        Ok(())
    }

    /// Link a tool version from an existing directory.
    ///
    /// Invokes `mise link <tool_spec> <dir>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the link operation fails.
    pub async fn link(&self, tool_spec: &str, dir: &str) -> MiseResult<()> {
        self.run_checked(["link", tool_spec, dir]).await?;
        Ok(())
    }

    /// Rebuild shims for all installed tools.
    ///
    /// Invokes `mise reshim`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command fails.
    pub async fn reshim(&self) -> MiseResult<()> {
        self.run_checked(["reshim"]).await?;
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

    fn build_mise(fake: Arc<FakeRunner>) -> Mise {
        Mise::builder()
            .runner(fake as Arc<dyn toride_runner::AsyncRunner>)
            .binary(crate::binary::MiseBinary::from_path("/usr/bin/mise"))
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn test_install_builds_correct_command() {
        let fake = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout("")));
        let mise = build_mise(fake.clone());

        mise.install("node@22").await.unwrap();

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].program, "/usr/bin/mise");
        assert!(calls[0].args.contains(&"install".to_string()));
        assert!(calls[0].args.contains(&"node@22".to_string()));
    }

    #[tokio::test]
    async fn test_install_with_force() {
        let fake = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout("")));
        let mise = build_mise(fake.clone());

        let req = super::InstallRequest::new(["node@22"]).force();
        mise.install_with(&req).await.unwrap();

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].args.contains(&"--force".to_string()));
        assert!(calls[0].args.contains(&"install".to_string()));
        assert!(calls[0].args.contains(&"node@22".to_string()));
    }

    #[tokio::test]
    async fn test_install_with_dry_run() {
        let fake = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout("")));
        let mise = build_mise(fake.clone());

        let req = super::InstallRequest::new(["python@3.12"]).dry_run();
        mise.install_with(&req).await.unwrap();

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].args.contains(&"--dry-run".to_string()));
        assert!(calls[0].args.contains(&"install".to_string()));
        assert!(calls[0].args.contains(&"python@3.12".to_string()));
    }

    #[tokio::test]
    async fn test_use_tool_local() {
        let fake = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout("")));
        let mise = build_mise(fake.clone());

        let req = super::UseRequest::new(["node@22"]).local();
        mise.use_tool(&req).await.unwrap();

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].args.contains(&"use".to_string()));
        assert!(calls[0].args.contains(&"node@22".to_string()));
        // Local scope should NOT add --global
        assert!(!calls[0].args.contains(&"--global".to_string()));
    }

    #[tokio::test]
    async fn test_use_tool_global() {
        let fake = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout("")));
        let mise = build_mise(fake.clone());

        let req = super::UseRequest::new(["python@3.12"]).global();
        mise.use_tool(&req).await.unwrap();

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].args.contains(&"use".to_string()));
        assert!(calls[0].args.contains(&"--global".to_string()));
        assert!(calls[0].args.contains(&"python@3.12".to_string()));
    }

    #[tokio::test]
    async fn test_pin() {
        let fake = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout("")));
        let mise = build_mise(fake.clone());

        mise.pin(&["node@22"]).await.unwrap();

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].args.contains(&"use".to_string()));
        assert!(calls[0].args.contains(&"--pin".to_string()));
        assert!(calls[0].args.contains(&"node@22".to_string()));
    }

    // -----------------------------------------------------------------------
    // Strict-mode tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_install_strict_mode() {
        let expected = toride_runner::CommandSpec::new("/usr/bin/mise")
            .arg("install")
            .arg("node@22")
            .redact(true);
        let fake = Arc::new(
            FakeRunner::new()
                .strict()
                .respond(expected, CommandOutput::from_stdout("")),
        );
        let mise = build_mise(fake.clone());

        mise.install("node@22").await.unwrap();

        // Exact-match response is consumed; no unmatched calls remain.
        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn test_install_assert_called_with() {
        let expected = toride_runner::CommandSpec::new("/usr/bin/mise")
            .arg("install")
            .arg("node@22")
            .redact(true);
        let fake = Arc::new(
            FakeRunner::new()
                .strict()
                .respond(expected, CommandOutput::from_stdout("")),
        );
        let mise = build_mise(fake.clone());

        mise.install("node@22").await.unwrap();

        fake.assert_called_with(
            &toride_runner::CommandSpec::new("/usr/bin/mise")
                .arg("install")
                .arg("node@22")
                .redact(true),
        );
    }

    #[tokio::test]
    async fn test_install_with_strict_mode() {
        let expected = toride_runner::CommandSpec::new("/usr/bin/mise")
            .arg("install")
            .arg("--force")
            .arg("--verbose")
            .arg("node@22")
            .redact(true);
        let fake = Arc::new(
            FakeRunner::new()
                .strict()
                .respond(expected, CommandOutput::from_stdout("")),
        );
        let mise = build_mise(fake.clone());

        let req = super::InstallRequest::new(["node@22"]).force().verbose();
        mise.install_with(&req).await.unwrap();

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].args.contains(&"install".to_string()));
        assert!(calls[0].args.contains(&"--force".to_string()));
        assert!(calls[0].args.contains(&"--verbose".to_string()));
        assert!(calls[0].args.contains(&"node@22".to_string()));
        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn test_install_with_assert_called_with() {
        let expected = toride_runner::CommandSpec::new("/usr/bin/mise")
            .arg("install")
            .arg("--jobs")
            .arg("4")
            .arg("python@3.12")
            .redact(true);
        let fake = Arc::new(
            FakeRunner::new()
                .strict()
                .respond(expected, CommandOutput::from_stdout("")),
        );
        let mise = build_mise(fake.clone());

        let req = super::InstallRequest::new(["python@3.12"]).jobs(4);
        mise.install_with(&req).await.unwrap();

        fake.assert_called_with(
            &toride_runner::CommandSpec::new("/usr/bin/mise")
                .arg("install")
                .arg("--jobs")
                .arg("4")
                .arg("python@3.12")
                .redact(true),
        );
    }
}
