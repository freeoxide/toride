//! Exec and binary resolution for mise.
//!
//! This module provides types for executing commands through mise's tool
//! environment and for resolving binary paths managed by mise.
//!
//! - [`ExecRequest`] — parameters for `mise exec` with builder methods.
//! - [`SandboxPolicy`] — controls sandboxing behaviour for exec.
//! - [`BinResolution`] — a resolved binary path with metadata.
//! - [`Mise`] extension methods: [`exec`](Mise::exec), [`which`](Mise::which),
//!   [`which_with_tool`](Mise::which_with_tool), [`which_version`](Mise::which_version),
//!   [`which_plugin`](Mise::which_plugin), [`where_tool`](Mise::where_tool).

use std::path::PathBuf;

use camino::Utf8PathBuf;

use crate::client::Mise;
use crate::error::{MiseError, MiseResult};
use crate::tool::ToolSpec;

// ---------------------------------------------------------------------------
// ExecRequest
// ---------------------------------------------------------------------------

/// Parameters for a `mise exec` invocation.
///
/// `mise exec` runs a command inside the environment that would be set up for
/// the requested tools, without permanently activating them.
///
/// Construct with [`ExecRequest::new`] and chain builder methods.
#[derive(Debug, Clone, Default)]
pub struct ExecRequest {
    /// Tool specs whose environment should be activated for the command.
    pub tools: Vec<ToolSpec>,
    /// The command and its arguments to execute.
    pub command: Vec<String>,
    /// Working directory for the command.
    pub cwd: Option<Utf8PathBuf>,
    /// Maximum number of parallel jobs for tool resolution.
    pub jobs: Option<usize>,
    /// When `true`, start from a clean environment instead of inheriting the
    /// current one.
    pub fresh_env: bool,
    /// When `true`, skip installing missing tools.
    pub no_deps: bool,
    /// When `true`, pass `--raw` to disable all mise shims/wrappers.
    pub raw: bool,
    /// Optional sandbox policy. When set, the corresponding `--sandbox`,
    /// `--deny-*`, and `--allow-*` flags are passed to `mise exec`.
    pub sandbox: Option<SandboxPolicy>,
}

impl ExecRequest {
    /// Create a new `ExecRequest` for the given tool specs and command.
    pub fn new(
        tools: impl IntoIterator<Item = impl Into<ToolSpec>>,
        command: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            tools: tools.into_iter().map(Into::into).collect(),
            command: command.into_iter().map(Into::into).collect(),
            ..Self::default()
        }
    }

    /// Add a tool spec to the request.
    pub fn tool(mut self, spec: impl Into<ToolSpec>) -> Self {
        self.tools.push(spec.into());
        self
    }

    /// Set the working directory for the command.
    pub fn cwd(mut self, path: impl Into<Utf8PathBuf>) -> Self {
        self.cwd = Some(path.into());
        self
    }

    /// Set the maximum number of parallel jobs.
    pub fn jobs(mut self, n: usize) -> Self {
        self.jobs = Some(n);
        self
    }

    /// Start from a clean environment.
    pub fn fresh_env(mut self) -> Self {
        self.fresh_env = true;
        self
    }

    /// Skip installing missing tools.
    pub fn no_deps(mut self) -> Self {
        self.no_deps = true;
        self
    }

    /// Disable all mise shims/wrappers.
    pub fn raw(mut self) -> Self {
        self.raw = true;
        self
    }

    /// Apply a sandbox policy to the exec request.
    pub fn sandbox(mut self, policy: SandboxPolicy) -> Self {
        self.sandbox = Some(policy);
        self
    }
}

// ---------------------------------------------------------------------------
// SandboxPolicy
// ---------------------------------------------------------------------------

/// Controls sandboxing behaviour when executing commands through mise.
///
/// When attached to an [`ExecRequest`], the fields are translated into the
/// corresponding `--deny-*` and `--allow-*` mise flags.
///
/// In real mise, `--deny-read` and `--deny-write` are bare boolean flags that
/// block all filesystem reads/writes respectively. Fine-grained path-based
/// denial does not exist. Similarly, `--allow-net` requires a host argument
/// and `--allow-env` requires an env-var pattern.
#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct SandboxPolicy {
    /// Whether to deny all filesystem reads.
    pub deny_read: bool,
    /// Whether to deny all filesystem writes.
    pub deny_write: bool,
    /// Whether to deny network access.
    pub deny_net: bool,
    /// Whether to deny environment variable access.
    pub deny_env: bool,
    /// Paths to explicitly allow read access to.
    pub allow_read: Vec<PathBuf>,
    /// Paths to explicitly allow write access to.
    pub allow_write: Vec<PathBuf>,
    /// Hosts to allow network access to (e.g. `"github.com"`).
    pub allow_net: Vec<String>,
    /// Env var patterns to allow (e.g. `"MYAPP_*"`).
    pub allow_env: Vec<String>,
}

// ---------------------------------------------------------------------------
// BinResolution
// ---------------------------------------------------------------------------

/// A resolved binary path with associated metadata.
///
/// Returned by [`Mise::which`] and related methods.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinResolution {
    /// The binary name that was queried.
    pub bin: String,
    /// Absolute path to the resolved binary.
    pub path: Utf8PathBuf,
    /// The version of the tool providing this binary, if known.
    pub version: Option<String>,
    /// The plugin/backend that provides this binary, if known.
    pub plugin: Option<String>,
}

impl BinResolution {
    /// Return the resolved binary path as a [`std::path::Path`].
    pub fn as_path(&self) -> &std::path::Path {
        self.path.as_std_path()
    }
}

// ---------------------------------------------------------------------------
// Mise impl — exec methods
// ---------------------------------------------------------------------------

impl Mise {
    /// Execute a command through `mise exec`.
    ///
    /// Runs `mise exec <tools> -- <command>` and returns the raw command
    /// output.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError`] if the mise binary cannot be found, the command
    /// cannot be spawned, or the underlying command exits non-zero.
    pub async fn exec(&self, req: &ExecRequest) -> MiseResult<toride_runner::CommandOutput> {
        let mut args: Vec<String> = Vec::new();
        args.push("exec".into());

        // Tool specs.
        for tool in &req.tools {
            args.push(tool.to_string());
        }

        // Parallelism.
        if let Some(jobs) = req.jobs {
            args.push("--jobs".into());
            args.push(jobs.to_string());
        }

        // Fresh environment.
        if req.fresh_env {
            args.push("--fresh".into());
        }

        // Skip deps.
        if req.no_deps {
            args.push("--no-deps".into());
        }

        // Raw mode.
        if req.raw {
            args.push("--raw".into());
        }

        // Working directory.
        if let Some(ref cwd) = req.cwd {
            args.push("--cwd".into());
            args.push(cwd.to_string());
        }

        // Sandbox flags. In real mise, sandboxing is implicit when any --deny-*
        // or --allow-* flags are present; there is no --sandbox flag.
        if let Some(ref policy) = req.sandbox {
            // --deny-read / --deny-write are bare boolean flags (no value).
            if policy.deny_read {
                args.push("--deny-read".into());
            }
            if policy.deny_write {
                args.push("--deny-write".into());
            }
            if policy.deny_net {
                args.push("--deny-net".into());
            }
            if policy.deny_env {
                args.push("--deny-env".into());
            }
            for path in &policy.allow_read {
                args.push("--allow-read".into());
                args.push(path.to_string_lossy().into_owned());
            }
            for path in &policy.allow_write {
                args.push("--allow-write".into());
                args.push(path.to_string_lossy().into_owned());
            }
            // --allow-net requires a host argument in real mise.
            for host in &policy.allow_net {
                args.push("--allow-net".into());
                args.push(host.clone());
            }
            // --allow-env requires an env-var pattern argument in real mise.
            for pattern in &policy.allow_env {
                args.push("--allow-env".into());
                args.push(pattern.clone());
            }
        }

        // Command separator.
        args.push("--".into());

        // The command and its arguments.
        if req.command.is_empty() {
            return Err(MiseError::CommandFailed {
                command: "mise exec".into(),
                exit_code: None,
                stdout: String::new(),
                stderr: "no command provided for mise exec".into(),
            });
        }
        args.extend(req.command.iter().cloned());

        let output = self.run_checked(args).await?;
        Ok(output)
    }

    /// Resolve the path to a binary managed by mise.
    ///
    /// Equivalent to `mise which <bin>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError`] if the binary cannot be found or the command
    /// fails.
    pub async fn which(&self, bin: &str) -> MiseResult<BinResolution> {
        let output = self.run_checked(["which", bin]).await?;
        let path_str = output.stdout_trimmed();

        if path_str.is_empty() {
            return Err(MiseError::CommandFailed {
                command: format!("mise which {bin}"),
                exit_code: Some(0),
                stdout: String::new(),
                stderr: format!("mise which {bin} returned an empty path"),
            });
        }

        let path = Utf8PathBuf::from(path_str.to_owned());

        Ok(BinResolution {
            bin: bin.to_owned(),
            path,
            version: None,
            plugin: None,
        })
    }

    /// Resolve the path to a binary within a specific tool's environment.
    ///
    /// Equivalent to `mise which --tool <tool> <bin>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError`] if the binary or tool cannot be found.
    pub async fn which_with_tool(&self, bin: &str, tool: &ToolSpec) -> MiseResult<BinResolution> {
        let output = self
            .run_checked(["which", "--tool", tool.as_ref(), bin])
            .await?;
        let path_str = output.stdout_trimmed();

        if path_str.is_empty() {
            return Err(MiseError::CommandFailed {
                command: format!("mise which --tool {tool} {bin}"),
                exit_code: Some(0),
                stdout: String::new(),
                stderr: format!("mise which --tool {tool} {bin} returned an empty path"),
            });
        }

        let path = Utf8PathBuf::from(path_str.to_owned());

        Ok(BinResolution {
            bin: bin.to_owned(),
            path,
            version: None,
            plugin: None,
        })
    }

    /// Resolve the version of a tool that provides a given binary.
    ///
    /// Equivalent to `mise which --version <bin>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError`] if the binary cannot be found.
    pub async fn which_version(&self, bin: &str) -> MiseResult<BinResolution> {
        let output = self.run_checked(["which", "--version", bin]).await?;

        let lines: Vec<&str> = output.stdout_trimmed().lines().collect();
        if lines.is_empty() {
            return Err(MiseError::CommandFailed {
                command: format!("mise which --version {bin}"),
                exit_code: Some(0),
                stdout: String::new(),
                stderr: format!("mise which --version {bin} returned an empty path"),
            });
        }

        let path = Utf8PathBuf::from(lines[0].to_owned());
        let version = lines.get(1).map(|s| (*s).to_owned());

        Ok(BinResolution {
            bin: bin.to_owned(),
            path,
            version,
            plugin: None,
        })
    }

    /// Resolve the plugin/backend that provides a given binary.
    ///
    /// Equivalent to `mise which --plugin <bin>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError`] if the binary cannot be found.
    pub async fn which_plugin(&self, bin: &str) -> MiseResult<BinResolution> {
        let output = self.run_checked(["which", "--plugin", bin]).await?;

        let lines: Vec<&str> = output.stdout_trimmed().lines().collect();
        if lines.is_empty() {
            return Err(MiseError::CommandFailed {
                command: format!("mise which --plugin {bin}"),
                exit_code: Some(0),
                stdout: String::new(),
                stderr: format!("mise which --plugin {bin} returned an empty path"),
            });
        }

        let path = Utf8PathBuf::from(lines[0].to_owned());
        let plugin = lines.get(1).map(|s| (*s).to_owned());

        Ok(BinResolution {
            bin: bin.to_owned(),
            path,
            version: None,
            plugin,
        })
    }

    /// Return the install directory for a tool.
    ///
    /// Equivalent to `mise where <tool-spec>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError`] if the tool is not installed or the command fails.
    pub async fn where_tool(&self, spec: &ToolSpec) -> MiseResult<Utf8PathBuf> {
        let output = self.run_checked(["where", spec.as_ref()]).await?;
        let path_str = output.stdout_trimmed();

        if path_str.is_empty() {
            return Err(MiseError::CommandFailed {
                command: format!("mise where {spec}"),
                exit_code: Some(0),
                stdout: String::new(),
                stderr: format!("mise where {spec} returned an empty path"),
            });
        }

        Ok(Utf8PathBuf::from(path_str.to_owned()))
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
    use crate::tool::ToolSpec;

    fn build_mise(fake: Arc<FakeRunner>) -> Mise {
        Mise::builder()
            .runner(fake as Arc<dyn toride_runner::AsyncRunner>)
            .binary(crate::binary::MiseBinary::from_path("/usr/bin/mise"))
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn test_exec_builds_correct_command() {
        let fake = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout("hello")));
        let mise = build_mise(fake.clone());

        let req = super::ExecRequest::new([ToolSpec::new("node@22")], ["node", "--version"]);
        let output = mise.exec(&req).await.unwrap();
        assert_eq!(output.stdout_trimmed(), "hello");

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        let args = &calls[0].args;
        assert!(args.contains(&"exec".to_string()));
        assert!(args.contains(&"node@22".to_string()));
        assert!(args.contains(&"--".to_string()));
        assert!(args.contains(&"node".to_string()));
        assert!(args.contains(&"--version".to_string()));
    }

    #[tokio::test]
    async fn test_which_builds_correct_command() {
        let fake = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout(
            "/home/user/.local/share/mise/installs/node/22.1.0/bin/node",
        )));
        let mise = build_mise(fake.clone());

        let result = mise.which("node").await.unwrap();
        assert_eq!(result.bin, "node");
        assert_eq!(
            result.path.as_str(),
            "/home/user/.local/share/mise/installs/node/22.1.0/bin/node"
        );

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].args.contains(&"which".to_string()));
        assert!(calls[0].args.contains(&"node".to_string()));
    }

    #[tokio::test]
    async fn test_where_builds_correct_command() {
        let fake = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout(
            "/home/user/.local/share/mise/installs/node/22.1.0",
        )));
        let mise = build_mise(fake.clone());

        let path = mise.where_tool(&ToolSpec::new("node@22")).await.unwrap();
        assert_eq!(
            path.as_str(),
            "/home/user/.local/share/mise/installs/node/22.1.0"
        );

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].args.contains(&"where".to_string()));
        assert!(calls[0].args.contains(&"node@22".to_string()));
    }

    // -----------------------------------------------------------------------
    // Strict-mode tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_exec_strict_mode() {
        let expected = toride_runner::CommandSpec::new("/usr/bin/mise")
            .arg("exec")
            .arg("node@22")
            .arg("--")
            .arg("node")
            .arg("--version")
            .redact(true);
        let fake = Arc::new(
            FakeRunner::new()
                .strict()
                .respond(expected, CommandOutput::from_stdout("v22.1.0")),
        );
        let mise = build_mise(fake.clone());

        let req = super::ExecRequest::new([ToolSpec::new("node@22")], ["node", "--version"]);
        let output = mise.exec(&req).await.unwrap();
        assert_eq!(output.stdout_trimmed(), "v22.1.0");

        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn test_exec_assert_called_with() {
        let expected = toride_runner::CommandSpec::new("/usr/bin/mise")
            .arg("exec")
            .arg("python@3.12")
            .arg("--")
            .arg("python")
            .arg("-c")
            .arg("print(1)")
            .redact(true);
        let fake = Arc::new(
            FakeRunner::new()
                .strict()
                .respond(expected, CommandOutput::from_stdout("ok")),
        );
        let mise = build_mise(fake.clone());

        let req =
            super::ExecRequest::new([ToolSpec::new("python@3.12")], ["python", "-c", "print(1)"]);
        let _ = mise.exec(&req).await.unwrap();

        fake.assert_called_with(
            &toride_runner::CommandSpec::new("/usr/bin/mise")
                .arg("exec")
                .arg("python@3.12")
                .arg("--")
                .arg("python")
                .arg("-c")
                .arg("print(1)")
                .redact(true),
        );
    }

    #[tokio::test]
    async fn test_exec_with_flags_strict() {
        let expected = toride_runner::CommandSpec::new("/usr/bin/mise")
            .arg("exec")
            .arg("node@22")
            .arg("--jobs")
            .arg("2")
            .arg("--fresh")
            .arg("--raw")
            .arg("--")
            .arg("echo")
            .arg("hello")
            .redact(true);
        let fake = Arc::new(
            FakeRunner::new()
                .strict()
                .respond(expected, CommandOutput::from_stdout("")),
        );
        let mise = build_mise(fake.clone());

        let req = super::ExecRequest::new([ToolSpec::new("node@22")], ["echo", "hello"])
            .jobs(2)
            .fresh_env()
            .raw();
        let _ = mise.exec(&req).await.unwrap();

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        let args = &calls[0].args;
        assert!(args.contains(&"exec".to_string()));
        assert!(args.contains(&"--jobs".to_string()));
        assert!(args.contains(&"2".to_string()));
        assert!(args.contains(&"--fresh".to_string()));
        assert!(args.contains(&"--raw".to_string()));
        assert!(args.contains(&"--".to_string()));
        assert!(args.contains(&"echo".to_string()));
        assert!(args.contains(&"hello".to_string()));
        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn test_which_strict_mode() {
        let expected = toride_runner::CommandSpec::new("/usr/bin/mise")
            .arg("which")
            .arg("node")
            .redact(true);
        let fake = Arc::new(FakeRunner::new().strict().respond(
            expected,
            CommandOutput::from_stdout(
                "/home/user/.local/share/mise/installs/node/22.1.0/bin/node",
            ),
        ));
        let mise = build_mise(fake.clone());

        let result = mise.which("node").await.unwrap();
        assert_eq!(result.bin, "node");

        fake.assert_called_with(
            &toride_runner::CommandSpec::new("/usr/bin/mise")
                .arg("which")
                .arg("node")
                .redact(true),
        );
    }
}
