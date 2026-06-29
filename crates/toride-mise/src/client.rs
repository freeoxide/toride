//! High-level async client for interacting with mise.
//!
//! [`Mise`] is the primary entry point for the `toride-mise` crate. It wraps
//! the `mise` CLI and exposes typed async methods for querying tool versions,
//! config files, and environment state.
//!
//! # Example
//!
//! ```rust,ignore
//! use toride_mise::Mise;
//!
//! let mise = Mise::builder().build()?;
//! let output = mise.run(["--version"]).await?;
//! println!("mise version: {}", output.stdout_trimmed());
//! ```

use std::collections::BTreeMap;
use std::sync::Arc;

use camino::Utf8PathBuf;

use crate::binary::MiseBinary;
use crate::error::{MiseError, MiseResult};
use crate::languages::{
    bun::BunHelper, deno::DenoHelper, generic::GenericHelper, go::GoHelper, java::JavaHelper,
    node::NodeHelper, python::PythonHelper, ruby::RubyHelper, rust::RustHelper,
};

// ---------------------------------------------------------------------------
// Re-export builder
// ---------------------------------------------------------------------------

pub use crate::builder::MiseBuilder;

// ---------------------------------------------------------------------------
// MiseMode
// ---------------------------------------------------------------------------

/// Controls how the `mise` binary is invoked with respect to trust.
///
/// - [`Trusted`](MiseMode::Trusted): assumes config files are already trusted.
///   No `mise trust` or confirmation prompts are expected.
/// - [`Untrusted`](MiseMode::Untrusted): mise may prompt or reject config
///   files that have not been explicitly trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MiseMode {
    /// Config files are treated as already trusted.
    #[default]
    Trusted,
    /// Config files may require explicit trust confirmation.
    Untrusted,
}

// ---------------------------------------------------------------------------
// LoadPolicy
// ---------------------------------------------------------------------------

/// Controls which mise subsystems are loaded on each invocation.
///
/// Each boolean maps to a corresponding `--no-*` CLI flag. All fields default
/// to `true` (i.e. everything is loaded).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadPolicy {
    /// Load config files. When `false`, passes `--no-config`.
    pub config: bool,
    /// Set environment variables. When `false`, passes `--no-env`.
    pub env: bool,
    /// Run hooks. When `false`, passes `--no-hooks`.
    pub hooks: bool,
}

impl Default for LoadPolicy {
    fn default() -> Self {
        Self {
            config: true,
            env: true,
            hooks: true,
        }
    }
}

// ---------------------------------------------------------------------------
// MiseProject (forward declaration)
// ---------------------------------------------------------------------------

/// Represents a mise-enabled project directory with its own config and tools.
///
/// This is a placeholder type; full implementation lives behind future work.
#[derive(Debug, Clone)]
pub struct MiseProject {
    /// Path to the project root.
    pub path: Utf8PathBuf,
    /// The mise client used for project operations.
    pub(crate) mise: Mise,
}

// ---------------------------------------------------------------------------
// RuntimeManager (forward declaration)
// ---------------------------------------------------------------------------

/// Manages runtime installations for a set of tools.
///
/// This is a placeholder type; full implementation lives behind future work.
#[derive(Debug)]
pub struct RuntimeManager {
    /// The mise client used for runtime operations.
    pub client: Mise,
}

// ---------------------------------------------------------------------------
// Mise
// ---------------------------------------------------------------------------

/// High-level async client for interacting with the mise CLI.
///
/// Owns an [`AsyncRunner`](toride_runner::AsyncRunner), a [`MiseBinary`],
/// and various configuration knobs. Use [`Mise::builder`] to construct one.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone)]
pub struct Mise {
    /// The async command runner used to execute mise.
    pub(crate) runner: Arc<dyn toride_runner::AsyncRunner>,
    /// Optional streaming runner for real-time output events.
    ///
    /// When set, [`install_streaming`](Mise::install_streaming) and
    /// [`exec_streaming`](Mise::exec_streaming) will use this runner to
    /// deliver [`CommandEvent`](toride_runner::CommandEvent)s to a sink.
    /// When `None`, those methods fall back to [`Mise::run_checked`].
    pub(crate) streaming_runner: Option<Arc<dyn toride_runner::AsyncStreamingRunner>>,
    /// The mise binary to invoke.
    pub(crate) binary: MiseBinary,
    /// Working directory for all commands.
    pub(crate) cwd: Option<Utf8PathBuf>,
    /// Extra environment variables.
    pub(crate) env: BTreeMap<String, String>,
    /// Trust mode.
    pub(crate) mode: MiseMode,
    /// Which subsystems to load.
    pub(crate) load_policy: LoadPolicy,
    /// Whether to pass `--locked`.
    pub(crate) locked: bool,
    /// Whether to pass `--no-config`.
    pub(crate) no_config: bool,
    /// Whether to pass `--no-env`.
    pub(crate) no_env: bool,
    /// Whether to pass `--no-hooks`.
    pub(crate) no_hooks: bool,
    /// Optional minimum mise version for [`Mise::verify_version`].
    pub(crate) minimum_version: Option<semver::Version>,
}

impl std::fmt::Debug for Mise {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mise")
            .field("binary", &self.binary)
            .field("cwd", &self.cwd)
            .field("mode", &self.mode)
            .field("load_policy", &self.load_policy)
            .field("locked", &self.locked)
            .field("no_config", &self.no_config)
            .field("no_env", &self.no_env)
            .field("no_hooks", &self.no_hooks)
            .field("minimum_version", &self.minimum_version)
            .field("env", &self.env)
            .field("streaming_runner", &self.streaming_runner.is_some())
            .finish_non_exhaustive()
    }
}

impl Mise {
    /// Return a new [`MiseBuilder`] for constructing a [`Mise`] client.
    #[must_use]
    pub fn builder() -> MiseBuilder {
        MiseBuilder::new()
    }

    /// Discover the `mise` binary on the system.
    ///
    /// Delegates to [`MiseBinary::discover`].
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::BinaryNotFound`] if the binary cannot be found.
    pub fn discover() -> MiseResult<MiseBinary> {
        MiseBinary::discover()
    }

    /// Return the binary name used for command construction.
    ///
    /// This is the string form of the discovered binary path, suitable for
    /// use as `CommandSpec::new(self.binary_name())`.
    pub fn binary_name(&self) -> &str {
        self.binary.as_str()
    }

    // -----------------------------------------------------------------------
    // Language accessor methods
    // -----------------------------------------------------------------------

    /// Return a [`NodeHelper`] for interacting with Node.js via mise.
    pub fn node(&self) -> NodeHelper<'_> {
        NodeHelper::new(self)
    }

    /// Return a [`BunHelper`] for interacting with Bun via mise.
    pub fn bun(&self) -> BunHelper<'_> {
        BunHelper::new(self)
    }

    /// Return a [`DenoHelper`] for interacting with Deno via mise.
    pub fn deno(&self) -> DenoHelper<'_> {
        DenoHelper::new(self)
    }

    /// Return a [`GoHelper`] for interacting with Go via mise.
    pub fn go(&self) -> GoHelper<'_> {
        GoHelper::new(self)
    }

    /// Return a [`PythonHelper`] for interacting with Python via mise.
    pub fn python(&self) -> PythonHelper<'_> {
        PythonHelper::new(self)
    }

    /// Return a [`RustHelper`] for interacting with Rust via mise.
    pub fn rust(&self) -> RustHelper<'_> {
        RustHelper::new(self)
    }

    /// Return a [`RubyHelper`] for interacting with Ruby via mise.
    pub fn ruby(&self) -> RubyHelper<'_> {
        RubyHelper::new(self)
    }

    /// Return a [`JavaHelper`] for interacting with Java via mise.
    pub fn java(&self) -> JavaHelper<'_> {
        JavaHelper::new(self)
    }

    /// Return a [`GenericHelper`] for interacting with an arbitrary mise tool.
    ///
    /// `name` should be a bare tool name recognised by mise (e.g. `"terraform"`,
    /// `"jq"`, `"ripgrep"`).
    pub fn tool(&self, name: &str) -> GenericHelper<'_> {
        GenericHelper::new(self, name)
    }

    /// Return a [`DiagnosticsBuilder`](crate::diagnostics::DiagnosticsBuilder)
    /// for running selective diagnostic checks.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let report = mise.diagnostics()
    ///     .check_binary()
    ///     .check_missing_tools()
    ///     .run()
    ///     .await?;
    /// ```
    pub fn diagnostics(&self) -> crate::diagnostics::DiagnosticsBuilder<'_> {
        crate::diagnostics::DiagnosticsBuilder::new(self)
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Build the base environment map for every mise invocation.
    ///
    /// Currently returns a clone of the configured extra environment. In the
    /// future this may merge in system environment or mode-specific overrides.
    fn base_env(&self) -> BTreeMap<String, String> {
        self.env.clone()
    }

    /// Build a [`toride_runner::CommandSpec`] for the given arguments, applying
    /// the global flags (`--no-config`, `--no-env`, `--no-hooks`, `--locked`)
    /// and the configured working directory and environment.
    pub(crate) fn build_command(
        &self,
        args: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> toride_runner::CommandSpec {
        let mut spec = toride_runner::CommandSpec::new(self.binary_name());

        // Apply global flags based on LoadPolicy and explicit overrides.
        if self.no_config || !self.load_policy.config {
            spec = spec.arg("--no-config");
        }
        if self.no_env || !self.load_policy.env {
            spec = spec.arg("--no-env");
        }
        if self.no_hooks || !self.load_policy.hooks {
            spec = spec.arg("--no-hooks");
        }
        if self.locked {
            spec = spec.arg("--locked");
        }

        // Append caller-provided arguments.
        for arg in args {
            spec = spec.arg(arg.as_ref());
        }

        // Apply working directory.
        if let Some(ref cwd) = self.cwd {
            spec = spec.cwd(cwd.as_std_path());
        }

        // Apply environment variables.
        let env = self.base_env();
        for (key, value) in env {
            spec = spec.env(key, value);
        }

        // Declare redaction on the spec itself. mise commands (notably
        // `env --json` / `--dotenv` / `--shell`) can echo tool-managed secrets
        // in their arguments or captured output. Marking the spec ensures the
        // runner scrubs sensitive material from display/logging and any
        // streamed chunks once redact is honored upstream.
        spec = spec.redact(true);

        spec
    }

    // -----------------------------------------------------------------------
    // Async command execution
    // -----------------------------------------------------------------------

    /// Run a mise command with the given arguments and return the raw output.
    ///
    /// This is the lowest-level async execution method. It does **not** check
    /// the exit code — callers that need error-on-failure should use
    /// [`Mise::run_checked`] instead.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::BinaryNotFound`] if the binary is missing.
    /// Returns [`MiseError::Io`] if the command cannot be spawned.
    pub async fn run(
        &self,
        args: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> MiseResult<toride_runner::CommandOutput> {
        let spec = self.build_command(args);
        let output = self.runner.run(&spec).await?;
        Ok(output)
    }

    /// Run a mise command and return an error if it exits non-zero.
    ///
    /// This is the same as [`Mise::run`] but converts non-zero exit codes
    /// into [`MiseError::CommandFailed`].
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::BinaryNotFound`] if the binary is missing.
    pub async fn run_checked(
        &self,
        args: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> MiseResult<toride_runner::CommandOutput> {
        let spec = self.build_command(args);
        let output = self.runner.run_checked(&spec).await?;
        Ok(output)
    }

    /// Run a mise command, verify it succeeded, and parse stdout as JSON.
    ///
    /// Calls [`Mise::run_checked`] to execute the command, then deserializes
    /// the trimmed stdout into `T` via `serde_json`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`] if stdout cannot be parsed as JSON.
    pub async fn run_json<T: serde::de::DeserializeOwned>(
        &self,
        args: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> MiseResult<T> {
        let output = self.run_checked(args).await?;
        let raw = output.stdout_trimmed();
        let raw_owned = raw.to_owned();
        serde_json::from_str(raw).map_err(|e| MiseError::JsonParse {
            command: self.binary_name().to_owned(),
            source: e,
            stdout: raw_owned,
        })
    }

    /// Like [`Mise::run_json`] but gracefully handles `{}` (empty JSON object)
    /// or `null` being returned where a `Vec<T>` is expected.
    ///
    /// Some mise commands (e.g. `mise ls --json`) return `{}` instead of `[]`
    /// when there are no entries. This method detects that case and returns
    /// an empty `Vec`.
    pub async fn run_json_vec_safe<T: serde::de::DeserializeOwned>(
        &self,
        args: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> MiseResult<Vec<T>> {
        let output = self.run_checked(args).await?;
        let raw = output.stdout_trimmed();

        // Fast path: if the output is empty, `{}`, or `null`, return an empty vec.
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed == "{}" || trimmed == "null" {
            return Ok(Vec::new());
        }

        let raw_owned = raw.to_owned();
        serde_json::from_str(raw).map_err(|e| MiseError::JsonParse {
            command: self.binary_name().to_owned(),
            source: e,
            stdout: raw_owned,
        })
    }

    /// Query the mise version as structured JSON.
    ///
    /// Invokes `mise version --json` and parses the output into a
    /// [`MiseVersionJson`](crate::serde_utils::json_outputs::MiseVersionJson).
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`] if the output cannot be deserialised.
    pub async fn version_json(
        &self,
    ) -> MiseResult<crate::serde_utils::json_outputs::MiseVersionJson> {
        self.run_json(["version", "--json"]).await
    }

    /// Verify that the installed mise version meets the minimum requirement.
    ///
    /// Runs `mise --version`, parses the output, and returns
    /// [`MiseError::UnsupportedVersion`] if the version is below the configured
    /// [`MiseBuilder::minimum_version`]. If no minimum version was configured,
    /// this is a no-op.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::UnsupportedVersion`] if the installed version is
    /// below the minimum. Returns [`MiseError::CommandFailed`] if `mise
    /// --version` fails.
    pub async fn verify_version(&self) -> MiseResult<()> {
        let Some(minimum) = &self.minimum_version else {
            return Ok(());
        };

        let output = self.run_checked(["--version"]).await?;
        let version = crate::binary::MiseVersion::parse(output.stdout_trimmed());

        if !version.is_at_least(minimum) {
            return Err(MiseError::UnsupportedVersion {
                version_output: version.raw,
            });
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MiseProject implementation
// ---------------------------------------------------------------------------

impl MiseProject {
    /// Create a new [`MiseProject`] rooted at `root` with the given [`Mise`] client.
    pub fn new(root: Utf8PathBuf, mise: Mise) -> Self {
        Self { path: root, mise }
    }

    /// Detect mise config files present in the project root.
    ///
    /// Looks for common filenames such as `.mise.toml`, `.mise.local.toml`,
    /// `mise.toml`, and `config/mise.toml`. Returns the paths of files that
    /// exist on disk relative to the project root.
    pub fn detect_config_files(&self) -> MiseResult<Vec<Utf8PathBuf>> {
        let candidates = [
            ".mise.toml",
            ".mise.local.toml",
            "mise.toml",
            "mise.local.toml",
            "config/mise.toml",
        ];

        let mut found = Vec::new();
        for name in &candidates {
            let candidate = self.path.join(name);
            if candidate.is_file() {
                found.push(candidate);
            }
        }

        Ok(found)
    }

    /// List the tools and their resolved versions for this project.
    ///
    /// Delegates to `mise ls --json` in the project directory.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`] if stdout cannot be parsed.
    pub async fn list_tools<T: serde::de::DeserializeOwned>(&self) -> MiseResult<T> {
        self.mise.run_json(["ls", "--json"]).await
    }

    /// Install any missing tools required by this project's config.
    ///
    /// Delegates to `mise install` in the project directory.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    pub async fn install_missing(&self) -> MiseResult<toride_runner::CommandOutput> {
        self.mise.run_checked(["install"]).await
    }

    /// Return the environment variables that mise would set for this project.
    ///
    /// Delegates to `mise env --json`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`] if stdout cannot be parsed.
    pub async fn env<T: serde::de::DeserializeOwned>(&self) -> MiseResult<T> {
        self.mise.run_json(["env", "--json"]).await
    }

    /// Execute a command inside the mise-managed environment.
    ///
    /// Delegates to `mise exec -- <command>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    pub async fn exec(
        &self,
        command: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> MiseResult<toride_runner::CommandOutput> {
        let mut args: Vec<String> = vec!["exec".into(), "--".into()];
        for arg in command {
            args.push(arg.as_ref().to_owned());
        }
        self.mise.run_checked(args).await
    }

    /// Generate or update the lockfile for this project.
    ///
    /// Delegates to `mise lock`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    pub async fn lock(&self) -> MiseResult<toride_runner::CommandOutput> {
        self.mise.run_checked(["lock"]).await
    }
}

// ---------------------------------------------------------------------------
// RuntimeManager implementation
// ---------------------------------------------------------------------------

impl RuntimeManager {
    /// Create a new [`RuntimeManager`] backed by the given [`Mise`] client.
    pub fn new(mise: Mise) -> Self {
        Self { client: mise }
    }

    /// Ensure that a specific version of a tool is installed.
    ///
    /// Delegates to `mise use <tool>@<version>` followed by `mise install`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if either command exits non-zero.
    pub async fn ensure(&self, tool: &str, version: &str) -> MiseResult<()> {
        let spec = format!("{tool}@{version}");
        self.client.run_checked(["use", &spec]).await?;
        self.client.run_checked(["install"]).await?;
        Ok(())
    }

    /// Ensure multiple tool/version pairs are installed.
    ///
    /// Calls [`RuntimeManager::ensure`] for each pair.
    ///
    /// # Errors
    ///
    /// Returns the first error encountered.
    pub async fn ensure_many(&self, tools: &[(&str, &str)]) -> MiseResult<()> {
        for (tool, version) in tools {
            self.ensure(tool, version).await?;
        }
        Ok(())
    }

    /// Run a command in an environment where all requested tools are available.
    ///
    /// Delegates to `mise exec <spec> -- <command>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    pub async fn run_with(
        &self,
        spec: impl AsRef<str>,
        command: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> MiseResult<toride_runner::CommandOutput> {
        let mut args: Vec<String> = vec!["exec".into(), spec.as_ref().to_owned(), "--".into()];
        for arg in command {
            args.push(arg.as_ref().to_owned());
        }
        self.client.run_checked(args).await
    }

    /// Resolve the filesystem path to a binary provided by a mise-managed tool.
    ///
    /// Delegates to `mise which <bin>` and returns the trimmed stdout as a path.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    pub async fn resolve_bin(&self, bin: &str) -> MiseResult<Utf8PathBuf> {
        let output = self.client.run_checked(["which", bin]).await?;
        Ok(Utf8PathBuf::from(output.stdout_trimmed().to_owned()))
    }
}
