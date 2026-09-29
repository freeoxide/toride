//! # Command-execution seam
//!
//! [`CommandRunner`] is the single choke point every backend command flows
//! through: it wraps an `Arc<dyn `[`AsyncRunner`]`>` (real
//! [`TokioRunner`] by default, `FakeRunner` — toride-runner's `fake`
//! feature — in tests), applies the seam's cwd/env policy to every spec,
//! and maps runner failures into the crate's
//! [`Error::Command`]. Backends never spawn processes directly — they build
//! specs with [`command`] (or [`CommandRunner::command`]) and hand them to
//! the seam.
//!
//! The builder mirrors toride-mise's `MiseBuilder` injection pattern: set an
//! explicit runner for tests, leave it unset for the production default.
//!
//! [`Error::Command`]: crate::Error::Command

use std::collections::BTreeMap;
use std::sync::Arc;

use camino::Utf8PathBuf;
use toride_runner::tokio_runner::TokioRunner;
use toride_runner::{AsyncRunner, CommandOutput, CommandSpec};

use crate::error::Result;

/// Build a [`CommandSpec`] for `program` with `args`, wired the way every
/// backend command must be wired.
///
/// This helper — not raw `CommandSpec::new` — is how backends construct
/// calls, so that stdio policy stays uniform: captured commands get
/// `stdin_null(true)` (the child can neither block on nor steal the parent
/// terminal's stdin; see the `stdin_null` field docs on [`CommandSpec`]).
///
/// # Example
///
/// ```
/// use toride_apps::command;
///
/// let spec = command("brew", ["install", "--cask", "firefox"]);
/// assert_eq!(spec.program, "brew");
/// assert_eq!(spec.args, ["install", "--cask", "firefox"]);
/// assert!(spec.stdin_null);
/// ```
#[must_use]
pub fn command(
    program: impl Into<String>,
    args: impl IntoIterator<Item = impl Into<String>>,
) -> CommandSpec {
    CommandSpec::new(program).args(args).stdin_null(true)
}

/// Thin async command-execution seam over a shared runner.
///
/// Cloning produces a second handle to the same underlying runner (the
/// runner lives behind an `Arc`), so backends can each hold a copy.
///
/// All execution flows through [`CommandRunner::run`] /
/// [`CommandRunner::run_checked`], which apply the seam's cwd/env policy
/// (see [`CommandRunner::prepare`]) before dispatching and map runner
/// failures into [`crate::Error::Command`].
#[derive(Clone)]
pub struct CommandRunner {
    /// The injectable command executor.
    runner: Arc<dyn AsyncRunner>,
    /// Working directory applied to every command; `None` inherits the
    /// process cwd.
    cwd: Option<Utf8PathBuf>,
    /// Extra environment variables applied to every command (`BTreeMap` for
    /// deterministic ordering — exact-match fake tests depend on it).
    env: BTreeMap<String, String>,
}

impl CommandRunner {
    /// Create a seam over an explicit runner, with no cwd/env policy.
    #[must_use]
    pub fn new(runner: Arc<dyn AsyncRunner>) -> Self {
        Self {
            runner,
            cwd: None,
            env: BTreeMap::new(),
        }
    }

    /// Start building a configured seam (runner defaults to
    /// [`TokioRunner`] when left unset).
    #[must_use]
    pub fn builder() -> CommandRunnerBuilder {
        CommandRunnerBuilder::new()
    }

    /// Build a spec for `program` + `args` through this seam: the shared
    /// [`command`] helper plus this seam's cwd/env policy.
    #[must_use]
    pub fn command(
        &self,
        program: impl Into<String>,
        args: impl IntoIterator<Item = impl Into<String>>,
    ) -> CommandSpec {
        self.prepare(command(program, args))
    }

    /// Apply the seam's cwd/env policy to a spec, returning the decorated
    /// spec. Exposed so backends and tests can inspect exactly what would be
    /// dispatched; [`CommandRunner::run`] applies it internally, so callers
    /// never need to.
    #[must_use]
    pub fn prepare(&self, mut spec: CommandSpec) -> CommandSpec {
        if let Some(cwd) = &self.cwd {
            spec = spec.cwd(cwd.clone().into_std_path_buf());
        }
        if !self.env.is_empty() {
            spec = spec.envs(self.env.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        }
        spec
    }

    /// Execute a spec and return its output, success or not.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Command`] when the runner fails to spawn, wait, or
    /// otherwise execute the command. A non-zero exit is *not* an error here — use
    /// [`CommandRunner::run_checked`] for that.
    pub async fn run(&self, spec: CommandSpec) -> Result<CommandOutput> {
        let spec = self.prepare(spec);
        Ok(self.runner.run(&spec).await?)
    }

    /// Execute a spec and fail on non-zero exits.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Command`] on execution failure or non-zero exit (the
    /// runner's `run_checked` renders program, args, exit code, and scrubbed
    /// stderr).
    pub async fn run_checked(&self, spec: CommandSpec) -> Result<CommandOutput> {
        let spec = self.prepare(spec);
        Ok(self.runner.run_checked(&spec).await?)
    }
}

/// Builder for constructing [`CommandRunner`] seams, modeled on toride-mise's
/// `MiseBuilder` runner-injection pattern: consume-and-return setters, with
/// the runner defaulting to a fresh [`TokioRunner`] when left unset (so,
/// unlike mise's, [`CommandRunnerBuilder::build`] is infallible — there is no
/// binary discovery to fail).
#[derive(Default)]
pub struct CommandRunnerBuilder {
    /// The async command runner. Defaults to [`TokioRunner`] in
    /// [`CommandRunnerBuilder::build`].
    runner: Option<Arc<dyn AsyncRunner>>,
    /// Working directory applied to every command.
    cwd: Option<Utf8PathBuf>,
    /// Extra environment variables applied to every command.
    env: BTreeMap<String, String>,
}

impl CommandRunnerBuilder {
    /// Create a builder with all defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the async command runner (a `FakeRunner` — toride-runner's
    /// `fake` feature — in tests, a [`TokioRunner`] or wrapper in
    /// production).
    #[must_use]
    pub fn runner(mut self, runner: Arc<dyn AsyncRunner>) -> Self {
        self.runner = Some(runner);
        self
    }

    /// Set the working directory for every command executed through the
    /// seam.
    #[must_use]
    pub fn cwd(mut self, cwd: impl Into<Utf8PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    /// Add a single environment variable applied to every command.
    #[must_use]
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    /// Add multiple environment variables applied to every command.
    #[must_use]
    pub fn envs<I, K, V>(mut self, pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        for (k, v) in pairs {
            self.env.insert(k.into(), v.into());
        }
        self
    }

    /// Consume the builder and produce the seam, defaulting the runner to a
    /// fresh [`TokioRunner`] when none was set.
    #[must_use]
    pub fn build(self) -> CommandRunner {
        let runner = self.runner.unwrap_or_else(|| Arc::new(TokioRunner));
        CommandRunner {
            runner,
            cwd: self.cwd,
            env: self.env,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use std::path::PathBuf;
    use toride_runner::fake::FakeRunner;

    /// Build a seam over a strict `FakeRunner`, for argv-exact assertions.
    fn seam(fake: FakeRunner) -> CommandRunner {
        CommandRunner::new(Arc::new(fake))
    }

    #[test]
    fn command_helper_sets_program_args_and_null_stdin() {
        let spec = command("flatpak", ["list", "--app"]);
        assert_eq!(spec.program, "flatpak");
        assert_eq!(spec.args, ["list", "--app"]);
        assert!(
            spec.stdin_null,
            "captured backend commands must not inherit stdin"
        );
    }

    #[tokio::test]
    async fn run_returns_output_through_the_seam() {
        let runner = seam(FakeRunner::new().push_response(CommandOutput::from_stdout("4.5.6")));
        let output = runner.run(command("brew", ["--version"])).await.unwrap();
        assert_eq!(output.stdout_trimmed(), "4.5.6");
    }

    #[tokio::test]
    async fn run_checked_maps_nonzero_exit_to_command_error() {
        let runner = seam(FakeRunner::new().push_response(CommandOutput::from_stderr("boom", 1)));
        let error = runner
            .run_checked(command("brew", ["install", "nope"]))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::Command(_)), "{error:?}");
    }

    #[tokio::test]
    async fn run_maps_runner_failure_to_command_error() {
        let spec = command("brew", ["--version"]);
        let runner = seam(FakeRunner::new().strict().respond_err(
            spec.clone(),
            toride_runner::Error::BinaryNotFound("brew".into()),
        ));
        let error = runner
            .run(command("brew", ["--version"]))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::Command(_)), "{error:?}");
    }

    #[tokio::test]
    async fn builder_env_and_cwd_are_applied_to_every_dispatched_spec() {
        let spec = command("brew", ["--prefix"]);
        let expected = command("brew", ["--prefix"])
            .cwd("/opt/brew")
            .env("HOMEBREW_NO_AUTO_UPDATE", "1");
        let fake = FakeRunner::new()
            .strict()
            .respond(expected.clone(), CommandOutput::from_stdout("/opt/brew"));
        let runner = CommandRunner::builder()
            .runner(Arc::new(fake.clone()))
            .cwd("/opt/brew")
            .env("HOMEBREW_NO_AUTO_UPDATE", "1")
            .build();
        let output = runner.run(spec).await.unwrap();
        assert_eq!(output.stdout_trimmed(), "/opt/brew");
        fake.assert_called_with(&expected);
    }

    #[test]
    fn builder_defaults_leave_the_spec_undecorated() {
        let runner = CommandRunner::builder().build();
        let spec = runner.prepare(command("brew", ["--version"]));
        assert_eq!(spec.cwd, None);
        assert!(spec.env.is_empty());
    }

    #[test]
    fn seam_command_method_applies_policy_to_helper_spec() {
        let runner = CommandRunner::builder()
            .cwd(Utf8PathBuf::from("/workspace"))
            .env("TORIDE_TEST", "1")
            .build();
        let spec = runner.command("make", ["check"]);
        assert_eq!(spec.cwd, Some(PathBuf::from("/workspace")));
        assert!(
            spec.env
                .contains(&("TORIDE_TEST".to_owned(), "1".to_owned()))
        );
    }
}
