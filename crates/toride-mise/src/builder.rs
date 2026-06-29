//! Builder for constructing configured [`Mise`](crate::Mise) instances.
//!
//! [`MiseBuilder`] follows the consume-and-return builder pattern: each setter
//! consumes `self`, applies the configuration, and returns a new `Self`.
//!
//! # Example
//!
//! ```rust,ignore
//! use toride_mise::MiseBuilder;
//!
//! let mise = MiseBuilder::new()
//!     .cwd("/projects/my-app")
//!     .env("MISE_USE_VERSIONS_HOST", "false")
//!     .no_config(true)
//!     .build()?;
//! ```

use std::collections::BTreeMap;
use std::sync::Arc;

use camino::Utf8PathBuf;

use crate::client::Mise;
use crate::error::MiseResult;

// ---------------------------------------------------------------------------
// MiseBuilder
// ---------------------------------------------------------------------------

/// Builder for constructing [`Mise`] instances.
///
/// Provides a fluent interface for configuring the runner, binary path,
/// working directory, environment variables, and various mise flags before
/// calling [`MiseBuilder::build`] to produce a [`Mise`].
#[allow(clippy::struct_excessive_bools)]
pub struct MiseBuilder {
    /// The async command runner. Defaults to [`TokioRunner`] if not set.
    runner: Option<Arc<dyn toride_runner::AsyncRunner>>,
    /// Optional streaming runner for real-time output events.
    streaming_runner: Option<Arc<dyn toride_runner::AsyncStreamingRunner>>,
    /// The mise binary to use. Discovered via `$PATH` if not set.
    binary: Option<crate::binary::MiseBinary>,
    /// Working directory for all mise commands. Defaults to the current
    /// directory if not set.
    cwd: Option<Utf8PathBuf>,
    /// Extra environment variables passed to every mise invocation.
    env: BTreeMap<String, String>,
    /// Pass `--no-config` to skip loading config files.
    no_config: bool,
    /// Pass `--no-env` to skip setting environment variables.
    no_env: bool,
    /// Pass `--no-hooks` to skip running hooks.
    no_hooks: bool,
    /// Pass `--locked` to enforce lockfile usage.
    locked: bool,
    /// Trust mode for mise invocations.
    mode: crate::client::MiseMode,
    /// When `true`, call [`Mise::verify_version`] immediately after construction
    /// if `minimum_version` is set.
    verify_version: bool,
    /// Optional minimum mise version. Used by [`Mise::verify_version`] to check
    /// that the installed mise meets the requirement.
    minimum_version: Option<semver::Version>,
}

impl MiseBuilder {
    /// Create a new builder with all defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            runner: None,
            streaming_runner: None,
            binary: None,
            cwd: None,
            env: BTreeMap::new(),
            no_config: false,
            no_env: false,
            no_hooks: false,
            locked: false,
            mode: crate::client::MiseMode::default(),
            verify_version: false,
            minimum_version: None,
        }
    }

    /// Set the async command runner.
    ///
    /// If not provided, [`MiseBuilder::build`] will default to a fresh
    /// [`TokioRunner`](toride_runner::tokio_runner::TokioRunner).
    #[must_use]
    pub fn runner(mut self, runner: Arc<dyn toride_runner::AsyncRunner>) -> Self {
        self.runner = Some(runner);
        self
    }

    /// Set the streaming command runner for real-time output events.
    ///
    /// When provided, [`Mise::install_streaming`] and [`Mise::exec_streaming`]
    /// will use this runner to deliver [`CommandEvent`](toride_runner::CommandEvent)s
    /// to a [`CommandEventSink`](toride_runner::CommandEventSink). When absent,
    /// those methods fall back to regular non-streaming execution.
    #[must_use]
    pub fn streaming_runner(
        mut self,
        runner: Arc<dyn toride_runner::AsyncStreamingRunner>,
    ) -> Self {
        self.streaming_runner = Some(runner);
        self
    }

    /// Set the mise binary explicitly.
    ///
    /// If not provided, [`MiseBuilder::build`] will attempt to discover the
    /// binary via [`Mise::discover`].
    #[must_use]
    pub fn binary(mut self, binary: crate::binary::MiseBinary) -> Self {
        self.binary = Some(binary);
        self
    }

    /// Set the mise binary from a path string.
    ///
    /// Convenience method that constructs a [`MiseBinary`] from the given path
    /// and delegates to [`MiseBuilder::binary`].
    #[must_use]
    pub fn binary_path(mut self, path: impl Into<camino::Utf8PathBuf>) -> Self {
        self.binary = Some(crate::binary::MiseBinary::from_path(path));
        self
    }

    /// Set the working directory for all mise invocations.
    #[must_use]
    pub fn cwd(mut self, cwd: impl Into<Utf8PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    /// Add a single environment variable.
    #[must_use]
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    /// Add multiple environment variables from an iterator.
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

    /// Set the `--no-config` flag.
    #[must_use]
    pub fn no_config(mut self, yes: bool) -> Self {
        self.no_config = yes;
        self
    }

    /// Set the `--no-env` flag.
    #[must_use]
    pub fn no_env(mut self, yes: bool) -> Self {
        self.no_env = yes;
        self
    }

    /// Set the `--no-hooks` flag.
    #[must_use]
    pub fn no_hooks(mut self, yes: bool) -> Self {
        self.no_hooks = yes;
        self
    }

    /// Set the `--locked` flag.
    #[must_use]
    pub fn locked(mut self, yes: bool) -> Self {
        self.locked = yes;
        self
    }

    /// Set the trust mode.
    #[must_use]
    pub fn mode(mut self, mode: crate::client::MiseMode) -> Self {
        self.mode = mode;
        self
    }

    /// Enable version verification after construction.
    ///
    /// When set to `true` and a [`MiseBuilder::minimum_version`] is configured,
    /// [`MiseBuilder::build`] will call [`Mise::verify_version`] before
    /// returning the [`Mise`] instance.
    #[must_use]
    pub fn verify_version(mut self, yes: bool) -> Self {
        self.verify_version = yes;
        self
    }

    /// Set a minimum required mise version.
    ///
    /// If [`MiseBuilder::verify_version`] is `true`, the built [`Mise`] client
    /// will check that the installed mise version meets this requirement.
    #[must_use]
    pub fn minimum_version(mut self, version: semver::Version) -> Self {
        self.minimum_version = Some(version);
        self
    }

    /// Consume the builder and produce a [`Mise`] client.
    ///
    /// If no runner was provided, defaults to a
    /// [`TokioRunner`](toride_runner::tokio_runner::TokioRunner). If no
    /// binary was provided, attempts to discover `mise` on `$PATH`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::BinaryNotFound`](crate::MiseError::BinaryNotFound)
    /// if no binary was provided and `mise` cannot be found on `$PATH`.
    pub fn build(self) -> MiseResult<Mise> {
        let runner = self
            .runner
            .unwrap_or_else(|| Arc::new(toride_runner::tokio_runner::TokioRunner));

        let binary = match self.binary {
            Some(b) => b,
            None => Mise::discover()?,
        };

        Ok(Mise {
            runner,
            streaming_runner: self.streaming_runner,
            binary,
            cwd: self.cwd,
            env: self.env,
            mode: self.mode,
            load_policy: crate::client::LoadPolicy::default(),
            locked: self.locked,
            no_config: self.no_config,
            no_env: self.no_env,
            no_hooks: self.no_hooks,
            minimum_version: self.minimum_version,
        })
    }
}

impl Default for MiseBuilder {
    fn default() -> Self {
        Self::new()
    }
}
