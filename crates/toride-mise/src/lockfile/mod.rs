//! Lockfile support for mise tool installations.
//!
//! This module provides [`LockRequest`] for describing a lockfile operation and
//! adds [`Mise::lock`], [`Mise::lock_dry_run`], and [`Mise::install_locked`]
//! methods on the [`Mise`](crate::Mise) client.
//!
//! # Example
//!
//! ```rust,ignore
//! use toride_mise::lockfile::LockRequest;
//! use toride_mise::Mise;
//!
//! let mise = Mise::builder().build()?;
//!
//! let req = LockRequest::new(["node", "python"])
//!     .global(true)
//!     .platform("linux-x64")
//!     .jobs(4);
//!
//! let report = mise.lock(&req).await?;
//! println!("locked: {report:?}");
//! ```

use crate::client::Mise;
use crate::error::MiseResult;

// ---------------------------------------------------------------------------
// LockRequest
// ---------------------------------------------------------------------------

/// Describes a `mise lock` operation.
///
/// Construct with [`LockRequest::new`] and chain builder methods to set
/// optional parameters. Pass a reference to [`Mise::lock`] to execute the
/// lock, or to [`Mise::lock_dry_run`] to preview what would be locked
/// without writing anything.
#[derive(Debug, Clone)]
pub struct LockRequest {
    /// Tool names (and optional version pins) to include in the lockfile,
    /// e.g. `["node", "python@3.12"]`.
    pub(crate) tools: Vec<String>,
    /// When `true`, operate on the global (user-level) lockfile instead of
    /// the project-local one.
    pub(crate) global: bool,
    /// Platform triplets to resolve for, e.g. `["linux-x64", "macos-arm64"]`.
    pub(crate) platforms: Vec<String>,
    /// Maximum number of parallel download / install jobs.
    pub(crate) jobs: Option<usize>,
    /// When `true`, only print what *would* be locked; do not write the file.
    pub(crate) dry_run: bool,
    /// When `true`, write the lockfile next to the local config instead of
    /// the project root (`--local`).
    pub(crate) local_lock: bool,
    /// Only consider releases published at least this long ago (e.g. `"7d"`).
    pub(crate) minimum_release_age: Option<String>,
}

impl LockRequest {
    /// Create a new lock request for the given tools.
    ///
    /// Accepts any type that can be turned into a `String` (e.g. `&str`,
    /// `String`, or `ToolSpec` display output).
    pub fn new(tools: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        Self {
            tools: tools.into_iter().map(|t| t.as_ref().to_owned()).collect(),
            global: false,
            platforms: Vec::new(),
            jobs: None,
            dry_run: false,
            local_lock: false,
            minimum_release_age: None,
        }
    }

    /// Set the `--global` flag.
    ///
    /// When enabled, the lockfile is written to (or read from) the global
    /// mise configuration directory rather than the current project.
    #[must_use]
    pub fn global(mut self, yes: bool) -> Self {
        self.global = yes;
        self
    }

    /// Add a single platform triplet (e.g. `"linux-x64"`).
    #[must_use]
    pub fn platform(mut self, platform: impl AsRef<str>) -> Self {
        self.platforms.push(platform.as_ref().to_owned());
        self
    }

    /// Replace the full set of platform triplets.
    #[must_use]
    pub fn platforms(mut self, platforms: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        self.platforms = platforms
            .into_iter()
            .map(|p| p.as_ref().to_owned())
            .collect();
        self
    }

    /// Set the maximum number of parallel jobs (`--jobs`).
    #[must_use]
    pub fn jobs(mut self, n: usize) -> Self {
        self.jobs = Some(n);
        self
    }

    /// Set the dry-run flag (`--dry-run`).
    ///
    /// When enabled the lock command only prints what it *would* do without
    /// modifying the lockfile.
    #[must_use]
    pub fn dry_run(mut self, yes: bool) -> Self {
        self.dry_run = yes;
        self
    }

    /// Set the `--local` flag for the lockfile output path.
    ///
    /// When enabled, the lockfile is written next to the local config file
    /// rather than the project root.
    #[must_use]
    pub fn local_lock(mut self, yes: bool) -> Self {
        self.local_lock = yes;
        self
    }

    /// Only consider releases published at least this long ago (e.g. `"7d"`).
    #[must_use]
    pub fn minimum_release_age(mut self, age: impl AsRef<str>) -> Self {
        self.minimum_release_age = Some(age.as_ref().to_owned());
        self
    }
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

/// Summary returned by a successful `mise lock` invocation.
#[derive(Debug, Clone)]
pub struct LockReport {
    /// The tools that were resolved and locked.
    pub tools: Vec<String>,
    /// Whether the lock was global.
    pub global: bool,
    /// Raw stdout from the mise command.
    pub raw_output: String,
}

/// Summary returned by a successful `mise install --locked` invocation.
#[derive(Debug, Clone)]
pub struct InstallReport {
    /// The tools that were installed from the lockfile.
    pub tools: Vec<String>,
    /// Raw stdout from the mise command.
    pub raw_output: String,
}

// ---------------------------------------------------------------------------
// Mise impl — lockfile methods
// ---------------------------------------------------------------------------

impl Mise {
    /// Execute `mise lock` according to the given [`LockRequest`].
    ///
    /// Resolves the tools listed in `req` and writes (or updates) the
    /// lockfile. Returns a [`LockReport`] with the resolved tool versions.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the `mise lock` command exits
    /// non-zero.
    pub async fn lock(&self, req: &LockRequest) -> MiseResult<LockReport> {
        let args = Self::build_lock_args(req, false);
        let output = self.run_checked(args).await?;
        Ok(LockReport {
            tools: req.tools.clone(),
            global: req.global,
            raw_output: output.stdout_trimmed().to_owned(),
        })
    }

    /// Execute `mise lock --dry-run` according to the given [`LockRequest`].
    ///
    /// Performs the same resolution as [`Mise::lock`] but does **not** write
    /// the lockfile. Useful for previewing changes.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the `mise lock` command exits
    /// non-zero.
    pub async fn lock_dry_run(&self, req: &LockRequest) -> MiseResult<LockReport> {
        let mut req = req.clone();
        req.dry_run = true;
        let args = Self::build_lock_args(&req, true);
        let output = self.run_checked(args).await?;
        Ok(LockReport {
            tools: req.tools.clone(),
            global: req.global,
            raw_output: output.stdout_trimmed().to_owned(),
        })
    }

    /// Execute `mise install --locked` to install all tools from the existing
    /// lockfile.
    ///
    /// This enforces the lockfile: if any tool version listed in the lockfile
    /// cannot be installed the command will fail rather than falling back to
    /// latest.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the `mise install` command
    /// exits non-zero (e.g. a locked version is no longer available).
    pub async fn install_locked(&self) -> MiseResult<InstallReport> {
        let output = self.run_checked(["install", "--locked"]).await?;
        let raw = output.stdout_trimmed().to_owned();

        // Parse installed tool names from stdout.
        // mise outputs lines like "node 22.1.0 installed" or "Installed python@3.12.1".
        let tools = raw
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    return None;
                }
                // Extract the tool name from lines like "node 22.1.0 installed"
                // or "Installed python@3.12.1" or "python 3.12.1    installed".
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    Some(parts[0].to_owned())
                } else {
                    None
                }
            })
            .collect();

        Ok(InstallReport {
            tools,
            raw_output: raw,
        })
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Build the argument list for `mise lock` from a [`LockRequest`].
    fn build_lock_args(req: &LockRequest, force_dry_run: bool) -> Vec<String> {
        let mut args = vec!["lock".to_owned()];

        if req.global {
            args.push("--global".to_owned());
        }

        if force_dry_run || req.dry_run {
            args.push("--dry-run".to_owned());
        }

        if req.local_lock {
            args.push("--local".to_owned());
        }

        if let Some(ref age) = req.minimum_release_age {
            args.push("--minimum-release-age".to_owned());
            args.push(age.clone());
        }

        for platform in &req.platforms {
            args.push("--platform".to_owned());
            args.push(platform.clone());
        }

        if let Some(jobs) = req.jobs {
            args.push("--jobs".to_owned());
            args.push(jobs.to_string());
        }

        // Tool names / version pins come last as positional arguments.
        args.extend(req.tools.iter().cloned());

        args
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_request_new_sets_defaults() {
        let req = LockRequest::new(["node"]);
        assert_eq!(req.tools, vec!["node"]);
        assert!(!req.global);
        assert!(req.platforms.is_empty());
        assert!(req.jobs.is_none());
        assert!(!req.dry_run);
    }

    #[test]
    fn lock_request_builder_chaining() {
        let req = LockRequest::new(["node", "python@3.12"])
            .global(true)
            .platform("linux-x64")
            .platforms(["macos-arm64", "linux-x64"])
            .jobs(4)
            .dry_run(true);

        assert_eq!(req.tools, vec!["node", "python@3.12"]);
        assert!(req.global);
        assert_eq!(req.platforms, vec!["macos-arm64", "linux-x64"]);
        assert_eq!(req.jobs, Some(4));
        assert!(req.dry_run);
    }

    #[test]
    fn build_lock_args_minimal() {
        let req = LockRequest::new(["node"]);
        let args = Mise::build_lock_args(&req, false);
        assert_eq!(args, vec!["lock", "node"]);
    }

    #[test]
    fn build_lock_args_full() {
        let req = LockRequest::new(["node", "python@3.12"])
            .global(true)
            .platform("linux-x64")
            .jobs(8)
            .dry_run(true);

        let args = Mise::build_lock_args(&req, false);

        assert!(args.contains(&"lock".to_owned()));
        assert!(args.contains(&"--global".to_owned()));
        assert!(args.contains(&"--dry-run".to_owned()));
        assert!(args.contains(&"--platform".to_owned()));
        assert!(args.contains(&"linux-x64".to_owned()));
        assert!(args.contains(&"--jobs".to_owned()));
        assert!(args.contains(&"8".to_owned()));
        assert!(args.contains(&"node".to_owned()));
        assert!(args.contains(&"python@3.12".to_owned()));
    }

    #[test]
    fn build_lock_args_force_dry_run() {
        let req = LockRequest::new(["node"]).dry_run(false);
        let args = Mise::build_lock_args(&req, true);
        assert!(args.contains(&"--dry-run".to_owned()));
    }

    // --- FakeRunner-based integration tests ---

    use std::sync::Arc;
    use toride_runner::{CommandOutput, FakeRunner};

    fn build_mise(fake: Arc<FakeRunner>) -> Mise {
        Mise::builder()
            .runner(fake as Arc<dyn toride_runner::AsyncRunner>)
            .binary(crate::binary::MiseBinary::from_path("/usr/bin/mise"))
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn test_lock_builds_correct_command() {
        let fake =
            Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout("locked node")));
        let mise = build_mise(fake.clone());

        let req = LockRequest::new(["node", "python@3.12"]);
        let report = mise.lock(&req).await.unwrap();
        assert_eq!(report.tools, vec!["node", "python@3.12"]);
        assert!(!report.global);
        assert_eq!(report.raw_output, "locked node");

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].args.contains(&"lock".to_string()));
        assert!(calls[0].args.contains(&"node".to_string()));
        assert!(calls[0].args.contains(&"python@3.12".to_string()));
        // No --dry-run for normal lock
        assert!(!calls[0].args.contains(&"--dry-run".to_string()));
    }

    #[tokio::test]
    async fn test_lock_dry_run() {
        let fake = Arc::new(
            FakeRunner::new().push_response(CommandOutput::from_stdout("would lock node")),
        );
        let mise = build_mise(fake.clone());

        let req = LockRequest::new(["node"]);
        let report = mise.lock_dry_run(&req).await.unwrap();
        assert_eq!(report.tools, vec!["node"]);

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].args.contains(&"lock".to_string()));
        assert!(calls[0].args.contains(&"--dry-run".to_string()));
        assert!(calls[0].args.contains(&"node".to_string()));
    }
}
