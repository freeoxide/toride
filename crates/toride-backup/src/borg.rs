//! Borg Backup CLI wrapper.
//!
//! [`BorgClient`] provides a typed interface to the `borg` binary for
//! common backup operations: initialising repositories, creating archives,
//! listing archives, checking integrity, pruning, extracting, and querying
//! repository info.
//!
//! All commands go through a centralised [`Runner`](toride_runner::Runner) so
//! that they are testable (via [`FakeRunner`](toride_runner::FakeRunner)) and
//! respect a uniform redaction / output-capping policy. The passphrase is
//! always passed via the `BORG_PASSPHRASE` environment variable (never as a
//! CLI argument, per the official Borg frontend guidance) and every
//! secret-bearing command is built with [`CommandSpec::redact`](toride_runner::CommandSpec::redact)`(true)`
//! so the passphrase and repo location are scrubbed from errors and logs.
//!
//! # Example
//!
//! ```ignore
//! use toride_backup::borg::BorgClient;
//!
//! let client = BorgClient::new("/mnt/backups/my-server")?
//!     .with_passphrase("correct horse battery staple");
//! client.init()?;
//! client.create("daily", &[std::path::Path::new("/etc")])?;
//! let archives = client.list()?;
//! ```

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::spec::Encryption;
use crate::{Error, Result};

// Re-export the runner primitives so the rest of this module can refer to them
// without a separate feature gate — the `client` feature (which is the only
// context in which the wrapper is meaningfully exercised) pulls in
// `toride_runner`'s `duct-runner` + `fake` features via the workspace Cargo.toml.
use toride_runner::{CommandSpec, Runner};

// ---------------------------------------------------------------------------
// BorgClient
// ---------------------------------------------------------------------------

/// Typed wrapper around the `borg` binary.
///
/// Every method constructs the appropriate argument list and delegates
/// execution to the underlying command runner. Arguments are always passed
/// as arrays -- no shell string concatenation is used.
///
/// # Secrets
///
/// The repository passphrase is held in [`Self::passphrase`] and injected into
/// each command via the `BORG_PASSPHRASE` environment variable. Commands that
/// carry the passphrase (or any other secret) are built with `redact(true)`,
/// which ensures the secret values are scrubbed from any error message or log
/// line produced by the runner.
pub struct BorgClient {
    /// Resolved path to the `borg` binary.
    binary: PathBuf,
    /// Repository path or URL.
    repo: PathBuf,
    /// Optional passphrase for repository encryption.
    passphrase: Option<String>,
    /// Extra environment variables.
    extra_env: Vec<(String, String)>,
    /// The command runner used to execute every `borg` invocation.
    runner: Arc<dyn Runner>,
}

impl BorgClient {
    /// Create a new borg client by locating `borg` on `$PATH`.
    ///
    /// Uses the default [`toride_runner::DuctRunner`] for command execution.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BinaryNotFound`] if `borg` is not on `$PATH`.
    pub fn new(repo: impl AsRef<Path>) -> Result<Self> {
        let binary = which::which("borg").map_err(|_| {
            Error::BinaryNotFound("borg".into())
        })?;
        Ok(Self {
            binary,
            repo: repo.as_ref().to_path_buf(),
            passphrase: None,
            extra_env: Vec::new(),
            runner: Arc::new(toride_runner::DuctRunner),
        })
    }

    /// Create a client with an explicit binary path.
    ///
    /// Uses the default [`toride_runner::DuctRunner`] for command execution.
    /// Call [`Self::with_runner`] to inject a fake runner for testing.
    pub fn with_binary(binary: PathBuf, repo: impl AsRef<Path>) -> Self {
        Self {
            binary,
            repo: repo.as_ref().to_path_buf(),
            passphrase: None,
            extra_env: Vec::new(),
            runner: Arc::new(toride_runner::DuctRunner),
        }
    }

    /// Set the passphrase for repository encryption.
    ///
    /// The passphrase is delivered to `borg` through the `BORG_PASSPHRASE`
    /// environment variable rather than a CLI flag (the recommended approach
    /// in the Borg frontend documentation).
    #[must_use]
    pub fn with_passphrase(mut self, passphrase: impl Into<String>) -> Self {
        self.passphrase = Some(passphrase.into());
        self
    }

    /// Add an extra environment variable.
    #[must_use]
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra_env.push((key.into(), value.into()));
        self
    }

    /// Replace the command runner.
    ///
    /// Primarily intended for injecting a [`FakeRunner`](toride_runner::FakeRunner)
    /// in unit tests. The runner is shared (via [`Arc`]) so the client remains
    /// cheap to clone-free.
    #[must_use]
    pub fn with_runner(mut self, runner: Arc<dyn Runner>) -> Self {
        self.runner = runner;
        self
    }

    // -----------------------------------------------------------------------
    // Repository management
    // -----------------------------------------------------------------------

    /// Initialise a new borg repository.
    ///
    /// Runs `borg init --encryption=<mode> <repo>` where `<mode>` is derived
    /// from [`Encryption`] (defaulting to `repokey`, the Borg-recommended
    /// mode). The passphrase — if set — is supplied via `BORG_PASSPHRASE`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RepositoryInit`] if the init command fails.
    pub fn init(&self) -> Result<()> {
        let mode = self.encryption_mode(&Encryption::RepoKey);
        let spec = self
            .command("init")
            .args(["--encryption", mode])
            .arg(self.repo_arg())
            .redact(self.carries_secret());

        tracing::info!(repo = %self.repo.display(), mode, "borg init");
        self.run_unit(&spec, Error::RepositoryInit)?;
        Ok(())
    }

    /// Check repository integrity.
    ///
    /// Runs `borg check <repo>`. Uses repository-only verification by default
    /// (no archive verification pass) which matches the common operational
    /// use of `borg check`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RepositoryAccess`] if the check command fails.
    pub fn check(&self) -> Result<String> {
        let spec = self
            .command("check")
            .arg(self.repo_arg())
            .redact(self.carries_secret());

        tracing::info!(repo = %self.repo.display(), "borg check");
        let output = self.run_string(&spec, Error::RepositoryAccess)?;
        Ok(output)
    }

    // -----------------------------------------------------------------------
    // Archive operations
    // -----------------------------------------------------------------------

    /// Create a new archive in the repository.
    ///
    /// Runs `borg create <repo>::<archive> <paths...>`. The `--stats` flag is
    /// added so the returned string contains a human-readable summary.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the create command fails.
    pub fn create(&self, archive: &str, paths: &[&Path]) -> Result<String> {
        let target = format!("{}::{}", self.repo_arg(), archive);
        let mut spec = self
            .command("create")
            .arg("--stats")
            .arg(target);
        for path in paths {
            spec = spec.arg(path.to_string_lossy().to_string());
        }
        let spec = spec.redact(self.carries_secret());

        tracing::info!(
            repo = %self.repo.display(),
            archive = %archive,
            paths = ?paths.iter().map(|p| p.display()).collect::<Vec<_>>(),
            "borg create"
        );
        let output = self.run_string(&spec, Error::command_failed)?;
        Ok(output)
    }

    /// List all archives in the repository as JSON.
    ///
    /// Runs `borg list --json <repo>`. The returned string is the raw JSON
    /// object documented by Borg: `{repository:{...}, encryption:{mode},
    /// archives:[{id,name,start}, ...]}`. Use [`BorgClient::parse_list`]
    /// to deserialize it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the list command fails.
    pub fn list(&self) -> Result<String> {
        let spec = self
            .command("list")
            .arg("--json")
            .arg(self.repo_arg())
            .redact(self.carries_secret());

        tracing::info!(repo = %self.repo.display(), "borg list --json");
        let output = self.run_string(&spec, Error::command_failed)?;
        Ok(output)
    }

    /// Query repository information as JSON.
    ///
    /// Runs `borg info --json <repo>`. The returned string is the raw JSON
    /// object documented by Borg: `{repository:{...}, cache:{...},
    /// encryption:{mode}, archives:[...]}`. Use [`BorgClient::parse_info`]
    /// to deserialize it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the info command fails.
    pub fn info(&self) -> Result<String> {
        let spec = self
            .command("info")
            .arg("--json")
            .arg(self.repo_arg())
            .redact(self.carries_secret());

        tracing::info!(repo = %self.repo.display(), "borg info --json");
        let output = self.run_string(&spec, Error::command_failed)?;
        Ok(output)
    }

    /// Prune archives according to a retention policy.
    ///
    /// Runs `borg prune <repo> --keep-daily=N --keep-weekly=N ...`. Only the
    /// retention counts that are `Some` are emitted.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the prune command fails.
    pub fn prune(
        &self,
        keep_daily: Option<u32>,
        keep_weekly: Option<u32>,
        keep_monthly: Option<u32>,
    ) -> Result<String> {
        let mut spec = self.command("prune").arg(self.repo_arg());
        if let Some(n) = keep_daily {
            spec = spec.args(["--keep-daily", &n.to_string()]);
        }
        if let Some(n) = keep_weekly {
            spec = spec.args(["--keep-weekly", &n.to_string()]);
        }
        if let Some(n) = keep_monthly {
            spec = spec.args(["--keep-monthly", &n.to_string()]);
        }
        let spec = spec.redact(self.carries_secret());

        tracing::info!(
            repo = %self.repo.display(),
            keep_daily = ?keep_daily,
            keep_weekly = ?keep_weekly,
            keep_monthly = ?keep_monthly,
            "borg prune"
        );
        let output = self.run_string(&spec, Error::command_failed)?;
        Ok(output)
    }

    // -----------------------------------------------------------------------
    // Extract / restore
    // -----------------------------------------------------------------------

    /// Extract (restore) an archive into a target directory.
    ///
    /// Runs `borg extract <repo>::<archive>` with the working directory set
    /// to `target`. Borg's `extract` subcommand has no `--destination` flag —
    /// it always writes into the current working directory — so the target is
    /// passed via [`CommandSpec::cwd`] rather than an argument.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RestoreFailed`] if the extract command fails.
    pub fn extract(&self, archive: &str, target: &Path) -> Result<()> {
        let target_arg = format!("{}::{}", self.repo_arg(), archive);
        let spec = self
            .command("extract")
            .arg(target_arg)
            .cwd(target)
            .redact(self.carries_secret());

        tracing::info!(
            repo = %self.repo.display(),
            archive = %archive,
            target = %target.display(),
            "borg extract"
        );
        self.run_unit(&spec, Error::RestoreFailed)?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // JSON parsing helpers
    // -----------------------------------------------------------------------

    /// Parse the JSON document produced by [`BorgClient::list`].
    ///
    /// Only the fields needed for archive enumeration are extracted; unknown
    /// keys are ignored. Available under the `client` feature (which implies
    /// `serde_json`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Other`] if the document is not valid JSON or does not
    /// match the expected envelope shape.
    #[cfg(feature = "client")]
    pub fn parse_list(json: &str) -> Result<BorgListOutput> {
        let parsed: ListEnvelope = serde_json::from_str(json)
            .map_err(|e| Error::Other(format!("borg list JSON parse error: {e}")))?;
        Ok(BorgListOutput {
            repository: parsed.repository,
            encryption: parsed.encryption,
            archives: parsed.archives,
        })
    }

    /// Parse the JSON document produced by [`BorgClient::info`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Other`] if the document is not valid JSON or does not
    /// match the expected envelope shape.
    #[cfg(feature = "client")]
    pub fn parse_info(json: &str) -> Result<BorgInfoOutput> {
        let parsed: InfoEnvelope = serde_json::from_str(json)
            .map_err(|e| Error::Other(format!("borg info JSON parse error: {e}")))?;
        Ok(BorgInfoOutput {
            repository: parsed.repository,
            encryption: parsed.encryption,
            archives: parsed.archives,
        })
    }

    // -----------------------------------------------------------------------
    // Accessors (useful for tests + diagnostics)
    // -----------------------------------------------------------------------

    /// The repository location as configured.
    pub fn repo(&self) -> &Path {
        &self.repo
    }

    /// Whether a passphrase has been configured.
    pub fn has_passphrase(&self) -> bool {
        self.passphrase.is_some()
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Build the repository path argument.
    fn repo_arg(&self) -> String {
        self.repo.to_string_lossy().to_string()
    }

    /// Start a [`CommandSpec`] for a borg subcommand, pre-loaded with the
    /// resolved binary, any configured `BORG_PASSPHRASE`, and the extra env.
    ///
    /// `redact(true)` is applied by each public method (only when
    /// [`Self::carries_secret`] is true) so that read-only commands against an
    /// unencrypted repo do not opt into needless redaction — but every command
    /// that *could* carry a passphrase must be redacted.
    fn command(&self, subcommand: &str) -> CommandSpec {
        let mut spec = CommandSpec::new(self.binary.to_string_lossy().as_ref())
            .arg(subcommand)
            .envs(self.extra_env.iter().cloned());
        if let Some(ref pw) = self.passphrase {
            // Per Borg frontend docs: pass passphrases via the environment,
            // never via an interactive prompt or a CLI flag.
            spec = spec.env("BORG_PASSPHRASE", pw.clone());
        }
        spec
    }

    /// `true` when the configured commands will carry a secret (the
    /// passphrase) in their environment. Such commands must be redacted.
    fn carries_secret(&self) -> bool {
        self.passphrase.is_some()
    }

    /// Map the [`Encryption`] enum to the borg `--encryption` mode token.
    ///
    /// Defaults to `repokey` (Borg's documented general recommendation) when
    /// the caller has not otherwise constrained the mode.
    fn encryption_mode(&self, default: &Encryption) -> &'static str {
        match default {
            Encryption::None => "none",
            Encryption::RepoKey => "repokey",
            Encryption::KeyFile => "keyfile",
            // Borg exposes blake2 variants as separate modes; the enum's
            // Blake2 variant maps to the recommended repokey-blake2 form.
            Encryption::Blake2 => "repokey-blake2",
            Encryption::Authenticated => "authenticated",
        }
    }

    /// Run a spec that produces no structured output, mapping runner errors to
    /// the supplied error constructor.
    fn run_unit(&self, spec: &CommandSpec, mk_err: fn(String) -> Error) -> Result<()> {
        self.runner
            .run_checked(spec)
            .map(|_| ())
            .map_err(|e| mk_err(e.to_string()))
    }

    /// Run a spec whose stdout is returned as a trimmed string, mapping runner
    /// errors to the supplied error constructor.
    fn run_string(
        &self,
        spec: &CommandSpec,
        mk_err: fn(String) -> Error,
    ) -> Result<String> {
        self.runner
            .run_checked(spec)
            .map(|o| o.stdout_trimmed().to_owned())
            .map_err(|e| mk_err(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Public parsed JSON shapes (file-local serde structs behind the client feature)
// ---------------------------------------------------------------------------

/// Subset of `borg list --json` / `borg info --json` repository metadata.
#[cfg(feature = "client")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BorgRepository {
    /// Repository ID (64 hex characters).
    pub id: String,
    /// Canonicalized repository path/URL.
    pub location: String,
    /// ISO-8601 timestamp of the last client modification.
    #[serde(default)]
    pub last_modified: Option<String>,
}

/// Encryption metadata reported by `borg list`/`borg info`.
#[cfg(feature = "client")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BorgEncryption {
    /// Encryption mode name (same tokens accepted by `borg init --encryption`).
    pub mode: String,
}

/// Minimal archive entry common to both `borg list --json` and
/// `borg info --json` (the `name`, `id`, `start` keys).
#[cfg(feature = "client")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BorgArchive {
    /// Archive name.
    pub name: String,
    /// Hex archive ID.
    pub id: String,
    /// ISO-8601 creation start timestamp.
    #[serde(default, alias = "time")]
    pub start: Option<String>,
}

/// Parsed `borg list --json` output.
#[cfg(feature = "client")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BorgListOutput {
    /// Repository metadata.
    pub repository: BorgRepository,
    /// Encryption mode in use.
    pub encryption: BorgEncryption,
    /// Archives in the repository.
    pub archives: Vec<BorgArchive>,
}

/// Parsed `borg info --json` output.
#[cfg(feature = "client")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BorgInfoOutput {
    /// Repository metadata.
    pub repository: BorgRepository,
    /// Encryption mode in use.
    pub encryption: BorgEncryption,
    /// Archives (info uses the extended archive format; only the common keys
    /// are surfaced here).
    pub archives: Vec<BorgArchive>,
}

// File-local envelopes for deserialization. Kept private so the public
// `BorgListOutput` / `BorgInfoOutput` types can be evolved independently of the
// raw borg JSON shape.

#[cfg(feature = "client")]
#[derive(Debug, serde::Deserialize)]
struct ListEnvelope {
    repository: BorgRepository,
    encryption: BorgEncryption,
    #[serde(default)]
    archives: Vec<BorgArchive>,
}

#[cfg(feature = "client")]
#[derive(Debug, serde::Deserialize)]
struct InfoEnvelope {
    repository: BorgRepository,
    encryption: BorgEncryption,
    #[serde(default)]
    archives: Vec<BorgArchive>,
}

// ---------------------------------------------------------------------------
// Error helper
// ---------------------------------------------------------------------------

impl Error {
    /// Construct a [`Error::CommandFailed`] from a free-form message.
    fn command_failed(msg: String) -> Self {
        Error::CommandFailed(msg)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use toride_runner::fake::FakeRunner;
    use toride_runner::CommandOutput;

    // ---- helpers --------------------------------------------------------

    /// Build a client wired to a fresh fake runner, returning both so the
    /// caller can push responses / inspect recorded calls. The client shares
    /// the same `Arc<FakeRunner>` (cloned cheaply), so calls are observable
    /// without any downcast.
    fn make(repo: &str, passphrase: Option<&str>) -> (BorgClient, Arc<FakeRunner>) {
        let runner = Arc::new(FakeRunner::new());
        let client = BorgClient::with_binary(PathBuf::from("borg"), repo)
            .with_runner(runner.clone())
            .with_passphrase_or_none(passphrase);
        (client, runner)
    }

    impl BorgClient {
        /// Test-only helper: apply a passphrase only if `Some`.
        fn with_passphrase_or_none(mut self, pw: Option<&str>) -> Self {
            if let Some(p) = pw {
                self.passphrase = Some(p.into());
            }
            self
        }
    }

    // ---- init -----------------------------------------------------------

    #[test]
    fn init_uses_repokey_and_passphrase_env_not_cli() {
        // Source: https://borgbackup.readthedocs.io/en/stable/usage/init.html
        //   `borg init --encryption=repokey /path/to/repo`
        // and https://borgbackup.readthedocs.io/en/stable/internals/frontends.html
        //   "Use the environment variables BORG_PASSPHRASE ... to pass
        //    passphrases to Borg, don't use the interactive passphrase prompts."
        let (c, rc) = make("/mnt/repo", Some("s3cr3t"));
        c.init().expect("init should succeed under fake runner");

        let calls = rc.calls();
        assert_eq!(calls.len(), 1, "init should issue exactly one borg command");
        let call = &calls[0];
        assert_eq!(call.program, "borg");
        assert_eq!(
            call.args,
            vec!["init", "--encryption", "repokey", "/mnt/repo"],
            "args must match `borg init --encryption repokey <repo>`"
        );
        // The passphrase MUST be in env, NOT in args.
        assert!(
            !call.args.iter().any(|a| a.contains("s3cr3t")),
            "passphrase must never appear in argv"
        );
        assert_eq!(
            call.env.iter().find(|(k, _)| k == "BORG_PASSPHRASE"),
            Some(&("BORG_PASSPHRASE".to_string(), "s3cr3t".to_string())),
            "passphrase must be delivered via BORG_PASSPHRASE env"
        );
        assert!(call.redact, "passphrase-bearing command must be redacted");
    }

    #[test]
    fn init_without_passphrase_is_not_redacted() {
        // An unencrypted repo init (or one where the caller will be prompted
        // interactively) carries no secret in the command, so redact stays off.
        let (c, rc) = make("/mnt/repo", None);
        c.init().unwrap();
        let call = &rc.calls()[0];
        assert!(!call.redact, "no passphrase => no redaction needed");
        assert!(
            call.env.iter().all(|(k, _)| k != "BORG_PASSPHRASE"),
            "BORG_PASSPHRASE must not be set when no passphrase configured"
        );
    }

    #[test]
    fn init_failure_maps_to_repository_init_error() {
        let rc = Arc::new(FakeRunner::new().push_result(Err(toride_runner::Error::CommandFailed {
            program: "borg".into(),
            args: String::new(),
            exit_code: Some(10),
            stderr: "Repository.AlreadyExists".into(),
        })));
        let c = BorgClient::with_binary(PathBuf::from("borg"), "/mnt/repo").with_runner(rc.clone());
        let err = c.init().unwrap_err();
        assert!(matches!(err, Error::RepositoryInit(_)), "got {err:?}");
    }

    // ---- check ----------------------------------------------------------

    #[test]
    fn check_builds_correct_command_and_returns_output() {
        // Source: https://borgbackup.readthedocs.io/en/stable/usage/check.html
        //   `borg check <repo>`
        let rc = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout(
            "Repository integrity check complete.",
        )));
        let c = BorgClient::with_binary(PathBuf::from("borg"), "/mnt/repo")
            .with_passphrase("pw")
            .with_runner(rc.clone());
        let out = c.check().unwrap();
        assert_eq!(out, "Repository integrity check complete.");
        let call = &rc.calls()[0];
        assert_eq!(call.args, vec!["check", "/mnt/repo"]);
        assert!(call.redact, "check against encrypted repo carries the passphrase");
    }

    #[test]
    fn check_failure_maps_to_repository_access_error() {
        let rc = Arc::new(FakeRunner::new().push_result(Err(toride_runner::Error::CommandFailed {
            program: "borg".into(),
            args: String::new(),
            exit_code: Some(12),
            stderr: "Repository.CheckNeeded".into(),
        })));
        let c = BorgClient::with_binary(PathBuf::from("borg"), "/mnt/repo").with_runner(rc.clone());
        let err = c.check().unwrap_err();
        assert!(matches!(err, Error::RepositoryAccess(_)), "got {err:?}");
    }

    // ---- create ---------------------------------------------------------

    #[test]
    fn create_builds_repo_archive_target_and_paths() {
        // Source: https://borgbackup.readthedocs.io/en/stable/usage/create.html
        //   `borg create [options] ARCHIVE [PATH...]`
        //   ARCHIVE is `<repo>::<archive>`.
        let rc = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout(
            "Created archive daily.",
        )));
        let c = BorgClient::with_binary(PathBuf::from("borg"), "/mnt/repo")
            .with_passphrase("pw")
            .with_runner(rc.clone());
        let paths = [Path::new("/etc"), Path::new("/home")];
        let out = c.create("daily", &paths).unwrap();
        assert_eq!(out, "Created archive daily.");
        let call = &rc.calls()[0];
        assert_eq!(
            call.args,
            vec!["create", "--stats", "/mnt/repo::daily", "/etc", "/home",],
            "create must target <repo>::<archive> followed by source paths"
        );
        assert!(call.redact);
    }

    #[test]
    fn create_failure_maps_to_command_failed() {
        let rc = Arc::new(FakeRunner::new().push_result(Err(toride_runner::Error::CommandFailed {
            program: "borg".into(),
            args: String::new(),
            exit_code: Some(30),
            stderr: "Archive.AlreadyExists".into(),
        })));
        let c = BorgClient::with_binary(PathBuf::from("borg"), "/mnt/repo").with_runner(rc.clone());
        let err = c.create("dup", &[Path::new("/etc")]).unwrap_err();
        assert!(matches!(err, Error::CommandFailed(_)), "got {err:?}");
    }

    // ---- list -----------------------------------------------------------

    // Verbatim `borg list --json` sample from the official frontend docs:
    // https://borgbackup.readthedocs.io/en/stable/internals/frontends.html
    // ("Example of a simple archive listing (`borg list --last 1 --json`)")
    const BORG_LIST_JSON: &str = r#"{
        "archives": [
            {
                "id": "80cd07219ad725b3c5f665c1dcf119435c4dee1647a560ecac30f8d40221a46a",
                "name": "host-system-backup-2017-02-27",
                "start": "2017-08-07T12:27:20.789123"
            }
        ],
        "encryption": {
            "mode": "repokey"
        },
        "repository": {
            "id": "0cbe6166b46627fd26b97f8831e2ca97584280a46714ef84d2b668daf8271a23",
            "last_modified": "2017-08-07T12:27:20.789123",
            "location": "/home/user/repository"
        }
    }"#;

    #[cfg(feature = "client")]
    #[test]
    fn list_parses_official_borg_list_json() {
        // Source: https://borgbackup.readthedocs.io/en/stable/internals/frontends.html
        let rc = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout(
            BORG_LIST_JSON,
        )));
        let c = BorgClient::with_binary(PathBuf::from("borg"), "/home/user/repository")
            .with_runner(rc.clone());
        let raw = c.list().unwrap();
        let parsed = BorgClient::parse_list(&raw).expect("must parse official shape");

        assert_eq!(
            parsed.repository.id,
            "0cbe6166b46627fd26b97f8831e2ca97584280a46714ef84d2b668daf8271a23"
        );
        assert_eq!(parsed.repository.location, "/home/user/repository");
        assert_eq!(
            parsed.repository.last_modified.as_deref(),
            Some("2017-08-07T12:27:20.789123")
        );
        assert_eq!(parsed.encryption.mode, "repokey");
        assert_eq!(parsed.archives.len(), 1);
        assert_eq!(parsed.archives[0].name, "host-system-backup-2017-02-27");
        assert_eq!(
            parsed.archives[0].id,
            "80cd07219ad725b3c5f665c1dcf119435c4dee1647a560ecac30f8d40221a46a"
        );
        assert_eq!(
            parsed.archives[0].start.as_deref(),
            Some("2017-08-07T12:27:20.789123")
        );

        let call = &rc.calls()[0];
        assert_eq!(call.args, vec!["list", "--json", "/home/user/repository"]);
    }

    #[test]
    fn list_returns_raw_json_string() {
        let rc = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout(
            BORG_LIST_JSON,
        )));
        let c = BorgClient::with_binary(PathBuf::from("borg"), "/repo")
            .with_passphrase("pw")
            .with_runner(rc.clone());
        let raw = c.list().unwrap();
        assert!(raw.contains("\"archives\""));
        assert!(raw.contains("host-system-backup-2017-02-27"));
        assert!(rc.calls()[0].redact);
    }

    // ---- info -----------------------------------------------------------

    // Verbatim `borg info --json` sample (repository-only form, archives: [])
    // from the official frontend docs:
    // https://borgbackup.readthedocs.io/en/stable/internals/frontends.html
    const BORG_INFO_JSON: &str = r#"{
        "cache": {
            "path": "/home/user/.cache/borg/0cbe6166b46627fd26b97f8831e2ca97584280a46714ef84d2b668daf8271a23",
            "stats": {
                "total_chunks": 511533,
                "total_csize": 17948017540,
                "total_size": 22635749792,
                "total_unique_chunks": 54892,
                "unique_csize": 1920405405,
                "unique_size": 2449675468
            }
        },
        "encryption": {
            "mode": "repokey"
        },
        "repository": {
            "id": "0cbe6166b46627fd26b97f8831e2ca97584280a46714ef84d2b668daf8271a23",
            "last_modified": "2017-08-07T12:27:20.789123",
            "location": "/home/user/testrepo"
        },
        "security_dir": "/home/user/.config/borg/security/0cbe6166b46627fd26b97f8831e2ca97584280a46714ef84d2b668daf8271a23",
        "archives": []
    }"#;

    #[cfg(feature = "client")]
    #[test]
    fn info_parses_official_borg_info_json() {
        // Source: https://borgbackup.readthedocs.io/en/stable/internals/frontends.html
        let rc = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout(
            BORG_INFO_JSON,
        )));
        let c = BorgClient::with_binary(PathBuf::from("borg"), "/home/user/testrepo")
            .with_runner(rc.clone());
        let raw = c.info().unwrap();
        let parsed = BorgClient::parse_info(&raw).expect("must parse official shape");

        assert_eq!(parsed.encryption.mode, "repokey");
        assert_eq!(parsed.repository.location, "/home/user/testrepo");
        assert!(parsed.archives.is_empty(), "this sample repo has no archives");

        let call = &rc.calls()[0];
        assert_eq!(call.args, vec!["info", "--json", "/home/user/testrepo"]);
    }

    #[test]
    fn info_returns_raw_json_string() {
        let rc = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout(
            BORG_INFO_JSON,
        )));
        let c = BorgClient::with_binary(PathBuf::from("borg"), "/repo").with_runner(rc.clone());
        let raw = c.info().unwrap();
        assert!(raw.contains("\"encryption\""));
        assert!(raw.contains("total_chunks"));
    }

    // ---- prune ----------------------------------------------------------

    #[test]
    fn prune_emits_only_provided_keep_flags() {
        // Source: https://borgbackup.readthedocs.io/en/stable/usage/prune.html
        //   `borg prune <repo> --keep-daily=N --keep-weekly=N --keep-monthly=N`
        let rc = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout("pruned")));
        let c = BorgClient::with_binary(PathBuf::from("borg"), "/mnt/repo")
            .with_passphrase("pw")
            .with_runner(rc.clone());
        let out = c.prune(Some(7), None, Some(6)).unwrap();
        assert_eq!(out, "pruned");
        let call = &rc.calls()[0];
        assert_eq!(
            call.args,
            vec!["prune", "/mnt/repo", "--keep-daily", "7", "--keep-monthly", "6",],
            "only Some(_) retention counts become flags"
        );
        assert!(call.redact);
    }

    #[test]
    fn prune_with_all_counts() {
        let rc = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout("ok")));
        let c = BorgClient::with_binary(PathBuf::from("borg"), "/r").with_runner(rc.clone());
        let _ = c.prune(Some(1), Some(2), Some(3)).unwrap();
        assert_eq!(
            rc.calls()[0].args,
            vec![
                "prune", "/r", "--keep-daily", "1", "--keep-weekly", "2", "--keep-monthly", "3",
            ]
        );
    }

    // ---- extract --------------------------------------------------------

    #[test]
    fn extract_uses_cwd_not_destination_flag() {
        // Source: https://borgbackup.readthedocs.io/en/stable/usage/extract.html
        //   "Currently, extract always writes into the current working
        //    directory (\".\"), so make sure you cd to the right place before
        //    calling borg extract." Borg has NO --destination flag.
        let rc = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout("")));
        let c = BorgClient::with_binary(PathBuf::from("borg"), "/mnt/repo")
            .with_passphrase("pw")
            .with_runner(rc.clone());
        c.extract("daily", Path::new("/tmp/restore")).unwrap();

        let call = &rc.calls()[0];
        assert_eq!(
            call.args,
            vec!["extract", "/mnt/repo::daily"],
            "extract takes only the ARCHIVE positional, no --destination"
        );
        assert_eq!(
            call.cwd.as_deref(),
            Some(std::path::Path::new("/tmp/restore")),
            "target must be conveyed via cwd, matching borg's semantics"
        );
        assert!(call.redact);
    }

    #[test]
    fn extract_failure_maps_to_restore_failed() {
        let rc = Arc::new(FakeRunner::new().push_result(Err(toride_runner::Error::CommandFailed {
            program: "borg".into(),
            args: String::new(),
            exit_code: Some(31),
            stderr: "Archive.DoesNotExist".into(),
        })));
        let c = BorgClient::with_binary(PathBuf::from("borg"), "/mnt/repo").with_runner(rc.clone());
        let err = c.extract("nope", Path::new("/tmp/r")).unwrap_err();
        assert!(matches!(err, Error::RestoreFailed(_)), "got {err:?}");
    }

    // ---- redaction property --------------------------------------------

    #[test]
    fn passphrase_command_is_redacted_and_env_borne() {
        // The single most important correctness property: a command that
        // carries the passphrase must (a) have redact(true) and (b) carry the
        // passphrase in env, not argv. Verified across all secret-bearing
        // operations. Source: https://borgbackup.readthedocs.io/en/stable/internals/frontends.html
        let (c, rc) = make("/mnt/repo", Some("hunter2"));

        // init, check, create, list, info, prune, extract — every op.
        c.init().unwrap();
        c.check().unwrap();
        c.create("a", &[Path::new("/x")]).unwrap();
        c.list().unwrap();
        c.info().unwrap();
        c.prune(Some(1), Some(1), None).unwrap();
        c.extract("a", Path::new("/tmp/r")).unwrap();

        assert!(!rc.calls().is_empty(), "should have issued several borg calls");
        for (i, call) in rc.calls().iter().enumerate() {
            assert!(
                call.redact,
                "call #{i} ({}) must be redacted (passphrase configured)",
                call.args.first().map(String::as_str).unwrap_or("<none>")
            );
            assert!(
                call.env
                    .iter()
                    .any(|(k, v)| k == "BORG_PASSPHRASE" && v == "hunter2"),
                "call #{i} must carry BORG_PASSPHRASE env"
            );
            assert!(
                !call.args.iter().any(|a| a.contains("hunter2")),
                "call #{i} leaked passphrase into argv"
            );
        }
    }

    #[test]
    fn extra_env_is_propagated() {
        let rc = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout("")));
        let c = BorgClient::with_binary(PathBuf::from("borg"), "/r")
            .with_env("BORG_HOST_ID", "deadbeef")
            .with_runner(rc.clone());
        c.check().unwrap();
        let call = &rc.calls()[0];
        assert_eq!(
            call.env.iter().find(|(k, _)| k == "BORG_HOST_ID"),
            Some(&("BORG_HOST_ID".to_string(), "deadbeef".to_string())),
        );
    }

    // ---- construction / accessors --------------------------------------

    #[test]
    fn with_binary_does_not_probe_path() {
        // with_binary must not require borg to exist on PATH (no which() call).
        let c = BorgClient::with_binary(PathBuf::from("/opt/borg"), "/repo");
        assert_eq!(c.repo(), std::path::Path::new("/repo"));
        assert!(!c.has_passphrase());
    }

    #[test]
    fn encryption_mode_mappings() {
        let c = BorgClient::with_binary(PathBuf::from("borg"), "/r");
        assert_eq!(c.encryption_mode(&Encryption::RepoKey), "repokey");
        assert_eq!(c.encryption_mode(&Encryption::None), "none");
        assert_eq!(c.encryption_mode(&Encryption::KeyFile), "keyfile");
        assert_eq!(c.encryption_mode(&Encryption::Blake2), "repokey-blake2");
        assert_eq!(c.encryption_mode(&Encryption::Authenticated), "authenticated");
    }
}
