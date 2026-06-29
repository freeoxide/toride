//! Restic CLI wrapper.
//!
//! [`ResticClient`] provides a typed interface to the `restic` binary for
//! common backup operations: initialising repositories, creating snapshots,
//! listing snapshots, checking integrity, pruning, and restoring.
//!
//! Every method constructs a [`toride_runner::CommandSpec`] and delegates
//! execution to a [`Runner`](toride_runner::Runner), so commands are testable
//! via [`FakeRunner`](toride_runner::FakeRunner) and respect redaction of
//! secret-bearing arguments automatically.
//!
//! # Secrets
//!
//! Repository passphrases are **never** placed on the command line. They are
//! either passed through the `RESTIC_PASSWORD` environment variable (when a
//! raw passphrase is configured) or via restic's own `--password-command`
//! plumbing (when a password-retrieval command is configured). Every spec that
//! touches the repository is built with [`CommandSpec::redact`](::toride_runner::CommandSpec::redact)`(true)`
//! so that any value that does end up adjacent to a sensitive flag is scrubbed
//! from errors and logs.
//!
//! # Example
//!
//! ```ignore
//! use toride_backup::restic::ResticClient;
//!
//! let client = ResticClient::new("/mnt/backups/my-server")?
//!     .with_password("hunter2");
//! client.init()?;
//! client.backup(&["/etc", "/home"])?;
//! let snapshots = client.snapshots()?;
//! ```

use std::path::{Path, PathBuf};
use std::sync::Arc;

use toride_runner::{CommandSpec, DuctRunner, Runner};

use crate::{Error, Result};

// ---------------------------------------------------------------------------
// Public typed views (parsed from restic --json output)
// ---------------------------------------------------------------------------

/// A single restic snapshot, as reported by `restic snapshots --json` /
/// `restic cat snapshot <id>`.
///
/// Field names mirror the official restic JSON schema exactly so the docs
/// remain the authoritative reference.
///
/// Docs: <https://restic.readthedocs.io/en/v0.17.2/075_scripting.html#snapshots>
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(feature = "client")]
pub struct Snapshot {
    /// Timestamp of when the backup was started.
    pub time: String,
    /// ID of the root tree blob.
    pub tree: String,
    /// Paths included in the backup.
    pub paths: Vec<String>,
    /// Hostname of the backed up machine.
    pub hostname: String,
    /// Username the backup command was run as.
    pub username: String,
    /// Full snapshot ID.
    pub id: String,
    /// Short snapshot ID.
    pub short_id: String,
    /// Tags applied to the snapshot.
    pub tags: Vec<String>,
}

/// Summary line emitted by `restic backup --json` (the final `message_type:
/// "summary"` JSON-lines record).
///
/// Docs: <https://restic.readthedocs.io/en/v0.17.2/075_scripting.html#summary>
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg(feature = "client")]
pub struct BackupSummary {
    /// Number of new files.
    pub files_new: u64,
    /// Number of files that changed.
    pub files_changed: u64,
    /// Number of files that did not change.
    pub files_unmodified: u64,
    /// Number of new directories.
    pub dirs_new: u64,
    /// Number of directories that changed.
    pub dirs_changed: u64,
    /// Number of directories that did not change.
    pub dirs_unmodified: u64,
    /// Amount of (uncompressed) data added, in bytes.
    pub data_added: u64,
    /// Total number of files processed.
    pub total_files_processed: u64,
    /// Total number of bytes processed.
    pub total_bytes_processed: u64,
    /// ID of the new snapshot. `None` when snapshot creation was skipped.
    pub snapshot_id: Option<String>,
}

/// Summary line emitted by `restic restore --json` (the final `message_type:
/// "summary"` JSON-lines record).
///
/// Docs: <https://restic.readthedocs.io/en/v0.17.2/075_scripting.html#restore>
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg(feature = "client")]
pub struct RestoreSummary {
    /// Total number of files detected.
    pub total_files: u64,
    /// Files restored.
    pub files_restored: u64,
    /// Files skipped due to overwrite setting.
    pub files_skipped: u64,
    /// Total number of bytes in the restore set.
    pub total_bytes: u64,
    /// Number of bytes restored.
    pub bytes_restored: u64,
    /// Total size of skipped files.
    pub bytes_skipped: u64,
}

/// Repository statistics reported by `restic stats --json`.
///
/// Docs: <https://restic.readthedocs.io/en/v0.17.2/075_scripting.html#stats>
#[derive(Debug, Clone, PartialEq)]
#[cfg(feature = "client")]
pub struct RepoStats {
    /// Repository size in bytes.
    pub total_size: f64,
    /// Number of files backed up in the repository.
    pub total_file_count: u64,
    /// Number of blobs in the repository.
    pub total_blob_count: u64,
    /// Number of processed snapshots.
    pub snapshots_count: u64,
}

// ---------------------------------------------------------------------------
// file-local serde helpers (only compiled under the `client` feature, which
// implies serde + serde_json). Keeping these private avoids leaking restic's
// exact JSON field set through the crate's public surface.
// ---------------------------------------------------------------------------

#[cfg(feature = "client")]
mod json_shapes {
    use serde::Deserialize;

    /// `restic snapshots --json` array element.
    #[derive(Debug, Deserialize)]
    pub(super) struct SnapshotJson {
        pub time: String,
        pub tree: String,
        #[serde(default)]
        pub paths: Vec<String>,
        #[serde(default)]
        pub hostname: String,
        #[serde(default)]
        pub username: String,
        pub id: String,
        pub short_id: String,
        #[serde(default)]
        pub tags: Vec<String>,
    }

    /// Discriminated record from a `--json` JSON-lines stream.
    #[derive(Debug, Deserialize)]
    #[serde(tag = "message_type")]
    pub(super) enum BackupMessage {
        #[serde(rename = "summary")]
        Summary(BackupSummaryJson),
        // Status / error / verbose_status records are produced during the run
        // but are not part of the final result; they are ignored on parse.
        #[serde(other)]
        Other,
    }

    #[derive(Debug, Deserialize)]
    pub(super) struct BackupSummaryJson {
        #[serde(default)]
        pub files_new: u64,
        #[serde(default)]
        pub files_changed: u64,
        #[serde(default)]
        pub files_unmodified: u64,
        #[serde(default)]
        pub dirs_new: u64,
        #[serde(default)]
        pub dirs_changed: u64,
        #[serde(default)]
        pub dirs_unmodified: u64,
        #[serde(default)]
        pub data_added: u64,
        #[serde(default)]
        pub total_files_processed: u64,
        #[serde(default)]
        pub total_bytes_processed: u64,
        pub snapshot_id: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(tag = "message_type")]
    pub(super) enum RestoreMessage {
        #[serde(rename = "summary")]
        Summary(RestoreSummaryJson),
        #[serde(other)]
        Other,
    }

    #[derive(Debug, Deserialize)]
    pub(super) struct RestoreSummaryJson {
        #[serde(default)]
        pub total_files: u64,
        #[serde(default)]
        pub files_restored: u64,
        #[serde(default)]
        pub files_skipped: u64,
        #[serde(default)]
        pub total_bytes: u64,
        #[serde(default)]
        pub bytes_restored: u64,
        #[serde(default)]
        pub bytes_skipped: u64,
    }

    /// `restic stats --json` payload.
    #[derive(Debug, Deserialize)]
    pub(super) struct StatsJson {
        #[serde(default)]
        pub total_size: f64,
        #[serde(default)]
        pub total_file_count: u64,
        #[serde(default)]
        pub total_blob_count: u64,
        #[serde(default)]
        pub snapshots_count: u64,
    }
}

// ---------------------------------------------------------------------------
// ResticClient
// ---------------------------------------------------------------------------

/// Typed wrapper around the `restic` binary.
///
/// Every method constructs the appropriate argument list and delegates
/// execution to the underlying command runner. Arguments are always passed
/// as arrays -- no shell string concatenation is used.
///
/// A runner is injected so the client can be exercised against a
/// [`FakeRunner`](::toride_runner::FakeRunner) in tests; in production it
/// defaults to [`DuctRunner`].
pub struct ResticClient {
    /// Resolved path to the `restic` binary.
    binary: PathBuf,
    /// Repository path or URL.
    repo: PathBuf,
    /// Raw repository passphrase, forwarded via `RESTIC_PASSWORD` env.
    password: Option<String>,
    /// Optional password command (e.g. `"cat /etc/restic/password"`), forwarded
    /// via restic's `--password-command` flag.
    password_command: Option<String>,
    /// Extra environment variables.
    extra_env: Vec<(String, String)>,
    /// Command runner. Boxed as a trait object behind an `Arc` so the client is
    /// `Clone`-cheap and a single runner can be shared across clones.
    runner: Arc<dyn Runner>,
}

impl ResticClient {
    /// Create a new restic client by locating `restic` on `$PATH`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BinaryNotFound`] if `restic` is not on `$PATH`.
    pub fn new(repo: impl AsRef<Path>) -> Result<Self> {
        let binary = which::which("restic").map_err(|_| Error::BinaryNotFound("restic".into()))?;
        Ok(Self {
            binary,
            repo: repo.as_ref().to_path_buf(),
            password: None,
            password_command: None,
            extra_env: Vec::new(),
            runner: Arc::new(DuctRunner),
        })
    }

    /// Create a client with an explicit binary path.
    ///
    /// This bypasses the `$PATH` lookup in [`Self::new`] and is primarily
    /// useful for tests or pinned installations.
    pub fn with_binary(binary: PathBuf, repo: impl AsRef<Path>) -> Self {
        Self {
            binary,
            repo: repo.as_ref().to_path_buf(),
            password: None,
            password_command: None,
            extra_env: Vec::new(),
            runner: Arc::new(DuctRunner),
        }
    }

    /// Set a raw repository passphrase for authentication.
    ///
    /// The passphrase is forwarded to restic via the `RESTIC_PASSWORD`
    /// environment variable -- it is **never** placed on the command line.
    /// Overrides any previously-configured [`Self::with_password_command`].
    #[must_use]
    pub fn with_password(mut self, pw: impl Into<String>) -> Self {
        self.password = Some(pw.into());
        self.password_command = None;
        self
    }

    /// Set the password command for repository authentication.
    ///
    /// The command is forwarded via restic's `--password-command` flag.
    /// Overrides any previously-configured [`Self::with_password`].
    #[must_use]
    pub fn with_password_command(mut self, cmd: impl Into<String>) -> Self {
        self.password_command = Some(cmd.into());
        self.password = None;
        self
    }

    /// Inject a custom command runner (e.g. a `FakeRunner` in tests).
    #[must_use]
    pub fn with_runner(mut self, runner: Arc<dyn Runner>) -> Self {
        self.runner = runner;
        self
    }

    /// Add an extra environment variable.
    #[must_use]
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra_env.push((key.into(), value.into()));
        self
    }

    // -----------------------------------------------------------------------
    // Repository management
    // -----------------------------------------------------------------------

    /// Initialise a new restic repository.
    ///
    /// Runs `restic init`. Emits a single JSON-lines `initialized` record
    /// (parsed and discarded).
    ///
    /// Docs: <https://restic.readthedocs.io/en/v0.17.2/075_scripting.html#init>
    ///
    /// # Errors
    ///
    /// Returns [`Error::RepositoryInit`] if the init command fails.
    pub fn init(&self) -> Result<()> {
        tracing::info!(repo = %self.repo.display(), "restic init");
        let spec = self.spec("init").arg("--json").redact(true);
        self.runner
            .run_checked(&spec)
            .map_err(|e| Error::RepositoryInit(restic_err(&e)))?;
        Ok(())
    }

    /// Check repository integrity.
    ///
    /// Runs `restic check`. `check` does not support `--json`; its human-readable
    /// progress is captured on stdout and returned as-is.
    ///
    /// Docs: <https://restic.readthedocs.io/en/latest/045_working_with_repos.html#checking-integrity-and-consistency>
    ///
    /// # Errors
    ///
    /// Returns [`Error::RepositoryAccess`] if the check command fails.
    pub fn check(&self) -> Result<String> {
        tracing::info!(repo = %self.repo.display(), "restic check");
        let spec = self.spec("check").redact(true);
        let output = self
            .runner
            .run_checked(&spec)
            .map_err(|e| Error::RepositoryAccess(restic_err(&e)))?;
        Ok(output.stdout)
    }

    /// Read repository statistics.
    ///
    /// Runs `restic stats --json` and parses the result.
    ///
    /// Docs: <https://restic.readthedocs.io/en/v0.17.2/075_scripting.html#stats>
    ///
    /// # Errors
    ///
    /// Returns [`Error::RepositoryAccess`] if the command fails or its output
    /// cannot be parsed.
    #[cfg(feature = "client")]
    pub fn stats(&self) -> Result<RepoStats> {
        tracing::info!(repo = %self.repo.display(), "restic stats");
        let spec = self.spec("stats").arg("--json").redact(true);
        let output = self
            .runner
            .run_checked(&spec)
            .map_err(|e| Error::RepositoryAccess(restic_err(&e)))?;
        let parsed: json_shapes::StatsJson = serde_json::from_str(output.stdout_trimmed())
            .map_err(|e| Error::RepositoryAccess(format!("parse restic stats json: {e}")))?;
        Ok(RepoStats {
            total_size: parsed.total_size,
            total_file_count: parsed.total_file_count,
            total_blob_count: parsed.total_blob_count,
            snapshots_count: parsed.snapshots_count,
        })
    }

    // -----------------------------------------------------------------------
    // Snapshot operations
    // -----------------------------------------------------------------------

    /// Create a backup snapshot of the given paths.
    ///
    /// Runs `restic backup --json <paths...>` and returns the raw JSON-lines
    /// stream (the final `summary` record is the last line). For a typed view,
    /// use [`Self::backup_typed`].
    ///
    /// Docs: <https://restic.readthedocs.io/en/v0.17.2/075_scripting.html#backup>
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the backup command fails.
    pub fn backup(&self, paths: &[&Path]) -> Result<String> {
        tracing::info!(
            repo = %self.repo.display(),
            paths = ?paths.iter().map(|p| p.display()).collect::<Vec<_>>(),
            "restic backup"
        );
        let mut spec = self.spec("backup").arg("--json");
        for tag in &Self::tags_scratch() {
            spec = spec.arg("--tag").arg(tag);
        }
        for p in paths {
            spec = spec.arg(path_string(p)?);
        }
        let spec = spec.redact(true);
        let output = self
            .runner
            .run_checked(&spec)
            .map_err(|e| Error::CommandFailed(restic_err(&e)))?;
        Ok(output.stdout)
    }

    /// Create a backup snapshot, returning the parsed [`BackupSummary`].
    ///
    /// Runs `restic backup --json` and decodes the final `summary` record.
    ///
    /// Docs: <https://restic.readthedocs.io/en/v0.17.2/075_scripting.html#summary>
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the backup command fails or its
    /// summary record cannot be parsed.
    #[cfg(feature = "client")]
    pub fn backup_typed(&self, paths: &[&Path]) -> Result<BackupSummary> {
        let raw = self.backup(paths)?;
        parse_backup_summary(raw.trim())
            .map_err(|e| Error::CommandFailed(format!("parse restic backup summary: {e}")))
    }

    /// List all snapshots in the repository as typed [`Snapshot`]s.
    ///
    /// Runs `restic snapshots --json` and parses the array.
    ///
    /// Docs: <https://restic.readthedocs.io/en/v0.17.2/075_scripting.html#snapshots>
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the command fails or the output
    /// cannot be parsed.
    #[cfg(feature = "client")]
    pub fn snapshots_typed(&self) -> Result<Vec<Snapshot>> {
        let raw = self.snapshots()?;
        let parsed: Vec<json_shapes::SnapshotJson> = serde_json::from_str(raw.trim())
            .map_err(|e| Error::CommandFailed(format!("parse restic snapshots json: {e}")))?;
        Ok(parsed
            .into_iter()
            .map(|s| Snapshot {
                time: s.time,
                tree: s.tree,
                paths: s.paths,
                hostname: s.hostname,
                username: s.username,
                id: s.id,
                short_id: s.short_id,
                tags: s.tags,
            })
            .collect())
    }

    /// List all snapshots in the repository.
    ///
    /// Runs `restic snapshots --repo <repo> --json` and returns the raw JSON
    /// array string (a `[{...}, {...}]` document).
    ///
    /// Docs: <https://restic.readthedocs.io/en/v0.17.2/075_scripting.html#snapshots>
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the command fails.
    pub fn snapshots(&self) -> Result<String> {
        tracing::info!(repo = %self.repo.display(), "restic snapshots");
        let spec = self.spec("snapshots").arg("--json").redact(true);
        let output = self
            .runner
            .run_checked(&spec)
            .map_err(|e| Error::CommandFailed(restic_err(&e)))?;
        Ok(output.stdout)
    }

    /// Look up a single snapshot by id.
    ///
    /// Runs `restic cat snapshot <id> --json`. Returns `Err(SnapshotNotFound)`
    /// when the snapshot id is unknown to restic.
    ///
    /// Docs: <https://restic.readthedocs.io/en/v0.17.2/075_scripting.html#cat>
    ///
    /// # Errors
    ///
    /// Returns [`Error::SnapshotNotFound`] if the snapshot does not exist, or
    /// [`Error::CommandFailed`] for other failures.
    #[cfg(feature = "client")]
    pub fn cat_snapshot(&self, snapshot: &str) -> Result<Snapshot> {
        tracing::info!(repo = %self.repo.display(), snapshot = %snapshot, "restic cat snapshot");
        let spec = self
            .spec("cat")
            .arg("snapshot")
            .arg(snapshot)
            .arg("--json")
            .redact(true);
        let result = self.runner.run_checked(&spec);
        let output = match result {
            Ok(o) => o,
            Err(e) => {
                let msg = format!("{e}");
                if is_snapshot_not_found(&msg) {
                    return Err(Error::SnapshotNotFound(snapshot.to_string()));
                }
                return Err(Error::CommandFailed(restic_err(&e)));
            }
        };
        let parsed: json_shapes::SnapshotJson = serde_json::from_str(output.stdout_trimmed())
            .map_err(|e| Error::CommandFailed(format!("parse restic cat snapshot json: {e}")))?;
        Ok(Snapshot {
            time: parsed.time,
            tree: parsed.tree,
            paths: parsed.paths,
            hostname: parsed.hostname,
            username: parsed.username,
            id: parsed.id,
            short_id: parsed.short_id,
            tags: parsed.tags,
        })
    }

    /// Prune snapshots according to a retention policy.
    ///
    /// Runs `restic forget --prune --keep-daily <n> --keep-weekly <n>
    /// --keep-monthly <n>`. Note from the docs: `prune` itself does not support
    /// JSON, so `forget --prune` produces mixed JSON + text output; we return
    /// the raw stdout.
    ///
    /// Docs: <https://restic.readthedocs.io/en/v0.17.2/075_scripting.html#forget>
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
        tracing::info!(
            repo = %self.repo.display(),
            keep_daily = ?keep_daily,
            keep_weekly = ?keep_weekly,
            keep_monthly = ?keep_monthly,
            "restic forget --prune"
        );
        let mut spec = self.spec("forget").arg("--prune");
        if let Some(d) = keep_daily {
            spec = spec.arg("--keep-daily").arg(d.to_string());
        }
        if let Some(w) = keep_weekly {
            spec = spec.arg("--keep-weekly").arg(w.to_string());
        }
        if let Some(m) = keep_monthly {
            spec = spec.arg("--keep-monthly").arg(m.to_string());
        }
        let spec = spec.redact(true);
        let output = self
            .runner
            .run_checked(&spec)
            .map_err(|e| Error::CommandFailed(restic_err(&e)))?;
        Ok(output.stdout)
    }

    /// Apply a retention policy **without** pruning (no data removal).
    ///
    /// Runs `restic forget --keep-* <n>` (no `--prune`), returning the parsed
    /// JSON plan: which snapshots restic would keep vs remove. Useful for
    /// dry-run retention previews.
    ///
    /// Docs: <https://restic.readthedocs.io/en/v0.17.2/075_scripting.html#forget>
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the command fails.
    pub fn forget(
        &self,
        keep_daily: Option<u32>,
        keep_weekly: Option<u32>,
        keep_monthly: Option<u32>,
    ) -> Result<String> {
        tracing::info!(
            repo = %self.repo.display(),
            keep_daily = ?keep_daily,
            keep_weekly = ?keep_weekly,
            keep_monthly = ?keep_monthly,
            "restic forget"
        );
        let mut spec = self.spec("forget").arg("--json");
        if let Some(d) = keep_daily {
            spec = spec.arg("--keep-daily").arg(d.to_string());
        }
        if let Some(w) = keep_weekly {
            spec = spec.arg("--keep-weekly").arg(w.to_string());
        }
        if let Some(m) = keep_monthly {
            spec = spec.arg("--keep-monthly").arg(m.to_string());
        }
        let spec = spec.redact(true);
        let output = self
            .runner
            .run_checked(&spec)
            .map_err(|e| Error::CommandFailed(restic_err(&e)))?;
        Ok(output.stdout)
    }

    // -----------------------------------------------------------------------
    // Restore
    // -----------------------------------------------------------------------

    /// Restore a snapshot to a target directory.
    ///
    /// Runs `restic restore <snapshot> --target <target> --json`. For a typed
    /// view of the restore summary, use [`Self::restore_typed`].
    ///
    /// Docs: <https://restic.readthedocs.io/en/v0.17.2/075_scripting.html#restore>
    ///
    /// # Errors
    ///
    /// Returns [`Error::RestoreFailed`] if the restore command fails.
    pub fn restore(&self, snapshot: &str, target: &Path) -> Result<()> {
        tracing::info!(
            repo = %self.repo.display(),
            snapshot = %snapshot,
            target = %target.display(),
            "restic restore"
        );
        let spec = self
            .spec("restore")
            .arg(snapshot)
            .arg("--target")
            .arg(path_string(target)?)
            .arg("--json")
            .redact(true);
        self.runner
            .run_checked(&spec)
            .map_err(|e| Error::RestoreFailed(restic_err(&e)))?;
        Ok(())
    }

    /// Restore a snapshot, returning the parsed [`RestoreSummary`].
    ///
    /// Runs `restic restore <snapshot> --target <target> --json` and decodes
    /// the final `summary` record.
    ///
    /// Docs: <https://restic.readthedocs.io/en/v0.17.2/075_scripting.html#restore>
    ///
    /// # Errors
    ///
    /// Returns [`Error::RestoreFailed`] if the restore command fails or its
    /// summary record cannot be parsed.
    #[cfg(feature = "client")]
    pub fn restore_typed(&self, snapshot: &str, target: &Path) -> Result<RestoreSummary> {
        tracing::info!(
            repo = %self.repo.display(),
            snapshot = %snapshot,
            target = %target.display(),
            "restic restore (typed)"
        );
        let spec = self
            .spec("restore")
            .arg(snapshot)
            .arg("--target")
            .arg(path_string(target)?)
            .arg("--json")
            .redact(true);
        let output = self
            .runner
            .run_checked(&spec)
            .map_err(|e| Error::RestoreFailed(restic_err(&e)))?;
        parse_restore_summary(output.stdout_trimmed())
            .map_err(|e| Error::RestoreFailed(format!("parse restic restore summary: {e}")))
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Build the base of a restic subcommand: `<binary> --repo <repo> [--password-command <cmd>]`.
    ///
    /// The repo and (raw) passphrase are never passed as positional args; the
    /// passphrase is attached as `RESTIC_PASSWORD` env by [`Self::apply_secrets`].
    fn spec(&self, subcommand: &str) -> CommandSpec {
        let mut spec = CommandSpec::new(self.binary.to_string_lossy().to_string())
            .arg("--repo")
            .arg(self.repo.to_string_lossy().to_string());
        if let Some(ref pw_cmd) = self.password_command {
            spec = spec.arg("--password-command").arg(pw_cmd.clone());
        }
        spec = spec.arg(subcommand);
        self.apply_secrets(spec)
    }

    /// Attach secret-bearing env: the raw passphrase (via `RESTIC_PASSWORD`)
    /// and any caller-provided extra env. The repo URL is also considered
    /// potentially secret (it can embed credentials for `sftp:`/`b2:` backends),
    /// so every spec built here is marked `redact(true)` at the call sites.
    fn apply_secrets(&self, mut spec: CommandSpec) -> CommandSpec {
        if let Some(ref pw) = self.password {
            spec = spec.env("RESTIC_PASSWORD", pw.clone());
        }
        for (k, v) in &self.extra_env {
            spec = spec.env(k.clone(), v.clone());
        }
        spec
    }

    /// Tags to attach to backups. Currently no per-client tag store is exposed
    /// publicly; this returns an empty list but centralises where future tag
    /// configuration would flow in.
    fn tags_scratch() -> Vec<String> {
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------------

/// Render a runner error into a compact string.
///
/// The runner's `Error` `Display` (produced by `run_checked`) already scrubs
/// secret values from the captured args/stderr when the originating spec was
/// built with `redact(true)` — which every restic spec is — so this is safe to
/// embed in our own error variants.
fn restic_err(err: &toride_runner::Error) -> String {
    err.to_string()
}

/// Convert a `&Path` to a string, failing with a clear error if the path
/// contains non-UTF-8 components (restic arguments are UTF-8 strings).
fn path_string(p: &Path) -> Result<String> {
    p.to_str()
        .map(str::to_owned)
        .ok_or_else(|| Error::CommandFailed(format!("non-UTF-8 path: {}", p.display())))
}

/// Heuristic: does this error message indicate an unknown snapshot id?
///
/// `restic cat snapshot <unknown>` exits non-zero with stderr resembling
/// `"Ignoring snapshot <id>, ID is not a snapshot"` or
/// `"unable to find snapshot with id ..."`.
#[cfg(feature = "client")]
fn is_snapshot_not_found(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("is not a snapshot")
        || lower.contains("no snapshot id")
        || lower.contains("unable to find snapshot")
        || lower.contains("snapshot not found")
}

/// Parse the final `message_type: "summary"` record from a `restic backup`
/// JSON-lines stream.
#[cfg(feature = "client")]
fn parse_backup_summary(stdout: &str) -> std::result::Result<BackupSummary, String> {
    let mut summary: Option<BackupSummary> = None;
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() || !line.starts_with('{') {
            continue;
        }
        match serde_json::from_str::<json_shapes::BackupMessage>(line) {
            Ok(json_shapes::BackupMessage::Summary(s)) => {
                summary = Some(BackupSummary {
                    files_new: s.files_new,
                    files_changed: s.files_changed,
                    files_unmodified: s.files_unmodified,
                    dirs_new: s.dirs_new,
                    dirs_changed: s.dirs_changed,
                    dirs_unmodified: s.dirs_unmodified,
                    data_added: s.data_added,
                    total_files_processed: s.total_files_processed,
                    total_bytes_processed: s.total_bytes_processed,
                    snapshot_id: s.snapshot_id.filter(|id| !id.is_empty()),
                });
            }
            Ok(json_shapes::BackupMessage::Other) | Err(_) => {
                // Non-summary record (status/error/verbose_status) or an
                // unparseable line; the summary is what we care about.
            }
        }
    }
    summary.ok_or_else(|| "no summary record in restic backup output".to_string())
}

/// Parse the final `message_type: "summary"` record from a `restic restore`
/// JSON-lines stream.
#[cfg(feature = "client")]
fn parse_restore_summary(stdout: &str) -> std::result::Result<RestoreSummary, String> {
    let mut summary: Option<RestoreSummary> = None;
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() || !line.starts_with('{') {
            continue;
        }
        match serde_json::from_str::<json_shapes::RestoreMessage>(line) {
            Ok(json_shapes::RestoreMessage::Summary(s)) => {
                summary = Some(RestoreSummary {
                    total_files: s.total_files,
                    files_restored: s.files_restored,
                    files_skipped: s.files_skipped,
                    total_bytes: s.total_bytes,
                    bytes_restored: s.bytes_restored,
                    bytes_skipped: s.bytes_skipped,
                });
            }
            Ok(json_shapes::RestoreMessage::Other) | Err(_) => {}
        }
    }
    summary.ok_or_else(|| "no summary record in restic restore output".to_string())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(all(test, feature = "client"))]
mod tests {
    use super::*;
    use toride_runner::CommandOutput;
    use toride_runner::fake::FakeRunner;

    /// Build a client wired to a shared `FakeRunner`, returning the client plus
    /// a handle on the same runner for post-call assertions.
    ///
    /// `FakeRunner` is not `Clone`, so we wrap it in an `Arc` once and hand
    /// the client a second `Arc` reference coerced to the trait object. The
    /// returned `Arc<FakeRunner>` keeps the concrete type so the test can call
    /// `FakeRunner`'s inherent assertion methods (`assert_called_with`,
    /// `calls`). Both `Arc`s point at the same allocation, so they observe the
    /// same call log.
    fn client_and_runner(runner: FakeRunner, repo: &str) -> (ResticClient, Arc<FakeRunner>) {
        let runner = Arc::new(runner);
        let for_client: Arc<dyn Runner> = runner.clone();
        let client = ResticClient::with_binary(PathBuf::from("/usr/bin/restic"), repo)
            .with_password("s3cr3t-passphrase")
            .with_runner(for_client);
        (client, runner)
    }

    // -------------------------------------------------------------------------
    // Command construction
    // -------------------------------------------------------------------------

    /// `restic init` builds `restic --repo <repo> init --json` and carries the
    /// passphrase via `RESTIC_PASSWORD` env (never as an arg).
    /// Source: <https://restic.readthedocs.io/en/v0.17.2/075_scripting.html#init>
    #[test]
    fn init_builds_correct_command() {
        // init emits a single JSON-lines "initialized" record.
        let init_json =
            r#"{"message_type":"initialized","id":"2ddef10f5c","repository":"/tmp/repo"}"#;
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(init_json));

        let (client, runner) = client_and_runner(runner, "/tmp/repo");

        client.init().expect("init should succeed");

        // Assert the EXACT command shape: program, args, redact, and that the
        // passphrase lives in env (not args).
        let expected = CommandSpec::new("/usr/bin/restic")
            .args(["--repo", "/tmp/repo", "init", "--json"])
            .env("RESTIC_PASSWORD", "s3cr3t-passphrase")
            .redact(true);
        runner.assert_called_with(&expected);
    }

    /// A passphrase-bearing command MUST be built with `redact(true)`. This is
    /// the single most important correctness property: secrets must be scrubbed
    /// from errors and logs. `specs_match` (used by `assert_called_with`)
    /// enforces redact, so a spec missing `redact(true)` fails an exact match.
    #[test]
    fn redact_is_set_on_secret_bearing_command() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(
            r#"{"message_type":"initialized"}"#,
        ));

        let (client, runner) = client_and_runner(runner, "/tmp/repo");
        client.init().expect("init should succeed");

        let calls = runner.calls();
        assert_eq!(calls.len(), 1);
        assert!(
            calls[0].redact,
            "every restic command must set redact(true) when it carries the repo passphrase"
        );
        // The passphrase is delivered via env, never via a positional arg.
        assert!(
            calls[0]
                .env
                .iter()
                .any(|(k, v)| k == "RESTIC_PASSWORD" && v == "s3cr3t-passphrase")
        );
        assert!(
            !calls[0]
                .args
                .iter()
                .any(|a| a.contains("s3cr3t-passphrase")),
            "passphrase must never appear in args: {:?}",
            calls[0].args
        );

        // And a spec built WITHOUT redact must fail an exact match (proving the
        // assertion is non-vacuous). `assert_called_with` panics on no-match, so
        // we expect a panic by catching it.
        let unredacted = CommandSpec::new("/usr/bin/restic")
            .args(["--repo", "/tmp/repo", "init", "--json"])
            .env("RESTIC_PASSWORD", "s3cr3t-passphrase");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runner.assert_called_with(&unredacted);
        }));
        assert!(
            result.is_err(),
            "a spec missing redact(true) must NOT match the recorded call"
        );
    }

    /// `restic check` (no --json; check does not support JSON).
    /// Source: <https://restic.readthedocs.io/en/latest/045_working_with_repos.html#checking-integrity-and-consistency>
    #[test]
    fn check_builds_correct_command_and_returns_stdout() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(
            "create exclusive lock for repository\nno errors were found\n",
        ));
        let (client, runner) = client_and_runner(runner, "/srv/backup");

        let out = client.check().expect("check should succeed");
        assert!(out.contains("no errors were found"));

        let expected = CommandSpec::new("/usr/bin/restic")
            .args(["--repo", "/srv/backup", "check"])
            .env("RESTIC_PASSWORD", "s3cr3t-passphrase")
            .redact(true);
        runner.assert_called_with(&expected);
    }

    /// `restic snapshots --json` returns an array parsed into typed Snapshots.
    /// Sample is the exact shape documented at
    /// <https://restic.readthedocs.io/en/v0.17.2/075_scripting.html#snapshots>
    #[test]
    fn snapshots_parses_docs_json_sample() {
        // Verbatim-style sample sourced from the official snapshots schema.
        let sample = r#"[
          {
            "time": "2024-09-18T12:34:56.789012345Z",
            "parent": "96b8e3a1d2c4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0",
            "tree": "fda3c5e8b2a1d4c6e9f0a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2",
            "paths": ["/home/user", "/etc"],
            "hostname": "kasa",
            "username": "user",
            "uid": 1000,
            "gid": 1000,
            "excludes": ["*.tmp"],
            "tags": ["home", "auto"],
            "program_version": "restic 0.17.2",
            "id": "5111c8ae5a5e3e2e8b6b4f0c5b8e3a2d1c9f0a1b2c3d4e5f6a7b8c9d0e1f2a3",
            "short_id": "5111c8ae"
          }
        ]"#;
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(sample));
        let (client, runner) = client_and_runner(runner, "/srv/backup");

        let snaps = client.snapshots_typed().expect("snapshots should parse");
        assert_eq!(snaps.len(), 1);
        let s = &snaps[0];
        assert_eq!(
            s.id,
            "5111c8ae5a5e3e2e8b6b4f0c5b8e3a2d1c9f0a1b2c3d4e5f6a7b8c9d0e1f2a3"
        );
        assert_eq!(s.short_id, "5111c8ae");
        assert_eq!(s.hostname, "kasa");
        assert_eq!(s.username, "user");
        assert_eq!(s.paths, vec!["/home/user", "/etc"]);
        assert_eq!(s.tags, vec!["home", "auto"]);
        assert_eq!(
            s.tree,
            "fda3c5e8b2a1d4c6e9f0a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2"
        );

        let expected = CommandSpec::new("/usr/bin/restic")
            .args(["--repo", "/srv/backup", "snapshots", "--json"])
            .env("RESTIC_PASSWORD", "s3cr3t-passphrase")
            .redact(true);
        runner.assert_called_with(&expected);
    }

    /// `restic snapshots` surfaces the raw JSON for non-client callers.
    #[test]
    fn snapshots_raw_returns_stdout_verbatim() {
        let sample = r#"[]"#;
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(sample));
        let (client, _runner) = client_and_runner(runner, "/srv/backup");
        let raw = client.snapshots().expect("snapshots raw should succeed");
        assert_eq!(raw.trim(), "[]");
    }

    /// `restic backup --json` final summary record is parsed into `BackupSummary`.
    /// Sample is the exact `message_type:"summary"` shape documented at
    /// <https://restic.readthedocs.io/en/v0.17.2/075_scripting.html#summary>
    #[test]
    fn backup_parses_docs_summary_sample() {
        // A realistic JSON-lines stream: one status record, then the summary.
        let stream = r#"{"message_type":"status","seconds_elapsed":1,"percent_done":0.5,"total_files":10,"files_done":5}
{"message_type":"summary","files_new":3,"files_changed":2,"files_unmodified":5,"dirs_new":1,"dirs_changed":0,"dirs_unmodified":4,"data_blobs":6,"tree_blobs":2,"data_added":2048,"data_added_packed":1024,"total_files_processed":10,"total_bytes_processed":4096,"total_duration":1.5,"snapshot_id":"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"}"#;
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(stream));
        let (client, runner) = client_and_runner(runner, "/srv/backup");

        let summary = client
            .backup_typed(&[Path::new("/etc"), Path::new("/home")])
            .expect("backup should succeed");
        assert_eq!(summary.files_new, 3);
        assert_eq!(summary.files_changed, 2);
        assert_eq!(summary.files_unmodified, 5);
        assert_eq!(summary.dirs_new, 1);
        assert_eq!(summary.data_added, 2048);
        assert_eq!(summary.total_files_processed, 10);
        assert_eq!(summary.total_bytes_processed, 4096);
        assert_eq!(
            summary.snapshot_id.as_deref(),
            Some("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2")
        );

        let expected = CommandSpec::new("/usr/bin/restic")
            .args(["--repo", "/srv/backup", "backup", "--json", "/etc", "/home"])
            .env("RESTIC_PASSWORD", "s3cr3t-passphrase")
            .redact(true);
        runner.assert_called_with(&expected);
    }

    /// When the backup summary omits `snapshot_id` (snapshot creation skipped),
    /// the field is `None`.
    #[test]
    fn backup_summary_without_snapshot_id() {
        let stream = r#"{"message_type":"summary","files_new":0,"files_changed":0,"files_unmodified":1,"dirs_new":0,"dirs_changed":0,"dirs_unmodified":1,"data_added":0,"total_files_processed":1,"total_bytes_processed":0,"total_duration":0.1}"#;
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(stream));
        let (client, _runner) = client_and_runner(runner, "/srv/backup");
        let summary = client
            .backup_typed(&[Path::new("/etc")])
            .expect("backup ok");
        assert_eq!(summary.snapshot_id, None);
    }

    /// `restic cat snapshot <id> --json` returns the single snapshot object.
    /// Source: <https://restic.readthedocs.io/en/v0.17.2/075_scripting.html#cat>
    #[test]
    fn cat_snapshot_parses_docs_sample() {
        let sample = r#"{
          "time": "2024-09-18T12:34:56.789012345Z",
          "tree": "fda3c5e8b2a1d4c6e9f0a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2",
          "paths": ["/home/user"],
          "hostname": "kasa",
          "username": "user",
          "uid": 1000,
          "gid": 1000,
          "id": "5111c8ae5a5e3e2e8b6b4f0c5b8e3a2d1c9f0a1b2c3d4e5f6a7b8c9d0e1f2a3",
          "short_id": "5111c8ae"
        }"#;
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(sample));
        let (client, runner) = client_and_runner(runner, "/srv/backup");

        let snap = client
            .cat_snapshot("5111c8ae")
            .expect("cat snapshot should succeed");
        assert_eq!(snap.short_id, "5111c8ae");
        assert_eq!(snap.hostname, "kasa");
        assert_eq!(snap.paths, vec!["/home/user"]);

        let expected = CommandSpec::new("/usr/bin/restic")
            .args([
                "--repo",
                "/srv/backup",
                "cat",
                "snapshot",
                "5111c8ae",
                "--json",
            ])
            .env("RESTIC_PASSWORD", "s3cr3t-passphrase")
            .redact(true);
        runner.assert_called_with(&expected);
    }

    /// An unknown snapshot id surfaces as `Error::SnapshotNotFound`, not a
    /// generic command failure.
    #[test]
    fn cat_snapshot_unknown_returns_snapshot_not_found() {
        let runner = FakeRunner::new().push_result(Err(toride_runner::Error::CommandFailed {
            program: "restic".into(),
            args: "...".into(),
            exit_code: Some(1),
            stderr: "Ignoring snapshot deadbeef, ID is not a snapshot".into(),
        }));
        let (client, _runner) = client_and_runner(runner, "/srv/backup");
        let err = client.cat_snapshot("deadbeef").unwrap_err();
        assert!(matches!(err, Error::SnapshotNotFound(ref id) if id == "deadbeef"));
    }

    /// `restic stats --json` parses into `RepoStats`.
    /// Source: <https://restic.readthedocs.io/en/v0.17.2/075_scripting.html#stats>
    #[test]
    fn stats_parses_docs_sample() {
        let sample = r#"{
          "total_size": 1234.5,
          "total_file_count": 42,
          "total_blob_count": 100,
          "snapshots_count": 3,
          "total_uncompressed_size": 2000,
          "compression_ratio": 1.6,
          "compression_progress": 100,
          "compression_space_saving": 38
        }"#;
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(sample));
        let (client, runner) = client_and_runner(runner, "/srv/backup");

        let stats = client.stats().expect("stats should parse");
        assert!((stats.total_size - 1234.5).abs() < f64::EPSILON);
        assert_eq!(stats.total_file_count, 42);
        assert_eq!(stats.total_blob_count, 100);
        assert_eq!(stats.snapshots_count, 3);

        let expected = CommandSpec::new("/usr/bin/restic")
            .args(["--repo", "/srv/backup", "stats", "--json"])
            .env("RESTIC_PASSWORD", "s3cr3t-passphrase")
            .redact(true);
        runner.assert_called_with(&expected);
    }

    /// `restic forget --prune --keep-*` retention policy.
    /// Source: <https://restic.readthedocs.io/en/v0.17.2/075_scripting.html#forget>
    #[test]
    fn prune_builds_forget_prune_command() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout("forgotten"));
        let (client, runner) = client_and_runner(runner, "/srv/backup");

        let _ = client
            .prune(Some(7), Some(4), Some(6))
            .expect("prune should succeed");

        let expected = CommandSpec::new("/usr/bin/restic")
            .args([
                "--repo",
                "/srv/backup",
                "forget",
                "--prune",
                "--keep-daily",
                "7",
                "--keep-weekly",
                "4",
                "--keep-monthly",
                "6",
            ])
            .env("RESTIC_PASSWORD", "s3cr3t-passphrase")
            .redact(true);
        runner.assert_called_with(&expected);
    }

    /// `restic forget --json --keep-*` (no prune) for a dry-run-style preview.
    #[test]
    fn forget_builds_command_without_prune() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout("[]"));
        let (client, runner) = client_and_runner(runner, "/srv/backup");

        let out = client
            .forget(None, Some(4), None)
            .expect("forget should succeed");
        assert_eq!(out.trim(), "[]");

        let expected = CommandSpec::new("/usr/bin/restic")
            .args([
                "--repo",
                "/srv/backup",
                "forget",
                "--json",
                "--keep-weekly",
                "4",
            ])
            .env("RESTIC_PASSWORD", "s3cr3t-passphrase")
            .redact(true);
        runner.assert_called_with(&expected);
    }

    /// `restic restore <snap> --target <dir> --json` parses the summary record.
    /// Source: <https://restic.readthedocs.io/en/v0.17.2/075_scripting.html#restore>
    #[test]
    fn restore_parses_docs_summary_sample() {
        let stream = r#"{"message_type":"status","seconds_elapsed":0,"percent_done":0,"total_files":3,"files_restored":0}
{"message_type":"summary","seconds_elapsed":2,"total_files":3,"files_restored":3,"files_skipped":0,"total_bytes":1024,"bytes_restored":1024,"bytes_skipped":0}"#;
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(stream));
        let (client, runner) = client_and_runner(runner, "/srv/backup");

        let summary = client
            .restore_typed("5111c8ae", Path::new("/tmp/restore"))
            .expect("restore should succeed");
        assert_eq!(summary.total_files, 3);
        assert_eq!(summary.files_restored, 3);
        assert_eq!(summary.bytes_restored, 1024);

        let expected = CommandSpec::new("/usr/bin/restic")
            .args([
                "--repo",
                "/srv/backup",
                "restore",
                "5111c8ae",
                "--target",
                "/tmp/restore",
                "--json",
            ])
            .env("RESTIC_PASSWORD", "s3cr3t-passphrase")
            .redact(true);
        runner.assert_called_with(&expected);
    }

    /// A failed restore surfaces as `Error::RestoreFailed`.
    #[test]
    fn restore_failure_maps_to_restore_failed() {
        let runner = FakeRunner::new().push_result(Err(toride_runner::Error::CommandFailed {
            program: "restic".into(),
            args: "...".into(),
            exit_code: Some(1),
            stderr: "target directory not writable".into(),
        }));
        let (client, _runner) = client_and_runner(runner, "/srv/backup");
        let err = client
            .restore("5111c8ae", Path::new("/tmp/restore"))
            .unwrap_err();
        assert!(matches!(err, Error::RestoreFailed(_)));
    }

    /// A failed init surfaces as `Error::RepositoryInit`.
    #[test]
    fn init_failure_maps_to_repository_init() {
        let runner = FakeRunner::new().push_result(Err(toride_runner::Error::CommandFailed {
            program: "restic".into(),
            args: "...".into(),
            exit_code: Some(1),
            stderr: "config file already exists".into(),
        }));
        let (client, _runner) = client_and_runner(runner, "/srv/backup");
        let err = client.init().unwrap_err();
        assert!(matches!(err, Error::RepositoryInit(_)));
    }

    /// A failed check surfaces as `Error::RepositoryAccess`.
    #[test]
    fn check_failure_maps_to_repository_access() {
        let runner = FakeRunner::new().push_result(Err(toride_runner::Error::CommandFailed {
            program: "restic".into(),
            args: "...".into(),
            exit_code: Some(1),
            stderr: "pack file appears corrupted".into(),
        }));
        let (client, _runner) = client_and_runner(runner, "/srv/backup");
        let err = client.check().unwrap_err();
        assert!(matches!(err, Error::RepositoryAccess(_)));
    }

    /// `--password-command` is plumbed via the flag (not env) when configured.
    #[test]
    fn password_command_uses_flag_not_env() {
        let runner = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout(
            r#"{"message_type":"initialized"}"#,
        )));
        let for_client: Arc<dyn Runner> = runner.clone();
        let client = ResticClient::with_binary(PathBuf::from("/usr/bin/restic"), "/srv/backup")
            .with_password_command("cat /etc/restic/pw")
            .with_runner(for_client);

        client.init().expect("init ok");

        // password_command is the cmd string, NOT a secret itself, but the spec
        // still carries the repo so redact(true) must be set.
        let expected = CommandSpec::new("/usr/bin/restic")
            .args([
                "--repo",
                "/srv/backup",
                "--password-command",
                "cat /etc/restic/pw",
                "init",
                "--json",
            ])
            .redact(true);
        runner.assert_called_with(&expected);

        // And there must be NO RESTIC_PASSWORD env entry when using a command.
        let calls = runner.calls();
        assert!(
            calls
                .iter()
                .all(|c| !c.env.iter().any(|(k, _)| k == "RESTIC_PASSWORD")),
            "password-command path must not also set RESTIC_PASSWORD env"
        );
    }

    /// Extra env is forwarded onto every spec.
    #[test]
    fn extra_env_is_forwarded() {
        let runner = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout(
            r#"{"message_type":"initialized"}"#,
        )));
        let for_client: Arc<dyn Runner> = runner.clone();
        let client = ResticClient::with_binary(PathBuf::from("/usr/bin/restic"), "/srv/backup")
            .with_password("pw")
            .with_env("RESTIC_PACK_SIZE", "32")
            .with_runner(for_client);

        client.init().expect("init ok");

        let calls = runner.calls();
        assert_eq!(calls.len(), 1);
        assert!(
            calls[0]
                .env
                .iter()
                .any(|(k, v)| k == "RESTIC_PACK_SIZE" && v == "32"),
            "extra env should be forwarded: {:?}",
            calls[0].env
        );
        // Passphrase still present via env.
        assert!(
            calls[0]
                .env
                .iter()
                .any(|(k, v)| k == "RESTIC_PASSWORD" && v == "pw")
        );
    }

    /// `is_snapshot_not_found` recognises the documented restic stderr phrasing.
    #[test]
    fn snapshot_not_found_heuristic() {
        assert!(is_snapshot_not_found(
            "Ignoring snapshot deadbeef, ID is not a snapshot"
        ));
        assert!(is_snapshot_not_found(
            "unable to find snapshot with id deadbeef"
        ));
        assert!(!is_snapshot_not_found("target directory not writable"));
    }
}
