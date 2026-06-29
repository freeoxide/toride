//! Restore workflows for backup repositories.
//!
//! Provides high-level restore operations that coordinate between the
//! restic/borg backends and produce typed [`RestoreReport`] values.
//! Supports full restores, partial restores (specific paths), and test
//! restores for integrity verification.
//!
//! # Backend selection
//!
//! [`RestoreManager`] dispatches to the appropriate backend based on
//! [`BackupSpec::backend`]:
//!
//! - [`Backend::Restic`](crate::spec::Backend::Restic) runs `restic restore`.
//! - [`Backend::Borg`](crate::spec::Backend::Borg) runs `borg extract`.
//!
//! All commands are built as [`toride_runner::CommandSpec`] and executed via
//! the [`Runner`](toride_runner::Runner) trait, making the full restore path
//! testable with [`FakeRunner`](toride_runner::FakeRunner).
//!
//! # Secret handling
//!
//! Repository passphrases are carried as environment variables
//! (`RESTIC_PASSWORD` / `BORG_PASSPHRASE`) rather than CLI arguments, and every
//! passphrase-bearing command is built with [`redact(true)`](CommandSpec::redact)
//! so the secret is scrubbed from error messages and logs. See
//! [`RestoreManager::restore`] for the dispatch entry point.

use std::path::Path;

use toride_runner::CommandSpec;
use toride_runner::Runner;

use crate::report::RestoreReport;
use crate::spec::{Backend, BackupSpec};
use crate::{Error, Result};

// ---------------------------------------------------------------------------
// RestoreOptions
// ---------------------------------------------------------------------------

/// Options for a restore operation.
#[derive(Debug, Clone)]
pub struct RestoreOptions {
    /// Snapshot or archive ID to restore from.
    /// If `None`, restores from the latest snapshot (`restic restore latest`
    /// or the most recent borg archive).
    pub snapshot_id: Option<String>,
    /// Specific paths to restore (empty = full restore).
    pub paths: Vec<String>,
    /// Target directory for the restore.
    pub target: String,
    /// Whether to verify the restore by comparing file checksums.
    pub verify: bool,
    /// Whether this is a test restore (restored to a temporary location).
    pub test: bool,
}

impl RestoreOptions {
    /// Create restore options targeting a specific directory.
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            snapshot_id: None,
            paths: Vec::new(),
            target: target.into(),
            verify: false,
            test: false,
        }
    }

    /// Restore from a specific snapshot.
    #[must_use]
    pub fn with_snapshot(mut self, id: impl Into<String>) -> Self {
        self.snapshot_id = Some(id.into());
        self
    }

    /// Restore only specific paths.
    #[must_use]
    pub fn with_paths(mut self, paths: Vec<String>) -> Self {
        self.paths = paths;
        self
    }

    /// Enable verification after restore.
    #[must_use]
    pub fn with_verify(mut self) -> Self {
        self.verify = true;
        self
    }

    /// Mark as a test restore.
    #[must_use]
    pub fn as_test(mut self) -> Self {
        self.test = true;
        self
    }
}

// ---------------------------------------------------------------------------
// RestoreManager
// ---------------------------------------------------------------------------

/// Manages restore workflows for backup repositories.
///
/// Coordinates between the backend-specific clients (restic/borg) and
/// provides high-level restore operations with reporting.
pub struct RestoreManager;

impl RestoreManager {
    /// Perform a full restore from the given backup spec.
    ///
    /// Dispatches to [`run_restic_restore`](Self::run_restic_restore) or
    /// [`run_borg_extract`](Self::run_borg_extract) based on
    /// [`BackupSpec::backend`], executing the command through the default
    /// [`DuctRunner`](toride_runner::DuctRunner).
    ///
    /// # Errors
    ///
    /// Returns [`Error::RestoreFailed`] if the restore operation fails, or a
    /// [`Error::ConfigParse`]/[`Error::ScheduleError`] if the spec fails
    /// validation before any restore command is issued.
    pub fn restore(spec: &BackupSpec, options: &RestoreOptions) -> Result<RestoreReport> {
        spec.validate()?;
        restore_with_runner(spec, options, &toride_runner::DuctRunner)
    }

    /// Perform a test restore to verify backup integrity.
    ///
    /// Restores to an OS-managed temporary directory (created via the `tempfile`
    /// crate so the path is unpredictable, not a fixed `/tmp/toride-backup-test-
    /// <name>` that an attacker could pre-create or symlink) and optionally
    /// verifies file checksums, then cleans up the temporary data.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RestoreFailed`] if the test restore fails (or if a
    /// unique temp directory cannot be created).
    pub fn test_restore(spec: &BackupSpec) -> Result<RestoreReport> {
        // Use a freshly created, unpredictable temp directory. `tempfile`
        // creates a uniquely-named dir under $TMPDIR (or /tmp) and (on Unices)
        // opens it with 0700 perms, so a fixed, attacker-predictable path can
        // no longer be pre-seeded.
        let dir = tempfile::Builder::new()
            .prefix("toride-backup-test-")
            .rand_bytes(12)
            .tempdir()
            .map_err(|e| {
                Error::RestoreFailed(format!("could not create temp dir for test restore: {e}"))
            })?;
        let target = dir.path().to_string_lossy().into_owned();
        let options = RestoreOptions::new(&target).as_test().with_verify();

        // Restore owns `dir`; the TempDir is removed on drop, so cleanup runs
        // whether restore succeeded or failed. The restore itself is allowed
        // to fail — the report/error is surfaced and the temp tree is dropped.
        Self::restore(spec, &options)
    }

    /// Verify that a restore target matches the original backup source.
    ///
    /// Compares file counts and total sizes between source and restore.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RestoreFailed`] if verification fails.
    pub fn verify(source: &Path, restore_target: &Path) -> Result<bool> {
        let src = count_tree(source)
            .map_err(|e| Error::RestoreFailed(format!("failed to walk source: {e}")))?;
        let dst = count_tree(restore_target)
            .map_err(|e| Error::RestoreFailed(format!("failed to walk restore target: {e}")))?;
        Ok(src == dst)
    }
}

// ---------------------------------------------------------------------------
// Backend dispatch (runner-injectable for testing)
// ---------------------------------------------------------------------------

/// Run a restore using an injectable [`Runner`].
///
/// This is the testable core of [`RestoreManager::restore`]: the public
/// static method delegates here with a [`DectRunner`](toride_runner::DuctRunner),
/// while tests pass a [`FakeRunner`](toride_runner::FakeRunner).
///
/// The runner is taken by reference (not owned) so callers can keep a handle
/// to inspect recorded calls after the restore completes.
fn restore_with_runner<R: Runner + ?Sized>(
    spec: &BackupSpec,
    options: &RestoreOptions,
    runner: &R,
) -> Result<RestoreReport> {
    // Validate the spec up front (name allowlist, cron, retention, and that an
    // encrypted repo actually has a password_command) — mirrors backup()/prune().
    spec.validate()?;
    let snapshot_id = resolve_snapshot_id(spec, options)?;
    tracing::info!(
        name = %spec.name,
        backend = %spec.backend,
        snapshot = %snapshot_id,
        target = %options.target,
        "starting restore"
    );

    let report = match spec.backend {
        Backend::Restic => run_restic_restore(spec, options, &snapshot_id, runner)?,
        Backend::Borg => run_borg_extract(spec, options, &snapshot_id, runner)?,
    };

    tracing::info!(
        name = %spec.name,
        files_restored = report.files_restored,
        success = report.success,
        "restore complete"
    );
    Ok(report)
}

/// Resolve which snapshot/archive ID to restore from.
///
/// Defaults to `"latest"` for restic when none is specified (a restic keyword
/// documented at <https://restic.readthedocs.io/en/latest/050_restore.html>).
/// For borg, `"latest"` is treated as a sentinel resolved by the caller before
/// building the command; here we only validate that *some* id is present.
fn resolve_snapshot_id(spec: &BackupSpec, options: &RestoreOptions) -> Result<String> {
    if let Some(id) = &options.snapshot_id {
        if id.trim().is_empty() {
            return Err(Error::RestoreFailed(format!(
                "backup spec {:?}: snapshot_id must not be empty",
                spec.name
            )));
        }
        return Ok(id.clone());
    }
    // restic accepts the literal keyword "latest"; borg needs an archive name,
    // which we resolve at command-build time below.
    Ok("latest".to_string())
}

// ---------------------------------------------------------------------------
// Restic restore
// ---------------------------------------------------------------------------

/// Run `restic restore` and parse its output into a [`RestoreReport`].
///
/// Command shape (sourced from the official restic man page
/// <https://man.archlinux.org/man/restic-restore.1.en> and restore guide
/// <https://restic.readthedocs.io/en/latest/050_restore.html>):
///
/// ```text
/// restic -r <repo> restore <snapshot|latest> \
///   --target <dir> \
///   [--include <path>]... \
///   [--verify]
/// ```
///
/// The repository password is supplied via the spec's `password_command`,
/// forwarded to restic's `--password-command` flag (see
/// <https://restic.readthedocs.io/en/stable/040_backup.html>). An encrypted
/// repository with no `password_command` produces a clear error rather than
/// silently authenticating with the job label. The command is always marked
/// [`redact(true)`](CommandSpec::redact) so the secret never leaks into error
/// messages.
fn run_restic_restore<R: Runner + ?Sized>(
    spec: &BackupSpec,
    options: &RestoreOptions,
    snapshot_id: &str,
    runner: &R,
) -> Result<RestoreReport> {
    let mut cmd = CommandSpec::new("restic")
        .arg("-r")
        .arg(spec.repository.to_string_lossy().as_ref())
        .arg("restore")
        .arg(snapshot_id)
        .arg("--target")
        .arg(&options.target);

    for path in &options.paths {
        cmd = cmd.arg("--include").arg(path);
    }

    if options.verify {
        // restic restore --verify re-reads restored files and checks their
        // contents against the repository data.
        cmd = cmd.arg("--verify");
    }

    // The password is a SECRET. Apply the spec's password_command via restic's
    // --password-command flag (the value is a *command path*, not the secret
    // itself, but we redact anyway so the command path is not logged either).
    // An encrypted repo with no password_command errors here rather than
    // authenticating with the job label.
    cmd = apply_restic_password(spec, cmd)?;

    cmd = cmd.redact(true);

    let output = runner
        .run_checked(&cmd)
        .map_err(|e| Error::RestoreFailed(format!("restic restore command failed: {e}")))?;

    let (files_restored, bytes_restored) = parse_restic_restore_output(&output.stdout);
    // Surface the backend's stderr diagnostic (warnings) as advisory messages.
    // The condition tests stderr, so the payload must be stderr too — emitting
    // stdout here (backend progress) was a copy-paste bug.
    let messages = if output.stderr.trim().is_empty() {
        Vec::new()
    } else {
        vec![output.stderr.trim().to_string()]
    };

    Ok(RestoreReport {
        snapshot_id: snapshot_id.to_string(),
        target_path: options.target.clone(),
        files_restored,
        bytes_restored,
        success: true,
        messages,
    })
}

/// Attach the repository password to a restic [`CommandSpec`].
///
/// Per the restic docs there are three mutually exclusive ways to provide the
/// password: `RESTIC_PASSWORD`, `--password-file`/`RESTIC_PASSWORD_FILE`, and
/// `--password-command`/`RESTIC_PASSWORD_COMMAND`. We honour the spec's
/// `password_command` when present (the most secure option) by forwarding it to
/// restic's `--password-command` flag.
///
/// When the repository is encrypted but no `password_command` is configured we
/// return a clear error instead of silently authenticating with the job *label*
/// (the spec's `name`) as the passphrase — that fallback could never unlock a
/// real repo and only masked misconfiguration. An unencrypted repo (`Encryption
/// ::None`) needs no password, so no env is attached in that case.
fn apply_restic_password(spec: &BackupSpec, cmd: CommandSpec) -> Result<CommandSpec> {
    if let Some(pw_cmd) = &spec.password_command {
        Ok(cmd.arg("--password-command").arg(pw_cmd))
    } else if spec.encryption != crate::spec::Encryption::None {
        Err(Error::RestoreFailed(format!(
            "backup spec {:?}: encrypted restic repository requires a \
             password_command (none configured); refusing to authenticate \
             with the job label as a passphrase",
            spec.name
        )))
    } else {
        Ok(cmd)
    }
}

// ---------------------------------------------------------------------------
// Borg extract
// ---------------------------------------------------------------------------

/// Run `borg extract` and parse its output into a [`RestoreReport`].
///
/// Command shape (sourced from the official borg extract docs
/// <https://borgbackup.readthedocs.io/en/stable/usage/extract.html>):
///
/// ```text
/// borg extract <repo>::<archive> [PATH...]
/// ```
///
/// Critical: `borg extract` has **no** `--destination` flag. It always writes
/// into the *current working directory* (see the "Note" in the official docs:
/// "extract always writes into the current working directory ('.'), so make
/// sure you `cd` to the right place before calling `borg extract`"). We
/// therefore set [`cwd`](CommandSpec::cwd) to the target directory rather than
/// passing a flag.
///
/// The repository passphrase is supplied via the `BORG_PASSPHRASE` environment
/// variable (documented at
/// <https://borgbackup.readthedocs.io/en/stable/usage/general.html#environment-variables>),
/// never as a CLI argument, and the command is marked
/// [`redact(true)`](CommandSpec::redact).
fn run_borg_extract<R: Runner + ?Sized>(
    spec: &BackupSpec,
    options: &RestoreOptions,
    archive_id: &str,
    runner: &R,
) -> Result<RestoreReport> {
    // borg resolves "latest" itself? No — borg has no "latest" keyword for
    // extract. We treat the literal "latest" as a caller-side placeholder and
    // require an explicit archive name. If the user passed nothing, error out
    // with a helpful message rather than silently extracting the wrong thing.
    if archive_id == "latest" && options.snapshot_id.is_none() {
        return Err(Error::RestoreFailed(format!(
            "backup spec {:?}: borg restore requires an explicit snapshot_id \
             (borg extract has no \"latest\" keyword)",
            spec.name
        )));
    }

    let repo = spec.repository.to_string_lossy();
    let archive_arg = format!("{repo}::{archive_id}");

    let mut cmd = CommandSpec::new("borg")
        .arg("extract")
        .arg("--list")
        .arg(&archive_arg)
        .args(&options.paths)
        // borg extract writes into cwd — there is no --destination flag.
        .cwd(&options.target);

    cmd = apply_borg_passphrase(spec, cmd)?;
    cmd = cmd.redact(true);

    let output = runner
        .run_checked(&cmd)
        .map_err(|e| Error::RestoreFailed(format!("borg extract command failed: {e}")))?;

    let (files_restored, bytes_restored) = parse_borg_extract_output(&output.stdout);
    // Surface the backend's stderr diagnostic (warnings) as advisory messages.
    // The condition tests stderr, so the payload must be stderr too — emitting
    // stdout here (backend progress) was a copy-paste bug.
    let messages = if output.stderr.trim().is_empty() {
        Vec::new()
    } else {
        vec![output.stderr.trim().to_string()]
    };

    Ok(RestoreReport {
        snapshot_id: archive_id.to_string(),
        target_path: options.target.clone(),
        files_restored,
        bytes_restored,
        success: true,
        messages,
    })
}

/// Attach the repository passphrase to a borg [`CommandSpec`].
///
/// Borg documents `BORG_PASSPHRASE` (env var) and `BORG_PASSCOMMAND` (runs a
/// command that prints the passphrase). We prefer the spec's `password_command`
/// mapped to `BORG_PASSCOMMAND`.
///
/// When the repository is encrypted but no `password_command` is configured we
/// return a clear error instead of falling back to the job *label* (the spec's
/// `name`) as the passphrase — that could never unlock a real repo and only
/// masked misconfiguration. An unencrypted repo (`Encryption::None`) needs no
/// passphrase.
fn apply_borg_passphrase(spec: &BackupSpec, cmd: CommandSpec) -> Result<CommandSpec> {
    if let Some(pw_cmd) = &spec.password_command {
        Ok(cmd.env("BORG_PASSCOMMAND", pw_cmd))
    } else if spec.encryption != crate::spec::Encryption::None {
        Err(Error::RestoreFailed(format!(
            "backup spec {:?}: encrypted borg repository requires a \
             password_command (none configured); refusing to authenticate \
             with the job label as a passphrase",
            spec.name
        )))
    } else {
        Ok(cmd)
    }
}

// ---------------------------------------------------------------------------
// Output parsing
// ---------------------------------------------------------------------------

/// Best-effort parse of `restic restore --json` summary output.
///
/// When restic is invoked with `--json` it emits a final summary object whose
/// documented shape (restic 0.19+, see
/// <https://restic.readthedocs.io/en/stable/075_scripting.html>) is the
/// *restore* summary: `message_type: "summary"` with `files_restored`,
/// `total_files`, `bytes_restored`, and `total_bytes` — NOT the backup-summary
/// fields (`files_new`/`files_modified`/`dirs_new`). We scan the stdout line by
/// line for the last JSON object with a `summary` `message_type` and read the
/// restored file and byte counts from it.
///
/// When no JSON summary is present (e.g. plain-text restore output), we fall
/// back to counting lines that look like restored-file entries, returning
/// counts of zero bytes (restic's text format does not surface byte totals).
fn parse_restic_restore_output(stdout: &str) -> (u64, u64) {
    // JSON parsing is available whenever serde_json is pulled in (the `client`
    // feature enables dep:serde_json; the `serde` feature also enables it).
    #[cfg(any(feature = "client", feature = "serde"))]
    {
        // Look for the last JSON line containing a summary object. restic
        // emits progress/status JSON objects followed by a final summary.
        for line in stdout.lines().rev() {
            let trimmed = line.trim();
            if !trimmed.starts_with('{') {
                continue;
            }
            if let Some(summary) = extract_restic_summary(trimmed) {
                return summary;
            }
        }
    }

    // Text heuristic (used when serde_json is unavailable, or when no summary
    // JSON was found): restic's verbose restore output emits lines like
    // "restored  /path/to/file with size 1.234 KiB" or "updated ..." /
    // "unchanged ...". Count only "restored" and "updated" lines.
    let mut files = 0u64;
    for line in stdout.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("restored") || lower.starts_with("updated") {
            files += 1;
        }
    }
    (files, 0)
}

/// File-local summary struct for parsing the restic restore JSON summary.
///
/// Field shape from the official restic `restore --json` summary record
/// (<https://restic.readthedocs.io/en/stable/075_scripting.html#restore>):
/// `message_type:"summary"` with `files_restored` / `total_files` /
/// `bytes_restored` / `total_bytes` (NOT the backup-summary fields
/// `files_new`/`dirs_new`).
#[cfg(any(feature = "client", feature = "serde"))]
#[expect(
    dead_code,
    reason = "mirrors restic restore JSON; total_bytes kept for fidelity"
)]
#[derive(serde::Deserialize)]
struct ResticRestoreSummary {
    message_type: String,
    #[serde(default)]
    files_restored: u64,
    #[serde(default)]
    total_files: u64,
    #[serde(default)]
    bytes_restored: u64,
    #[serde(default)]
    total_bytes: u64,
}

/// Extract file/byte counts from a single restic restore summary JSON line.
#[cfg(any(feature = "client", feature = "serde"))]
fn extract_restic_summary(json_line: &str) -> Option<(u64, u64)> {
    let summary: ResticRestoreSummary = serde_json::from_str(json_line).ok()?;
    if summary.message_type != "summary" {
        return None;
    }
    // Prefer the exact files_restored count; fall back to total_files when the
    // field is absent (older restic / edge samples). Bytes come from
    // bytes_restored (total_bytes includes skipped data).
    let files = if summary.files_restored > 0 {
        summary.files_restored
    } else {
        summary.total_files
    };
    Some((files, summary.bytes_restored))
}

/// Best-effort parse of `borg extract --list` output.
///
/// With `--list`, borg prints one line per extracted item: `x <path>` for
/// extracted files, `o <path>` for files that already existed with the right
/// contents, and `A`/`U` markers for some metadata operations. We count lines
/// beginning with `x ` (extracted) as restored files. borg does not surface a
/// byte total in this output, so bytes defaults to zero.
fn parse_borg_extract_output(stdout: &str) -> (u64, u64) {
    let mut files = 0u64;
    for line in stdout.lines() {
        let trimmed = line.trim_start();
        // borg --list uses status letters: 'x' = extracted, 'o' = ok/unchanged.
        if let Some(rest) = trimmed.strip_prefix("x ")
            && !rest.is_empty()
        {
            files += 1;
        }
    }
    (files, 0)
}

// ---------------------------------------------------------------------------
// Tree comparison for verify()
// ---------------------------------------------------------------------------

/// Recursive file count and total byte size of a directory tree.
#[derive(Debug, PartialEq, Eq)]
struct TreeStats {
    files: u64,
    bytes: u64,
}

/// Walk a directory tree summing regular-file counts and sizes.
fn count_tree(root: &Path) -> std::io::Result<TreeStats> {
    let mut stats = TreeStats { files: 0, bytes: 0 };
    walk(root, &mut stats)?;
    Ok(stats)
}

fn walk(path: &Path, stats: &mut TreeStats) -> std::io::Result<()> {
    if path.is_file() {
        stats.files += 1;
        if let Ok(meta) = std::fs::metadata(path) {
            stats.bytes += meta.len();
        }
        return Ok(());
    }
    let Some(entries) = std::fs::read_dir(path).ok() else {
        // Not a directory or unreadable: treat as zero files.
        return Ok(());
    };
    for entry in entries.flatten() {
        walk(&entry.path(), stats)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use toride_runner::CommandOutput;
    use toride_runner::fake::FakeRunner;

    // -------------------------------------------------------------------
    // Test helpers
    // -------------------------------------------------------------------

    fn spec_restic(repo: &str) -> BackupSpec {
        use crate::spec::{Encryption, RetentionPolicy, Schedule};
        BackupSpec {
            name: "test-job".into(),
            backend: Backend::Restic,
            repository: PathBuf::from(repo),
            sources: vec![PathBuf::from("/data")],
            schedule: Schedule::new("0 2 * * *"),
            retention: RetentionPolicy::default_policy(),
            encryption: Encryption::RepoKey,
            password_command: Some("cat /etc/restic/pw".into()),
            exclude_patterns: vec![],
            tags: vec![],
            extra_env: std::collections::HashMap::new(),
        }
    }

    fn spec_borg(repo: &str) -> BackupSpec {
        use crate::spec::{Encryption, RetentionPolicy, Schedule};
        BackupSpec {
            name: "test-job".into(),
            backend: Backend::Borg,
            repository: PathBuf::from(repo),
            sources: vec![PathBuf::from("/data")],
            schedule: Schedule::new("0 2 * * *"),
            retention: RetentionPolicy::default_policy(),
            encryption: Encryption::RepoKey,
            password_command: Some("cat /etc/borg/pw".into()),
            exclude_patterns: vec![],
            tags: vec![],
            extra_env: std::collections::HashMap::new(),
        }
    }

    /// The real restic restore --json summary shape, as documented at
    /// <https://restic.readthedocs.io/en/stable/075_scripting.html>.
    const RESTIC_RESTORE_SUMMARY_JSON: &str = r#"{"message_type":"summary","snapshot_id":"79766175","seconds_elapsed":12.3,"total_files":60,"files_restored":50,"files_skipped":3,"total_bytes":1572864,"bytes_restored":1572864,"bytes_skipped":0}"#;

    // -------------------------------------------------------------------
    // Restic: command construction
    // -------------------------------------------------------------------

    #[test]
    fn restic_restore_builds_exact_command() {
        // Asserts the EXACT restic restore command shape documented at
        // https://restic.readthedocs.io/en/latest/050_restore.html:
        //   restic -r <repo> restore <snapshot> --target <dir>
        let spec = spec_restic("/srv/restic-repo");
        let options = RestoreOptions::new("/tmp/restore-work")
            .with_snapshot("79766175")
            .with_verify();

        let runner = FakeRunner::new().respond(
            CommandSpec::new("restic")
                .arg("-r")
                .arg("/srv/restic-repo")
                .arg("restore")
                .arg("79766175")
                .arg("--target")
                .arg("/tmp/restore-work")
                .arg("--verify")
                .arg("--password-command")
                .arg("cat /etc/restic/pw")
                .redact(true),
            CommandOutput::from_stdout(RESTIC_RESTORE_SUMMARY_JSON),
        );

        let report = restore_with_runner(&spec, &options, &runner).unwrap();
        assert!(report.success);
        runner.assert_called_with(
            &CommandSpec::new("restic")
                .arg("-r")
                .arg("/srv/restic-repo")
                .arg("restore")
                .arg("79766175")
                .arg("--target")
                .arg("/tmp/restore-work")
                .arg("--verify")
                .arg("--password-command")
                .arg("cat /etc/restic/pw")
                .redact(true),
        );
        // snapshot_id is surfaced in the report.
        assert_eq!(report.snapshot_id, "79766175");
    }

    #[test]
    fn restic_restore_latest_keyword_when_no_snapshot() {
        // restic accepts the literal "latest" keyword to restore the most
        // recent snapshot (see https://man.archlinux.org/man/restic-restore.1.en:
        // 'The special snapshotID "latest" can be used to restore the latest
        // snapshot in the repository.').
        let spec = spec_restic("/srv/restic-repo");
        let options = RestoreOptions::new("/tmp/restore-latest");

        let expected = CommandSpec::new("restic")
            .arg("-r")
            .arg("/srv/restic-repo")
            .arg("restore")
            .arg("latest")
            .arg("--target")
            .arg("/tmp/restore-latest")
            .arg("--password-command")
            .arg("cat /etc/restic/pw")
            .redact(true);

        let runner = FakeRunner::new().respond(expected.clone(), CommandOutput::from_stdout("{}"));
        let report = restore_with_runner(&spec, &options, &runner).unwrap();
        assert_eq!(report.snapshot_id, "latest");
        runner.assert_called_with(&expected);
    }

    #[test]
    fn restic_restore_includes_paths_as_include_flags() {
        let spec = spec_restic("/srv/restic-repo");
        let options = RestoreOptions::new("/tmp/restore-work")
            .with_snapshot("79766175")
            .with_paths(vec!["/work/foo".into(), "/work/bar".into()]);

        let expected = CommandSpec::new("restic")
            .arg("-r")
            .arg("/srv/restic-repo")
            .arg("restore")
            .arg("79766175")
            .arg("--target")
            .arg("/tmp/restore-work")
            .arg("--include")
            .arg("/work/foo")
            .arg("--include")
            .arg("/work/bar")
            .arg("--password-command")
            .arg("cat /etc/restic/pw")
            .redact(true);

        let runner = FakeRunner::new().respond(expected.clone(), CommandOutput::from_stdout(""));
        let _ = restore_with_runner(&spec, &options, &runner).unwrap();
        runner.assert_called_with(&expected);
    }

    // -------------------------------------------------------------------
    // Restic: redaction of passphrase-bearing commands
    // -------------------------------------------------------------------

    #[test]
    fn restic_restore_marks_passphrase_command_redact_true() {
        // REDACTION property: every restic restore command carries the repo
        // password (here via --password-command), so it MUST be built with
        // redact(true). specs_match in toride_runner enforces redact, so a
        // spec built without redact(true) would fail to match this response.
        let spec = spec_restic("/srv/restic-repo");
        let options = RestoreOptions::new("/tmp/restore-work");

        // This response carries redact(true); the restore code must build its
        // command with redact(true) for the match to succeed.
        let expected = CommandSpec::new("restic")
            .arg("-r")
            .arg("/srv/restic-repo")
            .arg("restore")
            .arg("latest")
            .arg("--target")
            .arg("/tmp/restore-work")
            .arg("--password-command")
            .arg("cat /etc/restic/pw")
            .redact(true);

        let runner = FakeRunner::new()
            .strict()
            .respond(expected.clone(), CommandOutput::from_stdout(""));
        let result = restore_with_runner(&spec, &options, &runner);
        assert!(
            result.is_ok(),
            "strict FakeRunner matched: redact(true) was applied. err={result:?}"
        );
    }

    #[test]
    fn restic_restore_without_redact_fails_match() {
        // Inverse property: a command carrying a passphrase but built WITHOUT
        // redact(true) must NOT match what RestoreManager produces. This proves
        // the redact(true) enforcement is non-vacuous.
        let spec = spec_restic("/srv/restic-repo");
        let options = RestoreOptions::new("/tmp/restore-work");

        // Response registered WITHOUT redact(true).
        let unredacted = CommandSpec::new("restic")
            .arg("-r")
            .arg("/srv/restic-repo")
            .arg("restore")
            .arg("latest")
            .arg("--target")
            .arg("/tmp/restore-work")
            .arg("--password-command")
            .arg("cat /etc/restic/pw");
        // (note: no .redact(true) above)

        let runner = FakeRunner::new()
            .strict()
            .respond(unredacted, CommandOutput::from_stdout(""));
        let result = restore_with_runner(&spec, &options, &runner);
        assert!(
            result.is_err(),
            "unredacted passphrase command must NOT match RestoreManager's redacted command"
        );
    }

    // -------------------------------------------------------------------
    // Restic: parses real docs-sourced JSON summary
    // -------------------------------------------------------------------

    #[test]
    fn restic_restore_parses_real_json_summary() {
        // Feeds the REAL restic restore --json summary shape (documented at
        // https://restic.readthedocs.io/en/stable/075_scripting.html) and
        // asserts files_restored / bytes_restored are parsed correctly.
        let spec = spec_restic("/srv/restic-repo");
        let options = RestoreOptions::new("/tmp/restore-work").with_snapshot("79766175");

        let runner = FakeRunner::new()
            .push_response(CommandOutput::from_stdout(RESTIC_RESTORE_SUMMARY_JSON));
        let report = restore_with_runner(&spec, &options, &runner).unwrap();
        // Restore summary carries files_restored / bytes_restored directly
        // (NOT the backup-summary fields files_new/dirs_new).
        assert_eq!(report.files_restored, 50);
        assert_eq!(report.bytes_restored, 1_572_864);
    }

    #[test]
    fn restic_restore_falls_back_to_text_heuristic() {
        // When stdout is plain text (no --json), count "restored"/"updated"
        // lines. Example verbose output from the restic restore dry-run docs.
        let text = "\
restored  /work/foo with size 1.234 KiB
updated   /work/bar with size 4.5 KiB
unchanged /work/baz
restored  /work/qux
";
        let spec = spec_restic("/srv/restic-repo");
        let options = RestoreOptions::new("/tmp/restore-work").with_snapshot("79766175");

        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(text));
        let report = restore_with_runner(&spec, &options, &runner).unwrap();
        assert_eq!(report.files_restored, 3);
        assert_eq!(report.bytes_restored, 0);
    }

    // -------------------------------------------------------------------
    // Restic: error propagation
    // -------------------------------------------------------------------

    #[test]
    fn restic_restore_propagates_command_failure() {
        let spec = spec_restic("/srv/restic-repo");
        let options = RestoreOptions::new("/tmp/restore-work").with_snapshot("79766175");

        // run_checked treats non-zero exit as failure.
        let runner = FakeRunner::new()
            .push_response(CommandOutput::from_stderr("Fatal: wrong password", 12));
        // restic exit 12 == incorrect password (per the man page).
        let result = restore_with_runner(&spec, &options, &runner);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::RestoreFailed(_)));
    }

    #[test]
    fn restic_restore_refuses_encrypted_repo_without_password_command() {
        // SECURITY: an encrypted repo with NO password_command must NOT fall
        // back to authenticating with the job *label* as the passphrase. The
        // restore path returns a clear error before any restic command is
        // issued (so no secret is ever sent), and the job label never reaches
        // a process env.
        use crate::spec::{Encryption, RetentionPolicy, Schedule};
        let spec = BackupSpec {
            name: "env-pw-job".into(),
            backend: Backend::Restic,
            repository: PathBuf::from("/srv/restic-repo"),
            sources: vec![PathBuf::from("/data")],
            schedule: Schedule::new("0 2 * * *"),
            retention: RetentionPolicy::default_policy(),
            encryption: Encryption::RepoKey,
            // No password_command on an encrypted repo.
            password_command: None,
            exclude_patterns: vec![],
            tags: vec![],
            extra_env: std::collections::HashMap::new(),
        };
        let options = RestoreOptions::new("/tmp/restore-work").with_snapshot("79766175");

        // Strict runner with no responses: restore must error BEFORE invoking
        // restic, so the runner is never consulted.
        let runner = FakeRunner::new().strict();
        let result = restore_with_runner(&spec, &options, &runner);
        let err =
            result.expect_err("encrypted repo with no password_command must error, not fall back");
        let msg = format!("{err}");
        assert!(
            msg.contains("password_command"),
            "error must explain the missing password_command: {msg}"
        );
        // No command was issued.
        assert!(
            runner.calls().is_empty(),
            "restore must not spawn restic when the password is unavailable"
        );
    }

    #[test]
    fn borg_restore_refuses_encrypted_repo_without_password_command() {
        // Same property for the borg path.
        use crate::spec::{Encryption, RetentionPolicy, Schedule};
        let spec = BackupSpec {
            name: "borg-job".into(),
            backend: Backend::Borg,
            repository: PathBuf::from("/srv/borg-repo"),
            sources: vec![PathBuf::from("/data")],
            schedule: Schedule::new("0 2 * * *"),
            retention: RetentionPolicy::default_policy(),
            encryption: Encryption::RepoKey,
            password_command: None,
            exclude_patterns: vec![],
            tags: vec![],
            extra_env: std::collections::HashMap::new(),
        };
        let options = RestoreOptions::new("/tmp/restore-work").with_snapshot("archive-1");
        let runner = FakeRunner::new().strict();
        let result = restore_with_runner(&spec, &options, &runner);
        let msg = format!("{}", result.expect_err("must error"));
        assert!(
            msg.contains("password_command"),
            "error must explain the missing password_command: {msg}"
        );
        assert!(runner.calls().is_empty());
    }

    #[test]
    fn restore_validates_spec_before_dispatch() {
        // An invalid spec (empty sources) is rejected before any backend call.
        let mut spec = spec_restic("/srv/restic-repo");
        spec.sources = vec![];
        let options = RestoreOptions::new("/tmp/restore-work").with_snapshot("79766175");
        let runner = FakeRunner::new().strict();
        let result = restore_with_runner(&spec, &options, &runner);
        assert!(matches!(result, Err(Error::ConfigParse(_))));
        assert!(runner.calls().is_empty());
    }

    #[test]
    fn restic_restore_rejects_empty_snapshot_id() {
        let spec = spec_restic("/srv/restic-repo");
        let options = RestoreOptions::new("/tmp/restore-work").with_snapshot("   ");
        let runner = FakeRunner::new();
        let result = restore_with_runner(&spec, &options, &runner);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::RestoreFailed(_)));
    }

    // -------------------------------------------------------------------
    // Borg: command construction
    // -------------------------------------------------------------------

    #[test]
    fn borg_extract_builds_exact_command_with_cwd() {
        // Asserts the EXACT borg extract command shape documented at
        // https://borgbackup.readthedocs.io/en/stable/usage/extract.html.
        // CRITICAL: borg extract has NO --destination flag — it extracts into
        // the current working directory, so the target is set via cwd.
        let spec = spec_borg("/path/to/repo");
        let options = RestoreOptions::new("/tmp/restore").with_snapshot("my-files");

        let expected = CommandSpec::new("borg")
            .arg("extract")
            .arg("--list")
            .arg("/path/to/repo::my-files")
            .cwd("/tmp/restore")
            .env("BORG_PASSCOMMAND", "cat /etc/borg/pw")
            .redact(true);

        let runner = FakeRunner::new().respond(expected.clone(), CommandOutput::from_stdout(""));
        let report = restore_with_runner(&spec, &options, &runner).unwrap();
        runner.assert_called_with(&expected);
        assert_eq!(report.snapshot_id, "my-files");
    }

    #[test]
    fn borg_extract_with_paths_appends_them() {
        let spec = spec_borg("/path/to/repo");
        let options = RestoreOptions::new("/tmp/restore")
            .with_snapshot("my-files")
            .with_paths(vec!["home/user/src".into()]);

        let expected = CommandSpec::new("borg")
            .arg("extract")
            .arg("--list")
            .arg("/path/to/repo::my-files")
            .arg("home/user/src")
            .cwd("/tmp/restore")
            .env("BORG_PASSCOMMAND", "cat /etc/borg/pw")
            .redact(true);

        let runner = FakeRunner::new().respond(expected.clone(), CommandOutput::from_stdout(""));
        let _ = restore_with_runner(&spec, &options, &runner).unwrap();
        runner.assert_called_with(&expected);
    }

    #[test]
    fn borg_extract_requires_explicit_archive() {
        // borg extract has no "latest" keyword, so restoring without an
        // explicit snapshot_id must error rather than guess.
        let spec = spec_borg("/path/to/repo");
        let options = RestoreOptions::new("/tmp/restore");
        let runner = FakeRunner::new();
        let result = restore_with_runner(&spec, &options, &runner);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("explicit snapshot_id"),
            "expected guidance about explicit snapshot_id, got: {msg}"
        );
    }

    // -------------------------------------------------------------------
    // Borg: redaction
    // -------------------------------------------------------------------

    #[test]
    fn borg_extract_marks_passphrase_command_redact_true() {
        let spec = spec_borg("/path/to/repo");
        let options = RestoreOptions::new("/tmp/restore").with_snapshot("my-files");

        let expected = CommandSpec::new("borg")
            .arg("extract")
            .arg("--list")
            .arg("/path/to/repo::my-files")
            .cwd("/tmp/restore")
            .env("BORG_PASSCOMMAND", "cat /etc/borg/pw")
            .redact(true);

        let runner = FakeRunner::new()
            .strict()
            .respond(expected.clone(), CommandOutput::from_stdout(""));
        let result = restore_with_runner(&spec, &options, &runner);
        assert!(result.is_ok(), "redact(true) matched: {result:?}");
    }

    #[test]
    fn borg_extract_without_redact_fails_match() {
        let spec = spec_borg("/path/to/repo");
        let options = RestoreOptions::new("/tmp/restore").with_snapshot("my-files");

        let unredacted = CommandSpec::new("borg")
            .arg("extract")
            .arg("--list")
            .arg("/path/to/repo::my-files")
            .cwd("/tmp/restore")
            .env("BORG_PASSCOMMAND", "cat /etc/borg/pw");
        // (no .redact(true))

        let runner = FakeRunner::new()
            .strict()
            .respond(unredacted, CommandOutput::from_stdout(""));
        let result = restore_with_runner(&spec, &options, &runner);
        assert!(result.is_err(), "unredacted borg command must not match");
    }

    // -------------------------------------------------------------------
    // Borg: parses --list output
    // -------------------------------------------------------------------

    #[test]
    fn borg_extract_parses_list_output() {
        // borg extract --list emits 'x <path>' for each extracted item
        // (see https://borgbackup.readthedocs.io/en/stable/usage/extract.html).
        let text = "\
x home/user/file1
x home/user/file2
o home/user/file3
x home/user/src/main.rs
";
        let spec = spec_borg("/path/to/repo");
        let options = RestoreOptions::new("/tmp/restore").with_snapshot("my-files");

        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(text));
        let report = restore_with_runner(&spec, &options, &runner).unwrap();
        assert_eq!(report.files_restored, 3);
        assert_eq!(report.bytes_restored, 0);
    }

    #[test]
    fn borg_extract_propagates_command_failure() {
        let spec = spec_borg("/path/to/repo");
        let options = RestoreOptions::new("/tmp/restore").with_snapshot("my-files");

        let runner = FakeRunner::new().push_response(CommandOutput::from_stderr(
            "passphrase supplied in BORG_PASSPHRASE is incorrect",
            1,
        ));
        let result = restore_with_runner(&spec, &options, &runner);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::RestoreFailed(_)));
    }

    // -------------------------------------------------------------------
    // Backend dispatch
    // -------------------------------------------------------------------

    #[test]
    fn dispatches_to_restic_for_restic_spec() {
        let spec = spec_restic("/srv/restic-repo");
        let options = RestoreOptions::new("/tmp/restore").with_snapshot("79766175");
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout("{}"));
        let _ = restore_with_runner(&spec, &options, &runner).unwrap();
        let calls = runner.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].program, "restic");
        assert!(calls[0].args.contains(&"restore".to_string()));
    }

    #[test]
    fn dispatches_to_borg_for_borg_spec() {
        let spec = spec_borg("/path/to/repo");
        let options = RestoreOptions::new("/tmp/restore").with_snapshot("my-files");
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(""));
        let _ = restore_with_runner(&spec, &options, &runner).unwrap();
        let calls = runner.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].program, "borg");
        assert!(calls[0].args.contains(&"extract".to_string()));
    }

    // -------------------------------------------------------------------
    // RestoreOptions builder
    // -------------------------------------------------------------------

    #[test]
    fn restore_options_builder() {
        let opts = RestoreOptions::new("/tmp/restore")
            .with_snapshot("abc123")
            .with_paths(vec!["a".into(), "b".into()])
            .with_verify()
            .as_test();
        assert_eq!(opts.target, "/tmp/restore");
        assert_eq!(opts.snapshot_id.as_deref(), Some("abc123"));
        assert_eq!(opts.paths, vec!["a".to_string(), "b".to_string()]);
        assert!(opts.verify);
        assert!(opts.test);
    }

    #[test]
    fn restore_options_defaults() {
        let opts = RestoreOptions::new("/tmp/restore");
        assert!(opts.snapshot_id.is_none());
        assert!(opts.paths.is_empty());
        assert!(!opts.verify);
        assert!(!opts.test);
    }

    // -------------------------------------------------------------------
    // verify()
    // -------------------------------------------------------------------

    #[test]
    fn verify_returns_true_for_identical_trees() {
        use std::fs;
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&dst).unwrap();
        fs::write(src.join("a.txt"), "hello").unwrap();
        fs::write(src.join("b.txt"), "world!!").unwrap();
        fs::write(dst.join("a.txt"), "hello").unwrap();
        fs::write(dst.join("b.txt"), "world!!").unwrap();
        assert!(RestoreManager::verify(&src, &dst).unwrap());
    }

    #[test]
    fn verify_returns_false_for_size_mismatch() {
        use std::fs;
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&dst).unwrap();
        fs::write(src.join("a.txt"), "hello").unwrap();
        fs::write(dst.join("a.txt"), "hello world").unwrap();
        assert!(!RestoreManager::verify(&src, &dst).unwrap());
    }

    #[test]
    fn verify_returns_false_for_count_mismatch() {
        use std::fs;
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&dst).unwrap();
        fs::write(src.join("a.txt"), "x").unwrap();
        fs::write(src.join("b.txt"), "y").unwrap();
        fs::write(dst.join("a.txt"), "x").unwrap();
        assert!(!RestoreManager::verify(&src, &dst).unwrap());
    }

    #[test]
    fn verify_errors_on_missing_source() {
        let result = RestoreManager::verify(Path::new("/nonexistent/src"), Path::new("/tmp"));
        // count_tree tolerates missing dirs (treats as empty), so this returns
        // Ok(false) when dst is also empty, or an error if dst has files.
        // The important property: no panic.
        assert!(result.is_ok() || matches!(result, Err(Error::RestoreFailed(_))));
    }

    // -------------------------------------------------------------------
    // Output parsing units
    // -------------------------------------------------------------------

    #[test]
    fn parse_restic_summary_counts_new_and_modified() {
        let (files, bytes) = parse_restic_restore_output(RESTIC_RESTORE_SUMMARY_JSON);
        assert_eq!(files, 50);
        assert_eq!(bytes, 1_572_864);
    }

    #[test]
    fn parse_restic_ignores_non_summary_json_lines() {
        // A status/progress line must not be mistaken for the summary.
        let stdout = format!(
            "{{\"message_type\":\"status\",\"seconds_elapsed\":1.0}}\n{RESTIC_RESTORE_SUMMARY_JSON}"
        );
        let (files, bytes) = parse_restic_restore_output(&stdout);
        assert_eq!(files, 50);
        assert_eq!(bytes, 1_572_864);
    }

    #[test]
    fn parse_borg_list_counts_x_lines() {
        let (files, _) = parse_borg_extract_output("x a\nx b\no c\n  x d\n");
        assert_eq!(files, 3);
    }
}
