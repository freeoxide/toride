//! Command-line interface for backup management.
//!
//! Provides clap-based argument parsing for the toride-backup CLI binary.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::client::BackupClient;
use crate::config::BackupConfig;
use crate::restore::RestoreOptions;

/// Backup CLI for toride.
#[derive(Parser, Debug)]
#[command(name = "toride-backup", about = "Backup scheduling and management")]
pub struct Cli {
    /// Path to configuration file.
    #[arg(
        short,
        long,
        default_value = "~/.config/toride/backup/config.json"
    )]
    pub config: PathBuf,

    /// Enable verbose logging.
    #[arg(short, long)]
    pub verbose: bool,

    /// Dry run mode - log actions without executing.
    #[arg(long)]
    pub dry_run: bool,

    /// The subcommand to execute.
    #[command(subcommand)]
    pub command: Commands,
}

/// Available CLI subcommands.
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run a backup job.
    Backup {
        /// Name of the backup job to run.
        name: String,
    },

    /// Run retention pruning for a backup job.
    Prune {
        /// Name of the backup job to prune.
        name: String,
    },

    /// Restore from a backup.
    Restore {
        /// Name of the backup job to restore from.
        name: String,
        /// Target directory for the restore.
        #[arg(short, long)]
        target: PathBuf,
        /// Specific snapshot ID (defaults to latest).
        #[arg(short, long)]
        snapshot: Option<String>,
        /// Specific paths to restore (empty = full restore).
        #[arg(short, long)]
        paths: Option<Vec<String>>,
    },

    /// Run a test restore to verify backup integrity.
    TestRestore {
        /// Name of the backup job to test.
        name: String,
    },

    /// List snapshots in a repository.
    Snapshots {
        /// Name of the backup job.
        name: String,
    },

    /// Run diagnostic checks.
    Doctor {
        /// Specific check category to run (defaults to all).
        #[arg(short, long)]
        scope: Option<String>,
    },

    /// Install a backup schedule.
    InstallSchedule {
        /// Name of the backup job.
        name: String,
    },

    /// Remove a backup schedule.
    RemoveSchedule {
        /// Name of the backup job.
        name: String,
    },

    /// Show backup configuration and status.
    Status {
        /// Name of a specific job (omit for all jobs).
        name: Option<String>,
    },

    /// Validate configuration without running backups.
    Validate,
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

impl Cli {
    /// Execute the parsed subcommand against a production [`BackupClient`].
    ///
    /// Constructs the client with [`BackupClient::system`] (real `DuctRunner`,
    /// XDG paths) and honours the global `--dry-run` flag. For a testable,
    /// runner-injectable entry point see [`Self::run_with_client`].
    ///
    /// # Errors
    ///
    /// Propagates any error from config loading or the underlying client call.
    pub fn run(&self) -> crate::Result<()> {
        let client = BackupClient::system()?.with_dry_run(self.dry_run);
        self.run_with_client(&client)
    }

    /// Execute the parsed subcommand against an injected [`BackupClient`].
    ///
    /// Every [`Commands`] variant is mapped to its corresponding real client
    /// method. Spec-bearing variants load the job from the config file given by
    /// `--config` (defaulting to the XDG path) and look it up by name.
    ///
    /// This is the seam used by the FakeRunner-backed tests: the test builds a
    /// `BackupClient` wired to a shared fake runner and asserts the dispatched
    /// command.
    ///
    /// # Errors
    ///
    /// Propagates any error from config loading or the underlying client call.
    pub fn run_with_client(&self, client: &BackupClient) -> crate::Result<()> {
        let config = BackupConfig::load_from(&self.config)?;

        match &self.command {
            Commands::Backup { name } => {
                let spec = lookup_job(&config, name)?;
                let report = client.backup(spec)?;
                println!("{report:?}");
                Ok(())
            }
            Commands::Prune { name } => {
                let spec = lookup_job(&config, name)?;
                let report = client.prune(spec)?;
                println!("{report:?}");
                Ok(())
            }
            Commands::Restore {
                name,
                target,
                snapshot,
                paths,
            } => {
                let spec = lookup_job(&config, name)?;
                let mut options = RestoreOptions::new(target.to_string_lossy());
                if let Some(id) = snapshot {
                    options = options.with_snapshot(id);
                }
                if let Some(paths) = paths {
                    options = options.with_paths(paths.clone());
                }
                let report = client.restore(spec, &options)?;
                println!("{report:?}");
                Ok(())
            }
            Commands::TestRestore { name } => {
                let spec = lookup_job(&config, name)?;
                let report = client.test_restore(spec)?;
                println!("{report:?}");
                Ok(())
            }
            Commands::Snapshots { name } => {
                let spec = lookup_job(&config, name)?;
                let listing = client.snapshots(spec)?;
                println!("{listing:?}");
                Ok(())
            }
            Commands::Doctor { scope } => {
                let scope = parse_doctor_scope(scope.as_deref())?;
                let report = client.doctor(scope)?;
                println!("{report:?}");
                Ok(())
            }
            Commands::InstallSchedule { name } => {
                let spec = lookup_job(&config, name)?;
                client.install_schedule(spec)?;
                println!("installed schedule for {name:?}");
                Ok(())
            }
            Commands::RemoveSchedule { name } => {
                client.remove_schedule(name)?;
                println!("removed schedule for {name:?}");
                Ok(())
            }
            Commands::Status { name } => {
                let reports = client.status(name.as_deref(), &config)?;
                for report in reports {
                    println!("{report:?}");
                }
                Ok(())
            }
            Commands::Validate => {
                config.validate()?;
                println!("config valid ({} jobs)", config.jobs.len());
                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Dispatch helpers
// ---------------------------------------------------------------------------

/// Look up a named backup job in the config, returning a typed error if absent.
fn lookup_job<'c>(
    config: &'c crate::config::BackupConfig,
    name: &str,
) -> crate::Result<&'c crate::spec::BackupSpec> {
    config.get_job(name).ok_or_else(|| {
        crate::Error::ConfigParse(format!("no backup job named {name:?} in config"))
    })
}

/// Map the `--scope <string>` CLI argument onto a [`DoctorScope`].
///
/// `None`, `"all"`, or empty => [`DoctorScope::All`]. Recognised category
/// labels (`binary`, `repository`, `staleness`, `integrity`, `encryption`,
/// `schedule`, `retention`, `space`) map to the corresponding per-job scope
/// carrying an empty job name (the string-named scope path; the doctor emits an
/// informational finding pointing at the spec-backed probe). Anything else is a
/// typed config error rather than a silent default.
fn parse_doctor_scope(scope: Option<&str>) -> crate::Result<crate::doctor::DoctorScope> {
    use crate::doctor::DoctorScope;
    match scope {
        None | Some("") | Some("all") => Ok(DoctorScope::All),
        Some("binary") => Ok(DoctorScope::Binary),
        Some("repository") => Ok(DoctorScope::Repository(String::new())),
        Some("staleness") => Ok(DoctorScope::Staleness(String::new())),
        Some("integrity") => Ok(DoctorScope::Integrity(String::new())),
        Some("encryption") => Ok(DoctorScope::Encryption(String::new())),
        Some("schedule") => Ok(DoctorScope::Schedule(String::new())),
        Some("retention") => Ok(DoctorScope::Retention(String::new())),
        Some("space") => Ok(DoctorScope::Space(String::new())),
        Some(other) => Err(crate::Error::ConfigParse(format!(
            "unknown doctor scope {other:?} (expected one of: all, binary, repository, \
             staleness, integrity, encryption, schedule, retention, space)"
        ))),
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::BackupClient;
    use crate::spec::{Backend, Encryption, RetentionPolicy, Schedule};
    use assert_fs::fixture::FileTouch;
    use assert_fs::NamedTempFile;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::Arc;
    use toride_runner::fake::FakeRunner;
    use toride_runner::{CommandOutput, CommandSpec};

    // -----------------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------------

    /// A minimal valid restic `BackupSpec` whose `backup` issues a real
    /// `restic backup --json` command (mirrors the spec in client.rs's tests).
    fn restic_spec() -> crate::spec::BackupSpec {
        crate::spec::BackupSpec {
            name: "nightly".into(),
            backend: Backend::Restic,
            repository: PathBuf::from("/srv/restic-repo"),
            sources: vec![PathBuf::from("/etc"), PathBuf::from("/home")],
            schedule: Schedule::new("0 2 * * *"),
            retention: RetentionPolicy::default_policy(),
            encryption: Encryption::RepoKey,
            password_command: Some("cat /etc/restic/pw".into()),
            exclude_patterns: vec![],
            tags: vec![],
            extra_env: HashMap::new(),
        }
    }

    /// Write a config containing a single restic job to a temp file and return
    /// its path. The dispatch loads this via `BackupConfig::load_from`.
    fn write_config(spec: &crate::spec::BackupSpec) -> NamedTempFile {
        let mut config = BackupConfig::empty();
        config.upsert_job(spec.clone());
        let file = NamedTempFile::new("backup-config.json").unwrap();
        file.touch().unwrap();
        config.save_to(file.path()).unwrap();
        file
    }

    /// Verbatim `restic backup --json` summary record + snapshots/stats arrays,
    /// matching the documented restic scripting envelope so the backup facade
    /// assembles a truthful report.
    /// Source: https://restic.readthedocs.io/en/stable/075_scripting.html
    const RESTIC_SUMMARY: &str = r#"{"message_type":"summary","files_new":3,"files_changed":2,"files_unmodified":5,"dirs_new":1,"dirs_changed":0,"dirs_unmodified":4,"data_blobs":6,"tree_blobs":2,"data_added":2048,"data_added_packed":1024,"total_files_processed":10,"total_bytes_processed":4096,"total_duration":1.5,"snapshot_id":"5111c8ae5a5e3e2e8b6b4f0c5b8e3a2d1c9f0a1b2c3d4e5f6a7b8c9d0e1f2a3"}"#;
    const RESTIC_SNAPSHOTS: &str = r#"[{"time":"2024-09-18T12:34:56Z","tree":"x","paths":["/etc"],"hostname":"h","username":"u","tags":[],"id":"5111c8ae5a5e3e2e8b6b4f0c5b8e3a2d1c9f0a1b2c3d4e5f6a7b8c9d0e1f2a3","short_id":"5111c8ae"}]"#;
    const RESTIC_STATS: &str = r#"{"total_size":1048576,"total_file_count":42,"total_blob_count":100,"snapshots_count":1,"total_uncompressed_size":2000000,"compression_ratio":1.6,"compression_progress":100,"compression_space_saving":38}"#;

    // -----------------------------------------------------------------------
    // Dispatch: `backup <name>` parses AND reaches the real restic backend
    // -----------------------------------------------------------------------

    /// `Cli::parse_from(["toride-backup", "--config", <path>, "backup", "nightly"])`
    /// must parse into `Commands::Backup { name: "nightly" }`, and
    /// `run_with_client` must dispatch to `BackupClient::backup`, which issues
    /// the real `restic backup --json` command. We assert the FakeRunner
    /// observed exactly that command (program + subcommand + repo flag +
    /// password-command flag + sources), proving the dispatch is real glue, not
    /// a stub.
    #[test]
    fn dispatch_backup_parses_and_invokes_real_backend() {
        let config_file = write_config(&restic_spec());

        let runner = FakeRunner::new()
            .push_response(CommandOutput::from_stdout(RESTIC_SUMMARY))
            .push_response(CommandOutput::from_stdout(RESTIC_SNAPSHOTS))
            .push_response(CommandOutput::from_stdout(RESTIC_STATS));
        let runner_arc = Arc::new(runner);
        let client = BackupClient::with_paths(dummy_paths())
            .with_runner(runner_arc.clone())
            .with_binary(PathBuf::from("/usr/bin/restic"));

        let cli = Cli::parse_from([
            "toride-backup",
            "--config",
            config_file.path().to_str().unwrap(),
            "backup",
            "nightly",
        ]);

        // Prove the parse landed on the right variant before dispatch.
        assert!(
            matches!(cli.command, Commands::Backup { ref name } if name == "nightly"),
            "parse should produce Commands::Backup{{ name: \"nightly\" }}, got {:?}",
            cli.command,
        );

        cli.run_with_client(&client)
            .expect("dispatch should reach the backend and succeed");

        // The exact first command the restic backup workflow issues. The repo
        // password is delivered via --password-command, never as a positional.
        let expected = CommandSpec::new("/usr/bin/restic")
            .args(["--repo", "/srv/restic-repo"])
            .arg("--password-command")
            .arg("cat /etc/restic/pw")
            .args(["backup", "--json", "/etc", "/home"])
            .redact(true);
        runner_arc.assert_called_with(&expected);

        // The backup workflow issues backup + snapshots + stats (3 calls).
        assert_eq!(
            runner_arc.calls().len(),
            3,
            "backup dispatch should issue backup+snapshots+stats"
        );
    }

    // -----------------------------------------------------------------------
    // Dispatch: unknown job name surfaces a typed error (no silent success)
    // -----------------------------------------------------------------------

    /// A `backup <missing>` must fail with a config-parse error rather than
    /// silently succeeding or panicking. Proves lookup_job is wired.
    #[test]
    fn dispatch_backup_unknown_job_returns_config_parse_error() {
        let config_file = write_config(&restic_spec());
        let runner_arc = Arc::new(FakeRunner::new().strict());
        let client = BackupClient::with_paths(dummy_paths())
            .with_runner(runner_arc)
            .with_binary(PathBuf::from("/usr/bin/restic"));

        let cli = Cli::parse_from([
            "toride-backup",
            "--config",
            config_file.path().to_str().unwrap(),
            "backup",
            "does-not-exist",
        ]);

        let err = cli
            .run_with_client(&client)
            .expect_err("unknown job must error");
        assert!(
            matches!(err, crate::Error::ConfigParse(_)),
            "expected ConfigParse error, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Dispatch: `doctor --scope integrity` parses the scope label
    // -----------------------------------------------------------------------

    /// `parse_doctor_scope` maps recognised labels to the right variant and
    /// rejects unknown labels with a typed error. This is the parsing seam the
    /// `doctor` subcommand relies on.
    #[test]
    fn parse_doctor_scope_maps_known_labels_and_rejects_unknown() {
        use crate::doctor::DoctorScope;
        assert!(matches!(parse_doctor_scope(None), Ok(DoctorScope::All)));
        assert!(matches!(
            parse_doctor_scope(Some("all")),
            Ok(DoctorScope::All)
        ));
        assert!(matches!(
            parse_doctor_scope(Some("binary")),
            Ok(DoctorScope::Binary)
        ));
        assert!(matches!(
            parse_doctor_scope(Some("integrity")),
            Ok(DoctorScope::Integrity(_))
        ));
        assert!(
            matches!(parse_doctor_scope(Some("bogus")), Err(crate::Error::ConfigParse(_))),
            "unknown scope label must be a ConfigParse error"
        );
    }

    /// A throwaway `BackupPaths` for tests (mirrors client.rs's dummy_paths).
    fn dummy_paths() -> crate::paths::BackupPaths {
        let root = PathBuf::from("/tmp/toride-backup-cli-test");
        crate::paths::BackupPaths {
            config_dir: root.join("config"),
            config_file: root.join("config").join("config.json"),
            data_dir: root.join("data"),
            cache_dir: root.join("cache"),
            restic_config_dir: root.join("config").join("restic"),
            borg_config_dir: root.join("config").join("borg"),
            schedule_dir: root.join("config").join("schedules"),
            restore_test_dir: root.join("data").join("restore-tests"),
            log_dir: root.join("data").join("logs"),
        }
    }
}
