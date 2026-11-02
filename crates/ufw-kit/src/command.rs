//! Command execution layer.
//!
//! Provides a trait-based runner for executing system commands, with a real
//! implementation delegating to [`toride_runner::DuctRunner`] and a fake
//! implementation delegating to [`toride_runner::FakeRunner`].
//!
//! The local [`CommandSpec`] is kept because it carries UFW-specific fields
//! (`requires_root`, `force_c_locale`, `redact_logs`) that the shared
//! [`toride_runner::CommandSpec`] does not have. Conversion is handled by
//! the `IntoShared` helper.
//!
//! The trait also carries a small filesystem view (`read_file`,
//! `file_exists`, `file_metadata`, `list_dir`) whose default implementation
//! reads the local filesystem. Doctor checks use these methods instead of
//! `std::fs` directly, so a runner that forwards commands to another host
//! (such as [`crate::ssh_runner::SshCommandRunner`]) serves the config
//! files from that host rather than mixing in local reads.

use std::collections::HashMap;
use std::time::Duration;

use toride_runner::Runner as _;

use crate::error::{Error, Result};
use crate::spec::{CommandResult, CommandSpec};

/// File facts the doctor checks need: size, unix permission bits, and unix
/// owner id.
///
/// `mode` and `uid` are `None` on non-unix targets and for remote runners
/// that cannot obtain them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileMetadata {
    /// Size in bytes.
    pub len: u64,
    /// Permission bits (`st_mode & 0o777`), unix only.
    pub mode: Option<u32>,
    /// Owning user id, unix only.
    pub uid: Option<u32>,
}

/// Trait for executing commands and reading the files those commands target.
///
/// Implementations must be `Send + Sync` so they can be shared across threads.
pub trait CommandRunner: Send + Sync {
    /// Execute a command and return its output.
    fn run(&self, spec: &CommandSpec) -> Result<CommandResult>;

    /// Check if a binary exists on the system.
    fn binary_exists(&self, name: &str) -> bool;

    /// Read a file's contents.
    ///
    /// The default implementation reads the local filesystem; doctor checks
    /// call this instead of `std::fs` so an injected runner decides which
    /// host the bytes come from.
    fn read_file(&self, path: &str) -> std::io::Result<String> {
        local_read_file(path)
    }

    /// Whether a path exists.
    fn file_exists(&self, path: &str) -> bool {
        local_file_exists(path)
    }

    /// Size, permission bits, and owner of a file, if it exists.
    fn file_metadata(&self, path: &str) -> Option<FileMetadata> {
        local_file_metadata(path)
    }

    /// Names of the entries in a directory (empty when it cannot be read).
    fn list_dir(&self, path: &str) -> Vec<String> {
        local_list_dir(path)
    }
}

/// Local-filesystem `read_file` used by the trait default and unscripted
/// fakes.
fn local_read_file(path: &str) -> std::io::Result<String> {
    std::fs::read_to_string(path)
}

/// Local-filesystem `file_exists`.
fn local_file_exists(path: &str) -> bool {
    std::path::Path::new(path).exists()
}

/// Local-filesystem `file_metadata`.
fn local_file_metadata(path: &str) -> Option<FileMetadata> {
    let meta = std::fs::metadata(path).ok()?;
    Some(FileMetadata {
        len: meta.len(),
        #[cfg(unix)]
        mode: Some(local_mode(&meta)),
        #[cfg(not(unix))]
        mode: None,
        #[cfg(unix)]
        uid: Some(local_uid(&meta)),
        #[cfg(not(unix))]
        uid: None,
    })
}

/// Local-filesystem `list_dir`.
fn local_list_dir(path: &str) -> Vec<String> {
    std::fs::read_dir(path)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(unix)]
fn local_mode(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o777
}

#[cfg(unix)]
fn local_uid(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    meta.uid()
}

/// Convert a local [`CommandSpec`] into a [`toride_runner::CommandSpec`].
///
/// The `force_c_locale` field is honoured by injecting `LC_ALL=C` and
/// `LANG=C` environment variables into the shared spec. The `redact_logs`
/// field is forwarded to the shared spec's `redact` flag so the executing
/// runner (and the tracing it emits) masks sensitive arguments.
fn to_shared_spec(spec: &CommandSpec) -> toride_runner::CommandSpec {
    let mut s = toride_runner::CommandSpec::new(&spec.program);
    for arg in &spec.args {
        s = s.arg(arg);
    }
    if let Some(timeout) = spec.timeout {
        s = s.timeout(timeout);
    }
    if spec.force_c_locale {
        s = s.env("LC_ALL", "C").env("LANG", "C");
    }
    if spec.redact_logs {
        s = s.redact(true);
    }
    s
}

/// Convert a shared [`toride_runner::CommandOutput`] into the local
/// [`CommandResult`].
fn to_local_result(output: &toride_runner::CommandOutput) -> CommandResult {
    CommandResult {
        stdout: output.stdout.clone(),
        stderr: output.stderr.clone(),
        exit_code: output.exit_code,
    }
}

/// Real command runner using `duct`.
pub struct DuctRunner;

impl DuctRunner {
    /// Create a new `DuctRunner`.
    pub fn new() -> Self {
        Self
    }
}

impl Default for DuctRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandRunner for DuctRunner {
    fn run(&self, spec: &CommandSpec) -> Result<CommandResult> {
        // Built up front so the failure warn below logs the redacted form.
        let display_args = if spec.redact_logs {
            redact_args(&spec.args)
        } else {
            spec.args.join(" ")
        };
        tracing::debug!(
            program = %spec.program,
            args = %display_args,
            "executing command"
        );

        let shared = to_shared_spec(spec);
        let timeout = spec.timeout.unwrap_or(Duration::from_secs(30));
        let runner = toride_runner::DuctRunner;

        let output = runner.run(&shared).map_err(|e| {
            let err_str = e.to_string();
            tracing::warn!(
                program = %spec.program,
                args = %display_args,
                error = %err_str,
                "command execution failed"
            );
            if err_str.contains("timeout") {
                Error::CommandTimeout {
                    program: spec.program.clone(),
                    timeout_secs: timeout.as_secs(),
                }
            } else {
                Error::CommandSpawnFailed(err_str)
            }
        })?;

        Ok(to_local_result(&output))
    }

    fn binary_exists(&self, name: &str) -> bool {
        which::which(name).is_ok()
    }
}

/// A fake command runner for testing.
///
/// Responders map `(program, args_string)` to predefined results.
/// If no exact match, falls back to a program-name-only key if registered.
///
/// The filesystem view can be scripted with [`FakeRunner::respond_file`],
/// [`FakeRunner::respond_stat`], and [`FakeRunner::respond_dir`]. Registering
/// any scripted fs response switches the fake's filesystem to scripted-only:
/// unscripted reads report not-found, so tests do not depend on the machine
/// the suite runs on.
pub struct FakeRunner {
    responses: HashMap<String, FakeResponse>,
    files: HashMap<String, String>,
    stats: HashMap<String, FileMetadata>,
    dirs: HashMap<String, Vec<String>>,
    /// Log of all commands executed (for assertions).
    log: std::sync::Mutex<Vec<CommandLog>>,
}

#[derive(Debug, Clone)]
struct FakeResponse {
    result: Result<CommandResult>,
}

/// A log entry for a command that was executed.
#[derive(Debug, Clone)]
pub struct CommandLog {
    /// Program name.
    pub program: String,
    /// Arguments.
    pub args: Vec<String>,
}

impl FakeRunner {
    /// Create a new empty fake runner.
    pub fn new() -> Self {
        Self {
            responses: HashMap::new(),
            files: HashMap::new(),
            stats: HashMap::new(),
            dirs: HashMap::new(),
            log: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn fs_scripted(&self) -> bool {
        !(self.files.is_empty() && self.stats.is_empty() && self.dirs.is_empty())
    }

    /// Register a response for a given program + args combination.
    ///
    /// The key is formatted as `"program arg1 arg2 ..."`.
    pub fn respond(mut self, program: &str, args: &[&str], result: Result<CommandResult>) -> Self {
        let key = format_key(program, args);
        self.responses.insert(key, FakeResponse { result });
        self
    }

    /// Register a one-shot response (consumed after first match).
    pub fn respond_once(
        mut self,
        program: &str,
        args: &[&str],
        result: Result<CommandResult>,
    ) -> Self {
        let key = format_key(program, args);
        self.responses.insert(key, FakeResponse { result });
        self
    }

    /// Register a success response with stdout.
    pub fn respond_ok(self, program: &str, args: &[&str], stdout: &str) -> Self {
        self.respond(
            program,
            args,
            Ok(CommandResult {
                stdout: stdout.into(),
                stderr: String::new(),
                exit_code: Some(0),
            }),
        )
    }

    /// Register a failure response.
    pub fn respond_err(self, program: &str, args: &[&str], stderr: &str, exit_code: i32) -> Self {
        self.respond(
            program,
            args,
            Ok(CommandResult {
                stdout: String::new(),
                stderr: stderr.into(),
                exit_code: Some(exit_code),
            }),
        )
    }

    /// Script the contents of one file for the filesystem view.
    ///
    /// Registering any scripted fs response switches the fake's filesystem
    /// to scripted-only: every unscripted path reads as not-found.
    #[must_use]
    pub fn respond_file(mut self, path: &str, content: &str) -> Self {
        self.files.insert(path.to_string(), content.to_string());
        self
    }

    /// Script the stat facts of one file for the filesystem view.
    ///
    /// As [`FakeRunner::respond_file`], this arms scripted-only mode.
    #[must_use]
    pub fn respond_stat(mut self, path: &str, metadata: FileMetadata) -> Self {
        self.stats.insert(path.to_string(), metadata);
        self
    }

    /// Script the entry names of one directory for the filesystem view.
    ///
    /// As [`FakeRunner::respond_file`], this arms scripted-only mode.
    #[must_use]
    pub fn respond_dir(mut self, path: &str, names: &[&str]) -> Self {
        self.dirs.insert(
            path.to_string(),
            names.iter().map(|name| (*name).to_string()).collect(),
        );
        self
    }

    /// Get the log of all commands that were executed.
    pub fn command_log(&self) -> Vec<CommandLog> {
        self.log.lock().unwrap().clone()
    }

    /// Clear the command log.
    pub fn clear_log(&self) {
        self.log.lock().unwrap().clear();
    }

    /// Number of commands executed.
    pub fn command_count(&self) -> usize {
        self.log.lock().unwrap().len()
    }
}

impl Default for FakeRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandRunner for FakeRunner {
    fn run(&self, spec: &CommandSpec) -> Result<CommandResult> {
        self.log.lock().unwrap().push(CommandLog {
            program: spec.program.clone(),
            args: spec.args.clone(),
        });

        let key = format_key(
            &spec.program,
            &spec.args.iter().map(String::as_str).collect::<Vec<_>>(),
        );

        if let Some(response) = self.responses.get(&key) {
            return response.result.clone();
        }

        if let Some(response) = self.responses.get(&spec.program) {
            return response.result.clone();
        }

        Err(Error::CommandSpawnFailed(format!(
            "no fake response registered for: {} {}",
            spec.program,
            spec.args.join(" ")
        )))
    }

    fn binary_exists(&self, name: &str) -> bool {
        matches!(
            name,
            "ufw"
                | "iptables"
                | "ip6tables"
                | "iptables-save"
                | "ip6tables-save"
                | "systemctl"
                | "journalctl"
                | "nft"
                | "docker"
                | "nginx"
                | "caddy"
                | "ss"
                | "traefik"
                | "traefik-client"
        )
    }

    fn read_file(&self, path: &str) -> std::io::Result<String> {
        if self.fs_scripted() {
            return self
                .files
                .get(path)
                .cloned()
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, path));
        }
        local_read_file(path)
    }

    fn file_exists(&self, path: &str) -> bool {
        if self.fs_scripted() {
            return self.files.contains_key(path) || self.stats.contains_key(path);
        }
        local_file_exists(path)
    }

    fn file_metadata(&self, path: &str) -> Option<FileMetadata> {
        if self.fs_scripted() {
            return self.stats.get(path).copied();
        }
        local_file_metadata(path)
    }

    fn list_dir(&self, path: &str) -> Vec<String> {
        if self.fs_scripted() {
            return self.dirs.get(path).cloned().unwrap_or_default();
        }
        local_list_dir(path)
    }
}

fn format_key(program: &str, args: &[&str]) -> String {
    let mut parts = vec![program.to_string()];
    parts.extend(args.iter().map(|s| (*s).to_string()));
    parts.join(" ")
}

/// Flags whose following argument should be redacted from logs.
const REDACT_FLAGS: &[&str] = &[
    "--password",
    "--passwd",
    "--secret",
    "--token",
    "--key",
    "--api-key",
    "--api_key",
    "--auth",
    "--credentials",
];

/// Redact sensitive arguments from a command's args list.
///
/// Returns a single string with sensitive values replaced by `"***"`.
/// Flags that indicate a following sensitive value (e.g., `--password`)
/// are detected and their next argument is masked.
pub fn redact_args(args: &[String]) -> String {
    let mut result = Vec::with_capacity(args.len());
    let mut redact_next = false;

    for arg in args {
        if redact_next {
            result.push("***".to_string());
            redact_next = false;
            continue;
        }

        let lower = arg.to_ascii_lowercase();
        if REDACT_FLAGS.iter().any(|f| lower == *f) {
            result.push(arg.clone());
            redact_next = true;
            continue;
        }

        if let Some(eq_pos) = arg.find('=') {
            let flag_part = &arg[..eq_pos];
            let lower_flag = flag_part.to_ascii_lowercase();
            if REDACT_FLAGS.iter().any(|f| lower_flag == *f) {
                result.push(format!("{flag_part}=***"));
                continue;
            }
        }

        result.push(arg.clone());
    }

    result.join(" ")
}

#[cfg(test)]
#[path = "command.test.rs"]
mod tests;
