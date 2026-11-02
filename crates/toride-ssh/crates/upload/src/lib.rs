#![warn(missing_docs)]

//! `toride-ssh-upload`: one-shot file upload to remote hosts over `sftp`
//! batch mode.
//!
//! [`UploadService`] owns a `Box<dyn toride_runner::Runner>` the same way
//! `toride_service::ServiceManager` owns one, and copies one existing local
//! regular file to a validated [`RemotePath`] on a
//! [`HostSpec`] host. The transfer runs as
//! `sftp -o BatchMode=yes -o ConnectTimeout=<secs> -o StrictHostKeyChecking=<policy>
//! -b <batchfile> <host>`, where the batch file holds a single `put`
//! directive; sftp batch mode aborts on the first failing directive and never
//! prompts. [`UploadService::upload_many`] ships several files in that one
//! batch, paying one sftp process instead of one per file.
//!
//! The local side is unix-only: the canonical local path is produced by
//! `fs::canonicalize`, and on Windows the resulting backslash-separated path
//! fails batch-directive validation as [`Error::InvalidLocalPath`] before
//! anything spawns.
//!
//! # Example
//!
//! ```
//! use std::fs;
//! use toride_runner::fake::FakeRunner;
//! use toride_ssh_core::HostSpec;
//! use toride_ssh_upload::{CommandOutput, RemotePath, UploadService};
//!
//! let payload = tempfile::NamedTempFile::new().unwrap();
//! fs::write(payload.path(), b"config").unwrap();
//!
//! let fake = FakeRunner::new().push_response(CommandOutput::from_stdout(""));
//! let service = UploadService::new(Box::new(fake));
//! let host = HostSpec::parse("root@203.0.113.10").unwrap();
//! let remote = RemotePath::parse("/etc/toride/app.conf").unwrap();
//! service.upload(&host, payload.path(), &remote).unwrap();
//! ```

pub use toride_runner::CommandOutput;
pub use toride_ssh_core::{HostKeyPolicy, HostSpec};

use std::fmt;
use std::fs;
use std::io::Write as _;
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

use toride_runner::Runner;
use toride_runner::display::{MIN_SUBSTRING_SCRUB_LEN, scrub_stderr};
use toride_runner::policy::contains_shell_metachars;
use toride_runner::{CommandSpec, discovery};

const DEFAULT_SFTP_PROGRAM: &str = "sftp";
const BATCH_MODE_OPTION: &str = "BatchMode=yes";
const HOST_KEY_FAILURE_SIGNATURE: &str = "host key verification failed";
const SFTP_FATAL_EXIT_CODE: i32 = 255;
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum accepted length, in bytes, of a remote path input.
pub const MAX_REMOTE_PATH_INPUT_LEN: usize = 4096;

/// A validated absolute remote destination for an sftp `put` directive.
///
/// Accepts absolute POSIX paths whose bytes cannot break the batch directive
/// syntax: no control characters (newlines included), no whitespace, no
/// quotes, no backslash, no glob metacharacters, no shell metacharacters, no
/// leading dash, and at most [`MAX_REMOTE_PATH_INPUT_LEN`] bytes. Everything
/// else is a typed [`Error::InvalidRemotePath`] rejection and can never be
/// constructed as a `RemotePath`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RemotePath {
    inner: String,
}

impl RemotePath {
    /// Parse and validate an absolute remote path.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidRemotePath`] when the input is empty, not
    /// absolute, longer than [`MAX_REMOTE_PATH_INPUT_LEN`] bytes, or contains
    /// control characters, whitespace, a leading dash, quotes, a backslash,
    /// glob metacharacters, or shell metacharacters. The reason never echoes
    /// the input.
    pub fn parse(input: &str) -> Result<Self> {
        if input.is_empty() {
            return Err(Error::InvalidRemotePath {
                reason: "must not be empty".to_owned(),
            });
        }
        if !input.starts_with('/') {
            return Err(Error::InvalidRemotePath {
                reason: "must be an absolute path starting with '/'".to_owned(),
            });
        }
        if input.len() > MAX_REMOTE_PATH_INPUT_LEN {
            return Err(Error::InvalidRemotePath {
                reason: format!("must not exceed {MAX_REMOTE_PATH_INPUT_LEN} bytes"),
            });
        }
        validate_batch_token(input).map_err(|reason| Error::InvalidRemotePath { reason })?;
        Ok(Self {
            inner: input.to_owned(),
        })
    }

    /// The validated path exactly as the batch directive spells it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.inner
    }
}

impl fmt::Display for RemotePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.inner)
    }
}

impl fmt::Debug for RemotePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RemotePath(<redacted>)")
    }
}

impl std::str::FromStr for RemotePath {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

/// Errors returned by [`UploadService`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The remote path was rejected before any process spawned. The reason
    /// never echoes the rejected path.
    #[error("remote path rejected: {reason}")]
    InvalidRemotePath {
        /// Why the path was rejected; never contains the path itself.
        reason: String,
    },
    /// The local path cannot appear in an sftp batch directive. The reason
    /// never echoes the rejected path.
    #[error("local path rejected: {reason}")]
    InvalidLocalPath {
        /// Why the path was rejected; never contains the path itself.
        reason: String,
    },
    /// The local file does not exist; checked before any process spawns.
    #[error("local file not found: {0}")]
    LocalFileNotFound(String),
    /// The local path exists but is not a regular file (directory, fifo,
    /// socket, ...); checked before any process spawns.
    #[error("local path is not a regular file: {0}")]
    LocalFileNotRegular(String),
    /// The transfer (or its ssh connection) exited non-zero for a non-host-key
    /// reason. Carries the scrubbed stderr, never the remote path.
    #[error("upload to {host} failed (exit {}): {stderr}", format_exit_code(*exit_code))]
    UploadFailed {
        /// The validated destination the transfer ran against.
        host: String,
        /// The sftp exit code, `None` when terminated by a signal.
        exit_code: Option<i32>,
        /// The runner-scrubbed sftp stderr diagnostic with both upload paths
        /// masked out, whatever their length.
        stderr: String,
    },
    /// A batched transfer ([`UploadService::upload_many`]) aborted at sftp's
    /// first failing directive or failed outright. `failed_index` names the
    /// pair the diagnostic mentions, when it mentions one; `None` means the
    /// aborting directive could not be identified.
    #[error(
        "upload batch to {host} failed{} (exit {}): {stderr}",
        format_failed_index(*failed_index),
        format_exit_code(*exit_code)
    )]
    UploadBatchFailed {
        /// The validated destination the transfer ran against.
        host: String,
        /// Position of the failing pair in the submitted slice, best-effort.
        failed_index: Option<usize>,
        /// The sftp exit code, `None` when terminated by a signal.
        exit_code: Option<i32>,
        /// The runner-scrubbed sftp stderr diagnostic with every upload path
        /// masked out, whatever its length.
        stderr: String,
    },
    /// [`UploadService::upload_many`] was handed an empty pair slice; nothing
    /// was staged and nothing spawned.
    #[error("upload batch rejected: at least one pair is required")]
    EmptyBatch,
    /// Shared `toride-ssh-core` vocabulary: invalid host, host-key
    /// verification failure, or a missing sftp binary.
    #[error(transparent)]
    Core(#[from] toride_ssh_core::Error),
    /// The runner refused or failed to execute the sftp invocation itself.
    #[error(transparent)]
    Runner(#[from] toride_runner::Error),
    /// Temp-file or filesystem I/O failure while staging the batch file.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Alias for results in this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Uploads one local file to a remote host through `sftp` batch mode via a
/// [`Runner`].
pub struct UploadService {
    runner: Box<dyn Runner>,
    host_key_policy: HostKeyPolicy,
    sftp_program: String,
    timeout: Option<Duration>,
    connect_timeout: Duration,
    sftp_present: OnceLock<bool>,
}

impl UploadService {
    /// Create a service over the given runner with [`HostKeyPolicy::Strict`]
    /// and the `sftp` binary looked up on `PATH`.
    #[must_use]
    pub fn new(runner: Box<dyn Runner>) -> Self {
        Self {
            runner,
            host_key_policy: HostKeyPolicy::Strict,
            sftp_program: DEFAULT_SFTP_PROGRAM.to_owned(),
            timeout: None,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            sftp_present: OnceLock::new(),
        }
    }

    /// Override the host-key checking posture.
    #[must_use]
    pub fn with_host_key_policy(mut self, policy: HostKeyPolicy) -> Self {
        self.host_key_policy = policy;
        self
    }

    /// Override the sftp program used in invocations and its presence check.
    ///
    /// The cached presence probe of the previous program is discarded, so the
    /// new program is probed on its next run.
    #[must_use]
    pub fn with_sftp_program(mut self, program: impl Into<String>) -> Self {
        self.sftp_program = program.into();
        self.sftp_present = OnceLock::new();
        self
    }

    /// Override the `-o ConnectTimeout=<secs>` cap sent with every
    /// invocation.
    ///
    /// Without it, a blackholed or firewalled host blocks until the runner's
    /// wall-clock timeout (60 s through a default
    /// [`DuctRunner`](toride_runner::DuctRunner)) and surfaces as an opaque
    /// [`Error::Runner`] timeout instead of sftp's typed connect failure. The
    /// default is 10 s; whole seconds are sent, so sub-second precision is
    /// truncated.
    #[must_use]
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set a wall-clock cap applied to every invocation spec.
    ///
    /// Large uploads routinely exceed the 60 s fallback timeout a default
    /// [`DuctRunner`](toride_runner::DuctRunner) applies; this pins the cap
    /// per service. When unset, the runner's own default (60 s for the
    /// default Duct and Tokio runners, overridable by injecting a configured
    /// runner) decides.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// The configured host-key checking posture.
    #[must_use]
    pub fn host_key_policy(&self) -> HostKeyPolicy {
        self.host_key_policy
    }

    /// The configured sftp program name.
    #[must_use]
    pub fn sftp_program(&self) -> &str {
        &self.sftp_program
    }

    /// The configured per-invocation timeout, if any.
    #[must_use]
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// The configured `-o ConnectTimeout` cap, in whole seconds.
    #[must_use]
    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Copy the local regular file `local` to `remote` on `host`, returning
    /// the captured output on sftp exit 0.
    ///
    /// The local file must exist and be a regular file, and its canonical
    /// path must survive batch-directive validation, before the sftp binary
    /// presence is checked and before any process spawns. The `put` directive
    /// lives in a `0o600` batch file inside a private temporary directory;
    /// both are removed whether the transfer succeeds or fails.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LocalFileNotFound`] or [`Error::LocalFileNotRegular`]
    /// for a missing or non-regular local file, [`Error::InvalidLocalPath`]
    /// when the canonical local path cannot appear in a batch directive,
    /// [`Error::Core`] carrying
    /// [`toride_ssh_core::Error::ToolNotFound`] when the sftp binary is absent
    /// or [`toride_ssh_core::Error::HostKeyVerificationFailed`] when sftp
    /// exits 255 with the host-key verification signature in stderr,
    /// [`Error::UploadFailed`] for any other non-zero exit, and
    /// [`Error::Runner`] when the runner itself fails.
    pub fn upload(
        &self,
        host: &HostSpec,
        local: &Path,
        remote: &RemotePath,
    ) -> Result<CommandOutput> {
        let staged = [StagedPair {
            local: canonical_local_text(local)?,
            remote: remote.as_str().to_owned(),
        }];
        match self.run_batch(host, &staged)? {
            Ok(output) => Ok(output),
            Err(failure) => Err(failure.into_upload_error(host)),
        }
    }

    /// Copy every `(local, remote)` pair to `host` in one sftp batch,
    /// returning the captured output on sftp exit 0.
    ///
    /// All pairs are validated before the sftp binary presence is checked and
    /// before anything spawns: one missing or non-regular local file, or one
    /// canonical local path that cannot appear in a batch directive, rejects
    /// the whole call. One `0o600` batch file holding one `put` directive per
    /// pair, in order, is staged in a private temporary directory and removed
    /// whether the transfer succeeds or fails; the whole batch costs a single
    /// sftp process, so N files pay one SSH handshake and authentication
    /// instead of N.
    ///
    /// sftp batch mode aborts at the first failing directive, so a non-zero
    /// exit means every earlier pair transferred and the failing one and all
    /// after it did not. Which pair failed is reported best-effort from the
    /// diagnostic sftp prints; when the diagnostic names no path,
    /// [`Error::UploadBatchFailed`] carries `failed_index: None`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyBatch`] for an empty slice, the per-pair
    /// [`Error::LocalFileNotFound`], [`Error::LocalFileNotRegular`], or
    /// [`Error::InvalidLocalPath`] for the first invalid pair,
    /// [`Error::Core`] carrying
    /// [`toride_ssh_core::Error::ToolNotFound`] when the sftp binary is absent
    /// or [`toride_ssh_core::Error::HostKeyVerificationFailed`] when sftp
    /// exits 255 with the host-key verification signature in stderr,
    /// [`Error::UploadBatchFailed`] for any other non-zero exit, and
    /// [`Error::Runner`] when the runner itself fails.
    pub fn upload_many(
        &self,
        host: &HostSpec,
        pairs: &[(&Path, &RemotePath)],
    ) -> Result<CommandOutput> {
        if pairs.is_empty() {
            return Err(Error::EmptyBatch);
        }
        let mut staged = Vec::with_capacity(pairs.len());
        for (local, remote) in pairs {
            staged.push(StagedPair {
                local: canonical_local_text(local)?,
                remote: remote.as_str().to_owned(),
            });
        }
        match self.run_batch(host, &staged)? {
            Ok(output) => Ok(output),
            Err(failure) => Err(failure.into_batch_error(host)),
        }
    }

    fn sftp_available(&self) -> bool {
        if let Some(present) = self.sftp_present.get() {
            return *present;
        }
        let present = discovery::binary_exists(&self.sftp_program);
        if present {
            let _ = self.sftp_present.set(true);
        }
        present
    }

    fn run_batch(
        &self,
        host: &HostSpec,
        staged: &[StagedPair],
    ) -> Result<std::result::Result<CommandOutput, RunFailure>> {
        if !self.sftp_available() {
            return Err(Error::Core(toride_ssh_core::Error::ToolNotFound(
                self.sftp_program.clone(),
            )));
        }
        let mut text = String::new();
        for pair in staged {
            text.push_str(&batch_text(&pair.local, &pair.remote));
        }
        let (spec, output) = {
            let dir = tempfile::tempdir()?;
            let mut batch = tempfile::NamedTempFile::new_in(&dir)?;
            batch.write_all(text.as_bytes())?;
            batch.flush()?;
            let batch_arg = batch.path().to_string_lossy().into_owned();
            let spec = self.sftp_spec(host, &batch_arg);
            let output = self.runner.run(&spec)?;
            (spec, output)
        };
        if output.success {
            return Ok(Ok(output));
        }
        let stderr = scrub_staged_stderr(&spec, &output.stderr, staged);
        if is_host_key_failure(&output) {
            return Ok(Err(RunFailure {
                host_key: Some(stderr),
                failed_index: None,
                exit_code: output.exit_code,
                stderr: String::new(),
            }));
        }
        Ok(Err(RunFailure {
            host_key: None,
            failed_index: failed_pair_index(&output.stderr, staged),
            exit_code: output.exit_code,
            stderr,
        }))
    }

    fn sftp_spec(&self, host: &HostSpec, batch_arg: &str) -> CommandSpec {
        let mut spec = CommandSpec::new(self.sftp_program.clone())
            .arg("-o")
            .arg(BATCH_MODE_OPTION)
            .arg("-o")
            .arg(connect_timeout_option(self.connect_timeout))
            .arg("-o")
            .arg(self.host_key_policy.ssh_option())
            .arg("-b")
            .arg(batch_arg)
            .arg(host.destination())
            .stdin_null(true)
            .redact(true);
        if let Some(timeout) = self.timeout {
            spec = spec.timeout(timeout);
        }
        spec
    }
}

/// One validated `(canonical local, remote)` pair bound for the batch file.
struct StagedPair {
    local: String,
    remote: String,
}

/// A non-zero sftp exit, classified, with the paths already masked out of
/// `stderr`.
struct RunFailure {
    host_key: Option<String>,
    failed_index: Option<usize>,
    exit_code: Option<i32>,
    stderr: String,
}

impl RunFailure {
    fn into_upload_error(self, host: &HostSpec) -> Error {
        if let Some(detail) = self.host_key {
            return Error::Core(toride_ssh_core::Error::HostKeyVerificationFailed(detail));
        }
        Error::UploadFailed {
            host: host.destination(),
            exit_code: self.exit_code,
            stderr: self.stderr,
        }
    }

    fn into_batch_error(self, host: &HostSpec) -> Error {
        if let Some(detail) = self.host_key {
            return Error::Core(toride_ssh_core::Error::HostKeyVerificationFailed(detail));
        }
        Error::UploadBatchFailed {
            host: host.destination(),
            failed_index: self.failed_index,
            exit_code: self.exit_code,
            stderr: self.stderr,
        }
    }
}

fn failed_pair_index(raw_stderr: &str, staged: &[StagedPair]) -> Option<usize> {
    staged
        .iter()
        .position(|pair| raw_stderr.contains(pair.remote.as_str()))
        .or_else(|| {
            staged
                .iter()
                .position(|pair| raw_stderr.contains(pair.local.as_str()))
        })
}

fn connect_timeout_option(timeout: Duration) -> String {
    format!("ConnectTimeout={}", timeout.as_secs())
}

fn format_exit_code(exit_code: Option<i32>) -> String {
    exit_code.map_or("signal".to_owned(), |code| code.to_string())
}

fn format_failed_index(failed_index: Option<usize>) -> String {
    failed_index.map_or(String::new(), |index| format!(" at pair index {index}"))
}

fn validate_batch_token(token: &str) -> std::result::Result<(), String> {
    if token.chars().any(char::is_control) {
        return Err("must not contain control characters".to_owned());
    }
    if token.chars().any(char::is_whitespace) {
        return Err("must not contain whitespace".to_owned());
    }
    if token.starts_with('-') {
        return Err("must not start with a dash".to_owned());
    }
    if token.contains(['"', '\'']) {
        return Err("must not contain quotes".to_owned());
    }
    if token.contains('\\') {
        return Err("must not contain a backslash".to_owned());
    }
    if token.contains(['*', '?', '[']) {
        return Err("must not contain glob metacharacters".to_owned());
    }
    if contains_shell_metachars(token) {
        return Err("must not contain shell metacharacters".to_owned());
    }
    Ok(())
}

fn canonical_local_text(local: &Path) -> Result<String> {
    let metadata = fs::metadata(local).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            Error::LocalFileNotFound(local.display().to_string())
        } else {
            Error::Io(err)
        }
    })?;
    if !metadata.is_file() {
        return Err(Error::LocalFileNotRegular(local.display().to_string()));
    }
    let canonical = fs::canonicalize(local)?;
    let text = canonical.to_str().ok_or_else(|| Error::InvalidLocalPath {
        reason: "must be valid UTF-8".to_owned(),
    })?;
    validate_batch_token(text).map_err(|reason| Error::InvalidLocalPath { reason })?;
    Ok(text.to_owned())
}

fn batch_text(local: &str, remote: &str) -> String {
    format!("put {local} {remote}\n")
}

fn scrub_staged_stderr(spec: &CommandSpec, stderr: &str, staged: &[StagedPair]) -> String {
    let masked = staged.iter().fold(stderr.to_owned(), |text, pair| {
        mask_value(&text, &pair.remote)
    });
    let masked = staged
        .iter()
        .fold(masked, |text, pair| mask_value(&text, &pair.local));
    scrub_stderr(spec, &masked)
}

/// Replace every occurrence of `value` with `***`.
///
/// Values of [`MIN_SUBSTRING_SCRUB_LEN`] characters or more are replaced
/// everywhere; shorter validated paths are replaced only where both sides sit
/// on a path boundary, so a `/a` remote path is masked in `/a: denied` but
/// left alone inside the longer, unrelated `/abc`.
fn mask_value(text: &str, value: &str) -> String {
    if value.chars().count() >= MIN_SUBSTRING_SCRUB_LEN {
        return text.replace(value, "***");
    }
    let haystack = text.as_bytes();
    let needle = value.as_bytes();
    if needle.is_empty() || haystack.len() < needle.len() {
        return text.to_owned();
    }
    let mut masked: Vec<u8> = Vec::with_capacity(haystack.len());
    let mut cursor = 0;
    while cursor < haystack.len() {
        let end = cursor + needle.len();
        if end <= haystack.len()
            && &haystack[cursor..end] == needle
            && is_boundary(haystack, cursor, end)
        {
            masked.extend_from_slice(b"***");
            cursor = end;
        } else {
            masked.push(haystack[cursor]);
            cursor += 1;
        }
    }
    String::from_utf8(masked)
        .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned())
}

fn is_boundary(haystack: &[u8], start: usize, end: usize) -> bool {
    let before_ok = start == 0 || !is_path_byte(haystack[start - 1]);
    let after_ok = end == haystack.len() || !is_path_byte(haystack[end]);
    before_ok && after_ok
}

fn is_path_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'-' | b'_')
}

fn is_host_key_failure(output: &CommandOutput) -> bool {
    output.exit_code == Some(SFTP_FATAL_EXIT_CODE)
        && contains_ignore_ascii_case(&output.stderr, HOST_KEY_FAILURE_SIGNATURE)
}

fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    let haystack = haystack.as_bytes();
    let needle = needle.as_bytes();
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use toride_runner::fake::FakeRunner;

    const CANNED_HOST_KEY_BANNER: &str = concat!(
        "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n",
        "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n",
        "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n",
        "Host key verification failed.\n",
    );

    const PAYLOAD_MARKER: &str = "PAYLOAD-MARKER-zz9x";

    #[derive(Clone)]
    struct BatchObservation {
        spec: CommandSpec,
        batch_arg: String,
        existed: bool,
        content: String,
        #[cfg(unix)]
        mode: u32,
    }

    struct BatchSpy {
        fake: FakeRunner,
        observations: Arc<Mutex<Vec<BatchObservation>>>,
    }

    impl BatchSpy {
        fn new(fake: FakeRunner) -> Self {
            Self {
                fake,
                observations: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl Runner for BatchSpy {
        fn run(&self, spec: &CommandSpec) -> toride_runner::Result<CommandOutput> {
            let position = spec
                .args
                .iter()
                .position(|arg| arg == "-b")
                .expect("sftp spec must carry -b");
            let batch_arg = spec.args[position + 1].clone();
            let path = Path::new(&batch_arg);
            let existed = path.exists();
            let mut content = String::new();
            #[cfg(unix)]
            let mut mode = 0;
            if existed {
                content = fs::read_to_string(path).expect("batch file must be readable");
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    mode = fs::metadata(path)
                        .expect("batch metadata")
                        .permissions()
                        .mode()
                        & 0o777;
                }
            }
            self.observations
                .lock()
                .expect("observations lock")
                .push(BatchObservation {
                    spec: spec.clone(),
                    batch_arg,
                    existed,
                    content,
                    #[cfg(unix)]
                    mode,
                });
            self.fake.run(spec)
        }
    }

    fn host() -> HostSpec {
        HostSpec::parse("root@203.0.113.10").unwrap()
    }

    fn remote() -> RemotePath {
        RemotePath::parse("/etc/toride/app.conf").unwrap()
    }

    fn payload_file() -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(file.path(), PAYLOAD_MARKER.as_bytes()).unwrap();
        file
    }

    fn spy_service(response: CommandOutput) -> (UploadService, Arc<Mutex<Vec<BatchObservation>>>) {
        let spy = BatchSpy::new(FakeRunner::new().push_response(response));
        let observations = Arc::clone(&spy.observations);
        (UploadService::new(Box::new(spy)), observations)
    }

    fn snapshot(observations: &Arc<Mutex<Vec<BatchObservation>>>) -> Vec<BatchObservation> {
        observations.lock().expect("observations lock").clone()
    }

    #[test]
    fn upload_invokes_sftp_with_exact_argv_and_no_shell_assembly() {
        let payload = payload_file();
        let (service, observations) = spy_service(CommandOutput::from_stdout(""));
        service.upload(&host(), payload.path(), &remote()).unwrap();

        let obs = snapshot(&observations);
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].spec.program, "sftp");
        assert_eq!(
            &obs[0].spec.args[..7],
            [
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                "-o",
                "StrictHostKeyChecking=yes",
                "-b"
            ]
        );
        assert_eq!(obs[0].spec.args[8], "root@203.0.113.10");
        assert_eq!(obs[0].spec.args.len(), 9);
        assert!(obs[0].existed, "the batch file must exist while sftp runs");
        assert!(
            !obs[0]
                .spec
                .args
                .iter()
                .any(|arg| arg.contains(' ') || arg.contains(';')),
            "no argument may be a joined shell line: {:?}",
            obs[0].spec.args
        );
        assert!(!obs[0].spec.args.contains(&"-c".to_owned()));
        assert!(obs[0].spec.stdin_null, "sftp must not inherit stdin");
        assert!(obs[0].spec.redact, "the spec must opt into redaction");
    }

    #[test]
    fn accept_new_policy_passes_the_accept_new_option() {
        let payload = payload_file();
        let spy = BatchSpy::new(FakeRunner::new().push_response(CommandOutput::from_stdout("")));
        let observations = Arc::clone(&spy.observations);
        let service =
            UploadService::new(Box::new(spy)).with_host_key_policy(HostKeyPolicy::AcceptNew);
        service.upload(&host(), payload.path(), &remote()).unwrap();

        let obs = snapshot(&observations);
        let args = &obs[0].spec.args;
        assert!(args.contains(&"StrictHostKeyChecking=accept-new".to_owned()));
        assert!(!args.contains(&"StrictHostKeyChecking=yes".to_owned()));
    }

    #[test]
    fn batch_file_holds_exactly_one_put_directive() {
        let payload = payload_file();
        let (service, observations) = spy_service(CommandOutput::from_stdout(""));
        service.upload(&host(), payload.path(), &remote()).unwrap();

        let obs = snapshot(&observations);
        let canonical = fs::canonicalize(payload.path()).unwrap();
        assert_eq!(
            obs[0].content,
            format!("put {} /etc/toride/app.conf\n", canonical.display())
        );
        assert_eq!(obs[0].content.lines().count(), 1);
        assert!(obs[0].content.starts_with("put "));
        assert!(obs[0].content.ends_with('\n'));
        assert!(
            !obs[0].content.contains('\r'),
            "the directive must be a single unix line"
        );
    }

    #[cfg(unix)]
    #[test]
    fn batch_file_is_created_owner_read_write_only() {
        let payload = payload_file();
        let (service, observations) = spy_service(CommandOutput::from_stdout(""));
        service.upload(&host(), payload.path(), &remote()).unwrap();

        let obs = snapshot(&observations);
        assert_eq!(obs[0].mode, 0o600);
    }

    #[test]
    fn batch_file_and_directory_are_removed_after_a_successful_run() {
        let payload = payload_file();
        let (service, observations) = spy_service(CommandOutput::from_stdout(""));
        service.upload(&host(), payload.path(), &remote()).unwrap();

        let obs = snapshot(&observations);
        let batch_path = Path::new(&obs[0].batch_arg);
        assert!(!batch_path.exists());
        assert!(!batch_path.parent().expect("batch has a parent").exists());
    }

    #[test]
    fn batch_file_and_directory_are_removed_after_a_failed_run() {
        let payload = payload_file();
        let (service, observations) =
            spy_service(CommandOutput::from_stderr("Couldn't upload: denied\n", 1));
        assert!(service.upload(&host(), payload.path(), &remote()).is_err());

        let obs = snapshot(&observations);
        let batch_path = Path::new(&obs[0].batch_arg);
        assert!(!batch_path.exists());
        assert!(!batch_path.parent().expect("batch has a parent").exists());
    }

    #[test]
    fn remote_paths_that_break_the_directive_are_rejected() {
        let bad_paths = [
            "/etc/a\nb",
            "/etc/a\rb",
            "/etc/a\tb",
            "/etc/a\0b",
            "/etc/a\x1bb",
            "/etc/a b",
            "-oProxyCommand=evil",
            "/etc/a\"b",
            "/etc/a'b",
            "/etc/a\\b",
            "/etc/a*b",
            "/etc/a?b",
            "/etc/a[b",
            "/etc/a;b",
            "/etc/$(id)",
            "/etc/a`id`",
            "/etc/a|b",
            "/etc/a&&b",
            "/etc/a>b",
            "",
            "etc/toride/app.conf",
        ];
        for bad in bad_paths {
            match RemotePath::parse(bad) {
                Err(Error::InvalidRemotePath { reason }) => {
                    assert!(
                        bad.is_empty() || !reason.contains(bad),
                        "{bad:?}: rejection reason leaked the path: {reason}"
                    );
                }
                other => panic!("{bad:?}: expected InvalidRemotePath, got {other:?}"),
            }
        }
        let overlong = format!("/{}", "a".repeat(MAX_REMOTE_PATH_INPUT_LEN));
        assert!(matches!(
            RemotePath::parse(&overlong),
            Err(Error::InvalidRemotePath { ref reason }) if reason.contains("4096")
        ));
    }

    #[test]
    fn remote_rejections_never_reach_a_spawn() {
        let payload = payload_file();
        let fake = FakeRunner::new();
        let service = UploadService::new(Box::new(fake.clone()));
        assert!(RemotePath::parse("/etc/a\nb").is_err());
        let valid = remote();
        assert!(service.upload(&host(), payload.path(), &valid).is_ok());
        assert_eq!(fake.calls().len(), 1, "only the valid upload may spawn");
    }

    #[test]
    fn hosts_that_fail_grammar_cannot_reach_an_argv_position() {
        for bad in [
            "-oProxyCommand=evil",
            "host;other",
            "",
            "   ",
            "-o",
            "user@",
        ] {
            assert!(HostSpec::parse(bad).is_err(), "{bad:?} must not parse");
        }
    }

    #[test]
    fn missing_local_file_is_a_typed_error_before_any_spawn() {
        let fake = FakeRunner::new();
        let service = UploadService::new(Box::new(fake.clone()));
        let missing = Path::new("/nonexistent-toride-upload-9f3a/payload.conf");
        match service.upload(&host(), missing, &remote()).unwrap_err() {
            Error::LocalFileNotFound(path) => {
                assert_eq!(path, "/nonexistent-toride-upload-9f3a/payload.conf");
            }
            other => panic!("expected LocalFileNotFound, got {other:?}"),
        }
        assert!(fake.calls().is_empty());
    }

    #[test]
    fn directory_local_path_is_rejected_as_not_regular() {
        let dir = tempfile::tempdir().unwrap();
        let fake = FakeRunner::new();
        let service = UploadService::new(Box::new(fake.clone()));
        match service.upload(&host(), dir.path(), &remote()).unwrap_err() {
            Error::LocalFileNotRegular(_) => {}
            other => panic!("expected LocalFileNotRegular, got {other:?}"),
        }
        assert!(fake.calls().is_empty());
    }

    #[test]
    fn local_paths_that_break_the_directive_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let fake = FakeRunner::new();
        let service = UploadService::new(Box::new(fake.clone()));
        for name in [
            "sp ace",
            "qu\"ote",
            "apo'strophe",
            "back\\slash",
            "star*name",
            "quest?ion",
            "brack[et",
            "semi;colon",
        ] {
            let file_path = dir.path().join(name);
            fs::write(&file_path, b"x").unwrap();
            let rendered = service
                .upload(&host(), &file_path, &remote())
                .unwrap_err()
                .to_string();
            assert!(
                !rendered.contains(name),
                "{name:?}: rejection leaked the path: {rendered}"
            );
            assert!(rendered.starts_with("local path rejected"), "{rendered}");
        }
        assert!(fake.calls().is_empty());
    }

    #[test]
    fn glob_bearing_payload_with_matching_siblings_is_rejected_before_spawn() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("payload-1.conf"), b"first").unwrap();
        fs::write(dir.path().join("payload-2.conf"), b"second").unwrap();
        let glob_bearing = dir.path().join("payload-*.conf");
        fs::write(&glob_bearing, PAYLOAD_MARKER.as_bytes()).unwrap();
        let directory_remote = RemotePath::parse("/etc/toride/").unwrap();
        let fake = FakeRunner::new();
        let service = UploadService::new(Box::new(fake.clone()));

        match service
            .upload(&host(), &glob_bearing, &directory_remote)
            .unwrap_err()
        {
            Error::InvalidLocalPath { reason } => {
                assert!(reason.contains("glob"), "{reason}");
                assert!(!reason.contains("payload"), "{reason}");
            }
            other => panic!("expected InvalidLocalPath, got {other:?}"),
        }
        assert!(
            fake.calls().is_empty(),
            "a glob-bearing payload must never reach sftp, which would upload every sibling"
        );
    }

    #[test]
    fn glob_characters_are_rejected_in_remote_paths_before_spawn() {
        let payload = payload_file();
        let fake = FakeRunner::new();
        let service = UploadService::new(Box::new(fake.clone()));
        for bad in [
            "/etc/toride/*.conf",
            "/etc/toride/payload?.conf",
            "/etc/toride/pa[tch",
        ] {
            assert!(
                matches!(
                    RemotePath::parse(bad),
                    Err(Error::InvalidRemotePath { ref reason }) if reason.contains("glob")
                ),
                "{bad:?}: expected the glob rejection"
            );
        }
        assert!(service.upload(&host(), payload.path(), &remote()).is_ok());
        assert_eq!(fake.calls().len(), 1, "only the clean upload may spawn");
    }

    #[test]
    fn exit_255_with_host_key_signature_maps_to_the_host_key_error() {
        let payload = payload_file();
        let (service, _observations) =
            spy_service(CommandOutput::from_stderr(CANNED_HOST_KEY_BANNER, 255));
        match service
            .upload(&host(), payload.path(), &remote())
            .unwrap_err()
        {
            Error::Core(toride_ssh_core::Error::HostKeyVerificationFailed(detail)) => {
                assert!(detail.contains("Host key verification failed"), "{detail}");
            }
            other => panic!("expected HostKeyVerificationFailed, got {other:?}"),
        }
    }

    #[test]
    fn exit_255_with_bare_signature_line_also_maps_to_the_host_key_error() {
        let payload = payload_file();
        let (service, _observations) = spy_service(CommandOutput::from_stderr(
            "root@203.0.113.10: Host key verification failed.\n",
            255,
        ));
        assert!(matches!(
            service
                .upload(&host(), payload.path(), &remote())
                .unwrap_err(),
            Error::Core(toride_ssh_core::Error::HostKeyVerificationFailed(_))
        ));
    }

    #[test]
    fn exit_255_without_the_signature_is_a_plain_upload_failure() {
        let payload = payload_file();
        let (service, _observations) = spy_service(CommandOutput::from_stderr(
            "ssh: connect to host 203.0.113.10 port 22: Connection refused\n",
            255,
        ));
        match service
            .upload(&host(), payload.path(), &remote())
            .unwrap_err()
        {
            Error::UploadFailed {
                exit_code: Some(255),
                ..
            } => {}
            other => panic!("expected UploadFailed(255), got {other:?}"),
        }
    }

    #[test]
    fn nonzero_exit_maps_to_upload_failed_with_scrubbed_stderr() {
        let payload = payload_file();
        let (service, _observations) =
            spy_service(CommandOutput::from_stderr("Couldn't upload: denied\n", 1));
        match service
            .upload(&host(), payload.path(), &remote())
            .unwrap_err()
        {
            Error::UploadFailed {
                host,
                exit_code,
                stderr,
            } => {
                assert_eq!(host, "root@203.0.113.10");
                assert_eq!(exit_code, Some(1));
                assert!(stderr.contains("denied"), "{stderr}");
            }
            other => panic!("expected UploadFailed, got {other:?}"),
        }
    }

    #[test]
    fn failure_errors_leak_neither_remote_path_nor_payload() {
        let payload = payload_file();
        let secret_remote = RemotePath::parse("/etc/toride/sekrit.target").unwrap();
        let (service, _observations) = spy_service(CommandOutput::from_stderr(
            "Couldn't upload to /etc/toride/sekrit.target: Permission denied\n",
            1,
        ));
        let rendered = service
            .upload(&host(), payload.path(), &secret_remote)
            .unwrap_err()
            .to_string();
        assert!(!rendered.contains("sekrit.target"), "{rendered}");
        assert!(!rendered.contains("/etc/toride"), "{rendered}");
        assert!(!rendered.contains(PAYLOAD_MARKER), "{rendered}");
        assert!(
            rendered.contains("***"),
            "the masked path must be elided: {rendered}"
        );
    }

    #[test]
    fn missing_sftp_binary_is_reported_before_any_spawn() {
        let payload = payload_file();
        let fake = FakeRunner::new();
        let service = UploadService::new(Box::new(fake.clone()))
            .with_sftp_program("toride-missing-sftp-probe");
        match service
            .upload(&host(), payload.path(), &remote())
            .unwrap_err()
        {
            Error::Core(toride_ssh_core::Error::ToolNotFound(name)) => {
                assert_eq!(name, "toride-missing-sftp-probe");
            }
            other => panic!("expected ToolNotFound, got {other:?}"),
        }
        assert!(fake.calls().is_empty());
    }

    #[test]
    fn runner_errors_propagate_as_the_runner_variant() {
        let payload = payload_file();
        let fake = FakeRunner::new().push_result(Err(toride_runner::Error::SpawnFailed {
            program: "sftp".to_owned(),
            detail: "exec format error".to_owned(),
        }));
        let service = UploadService::new(Box::new(fake));
        assert!(matches!(
            service
                .upload(&host(), payload.path(), &remote())
                .unwrap_err(),
            Error::Runner(toride_runner::Error::SpawnFailed { .. })
        ));
    }

    #[test]
    fn success_returns_the_captured_output() {
        let payload = payload_file();
        let (service, _observations) =
            spy_service(CommandOutput::from_stdout("Uploading payload.conf\n"));
        let output = service.upload(&host(), payload.path(), &remote()).unwrap();
        assert!(output.success);
        assert_eq!(output.exit_code, Some(0));
    }

    #[test]
    fn builders_override_policy_and_program() {
        let svc = UploadService::new(Box::new(FakeRunner::new()))
            .with_host_key_policy(HostKeyPolicy::AcceptNew)
            .with_sftp_program("/usr/bin/sftp");
        assert_eq!(svc.host_key_policy(), HostKeyPolicy::AcceptNew);
        assert_eq!(svc.sftp_program(), "/usr/bin/sftp");
    }

    #[test]
    fn defaults_are_strict_policy_and_path_sftp() {
        let svc = UploadService::new(Box::new(FakeRunner::new()));
        assert_eq!(svc.host_key_policy(), HostKeyPolicy::Strict);
        assert_eq!(svc.sftp_program(), "sftp");
        assert_eq!(svc.timeout(), None);
        assert_eq!(svc.connect_timeout(), Duration::from_secs(10));
    }

    /// foundations-0: `with_timeout` must land on every invocation spec, so a
    /// large upload is not killed by the runner's 60 s default.
    #[test]
    fn with_timeout_applies_the_cap_to_the_invocation_spec() {
        let payload = payload_file();
        let (service, observations) = spy_service(CommandOutput::from_stdout(""));
        let service = service.with_timeout(Duration::from_secs(600));
        assert_eq!(service.timeout(), Some(Duration::from_secs(600)));

        service.upload(&host(), payload.path(), &remote()).unwrap();

        let obs = snapshot(&observations);
        assert_eq!(obs.len(), 1);
        assert_eq!(
            obs[0].spec.timeout,
            Some(Duration::from_secs(600)),
            "the spec must carry the service timeout"
        );
    }

    /// Without the knob the spec leaves the timeout unset, deferring to the
    /// runner default (60 s on the default Duct/Tokio runners).
    #[test]
    fn without_timeout_the_spec_defers_to_the_runner_default() {
        let payload = payload_file();
        let (service, observations) = spy_service(CommandOutput::from_stdout(""));
        service.upload(&host(), payload.path(), &remote()).unwrap();
        assert_eq!(snapshot(&observations)[0].spec.timeout, None);
    }

    #[test]
    fn remote_path_parse_accepts_benign_absolute_paths() {
        for good in [
            "/etc/toride/app.conf",
            "/srv/static/pkg-1.2/dist.tar.gz",
            "/root/.ssh/authorized_keys",
            "/etc/toride/",
            "/a",
        ] {
            let parsed = RemotePath::parse(good).unwrap_or_else(|err| panic!("{good:?}: {err}"));
            assert_eq!(parsed.as_str(), good);
            assert_eq!(parsed.to_string(), good);
        }
    }

    #[test]
    fn remote_path_from_str_and_traits_round_trip() {
        let parsed: RemotePath = "/etc/toride/app.conf".parse().unwrap();
        assert_eq!(parsed, RemotePath::parse("/etc/toride/app.conf").unwrap());
        assert_eq!(parsed.clone().as_str(), "/etc/toride/app.conf");
        assert!("/etc/bad\npath".parse::<RemotePath>().is_err());
    }

    #[test]
    fn remote_path_debug_never_reveals_the_path() {
        let rendered = format!("{:?}", remote());
        assert!(!rendered.contains("/etc"), "{rendered}");
        assert!(!rendered.contains("app.conf"), "{rendered}");
    }

    #[test]
    fn batch_text_is_a_single_put_directive() {
        assert_eq!(
            batch_text("/tmp/src", "/etc/dst"),
            "put /tmp/src /etc/dst\n"
        );
    }

    #[test]
    fn failure_display_names_the_exit_code_without_the_option_wrapper() {
        let payload = payload_file();
        let (service, _observations) = spy_service(CommandOutput::from_stderr("denied\n", 3));
        let rendered = service
            .upload(&host(), payload.path(), &remote())
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("exit 3"), "{rendered}");
        assert!(!rendered.contains("Some(3)"), "{rendered}");
    }

    #[test]
    fn failure_display_names_signal_termination_instead_of_exit_none() {
        let payload = payload_file();
        let killed = CommandOutput::new(String::new(), "killed\n".to_owned(), None);
        let (service, _observations) = spy_service(killed);
        let rendered = service
            .upload(&host(), payload.path(), &remote())
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("exit signal"), "{rendered}");
        assert!(!rendered.contains("None"), "{rendered}");
    }

    /// A blackholed host must fail at sftp's `ConnectTimeout` option, not at
    /// the runner's 60 s wall clock, so every spec carries it.
    #[test]
    fn every_spec_carries_the_default_connect_timeout() {
        let payload = payload_file();
        let (service, observations) = spy_service(CommandOutput::from_stdout(""));
        assert_eq!(service.connect_timeout(), Duration::from_secs(10));
        service.upload(&host(), payload.path(), &remote()).unwrap();

        let obs = snapshot(&observations);
        let position = obs[0]
            .spec
            .args
            .iter()
            .position(|arg| arg == "ConnectTimeout=10")
            .expect("the ConnectTimeout option must be present");
        assert_eq!(&obs[0].spec.args[position - 1], &"-o".to_owned());
    }

    #[test]
    fn with_connect_timeout_overrides_the_option_value() {
        let payload = payload_file();
        let spy = BatchSpy::new(FakeRunner::new().push_response(CommandOutput::from_stdout("")));
        let observations = Arc::clone(&spy.observations);
        let service =
            UploadService::new(Box::new(spy)).with_connect_timeout(Duration::from_secs(4));
        assert_eq!(service.connect_timeout(), Duration::from_secs(4));
        service.upload(&host(), payload.path(), &remote()).unwrap();

        let obs = snapshot(&observations);
        assert!(
            obs[0].spec.args.contains(&"ConnectTimeout=4".to_owned()),
            "{:?}",
            obs[0].spec.args
        );
        assert!(
            !obs[0].spec.args.contains(&"ConnectTimeout=10".to_owned()),
            "{:?}",
            obs[0].spec.args
        );
    }

    /// The presence probe caches per instance; switching programs through the
    /// consuming builder must not inherit the previous program's probe.
    #[test]
    fn changing_the_sftp_program_discards_the_cached_presence_probe() {
        let payload = payload_file();
        let fake = FakeRunner::new().push_response(CommandOutput::from_stdout(""));
        let service = UploadService::new(Box::new(fake.clone()));
        service.upload(&host(), payload.path(), &remote()).unwrap();

        let rebuilt = service.with_sftp_program("toride-missing-sftp-probe");
        match rebuilt
            .upload(&host(), payload.path(), &remote())
            .unwrap_err()
        {
            Error::Core(toride_ssh_core::Error::ToolNotFound(name)) => {
                assert_eq!(name, "toride-missing-sftp-probe");
            }
            other => panic!("expected ToolNotFound, got {other:?}"),
        }
        assert_eq!(fake.calls().len(), 1, "only the first upload may spawn");
    }

    #[test]
    fn exit_255_with_uppercase_signature_still_maps_to_the_host_key_error() {
        let payload = payload_file();
        let (service, _observations) = spy_service(CommandOutput::from_stderr(
            "ROOT@HOST: HOST KEY VERIFICATION FAILED.\n",
            255,
        ));
        assert!(matches!(
            service
                .upload(&host(), payload.path(), &remote())
                .unwrap_err(),
            Error::Core(toride_ssh_core::Error::HostKeyVerificationFailed(_))
        ));
    }

    /// A validated one- or two-character remote path is masked wherever it
    /// appears as a whole token, so no length floor leaks short paths.
    #[test]
    fn short_remote_paths_are_masked_on_path_boundaries() {
        let dir = tempfile::tempdir().unwrap();
        let local = dir.path().join("payload");
        fs::write(&local, b"x").unwrap();
        let short_remote = RemotePath::parse("/a").unwrap();

        let (service, _observations) = spy_service(CommandOutput::from_stderr(
            "Couldn't upload to /a: Permission denied\n",
            1,
        ));
        let rendered = service
            .upload(&host(), &local, &short_remote)
            .unwrap_err()
            .to_string();
        assert!(!rendered.contains("/a:"), "{rendered}");
        assert!(rendered.contains("***"), "{rendered}");

        let unrelated = mask_value("failed for /abc and /a too", "/a");
        assert_eq!(unrelated, "failed for /abc and *** too");
    }

    #[test]
    fn mask_value_leaves_longer_tokens_embedding_a_short_path_alone() {
        assert_eq!(mask_value("see /archive first", "/a"), "see /archive first");
        assert_eq!(mask_value("path /a end", "/a"), "path *** end");
        assert_eq!(mask_value("nothing here", "/a"), "nothing here");
    }

    #[test]
    fn upload_many_stages_one_batch_and_spawns_one_sftp_process() {
        let dir = tempfile::tempdir().unwrap();
        let unit = dir.path().join("web.service");
        fs::write(&unit, b"[Unit]\n").unwrap();
        let env = dir.path().join("web.env");
        fs::write(&env, b"PORT=8080\n").unwrap();
        let first = RemotePath::parse("/etc/systemd/system/web.service").unwrap();
        let second = RemotePath::parse("/etc/toride/web.env").unwrap();

        let (service, observations) = spy_service(CommandOutput::from_stdout(""));
        service
            .upload_many(
                &host(),
                &[(unit.as_path(), &first), (env.as_path(), &second)],
            )
            .unwrap();

        let obs = snapshot(&observations);
        assert_eq!(obs.len(), 1, "a batched upload is exactly one sftp process");
        let unit_canonical = fs::canonicalize(&unit).unwrap();
        let env_canonical = fs::canonicalize(&env).unwrap();
        assert_eq!(
            obs[0].content,
            format!(
                "put {} /etc/systemd/system/web.service\nput {} /etc/toride/web.env\n",
                unit_canonical.display(),
                env_canonical.display()
            )
        );
        assert_eq!(obs[0].content.lines().count(), 2);
        let batch_path = Path::new(&obs[0].batch_arg);
        assert!(
            !batch_path.exists(),
            "staging must be removed after success"
        );
        assert!(!batch_path.parent().expect("batch has a parent").exists());
    }

    #[test]
    fn upload_many_rejects_the_whole_batch_when_any_pair_is_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let good = dir.path().join("good.conf");
        fs::write(&good, b"x").unwrap();
        let missing = dir.path().join("missing.conf");
        let first = RemotePath::parse("/etc/toride/good.conf").unwrap();
        let second = RemotePath::parse("/etc/toride/missing.conf").unwrap();

        let fake = FakeRunner::new();
        let service = UploadService::new(Box::new(fake.clone()));
        match service
            .upload_many(
                &host(),
                &[(good.as_path(), &first), (missing.as_path(), &second)],
            )
            .unwrap_err()
        {
            Error::LocalFileNotFound(path) => {
                assert!(path.ends_with("missing.conf"), "{path}");
            }
            other => panic!("expected LocalFileNotFound, got {other:?}"),
        }
        assert!(
            fake.calls().is_empty(),
            "one invalid pair must reject the whole batch before any spawn"
        );
    }

    #[test]
    fn upload_many_rejects_an_empty_pair_slice() {
        let fake = FakeRunner::new();
        let service = UploadService::new(Box::new(fake.clone()));
        assert!(matches!(
            service.upload_many(&host(), &[]).unwrap_err(),
            Error::EmptyBatch
        ));
        assert!(fake.calls().is_empty());
    }

    #[test]
    fn upload_many_failure_names_the_failing_pair_best_effort() {
        let dir = tempfile::tempdir().unwrap();
        let one = dir.path().join("one.conf");
        fs::write(&one, b"1").unwrap();
        let two = dir.path().join("two.conf");
        fs::write(&two, b"2").unwrap();
        let first = RemotePath::parse("/etc/toride/one.conf").unwrap();
        let second = RemotePath::parse("/etc/toride/two.conf").unwrap();

        let (service, _observations) = spy_service(CommandOutput::from_stderr(
            "sftp> put two\nCouldn't upload to /etc/toride/two.conf: Permission denied\n",
            1,
        ));
        match service
            .upload_many(
                &host(),
                &[(one.as_path(), &first), (two.as_path(), &second)],
            )
            .unwrap_err()
        {
            Error::UploadBatchFailed {
                failed_index,
                exit_code,
                stderr,
                ..
            } => {
                assert_eq!(failed_index, Some(1), "{stderr}");
                assert_eq!(exit_code, Some(1));
                assert!(!stderr.contains("/etc/toride/two.conf"), "{stderr}");
                assert!(stderr.contains("***"), "{stderr}");
            }
            other => panic!("expected UploadBatchFailed, got {other:?}"),
        }
    }

    #[test]
    fn upload_many_failure_without_a_named_path_reports_no_index() {
        let dir = tempfile::tempdir().unwrap();
        let one = dir.path().join("one.conf");
        fs::write(&one, b"1").unwrap();
        let remote_one = RemotePath::parse("/etc/toride/one.conf").unwrap();

        let (service, _observations) =
            spy_service(CommandOutput::from_stderr("connection lost\n", 2));
        match service
            .upload_many(&host(), &[(one.as_path(), &remote_one)])
            .unwrap_err()
        {
            Error::UploadBatchFailed { failed_index, .. } => {
                assert_eq!(failed_index, None);
            }
            other => panic!("expected UploadBatchFailed, got {other:?}"),
        }
    }

    #[test]
    fn upload_many_host_key_failure_masks_the_banner_paths() {
        let dir = tempfile::tempdir().unwrap();
        let one = dir.path().join("one.conf");
        fs::write(&one, b"1").unwrap();
        let secret_remote = RemotePath::parse("/etc/toride/sekrit.conf").unwrap();

        let (service, _observations) = spy_service(CommandOutput::from_stderr(
            "Host key verification failed for /etc/toride/sekrit.conf.\n",
            255,
        ));
        match service
            .upload_many(&host(), &[(one.as_path(), &secret_remote)])
            .unwrap_err()
        {
            Error::Core(toride_ssh_core::Error::HostKeyVerificationFailed(detail)) => {
                assert!(detail.contains("Host key verification failed"), "{detail}");
                assert!(!detail.contains("/etc/toride/sekrit.conf"), "{detail}");
            }
            other => panic!("expected HostKeyVerificationFailed, got {other:?}"),
        }
    }

    #[test]
    fn upload_many_failure_display_names_signal_termination() {
        let dir = tempfile::tempdir().unwrap();
        let one = dir.path().join("one.conf");
        fs::write(&one, b"1").unwrap();
        let remote_one = RemotePath::parse("/etc/toride/one.conf").unwrap();

        let killed = CommandOutput::new(String::new(), "killed\n".to_owned(), None);
        let (service, _observations) = spy_service(killed);
        let rendered = service
            .upload_many(&host(), &[(one.as_path(), &remote_one)])
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("exit signal"), "{rendered}");
        assert!(!rendered.contains("None"), "{rendered}");
    }
}
