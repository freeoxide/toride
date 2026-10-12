#![warn(missing_docs)]

//! `toride-ssh-upload` — one-shot file upload to remote hosts over `sftp`
//! batch mode.
//!
//! [`UploadService`] owns a `Box<dyn toride_runner::Runner>` the same way
//! `toride_service::ServiceManager` owns one, and copies one existing local
//! regular file to a validated [`RemotePath`] on a
//! [`HostSpec`](toride_ssh_core::HostSpec) host. The transfer runs as
//! `sftp -o BatchMode=yes -o StrictHostKeyChecking=<policy> -b <batchfile>
//! <host>`, where the batch file holds a single `put` directive; sftp batch
//! mode aborts on the first failing directive and never prompts.
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

use toride_runner::Runner;
use toride_runner::display::{MIN_SUBSTRING_SCRUB_LEN, scrub_stderr};
use toride_runner::policy::contains_shell_metachars;
use toride_runner::{CommandSpec, discovery};

const DEFAULT_SFTP_PROGRAM: &str = "sftp";
const BATCH_MODE_OPTION: &str = "BatchMode=yes";
const HOST_KEY_FAILURE_SIGNATURE: &str = "host key verification failed";
const SFTP_FATAL_EXIT_CODE: i32 = 255;

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
    #[error("upload to {host} failed (exit {exit_code:?}): {stderr}")]
    UploadFailed {
        /// The validated destination the transfer ran against.
        host: String,
        /// The sftp exit code, `None` when terminated by a signal.
        exit_code: Option<i32>,
        /// The runner-scrubbed sftp stderr diagnostic with both upload paths
        /// masked out.
        stderr: String,
    },
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
        }
    }

    /// Override the host-key checking posture.
    #[must_use]
    pub fn with_host_key_policy(mut self, policy: HostKeyPolicy) -> Self {
        self.host_key_policy = policy;
        self
    }

    /// Override the sftp program used in invocations and its presence check.
    #[must_use]
    pub fn with_sftp_program(mut self, program: impl Into<String>) -> Self {
        self.sftp_program = program.into();
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
        let local_text = canonical_local_text(local)?;
        if !discovery::binary_exists(&self.sftp_program) {
            return Err(Error::Core(toride_ssh_core::Error::ToolNotFound(
                self.sftp_program.clone(),
            )));
        }
        let text = batch_text(local_text.as_str(), remote.as_str());
        let dir = tempfile::tempdir()?;
        let mut batch = tempfile::NamedTempFile::new_in(&dir)?;
        batch.write_all(text.as_bytes())?;
        batch.flush()?;
        let batch_arg = batch.path().to_string_lossy().into_owned();
        let spec = self.sftp_spec(host, &batch_arg);
        let output = self.runner.run(&spec)?;
        drop(batch);
        drop(dir);
        if output.success {
            return Ok(output);
        }
        let stderr = scrub_upload_stderr(&spec, &output.stderr, &local_text, remote.as_str());
        if is_host_key_failure(&output) {
            return Err(Error::Core(
                toride_ssh_core::Error::HostKeyVerificationFailed(stderr),
            ));
        }
        Err(Error::UploadFailed {
            host: host.destination(),
            exit_code: output.exit_code,
            stderr,
        })
    }

    fn sftp_spec(&self, host: &HostSpec, batch_arg: &str) -> CommandSpec {
        CommandSpec::new(self.sftp_program.clone())
            .arg("-o")
            .arg(BATCH_MODE_OPTION)
            .arg("-o")
            .arg(self.host_key_policy.ssh_option())
            .arg("-b")
            .arg(batch_arg)
            .arg(host.destination())
            .stdin_null(true)
            .redact(true)
    }
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

fn scrub_upload_stderr(spec: &CommandSpec, stderr: &str, local: &str, remote: &str) -> String {
    let masked = mask_value(stderr, remote);
    let masked = mask_value(&masked, local);
    scrub_stderr(spec, &masked)
}

fn mask_value(text: &str, value: &str) -> String {
    if value.chars().count() < MIN_SUBSTRING_SCRUB_LEN {
        text.to_owned()
    } else {
        text.replace(value, "***")
    }
}

fn is_host_key_failure(output: &CommandOutput) -> bool {
    output.exit_code == Some(SFTP_FATAL_EXIT_CODE)
        && output
            .stderr
            .to_ascii_lowercase()
            .contains(HOST_KEY_FAILURE_SIGNATURE)
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
            &obs[0].spec.args[..5],
            [
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-b"
            ]
        );
        assert_eq!(obs[0].spec.args[6], "root@203.0.113.10");
        assert_eq!(obs[0].spec.args.len(), 7);
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
}
