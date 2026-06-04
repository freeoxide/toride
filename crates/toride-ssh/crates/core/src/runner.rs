//! Thin helpers for running external SSH tools via `duct`.
//!
//! These wrap the few operations that require shelling out:
//! FIDO key generation, `ssh-keyscan`, `ssh-copy-id`, passphrase changes, etc.
//! All calls go through `tokio::task::spawn_blocking` to avoid blocking the
//! async runtime.
//!
//! The [`CliRunner`] trait abstracts over command execution for testability.
//! Production code uses [`DefaultCliRunner`] which delegates to
//! [`toride_runner::TokioRunner`]; tests swap in [`MockCliRunner`].

use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::Mutex;

use async_trait::async_trait;
use toride_runner::AsyncRunner;
use toride_runner::CommandSpec;
use toride_runner::tokio_runner::TokioRunner;

use crate::{Error, Result};

// ---------------------------------------------------------------------------
// Duct-based helpers
// ---------------------------------------------------------------------------

/// Run an external command via `tokio::task::spawn_blocking`.
async fn run_tool(cmd: &str, args: Vec<String>) -> Result<String> {
    let cmd = cmd.to_owned();
    tokio::task::spawn_blocking(move || {
        duct::cmd(&*cmd, &args)
            .read()
            .map_err(|e| Error::CommandFailed(e.to_string()))
    })
    .await
    .map_err(|e| Error::TaskFailed(e.to_string()))?
}

/// Run `ssh-keygen` with the given arguments and return stdout.
///
/// # Errors
///
/// Returns [`Error::ToolNotFound`] if `ssh-keygen` is not in `PATH`,
/// [`Error::CommandFailed`] if the command exits with a non-zero status,
/// or [`Error::TaskFailed`] if the background task panics.
pub async fn ssh_keygen(args: &[&str]) -> Result<String> {
    run_tool("ssh-keygen", args.iter().map(|s| (*s).to_owned()).collect()).await
}

/// Run `ssh-keyscan -H <host>` and return the host key lines.
///
/// The `-H` flag hashes hostnames in the output for privacy.
///
/// # Errors
///
/// Returns [`Error::CommandFailed`] if the scan fails, or
/// [`Error::TaskFailed`] if the background task panics.
pub async fn ssh_keyscan(host: &str) -> Result<String> {
    run_tool("ssh-keyscan", vec!["-H".into(), host.to_owned()]).await
}

/// Run `ssh-keyscan <host>` (without `-H`) and return the host key lines.
///
/// Hostnames appear in plaintext in the output, which is useful when the
/// caller wants to display or inspect the keys before deciding whether to
/// add them to `known_hosts`.
///
/// # Errors
///
/// Returns [`Error::CommandFailed`] if the scan fails, or
/// [`Error::TaskFailed`] if the background task panics.
pub async fn ssh_keyscan_no_hash(host: &str) -> Result<String> {
    run_tool("ssh-keyscan", vec![host.to_owned()]).await
}

/// Run `ssh-add -l` to list agent identities.
///
/// # Errors
///
/// Returns [`Error::CommandFailed`] if the command fails (e.g. agent not
/// running), or [`Error::TaskFailed`] if the background task panics.
pub async fn ssh_add_list() -> Result<String> {
    run_tool("ssh-add", vec!["-l".into()]).await
}

/// Run `ssh-copy-id -i <pubkey> <dest>`.
///
/// # Errors
///
/// Returns [`Error::CommandFailed`] if the copy fails (e.g. authentication
/// denied), or [`Error::TaskFailed`] if the background task panics.
pub async fn ssh_copy_id(pubkey: &Path, dest: &str) -> Result<String> {
    let pubkey_str = pubkey.to_str().ok_or_else(|| {
        Error::CommandFailed(format!(
            "public key path is not valid UTF-8: {}",
            pubkey.display()
        ))
    })?;
    run_tool("ssh-copy-id", vec!["-i".into(), pubkey_str.to_owned(), dest.to_owned()]).await
}

/// Check whether a tool exists in `PATH`.
pub fn tool_exists(name: &str) -> bool {
    which::which(name).is_ok()
}

// ---------------------------------------------------------------------------
// CliRunner trait
// ---------------------------------------------------------------------------

/// Abstraction over external command execution.
///
/// Production code uses [`DefaultCliRunner`]; tests swap in [`MockCliRunner`].
#[async_trait]
pub trait CliRunner: Send + Sync {
    /// Run an external command and return its captured stdout.
    ///
    /// Implementations MUST forward the call through
    /// `tokio::task::spawn_blocking` (or equivalent) so that the async
    /// runtime is never blocked.
    async fn run(&self, cmd: &str, args: Vec<String>) -> Result<String>;

    /// Run an external command with additional environment variables and
    /// return its captured stdout.
    ///
    /// Entries in `env` are added to the inherited environment of the
    /// current process. This is used, for example, to pass `SSH_ASKPASS`
    /// when loading passphrase-protected keys.
    ///
    /// Implementations MUST forward the call through
    /// `tokio::task::spawn_blocking` (or equivalent) so that the async
    /// runtime is never blocked.
    async fn run_with_env(
        &self,
        cmd: &str,
        args: Vec<String>,
        env: Vec<(String, String)>,
    ) -> Result<String>;

    /// Return `true` when the given tool is available on `PATH`.
    fn tool_exists(&self, name: &str) -> bool;
}

// ---------------------------------------------------------------------------
// DefaultCliRunner  (production – delegates to `toride_runner::TokioRunner`)
// ---------------------------------------------------------------------------

/// Production [`CliRunner`] that delegates to [`TokioRunner`] from
/// `toride-runner`, which uses `tokio::process` internally.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultCliRunner;

#[async_trait]
impl CliRunner for DefaultCliRunner {
    async fn run(&self, cmd: &str, args: Vec<String>) -> Result<String> {
        let spec = CommandSpec::new(cmd).args(args);
        let runner = TokioRunner;
        let output = runner.run(&spec).await.map_err(|e| Error::CommandFailed(e.to_string()))?;
        if !output.success {
            return Err(Error::CommandFailed(format!(
                "command `{cmd}` failed with exit {:?}: {}",
                output.exit_code,
                output.stderr.trim()
            )));
        }
        Ok(output.stdout)
    }

    async fn run_with_env(
        &self,
        cmd: &str,
        args: Vec<String>,
        env: Vec<(String, String)>,
    ) -> Result<String> {
        let spec = CommandSpec::new(cmd).args(args).envs(env);
        let runner = TokioRunner;
        let output = runner.run(&spec).await.map_err(|e| Error::CommandFailed(e.to_string()))?;
        if !output.success {
            return Err(Error::CommandFailed(format!(
                "command `{cmd}` failed with exit {:?}: {}",
                output.exit_code,
                output.stderr.trim()
            )));
        }
        Ok(output.stdout)
    }

    fn tool_exists(&self, name: &str) -> bool {
        which::which(name).is_ok()
    }
}

// ---------------------------------------------------------------------------
// MockCliRunner  (test double)
// ---------------------------------------------------------------------------

/// A canned-response [`CliRunner`] for unit tests.
///
/// Register per-command responses before exercising the code under test:
///
/// ```rust,ignore
/// use toride_ssh_core::runner::MockCliRunner;
///
/// let mock = MockCliRunner::new();
/// mock.push_run_response("ssh-keygen", Ok("key generated".into()));
/// mock.set_tool_exists("ssh-keygen", true);
/// ```
pub struct MockCliRunner {
    /// Ordered responses keyed by command name.
    run_responses: Mutex<HashMap<String, VecDeque<Result<String>>>>,
    /// Fixed answers for [`CliRunner::tool_exists`].
    tool_exists_responses: Mutex<HashMap<String, bool>>,
}

impl MockCliRunner {
    /// Create an empty mock (all calls will return errors by default).
    pub fn new() -> Self {
        Self {
            run_responses: Mutex::new(HashMap::new()),
            tool_exists_responses: Mutex::new(HashMap::new()),
        }
    }

    /// Enqueue a response for the given command name.
    ///
    /// Responses are returned in FIFO order.  If the queue for `cmd` is
    /// exhausted the mock returns [`Error::CommandFailed`].
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn push_run_response(&self, cmd: &str, result: Result<String>) {
        self.run_responses
            .lock()
            .expect("mock lock poisoned")
            .entry(cmd.to_owned())
            .or_default()
            .push_back(result);
    }

    /// Set whether [`CliRunner::tool_exists`] should return `true` or `false`
    /// for the given tool name.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn set_tool_exists(&self, name: &str, exists: bool) {
        self.tool_exists_responses
            .lock()
            .expect("mock lock poisoned")
            .insert(name.to_owned(), exists);
    }
}

impl Default for MockCliRunner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CliRunner for MockCliRunner {
    async fn run(&self, cmd: &str, _args: Vec<String>) -> Result<String> {
        let mut map = self.run_responses.lock().expect("mock lock poisoned");
        let queue = map.get_mut(cmd);
        match queue.and_then(VecDeque::pop_front) {
            Some(result) => result,
            None => Err(Error::CommandFailed(format!(
                "mock: no response registered for `{cmd}`"
            ))),
        }
    }

    async fn run_with_env(
        &self,
        cmd: &str,
        _args: Vec<String>,
        _env: Vec<(String, String)>,
    ) -> Result<String> {
        // Mock ignores env vars — only the command name matters for
        // dispatching canned responses.
        let mut map = self.run_responses.lock().expect("mock lock poisoned");
        let queue = map.get_mut(cmd);
        match queue.and_then(VecDeque::pop_front) {
            Some(result) => result,
            None => Err(Error::CommandFailed(format!(
                "mock: no response registered for `{cmd}`"
            ))),
        }
    }

    fn tool_exists(&self, name: &str) -> bool {
        *self
            .tool_exists_responses
            .lock()
            .expect("mock lock poisoned")
            .get(name)
            .unwrap_or(&false)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_run_returns_enqueued_responses_in_order() {
        let mock = MockCliRunner::new();
        mock.push_run_response("ssh-keygen", Ok("line 1".into()));
        mock.push_run_response("ssh-keygen", Ok("line 2".into()));

        let r1 = mock
            .run("ssh-keygen", vec!["-t".into(), "ed25519".into()])
            .await
            .unwrap();
        assert_eq!(r1, "line 1");

        let r2 = mock
            .run("ssh-keygen", vec!["-t".into(), "rsa".into()])
            .await
            .unwrap();
        assert_eq!(r2, "line 2");
    }

    #[tokio::test]
    async fn mock_run_returns_error_when_queue_exhausted() {
        let mock = MockCliRunner::new();
        mock.push_run_response("ssh-keygen", Ok("ok".into()));

        // First call succeeds.
        let _ = mock.run("ssh-keygen", vec![]).await.unwrap();

        // Second call has no more enqueued responses.
        let err = mock.run("ssh-keygen", vec![]).await.unwrap_err();
        assert!(matches!(err, Error::CommandFailed(_)));
    }

    #[tokio::test]
    async fn mock_run_unregistered_command_errors() {
        let mock = MockCliRunner::new();
        let err = mock.run("unknown", vec![]).await.unwrap_err();
        assert!(matches!(err, Error::CommandFailed(_)));
    }

    #[test]
    fn mock_tool_exists_default_false() {
        let mock = MockCliRunner::new();
        assert!(!mock.tool_exists("ssh-keygen"));
    }

    #[test]
    fn mock_tool_exists_respects_configured_value() {
        let mock = MockCliRunner::new();
        mock.set_tool_exists("ssh-keygen", true);
        assert!(mock.tool_exists("ssh-keygen"));
        assert!(!mock.tool_exists("ssh-keyscan"));
    }

    #[tokio::test]
    async fn mock_ssh_add_t_key_usable() {
        let mock = MockCliRunner::new();
        mock.push_run_response("ssh-add", Ok("".into()));
        mock.set_tool_exists("ssh-add", true);

        assert!(mock.tool_exists("ssh-add"));
        let result = mock.run("ssh-add", vec!["-T".into(), "/path/to/key".into()]).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn mock_ssh_add_t_key_not_usable() {
        let mock = MockCliRunner::new();
        mock.push_run_response(
            "ssh-add",
            Err(crate::Error::CommandFailed("key not usable".into())),
        );

        let result = mock.run("ssh-add", vec!["-T".into(), "/path/to/key".into()]).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn mock_ssh_add_l_lists_keys() {
        let mock = MockCliRunner::new();
        mock.push_run_response(
            "ssh-add",
            Ok("256 SHA256:AAAA user@host (ED25519)\n4096 SHA256:BBBB server (RSA)\n".into()),
        );

        let result = mock.run("ssh-add", vec!["-l".into()]).await.unwrap();
        assert!(result.contains("SHA256:AAAA"));
        assert!(result.contains("SHA256:BBBB"));
        assert!(result.contains("ED25519"));
        assert!(result.contains("RSA"));
    }

    #[tokio::test]
    async fn mock_ssh_add_l_no_identities() {
        let mock = MockCliRunner::new();
        mock.push_run_response(
            "ssh-add",
            Ok("The agent has no identities\n".into()),
        );

        let result = mock.run("ssh-add", vec!["-l".into()]).await.unwrap();
        assert!(result.contains("no identities"));
    }

    #[test]
    fn mock_cli_runner_as_trait_object() {
        let mock = MockCliRunner::new();
        mock.set_tool_exists("ssh-keygen", true);
        mock.set_tool_exists("ssh-keyscan", true);
        mock.set_tool_exists("ssh-add", true);
        mock.set_tool_exists("ssh-copy-id", true);

        let runner: &dyn CliRunner = &mock;
        assert!(runner.tool_exists("ssh-keygen"));
        assert!(runner.tool_exists("ssh-keyscan"));
        assert!(runner.tool_exists("ssh-add"));
        assert!(runner.tool_exists("ssh-copy-id"));
        assert!(!runner.tool_exists("nonexistent-tool"));
    }

    #[tokio::test]
    async fn mock_runner_fifo_ordering() {
        let mock = MockCliRunner::new();
        mock.push_run_response("ssh", Ok("response-1".into()));
        mock.push_run_response("ssh", Ok("response-2".into()));
        mock.push_run_response("ssh", Ok("response-3".into()));

        assert_eq!(mock.run("ssh", vec![]).await.unwrap(), "response-1");
        assert_eq!(mock.run("ssh", vec![]).await.unwrap(), "response-2");
        assert_eq!(mock.run("ssh", vec![]).await.unwrap(), "response-3");
    }

    #[tokio::test]
    async fn mock_runner_independent_command_queues() {
        let mock = MockCliRunner::new();
        mock.push_run_response("ssh-keygen", Ok("keygen-ok".into()));
        mock.push_run_response("ssh-keyscan", Ok("keyscan-ok".into()));
        mock.push_run_response("ssh-keygen", Ok("keygen-ok-2".into()));

        assert_eq!(mock.run("ssh-keygen", vec![]).await.unwrap(), "keygen-ok");
        assert_eq!(mock.run("ssh-keyscan", vec![]).await.unwrap(), "keyscan-ok");
        assert_eq!(mock.run("ssh-keygen", vec![]).await.unwrap(), "keygen-ok-2");
    }

    #[test]
    fn mock_runner_multiple_tool_exists() {
        let mock = MockCliRunner::new();
        mock.set_tool_exists("ssh", true);
        mock.set_tool_exists("ssh-keygen", true);
        mock.set_tool_exists("ssh-keyscan", true);
        mock.set_tool_exists("ssh-add", true);
        mock.set_tool_exists("ssh-copy-id", false);
        mock.set_tool_exists("scp", true);

        assert!(mock.tool_exists("ssh"));
        assert!(mock.tool_exists("ssh-keygen"));
        assert!(mock.tool_exists("ssh-keyscan"));
        assert!(mock.tool_exists("ssh-add"));
        assert!(!mock.tool_exists("ssh-copy-id"));
        assert!(mock.tool_exists("scp"));
        assert!(!mock.tool_exists("rsync"));
    }

    #[tokio::test]
    async fn mock_runner_error_propagation() {
        let mock = MockCliRunner::new();
        mock.push_run_response(
            "ssh-keygen",
            Err(crate::Error::CommandFailed("permission denied".into())),
        );

        let err = mock.run("ssh-keygen", vec!["-t".into(), "ed25519".into()]).await.unwrap_err();
        match err {
            crate::Error::CommandFailed(msg) => assert!(msg.contains("permission denied")),
            other => panic!("expected CommandFailed, got: {other:?}"),
        }
    }
}
