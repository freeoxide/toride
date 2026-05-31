//! Trait abstraction for running external CLI tools.
//!
//! The [`CliRunner`] trait decouples the rest of the crate from the concrete
//! `duct`-based process spawning, making it straightforward to substitute a
//! mock in tests.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use async_trait::async_trait;

use crate::{Error, Result};

// ---------------------------------------------------------------------------
// Trait
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
// DefaultCliRunner  (production – wraps `duct`)
// ---------------------------------------------------------------------------

/// Production [`CliRunner`] that shells out via `duct` inside
/// `tokio::task::spawn_blocking`.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultCliRunner;

#[async_trait]
impl CliRunner for DefaultCliRunner {
    async fn run(&self, cmd: &str, args: Vec<String>) -> Result<String> {
        let cmd = cmd.to_owned();
        tokio::task::spawn_blocking(move || {
            duct::cmd(&*cmd, &args)
                .read()
                .map_err(|e| Error::CommandFailed(e.to_string()))
        })
        .await
        .map_err(|e| Error::TaskFailed(e.to_string()))?
    }

    async fn run_with_env(
        &self,
        cmd: &str,
        args: Vec<String>,
        env: Vec<(String, String)>,
    ) -> Result<String> {
        let cmd = cmd.to_owned();
        tokio::task::spawn_blocking(move || {
            let mut expression = duct::cmd(&*cmd, &args);
            for (key, value) in &env {
                expression = expression.env(key, value);
            }
            expression
                .read()
                .map_err(|e| Error::CommandFailed(e.to_string()))
        })
        .await
        .map_err(|e| Error::TaskFailed(e.to_string()))?
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
/// use toride_ssh::runner::cli_runner::MockCliRunner;
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

    // -----------------------------------------------------------------------
    // Agent key usability — ssh-add -T integration via mock
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn mock_ssh_add_t_key_usable() {
        // ssh-add -T tests whether a key can be used by the agent.
        // Exit code 0 means the key is usable.
        let mock = MockCliRunner::new();
        mock.push_run_response("ssh-add", Ok("".into()));
        mock.set_tool_exists("ssh-add", true);

        assert!(mock.tool_exists("ssh-add"));
        let result = mock.run("ssh-add", vec!["-T".into(), "/path/to/key".into()]).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn mock_ssh_add_t_key_not_usable() {
        // ssh-add -T returns non-zero when the key is not usable.
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

    // -----------------------------------------------------------------------
    // SshManager::with_cli_runner — mock injection through service layer
    // -----------------------------------------------------------------------

    #[test]
    fn mock_cli_runner_as_trait_object() {
        // MockCliRunner implements CliRunner and can be used wherever
        // a CliRunner is expected (service layer injection).
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
        // Verify that responses are returned in FIFO order per command.
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
        // Different commands have independent response queues.
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
        // Set multiple tools and verify each returns the configured value.
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
        assert!(!mock.tool_exists("rsync")); // not configured
    }

    #[tokio::test]
    async fn mock_runner_error_propagation() {
        // Errors from the mock should propagate correctly through the runner.
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
