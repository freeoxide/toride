//! Fake [`Runner`] and [`AsyncRunner`] implementation for testing.
//!
//! [`FakeRunner`] returns pre-configured responses in FIFO order and
//! records all calls for later inspection. It supports two modes:
//!
//! - **Lenient** (default): unmatched calls return a successful empty output.
//! - **Strict**: unmatched calls return an error.

use std::sync::{Arc, Mutex};

use crate::error::{Error, Result};
use crate::output::CommandOutput;
use crate::runner::Runner;
use crate::spec::CommandSpec;

#[cfg(feature = "tokio-runner")]
use crate::async_runner::AsyncRunner;

/// A pre-configured response for a specific [`CommandSpec`].
#[derive(Debug, Clone)]
struct ExactResponse {
    /// The spec to match against.
    spec: CommandSpec,
    /// The result to return when matched.
    result: Result<CommandOutput>,
}

/// A [`Runner`] that returns canned responses for testing.
///
/// Responses are consumed in FIFO order. If more calls are made than
/// responses have been pushed, the last response is reused.
///
/// # Modes
///
/// - **Lenient** (default): unmatched calls return a successful empty output.
/// - **Strict**: unmatched calls return [`Error::Other`].
///
/// # Examples
///
/// ## Basic FIFO usage
///
/// ```rust
/// use toride_runner::{CommandOutput, CommandSpec, Runner};
/// use toride_runner::fake::FakeRunner;
///
/// let runner = FakeRunner::new()
///     .push_response(CommandOutput::from_stdout("ok"));
///
/// let spec = CommandSpec::new("echo").arg("hello");
/// let output = runner.run(&spec).unwrap();
/// assert_eq!(output.stdout_trimmed(), "ok");
/// ```
///
/// ## Strict mode with exact matching
///
/// ```rust
/// use toride_runner::{CommandOutput, CommandSpec, Runner};
/// use toride_runner::fake::FakeRunner;
///
/// let runner = FakeRunner::new()
///     .strict()
///     .respond(
///         CommandSpec::new("mise").args(["ls", "--json"]),
///         CommandOutput::from_stdout("[]"),
///     );
///
/// let spec = CommandSpec::new("mise").args(["ls", "--json"]);
/// let output = runner.run(&spec).unwrap();
/// assert_eq!(output.stdout_trimmed(), "[]");
/// ```
pub struct FakeRunner {
    /// FIFO response queue (used when no exact match is found).
    responses: Arc<Mutex<Vec<Result<CommandOutput>>>>,
    /// Exact-match responses keyed by spec.
    exact_responses: Arc<Mutex<Vec<ExactResponse>>>,
    /// All calls recorded for later inspection.
    calls: Arc<Mutex<Vec<CommandSpec>>>,
    /// Whether to error on unmatched calls instead of returning empty success.
    strict: bool,
}

impl FakeRunner {
    /// Create a new `FakeRunner` in lenient mode with no responses configured.
    #[must_use]
    pub fn new() -> Self {
        Self {
            responses: Arc::new(Mutex::new(Vec::new())),
            exact_responses: Arc::new(Mutex::new(Vec::new())),
            calls: Arc::new(Mutex::new(Vec::new())),
            strict: false,
        }
    }

    /// Enable strict mode: unmatched calls return an error.
    #[must_use]
    pub fn strict(mut self) -> Self {
        self.strict = true;
        self
    }

    /// Add a successful response to the FIFO queue.
    #[must_use]
    pub fn push_response(self, output: CommandOutput) -> Self {
        self.responses
            .lock()
            .expect("responses lock")
            .push(Ok(output));
        self
    }

    /// Add a result (success or error) to the FIFO queue.
    #[must_use]
    pub fn push_result(self, result: Result<CommandOutput>) -> Self {
        self.responses.lock().expect("responses lock").push(result);
        self
    }

    /// Register an exact-match response for a specific [`CommandSpec`].
    ///
    /// When a call matches the spec, this response takes priority over the
    /// FIFO queue. Matching compares `program`, `args`, `stdin`, `env`, and
    /// `cwd`.
    #[must_use]
    pub fn respond(self, spec: CommandSpec, output: CommandOutput) -> Self {
        self.exact_responses
            .lock()
            .expect("exact_responses lock")
            .push(ExactResponse {
                spec,
                result: Ok(output),
            });
        self
    }

    /// Register an exact-match error for a specific [`CommandSpec`].
    ///
    /// Useful for testing error-handling paths such as spawn failures,
    /// timeouts, or permission errors.
    #[must_use]
    pub fn respond_err(self, spec: CommandSpec, error: Error) -> Self {
        self.exact_responses
            .lock()
            .expect("exact_responses lock")
            .push(ExactResponse {
                spec,
                result: Err(error),
            });
        self
    }

    /// Return a snapshot of all calls made to this runner.
    pub fn calls(&self) -> Vec<CommandSpec> {
        self.calls.lock().expect("calls lock").clone()
    }

    /// Assert that the runner received a call matching the given spec.
    ///
    /// # Panics
    ///
    /// Panics if no matching call is found.
    pub fn assert_called_with(&self, expected: &CommandSpec) {
        let calls = self.calls();
        let found = calls.iter().any(|c| specs_match(c, expected));
        assert!(
            found,
            "expected call to {:?} but no matching call found.\n\
             Actual calls: {:?}",
            expected, calls
        );
    }

    /// Assert that all pushed FIFO responses were consumed.
    ///
    /// # Panics
    ///
    /// Panics if there are unconsumed responses remaining.
    pub fn assert_no_unmatched_calls(&self) {
        let remaining = self.responses.lock().expect("responses lock").len();
        assert_eq!(
            remaining, 0,
            "expected all FIFO responses to be consumed, but {remaining} remain"
        );
    }

    /// Try to find an exact-match response for the given spec.
    fn find_exact_response(&self, spec: &CommandSpec) -> Option<Result<CommandOutput>> {
        let mut exact = self.exact_responses.lock().expect("exact_responses lock");
        for (i, resp) in exact.iter().enumerate() {
            if specs_match(&resp.spec, spec) {
                return Some(exact.remove(i).result);
            }
        }
        None
    }

    /// Get the next FIFO response, or a default.
    fn next_fifo_response(&self) -> Result<CommandOutput> {
        let mut responses = self.responses.lock().expect("responses lock");
        if responses.is_empty() {
            if self.strict {
                return Err(Error::Other(format!(
                    "FakeRunner (strict): no response configured for call"
                )));
            }
            return Ok(CommandOutput::from_stdout(String::new()));
        }
        if responses.len() == 1 {
            return responses.first().expect("just checked").clone();
        }
        responses.remove(0)
    }
}

impl Default for FakeRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl Runner for FakeRunner {
    fn run(&self, spec: &CommandSpec) -> Result<CommandOutput> {
        // Record the call.
        self.calls.lock().expect("calls lock").push(spec.clone());

        // Check exact-match responses first.
        if let Some(result) = self.find_exact_response(spec) {
            return result;
        }

        // Fall back to FIFO queue.
        self.next_fifo_response()
    }
}

#[cfg(feature = "tokio-runner")]
#[async_trait::async_trait]
impl AsyncRunner for FakeRunner {
    async fn run(&self, spec: &CommandSpec) -> Result<CommandOutput> {
        // Delegate to the sync impl — FakeRunner is in-memory, no real I/O.
        Runner::run(self, spec)
    }
}

/// Check if two specs match on the fields used for exact matching.
///
/// Compares `program`, `args`, `stdin`, `env`, and `cwd`.
/// Timeout is ignored by default — it is a runtime concern, not
/// a command-construction concern.
fn specs_match(a: &CommandSpec, b: &CommandSpec) -> bool {
    a.program == b.program
        && a.args == b.args
        && a.stdin == b.stdin
        && a.env == b.env
        && a.cwd == b.cwd
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to call the sync Runner::run without ambiguity when both
    /// Runner and AsyncRunner are in scope.
    fn run_sync(runner: &FakeRunner, spec: &CommandSpec) -> Result<CommandOutput> {
        Runner::run(runner, spec)
    }

    #[test]
    fn returns_pushed_response() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout("first"));
        let output = run_sync(&runner, &CommandSpec::new("cmd")).unwrap();
        assert_eq!(output.stdout_trimmed(), "first");
    }

    #[test]
    fn records_calls() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout("ok"));
        let _ = run_sync(&runner, &CommandSpec::new("a").arg("1"));
        let _ = run_sync(&runner, &CommandSpec::new("b").arg("2"));

        let calls = runner.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].program, "a");
        assert_eq!(calls[1].program, "b");
    }

    #[test]
    fn fifo_ordering() {
        let runner = FakeRunner::new()
            .push_response(CommandOutput::from_stdout("1"))
            .push_response(CommandOutput::from_stdout("2"));

        let o1 = run_sync(&runner, &CommandSpec::new("cmd")).unwrap();
        let o2 = run_sync(&runner, &CommandSpec::new("cmd")).unwrap();
        assert_eq!(o1.stdout_trimmed(), "1");
        assert_eq!(o2.stdout_trimmed(), "2");
    }

    #[test]
    fn default_response_when_empty() {
        let runner = FakeRunner::new();
        let output = run_sync(&runner, &CommandSpec::new("cmd")).unwrap();
        assert!(output.success);
        assert!(output.stdout.is_empty());
    }

    #[test]
    fn single_response_reused() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout("only"));
        let _ = run_sync(&runner, &CommandSpec::new("a"));
        let _ = run_sync(&runner, &CommandSpec::new("b"));
        let _ = run_sync(&runner, &CommandSpec::new("c"));
        // Single response is reused, not consumed.
        assert_eq!(runner.calls().len(), 3);
    }

    #[test]
    fn strict_mode_errors_on_unmatched() {
        let runner = FakeRunner::new().strict();
        let result = run_sync(&runner, &CommandSpec::new("cmd"));
        assert!(result.is_err());
    }

    #[test]
    fn exact_match_response() {
        let runner = FakeRunner::new().respond(
            CommandSpec::new("mise").args(["ls", "--json"]),
            CommandOutput::from_stdout("[]"),
        );

        let output = run_sync(&runner, &CommandSpec::new("mise").args(["ls", "--json"])).unwrap();
        assert_eq!(output.stdout_trimmed(), "[]");
    }

    #[test]
    fn exact_match_error_response() {
        let runner = FakeRunner::new().respond_err(
            CommandSpec::new("bad-cmd"),
            Error::BinaryNotFound("bad-cmd".into()),
        );

        let result = run_sync(&runner, &CommandSpec::new("bad-cmd"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, Error::BinaryNotFound(_)));
    }

    #[test]
    fn exact_match_takes_priority_over_fifo() {
        let runner = FakeRunner::new()
            .push_response(CommandOutput::from_stdout("fifo"))
            .respond(
                CommandSpec::new("exact").arg("match"),
                CommandOutput::from_stdout("exact"),
            );

        // Exact match should take priority.
        let output = run_sync(&runner, &CommandSpec::new("exact").arg("match")).unwrap();
        assert_eq!(output.stdout_trimmed(), "exact");

        // Non-matching call should get FIFO response.
        let output = run_sync(&runner, &CommandSpec::new("other")).unwrap();
        assert_eq!(output.stdout_trimmed(), "fifo");
    }

    #[test]
    fn assert_called_with_passes() {
        let runner = FakeRunner::new().strict().respond(
            CommandSpec::new("mise").args(["install", "node"]),
            CommandOutput::from_stdout("installed"),
        );

        let _ = run_sync(&runner, &CommandSpec::new("mise").args(["install", "node"]));
        runner.assert_called_with(&CommandSpec::new("mise").args(["install", "node"]));
    }

    #[test]
    #[should_panic(expected = "expected call to")]
    fn assert_called_with_panics_on_mismatch() {
        let runner = FakeRunner::new().strict().respond(
            CommandSpec::new("mise").args(["install", "node"]),
            CommandOutput::from_stdout("installed"),
        );

        let _ = run_sync(&runner, &CommandSpec::new("mise").args(["install", "node"]));
        runner.assert_called_with(&CommandSpec::new("mise").args(["install", "python"]));
    }

    #[test]
    fn push_result_error() {
        let runner = FakeRunner::new().push_result(Err(Error::CommandTimeout {
            program: "slow".into(),
            args: vec![],
            timeout: std::time::Duration::from_secs(5),
        }));

        let result = run_sync(&runner, &CommandSpec::new("slow"));
        assert!(result.is_err());
    }

    #[test]
    fn exact_match_consumed_once() {
        let runner = FakeRunner::new().strict().respond(
            CommandSpec::new("once"),
            CommandOutput::from_stdout("first"),
        );

        // First call matches and consumes the exact response.
        let o1 = run_sync(&runner, &CommandSpec::new("once")).unwrap();
        assert_eq!(o1.stdout_trimmed(), "first");

        // Second call with same spec should fail in strict mode (no more exact matches).
        let result = run_sync(&runner, &CommandSpec::new("once"));
        assert!(result.is_err());
    }

    #[test]
    fn specs_match_compares_cwd() {
        let runner = FakeRunner::new().strict().respond(
            CommandSpec::new("make").cwd("/project"),
            CommandOutput::from_stdout("built"),
        );

        // Without cwd, should not match.
        let result = run_sync(&runner, &CommandSpec::new("make"));
        assert!(result.is_err());

        // With matching cwd, should match.
        let output = run_sync(&runner, &CommandSpec::new("make").cwd("/project")).unwrap();
        assert_eq!(output.stdout_trimmed(), "built");
    }

    #[cfg(feature = "tokio-runner")]
    mod async_tests {
        use super::*;

        #[tokio::test]
        async fn async_run_delegates_to_sync() {
            let runner = FakeRunner::new().push_response(CommandOutput::from_stdout("async-ok"));
            let output = AsyncRunner::run(&runner, &CommandSpec::new("cmd"))
                .await
                .unwrap();
            assert_eq!(output.stdout_trimmed(), "async-ok");
        }

        #[tokio::test]
        async fn async_run_checked_errors_on_failure() {
            let runner = FakeRunner::new().push_response(CommandOutput::from_stderr("nope", 1));
            let result = AsyncRunner::run_checked(&runner, &CommandSpec::new("fail")).await;
            assert!(result.is_err());
        }
    }
}
