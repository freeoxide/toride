//! SSH-forwarding adapter for [`toride_runner::Runner`].
//!
//! [`SshRunner`] turns any subsystem that accepts an injected
//! `toride_runner::Runner` (toride-harden, toride-service) into a remote
//! driver: each local `program args` spec is executed on the fixed
//! [`HostSpec`] through [`ExecService`], with the same argv validation,
//! host-key policy, and scrubbed diagnostics. A spec is refused with a
//! typed error when it asks for something the remote side cannot honor
//! (environment changes, stdin payloads, a working directory).
//!
//! Per-spec timeouts are not forwarded: one shared [`ExecService`] serves
//! every call (so the ssh presence probe runs once), and the wall-clock
//! cap is whatever was configured on the adapter through
//! [`SshRunner::with_timeout`].

use toride_runner::CommandOutput;
use toride_runner::CommandSpec;

use crate::Error;
use crate::ExecService;
use crate::HostKeyPolicy;
use crate::HostSpec;

/// Forwards local command specs to a remote host over `ssh`.
///
/// Implements [`toride_runner::Runner`], so it can be injected anywhere a
/// plain runner is accepted:
///
/// ```
/// use toride_runner::fake::FakeRunner;
/// use toride_runner::{CommandSpec, Runner};
/// use toride_ssh_core::HostSpec;
/// use toride_ssh_exec::SshRunner;
///
/// let fake = FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(""));
/// let adapter = SshRunner::new(Box::new(fake), HostSpec::parse("root@203.0.113.10").unwrap());
/// let output = adapter.run(&CommandSpec::new("ufw").arg("status"))?;
/// # Ok::<(), toride_runner::Error>(())
/// ```
///
/// # Refused specs
///
/// A spec carrying `env` entries, `env_remove`, `clear_env`, `stdin` or
/// `stdin_bytes` payloads, or a `cwd` cannot be expressed on the remote
/// side; [`Runner::run`](toride_runner::Runner::run) refuses it with
/// [`toride_runner::Error::Other`] naming the offending field, and no ssh
/// process spawns. `stdin_null` is accepted (ssh reads no stdin either
/// way), and per-spec `timeout` values are ignored in favor of the
/// adapter-level [`SshRunner::with_timeout`] cap.
pub struct SshRunner {
    host: HostSpec,
    service: ExecService,
}

impl SshRunner {
    /// Forward every spec to `host`, running `ssh` locally through
    /// `runner` with [`HostKeyPolicy::Strict`].
    #[must_use]
    pub fn new(runner: Box<dyn toride_runner::Runner>, host: HostSpec) -> Self {
        Self {
            host,
            service: ExecService::new(runner),
        }
    }

    /// Override the host-key checking posture of every forwarded command.
    #[must_use]
    pub fn with_host_key_policy(mut self, policy: HostKeyPolicy) -> Self {
        self.service = self.service.with_host_key_policy(policy);
        self
    }

    /// Override the ssh program used for every forwarded command.
    #[must_use]
    pub fn with_ssh_program(mut self, program: impl Into<String>) -> Self {
        self.service = self.service.with_ssh_program(program);
        self
    }

    /// Override the `-o ConnectTimeout` cap of every forwarded command.
    #[must_use]
    pub fn with_connect_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.service = self.service.with_connect_timeout(timeout);
        self
    }

    /// Set the wall-clock cap applied to every forwarded command. When
    /// unset, the local runner's own default applies (60 s for the default
    /// Duct and Tokio runners).
    #[must_use]
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.service = self.service.with_timeout(timeout);
        self
    }

    /// The fixed destination every spec is forwarded to.
    #[must_use]
    pub fn host(&self) -> &HostSpec {
        &self.host
    }
}

impl toride_runner::Runner for SshRunner {
    fn run(&self, spec: &CommandSpec) -> toride_runner::Result<CommandOutput> {
        reject_unforwardable(spec)?;
        let mut command = Vec::with_capacity(spec.args.len() + 1);
        command.push(spec.program.as_str());
        command.extend(spec.args.iter().map(String::as_str));
        self.service.run(&self.host, &command).map_err(encode_error)
    }
}

fn reject_unforwardable(spec: &CommandSpec) -> toride_runner::Result<()> {
    let refusal = |field: &str| {
        Err(toride_runner::Error::Other(format!(
            "spec cannot be forwarded over ssh: {field} has no remote meaning here"
        )))
    };
    if !spec.env.is_empty() {
        return refusal("env");
    }
    if !spec.env_remove.is_empty() {
        return refusal("env_remove");
    }
    if spec.clear_env {
        return refusal("clear_env");
    }
    if spec.stdin.is_some() {
        return refusal("stdin");
    }
    if spec.stdin_bytes.is_some() {
        return refusal("stdin_bytes");
    }
    if spec.cwd.is_some() {
        return refusal("cwd");
    }
    Ok(())
}

fn encode_error(error: Error) -> toride_runner::Error {
    match error {
        Error::Runner(inner) => inner,
        other => toride_runner::Error::Other(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use toride_runner::Runner as _;
    use toride_runner::fake::FakeRunner;

    fn host() -> HostSpec {
        HostSpec::parse("root@203.0.113.10").unwrap()
    }

    fn adapter(fake: &FakeRunner) -> SshRunner {
        SshRunner::new(Box::new(fake.clone()), host())
    }

    #[test]
    fn forwards_program_and_args_as_the_remote_argv() {
        let fake = FakeRunner::new().push_response(CommandOutput::from_stdout("Status: active"));
        let runner = adapter(&fake);

        let output = runner
            .run(&CommandSpec::new("ufw").arg("status").arg("verbose"))
            .unwrap();

        assert_eq!(output.stdout, "Status: active");
        let calls = fake.calls();
        assert_eq!(calls.len(), 1, "one ssh process per forwarded spec");
        assert_eq!(calls[0].program, "ssh");
        let destination = calls[0]
            .args
            .iter()
            .position(|arg| arg == "root@203.0.113.10")
            .expect("the destination operand must be present");
        assert_eq!(
            calls[0].args[destination + 1..],
            ["ufw", "status", "verbose"],
            "the local program and args become the remote argv tail"
        );
    }

    #[test]
    fn forwarded_argv_keeps_the_strict_host_key_options() {
        let fake = FakeRunner::new().push_response(CommandOutput::from_stdout(""));
        let runner = adapter(&fake);

        runner.run(&CommandSpec::new("uptime")).unwrap();

        let args = &fake.calls()[0].args;
        assert!(args.contains(&"BatchMode=yes".to_owned()), "{args:?}");
        assert!(
            args.contains(&"StrictHostKeyChecking=yes".to_owned()),
            "{args:?}"
        );
        assert!(args.contains(&"ConnectTimeout=10".to_owned()), "{args:?}");
    }

    #[test]
    fn with_host_key_policy_reaches_the_forwarded_spec() {
        let fake = FakeRunner::new().push_response(CommandOutput::from_stdout(""));
        let runner = SshRunner::new(Box::new(fake.clone()), host())
            .with_host_key_policy(HostKeyPolicy::AcceptNew);

        runner.run(&CommandSpec::new("uptime")).unwrap();

        let args = &fake.calls()[0].args;
        assert!(
            args.contains(&"StrictHostKeyChecking=accept-new".to_owned()),
            "{args:?}"
        );
    }

    #[test]
    fn with_timeout_caps_the_forwarded_spec() {
        let fake = FakeRunner::new().push_response(CommandOutput::from_stdout(""));
        let runner = SshRunner::new(Box::new(fake.clone()), host())
            .with_timeout(std::time::Duration::from_secs(120));

        runner.run(&CommandSpec::new("uptime")).unwrap();

        assert_eq!(
            fake.calls()[0].timeout,
            Some(std::time::Duration::from_secs(120)),
            "the adapter-level cap must land on the ssh spec"
        );
    }

    fn assert_refused(fake: &FakeRunner, spec: &CommandSpec, field: &str) {
        let runner = adapter(fake);
        match runner.run(spec) {
            Err(toride_runner::Error::Other(message)) => {
                assert!(message.contains(field), "{field} must be named: {message}");
            }
            other => panic!("{field}: expected Error::Other refusal, got {other:?}"),
        }
        assert!(fake.calls().is_empty(), "a refused spec must not spawn ssh");
    }

    #[test]
    fn refuses_specs_the_remote_side_cannot_honor() {
        let fake = FakeRunner::new();
        assert_refused(&fake, &CommandSpec::new("ufw").env("LC_ALL", "C"), "env");
        let mut spec = CommandSpec::new("ufw");
        spec.env_remove.push("LANG".to_owned());
        assert_refused(&fake, &spec, "env_remove");
        let mut spec = CommandSpec::new("ufw");
        spec.clear_env = true;
        assert_refused(&fake, &spec, "clear_env");
        assert_refused(&fake, &CommandSpec::new("ufw").stdin("payload"), "stdin");
        let mut spec = CommandSpec::new("ufw");
        spec.stdin_bytes = Some(vec![0]);
        assert_refused(&fake, &spec, "stdin_bytes");
        let mut spec = CommandSpec::new("ufw");
        spec.cwd = Some(std::path::PathBuf::from("/etc"));
        assert_refused(&fake, &spec, "cwd");
    }

    #[test]
    fn stdin_null_specs_are_accepted() {
        let fake = FakeRunner::new().push_response(CommandOutput::from_stdout(""));
        let runner = adapter(&fake);

        runner
            .run(&CommandSpec::new("uptime").stdin_null(true))
            .unwrap();

        assert_eq!(fake.calls().len(), 1);
    }

    #[test]
    fn remote_failure_maps_to_a_scrubbed_runner_error() {
        let fake = FakeRunner::new().push_response(CommandOutput::from_stderr(
            "ERROR: could not establish a connection\n",
            1,
        ));
        let runner = adapter(&fake);

        let err = runner
            .run(&CommandSpec::new("ufw").arg("enable"))
            .unwrap_err();

        assert!(
            err.to_string().contains("could not establish a connection"),
            "the scrubbed remote stderr must surface: {err}"
        );
        assert!(
            !err.to_string().contains("ufw enable"),
            "the remote argv must not leak into the mapped error: {err}"
        );
    }

    #[test]
    fn local_runner_errors_propagate_unchanged() {
        let fake = FakeRunner::new().push_result(Err(toride_runner::Error::SpawnFailed {
            program: "ssh".to_owned(),
            detail: "exec format error".to_owned(),
        }));
        let runner = adapter(&fake);

        assert!(matches!(
            runner.run(&CommandSpec::new("uptime")).unwrap_err(),
            toride_runner::Error::SpawnFailed { .. }
        ));
    }

    #[test]
    fn run_checked_reports_non_zero_remote_exits() {
        let fake = FakeRunner::new().push_response(CommandOutput::from_stderr("denied\n", 1));
        let runner = adapter(&fake);

        assert!(runner.run_checked(&CommandSpec::new("ufw")).is_err());
    }
}
