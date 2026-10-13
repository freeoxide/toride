#![warn(missing_docs)]

//! `toride-ssh-exec` — remote command execution over `ssh`.
//!
//! [`ExecService`] runs an argv command on a validated [`HostSpec`] through a
//! [`Runner`](toride_runner::Runner), mirroring how
//! `toride_service::ServiceManager` wraps `systemctl`. The invocation is
//! argv-disciplined through [`CommandSpec`] — never a shell string — and every
//! command element is validated before any process spawns.
//!
//! # Example
//!
//! ```
//! use toride_runner::fake::FakeRunner;
//! use toride_ssh_core::HostSpec;
//! use toride_ssh_exec::{CommandOutput, ExecService};
//!
//! let fake = FakeRunner::new().push_response(CommandOutput::from_stdout("up 1 day\n"));
//! let service = ExecService::new(Box::new(fake));
//! let host = HostSpec::parse("root@203.0.113.10").unwrap();
//! let output = service.run(&host, &["uptime"]).unwrap();
//! assert!(output.success);
//! ```

pub use toride_runner::CommandOutput;
pub use toride_ssh_core::{HostKeyPolicy, HostSpec};

use std::time::Duration;

use toride_runner::CommandSpec;
use toride_runner::Runner;
use toride_runner::display::scrub_stderr;
use toride_runner::policy::contains_shell_metachars;

const DEFAULT_SSH_PROGRAM: &str = "ssh";
const BATCH_MODE_OPTION: &str = "BatchMode=yes";
const HOST_KEY_FAILURE_SIGNATURE: &str = "host key verification failed";
const SSH_FATAL_EXIT_CODE: i32 = 255;

/// Errors returned by [`ExecService`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A command element was rejected before any process spawned. The element
    /// is identified by position; its value is never echoed.
    #[error("remote command rejected at element {index}: {reason}")]
    InvalidRemoteCommand {
        /// Position of the offending element in the command slice.
        index: usize,
        /// Why the element was rejected; never contains the element itself.
        reason: String,
    },
    /// The remote command (or its ssh connection) exited non-zero for a
    /// non-host-key reason. Carries the scrubbed stderr, never the argv.
    #[error("remote command on {host} failed (exit {exit_code:?}): {stderr}")]
    RemoteCommandFailed {
        /// The validated destination the command ran against.
        host: String,
        /// The ssh exit code, `None` when terminated by a signal.
        exit_code: Option<i32>,
        /// The runner-scrubbed ssh stderr diagnostic.
        stderr: String,
    },
    /// Shared `toride-ssh-core` vocabulary: invalid host, host-key
    /// verification failure, or a missing ssh binary.
    #[error(transparent)]
    Core(#[from] toride_ssh_core::Error),
    /// The runner refused or failed to execute the ssh invocation itself.
    #[error(transparent)]
    Runner(#[from] toride_runner::Error),
}

/// Alias for results in this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Runs commands on remote hosts through `ssh` via a [`Runner`].
pub struct ExecService {
    runner: Box<dyn Runner>,
    host_key_policy: HostKeyPolicy,
    ssh_program: String,
    timeout: Option<Duration>,
}

impl ExecService {
    /// Create a service over the given runner with [`HostKeyPolicy::Strict`]
    /// and the `ssh` binary looked up on `PATH`.
    #[must_use]
    pub fn new(runner: Box<dyn Runner>) -> Self {
        Self {
            runner,
            host_key_policy: HostKeyPolicy::Strict,
            ssh_program: DEFAULT_SSH_PROGRAM.to_owned(),
            timeout: None,
        }
    }

    /// Override the host-key checking posture.
    #[must_use]
    pub fn with_host_key_policy(mut self, policy: HostKeyPolicy) -> Self {
        self.host_key_policy = policy;
        self
    }

    /// Override the ssh program used in invocations and its presence check.
    #[must_use]
    pub fn with_ssh_program(mut self, program: impl Into<String>) -> Self {
        self.ssh_program = program.into();
        self
    }

    /// Set a wall-clock cap applied to every invocation spec.
    ///
    /// Long deploys routinely exceed the 60 s fallback timeout a default
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

    /// The configured ssh program name.
    #[must_use]
    pub fn ssh_program(&self) -> &str {
        &self.ssh_program
    }

    /// The configured per-invocation timeout, if any.
    #[must_use]
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Run `command` on `host`, returning the captured output on ssh exit 0.
    ///
    /// The command is an argv slice; every element is validated (no shell
    /// metacharacters, control characters, or empty elements) before the ssh
    /// binary presence is checked and before any process spawns. There is no
    /// API taking a pre-joined command string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidRemoteCommand`] for a rejected element, [`Error::Core`] carrying
    /// [`toride_ssh_core::Error::ToolNotFound`] when the ssh binary is absent or
    /// [`toride_ssh_core::Error::HostKeyVerificationFailed`] when ssh exits 255 with the
    /// host-key verification signature in stderr, [`Error::RemoteCommandFailed`] for any other
    /// non-zero exit, and [`Error::Runner`] when the runner itself fails.
    pub fn run(&self, host: &HostSpec, command: &[&str]) -> Result<CommandOutput> {
        validate_command(command)?;
        if !toride_runner::discovery::binary_exists(&self.ssh_program) {
            return Err(Error::Core(toride_ssh_core::Error::ToolNotFound(
                self.ssh_program.clone(),
            )));
        }
        let spec = self.ssh_spec(host, command);
        let output = self.runner.run(&spec)?;
        if output.success {
            return Ok(output);
        }
        let stderr = scrub_stderr(&spec, &output.stderr);
        if is_host_key_failure(&output) {
            return Err(Error::Core(
                toride_ssh_core::Error::HostKeyVerificationFailed(stderr),
            ));
        }
        Err(Error::RemoteCommandFailed {
            host: host.destination(),
            exit_code: output.exit_code,
            stderr,
        })
    }

    fn ssh_spec(&self, host: &HostSpec, command: &[&str]) -> CommandSpec {
        let mut spec = CommandSpec::new(self.ssh_program.clone())
            .arg("-o")
            .arg(BATCH_MODE_OPTION)
            .arg("-o")
            .arg(self.host_key_policy.ssh_option())
            .arg(host.destination())
            .args(command.iter().copied())
            .stdin_null(true)
            .redact(true);
        if let Some(timeout) = self.timeout {
            spec = spec.timeout(timeout);
        }
        spec
    }
}

fn validate_command(command: &[&str]) -> Result<()> {
    if command.is_empty() {
        return Err(Error::InvalidRemoteCommand {
            index: 0,
            reason: "the command must contain at least one element".to_owned(),
        });
    }
    for (index, element) in command.iter().enumerate() {
        if element.is_empty() {
            return Err(Error::InvalidRemoteCommand {
                index,
                reason: "elements must not be empty".to_owned(),
            });
        }
        if element.chars().any(char::is_control) {
            return Err(Error::InvalidRemoteCommand {
                index,
                reason: "elements must not contain control characters".to_owned(),
            });
        }
        if contains_shell_metachars(element) {
            return Err(Error::InvalidRemoteCommand {
                index,
                reason: "elements must not contain shell metacharacters".to_owned(),
            });
        }
    }
    Ok(())
}

fn is_host_key_failure(output: &CommandOutput) -> bool {
    output.exit_code == Some(SSH_FATAL_EXIT_CODE)
        && output
            .stderr
            .to_ascii_lowercase()
            .contains(HOST_KEY_FAILURE_SIGNATURE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use toride_runner::fake::FakeRunner;

    const CANNED_HOST_KEY_BANNER: &str = concat!(
        "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n",
        "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n",
        "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n",
        "IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\n",
        "Someone could be eavesdropping on you right now (man-in-the-middle attack)!\n",
        "Host key verification failed.\n",
    );

    fn host() -> HostSpec {
        HostSpec::parse("root@203.0.113.10").unwrap()
    }

    fn service(fake: &FakeRunner) -> ExecService {
        ExecService::new(Box::new(fake.clone()))
    }

    #[test]
    fn run_invokes_ssh_with_exact_argv_and_no_shell_assembly() {
        let fake = FakeRunner::new().push_response(CommandOutput::from_stdout("ok"));
        let svc = service(&fake);
        svc.run(&host(), &["systemctl", "is-active", "sshd"])
            .unwrap();

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].program, "ssh");
        assert_eq!(
            calls[0].args,
            vec![
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "root@203.0.113.10",
                "systemctl",
                "is-active",
                "sshd",
            ]
        );
        assert!(
            !calls[0].args.iter().any(|arg| arg.contains(' ')),
            "no argument may be a joined shell line: {:?}",
            calls[0].args
        );
        assert!(!calls[0].args.contains(&"-c".to_owned()));
        assert!(calls[0].stdin_null, "ssh must not inherit stdin");
        assert!(calls[0].redact, "the spec must opt into redaction");
    }

    #[test]
    fn accept_new_policy_passes_the_accept_new_option() {
        let fake = FakeRunner::new().push_response(CommandOutput::from_stdout("ok"));
        let svc =
            ExecService::new(Box::new(fake.clone())).with_host_key_policy(HostKeyPolicy::AcceptNew);
        svc.run(&host(), &["uptime"]).unwrap();

        let args = &fake.calls()[0].args;
        assert!(args.contains(&"StrictHostKeyChecking=accept-new".to_owned()));
        assert!(!args.contains(&"StrictHostKeyChecking=yes".to_owned()));
    }

    #[test]
    fn command_elements_with_metacharacters_are_rejected_before_spawn() {
        let fake = FakeRunner::new();
        let svc = service(&fake);
        for bad in [
            "a;b",
            "a && b",
            "a`id`",
            "$(reboot)",
            "${HOME}",
            "a|b",
            "a>b",
            "a<b",
            "a&b",
            "a\nb",
            "a\rb",
        ] {
            match svc.run(&host(), &["echo", bad]) {
                Err(Error::InvalidRemoteCommand { index, reason }) => {
                    assert_eq!(index, 1, "{bad:?}: wrong position");
                    assert!(
                        !reason.contains(bad),
                        "{bad:?}: rejection reason leaked the element: {reason}"
                    );
                }
                other => panic!("{bad:?}: expected InvalidRemoteCommand, got {other:?}"),
            }
        }
        assert!(
            fake.calls().is_empty(),
            "no invocation may reach the runner for a rejected element"
        );
    }

    #[test]
    fn command_elements_with_control_characters_are_rejected_before_spawn() {
        let fake = FakeRunner::new();
        let svc = service(&fake);
        for bad in ["a\tb", "a\0b", "a\x1bb"] {
            match svc.run(&host(), &["echo", bad]) {
                Err(Error::InvalidRemoteCommand { index, reason }) => {
                    assert_eq!(index, 1, "{bad:?}: wrong position");
                    assert!(reason.contains("control"), "{bad:?}: {reason}");
                }
                other => panic!("{bad:?}: expected InvalidRemoteCommand, got {other:?}"),
            }
        }
        assert!(fake.calls().is_empty());
    }

    #[test]
    fn empty_command_is_rejected_before_spawn() {
        let fake = FakeRunner::new();
        let svc = service(&fake);
        match svc.run(&host(), &[]) {
            Err(Error::InvalidRemoteCommand { index, reason }) => {
                assert_eq!(index, 0);
                assert!(reason.contains("at least one element"), "{reason}");
            }
            other => panic!("expected InvalidRemoteCommand, got {other:?}"),
        }
        assert!(fake.calls().is_empty());
    }

    #[test]
    fn empty_command_element_is_rejected_before_spawn() {
        let fake = FakeRunner::new();
        let svc = service(&fake);
        match svc.run(&host(), &["echo", ""]) {
            Err(Error::InvalidRemoteCommand { index, reason }) => {
                assert_eq!(index, 1);
                assert!(reason.contains("empty"), "{reason}");
            }
            other => panic!("expected InvalidRemoteCommand, got {other:?}"),
        }
        assert!(fake.calls().is_empty());
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
    fn exit_255_with_host_key_signature_maps_to_the_host_key_error() {
        let fake = FakeRunner::new()
            .push_response(CommandOutput::from_stderr(CANNED_HOST_KEY_BANNER, 255));
        let svc = service(&fake);
        let err = svc.run(&host(), &["uptime"]).unwrap_err();
        match err {
            Error::Core(toride_ssh_core::Error::HostKeyVerificationFailed(detail)) => {
                assert!(detail.contains("Host key verification failed"), "{detail}");
            }
            other => panic!("expected HostKeyVerificationFailed, got {other:?}"),
        }
    }

    #[test]
    fn exit_255_with_bare_signature_line_also_maps_to_the_host_key_error() {
        let fake = FakeRunner::new().push_response(CommandOutput::from_stderr(
            "root@203.0.113.10: Host key verification failed.\n",
            255,
        ));
        let svc = service(&fake);
        assert!(matches!(
            svc.run(&host(), &["uptime"]).unwrap_err(),
            Error::Core(toride_ssh_core::Error::HostKeyVerificationFailed(_))
        ));
    }

    #[test]
    fn exit_255_without_the_signature_is_a_plain_command_failure() {
        let fake = FakeRunner::new().push_response(CommandOutput::from_stderr(
            "ssh: connect to host 203.0.113.10 port 22: Connection refused\n",
            255,
        ));
        let svc = service(&fake);
        match svc.run(&host(), &["uptime"]).unwrap_err() {
            Error::RemoteCommandFailed {
                exit_code: Some(255),
                ..
            } => {}
            other => panic!("expected RemoteCommandFailed(255), got {other:?}"),
        }
    }

    #[test]
    fn remote_nonzero_exit_maps_to_remote_command_failed() {
        let fake =
            FakeRunner::new().push_response(CommandOutput::from_stderr("E: unable to lock\n", 100));
        let svc = service(&fake);
        match svc.run(&host(), &["apt-get", "update"]).unwrap_err() {
            Error::RemoteCommandFailed {
                host,
                exit_code,
                stderr,
            } => {
                assert_eq!(host, "root@203.0.113.10");
                assert_eq!(exit_code, Some(100));
                assert!(stderr.contains("unable to lock"), "{stderr}");
            }
            other => panic!("expected RemoteCommandFailed, got {other:?}"),
        }
    }

    #[test]
    fn success_returns_the_captured_output() {
        let fake =
            FakeRunner::new().push_response(CommandOutput::from_stdout(" 10:00  up 1 day\n"));
        let svc = service(&fake);
        let output = svc.run(&host(), &["uptime"]).unwrap();
        assert!(output.success);
        assert_eq!(output.exit_code, Some(0));
        assert!(output.stdout.contains("up 1 day"));
    }

    #[test]
    fn failure_errors_do_not_embed_the_remote_command() {
        let fake = FakeRunner::new().push_response(CommandOutput::from_stderr("boom\n", 1));
        let svc = service(&fake);
        let err = svc
            .run(&host(), &["deploy", "sekrit-token-value", "--force"])
            .unwrap_err();
        let rendered = err.to_string();
        assert!(!rendered.contains("deploy"), "{rendered}");
        assert!(!rendered.contains("sekrit-token-value"), "{rendered}");
        assert!(!rendered.contains("--force"), "{rendered}");
    }

    #[test]
    fn sensitive_argv_positions_are_scrubbed_from_error_stderr() {
        let fake = FakeRunner::new()
            .push_response(CommandOutput::from_stderr("error: hunter2 rejected\n", 1));
        let svc = service(&fake);
        let err = svc
            .run(&host(), &["env", "--password", "hunter2", "uptime"])
            .unwrap_err();
        let rendered = err.to_string();
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("***"), "{rendered}");
    }

    #[test]
    fn missing_ssh_binary_is_reported_before_any_spawn() {
        let fake = FakeRunner::new();
        let svc =
            ExecService::new(Box::new(fake.clone())).with_ssh_program("toride-missing-ssh-probe");
        match svc.run(&host(), &["uptime"]).unwrap_err() {
            Error::Core(toride_ssh_core::Error::ToolNotFound(name)) => {
                assert_eq!(name, "toride-missing-ssh-probe");
            }
            other => panic!("expected ToolNotFound, got {other:?}"),
        }
        assert!(fake.calls().is_empty());
    }

    #[test]
    fn runner_errors_propagate_as_the_runner_variant() {
        let fake = FakeRunner::new().push_result(Err(toride_runner::Error::SpawnFailed {
            program: "ssh".to_owned(),
            detail: "exec format error".to_owned(),
        }));
        let svc = service(&fake);
        assert!(matches!(
            svc.run(&host(), &["uptime"]).unwrap_err(),
            Error::Runner(toride_runner::Error::SpawnFailed { .. })
        ));
    }

    #[test]
    fn builders_override_policy_and_program() {
        let svc = ExecService::new(Box::new(FakeRunner::new()))
            .with_host_key_policy(HostKeyPolicy::AcceptNew)
            .with_ssh_program("/usr/bin/ssh");
        assert_eq!(svc.host_key_policy(), HostKeyPolicy::AcceptNew);
        assert_eq!(svc.ssh_program(), "/usr/bin/ssh");
    }

    #[test]
    fn defaults_are_strict_policy_and_path_ssh() {
        let svc = ExecService::new(Box::new(FakeRunner::new()));
        assert_eq!(svc.host_key_policy(), HostKeyPolicy::Strict);
        assert_eq!(svc.ssh_program(), "ssh");
        assert_eq!(svc.timeout(), None);
    }

    /// foundations-0: `with_timeout` must land on every invocation spec, so a
    /// long deploy is not killed by the runner's 60 s default.
    #[test]
    fn with_timeout_applies_the_cap_to_the_invocation_spec() {
        let fake = FakeRunner::new().push_response(CommandOutput::from_stdout("ok"));
        let svc = ExecService::new(Box::new(fake.clone())).with_timeout(Duration::from_secs(300));
        assert_eq!(svc.timeout(), Some(Duration::from_secs(300)));

        svc.run(&host(), &["systemctl", "restart", "app"]).unwrap();

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].timeout,
            Some(Duration::from_secs(300)),
            "the spec must carry the service timeout: {:?}",
            calls[0]
        );
    }

    /// Without the knob the spec leaves the timeout unset, deferring to the
    /// runner default (60 s on the default Duct/Tokio runners).
    #[test]
    fn without_timeout_the_spec_defers_to_the_runner_default() {
        let fake = FakeRunner::new().push_response(CommandOutput::from_stdout("ok"));
        let svc = ExecService::new(Box::new(fake.clone()));
        svc.run(&host(), &["uptime"]).unwrap();
        assert_eq!(fake.calls()[0].timeout, None);
    }
}
