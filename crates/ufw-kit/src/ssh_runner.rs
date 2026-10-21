//! SSH-forwarding adapter for [`CommandRunner`].
//!
//! [`SshCommandRunner`] executes every ufw-kit command spec on a fixed
//! remote [`HostSpec`] through `ssh`, so the whole ufw-kit surface
//! (status, rules, doctor, presets) drives a remote VPS unchanged. The
//! `force_c_locale` pin is honored remotely by prefixing the argv with
//! `env LC_ALL=C LANG=C`, which survives ssh's argv re-joining. Spec
//! timeouts are not forwarded: configure the cap once on the adapter
//! through [`SshCommandRunner::with_timeout`]. `requires_root` stays
//! advisory: the remote login user must already hold the privileges.

use toride_ssh_exec::{Error as ExecError, ExecService, HostKeyPolicy, HostSpec};

use crate::command::CommandRunner;
use crate::error::{Error, Result};
use crate::spec::{CommandResult, CommandSpec};

/// Runs ufw-kit command specs on a remote host over `ssh`.
///
/// Built on [`toride_ssh_exec::SshRunner`]'s service layer: argv
/// validation, [`HostKeyPolicy::Strict`] by default, one shared ssh
/// presence probe, and scrubbed remote diagnostics.
pub struct SshCommandRunner {
    host: HostSpec,
    service: ExecService,
}

impl SshCommandRunner {
    /// Forward every command spec to `host`, running `ssh` locally
    /// through `runner`.
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

    /// The fixed destination every command is forwarded to.
    #[must_use]
    pub fn host(&self) -> &HostSpec {
        &self.host
    }
}

impl CommandRunner for SshCommandRunner {
    fn run(&self, spec: &CommandSpec) -> Result<CommandResult> {
        let mut command: Vec<&str> = Vec::with_capacity(spec.args.len() + 4);
        if spec.force_c_locale {
            command.extend(["env", "LC_ALL=C", "LANG=C"]);
        }
        command.push(&spec.program);
        command.extend(spec.args.iter().map(String::as_str));
        let output = self
            .service
            .run(&self.host, &command)
            .map_err(|e| map_error(spec, e))?;
        Ok(CommandResult {
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.exit_code,
        })
    }

    fn binary_exists(&self, name: &str) -> bool {
        self.service
            .run(&self.host, &["command", "-v", name])
            .is_ok_and(|output| output.success)
    }
}

fn map_error(spec: &CommandSpec, error: ExecError) -> Error {
    match error {
        ExecError::RemoteCommandFailed {
            exit_code, stderr, ..
        } => Error::CommandFailed {
            program: spec.program.clone(),
            args: spec.args.join(" "),
            exit_code,
            stderr,
        },
        ExecError::Runner(toride_runner::Error::CommandTimeout { timeout, .. }) => {
            Error::CommandTimeout {
                program: spec.program.clone(),
                timeout_secs: timeout.as_secs(),
            }
        }
        ExecError::Runner(inner) => Error::CommandSpawnFailed(inner.to_string()),
        ExecError::InvalidRemoteCommand { reason, .. } => {
            Error::Validation(format!("remote command rejected: {reason}"))
        }
        ExecError::Core(core) => Error::CommandSpawnFailed(core.to_string()),
        unnameable => Error::CommandSpawnFailed(unnameable.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use toride_runner::fake::FakeRunner;

    fn host() -> HostSpec {
        HostSpec::parse("root@203.0.113.10").unwrap()
    }

    fn runner(fake: &FakeRunner) -> SshCommandRunner {
        SshCommandRunner::new(Box::new(fake.clone()), host())
    }

    fn remote_tail(fake: &FakeRunner) -> Vec<String> {
        let args = &fake.calls()[0].args;
        let position = args
            .iter()
            .position(|arg| arg == "root@203.0.113.10")
            .expect("the destination operand must be present");
        args[position + 1..].to_vec()
    }

    #[test]
    fn run_forwards_the_ufw_argv_with_the_c_locale_prefix() {
        let fake = FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(""));
        let remote = runner(&fake);

        remote
            .run(&CommandSpec::ufw(vec![
                "status".to_owned(),
                "verbose".to_owned(),
            ]))
            .unwrap();

        assert_eq!(
            remote_tail(&fake),
            ["env", "LC_ALL=C", "LANG=C", "ufw", "status", "verbose"],
            "force_c_locale must translate into an argv-clean env prefix"
        );
    }

    #[test]
    fn run_without_c_locale_omits_the_env_prefix() {
        let fake = FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(""));
        let remote = runner(&fake);
        let spec = CommandSpec {
            force_c_locale: false,
            ..CommandSpec::ufw(vec!["status".to_owned()])
        };

        remote.run(&spec).unwrap();

        assert_eq!(
            remote_tail(&fake),
            ["ufw", "status"],
            "no locale pin, no env prefix"
        );
    }

    #[test]
    fn command_result_fields_map_through() {
        let fake = FakeRunner::new().push_response(toride_runner::CommandOutput::new(
            "Status: active\n".to_owned(),
            String::new(),
            Some(0),
        ));
        let remote = runner(&fake);

        let result = remote
            .run(&CommandSpec::ufw(vec!["status".to_owned()]))
            .unwrap();

        assert_eq!(result.stdout, "Status: active\n");
        assert_eq!(result.exit_code, Some(0));
    }

    #[test]
    fn binary_exists_is_true_when_the_remote_lookup_succeeds() {
        let fake = FakeRunner::new()
            .push_response(toride_runner::CommandOutput::from_stdout("/usr/sbin/ufw\n"));
        let remote = runner(&fake);

        assert!(remote.binary_exists("ufw"));
        assert_eq!(
            remote_tail(&fake),
            ["command", "-v", "ufw"],
            "the probe must use the POSIX command -v lookup"
        );
    }

    #[test]
    fn binary_exists_is_false_when_the_remote_lookup_fails() {
        let fake =
            FakeRunner::new().push_response(toride_runner::CommandOutput::from_stderr("", 1));
        let remote = runner(&fake);

        assert!(!remote.binary_exists("toride-absent"));
    }

    #[test]
    fn remote_failure_maps_to_command_failed() {
        let fake = FakeRunner::new().push_response(toride_runner::CommandOutput::from_stderr(
            "ERROR: problem running ufw\n",
            1,
        ));
        let remote = runner(&fake);

        match remote
            .run(&CommandSpec::ufw(vec!["enable".to_owned()]))
            .unwrap_err()
        {
            Error::CommandFailed {
                program,
                args,
                exit_code,
                stderr,
            } => {
                assert_eq!(program, "ufw");
                assert_eq!(args, "enable");
                assert_eq!(exit_code, Some(1));
                assert!(stderr.contains("problem running ufw"), "{stderr}");
            }
            other => panic!("expected CommandFailed, got {other:?}"),
        }
    }

    #[test]
    fn argv_elements_the_remote_side_rejects_map_to_validation() {
        let fake = FakeRunner::new();
        let remote = runner(&fake);

        let err = remote
            .run(&CommandSpec::ufw(vec!["allow 22".to_owned()]))
            .unwrap_err();

        assert!(
            matches!(err, Error::Validation(ref detail) if detail.contains("rejected")),
            "got {err:?}"
        );
        assert!(fake.calls().is_empty(), "no ssh spawn may happen");
    }
}
