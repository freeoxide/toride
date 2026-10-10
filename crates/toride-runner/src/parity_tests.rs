//! Parity tests between `DuctRunner` and `TokioRunner`.
//!
//! These verify that both runners produce equivalent `CommandOutput` for
//! basic success and failure commands. Only compiled when both `duct-runner`
//! and `tokio-runner` features are enabled.
//!
//! # Covered parity rows
//!
//! - Unit `DuctRunner` vs unit `TokioRunner`: success, failure with an exact
//!   exit code, stderr separation, stdin, null-stdin, env add/remove/clear,
//!   cwd, env precedence, argv rejection, path-policy refusal and
//!   child-env resolution, output caps, and `OutputMode::Stream` rejection
//!   in the captured paths.
//! - Configured runners (`ConfiguredDuctRunner`, `ConfiguredTokioRunner`)
//!   vs the unit runners: identical outputs under default options, shared
//!   default-timeout application, shared no-default-timeout completion, and
//!   spec-timeout override of the runner default.
//! - Streaming (feature `stream`): the final aggregate of
//!   `TokioRunner::run_streaming` is compared against `TokioRunner::run`'s
//!   captured output.
//! - `FakeRunner` (feature `fake`): a recorded real output replays
//!   identically through both the `Runner` and `AsyncRunner` traits.
//!
//! # Intentionally excluded parity rows
//!
//! These exclusions are deliberate decisions, not gaps; the suite never
//! claims them by omission:
//!
//! - **Duct streaming**: there is no sync streaming Duct implementation by
//!   design — both captured paths reject `OutputMode::Stream` (asserted by
//!   `parity_stream_mode_rejected_by_both_captured_paths`), so the streaming
//!   row compares Tokio streaming against Tokio captured output instead.
//! - **`FakeRunner` process behavior**: `FakeRunner` spawns no process, so env
//!   wiring, cwd, stdio plumbing, timeout kill-and-reap, output caps, and
//!   error-construction redaction cannot be parity-tested against it; only
//!   the replay row above applies to it.
//! - **Command-log emission**: the `log_commands` toggle is observable only
//!   through a tracing subscriber, never through the runners' return values,
//!   so no parity row asserts log emission; the toggle is pinned by the
//!   options unit tests in `duct_runner` and `tokio_runner`.
//! - **Kill-and-reap process-tree effects**: timeout and cap-breach child
//!   termination is covered by the per-runner marker-file tests in
//!   `duct_runner` and `tokio_runner`; parity rows compare `CommandOutput`
//!   values only.

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::async_runner::AsyncRunner;
    use crate::duct_runner::DuctRunner;
    use crate::runner::Runner;
    use crate::spec::CommandSpec;
    use crate::tokio_runner::TokioRunner;

    #[tokio::test]
    async fn parity_success() {
        let spec = CommandSpec::new("echo").arg("hello");

        let sync_output = Runner::run(&DuctRunner, &spec).unwrap();
        let async_output = AsyncRunner::run(&TokioRunner, &spec).await.unwrap();

        assert!(sync_output.success);
        assert!(async_output.success);
        assert_eq!(sync_output.stdout_trimmed(), async_output.stdout_trimmed());
        assert_eq!(sync_output.exit_code, async_output.exit_code);
    }

    #[tokio::test]
    async fn parity_failure() {
        // A distinctive non-zero exit code: each runner must report the exact
        // code the child exited with, not merely agree with the other runner
        // (mutual equality would still pass if both reported a wrong value).
        let spec = CommandSpec::new("bash").args(["-c", "exit 42"]);

        let sync_output = Runner::run(&DuctRunner, &spec).unwrap();
        let async_output = AsyncRunner::run(&TokioRunner, &spec).await.unwrap();

        assert!(!sync_output.success);
        assert!(!async_output.success);
        assert_eq!(sync_output.exit_code, Some(42));
        assert_eq!(async_output.exit_code, Some(42));
        assert_eq!(sync_output.exit_code, async_output.exit_code);
    }

    #[tokio::test]
    async fn parity_stderr() {
        let spec = CommandSpec::new("bash").args(["-c", "echo ok; echo err >&2"]);

        let sync_output = Runner::run(&DuctRunner, &spec).unwrap();
        let async_output = AsyncRunner::run(&TokioRunner, &spec).await.unwrap();

        assert!(sync_output.success);
        assert!(async_output.success);
        assert_eq!(sync_output.stdout_trimmed(), async_output.stdout_trimmed());
        assert_eq!(sync_output.stderr.trim(), async_output.stderr.trim());
    }

    #[tokio::test]
    async fn parity_stdin() {
        let spec = CommandSpec::new("cat").stdin("hello world");

        let sync_output = Runner::run(&DuctRunner, &spec).unwrap();
        let async_output = AsyncRunner::run(&TokioRunner, &spec).await.unwrap();

        assert!(sync_output.success);
        assert!(async_output.success);
        assert_eq!(sync_output.stdout_trimmed(), async_output.stdout_trimmed());
        assert_eq!(sync_output.stdout_trimmed(), "hello world");
    }

    #[tokio::test]
    async fn parity_stdin_null_eof() {
        // Both runners must wire a null-stdin spec to the null device: `cat`
        // sees EOF immediately and both return empty successes (rather than
        // inheriting the harness's stdin).
        let spec = CommandSpec::new("cat")
            .stdin_null(true)
            .timeout(Duration::from_secs(2));

        let sync_output = Runner::run(&DuctRunner, &spec).unwrap();
        let async_output = AsyncRunner::run(&TokioRunner, &spec).await.unwrap();

        assert!(sync_output.success);
        assert!(async_output.success);
        assert_eq!(sync_output.stdout, async_output.stdout);
        assert_eq!(sync_output.stdout, "");
    }

    #[tokio::test]
    async fn parity_env() {
        let spec = CommandSpec::new("env").env("TORIDE_PARITY_VAR", "test");

        let sync_output = Runner::run(&DuctRunner, &spec).unwrap();
        let async_output = AsyncRunner::run(&TokioRunner, &spec).await.unwrap();

        assert!(sync_output.stdout.contains("TORIDE_PARITY_VAR=test"));
        assert!(async_output.stdout.contains("TORIDE_PARITY_VAR=test"));
    }

    #[tokio::test]
    async fn parity_env_remove() {
        let spec = CommandSpec::new("/bin/sh")
            .args(["-c", "printf '%s' \"${HOME-unset}\""])
            .env_remove("HOME");

        let sync_output = Runner::run(&DuctRunner, &spec).unwrap();
        let async_output = AsyncRunner::run(&TokioRunner, &spec).await.unwrap();

        assert_eq!(sync_output.stdout, async_output.stdout);
        assert_eq!(sync_output.stdout, "unset");
    }

    #[tokio::test]
    async fn parity_clear_env() {
        let spec = CommandSpec::new("/bin/sh")
            .args([
                "-c",
                "printf '%s:%s' \"${HOME-unset}\" \"$TORIDE_PARITY_KEEP\"",
            ])
            .clear_env(true)
            .env("TORIDE_PARITY_KEEP", "kept");

        let sync_output = Runner::run(&DuctRunner, &spec).unwrap();
        let async_output = AsyncRunner::run(&TokioRunner, &spec).await.unwrap();

        assert_eq!(sync_output.stdout, async_output.stdout);
        assert_eq!(sync_output.stdout, "unset:kept");
    }

    #[tokio::test]
    async fn parity_cwd() {
        let spec = CommandSpec::new("pwd").cwd("/tmp");

        let sync_output = Runner::run(&DuctRunner, &spec).unwrap();
        let async_output = AsyncRunner::run(&TokioRunner, &spec).await.unwrap();

        // On macOS /tmp is a symlink — both runners should resolve the same way.
        assert_eq!(sync_output.stdout_trimmed(), async_output.stdout_trimmed());
    }

    #[tokio::test]
    async fn parity_env_precedence_remove_wins() {
        let spec = CommandSpec::new("/bin/sh")
            .args(["-c", "printf '%s' \"${TORIDE_PARITY_VAR-unset}\""])
            .env_remove("TORIDE_PARITY_VAR")
            .env("TORIDE_PARITY_VAR", "present")
            .env_precedence(crate::policy::EnvPrecedence::RemoveWins);

        let sync_output = Runner::run(&DuctRunner, &spec).unwrap();
        let async_output = AsyncRunner::run(&TokioRunner, &spec).await.unwrap();

        assert_eq!(sync_output.stdout, async_output.stdout);
        assert_eq!(sync_output.stdout, "unset");
    }

    #[tokio::test]
    async fn parity_argv_rejection() {
        let spec = CommandSpec::new("echo")
            .arg("a;b")
            .argv_policy(crate::policy::ArgvPolicy::RejectShellMetachars);

        let sync_result = Runner::run(&DuctRunner, &spec);
        let async_result = AsyncRunner::run(&TokioRunner, &spec).await;

        for result in [sync_result, async_result] {
            assert!(
                matches!(result, Err(crate::error::Error::ArgvRejected { .. })),
                "expected ArgvRejected from both runners"
            );
        }
    }

    #[tokio::test]
    async fn parity_path_policy_refusal() {
        let spec = CommandSpec::new("./nope")
            .path_resolution(crate::policy::PathResolution::ChildEnvNoCwd);

        let sync_result = Runner::run(&DuctRunner, &spec);
        let async_result = AsyncRunner::run(&TokioRunner, &spec).await;

        for result in [sync_result, async_result] {
            assert!(
                matches!(result, Err(crate::error::Error::ProgramRejected { .. })),
                "expected ProgramRejected from both runners"
            );
        }
    }

    #[tokio::test]
    async fn parity_output_cap_always() {
        let spec = CommandSpec::new("bash")
            .args(["-c", "for i in $(seq 1 100); do echo line; done"])
            .output_cap(crate::policy::OutputCap::Always(64));

        let sync_result = Runner::run(&DuctRunner, &spec);
        let async_result = AsyncRunner::run(&TokioRunner, &spec).await;

        for result in [sync_result, async_result] {
            assert!(
                matches!(
                    result,
                    Err(crate::error::Error::OutputLimitExceeded { limit: 64, .. })
                ),
                "expected OutputLimitExceeded(64) from both runners"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn parity_path_policy_child_env_resolution() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let probe = dir.path().join("toride_parity_probe");
        std::fs::write(&probe, "#!/bin/sh\necho from-probe\n").unwrap();
        let mut perms = std::fs::metadata(&probe).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&probe, perms).unwrap();

        let spec = CommandSpec::new("toride_parity_probe")
            .env("PATH", dir.path().to_string_lossy().into_owned())
            .path_resolution(crate::policy::PathResolution::ChildEnvNoCwd)
            .timeout(Duration::from_secs(5));

        let sync_output = Runner::run(&DuctRunner, &spec).unwrap();
        let async_output = AsyncRunner::run(&TokioRunner, &spec).await.unwrap();

        assert_eq!(sync_output.stdout_trimmed(), "from-probe");
        assert_eq!(async_output.stdout_trimmed(), "from-probe");
    }

    #[tokio::test]
    async fn parity_stream_mode_rejected_by_both_captured_paths() {
        // OutputMode::Stream belongs to the streaming API only; both captured
        // paths must refuse it with Error::Other. This pins the streaming
        // boundary the Duct-streaming exclusion (module docs) rests on.
        let spec = CommandSpec::new("echo")
            .arg("hello")
            .output_mode(crate::OutputMode::Stream);

        let sync_result = Runner::run(&DuctRunner, &spec);
        let async_result = AsyncRunner::run(&TokioRunner, &spec).await;

        for result in [sync_result, async_result] {
            assert!(
                matches!(
                    result,
                    Err(crate::error::Error::Other(ref message)) if message.contains("Stream")
                ),
                "expected Error::Other mentioning Stream from both captured paths"
            );
        }
    }

    #[tokio::test]
    async fn parity_configured_duct_runner_matches_unit_runners() {
        // A ConfiguredDuctRunner built with default options must behave
        // exactly like the unit runners it configures.
        let runner = DuctRunner::builder().build();
        let spec = CommandSpec::new("bash").args(["-c", "echo out; echo err >&2"]);

        let configured_output = Runner::run(&runner, &spec).unwrap();
        let sync_output = Runner::run(&DuctRunner, &spec).unwrap();
        let async_output = AsyncRunner::run(&TokioRunner, &spec).await.unwrap();

        assert_eq!(
            configured_output.stdout_trimmed(),
            sync_output.stdout_trimmed()
        );
        assert_eq!(
            configured_output.stdout_trimmed(),
            async_output.stdout_trimmed()
        );
        assert_eq!(configured_output.stderr.trim(), sync_output.stderr.trim());
        assert_eq!(configured_output.stderr.trim(), async_output.stderr.trim());
        assert_eq!(configured_output.exit_code, Some(0));
        assert_eq!(configured_output.exit_code, sync_output.exit_code);
        assert_eq!(configured_output.exit_code, async_output.exit_code);
    }

    #[tokio::test]
    async fn parity_configured_runners_share_default_timeout_behavior() {
        // Neither spec carries a timeout; both configured runners must apply
        // their own 50ms default and time out identically.
        let duct = DuctRunner::builder()
            .default_timeout(Duration::from_millis(50))
            .build();
        let tokio = TokioRunner::builder()
            .default_timeout(Duration::from_millis(50))
            .build();
        let spec = CommandSpec::new("sleep").arg("10");

        let sync_result = Runner::run(&duct, &spec);
        let async_result = AsyncRunner::run(&tokio, &spec).await;

        for result in [sync_result, async_result] {
            assert!(
                matches!(
                    result,
                    Err(crate::error::Error::CommandTimeout { timeout, .. })
                        if timeout == Duration::from_millis(50)
                ),
                "expected CommandTimeout(50ms) from both configured runners"
            );
        }
    }

    #[tokio::test]
    async fn parity_configured_runners_share_no_default_timeout_behavior() {
        // With the default timeout disabled and no spec timeout, both runners
        // run unbounded and the command completes naturally.
        let duct = DuctRunner::builder()
            .no_default_timeout()
            .log_commands(false)
            .build();
        let tokio = TokioRunner::builder()
            .no_default_timeout()
            .log_commands(false)
            .build();
        let spec = CommandSpec::new("bash").args(["-c", "sleep 0.05; echo done"]);

        let sync_output = Runner::run(&duct, &spec).unwrap();
        let async_output = AsyncRunner::run(&tokio, &spec).await.unwrap();

        assert_eq!(sync_output.stdout_trimmed(), async_output.stdout_trimmed());
        assert_eq!(sync_output.stdout_trimmed(), "done");
        assert_eq!(sync_output.exit_code, async_output.exit_code);
    }

    #[tokio::test]
    async fn parity_spec_timeout_overrides_runner_default_in_both_configured_runners() {
        // The runner default is 50ms (which would kill this command); the
        // spec's own timeout must win in both runners.
        let duct = DuctRunner::builder()
            .default_timeout(Duration::from_millis(50))
            .build();
        let tokio = TokioRunner::builder()
            .default_timeout(Duration::from_millis(50))
            .build();
        let spec = CommandSpec::new("bash")
            .args(["-c", "sleep 0.1; echo done"])
            .timeout(Duration::from_secs(1));

        let sync_output = Runner::run(&duct, &spec).unwrap();
        let async_output = AsyncRunner::run(&tokio, &spec).await.unwrap();

        assert_eq!(sync_output.stdout_trimmed(), async_output.stdout_trimmed());
        assert_eq!(sync_output.stdout_trimmed(), "done");
    }

    #[cfg(feature = "stream")]
    #[tokio::test]
    async fn parity_streaming_aggregate_matches_captured_run() {
        use crate::error::Result;
        use crate::streaming::{AsyncStreamingRunner, CommandEvent, CommandEventSink};
        use async_trait::async_trait;

        // Collects every event for later inspection.
        struct CollectingSink {
            events: Vec<CommandEvent>,
        }

        #[async_trait]
        impl CommandEventSink for CollectingSink {
            async fn on_event(&mut self, event: CommandEvent) -> Result<()> {
                self.events.push(event);
                Ok(())
            }
        }

        let spec = CommandSpec::new("bash").args(["-c", "echo out; echo err >&2"]);
        let captured = AsyncRunner::run(&TokioRunner, &spec).await.unwrap();

        let mut sink = CollectingSink { events: Vec::new() };
        let streamed = TokioRunner.run_streaming(&spec, &mut sink).await.unwrap();

        assert_eq!(streamed.success, captured.success);
        assert_eq!(streamed.stdout_trimmed(), captured.stdout_trimmed());
        assert_eq!(streamed.stderr.trim(), captured.stderr.trim());
        assert_eq!(streamed.exit_code, captured.exit_code);

        // The event envelope must bracket the data events and report the same
        // exit code the captured path reports.
        assert!(matches!(
            sink.events.first(),
            Some(CommandEvent::Started { program, .. }) if program == "bash"
        ));
        assert!(matches!(
            sink.events.last(),
            Some(CommandEvent::Exited { exit_code: Some(0) })
        ));
        assert!(
            sink.events
                .iter()
                .any(|e| matches!(e, CommandEvent::StdoutLine(line) if line == "out"))
        );
        assert!(
            sink.events
                .iter()
                .any(|e| matches!(e, CommandEvent::StderrLine(line) if line == "err"))
        );
    }

    #[cfg(feature = "fake")]
    #[tokio::test]
    async fn parity_fake_runner_replays_real_output_through_both_traits() {
        use crate::fake::FakeRunner;

        // Record a real runner's output, then replay it: the fake must hand
        // back exactly that output through both the sync and async traits —
        // the contract callers rely on when swapping a real runner for a fake.
        let spec = CommandSpec::new("bash").args(["-c", "echo out; echo err >&2"]);
        let real = Runner::run(&DuctRunner, &spec).unwrap();

        let fake = FakeRunner::new()
            .respond(spec.clone(), real.clone())
            .respond(spec.clone(), real.clone());
        let sync_output = Runner::run(&fake, &spec).unwrap();
        let async_output = AsyncRunner::run(&fake, &spec).await.unwrap();

        assert_eq!(sync_output.success, async_output.success);
        assert_eq!(sync_output.exit_code, async_output.exit_code);
        assert_eq!(sync_output.stdout_trimmed(), async_output.stdout_trimmed());
        assert_eq!(sync_output.stderr.trim(), async_output.stderr.trim());
        assert_eq!(sync_output.exit_code, Some(0));
        assert_eq!(sync_output.stdout_trimmed(), "out");
        assert_eq!(sync_output.stderr.trim(), "err");
    }
}
