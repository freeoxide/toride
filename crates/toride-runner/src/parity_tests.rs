//! Parity tests between `DuctRunner` and `TokioRunner`.
//!
//! These verify that both runners produce equivalent `CommandOutput` for
//! basic success and failure commands. Only compiled when both `duct-runner`
//! and `tokio-runner` features are enabled.

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
        let spec = CommandSpec::new("false");

        let sync_output = Runner::run(&DuctRunner, &spec).unwrap();
        let async_output = AsyncRunner::run(&TokioRunner, &spec).await.unwrap();

        assert!(!sync_output.success);
        assert!(!async_output.success);
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
}
