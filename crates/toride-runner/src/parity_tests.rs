//! Parity tests between `DuctRunner` and `TokioRunner`.
//!
//! These verify that both runners produce equivalent `CommandOutput` for
//! basic success and failure commands. Only compiled when both `duct-runner`
//! and `tokio-runner` features are enabled.

#[cfg(test)]
mod tests {
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
    async fn parity_env() {
        let spec = CommandSpec::new("env").env("TORIDE_PARITY_VAR", "test");

        let sync_output = Runner::run(&DuctRunner, &spec).unwrap();
        let async_output = AsyncRunner::run(&TokioRunner, &spec).await.unwrap();

        assert!(sync_output.stdout.contains("TORIDE_PARITY_VAR=test"));
        assert!(async_output.stdout.contains("TORIDE_PARITY_VAR=test"));
    }

    #[tokio::test]
    async fn parity_cwd() {
        let spec = CommandSpec::new("pwd").cwd("/tmp");

        let sync_output = Runner::run(&DuctRunner, &spec).unwrap();
        let async_output = AsyncRunner::run(&TokioRunner, &spec).await.unwrap();

        // On macOS /tmp is a symlink — both runners should resolve the same way.
        assert_eq!(sync_output.stdout_trimmed(), async_output.stdout_trimmed());
    }
}
