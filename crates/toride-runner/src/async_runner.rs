//! Core asynchronous [`AsyncRunner`] trait.
//!
//! Every async command executor implements this trait, allowing callers to
//! swap between real and fake implementations without changing downstream logic.

use async_trait::async_trait;

use crate::error::{Error, Result};
use crate::output::CommandOutput;
use crate::spec::CommandSpec;

/// A trait for executing commands asynchronously.
///
/// This mirrors the synchronous [`Runner`](crate::Runner) trait but uses
/// `async` methods. Implementations should use `tokio::process` and must
/// not block runtime worker threads.
#[async_trait]
pub trait AsyncRunner: Send + Sync {
    /// Execute the given [`CommandSpec`] and return its output.
    async fn run(&self, spec: &CommandSpec) -> Result<CommandOutput>;

    /// Execute the command and return an error if it did not succeed.
    ///
    /// The default implementation calls [`AsyncRunner::run`] and checks the
    /// `success` flag on the returned [`CommandOutput`].
    async fn run_checked(&self, spec: &CommandSpec) -> Result<CommandOutput> {
        let output = self.run(spec).await?;
        if !output.success {
            return Err(Error::CommandFailed {
                program: spec.program.clone(),
                args: crate::display::redacted_args_display(spec),
                exit_code: output.exit_code,
                stderr: crate::display::scrub_stderr(spec, &output.stderr),
            });
        }
        Ok(output)
    }
}
