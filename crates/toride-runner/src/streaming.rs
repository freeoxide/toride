//! Streaming command execution types.
//!
//! These types support real-time output streaming for long-running commands.
//! Behind the `stream` feature, which implies `tokio-runner`.

use async_trait::async_trait;

use crate::async_runner::AsyncRunner;
use crate::error::Result;
use crate::output::CommandOutput;
use crate::spec::CommandSpec;

/// Events emitted during streaming command execution.
#[derive(Debug, Clone)]
pub enum CommandEvent {
    /// The child process has been spawned.
    Started {
        /// Program name.
        program: String,
        /// Arguments passed.
        args: Vec<String>,
    },
    /// Raw stdout bytes received from the child.
    ///
    /// Emitted as chunks because some commands emit progress without
    /// newline boundaries.
    StdoutChunk(Vec<u8>),
    /// Raw stderr bytes received from the child.
    StderrChunk(Vec<u8>),
    /// A complete line from stdout (newline-stripped).
    StdoutLine(String),
    /// A complete line from stderr (newline-stripped).
    StderrLine(String),
    /// The child process has exited.
    Exited {
        /// Exit code, if available.
        exit_code: Option<i32>,
    },
}

/// An async sink that receives [`CommandEvent`]s during streaming execution.
///
/// The sink is async to allow backpressure. A blocking sink in an async runner
/// can stall process output handling and deadlock if buffers fill.
#[async_trait]
pub trait CommandEventSink: Send {
    /// Handle a streaming event.
    ///
    /// Return `Ok(())` to continue receiving events, or an error to abort
    /// the streaming session.
    async fn on_event(&mut self, event: CommandEvent) -> Result<()>;
}

/// A streaming extension of [`AsyncRunner`].
///
/// Implementors provide real-time output streaming via a
/// [`CommandEventSink`], in addition to the standard captured-output
/// execution.
#[async_trait]
pub trait AsyncStreamingRunner: AsyncRunner {
    /// Execute the given [`CommandSpec`] with streaming output events.
    ///
    /// Events are delivered to `sink` as they arrive. The method returns
    /// the final [`CommandOutput`] with captured stdout/stderr and exit code
    /// after the process completes.
    async fn run_streaming(
        &self,
        spec: &CommandSpec,
        sink: &mut dyn CommandEventSink,
    ) -> Result<CommandOutput>;
}
