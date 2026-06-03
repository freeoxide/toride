//! Output mode for command execution.
//!
//! Controls how a runner handles the child process's stdout and stderr.

/// How a runner should handle process output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputMode {
    /// Capture stdout and stderr into [`CommandOutput`](crate::CommandOutput).
    ///
    /// This is the default and should be used for commands that produce
    /// structured output (JSON, version strings, etc.).
    #[default]
    Capture,
    /// Stream stdout and stderr as [`CommandEvent`](crate::streaming::CommandEvent)
    /// events via a [`CommandEventSink`](crate::streaming::CommandEventSink).
    ///
    /// May also return collected stdout/stderr in the final `CommandOutput`
    /// depending on the runner implementation.
    ///
    /// Use for long-running commands where real-time progress matters
    /// (installs, upgrades, `mise exec`, etc.).
    Stream,
    /// Connect child stdio directly to the parent process.
    ///
    /// Returns empty captured strings in `CommandOutput`. Use only when the
    /// caller explicitly opts in — this is unsafe for libraries because it can
    /// leak output and interfere with app UI.
    Inherit,
}
