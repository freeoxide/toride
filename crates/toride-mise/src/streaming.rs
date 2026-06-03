//! Streaming support for long-running mise operations.
//!
//! This module provides streaming variants of [`Mise`](crate::Mise) methods
//! that deliver real-time [`CommandEvent`](toride_runner::CommandEvent)s to a
//! [`CommandEventSink`](toride_runner::CommandEventSink). This is useful for
//! operations like `mise install` that may take a long time and produce
//! progress output.
//!
//! Streaming is opt-in: the [`MiseBuilder`](crate::MiseBuilder) must be
//! configured with a
//! [`streaming_runner`](crate::MiseBuilder::streaming_runner) for these
//! methods to stream events. When no streaming runner is available, they fall
//! back to regular non-streaming execution via [`Mise::run_checked`].
//!
//! # Example
//!
//! ```rust,ignore
//! use toride_mise::Mise;
//! use toride_runner::CommandEventSink;
//!
//! struct MySink;
//!
//! #[async_trait::async_trait]
//! impl CommandEventSink for MySink {
//!     async fn on_event(&mut self, event: toride_runner::CommandEvent) -> toride_runner::Result<()> {
//!         println!("{event:?}");
//!         Ok(())
//!     }
//! }
//!
//! let mise = Mise::builder()
//!     .streaming_runner(Arc::new(toride_runner::tokio_runner::TokioRunner))
//!     .build()?;
//!
//! let output = mise.install_streaming("node@22", &mut MySink).await?;
//! ```

use std::sync::Arc;

use crate::client::Mise;
use crate::error::MiseResult;
use crate::exec::ExecRequest;

// ---------------------------------------------------------------------------
// Mise impl — streaming methods
// ---------------------------------------------------------------------------

impl Mise {
    /// Install a tool with real-time output streaming.
    ///
    /// Runs `mise install <tool_spec>` and streams
    /// [`CommandEvent`](toride_runner::CommandEvent)s to `sink` as they
    /// arrive. This is the streaming counterpart to calling
    /// [`Mise::run_checked`] with `["install", tool_spec]`.
    ///
    /// If no [`streaming_runner`](MiseBuilder::streaming_runner) was
    /// configured, falls back to non-streaming execution.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed)
    /// if the install command exits non-zero.
    pub async fn install_streaming(
        &self,
        tool_spec: &str,
        sink: &mut dyn toride_runner::CommandEventSink,
    ) -> MiseResult<toride_runner::CommandOutput> {
        let args: Vec<String> = vec!["install".into(), tool_spec.into()];

        if let Some(ref streaming_runner) = self.streaming_runner {
            let spec = self.build_command(args);
            let output = streaming_runner
                .run_streaming(&spec, sink)
                .await
                .map_err(crate::error::MiseError::from)?;

            if !output.success {
                return Err(crate::error::MiseError::CommandFailed {
                    command: format!("mise install {tool_spec}"),
                    exit_code: output.exit_code,
                    stdout: output.stdout.clone(),
                    stderr: output.stderr.clone(),
                });
            }

            Ok(output)
        } else {
            self.run_checked(args).await
        }
    }

    /// Execute a command through `mise exec` with real-time output streaming.
    ///
    /// This is the streaming counterpart to [`Mise::exec`](Mise::exec). It
    /// streams [`CommandEvent`](toride_runner::CommandEvent)s to `sink` as
    /// they arrive.
    ///
    /// If no [`streaming_runner`](MiseBuilder::streaming_runner) was
    /// configured, falls back to non-streaming execution.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed)
    /// if the exec command exits non-zero. Returns an error if `req.command`
    /// is empty.
    pub async fn exec_streaming(
        &self,
        req: &ExecRequest,
        sink: &mut dyn toride_runner::CommandEventSink,
    ) -> MiseResult<toride_runner::CommandOutput> {
        // Validate command before branching, matching exec/mod.rs behaviour.
        if req.command.is_empty() {
            return Err(crate::error::MiseError::CommandFailed {
                command: "mise exec".into(),
                exit_code: None,
                stdout: String::new(),
                stderr: "no command provided for mise exec".into(),
            });
        }

        if let Some(ref streaming_runner) = self.streaming_runner {
            let args = build_exec_args(req);
            let spec = self.build_command(args);
            let output = streaming_runner
                .run_streaming(&spec, sink)
                .await
                .map_err(crate::error::MiseError::from)?;

            if !output.success {
                return Err(crate::error::MiseError::CommandFailed {
                    command: build_exec_display(req),
                    exit_code: output.exit_code,
                    stdout: output.stdout.clone(),
                    stderr: output.stderr.clone(),
                });
            }

            Ok(output)
        } else {
            self.exec(req).await
        }
    }

    /// Run an arbitrary mise command with streaming output.
    ///
    /// This is a general-purpose streaming method. Prefer
    /// [`install_streaming`](Mise::install_streaming) or
    /// [`exec_streaming`](Mise::exec_streaming) for those specific operations.
    ///
    /// If no [`streaming_runner`](MiseBuilder::streaming_runner) was
    /// configured, falls back to non-streaming [`Mise::run_checked`].
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed)
    /// if the command exits non-zero.
    pub async fn run_streaming(
        &self,
        args: impl IntoIterator<Item = impl AsRef<str>>,
        sink: &mut dyn toride_runner::CommandEventSink,
    ) -> MiseResult<toride_runner::CommandOutput> {
        if let Some(ref streaming_runner) = self.streaming_runner {
            let args: Vec<String> = args.into_iter().map(|a| a.as_ref().to_owned()).collect();
            let spec = self.build_command(&args);
            let output = streaming_runner
                .run_streaming(&spec, sink)
                .await
                .map_err(crate::error::MiseError::from)?;

            if !output.success {
                return Err(crate::error::MiseError::CommandFailed {
                    command: args.join(" "),
                    exit_code: output.exit_code,
                    stdout: output.stdout.clone(),
                    stderr: output.stderr.clone(),
                });
            }

            Ok(output)
        } else {
            self.run_checked(args).await
        }
    }

    /// Return a reference to the configured streaming runner, if any.
    ///
    /// This allows callers to check whether streaming is available before
    /// calling streaming methods, or to obtain the runner for custom use.
    pub fn streaming_runner(&self) -> Option<&Arc<dyn toride_runner::AsyncStreamingRunner>> {
        self.streaming_runner.as_ref()
    }

    /// Return a clone of the streaming runner arc if one is configured.
    ///
    /// Useful when you need ownership of the streaming runner separately from
    /// the [`Mise`] client.
    pub fn clone_streaming_runner(&self) -> Option<Arc<dyn toride_runner::AsyncStreamingRunner>> {
        self.streaming_runner.clone()
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Build the argument list for a `mise exec` invocation from an [`ExecRequest`].
///
/// Mirrors the arg-building logic in [`Mise::exec`](crate::client::Mise::exec)
/// so that streaming and non-streaming paths produce identical flags.
fn build_exec_args(req: &ExecRequest) -> Vec<String> {
    let mut args: Vec<String> = Vec::new();
    args.push("exec".into());

    for tool in &req.tools {
        args.push(tool.to_string());
    }

    if let Some(jobs) = req.jobs {
        args.push("--jobs".into());
        args.push(jobs.to_string());
    }

    if req.fresh_env {
        args.push("--fresh".into());
    }

    if req.no_deps {
        args.push("--no-deps".into());
    }

    // Raw mode — must match the non-streaming exec path.
    if req.raw {
        args.push("--raw".into());
    }

    if let Some(ref cwd) = req.cwd {
        args.push("--cwd".into());
        args.push(cwd.to_string());
    }

    // Sandbox flags — must match the non-streaming exec path.
    if let Some(ref policy) = req.sandbox {
        if policy.deny_read {
            args.push("--deny-read".into());
        }
        if policy.deny_write {
            args.push("--deny-write".into());
        }
        if policy.deny_net {
            args.push("--deny-net".into());
        }
        if policy.deny_env {
            args.push("--deny-env".into());
        }
        for path in &policy.allow_read {
            args.push("--allow-read".into());
            args.push(path.to_string_lossy().into_owned());
        }
        for path in &policy.allow_write {
            args.push("--allow-write".into());
            args.push(path.to_string_lossy().into_owned());
        }
        for host in &policy.allow_net {
            args.push("--allow-net".into());
            args.push(host.clone());
        }
        for pattern in &policy.allow_env {
            args.push("--allow-env".into());
            args.push(pattern.clone());
        }
    }

    args.push("--".into());
    args.extend(req.command.iter().cloned());

    args
}

/// Build a human-readable display string for an exec request (for error messages).
fn build_exec_display(req: &ExecRequest) -> String {
    let tools: String = req
        .tools
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");

    let cmd = req.command.join(" ");

    if tools.is_empty() {
        format!("mise exec -- {cmd}")
    } else {
        format!("mise exec {tools} -- {cmd}")
    }
}
