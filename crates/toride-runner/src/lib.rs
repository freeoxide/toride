//! # toride-runner
//!
//! Shared command runner trait, implementations, and utilities.
//!
//! This crate provides:
//!
//! - A sync [`Runner`] trait for executing commands
//! - An async `AsyncRunner` trait (feature `tokio-runner`)
//! - [`CommandSpec`] for describing commands to run
//! - Spec-level policy knobs ([`EnvPrecedence`], [`PathResolution`],
//!   [`ArgvPolicy`], [`OutputCap`], [`TimeoutPolicy`]) for embedder
//!   security postures
//! - [`CommandOutput`] for capturing results
//! - Argument redaction for sensitive flags
//! - Binary discovery helpers
//! - A real sync implementation via `duct` (feature `duct-runner`)
//! - A real async implementation via `tokio::process` (feature `tokio-runner`)
//! - Real-time output streaming (feature `stream`, implies `tokio-runner`)
//! - A fake implementation for testing (feature `fake`)
//!
//! ## Quick start (sync)
//!
//! ```rust
//! # #[cfg(feature = "duct-runner")]
//! # {
//! use toride_runner::{CommandSpec, DuctRunner, Runner};
//!
//! let runner = DuctRunner;
//! let spec = CommandSpec::new("echo").arg("hello");
//! let output = runner.run(&spec).unwrap();
//! assert!(output.success);
//! assert_eq!(output.stdout_trimmed(), "hello");
//! # }
//! ```
//!
//! ## Quick start (async)
//!
//! ```rust
//! # #[cfg(feature = "tokio-runner")]
//! # #[tokio::main]
//! # async fn main() {
//! use toride_runner::{CommandSpec, tokio_runner::TokioRunner, AsyncRunner};
//!
//! let runner = TokioRunner;
//! let spec = CommandSpec::new("echo").arg("hello");
//! let output = runner.run(&spec).await.unwrap();
//! assert!(output.success);
//! assert_eq!(output.stdout_trimmed(), "hello");
//! # }
//! # #[cfg(not(feature = "tokio-runner"))]
//! # fn main() {}
//! ```
//!
//! ## Feature map
//!
//! | Feature | Enables |
//! |---|---|
//! | `duct-runner` (default) | `DuctRunner`, `ConfiguredDuctRunner`, `DuctRunnerOptions`, `DuctRunnerBuilder` |
//! | `tokio-runner` | `TokioRunner`, `ConfiguredTokioRunner`, `TokioRunnerOptions`, `TokioRunnerBuilder`, `AsyncRunner` |
//! | `stream` (implies `tokio-runner`) | `AsyncStreamingRunner`, `CommandEvent`, `CommandEventSink` |
//! | `fake` | `FakeRunner` |
//! | `serde` | serde `Serialize`/`Deserialize` on [`CommandSpec`], [`CommandOutput`], and the policy enums |
//!
//! # Capability matrix
//!
//! Four execution backends share one spec type. Every row below names the
//! runner it describes; "✓" means supported, "✗" means rejected with an
//! error, "—" means not applicable to that backend.
//!
//! | Capability | `DuctRunner` (feature `duct-runner`) | `TokioRunner` (feature `tokio-runner`) | Streaming Tokio (feature `stream`) | `FakeRunner` (feature `fake`) |
//! |---|---|---|---|---|
//! | Traits implemented | sync `Runner` (unit struct + configured) | async `AsyncRunner` (unit struct + configured) | `AsyncStreamingRunner` on both the unit and configured Tokio runners | sync `Runner` + async `AsyncRunner` (feature `tokio-runner`) |
//! | Captured output (`OutputMode::Capture`) | ✓ default; separate stdout/stderr, exit code, `success` | ✓ identical semantics | ✓ live events plus a final aggregated `CommandOutput` | ✓ canned responses returned as-is |
//! | Inherited stdio (`OutputMode::Inherit`) | ✓ child writes to the parent's stdio; captured strings come back empty, exit code is real | ✓ identical semantics | — `run_streaming` always pipes both streams so events can flow | recorded in exact matching; nothing is spawned, so the mode is matched, not acted on |
//! | `OutputMode::Stream` passed to `run` | ✗ rejected with `Error::Other`; use the streaming runner | ✗ rejected identically | streaming is selected by calling `run_streaming`, not by the mode; every mode streams | never rejected — no spawn happens |
//! | Checked execution (`run_checked`) | ✓ default trait method; failure yields `Error::CommandFailed` with redacted args and scrubbed stderr | ✓ identical | ✓ via the inherited default, which resolves through the captured `run` path — streaming callers check `output.success` on the aggregate | ✓ on both implemented traits |
//! | Timeouts | ✓ `CommandSpec::timeout` under `TimeoutPolicy` control; runner default 60 s, removable per runner (`no_default_timeout`); on expiry the child is killed and reaped | ✓ identical (async mirror of the same options) | ✓ same resolution; the unit runner uses the 60 s default, the configured runner uses its `default_timeout` | not enforced; `timeout` and `timeout_policy` are excluded from exact matching (runtime policy) |
//! | Env manipulation | ✓ `env` add, `env_remove`, `clear_env`, `env_precedence`, `cwd` | ✓ identical | ✓ identical (shared env policy) | matched exactly in `respond`; never applied to any process |
//! | stdin | ✓ `stdin` (UTF-8), `stdin_bytes` (raw, wins over `stdin`), `stdin_null`; a write failure (child exits before reading) yields `Error::StdinFailed` after kill-and-reap | ✓ identical via the shared write helper | ✓ identical via the same helper | `stdin`/`stdin_bytes`/`stdin_null` matched; nothing is written |
//! | Output limits | ✓ enforced *while* capturing on combined stdout+stderr bytes; child killed and reaped on breach; ignored under `Inherit` | ✓ identical | ✓ the cap counts both streams' bytes mid-stream | not enforced; `output_limit` and `output_cap` excluded from matching |
//! | Lossy UTF-8 output | ✓ captured bytes decoded with `from_utf8_lossy` | ✓ identical | ✓ chunks carry raw bytes; lines and the final aggregate are lossy-decoded | canned strings returned verbatim |
//! | Redaction | ✓ errors and captured output honor `spec.redact`; runner log lines redact by default (`redact_logs`, default `true`) | ✓ identical | ✓ chunks, lines, and the aggregate scrubbed under `spec.redact`; the span display is log-redacted | `redact` flag matched; nothing to scrub |
//! | Diagnostics | ✓ INFO `command` span wraps success and failure; DEBUG completion event with a sanitized env summary; both off with `log_commands(false)` | ✓ identical (plus a log-redacted `command` field on the completion event) | ✓ span only — the streaming path has no completion event | silent by construction |
//! | Cleanup on timeout / cap breach / stdin failure | ✓ kill and reap the direct child | ✓ identical, plus `kill_on_drop` guards future cancellation | ✓ identical | — no process exists |
//! | Pre-spawn gates | ✓ `ArgvPolicy` argv validation, `PathResolution` program resolution | ✓ identical | ✓ identical | not applied; `argv_policy`/`output_cap` are not even matched |
//!
//! Intentional differences, so nobody hunts them as bugs:
//!
//! - The two real runners are option-mirrored (`DuctRunnerOptions` /
//!   `TokioRunnerOptions` carry the same three fields with the same
//!   defaults); the unit structs simply run with the default options.
//! - `FakeRunner` is a replay device, not an executor: it never spawns, so
//!   process behavior (env wiring, stdio, kill-and-reap, caps, log emission)
//!   is out of its scope by design.
//! - There is no sync streaming implementation; both captured paths reject
//!   `OutputMode::Stream` and point at the Tokio streaming runner.
//!
//! # Examples
//!
//! ## Captured output
//!
//! ```rust
//! # #[cfg(feature = "duct-runner")]
//! # {
//! use toride_runner::{CommandSpec, DuctRunner, Runner};
//!
//! let output = DuctRunner
//!     .run(&CommandSpec::new("echo").arg("hello"))
//!     .unwrap();
//! assert!(output.success);
//! assert_eq!(output.exit_code, Some(0));
//! assert_eq!(output.stdout_trimmed(), "hello");
//! # }
//! ```
//!
//! ## Inherited stdio
//!
//! With `OutputMode::Inherit` the child writes straight to the parent's
//! stdout/stderr; the captured strings come back empty and the exit code is
//! still real.
//!
//! ```rust
//! # #[cfg(feature = "duct-runner")]
//! # {
//! use toride_runner::{CommandSpec, DuctRunner, OutputMode, Runner};
//!
//! let spec = CommandSpec::new("echo")
//!     .arg("doc-test-inherit")
//!     .output_mode(OutputMode::Inherit);
//! let output = DuctRunner.run(&spec).unwrap();
//! assert!(output.success);
//! assert_eq!(output.stdout, "");
//! # }
//! ```
//!
//! ## Checked execution
//!
//! [`Runner::run_checked`] turns a non-zero exit into an
//! [`Error::CommandFailed`] instead of
//! returning an unsuccessful output.
//!
//! ```rust
//! # #[cfg(feature = "duct-runner")]
//! # {
//! use toride_runner::{CommandSpec, DuctRunner, Error, Runner};
//!
//! let ok = DuctRunner
//!     .run_checked(&CommandSpec::new("echo").arg("hi"))
//!     .unwrap();
//! assert!(ok.success);
//!
//! match DuctRunner.run_checked(&CommandSpec::new("false")) {
//!     Err(Error::CommandFailed { exit_code, .. }) => assert_eq!(exit_code, Some(1)),
//!     other => panic!("expected CommandFailed, got {other:?}"),
//! }
//! # }
//! ```
//!
//! ## Custom timeout
//!
//! [`CommandSpec::timeout`] bounds one command; on expiry the child is
//! killed, reaped, and [`Error::CommandTimeout`] is returned.
//!
//! ```rust
//! # #[cfg(feature = "duct-runner")]
//! # {
//! use std::time::Duration;
//! use toride_runner::{CommandSpec, DuctRunner, Error, Runner};
//!
//! let spec = CommandSpec::new("sleep")
//!     .arg("10")
//!     .timeout(Duration::from_millis(100));
//! match DuctRunner.run(&spec) {
//!     Err(Error::CommandTimeout { timeout, .. }) => {
//!         assert_eq!(timeout, Duration::from_millis(100));
//!     }
//!     other => panic!("expected CommandTimeout, got {other:?}"),
//! }
//! # }
//! ```
//!
//! [`TimeoutPolicy`] refines how a spec timeout meets the runner default:
//! `SpecOrRunnerDefault` (the default) keeps the historical resolution,
//! `Never` disables timeouts for that command, and `Explicit` pins an exact
//! duration overriding both other sources.
//!
//! ## No default timeout via a configured runner
//!
//! Both real runners default to a 60 s fallback timeout. A configured
//! runner can drop that default so specs without their own timeout run to
//! natural exit.
//!
//! ```rust
//! # #[cfg(feature = "duct-runner")]
//! # {
//! use toride_runner::{CommandSpec, DuctRunner, Runner};
//!
//! let runner = DuctRunner::builder().no_default_timeout().build();
//! assert!(runner.options().default_timeout.is_none());
//!
//! // No spec timeout either — this command finishes on its own:
//! let output = runner.run(&CommandSpec::new("echo").arg("done")).unwrap();
//! assert!(output.success);
//! # }
//! ```
//!
//! ## Additive environment variables
//!
//! ```rust
//! # #[cfg(feature = "duct-runner")]
//! # {
//! use toride_runner::{CommandSpec, DuctRunner, Runner};
//!
//! let spec = CommandSpec::new("env").env("TORIDE_DOC_VAR", "added");
//! let output = DuctRunner.run(&spec).unwrap();
//! assert!(output.stdout.contains("TORIDE_DOC_VAR=added"));
//! # }
//! ```
//!
//! ## Removing environment variables
//!
//! ```rust
//! # #[cfg(feature = "duct-runner")]
//! # {
//! use toride_runner::{CommandSpec, DuctRunner, Runner};
//!
//! let spec = CommandSpec::new("/bin/sh")
//!     .args(["-c", "printf '%s' \"${HOME-unset}\""])
//!     .env_remove("HOME");
//! let output = DuctRunner.run(&spec).unwrap();
//! assert_eq!(output.stdout, "unset");
//! # }
//! ```
//!
//! Which side wins when `env` and `env_remove` name the same key is decided
//! by [`EnvPrecedence`] (`ExplicitWins` by default, `RemoveWins` to flip).
//!
//! ## Clean environment — and the Unix `PATH` footgun
//!
//! `clear_env(true)` starts the child from an empty environment (plus a
//! minimal platform set on Windows) before applying `spec.env`. On Unix the
//! preserved set is empty, so **the child ends up with no `PATH`** while the
//! default [`PathResolution::OsSearch`] passes the program string through
//! verbatim — a bare program name then depends on the parent-side OS
//! search, and anything the child looks up on `PATH` itself fails. Use one
//! of the three mitigations: an **absolute program path** (as below), an
//! **explicit `PATH` entry** via `.env("PATH", ...)`, or
//! [`PathResolution::ChildEnvNoCwd`], which resolves against the composed
//! child environment (falling back to the parent's `PATH`) and refuses
//! `.`/`..` programs.
//!
//! ```rust
//! # #[cfg(feature = "duct-runner")]
//! # {
//! use toride_runner::{CommandSpec, DuctRunner, Runner};
//!
//! // Absolute /bin/sh: the spawn does not depend on any PATH lookup.
//! let spec = CommandSpec::new("/bin/sh")
//!     .args(["-c", "printf '%s:%s' \"${HOME-unset}\" \"$TORIDE_DOC_KEEP\""])
//!     .clear_env(true)
//!     .env("TORIDE_DOC_KEEP", "kept");
//! let output = DuctRunner.run(&spec).unwrap();
//! assert_eq!(output.stdout, "unset:kept");
//! # }
//! ```
//!
//! ## Redaction
//!
//! With `spec.redact(true)`, sensitive flag values are replaced with `***`
//! in error variants, captured output, and displays — never in the argv the
//! child actually receives. Runner **log lines** redact by default
//! (`redact_logs`, default `true` on both real runners) even for specs that
//! did not opt in; error variants always honor `spec.redact` alone.
//!
//! ```rust
//! # #[cfg(feature = "duct-runner")]
//! # {
//! use toride_runner::display::display_command_for_log;
//! use toride_runner::{CommandSpec, DuctRunner, Error, Runner};
//!
//! // Error variants honor spec.redact:
//! let spec = CommandSpec::new("false")
//!     .args(["--token", "secret-value"])
//!     .redact(true);
//! match DuctRunner.run_checked(&spec) {
//!     Err(Error::CommandFailed { args, .. }) => {
//!         assert!(args.contains("***"));
//!         assert!(!args.contains("secret-value"));
//!     }
//!     other => panic!("expected CommandFailed, got {other:?}"),
//! }
//!
//! // Log displays redact by default, even without spec.redact:
//! let plain = CommandSpec::new("curl").args(["--token", "secret-value"]);
//! let displayed = display_command_for_log(&plain, true);
//! assert!(displayed.contains("***"));
//! assert!(!displayed.contains("secret-value"));
//! # }
//! ```
//!
//! See the [`display`] module for `display_command`,
//! `display_env`, and the env-summary helper behind the runner log events.
//!
//! ## Output limits
//!
//! [`CommandSpec::output_limit`] caps combined captured stdout+stderr
//! *while* capturing: the child is killed and reaped the moment the byte
//! cap is breached and [`Error::OutputLimitExceeded`] is returned — no
//! partial output, no unbounded buffering. [`OutputCap::Always`] forces a
//! cap regardless of the per-spec field.
//!
//! ```rust
//! # #[cfg(feature = "duct-runner")]
//! # {
//! use toride_runner::{CommandSpec, DuctRunner, Error, Runner};
//!
//! let spec = CommandSpec::new("bash")
//!     .args(["-c", "for i in $(seq 1 100); do echo line; done"])
//!     .output_limit(64);
//! match DuctRunner.run(&spec) {
//!     Err(Error::OutputLimitExceeded { limit, .. }) => assert_eq!(limit, 64),
//!     other => panic!("expected OutputLimitExceeded, got {other:?}"),
//! }
//! # }
//! ```
//!
//! # Output encoding: lossy UTF-8
//!
//! Every real runner decodes captured stdout/stderr with
//! `String::from_utf8_lossy`: invalid byte sequences become U+FFFD
//! (REPLACEMENT CHARACTER) and the surrounding bytes are preserved, so a
//! child emitting mixed binary/text never fails the run. This is lossy by
//! design and is the crate's contract for [`CommandOutput`]:
//!
//! - Output caps are accounted in **bytes** and enforced *before* any
//!   decoding, so a cap decision never depends on UTF-8 boundaries.
//! - [`CommandSpec::stdin_bytes`] can carry non-UTF-8 payloads *into* the
//!   child intact; what the child echoes *back* is still captured lossily.
//! - On the streaming path, `CommandEvent::StdoutChunk`/`StderrChunk`
//!   deliver the **raw bytes** untouched; `StdoutLine`/`StderrLine` events
//!   and the final aggregate `CommandOutput` are lossy-decoded.
//!
//! Raw-byte captured output (a bytes-typed `CommandOutput`) is deliberately
//! deferred: there is no caller need for it, and re-typing existing public
//! fields would be a double break (see the deferred-work tracker).
//!
//! # Cleanup policy: direct child only
//!
//! On timeout, output-limit breach, and stdin-write failure, both real
//! runners **kill and reap the direct child** — kill first, then wait, so no
//! zombie is left behind — before returning the corresponding error
//! (`Error::CommandTimeout`, `Error::OutputLimitExceeded`,
//! `Error::StdinFailed`).
//!
//! This cleanup is **direct-child-only** by supported policy:
//!
//! - Grandchildren — processes the child spawns — survive a kill. Killing
//!   a process tree (Unix process groups with `killpg`, Windows job
//!   objects) is out of scope and stays deferred until a real call site
//!   demonstrates grandchild survival as a bug.
//! - A grandchild holding an inherited pipe end cannot hang the runner
//!   forever: reader/writer threads that outlive the reaped child are
//!   detached after a bounded wait (Duct), and the streaming stderr task
//!   is aborted on a cap breach (Tokio).
//! - On the Tokio paths, `kill_on_drop` additionally SIGKILLs the direct
//!   child if the caller drops (cancels) the run future mid-flight — again
//!   best-effort for the direct child only.
//!
//! The same policy is documented next to the implementation in
//! `duct_runner` and `tokio_runner`.
//!
//! # Diagnostics
//!
//! With `log_commands` enabled (the default on both real runners):
//!
//! - an INFO tracing span named `command` (fields: `program`, `command` —
//!   the log-redacted display) wraps the *entire* execution, success and
//!   every failure path alike, on all real-runner paths including
//!   streaming;
//! - a DEBUG completion event fires on both captured paths when the child
//!   exits, carrying the exit code, the log-redacted command display, and
//!   — when the spec sets explicit env vars — a sanitized env summary in
//!   which sensitive values are `***` regardless of `spec.redact`. The
//!   streaming path has no completion event; its span wraps the session.
//!
//! `log_commands(false)` is the single diagnostics switch: it disables both
//! the span and the events. Log displays honor `redact_logs` (default
//! `true`); error variants honor `spec.redact` alone.
//!
//! # Shell execution: not offered
//!
//! `CommandSpec` carries direct argv only — there is no shell opt-in and
//! there never will be. A shell command string would re-introduce, in one
//! field, the injection risk the argv model exists to prevent, and its
//! free-form text cannot be token-redacted. The crate ships the inverse
//! posture: [`ArgvPolicy::RejectShellMetachars`] refuses shell syntax in
//! argv before spawn, and a caller who genuinely needs shell features
//! writes `CommandSpec::new("bash").args(["-c", script])`, keeping that
//! decision visible in code review. This is a recorded ruling, not an
//! omission — see the [`policy`] module docs.
//!
//! # `FakeRunner` semantics
//!
//! `FakeRunner` (feature `fake`) replays canned responses in FIFO order or
//! by exact spec match, records every call, and is lenient by default
//! (unmatched calls succeed with empty output; `.strict()` turns that into
//! an error). Exact matching compares command *construction* — program,
//! args, `stdin`, `stdin_bytes`, `stdin_null`, env, `env_remove`,
//! `clear_env`, `cwd`, `output_mode`, `redact`, `env_precedence`,
//! `path_resolution` — and excludes runtime policy (`timeout`,
//! `timeout_policy`, `output_limit`, `argv_policy`, `output_cap`). See the
//! [`fake`] module.

#![deny(unsafe_code)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::module_name_repetitions)]

pub mod discovery;
pub mod display;
pub mod error;
pub mod output;
pub mod output_mode;
pub mod policy;
pub mod redact;
pub mod runner;
pub mod spec;

#[cfg(feature = "duct-runner")]
pub mod duct_runner;

#[cfg(feature = "fake")]
pub mod fake;

#[cfg(feature = "tokio-runner")]
pub mod async_runner;

#[cfg(feature = "tokio-runner")]
pub mod tokio_runner;

#[cfg(feature = "stream")]
pub mod streaming;

#[cfg(all(test, feature = "duct-runner", feature = "tokio-runner"))]
mod parity_tests;

#[cfg(all(test, feature = "stream"))]
mod streaming_tests;

// Re-export primary types at crate root.
#[cfg(feature = "tokio-runner")]
pub use async_runner::AsyncRunner;
#[cfg(feature = "duct-runner")]
pub use duct_runner::{ConfiguredDuctRunner, DuctRunner, DuctRunnerBuilder, DuctRunnerOptions};
pub use error::{Error, Result};
#[cfg(feature = "fake")]
pub use fake::FakeRunner;
pub use output::CommandOutput;
pub use output_mode::OutputMode;
pub use policy::{ArgvPolicy, EnvPrecedence, OutputCap, PathResolution, TimeoutPolicy};
pub use runner::Runner;
pub use spec::CommandSpec;
#[cfg(feature = "stream")]
pub use streaming::{AsyncStreamingRunner, CommandEvent, CommandEventSink};
#[cfg(feature = "tokio-runner")]
pub use tokio_runner::{
    ConfiguredTokioRunner, TokioRunner, TokioRunnerBuilder, TokioRunnerOptions,
};
