//! # toride-runner
//!
//! Shared command runner trait, implementations, and utilities.
//!
//! This crate provides:
//!
//! - A sync [`Runner`] trait for executing commands
//! - An async [`AsyncRunner`] trait (feature `tokio-runner`)
//! - [`CommandSpec`] for describing commands to run
//! - [`CommandOutput`] for capturing results
//! - Argument redaction for sensitive flags
//! - Binary discovery helpers
//! - A real sync implementation via `duct` (feature `duct-runner`)
//! - A real async implementation via `tokio::process` (feature `tokio-runner`)
//! - A fake implementation for testing (feature `fake`)
//!
//! ## Quick start (sync)
//!
//! ```rust,ignore
//! use toride_runner::{CommandSpec, DuctRunner, Runner};
//!
//! let runner = DuctRunner;
//! let spec = CommandSpec::new("echo").arg("hello");
//! let output = runner.run(&spec)?;
//! assert!(output.success);
//! ```
//!
//! ## Quick start (async)
//!
//! ```rust,ignore
//! use toride_runner::{CommandSpec, tokio_runner::TokioRunner, AsyncRunner};
//!
//! let runner = TokioRunner;
//! let spec = CommandSpec::new("echo").arg("hello");
//! let output = runner.run(&spec).await?;
//! assert!(output.success);
//! ```

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
pub use duct_runner::DuctRunner;
pub use error::{Error, Result};
#[cfg(feature = "fake")]
pub use fake::FakeRunner;
pub use output::CommandOutput;
pub use output_mode::OutputMode;
pub use runner::Runner;
#[cfg(feature = "stream")]
pub use streaming::{AsyncStreamingRunner, CommandEvent, CommandEventSink};
pub use spec::CommandSpec;
