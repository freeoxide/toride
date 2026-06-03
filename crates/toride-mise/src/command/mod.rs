//! Command adapter layer for the toride-mise crate.
//!
//! This module provides a thin abstraction over [`toride_runner::CommandSpec`]
//! construction and error mapping so that the rest of the crate does not need
//! to import `toride_runner` directly.
//!
//! - [`adapter`] — builds [`CommandSpec`] values and parses JSON output.
//! - [`mapping`] — converts [`toride_runner::Error`] into [`MiseError`](crate::MiseError).

pub mod adapter;
pub mod mapping;

// Re-export the public API of the sub-modules so that callers can write
// `toride_mise::command::build_spec(…)` without knowing the internal split.
pub use adapter::{build_mise_args, build_spec, parse_json_output};
pub use mapping::map_runner_error;
