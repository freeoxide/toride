//! Serde deserialization helpers for mise JSON output formats.
//!
//! Each sub-module contains typed `Deserialize` structs that map to the JSON
//! produced by a specific `mise` sub-command. All fields are `Option`-wrapped
//! so that variations across mise versions or configurations are handled
//! gracefully without causing parse failures.

pub mod json_outputs;
