//! Configuration file handling for mise.
//!
//! This module provides types and methods for reading, writing, and querying
//! mise configuration files (`~/.config/mise/config.toml` and local `.mise.toml`).
//!
//! - [`model`] — data structures representing mise config (`MiseToml`,
//!   `ConfigWriteResult`, `SettingsEntry`).
//! - [`read`] — read-only operations: `config_ls`, `config_get`, `settings`,
//!   `settings_get`.
//! - [`write`] — mutation operations: `config_set`, `settings_set`,
//!   `settings_unset`.
//! - [`path`] — path resolution: `config_path`.

pub mod model;
pub mod path;
pub mod read;
pub mod write;

// Re-export the public types so callers can write
// `toride_mise::config::MiseToml` without reaching into sub-modules.
pub use model::{ConfigWriteResult, MiseToml, SettingsEntry};
