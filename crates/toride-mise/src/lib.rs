//! # toride-mise
//!
//! Mise (formerly rtx) integration for toride.
//!
//! This crate provides:
//!
//! - [`Mise`] client for interacting with the mise CLI
//! - [`MiseBuilder`] for constructing configured [`Mise`] instances
//! - [`MiseBinary`] and [`MiseVersion`] for binary discovery
//! - [`ToolSpec`], [`VersionRequest`], and [`ToolOptionValue`] for describing tools
//! - [`MiseProject`] and [`RuntimeManager`] for project-level runtime management
//! - [`MiseMode`] and [`LoadPolicy`] for controlling mise behaviour
//!
//! ## Quick start
//!
//! ```rust,ignore
//! use toride_mise::{Mise, MiseBuilder};
//!
//! let mise = MiseBuilder::new().build()?;
//! let tools = mise.list_installed().await?;
//! ```

#![deny(unsafe_code)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::module_name_repetitions)]

// ---------------------------------------------------------------------------
// Module declarations -- file modules
// ---------------------------------------------------------------------------

pub mod builder;
pub mod capabilities;
pub mod client;
pub mod diagnostics;
pub mod error;
pub mod exec;
pub mod lockfile;
pub mod security;
pub mod streaming;

// ---------------------------------------------------------------------------
// Module declarations -- directory modules
// ---------------------------------------------------------------------------

pub mod binary;
pub mod command;
pub mod config;
pub mod env;
pub mod languages;
pub mod serde_utils;
pub mod tool;

// ---------------------------------------------------------------------------
// Re-exports
// ---------------------------------------------------------------------------

pub use client::{Mise, MiseBuilder, MiseMode, MiseProject, LoadPolicy, RuntimeManager};
pub use capabilities::MiseCapabilities;
pub use error::{MiseError, MiseResult};
pub use diagnostics::DiagnosticsBuilder;
pub use security::SecurityPolicy;
pub use tool::{
    ToolSpec, VersionRequest, ToolOptionValue, ToolAlias, TaskInfo, TaskRunRequest,
    InstallRequest, UseRequest, UseScope,
    UninstallRequest, UnuseRequest,
    OutdatedTool, UpgradeRequest,
    PrunePlan, PruneRequest,
    ListRemoteRequest, RemoteVersion,
    ListToolsRequest, ToolStatus,
    ActiveTool, ListActiveRequest,
    PluginInfo, PluginInstallRequest,
};
pub use binary::{MiseBinary, MiseVersion, BootstrapMethod, BootstrapOptions};
