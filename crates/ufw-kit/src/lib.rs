//! # ufw-kit
//!
//! <!-- clippy allows for pedantic doc lints — these are fine for an early-stage crate -->
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::collapsible_if)]
//!
//! Safely manage, inspect, validate, and diagnose UFW firewall installations.
//!
//! This is a **library crate** — not a CLI, not a firewall replacement.
//! Other Rust applications embed it to orchestrate UFW through a typed,
//! idempotent, dry-run-capable API.
//!
//! ## Quick start
//!
//! ```rust,no_run,ignore
//! use ufw_kit::Ufw;
//!
//! let ufw = Ufw::system();
//! let status = ufw.status().unwrap();
//! println!("UFW is {}", if status.active { "active" } else { "inactive" });
//! ```

pub mod command;
pub mod error;
pub mod spec;
pub mod rule;
pub mod status;
pub mod net;
pub mod paths;
pub mod diff;
pub mod backup;
pub mod report;
pub mod config;
pub mod firewall;
pub mod presets;

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "doctor")]
pub mod doctor;

#[cfg(feature = "app-profile")]
pub mod app_profile;

#[cfg(feature = "framework")]
pub mod framework;

#[cfg(feature = "service")]
pub mod service;

#[cfg(test)]
#[path = "snapshots.test.rs"]
mod snapshot_tests;

// Re-export the primary entry point at crate root.
#[cfg(feature = "client")]
pub use client::Ufw;
pub use error::{Error, Result};
pub use spec::*;
