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

pub mod backup;
pub mod command;
pub mod config;
pub mod diff;
pub mod docker;
pub mod error;
pub mod firewall;
pub mod nat;
pub mod net;
pub mod paths;
pub mod presets;
pub mod report;
pub mod rule;
pub mod spec;
pub mod status;

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

#[cfg(feature = "firewall-nft")]
pub mod nft;

#[cfg(feature = "firewall-iptables")]
pub mod iptables;

#[cfg(feature = "systemd-zbus")]
pub mod systemd_zbus;

#[cfg(feature = "tokio")]
pub mod async_client;

#[cfg(test)]
#[path = "snapshots.test.rs"]
mod snapshot_tests;

// Re-export the primary entry point at crate root.
#[cfg(feature = "client")]
pub use client::Ufw;
pub use error::{Error, Result};
pub use spec::*;
