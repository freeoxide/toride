//! # ufw-kit
//!
//! Library crate for safely managing, inspecting, validating, and diagnosing
//! UFW installations through a typed, idempotent, dry-run-capable API.
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::collapsible_if)]

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

#[cfg(all(test, feature = "client", feature = "doctor"))]
pub mod spawn_oracle;

#[cfg(feature = "client")]
pub use client::Ufw;
pub use error::{Error, Result};
pub use spec::*;
