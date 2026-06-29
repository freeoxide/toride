//! # toride-harden
//!
//! System hardening via sysctl kernel parameters, shared memory mount restrictions,
//! and kernel security profiles.
//!
//! This crate provides a typed, idempotent, dry-run-capable API for managing
//! Linux kernel security parameters. It supports CIS/STIG benchmark profiles
//! for Desktop, Server, and Router use cases.
//!
//! ## Quick start
//!
//! ```rust,ignore
//! use toride_harden::HardenClient;
//! use toride_harden::profile::HardeningProfile;
//!
//! let client = HardenClient::system();
//! client.apply_profile(&HardeningProfile::Server)?;
//! ```
//!
//! # Module layout
//!
//! - [`sysctl`] — read/write sysctl parameters
//! - [`profile`] — CIS/STIG hardening profiles (Desktop, Server, Router)
//! - [`shm`] — shared memory mount hardening
//! - [`kernel`] — kernel security parameters (ASLR, `kptr_restrict`, etc.)
//! - [`parse`] — parse sysctl output and config files
//! - [`render`] — render sysctl config files
//! - [`validate`] — validate sysctl keys, values, and specs
//! - [`diff`] — diff current vs. desired sysctl state
//! - [`backup`] — pre-mutation backup of sysctl config files
//! - [`report`] — structured report of applied/skipped parameters
//!
//! ## Feature flags
//!
//! | Feature   | Default | Description                              |
//! |-----------|---------|------------------------------------------|
//! | `client`  | yes     | High-level HardenClient                  |
//! | `doctor`  | yes     | Diagnostic checks via toride-doctor      |
//! | `service` | no      | systemd sysctl service integration       |
//! | `config`  | no      | sysctl.d drop-in file parsing/writing    |
//! | `serde`   | no      | Serialize/Deserialize on types           |
//! | `cli`     | no      | clap argument parsing                    |

#![deny(unsafe_code)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::module_name_repetitions)]

// ── Always-available modules ───────────────────────────────────────────

pub mod backup;
pub mod diff;
pub mod error;
pub mod kernel;
pub mod parse;
pub mod paths;
pub mod profile;
pub mod render;
pub mod report;
pub mod shm;
pub mod spec;
pub mod sysctl;
pub mod validate;

// ── Feature-gated modules ──────────────────────────────────────────────

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "doctor")]
pub mod doctor;

#[cfg(feature = "config")]
pub mod config;

#[cfg(feature = "service")]
pub mod service;

#[cfg(feature = "cli")]
pub mod cli;

// ── Crate-level re-exports ─────────────────────────────────────────────

pub use error::{Error, Result};
pub use profile::HardeningProfile;
pub use spec::HardenSpec;

/// Re-export of the diagnostic [`toride_diagnostic_types::Finding`] type so
/// downstream crates (notably the `toride` TUI) can name the doctor findings
/// returned by [`doctor::doctor`] WITHOUT taking a direct dependency on
/// `toride-diagnostic-types`. Mirrors `ufw-kit`'s re-export of the same types
/// from its `spec` module.
#[cfg(feature = "doctor")]
pub use toride_diagnostic_types::Finding;
/// Re-export of the diagnostic [`toride_diagnostic_types::Severity`] enum.
#[cfg(feature = "doctor")]
pub use toride_diagnostic_types::Severity;

/// Re-export of the [`toride_runner::DuctRunner`] constructor type so downstream
/// crates (notably the `toride` TUI) can build a fresh runner for the
/// [`doctor::doctor`] free function WITHOUT taking a direct dependency on
/// `toride-runner`. Mirrors `toride-fail2ban`'s `command::DuctRunner` re-export.
#[cfg(feature = "client")]
pub use toride_runner::DuctRunner;
/// Re-export of the [`toride_runner::Runner`] trait (companion to
/// [`DuctRunner`], needed to name `&dyn Runner` at the call site).
#[cfg(feature = "client")]
pub use toride_runner::Runner;
