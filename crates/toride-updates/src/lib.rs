//! `toride-updates` — automatic security update management for Linux VPS hosts.
//!
//! Wraps `unattended-upgrades` (Debian/Ubuntu) and `dnf-automatic` (Fedora/RHEL)
//! behind a unified API for configuring, scheduling, and monitoring automatic
//! security updates.
//!
//! # Architecture
//!
//! The crate is organized into several subsystems:
//!
//! - **[`spec`]** -- declarative update specification (`UpdateSpec`)
//! - **[`detect`]** -- package manager detection (`apt` vs `dnf`)
//! - **[`parse`]** -- parsing command output into structured types
//! - **[`render`]** -- rendering specs into config file content
//! - **[`validate`]** -- validating specs and configurations
//! - **[`paths`]** -- resolved filesystem paths for update configs
//! - **[`report`]** -- structured status and diagnostic reports
//! - **[`backup`]** -- pre-mutation config backup
//!
//! Feature-gated subsystems:
//!
//! - **`client`** -- command execution for update operations
//! - **`service`** -- systemd service management
//! - **`doctor`** -- diagnostic health checks
//! - **`config`** -- config file read/write
//! - **`apt`** -- Debian/Ubuntu-specific backend
//! - **`dnf`** -- Fedora/RHEL-specific backend
//! - **`schedule`** -- systemd timer / cron schedule management
//! - **`cli`** -- command-line argument parsing

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![expect(dead_code, reason = "scaffolding for modules under active development")]
#![expect(
    clippy::must_use_candidate,
    reason = "constructors and getters are obvious"
)]
#![expect(clippy::missing_errors_doc, reason = "library is internal")]

// ---------------------------------------------------------------------------
// Module declarations -- always compiled
// ---------------------------------------------------------------------------

/// Pre-mutation config file backup.
pub mod backup;
/// Package manager detection (apt vs dnf).
pub mod detect;
/// Error types for the crate.
pub mod error;
/// Parsers for command output (unattended-upgrades, apt-check, dnf).
pub mod parse;
/// Resolved filesystem paths for update configuration files.
pub mod paths;
/// Config file renderers (auto-upgrades, dnf-automatic, apt).
pub mod render;
/// Structured status reports and diagnostic findings.
pub mod report;
/// Declarative update specification types.
pub mod spec;
/// Spec and configuration validation.
pub mod validate;

// ---------------------------------------------------------------------------
// Module declarations -- feature-gated
// ---------------------------------------------------------------------------

/// Client for executing update commands.
#[cfg(feature = "client")]
pub mod client;

/// Service management for unattended-upgrades / dnf-automatic.
#[cfg(feature = "service")]
pub mod service;

/// Doctor checks for update subsystem health.
#[cfg(feature = "doctor")]
pub mod doctor;

/// Config file read/write with atomic writes.
#[cfg(feature = "config")]
pub mod config;

/// Debian/Ubuntu (APT) specific update backend.
#[cfg(feature = "apt")]
pub mod apt;

/// Fedora/RHEL (DNF) specific update backend.
#[cfg(feature = "dnf")]
pub mod dnf;

/// Systemd timer / cron schedule management.
#[cfg(feature = "schedule")]
pub mod schedule;

/// CLI argument parsing via clap.
#[cfg(feature = "cli")]
pub mod cli;

// ---------------------------------------------------------------------------
// Re-exports
// ---------------------------------------------------------------------------

pub use error::{Error, Result};
pub use spec::UpdateSpec;

/// Re-export of the diagnostic [`toride_diagnostic_types::Finding`] type so
/// downstream crates (notably the `toride` TUI) can name the doctor findings
/// returned by [`doctor::Doctor::run`] WITHOUT taking a direct dependency on
/// `toride-diagnostic-types`. Mirrors `toride-harden`'s re-export of the same
/// types.
#[cfg(feature = "doctor")]
pub use toride_diagnostic_types::Finding;
/// Re-export of the diagnostic [`toride_diagnostic_types::Severity`] enum.
#[cfg(feature = "doctor")]
pub use toride_diagnostic_types::Severity;

/// Re-export of the [`toride_runner::DuctRunner`] constructor type so downstream
/// crates (notably the `toride` TUI) can build a fresh runner for the
/// [`doctor::Doctor::new`] / [`apt::AptBackend::new`] / [`dnf::DnfBackend::new`]
/// / [`service::ServiceManager::new`] / [`schedule::ScheduleManager::new`]
/// constructors (which take `&dyn Runner`) WITHOUT taking a direct dependency
/// on `toride-runner`. Mirrors `toride-harden`'s re-export.
#[cfg(feature = "client")]
pub use toride_runner::DuctRunner;
/// Re-export of the [`toride_runner::Runner`] trait (companion to
/// [`DuctRunner`], needed to name `&dyn Runner` at the call site).
#[cfg(feature = "client")]
pub use toride_runner::Runner;
