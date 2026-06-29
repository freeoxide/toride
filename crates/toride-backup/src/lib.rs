//! Backup scheduling and management library for toride.
//!
//! Provides backup repository management, scheduling, restore testing, and
//! integrity checking via [restic] or [Borg Backup] backends.
//!
//! [restic]: https://restic.net/
//! [Borg Backup]: https://www.borgbackup.org/
//!
//! # High-level API
//!
//! The [`BackupClient`] struct is the main entry point when the `client`
//! feature is enabled. It composes a command runner, system paths, and
//! delegates to sub-modules for backup operations, restore workflows,
//! scheduling, and doctor diagnostics.
//!
//! ```ignore
//! use toride_backup::BackupClient;
//!
//! let client = BackupClient::system()?;
//! client.init_repository("/mnt/backups/my-server")?;
//! let report = client.backup(&spec)?;
//! let doctor_report = client.doctor(toride_backup::doctor::DoctorScope::All)?;
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![expect(
    clippy::must_use_candidate,
    reason = "constructors and getters are obvious"
)]
#![expect(clippy::missing_errors_doc, reason = "library is internal")]
#![cfg_attr(
    test,
    expect(
        clippy::needless_raw_string_hashes,
        reason = "test code tolerates stricter lint patterns"
    )
)]

// ---------------------------------------------------------------------------
// Module declarations -- always compiled
// ---------------------------------------------------------------------------

pub mod borg;
pub mod error;
pub mod parse;
pub mod paths;
pub mod render;
pub mod report;
pub mod restic;
pub mod restore;
pub mod schedule;
pub mod spec;
pub mod systemd;
pub mod validate;

// ---------------------------------------------------------------------------
// Module declarations -- feature-gated
// ---------------------------------------------------------------------------

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "service")]
pub mod service;

#[cfg(feature = "doctor")]
pub mod doctor;

#[cfg(feature = "config")]
pub mod config;

#[cfg(feature = "cli")]
pub mod cli;

// ---------------------------------------------------------------------------
// Error types -- re-exported from the `error` module (unified source of truth)
// ---------------------------------------------------------------------------

pub use error::{Error, Result};
