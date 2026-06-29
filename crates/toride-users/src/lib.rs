//! `toride-users` -- OS-level user, sudo, PAM, and 2FA management.
//!
//! Provides user creation, group management, sudoers configuration, PAM
//! configuration, TOTP/2FA enrollment via `google-authenticator`, and password
//! policy enforcement.
//!
//! # Architecture
//!
//! The always-compiled modules provide the core data types and pure functions:
//!
//! - [`UserSpec`] -- typed specification for user accounts
//! - [`paths::UserPaths`] -- system paths for `/etc/passwd`, `/etc/shadow`, etc.
//! - [`parse`] -- parsing `/etc/passwd`, `/etc/group`, `/etc/sudoers`
//! - [`render`] -- rendering sudoers entries and PAM configuration
//! - [`validate`] -- validation for usernames, shells, and specs
//!
//! When the `client` feature is enabled, [`client::UsersClient`] provides a
//! high-level facade that composes all subsystems.
//!
//! # Feature flags
//!
//! | Feature   | Description                              |
//! |-----------|------------------------------------------|
//! | `client`  | CLI wrapper for `useradd`/`usermod` etc. |
//! | `service` | Service management (implies `client`)    |
//! | `doctor`  | Diagnostic engine (implies `service`)    |
//! | `config`  | Config parsing and rendering             |
//! | `totp`    | TOTP/2FA enrollment (implies `client`)   |
//! | `serde`   | Serde support for specs and reports      |
//! | `cli`     | CLI argument parsing via clap            |

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![expect(
    clippy::must_use_candidate,
    reason = "constructors and getters are obvious"
)]
#![expect(clippy::missing_errors_doc, reason = "library is internal")]

// ---------------------------------------------------------------------------
// Module declarations -- always compiled
// ---------------------------------------------------------------------------

/// Configuration file backup and restore.
pub mod backup;
/// Error types for the crate.
pub mod error;
/// Group management (`groupadd`, `groupdel`, etc.).
pub mod group;
/// PAM (Pluggable Authentication Modules) configuration.
pub mod pam;
/// Parsing `/etc/passwd`, `/etc/group`, and `/etc/sudoers`.
pub mod parse;
/// Password policy enforcement (`chage`, `passwd`).
pub mod password;
/// System paths for user configuration files.
pub mod paths;
/// Rendering sudoers entries and PAM configuration.
pub mod render;
/// Diagnostic report types.
pub mod report;
/// Typed specification for user accounts.
pub mod spec;
/// Sudoers configuration management.
pub mod sudo;
/// TOTP/2FA enrollment via `google-authenticator`.
pub mod totp;
/// User account management (`useradd`, `usermod`, `userdel`).
pub mod user;
/// Validation for usernames, shells, and specs.
pub mod validate;

// ---------------------------------------------------------------------------
// Module declarations -- feature-gated
// ---------------------------------------------------------------------------

/// High-level client facade composing all subsystems.
#[cfg(feature = "client")]
pub mod client;

/// Service management for user-related system daemons.
#[cfg(feature = "service")]
pub mod service;

/// Diagnostic checks for user security (root login, empty passwords, etc.).
#[cfg(feature = "doctor")]
pub mod doctor;

/// Config file read/write operations.
#[cfg(feature = "config")]
pub mod config;

/// CLI argument definitions via clap.
#[cfg(feature = "cli")]
pub mod cli;

// ---------------------------------------------------------------------------
// Re-exports
// ---------------------------------------------------------------------------

pub use error::{Error, Result};
pub use spec::UserSpec;
