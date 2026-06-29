//! Cloud provider security group and firewall management for toride.
//!
//! Provides cloud provider detection, security group management, and firewall
//! rule lifecycle management across AWS, GCP, `DigitalOcean`, and Hetzner.
//!
//! # High-level API
//!
//! The [`CloudClient`] struct is the main entry point when the `client` feature
//! is enabled. It composes a command runner and delegates to provider-specific
//! modules for security group operations.
//!
//! # Feature flags
//!
//! | Feature   | Description                              |
//! |-----------|------------------------------------------|
//! | `client`  | Cloud provider client wrappers           |
//! | `doctor`  | Diagnostic engine for cloud resources    |
//! | `service` | Service management for cloud agents      |
//! | `config`  | Configuration parsing and validation     |
//! | `serde`   | Serde serialization for domain types     |
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

pub mod aws;
pub mod detect;
pub mod digitalocean;
pub mod error;
pub mod gcp;
pub mod hetzner;
pub mod parse;
pub mod paths;
pub mod render;
pub mod report;
pub mod spec;
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
// Re-exports
// ---------------------------------------------------------------------------

pub use detect::CloudProvider;
pub use error::{Error, Result};
