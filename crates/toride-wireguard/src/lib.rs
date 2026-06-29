//! `toride-wireguard` -- WireGuard VPN tunnel management library.
//!
//! Provides interface configuration, peer lifecycle management, key generation,
//! and diagnostic checks for WireGuard tunnels on Linux servers.
//!
//! # Architecture
//!
//! The core modules are always compiled:
//!
//! - [`error`] -- unified error type and [`Result`] alias
//! - [`paths`] -- WireGuard system path layout (`/etc/wireguard/`)
//! - [`spec`] -- data types describing interfaces and peers
//! - [`parse`] -- parsers for `wg show` and INI config files
//! - [`render`] -- INI config rendering
//! - [`validate`] -- input validation for names, addresses, ports
//! - [`diff`] -- config diffing via `similar`
//! - [`backup`] -- config file backup and restore
//! - [`net`] -- network interface helpers
//! - [`peer`] -- peer management types
//! - [`key`] -- key generation with `zeroize` hygiene
//! - [`report`] -- diagnostic and status reports
//!
//! Feature-gated modules extend the core:
//!
//! - `client` -- [`client::WireguardClient`] wrapping `wg` CLI
//! - `service` -- `wg-quick` service management via `toride-service`
//! - `doctor` -- tunnel health diagnostics
//! - `config` -- full INI config read/write
//! - `cli` -- clap argument definitions

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![expect(
    clippy::must_use_candidate,
    reason = "constructors and getters are obvious"
)]
#![expect(clippy::missing_errors_doc, reason = "library is internal")]
#![expect(clippy::doc_markdown, reason = "WireGuard is a well-known name")]

// ---------------------------------------------------------------------------
// Always-on core modules
// ---------------------------------------------------------------------------

/// Config file backup and restore.
pub mod backup;
/// Config diffing via the `similar` crate.
pub mod diff;
/// Unified error type and [`Result`] alias.
pub mod error;
/// Key generation with `zeroize` hygiene.
pub mod key;
/// Network interface helpers.
pub mod net;
/// Parsers for `wg show`, `wg showconf`, and INI config files.
pub mod parse;
/// WireGuard system path layout.
pub mod paths;
/// Peer management types.
pub mod peer;
/// INI config rendering for interface and peer entries.
pub mod render;
/// Diagnostic and status reports.
pub mod report;
/// Data types for WireGuard interfaces and peers.
pub mod spec;
/// Input validation for interface names, addresses, and ports.
pub mod validate;

// ---------------------------------------------------------------------------
// Feature-gated modules
// ---------------------------------------------------------------------------

/// WireGuard client wrapping `wg` CLI commands.
#[cfg(feature = "client")]
pub mod client;

/// `wg-quick` service management via `toride-service`.
#[cfg(feature = "service")]
pub mod service;

/// Tunnel health diagnostics.
#[cfg(feature = "doctor")]
pub mod doctor;

/// Full INI config file read/write.
#[cfg(feature = "config")]
pub mod config;

/// Clap argument definitions for the CLI.
#[cfg(feature = "cli")]
pub mod cli;

// ---------------------------------------------------------------------------
// Re-exports
// ---------------------------------------------------------------------------

pub use error::{Error, Result};
