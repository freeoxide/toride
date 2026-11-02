//! `toride-tailscale` -- Tailscale mesh VPN management via HTTP API.
//!
//! Provides async access to the Tailscale local HTTP API for status queries,
//! network topology inspection, DNS configuration, ACL management, and
//! connectivity checks.
//!
//! # Architecture
//!
//! The entry point is [`TailscaleClient`], which communicates with the
//! tailscaled LocalAPI over its Unix socket
//! (`/var/run/tailscale/tailscaled.sock`; see [`api`]). It delegates to
//! sub-modules for specific concerns:
//!
//! - [`api`] -- low-level HTTP client for the Tailscale local API
//! - [`status`] -- node status and connection state
//! - [`tailnet`] -- network topology and peer discovery
//! - [`acl`] -- ACL policy management
//! - [`dns`] -- DNS configuration and MagicDNS
//! - [`netcheck`] -- network connectivity and DERP latency
//! - [`service`] -- service lifecycle management
//! - [`doctor`] -- diagnostic checks for Tailscale health
//!
//! # Example
//!
//! ```ignore
//! use toride_tailscale::TailscaleClient;
//!
//! let client = TailscaleClient::new();
//! let status = client.status().await?;
//! println!("Connected as {}", status.name);
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![expect(
    clippy::must_use_candidate,
    reason = "constructors and getters are obvious"
)]
#![expect(clippy::missing_errors_doc, reason = "library is internal")]
#![expect(
    clippy::doc_markdown,
    reason = "Tailscale-specific terms trigger false positives"
)]
// ---------------------------------------------------------------------------
// Module declarations -- always compiled
// ---------------------------------------------------------------------------

pub mod error;
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

#[cfg(feature = "client")]
pub mod api;

/// Typed local-API response documents, the wire types
/// [`crate::api::TailscaleApi`] deserializes into. Unknown fields are
/// ignored and consumed fields default, so both newer and older tailscaled
/// stay parseable.
#[cfg(feature = "client")]
pub mod models;

#[cfg(feature = "client")]
pub mod acl;

#[cfg(feature = "client")]
pub mod tailnet;

#[cfg(feature = "client")]
pub mod status;

#[cfg(feature = "client")]
pub mod netcheck;

#[cfg(feature = "client")]
pub mod dns;

#[cfg(feature = "cli")]
pub mod cli;

// ---------------------------------------------------------------------------
// Error types -- re-exported from the `error` module (unified source of truth)
// ---------------------------------------------------------------------------

pub use error::{Error, Result};

// ---------------------------------------------------------------------------
// Re-exports -- feature-gated
// ---------------------------------------------------------------------------

#[cfg(feature = "client")]
pub use client::TailscaleClient;
