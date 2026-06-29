//! Outbound traffic monitoring and anomaly detection for toride.
//!
//! Provides iptables OUTPUT chain logging, conntrack parsing, anomaly
//! detection heuristics, and alert dispatching for outbound network
//! connections.
//!
//! # High-level API
//!
//! The [`MonitorClient`] struct is the main entry point when the `client`
//! feature is enabled. It composes a command runner and delegates to
//! sub-modules for output chain management, conntrack parsing, anomaly
//! detection, and alert dispatching.
//!
//! ```ignore
//! use toride_monitor::MonitorClient;
//!
//! let client = MonitorClient::system()?;
//! client.setup_logging()?;
//! let report = client.snapshot()?;
//! let anomalies = client.detect_anomalies(&report)?;
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![expect(
    clippy::must_use_candidate,
    reason = "constructors and getters are obvious"
)]

// ---------------------------------------------------------------------------
// Module declarations -- always compiled
// ---------------------------------------------------------------------------

pub mod alert;
pub mod anomaly;
pub mod conntrack;
pub mod error;
pub mod output;
pub mod parse;
pub mod paths;
pub mod ports;
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
// Error types -- re-exported from the `error` module (unified source of truth)
// ---------------------------------------------------------------------------

pub use error::{Error, Result};
