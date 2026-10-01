//! Outbound traffic monitoring and anomaly detection for toride: iptables
//! OUTPUT logging, conntrack/`ss` parsing, anomaly heuristics, alert dispatch.

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![expect(
    clippy::must_use_candidate,
    reason = "constructors and getters are obvious"
)]

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

pub use error::{Error, Result};
