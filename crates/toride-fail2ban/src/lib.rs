//! Fail2ban-style intrusion prevention library for toride.
//!
//! Provides log parsing, IP banning, and automated response capabilities
//! with support for iptables, nftables, pf, and firewalld backends.

#![expect(clippy::must_use_candidate, reason = "constructors and getters are obvious")]
#![expect(clippy::missing_errors_doc, reason = "library is internal")]
#![expect(clippy::doc_markdown, reason = "Fail2Ban is a well-known name")]
#![cfg_attr(
    test,
    allow(
        clippy::needless_raw_string_hashes,
        clippy::uninlined_format_args,
        clippy::clone_on_copy,
        clippy::items_after_statements,
        clippy::too_many_lines,
        clippy::cast_possible_truncation,
        clippy::redundant_closure_for_method_calls,
        clippy::needless_pass_by_value,
        clippy::useless_conversion,
        clippy::stable_sort_primitive,
        clippy::write_with_newline,
        clippy::no_effect_underscore_binding,
        clippy::op_ref,
        clippy::match_same_arms,
        clippy::collapsible_if
    )
)]

pub mod action;
pub mod ban;
pub(crate) mod cli;
pub mod config;
pub mod detector;
pub mod jail;
pub mod manager;
pub mod paths;
pub mod store;
pub mod support;
pub mod types;

use std::io;
use std::result;

/// Crate-level error enum covering all subsystems.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    // -- I/O subsystem --
    /// I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    // -- Serialization subsystem --
    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    // -- Config subsystem --
    /// Configuration file missing at expected path.
    #[error("Config file not found: {0}")]
    ConfigNotFound(String),

    /// Invalid configuration value.
    #[error("Invalid config value: {0}")]
    InvalidConfig(String),

    // -- Ban subsystem --
    /// Invalid IP address or CIDR notation.
    #[error("Invalid IP or CIDR: {0}")]
    InvalidIp(String),

    /// IP address is already banned.
    #[error("IP already banned: {0}")]
    AlreadyBanned(String),

    /// IP address is not currently banned.
    #[error("IP not banned: {0}")]
    NotBanned(String),

    // -- Log parsing subsystem --
    /// Invalid regular expression pattern.
    #[error("Invalid regex pattern: {0}")]
    InvalidRegex(String),

    /// Log file could not be read.
    #[error("Log file error: {0}")]
    LogFileError(String),

    // -- Action subsystem --
    /// Command execution failed.
    #[error("Command execution failed: {0}")]
    CommandFailed(String),

    // -- Jail subsystem --
    /// Jail with the given name already exists.
    #[error("Jail already exists: {0}")]
    JailAlreadyExists(String),

    /// Jail with the given name not found.
    #[error("Jail not found: {0}")]
    JailNotFound(String),
}

/// Crate-level result alias.
pub type Result<T> = result::Result<T, Error>;
