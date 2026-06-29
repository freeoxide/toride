//! Test support utilities for ufw-kit.
//!
//! Provides helpers for writing tests against ufw-kit without
//! requiring a real UFW installation.

pub mod fixtures;

// Re-export command types
pub use ufw_kit::command::{CommandLog, CommandRunner, FakeRunner, redact_args};

// Re-export spec types for convenience
pub use ufw_kit::spec::{
    Action, Address, AppDefaultPolicy, AppPort, ApplyReport, BackupBundle, DeleteOptions,
    Direction, DisableOptions, DoctorScope, EnableOptions, Finding, FrameworkRuleBlock,
    ListeningPort, LoggingLevel, ParsedRule, Policy, PortSpec, Protocol, ProtocolFilter,
    ResetOptions, RouteRuleSpec, RuleLogging, RulePosition, RuleSpec, RuleTarget, Severity,
    SshCheckResult, UfwConf, UfwConfig, UfwReport, UfwStatus,
};

// Re-export paths
pub use ufw_kit::paths::UfwPaths;

// Re-export presets
pub use ufw_kit::presets::Preset;

// Re-export NAT types
pub use ufw_kit::nat::{ForwardPolicy, ForwardSpec, IpVersion, MasqueradeSpec, NatApplyResult};

// Re-export firewall inspection types
pub use ufw_kit::firewall::FirewallInspection;

// Re-export diff types
pub use ufw_kit::diff::{FileDiff, FirewallDiff};

// Re-export error types
pub use ufw_kit::error::{Error, Result};

/// Helper to create a fake UFW status response.
pub fn fake_status_response(active: bool, rules: &[&str]) -> String {
    if active {
        let mut out = "Status: active\n\nTo                         Action      From\n--                         ------      ----\n".to_string();
        for rule in rules {
            out.push_str(rule);
            out.push('\n');
        }
        out
    } else {
        "Status: inactive\n".to_string()
    }
}

/// Helper to create a fake UFW version response.
pub fn fake_version_response(version: &str) -> String {
    format!("ufw {version}\nCopyright (C) 2024 Canonical Ltd.\n")
}
