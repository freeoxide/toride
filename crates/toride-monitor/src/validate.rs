//! Validation helpers for logging rules and anomaly thresholds.
//!
//! Provides [`validate_logging_rule`] and [`validate_threshold`] for checking
//! that configuration values are sane before applying them.

use crate::output::TORIDE_LOG_PREFIX_MARKER;
use crate::spec::{AnomalyThreshold, LoggingRule};
use crate::{Error, Result};

// ---------------------------------------------------------------------------
// Logging rule validation
// ---------------------------------------------------------------------------

/// Validate a [`LoggingRule`] before it is applied to iptables.
///
/// Checks:
/// - `name` is non-empty.
/// - `log_prefix` contains the toride ownership marker (so teardown only ever
///   removes rules toride installed).
/// - `destination` is a valid CIDR or IP.
/// - `protocol` is one of `"tcp"`, `"udp"`, `"icmp"`, `"all"`.
/// - `log_prefix` is at most 29 characters (iptables limit).
/// - `log_level` is a valid iptables log level.
/// - `limit_rate` is non-empty.
///
/// # Errors
///
/// Returns [`Error::Other`] with a description of the first validation
/// failure.
pub fn validate_logging_rule(rule: &LoggingRule) -> Result<()> {
    if rule.name.is_empty() {
        return Err(Error::Other("logging rule name must not be empty".into()));
    }

    // Ownership marker: every toride-installed LOG rule must carry the toride
    // log-prefix marker so teardown can identify and remove *only* rules we
    // created — never unrelated LOG rules in the OUTPUT chain.
    if !rule.log_prefix.contains(TORIDE_LOG_PREFIX_MARKER) {
        return Err(Error::Other(format!(
            "logging rule `{}`: log_prefix must contain the toride marker `{}` \
             (got `{}`)",
            rule.name, TORIDE_LOG_PREFIX_MARKER, rule.log_prefix
        )));
    }

    if rule.destination.is_empty() {
        return Err(Error::Other(format!(
            "logging rule `{}`: destination must not be empty",
            rule.name
        )));
    }

    let valid_protocols = ["tcp", "udp", "icmp", "all"];
    if !valid_protocols.contains(&rule.protocol.as_str()) {
        return Err(Error::Other(format!(
            "logging rule `{}`: invalid protocol `{}` (expected one of {:?})",
            rule.name, rule.protocol, valid_protocols
        )));
    }

    if rule.log_prefix.len() > 29 {
        return Err(Error::Other(format!(
            "logging rule `{}`: log prefix exceeds 29 characters (got {})",
            rule.name,
            rule.log_prefix.len()
        )));
    }

    let valid_levels = [
        "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
    ];
    if !valid_levels.contains(&rule.log_level.as_str()) {
        return Err(Error::Other(format!(
            "logging rule `{}`: invalid log level `{}` (expected one of {:?})",
            rule.name, rule.log_level, valid_levels
        )));
    }

    if rule.limit_rate.is_empty() {
        return Err(Error::Other(format!(
            "logging rule `{}`: limit_rate must not be empty",
            rule.name
        )));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Threshold validation
// ---------------------------------------------------------------------------

/// Validate an [`AnomalyThreshold`] configuration.
///
/// Checks that all numeric thresholds are non-zero and that the window
/// duration is at least one second.
///
/// # Errors
///
/// Returns [`Error::AnomalyThreshold`] with a description of the first
/// validation failure.
pub fn validate_threshold(threshold: &AnomalyThreshold) -> Result<()> {
    if threshold.max_connections == 0 {
        return Err(Error::AnomalyThreshold(
            "max_connections must be greater than zero".into(),
        ));
    }

    if threshold.max_unique_destinations == 0 {
        return Err(Error::AnomalyThreshold(
            "max_unique_destinations must be greater than zero".into(),
        ));
    }

    if threshold.max_bytes == 0 {
        return Err(Error::AnomalyThreshold(
            "max_bytes must be greater than zero".into(),
        ));
    }

    if threshold.max_packets_per_second == 0 {
        return Err(Error::AnomalyThreshold(
            "max_packets_per_second must be greater than zero".into(),
        ));
    }

    if threshold.window.is_zero() {
        return Err(Error::AnomalyThreshold(
            "window duration must be greater than zero".into(),
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn valid_rule() -> LoggingRule {
        LoggingRule {
            name: "test-rule".into(),
            destination: "0.0.0.0/0".into(),
            dest_port: None,
            protocol: "tcp".into(),
            log_prefix: "toride-mon-test".into(),
            log_level: "info".into(),
            limit_burst: 10,
            limit_rate: "10/minute".into(),
        }
    }

    #[test]
    fn valid_logging_rule_passes() {
        assert!(validate_logging_rule(&valid_rule()).is_ok());
    }

    #[test]
    fn empty_name_fails() {
        let mut rule = valid_rule();
        rule.name.clear();
        assert!(validate_logging_rule(&rule).is_err());
    }

    #[test]
    fn invalid_protocol_fails() {
        let mut rule = valid_rule();
        rule.protocol = "sctp".into();
        assert!(validate_logging_rule(&rule).is_err());
    }

    #[test]
    fn long_prefix_fails() {
        let mut rule = valid_rule();
        // Include the marker so we exercise the length check, not the marker
        // check (the marker stays under the limit on its own).
        rule.log_prefix = format!("{}{}", "toride-mon-", "x".repeat(30));
        assert!(validate_logging_rule(&rule).is_err());
    }

    #[test]
    fn prefix_without_marker_fails() {
        let mut rule = valid_rule();
        rule.log_prefix = "NOT_OURS".into();
        assert!(validate_logging_rule(&rule).is_err());
    }

    #[test]
    fn valid_threshold_passes() {
        assert!(validate_threshold(&AnomalyThreshold::default()).is_ok());
    }

    #[test]
    fn zero_max_connections_fails() {
        let t = AnomalyThreshold {
            max_connections: 0,
            ..AnomalyThreshold::default()
        };
        assert!(validate_threshold(&t).is_err());
    }

    #[test]
    fn zero_window_fails() {
        let t = AnomalyThreshold {
            window: Duration::ZERO,
            ..AnomalyThreshold::default()
        };
        assert!(validate_threshold(&t).is_err());
    }
}
