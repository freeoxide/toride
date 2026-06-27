//! Monitoring specification types.
//!
//! [`MonitorSpec`] defines the complete configuration for outbound traffic
//! monitoring: logging rules, anomaly thresholds, and alert targets.

use std::time::Duration;

// ---------------------------------------------------------------------------
// serde glue
// ---------------------------------------------------------------------------

/// Serialize/deserialize a [`Duration`] as a whole number of seconds.
///
/// TOML has no native duration type; representing the window as an integer
/// keeps config files human-readable and round-trips cleanly.
#[cfg(feature = "serde")]
mod duration_secs {
    use super::Duration;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(dur: &Duration, ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        dur.as_secs().serialize(ser)
    }

    pub fn deserialize<'de, D>(de: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(de)?;
        Ok(Duration::from_secs(secs))
    }
}

// ---------------------------------------------------------------------------
// LoggingRule
// ---------------------------------------------------------------------------

/// A single iptables OUTPUT chain logging rule.
///
/// Describes which outbound traffic to log via the iptables `LOG` target.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LoggingRule {
    /// Human-readable name for this rule.
    pub name: String,
    /// Destination CIDR or host to match (e.g. `"0.0.0.0/0"` for all).
    pub destination: String,
    /// Destination port to match, or `None` for any port.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub dest_port: Option<u16>,
    /// Protocol to match (e.g. `"tcp"`, `"udp"`).
    pub protocol: String,
    /// Log prefix written to kernel log (max 29 characters).
    pub log_prefix: String,
    /// Log level (e.g. `"info"`, `"warning"`).
    pub log_level: String,
    /// Maximum burst rate before logging is rate-limited.
    pub limit_burst: u32,
    /// Rate limit for log entries (e.g. `"10/minute"`).
    pub limit_rate: String,
}

// ---------------------------------------------------------------------------
// AnomalyThreshold
// ---------------------------------------------------------------------------

/// Threshold configuration for anomaly detection.
///
/// When monitored metrics exceed these values, an anomaly is flagged.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AnomalyThreshold {
    /// Maximum number of concurrent outbound connections before flagging.
    pub max_connections: u64,
    /// Maximum number of unique destination IPs in the sampling window.
    pub max_unique_destinations: u64,
    /// Maximum bytes transferred in the sampling window.
    pub max_bytes: u64,
    /// Maximum packets per second before flagging.
    pub max_packets_per_second: u64,
    /// Duration of the sliding sampling window, in seconds.
    #[cfg_attr(feature = "serde", serde(with = "duration_secs"))]
    pub window: Duration,
}

impl Default for AnomalyThreshold {
    fn default() -> Self {
        Self {
            max_connections: 500,
            max_unique_destinations: 200,
            max_bytes: 100 * 1024 * 1024, // 100 MB
            max_packets_per_second: 10_000,
            window: Duration::from_secs(60),
        }
    }
}

// ---------------------------------------------------------------------------
// AlertTarget
// ---------------------------------------------------------------------------

/// An alert dispatch target.
///
/// Defines where anomaly alerts are sent when triggered.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "kind", rename_all = "lowercase")
)]
pub enum AlertTarget {
    /// Send alerts to the systemd journal.
    Journald {
        /// Priority level (e.g. `"warning"`, `"crit"`).
        priority: String,
    },
    /// Send alerts to a webhook endpoint.
    Webhook {
        /// URL to POST alert payloads to.
        url: String,
        /// Custom HTTP headers to include.
        #[cfg_attr(feature = "serde", serde(default))]
        headers: Vec<(String, String)>,
    },
    /// Write alerts to a log file.
    File {
        /// File path to append alert entries.
        path: String,
    },
}

// ---------------------------------------------------------------------------
// MonitorSpec
// ---------------------------------------------------------------------------

/// Complete monitoring specification.
///
/// Aggregates logging rules, anomaly thresholds, and alert targets into a
/// single configuration object.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MonitorSpec {
    /// Logging rules to apply to the iptables OUTPUT chain.
    #[cfg_attr(feature = "serde", serde(default))]
    pub logging_rules: Vec<LoggingRule>,
    /// Thresholds for anomaly detection.
    #[cfg_attr(feature = "serde", serde(default))]
    pub thresholds: AnomalyThreshold,
    /// Alert dispatch targets.
    #[cfg_attr(feature = "serde", serde(default))]
    pub alert_targets: Vec<AlertTarget>,
    /// Whether monitoring is enabled.
    #[cfg_attr(feature = "serde", serde(default = "default_enabled"))]
    pub enabled: bool,
}

#[cfg(feature = "serde")]
fn default_enabled() -> bool {
    true
}

impl Default for MonitorSpec {
    fn default() -> Self {
        Self {
            logging_rules: Vec::new(),
            thresholds: AnomalyThreshold::default(),
            alert_targets: vec![AlertTarget::Journald {
                priority: "warning".to_owned(),
            }],
            enabled: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use super::*;

    #[test]
    fn threshold_round_trips_duration_as_secs() {
        let t = AnomalyThreshold {
            window: Duration::from_secs(120),
            ..AnomalyThreshold::default()
        };
        let json = serde_json::to_string(&t).unwrap();
        assert!(json.contains("\"window\":120"));
        let back: AnomalyThreshold = serde_json::from_str(&json).unwrap();
        assert_eq!(back.window, Duration::from_secs(120));
    }

    #[test]
    fn alert_target_tagged_round_trip() {
        let targets = vec![
            AlertTarget::Journald {
                priority: "crit".into(),
            },
            AlertTarget::Webhook {
                url: "https://example.invalid/hook".into(),
                headers: vec![("X-Token".into(), "s".into())],
            },
            AlertTarget::File {
                path: "/var/log/toride.log".into(),
            },
        ];
        let json = serde_json::to_string(&targets).unwrap();
        let back: Vec<AlertTarget> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 3);
        assert!(matches!(back[0], AlertTarget::Journald { .. }));
        assert!(matches!(back[1], AlertTarget::Webhook { .. }));
        assert!(matches!(back[2], AlertTarget::File { .. }));
    }

    #[test]
    fn spec_round_trip_json() {
        let spec = MonitorSpec {
            enabled: false,
            logging_rules: vec![LoggingRule {
                name: "out".into(),
                destination: "0.0.0.0/0".into(),
                dest_port: Some(443),
                protocol: "tcp".into(),
                log_prefix: "TORIDE_OUT".into(),
                log_level: "info".into(),
                limit_burst: 5,
                limit_rate: "5/minute".into(),
            }],
            thresholds: AnomalyThreshold::default(),
            alert_targets: Vec::new(),
        };
        let json = serde_json::to_string(&spec).unwrap();
        let back: MonitorSpec = serde_json::from_str(&json).unwrap();
        assert!(!back.enabled);
        assert_eq!(back.logging_rules.len(), 1);
        assert_eq!(back.logging_rules[0].dest_port, Some(443));
    }
}
