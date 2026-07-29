//! auditd.conf parsing and management.
//!
//! Provides types and functions for reading, parsing, and writing the
//! audit daemon configuration file (`/etc/audit/auditd.conf`).

use std::collections::BTreeMap;

use crate::Result;

// ---------------------------------------------------------------------------
// AuditdConfig
// ---------------------------------------------------------------------------

/// Parsed representation of `auditd.conf`.
///
/// The configuration file uses `key = value` pairs. This struct provides
/// typed access to the most commonly used settings while preserving
/// all keys in the [`Self::extra`] map for forward compatibility.
#[derive(Debug, Clone)]
pub struct AuditdConfig {
    /// Maximum log file size in megabytes.
    pub max_log_file: Option<u64>,
    /// Action when the log file reaches max size: `ignore`, `syslog`, `suspend`, `rotate`, `keep_logs`.
    pub max_log_file_action: Option<String>,
    /// Number of log files to retain when rotating.
    pub num_logs: Option<u32>,
    /// Log file format: `raw`, `nolog`.
    pub log_format: Option<String>,
    /// Flush mode: `none`, `incremental`, `data`, `sync`.
    pub flush: Option<String>,
    /// Priority boost for the audit daemon.
    pub priority_boost: Option<u32>,
    /// Any additional key-value pairs not covered by typed fields.
    pub extra: BTreeMap<String, String>,
}

impl AuditdConfig {
    /// Parse an `auditd.conf` file content.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigParse`] if the content cannot be parsed.
    pub fn parse(content: &str) -> Result<Self> {
        let mut config = Self {
            max_log_file: None,
            max_log_file_action: None,
            num_logs: None,
            log_format: None,
            flush: None,
            priority_boost: None,
            extra: BTreeMap::new(),
        };

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if let Some((key, value)) = trimmed.split_once('=') {
                let key = key.trim();
                let value = value.trim();

                match key {
                    "max_log_file" => {
                        config.max_log_file = value.parse().ok();
                    }
                    "max_log_file_action" => {
                        config.max_log_file_action = Some(value.to_owned());
                    }
                    "num_logs" => {
                        config.num_logs = value.parse().ok();
                    }
                    "log_format" => {
                        config.log_format = Some(value.to_owned());
                    }
                    "flush" => {
                        config.flush = Some(value.to_owned());
                    }
                    "priority_boost" => {
                        config.priority_boost = value.parse().ok();
                    }
                    _ => {
                        config.extra.insert(key.to_owned(), value.to_owned());
                    }
                }
            }
        }

        Ok(config)
    }

    /// Render the configuration back to a string suitable for writing to
    /// `auditd.conf`.
    #[must_use]
    pub fn render(&self) -> String {
        let mut lines = Vec::new();

        if let Some(v) = &self.max_log_file {
            lines.push(format!("max_log_file = {v}"));
        }
        if let Some(v) = &self.max_log_file_action {
            lines.push(format!("max_log_file_action = {v}"));
        }
        if let Some(v) = &self.num_logs {
            lines.push(format!("num_logs = {v}"));
        }
        if let Some(v) = &self.log_format {
            lines.push(format!("log_format = {v}"));
        }
        if let Some(v) = &self.flush {
            lines.push(format!("flush = {v}"));
        }
        if let Some(v) = &self.priority_boost {
            lines.push(format!("priority_boost = {v}"));
        }

        for (key, value) in &self.extra {
            lines.push(format!("{key} = {value}"));
        }

        lines.join("\n")
    }

    /// Returns an empty configuration with sensible defaults.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self {
            max_log_file: Some(100),
            max_log_file_action: Some("rotate".to_owned()),
            num_logs: Some(10),
            log_format: Some("raw".to_owned()),
            flush: Some("incremental_async".to_owned()),
            priority_boost: Some(4),
            extra: BTreeMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_yields_empty_config() {
        let config = AuditdConfig::parse("").expect("empty input parses");
        assert!(config.max_log_file.is_none());
        assert!(config.max_log_file_action.is_none());
        assert!(config.num_logs.is_none());
        assert!(config.log_format.is_none());
        assert!(config.flush.is_none());
        assert!(config.priority_boost.is_none());
        assert!(config.extra.is_empty());
    }

    #[test]
    fn parse_skips_comments_and_blank_lines() {
        let content = "\
# leading comment
# another

max_log_file = 50
";
        let config = AuditdConfig::parse(content).expect("parses with comments");
        assert_eq!(config.max_log_file, Some(50));
        assert!(config.extra.is_empty());
    }

    #[test]
    fn parse_and_render_round_trip() {
        let content = "\
max_log_file = 50
max_log_file_action = rotate
num_logs = 5
log_format = raw
flush = incremental_async
priority_boost = 4
";
        let config = AuditdConfig::parse(content).expect("parses");
        assert_eq!(config.max_log_file, Some(50));
        assert_eq!(config.max_log_file_action.as_deref(), Some("rotate"));
        assert_eq!(config.num_logs, Some(5));
        assert_eq!(config.log_format.as_deref(), Some("raw"));
        assert_eq!(config.flush.as_deref(), Some("incremental_async"));
        assert_eq!(config.priority_boost, Some(4));

        // Re-parsing the rendered output must yield an equivalent config.
        let reparsed = AuditdConfig::parse(&config.render()).expect("re-parses render");
        assert_eq!(reparsed.max_log_file, config.max_log_file);
        assert_eq!(reparsed.max_log_file_action, config.max_log_file_action);
        assert_eq!(reparsed.num_logs, config.num_logs);
        assert_eq!(reparsed.log_format, config.log_format);
        assert_eq!(reparsed.flush, config.flush);
        assert_eq!(reparsed.priority_boost, config.priority_boost);
    }

    #[test]
    fn parse_unknown_keys_go_to_extra() {
        let content = "\
max_log_file = 10
some_unknown_key = hello
another_key = world
";
        let config = AuditdConfig::parse(content).expect("parses");
        assert_eq!(config.max_log_file, Some(10));
        assert_eq!(
            config.extra.get("some_unknown_key").map(String::as_str),
            Some("hello")
        );
        assert_eq!(
            config.extra.get("another_key").map(String::as_str),
            Some("world")
        );
    }

    #[test]
    fn render_includes_extra_keys() {
        let mut config = AuditdConfig::with_defaults();
        config
            .extra
            .insert("custom_key".to_owned(), "custom_value".to_owned());

        let rendered = config.render();
        assert!(rendered.contains("custom_key = custom_value"));
        // Known typed fields are rendered too.
        assert!(rendered.contains("max_log_file = 100"));
        assert!(rendered.contains("flush = incremental_async"));
    }

    #[test]
    fn render_empty_config_is_empty_string() {
        let config = AuditdConfig {
            max_log_file: None,
            max_log_file_action: None,
            num_logs: None,
            log_format: None,
            flush: None,
            priority_boost: None,
            extra: BTreeMap::new(),
        };
        assert!(config.render().is_empty());
    }

    #[test]
    fn parse_whitespace_around_key_value_is_trimmed() {
        let config = AuditdConfig::parse("   max_log_file    =    42   ").expect("parses");
        assert_eq!(config.max_log_file, Some(42));
    }

    #[test]
    fn parse_unparseable_numeric_field_becomes_none() {
        // The parser uses `value.parse().ok()`, so a non-numeric value drops
        // the field silently (this pins the documented current behavior).
        let config =
            AuditdConfig::parse("max_log_file = not-a-number").expect("parses despite bad value");
        assert!(config.max_log_file.is_none());
    }

    #[test]
    fn parse_line_without_equals_is_ignored() {
        let config = AuditdConfig::parse("garbage line\nmax_log_file = 7").expect("parses");
        assert_eq!(config.max_log_file, Some(7));
        assert!(config.extra.is_empty());
    }

    #[test]
    fn parse_value_containing_equals_is_preserved() {
        let config = AuditdConfig::parse("extra_key = a=b=c").expect("parses");
        assert_eq!(
            config.extra.get("extra_key").map(String::as_str),
            Some("a=b=c")
        );
    }

    #[test]
    fn with_defaults_round_trips() {
        let config = AuditdConfig::with_defaults();
        let rendered = config.render();
        let reparsed = AuditdConfig::parse(&rendered).expect("re-parses");
        assert_eq!(reparsed.max_log_file, Some(100));
        assert_eq!(reparsed.max_log_file_action.as_deref(), Some("rotate"));
        assert_eq!(reparsed.num_logs, Some(10));
        assert_eq!(reparsed.log_format.as_deref(), Some("raw"));
        assert_eq!(reparsed.flush.as_deref(), Some("incremental_async"));
        assert_eq!(reparsed.priority_boost, Some(4));
    }
}
