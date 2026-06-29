//! AIDE configuration management.
//!
//! Provides types and functions for reading, parsing, and writing
//! the AIDE configuration file (`/etc/aide.conf`).

use std::collections::BTreeMap;

use crate::Result;

// ---------------------------------------------------------------------------
// AideConfig
// ---------------------------------------------------------------------------

/// Parsed representation of the AIDE configuration file.
///
/// AIDE configuration consists of database paths, custom groups,
/// selection lines, and other directives. This struct provides
/// structured access to the most important settings.
#[derive(Debug, Clone)]
pub struct AideConfig {
    /// Path to the reference database.
    pub database: Option<String>,
    /// Path to the output database (for initialization/update).
    pub database_out: Option<String>,
    /// Report URL or path.
    pub report_url: Option<String>,
    /// Custom group definitions (name -> definition).
    pub custom_groups: BTreeMap<String, String>,
    /// Monitored paths with their selection rules.
    pub selections: Vec<AideSelection>,
    /// Ignored (negative) paths.
    pub negations: Vec<String>,
    /// Raw content for any unrecognized directives.
    pub extra_lines: Vec<String>,
}

// ---------------------------------------------------------------------------
// AideSelection
// ---------------------------------------------------------------------------

/// A single path selection entry in the AIDE configuration.
#[derive(Debug, Clone)]
pub struct AideSelection {
    /// The path being monitored.
    pub path: String,
    /// The group rule applied to this path (e.g. `ALL`, `PERMS`, `sha256`).
    pub groups: String,
    /// Whether this is a positive selection (monitor) or negative (ignore).
    pub positive: bool,
}

impl AideConfig {
    /// Parse an AIDE configuration file content.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigParse`] if the content cannot be parsed.
    pub fn parse(content: &str) -> Result<Self> {
        let mut config = Self {
            database: None,
            database_out: None,
            report_url: None,
            custom_groups: BTreeMap::new(),
            selections: Vec::new(),
            negations: Vec::new(),
            extra_lines: Vec::new(),
        };

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("@@") {
                continue;
            }

            // Handle key=value directives.
            if let Some((key, value)) = trimmed.split_once('=') {
                let key = key.trim();
                let value = value.trim();

                match key {
                    "database" | "database_in" => {
                        // Strip prefix like "file:"
                        config.database = Some(strip_prefix(value));
                    }
                    "database_out" => {
                        config.database_out = Some(strip_prefix(value));
                    }
                    "report_url" => {
                        config.report_url = Some(value.to_owned());
                    }
                    _ => {
                        // Could be a group definition.
                        config
                            .custom_groups
                            .insert(key.to_owned(), value.to_owned());
                    }
                }
                continue;
            }

            // Handle path selections.
            if let Some(stripped) = trimmed.strip_prefix('!') {
                config.negations.push(stripped.trim().to_owned());
            } else if trimmed.starts_with('/') {
                if let Some((path, groups)) = trimmed.split_once(' ') {
                    config.selections.push(AideSelection {
                        path: path.to_owned(),
                        groups: groups.trim().to_owned(),
                        positive: true,
                    });
                } else {
                    config.selections.push(AideSelection {
                        path: trimmed.to_owned(),
                        groups: "ALL".to_owned(),
                        positive: true,
                    });
                }
            }
        }

        Ok(config)
    }

    /// Render the configuration back to a string suitable for `aide.conf`.
    #[must_use]
    pub fn render(&self) -> String {
        let mut lines = Vec::new();

        if let Some(db) = &self.database {
            lines.push(format!("database=file:{db}"));
        }
        if let Some(db) = &self.database_out {
            lines.push(format!("database_out=file:{db}"));
        }
        if let Some(url) = &self.report_url {
            lines.push(format!("report_url={url}"));
        }

        for (name, def) in &self.custom_groups {
            lines.push(format!("{name} = {def}"));
        }

        lines.push(String::new());

        for negation in &self.negations {
            lines.push(format!("!{negation}"));
        }

        for sel in &self.selections {
            if sel.positive {
                lines.push(format!("{} {}", sel.path, sel.groups));
            }
        }

        lines.join("\n")
    }
}

/// Strip a prefix like `file:` from a configuration value.
fn strip_prefix(value: &str) -> String {
    value.strip_prefix("file:").unwrap_or(value).to_owned()
}
