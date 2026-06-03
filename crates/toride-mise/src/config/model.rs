//! Data structures for mise configuration files.
//!
//! These types model the contents of `~/.config/mise/config.toml` (global) and
//! `.mise.toml` (project-local) files. They are used by the read and write
//! modules.

use std::collections::BTreeMap;

use camino::Utf8PathBuf;

// ---------------------------------------------------------------------------
// MiseToml
// ---------------------------------------------------------------------------

/// Represents the contents of a mise config file (`.mise.toml` or
/// `config.toml`).
///
/// This is a simplified view of the config: a flat map of settings, a list of
/// tool entries, and optional environment variables. It does **not** attempt to
/// model every possible mise config key — only the subset the crate interacts
/// with. Unknown keys are preserved in the `extra` field when the `toml`
/// feature is enabled.
#[derive(Debug, Clone)]
pub struct MiseToml {
    /// Path to the config file this was read from, if known.
    pub path: Option<Utf8PathBuf>,
    /// Top-level `settings.*` entries.
    pub settings: BTreeMap<String, SettingsEntry>,
    /// Raw `[tools]` entries as `"tool" => "version"` strings.
    pub tools: BTreeMap<String, String>,
    /// Raw `[env]` entries.
    pub env: BTreeMap<String, String>,
    /// Raw `[tasks]` entries as `"task_name" => "command"` strings.
    pub tasks: BTreeMap<String, String>,
    /// Unknown top-level keys preserved from the TOML document.
    ///
    /// Only populated when the `toml` feature is enabled.
    #[cfg(feature = "toml")]
    pub extra: BTreeMap<String, toml::Value>,
}

impl MiseToml {
    /// Create an empty config.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            path: None,
            settings: BTreeMap::new(),
            tools: BTreeMap::new(),
            env: BTreeMap::new(),
            tasks: BTreeMap::new(),
            #[cfg(feature = "toml")]
            extra: BTreeMap::new(),
        }
    }

    /// Create an empty config associated with a specific file path.
    #[must_use]
    pub fn at(path: Utf8PathBuf) -> Self {
        Self {
            path: Some(path),
            ..Self::empty()
        }
    }
}

impl Default for MiseToml {
    fn default() -> Self {
        Self::empty()
    }
}

// ---------------------------------------------------------------------------
// ConfigWriteResult
// ---------------------------------------------------------------------------

/// Outcome of a write operation against a mise config file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigWriteResult {
    /// The file that was written (or would have been written in a dry-run).
    pub path: Utf8PathBuf,
    /// Whether a new file was created (`true`) or an existing file was modified
    /// (`false`).
    pub created: bool,
    /// The key that was set or unset, if applicable.
    pub key: Option<String>,
    /// The previous value before the write, if known.
    pub old_value: Option<String>,
    /// The new value that was written, if known.
    pub new_value: Option<String>,
    /// Whether the value actually changed (`true` if the new value differs from
    /// the old value, or the old value was absent).
    pub changed: bool,
}

// ---------------------------------------------------------------------------
// SettingsEntry
// ---------------------------------------------------------------------------

/// A single `settings.*` value from a mise config file.
///
/// Mise settings can be strings, numbers, booleans, or arrays. This enum
/// preserves the raw value while also tracking the original string
/// representation for round-tripping.
#[derive(Debug, Clone, PartialEq)]
pub enum SettingsEntry {
    /// A boolean setting (`true` / `false`).
    Bool(bool),
    /// An integer setting.
    Int(i64),
    /// A string setting.
    String(String),
    /// An array of string values.
    Array(Vec<String>),
}

impl SettingsEntry {
    /// Return the value as a string suitable for `mise settings set`.
    ///
    /// Booleans become `"true"` / `"false"`, integers are decimal-formatted,
    /// and arrays are joined with commas.
    #[must_use]
    pub fn to_mise_value(&self) -> String {
        match self {
            Self::Bool(b) => b.to_string(),
            Self::Int(n) => n.to_string(),
            Self::String(s) => s.clone(),
            Self::Array(items) => items.join(","),
        }
    }

    /// Try to parse a raw string value into a `SettingsEntry`.
    ///
    /// Recognises `"true"` / `"false"` as booleans, pure digit strings as
    /// integers, and falls back to a plain string otherwise.
    pub fn from_raw(raw: &str) -> Self {
        if raw == "true" {
            Self::Bool(true)
        } else if raw == "false" {
            Self::Bool(false)
        } else if raw.parse::<i64>().is_ok() {
            Self::Int(raw.parse::<i64>().unwrap_or_default())
        } else {
            Self::String(raw.to_owned())
        }
    }
}

impl std::fmt::Display for SettingsEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bool(b) => write!(f, "{b}"),
            Self::Int(n) => write!(f, "{n}"),
            Self::String(s) => write!(f, "{s}"),
            Self::Array(items) => write!(f, "[{}]", items.join(", ")),
        }
    }
}
