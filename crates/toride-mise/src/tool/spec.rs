//! Parsing of mise tool specification strings.
//!
//! Mise identifies tools using compact specification strings that encode a
//! backend shorthand, a tool name, an optional version constraint, and optional
//! key-value options. This module turns those strings into structured data
//! while preserving the original text so it can be emitted losslessly.

use std::collections::BTreeMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Known backend prefixes
// ---------------------------------------------------------------------------

const KNOWN_BACKENDS: &[&str] = &[
    "core", "asdf", "aqua", "cargo", "conda", "dotnet", "forgejo", "gem", "github", "gitlab", "go",
    "http", "npm", "pipx", "spm", "ubi", "vfox",
];

// ---------------------------------------------------------------------------
// VersionRequest
// ---------------------------------------------------------------------------

/// How a tool version was requested.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum VersionRequest {
    /// No specific version -- ask mise for the latest match.
    Latest,
    /// A prefix such as `"22"` that allows any matching semver.
    Prefix(String),
    /// An exact version string.
    Exact(String),
    /// A named alias (e.g. `"lts"`, `"stable"`).
    Alias(String),
    /// A release channel (e.g. `"nightly"`, `"beta"`).
    Channel(String),
}

impl fmt::Display for VersionRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Latest => write!(f, "latest"),
            Self::Prefix(s) | Self::Exact(s) | Self::Alias(s) | Self::Channel(s) => {
                write!(f, "{s}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ToolOptionValue
// ---------------------------------------------------------------------------

/// A value appearing inside `[key=val,…]` option brackets.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ToolOptionValue {
    Bool(bool),
    Integer(i64),
    String(String),
    StringList(Vec<String>),
    /// Raw text that could not be decomposed into a more specific variant.
    Raw(String),
}

impl fmt::Display for ToolOptionValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bool(b) => write!(f, "{b}"),
            Self::Integer(n) => write!(f, "{n}"),
            Self::String(s) | Self::Raw(s) => write!(f, "{s}"),
            Self::StringList(list) => {
                let joined = list.join(",");
                write!(f, "{joined}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ToolSpec
// ---------------------------------------------------------------------------

/// A parsed mise tool specification.
///
/// The [`Display`](fmt::Display) implementation reproduces the original text
/// so that round-tripping through parse and display is lossless.
///
/// # Examples
///
/// ```
/// use toride_mise::ToolSpec;
///
/// let spec = ToolSpec::new("node@22");
/// assert_eq!(spec.name(), "node");
/// assert_eq!(spec.version().unwrap().to_string(), "22");
///
/// let spec = ToolSpec::new("npm:prettier@latest");
/// assert_eq!(spec.backend().unwrap(), "npm");
/// assert_eq!(spec.name(), "prettier");
///
/// let spec = ToolSpec::new("ubi:Foo/Bar[exe=rg]");
/// assert_eq!(spec.options().get("exe").unwrap().to_string(), "rg");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ToolSpec {
    raw: String,
    backend: Option<String>,
    name: String,
    version: Option<VersionRequest>,
    options: BTreeMap<String, ToolOptionValue>,
}

impl ToolSpec {
    /// Parse a raw mise tool specification string.
    ///
    /// Supported forms:
    ///
    /// | raw                      | backend | name       | version     | options         |
    /// |--------------------------|---------|------------|-------------|-----------------|
    /// | `node@22`                | _none_  | `node`     | `Prefix(22)`| _none_          |
    /// | `npm:prettier@latest`    | `npm`   | `prettier` | `Latest`    | _none_          |
    /// | `ubi:Foo/Bar[exe=rg]`   | `ubi`   | `Foo/Bar`  | _none_      | `exe -> "rg"`   |
    /// | `python@3.12.1`          | _none_  | `python`   | `Exact(..)` | _none_          |
    /// | `go:github.com/foo/bar`  | `go`    | `..bar`    | _none_      | _none_          |
    pub fn new(raw: impl Into<String>) -> Self {
        let raw = raw.into();
        let (options, remainder) = split_options(&raw);
        let (backend, name_and_version) = split_backend(remainder);
        let (name, version) = split_name_version(name_and_version);

        Self {
            backend,
            name: name.to_owned(),
            version,
            options,
            raw,
        }
    }

    /// The original specification string, preserved verbatim.
    #[must_use]
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// The backend prefix, if one was present.
    ///
    /// Known backends include `core`, `asdf`, `aqua`, `cargo`, `conda`,
    /// `dotnet`, `forgejo`, `gem`, `github`, `gitlab`, `go`, `http`,
    /// `npm`, `pipx`, `spm`, `ubi`, and `vfox`.
    #[must_use]
    pub fn backend(&self) -> Option<&str> {
        self.backend.as_deref()
    }

    /// The tool name (without backend prefix or version).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The version constraint that was specified, if any.
    #[must_use]
    pub fn version(&self) -> Option<&VersionRequest> {
        self.version.as_ref()
    }

    /// Key-value options that appeared inside `[…]` brackets.
    #[must_use]
    pub fn options(&self) -> &BTreeMap<String, ToolOptionValue> {
        &self.options
    }
}

impl fmt::Display for ToolSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Lossless: always emit the preserved raw string.
        write!(f, "{}", self.raw)
    }
}

impl AsRef<str> for ToolSpec {
    fn as_ref(&self) -> &str {
        &self.raw
    }
}

// ---------------------------------------------------------------------------
// Parsing helpers (private)
// ---------------------------------------------------------------------------

/// Separate trailing `[key=val,…]` option brackets from the rest.
///
/// Returns `(options_map, remainder_without_options)`.
fn split_options(raw: &str) -> (BTreeMap<String, ToolOptionValue>, &str) {
    // Find the *last* `[` that is matched by a trailing `]`.
    if !raw.ends_with(']') {
        return (BTreeMap::new(), raw);
    }

    // Find the opening `[` that pairs with the final `]`.
    let Some(open) = raw.rfind('[') else {
        return (BTreeMap::new(), raw);
    };

    let remainder = &raw[..open];
    let options_str = &raw[open + 1..raw.len() - 1];

    let options = parse_option_list(options_str);
    (options, remainder)
}

/// Parse a comma-separated list of `key=value` pairs.
fn parse_option_list(s: &str) -> BTreeMap<String, ToolOptionValue> {
    let mut map = BTreeMap::new();
    // Simple comma split -- does not handle commas inside quoted values.
    for pair in s.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        if let Some((k, v)) = pair.split_once('=') {
            map.insert(k.trim().to_owned(), parse_option_value(v.trim()));
        } else {
            // Bare flag treated as `key=true`.
            map.insert(pair.to_owned(), ToolOptionValue::Bool(true));
        }
    }
    map
}

/// Convert a single option value string into the best-fitting variant.
fn parse_option_value(v: &str) -> ToolOptionValue {
    // Boolean.
    if v.eq_ignore_ascii_case("true") {
        return ToolOptionValue::Bool(true);
    }
    if v.eq_ignore_ascii_case("false") {
        return ToolOptionValue::Bool(false);
    }

    // Integer.
    if let Ok(n) = v.parse::<i64>() {
        return ToolOptionValue::Integer(n);
    }

    // Comma-separated list (only when the value itself is not inside brackets,
    // which the outer splitter would have already consumed).
    if v.contains(',') {
        let items: Vec<String> = v.split(',').map(|s| s.trim().to_owned()).collect();
        if items.len() > 1 {
            return ToolOptionValue::StringList(items);
        }
    }

    // Fallback: plain string.
    ToolOptionValue::String(v.to_owned())
}

/// Detect and strip a known backend prefix (`xxx:`) from the head of `s`.
///
/// Returns `(Some("backend"), rest)` or `(None, s)`.
///
/// If the remainder after stripping the backend prefix is empty (e.g. `"npm:"`),
/// the whole string is kept as the name with no backend.
fn split_backend(s: &str) -> (Option<String>, &str) {
    let Some(colon) = s.find(':') else {
        return (None, s);
    };
    let candidate = &s[..colon];
    let remainder = &s[colon + 1..];
    if KNOWN_BACKENDS.contains(&candidate) && !remainder.is_empty() {
        (Some(candidate.to_owned()), remainder)
    } else {
        (None, s)
    }
}

/// Split `name@version` into `(name, Some(version))`.
///
/// The version portion is classified as [`VersionRequest::Latest`],
/// [`VersionRequest::Prefix`], or [`VersionRequest::Exact`].
///
/// Edge cases:
/// - If the name portion before `@` is empty (e.g. `"@22"`), the leading `@`
///   is treated as part of the name with no version split.
/// - If the version portion after `@` is empty (e.g. `"node@"`), the trailing
///   `@` is treated as part of the name with no version split.
fn split_name_version(s: &str) -> (&str, Option<VersionRequest>) {
    // We split on the *first* `@` so that `go:github.com/foo@v1@bar` (if it
    // ever appears) keeps the name portion intact.
    let Some(at) = s.find('@') else {
        return (s, None);
    };

    let name = &s[..at];
    let ver_str = &s[at + 1..];

    // Guard: empty name or empty version means the `@` is not a delimiter.
    if name.is_empty() || ver_str.is_empty() {
        return (s, None);
    }

    let version = classify_version(ver_str);
    (name, Some(version))
}

/// Classify a version string into the appropriate [`VersionRequest`] variant.
fn classify_version(s: &str) -> VersionRequest {
    if s.eq_ignore_ascii_case("latest") {
        return VersionRequest::Latest;
    }

    // Known channel / alias keywords.
    let lower = s.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "nightly" | "beta" | "alpha" | "canary" | "dev" | "preview" | "rc"
    ) {
        return VersionRequest::Channel(s.to_owned());
    }
    if matches!(
        lower.as_str(),
        "lts" | "stable" | "current" | "default" | "system"
    ) {
        return VersionRequest::Alias(s.to_owned());
    }

    // If the version looks like an exact semver (contains at least one dot and
    // starts with a digit or a 'v' followed by a digit) we treat it as exact.
    // This handles common version formats: "1.2.3", "v1.2.3", "V1.2.3".
    let digits_start = s.strip_prefix('v').or_else(|| s.strip_prefix('V'));
    if s.contains('.')
        && (s.bytes().next().is_some_and(|b| b.is_ascii_digit())
            || digits_start.is_some_and(|rest| {
                rest.bytes().next().is_some_and(|b| b.is_ascii_digit()) && rest.contains('.')
            }))
    {
        return VersionRequest::Exact(s.to_owned());
    }

    // Anything else is a prefix (e.g. `"22"` for node, `"3.12"` for python).
    VersionRequest::Prefix(s.to_owned())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_name_and_prefix_version() {
        let spec = ToolSpec::new("node@22");
        assert_eq!(spec.backend(), None);
        assert_eq!(spec.name(), "node");
        assert!(matches!(
            spec.version(),
            Some(VersionRequest::Prefix(s)) if s == "22"
        ));
        assert!(spec.options().is_empty());
    }

    #[test]
    fn backend_and_latest_version() {
        let spec = ToolSpec::new("npm:prettier@latest");
        assert_eq!(spec.backend(), Some("npm"));
        assert_eq!(spec.name(), "prettier");
        assert!(matches!(spec.version(), Some(VersionRequest::Latest)));
    }

    #[test]
    fn backend_with_options() {
        let spec = ToolSpec::new("ubi:Foo/Bar[exe=rg]");
        assert_eq!(spec.backend(), Some("ubi"));
        assert_eq!(spec.name(), "Foo/Bar");
        assert!(spec.version().is_none());
        assert_eq!(
            spec.options().get("exe"),
            Some(&ToolOptionValue::String("rg".to_owned()))
        );
    }

    #[test]
    fn exact_version() {
        let spec = ToolSpec::new("python@3.12.1");
        assert!(matches!(
            spec.version(),
            Some(VersionRequest::Exact(s)) if s == "3.12.1"
        ));
    }

    #[test]
    fn alias_version() {
        let spec = ToolSpec::new("node@lts");
        assert!(matches!(
            spec.version(),
            Some(VersionRequest::Alias(s)) if s == "lts"
        ));
    }

    #[test]
    fn channel_version() {
        let spec = ToolSpec::new("rust@nightly");
        assert!(matches!(
            spec.version(),
            Some(VersionRequest::Channel(s)) if s == "nightly"
        ));
    }

    #[test]
    fn display_is_lossless() {
        for raw in &[
            "node@22",
            "npm:prettier@latest",
            "ubi:Foo/Bar[exe=rg]",
            "python@3.12.1",
            "go:github.com/foo/bar",
        ] {
            let spec = ToolSpec::new(raw.to_owned());
            assert_eq!(spec.to_string(), *raw);
        }
    }

    #[test]
    fn bare_flag_option() {
        let spec = ToolSpec::new("cargo:cargo-audit[locked]");
        assert_eq!(
            spec.options().get("locked"),
            Some(&ToolOptionValue::Bool(true))
        );
    }

    #[test]
    fn multiple_options() {
        let spec = ToolSpec::new("aqua:foo/bar[exe=baz,version=2]");
        assert_eq!(
            spec.options().get("exe"),
            Some(&ToolOptionValue::String("baz".to_owned()))
        );
        assert_eq!(
            spec.options().get("version"),
            Some(&ToolOptionValue::Integer(2))
        );
    }

    #[test]
    fn no_backend_no_version() {
        let spec = ToolSpec::new("jq");
        assert_eq!(spec.backend(), None);
        assert_eq!(spec.name(), "jq");
        assert!(spec.version().is_none());
    }

    #[test]
    fn unknown_backend_not_stripped() {
        // "unknown" is not in KNOWN_BACKENDS so the whole string is the name.
        let spec = ToolSpec::new("unknown:foo@1.0");
        assert_eq!(spec.backend(), None);
        // The colon is part of the name because the backend wasn't recognised.
        assert_eq!(spec.name(), "unknown:foo");
    }

    #[test]
    fn as_ref_str() {
        let spec = ToolSpec::new("node@22");
        assert_eq!(spec.as_ref(), "node@22");
    }
}
