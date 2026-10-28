//! Parsing of mise tool specification strings.
//!
//! Mise identifies tools using compact specification strings that encode a
//! backend shorthand, a tool name, an optional version constraint, and optional
//! key-value options. This module turns those strings into structured data
//! while preserving the original text so it can be emitted losslessly.

use std::collections::BTreeMap;
use std::fmt;

const KNOWN_BACKENDS: &[&str] = &[
    "core", "asdf", "aqua", "cargo", "conda", "dotnet", "forgejo", "gem", "github", "gitlab", "go",
    "http", "npm", "pipx", "spm", "ubi", "vfox",
];

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
    /// | `npm:@scope/pkg@3`       | `npm`   | `@scope/pkg` | `Prefix(3)` | _none_        |
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

/// Split an option string into `key=value` pairs on commas outside quotes.
///
/// Splitting on every comma (the previous behavior) made a value containing
/// a comma unparseable: `tags=a,b` yielded `tags="a"` plus a phantom
/// `b=true` flag, and [`ToolOptionValue::StringList`] was unreachable.
fn parse_option_list(s: &str) -> BTreeMap<String, ToolOptionValue> {
    let mut map = BTreeMap::new();
    for pair in split_pairs_outside_quotes(s) {
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

fn split_pairs_outside_quotes(s: &str) -> Vec<&str> {
    let mut pairs = Vec::new();
    let mut quote: Option<char> = None;
    let mut start = 0;
    for (index, ch) in s.char_indices() {
        match quote {
            Some(open) if ch == open => quote = None,
            None if ch == '"' || ch == '\'' => quote = Some(ch),
            None if ch == ',' => {
                pairs.push(&s[start..index]);
                start = index + ch.len_utf8();
            }
            _ => {}
        }
    }
    pairs.push(&s[start..]);
    pairs
}

/// Convert a single option value string into the best-fitting variant.
///
/// A value wrapped in matching quotes is the list form: the inner content
/// splits on commas into a [`ToolOptionValue::StringList`] (one element
/// stays a single [`ToolOptionValue::String`]). Unquoted commas never reach
/// this function as one value (the pair splitter consumes them) so an
/// unquoted `tags=a,b` remains two pairs (`tags="a"` and the bare flag
/// `b=true`), matching mise's own comma grammar; quote the value to express
/// a list.
fn parse_option_value(v: &str) -> ToolOptionValue {
    let quoted = v.len() >= 2
        && ((v.starts_with('"') && v.ends_with('"')) || (v.starts_with('\'') && v.ends_with('\'')));
    if quoted {
        let inner = &v[1..v.len() - 1];
        let items: Vec<String> = inner.split(',').map(|s| s.trim().to_owned()).collect();
        if items.len() > 1 {
            return ToolOptionValue::StringList(items);
        }
        return ToolOptionValue::String(inner.to_owned());
    }

    if v.eq_ignore_ascii_case("true") {
        return ToolOptionValue::Bool(true);
    }
    if v.eq_ignore_ascii_case("false") {
        return ToolOptionValue::Bool(false);
    }

    if let Ok(n) = v.parse::<i64>() {
        return ToolOptionValue::Integer(n);
    }

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
/// - Scoped names whose first `@` is part of the name (`"@scope/pkg@3"`,
///   `"npm:@scope/pkg@3.0.0"`) split on the *last* `@`, mirroring mise's
///   grammar: the empty-before-first-`@` or `/`-bearing name portion means a
///   later `@` is the real version separator.
/// - If the version portion after the split is empty (e.g. `"node@"` or a
///   bare `"@scope/pkg"`), the `@` is treated as part of the name with no
///   version split.
fn split_name_version(s: &str) -> (&str, Option<VersionRequest>) {
    let Some(first_at) = s.find('@') else {
        return (s, None);
    };

    let name_head = &s[..first_at];
    let at = if name_head.is_empty() || name_head.contains('/') {
        s.rfind('@').unwrap_or(first_at)
    } else {
        first_at
    };

    let name = &s[..at];
    let ver_str = &s[at + 1..];

    if name.is_empty() || ver_str.is_empty() {
        return (s, None);
    }

    let version = classify_version(ver_str);
    (name, Some(version))
}

/// Classify a version string into the appropriate [`VersionRequest`] variant.
///
/// `Exact` is reserved for full `X.Y.Z` semver (optionally `v`/`V`-prefixed);
/// mise resolves shorter forms (`"3.12"`, `"22"`) as version prefixes.
fn classify_version(s: &str) -> VersionRequest {
    if s.eq_ignore_ascii_case("latest") {
        return VersionRequest::Latest;
    }

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

    let trimmed = s
        .strip_prefix('v')
        .or_else(|| s.strip_prefix('V'))
        .unwrap_or(s);
    if semver::Version::parse(trimmed).is_ok() {
        return VersionRequest::Exact(s.to_owned());
    }

    VersionRequest::Prefix(s.to_owned())
}

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
    fn exact_requires_full_three_component_semver() {
        for (raw, expected) in [
            ("3.12.1", "3.12.1"),
            ("v1.2.3", "v1.2.3"),
            ("V2.0.0", "V2.0.0"),
            ("1.2.3-rc.1", "1.2.3-rc.1"),
        ] {
            let spec = ToolSpec::new(format!("tool@{raw}"));
            assert!(
                matches!(spec.version(), Some(VersionRequest::Exact(s)) if s == expected),
                "{raw} must classify as Exact({expected})"
            );
        }
    }

    #[test]
    fn shorter_version_forms_stay_prefix() {
        for raw in ["22", "3.12", "3"] {
            let spec = ToolSpec::new(format!("tool@{raw}"));
            assert!(
                matches!(spec.version(), Some(VersionRequest::Prefix(s)) if s == raw),
                "{raw} must classify as Prefix"
            );
        }
    }

    #[test]
    fn scoped_npm_spec_splits_on_last_at() {
        let spec = ToolSpec::new("npm:@scope/pkg@3.0.0");
        assert_eq!(spec.backend(), Some("npm"));
        assert_eq!(spec.name(), "@scope/pkg");
        assert!(matches!(
            spec.version(),
            Some(VersionRequest::Exact(s)) if s == "3.0.0"
        ));
    }

    #[test]
    fn quoted_comma_value_builds_a_string_list() {
        let spec = ToolSpec::new("aqua:foo/bar[tags=\"a,b\",version=2]");
        assert_eq!(spec.backend(), Some("aqua"));
        assert_eq!(
            spec.options().get("tags"),
            Some(&ToolOptionValue::StringList(vec![
                "a".to_owned(),
                "b".to_owned()
            ])),
            "the quoted comma form is the list form"
        );
        assert_eq!(
            spec.options().get("version"),
            Some(&ToolOptionValue::Integer(2))
        );
        assert_eq!(
            spec.options().len(),
            2,
            "no phantom flag from the quoted comma"
        );
    }

    #[test]
    fn quoted_single_value_stays_one_string() {
        let spec = ToolSpec::new("ubi:Foo/Bar[exe=\"rg\"]");
        assert_eq!(
            spec.options().get("exe"),
            Some(&ToolOptionValue::String("rg".to_owned()))
        );
    }

    #[test]
    fn bare_scoped_name_has_no_version() {
        let spec = ToolSpec::new("@scope/pkg");
        assert_eq!(spec.name(), "@scope/pkg");
        assert!(spec.version().is_none());
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
