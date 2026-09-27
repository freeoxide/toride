//! Mise version parsing and comparison.

use std::fmt;

// ---------------------------------------------------------------------------
// MiseVersion
// ---------------------------------------------------------------------------

/// A parsed mise version with both the raw string and an optional semver.
///
/// Constructed via [`MiseVersion::parse`] from the output of `mise --version`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiseVersion {
    /// The raw version string as reported by `mise --version` (e.g. `"2024.1.2"`).
    pub raw: String,
    /// The best-effort parsed semantic version. `None` if the output could not
    /// be parsed as a valid semver.
    pub parsed: Option<semver::Version>,
}

impl MiseVersion {
    /// Parse a version from the full output of `mise --version`.
    ///
    /// Accepts lines like `"mise 2024.1.2"`, `"2024.1.2"`, or the real format
    /// `"2026.5.18 macos-arm64 (2026-05-31)"`. Leading whitespace and trailing
    /// newlines are stripped automatically. Only the leading semver-like portion
    /// is used for the `parsed` field; the full string is stored in `raw`.
    pub fn parse(output: &str) -> Self {
        let trimmed = output.trim();

        // Strip a leading binary name, e.g. "mise 2024.1.2" -> "2024.1.2"
        let after_prefix = trimmed.strip_prefix("mise ").map_or(trimmed, str::trim);

        // Extract just the version portion — everything up to the first space.
        // Real mise outputs e.g. "2026.5.18 macos-arm64 (2026-05-31)".
        let version_str = after_prefix
            .split_once(' ')
            .map_or(after_prefix, |(v, _rest)| v);

        let parsed = semver::Version::parse(version_str).ok();

        Self {
            raw: version_str.to_owned(),
            parsed,
        }
    }

    /// Returns `true` if this version is at least `required`.
    ///
    /// If the version could not be parsed as a valid semver, this method
    /// returns `false` (conservative fallback).
    pub fn is_at_least(&self, required: &semver::Version) -> bool {
        self.parsed.as_ref().is_some_and(|v| v >= required)
    }
}

impl fmt::Display for MiseVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl From<&toride_installer::ToolVersion> for MiseVersion {
    /// Convert the installer detector's probed version into a
    /// [`MiseVersion`]. Both types parse with the same conventions (prefix
    /// strip, first whitespace token, best-effort semver), so `raw` and
    /// `parsed` carry over unchanged; `ToolVersion::line` (the full
    /// trimmed output line) has no `MiseVersion` counterpart and is
    /// dropped.
    fn from(v: &toride_installer::ToolVersion) -> Self {
        Self {
            raw: v.raw.clone(),
            parsed: v.parsed.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use semver::Version;

    #[test]
    fn parse_plain_version() {
        let v = MiseVersion::parse("2024.1.2");
        assert_eq!(v.raw, "2024.1.2");
        assert_eq!(v.parsed, Some(Version::parse("2024.1.2").unwrap()));
    }

    #[test]
    fn parse_with_prefix() {
        let v = MiseVersion::parse("mise 2024.1.2");
        assert_eq!(v.raw, "2024.1.2");
        assert_eq!(v.parsed, Some(Version::parse("2024.1.2").unwrap()));
    }

    #[test]
    fn parse_with_whitespace() {
        let v = MiseVersion::parse("  mise 2024.1.2\n");
        assert_eq!(v.raw, "2024.1.2");
    }

    #[test]
    fn parse_real_mise_output() {
        let v = MiseVersion::parse("2026.5.18 macos-arm64 (2026-05-31)");
        assert_eq!(v.raw, "2026.5.18");
        assert!(v.parsed.is_some());
        assert_eq!(v.parsed.as_ref().unwrap().major, 2026);
        assert_eq!(v.parsed.as_ref().unwrap().minor, 5);
        assert_eq!(v.parsed.as_ref().unwrap().patch, 18);
    }

    #[test]
    fn parse_unparseable_output() {
        let v = MiseVersion::parse("unknown-format");
        assert_eq!(v.raw, "unknown-format");
        assert!(v.parsed.is_none());
    }

    #[test]
    fn is_at_least_true() {
        let v = MiseVersion::parse("2024.1.2");
        let req = Version::parse("2024.1.0").unwrap();
        assert!(v.is_at_least(&req));
    }

    #[test]
    fn is_at_least_false() {
        let v = MiseVersion::parse("2024.1.2");
        let req = Version::parse("2025.0.0").unwrap();
        assert!(!v.is_at_least(&req));
    }

    #[test]
    fn is_at_least_unparseable_is_false() {
        let v = MiseVersion::parse("unknown-format");
        let req = Version::parse("0.0.1").unwrap();
        assert!(!v.is_at_least(&req));
    }

    #[test]
    fn display_uses_raw() {
        let v = MiseVersion::parse("mise 2024.1.2");
        assert_eq!(v.to_string(), "2024.1.2");
    }

    #[test]
    fn from_tool_version_keeps_raw_and_parsed() {
        // The detector parses with the same prefix-strip + first-token
        // conventions as `MiseVersion::parse`, so both routes agree.
        let tv = toride_installer::ToolVersion::parse("mise 2026.9.1 linux-x64", "mise");
        let mv = MiseVersion::from(&tv);
        assert_eq!(mv, MiseVersion::parse("2026.9.1 linux-x64"));
        assert_eq!(mv.raw, "2026.9.1");
        assert_eq!(mv.parsed, Some(Version::parse("2026.9.1").unwrap()));
    }

    #[test]
    fn from_unparseable_tool_version_stays_unparsed() {
        let tv = toride_installer::ToolVersion::parse("not a version", "mise");
        let mv = MiseVersion::from(&tv);
        assert_eq!(mv.raw, "not");
        assert!(mv.parsed.is_none());
        assert!(!mv.is_at_least(&Version::new(0, 0, 1)));
    }
}
