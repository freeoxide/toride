//! Typed specification module with validated newtypes and spec builders.
//!
//! This module defines the strongly-typed Rust model for Fail2Ban configuration.
//! All names are validated on construction to reject shell metacharacters and path
//! traversal attempts. Specs use `typed_builder` for compile-time checked builders
//! that enforce required fields at the type level.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{Error, Result};

// ---------------------------------------------------------------------------
// Name validation helpers
// ---------------------------------------------------------------------------

/// Characters that are forbidden in jail/filter/action names.
///
/// Rejects: `/`, `..`, newlines, and shell metacharacters
/// `;`, `|`, `&`, `$`, backtick, `\`, `'`, `"`, `(`, `)`, `<`, `>`, `{`, `}`.
const FORBIDDEN_NAME_CHARS: &[char] = &[
    '/', '\n', '\r', ';', '|', '&', '$', '`', '\\', '\'', '"', '(', ')', '<', '>', '{', '}',
];

/// Validates that a name string is non-empty and contains no forbidden characters
/// or path-traversal sequences.
fn validate_name(s: &str, type_label: &str) -> Result<String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(Error::InvalidConfig(format!(
            "{type_label} must not be empty"
        )));
    }
    if trimmed.contains("..") {
        return Err(Error::InvalidConfig(format!(
            "{type_label} must not contain \"..\": {s:?}"
        )));
    }
    if let Some(ch) = trimmed.chars().find(|c| FORBIDDEN_NAME_CHARS.contains(c)) {
        return Err(Error::InvalidConfig(format!(
            "{type_label} contains forbidden character {ch:?}: {s:?}"
        )));
    }
    Ok(trimmed.to_owned())
}

/// Macro-like helper: generates a validated name newtype with common trait impls.
///
/// Produces a struct wrapping a `String`, validates via `validate_name` in `FromStr`,
/// and derives `Clone`, `Debug`, `PartialEq`, `Eq`, `Hash`, `Serialize`, `Deserialize`.
macro_rules! define_name_type {
    ($name:ident, $label:literal) => {
        /// Validated name newtype.
        ///
        /// Rejects empty strings, `/`, `..`, newlines, and shell metacharacters on construction.
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl $name {
            /// Construct a validated name, returning an error if invalid.
            pub fn new(s: &str) -> Result<Self> {
                validate_name(s, $label).map(Self)
            }

            /// Returns the inner name as a string slice.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consumes the newtype and returns the inner `String`.
            pub fn into_inner(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl FromStr for $name {
            type Err = Error;

            fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
                Self::new(s)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(
                &self,
                serializer: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(
                deserializer: D,
            ) -> std::result::Result<Self, D::Error> {
                let s = String::deserialize(deserializer)?;
                Self::new(&s).map_err(serde::de::Error::custom)
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Validated name newtypes
// ---------------------------------------------------------------------------

define_name_type!(JailName, "JailName");
define_name_type!(FilterName, "FilterName");
define_name_type!(ActionName, "ActionName");

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Fail2Ban log backend selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum Backend {
    /// Auto-detect the appropriate backend.
    #[default]
    Auto,
    /// Use systemd journal.
    Systemd,
    /// Poll log files directly.
    Polling,
}

impl fmt::Display for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auto => write!(f, "auto"),
            Self::Systemd => write!(f, "systemd"),
            Self::Polling => write!(f, "polling"),
        }
    }
}

/// Network protocol for port-based filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum Protocol {
    /// TCP protocol.
    #[default]
    Tcp,
    /// UDP protocol.
    Udp,
    /// Both TCP and UDP.
    Both,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Udp => write!(f, "udp"),
            Self::Both => write!(f, "both"),
        }
    }
}

/// DNS resolution policy for logged hostnames.
///
/// Defaults to `No` for security: app logs typically contain IPs already,
/// and DNS resolution in Fail2Ban can cause delays or amplify DoS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum UseDns {
    /// Resolve hostnames found in log lines.
    Yes,
    /// Do not resolve hostnames (recommended default).
    #[default]
    No,
    /// Resolve but warn about potential issues.
    Warn,
}

impl fmt::Display for UseDns {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Yes => write!(f, "yes"),
            Self::No => write!(f, "no"),
            Self::Warn => write!(f, "warn"),
        }
    }
}

/// Whether an action is a stock Fail2Ban action or a custom one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum ActionKind {
    /// Use a stock action shipped with Fail2Ban.
    #[default]
    Stock,
    /// Use a custom action defined by the caller.
    Custom,
}

impl fmt::Display for ActionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stock => write!(f, "stock"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

// ---------------------------------------------------------------------------
// Value types
// ---------------------------------------------------------------------------

/// A human-readable duration string validated by `humantime`, or a permanent marker.
///
/// Examples: `"10m"`, `"1h"`, `"7d"`, `"30s"`, `"permanent"`, `"-1"`.
/// Stored as the original string and validated on construction via `humantime::parse_duration`,
/// unless the value is `"permanent"` or `"-1"` which represent an indefinite duration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DurationSpec(String);

/// Sentinel values that represent a permanent (indefinite) ban duration.
const PERMANENT_MARKERS: &[&str] = &["permanent", "-1"];

impl DurationSpec {
    /// Construct a validated duration spec from a string.
    ///
    /// Accepts standard `humantime` duration strings (e.g. `"10m"`, `"1h"`) as well as
    /// the special sentinel values `"permanent"` and `"-1"` which represent an indefinite
    /// duration used for permanent bans.
    pub fn new(s: &str) -> Result<Self> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidConfig(
                "DurationSpec must not be empty".into(),
            ));
        }
        if !PERMANENT_MARKERS.contains(&trimmed) {
            humantime::parse_duration(trimmed)
                .map_err(|e| Error::InvalidConfig(format!("invalid duration {s:?}: {e}")))?;
        }
        Ok(Self(trimmed.to_owned()))
    }

    /// Returns the duration string as a slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns `true` if this duration represents a permanent (indefinite) ban.
    pub fn is_permanent(&self) -> bool {
        PERMANENT_MARKERS.contains(&self.0.as_str())
    }

    /// Parse the inner string into a `std::time::Duration`.
    ///
    /// For permanent durations, returns `std::time::Duration::MAX`.
    ///
    /// # Panics
    ///
    /// Will never panic because the string was validated on construction.
    pub fn to_duration(&self) -> std::time::Duration {
        if self.is_permanent() {
            return std::time::Duration::MAX;
        }
        humantime::parse_duration(&self.0).expect("DurationSpec was validated on construction")
    }
}

impl fmt::Display for DurationSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for DurationSpec {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl Serialize for DurationSpec {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for DurationSpec {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::new(&s).map_err(serde::de::Error::custom)
    }
}

/// A port number with an associated protocol.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PortSpec {
    /// Port number (0-65535).
    pub port: u16,
    /// Associated protocol.
    pub protocol: Protocol,
}

impl PortSpec {
    /// Create a new port spec with the given port and TCP protocol.
    #[must_use]
    pub fn new(port: u16) -> Self {
        Self {
            port,
            protocol: Protocol::default(),
        }
    }

    /// Create a port spec with a specific protocol.
    #[must_use]
    pub fn with_protocol(port: u16, protocol: Protocol) -> Self {
        Self { port, protocol }
    }
}

impl fmt::Display for PortSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.port)
    }
}

/// An IP address or CIDR block, parsed via `ipnet`.
///
/// Supports both bare IPs (`"192.168.1.1"`) and CIDR notation (`"10.0.0.0/8"`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IpOrCidr(#[serde(with = "ipnet_serde")] ipnet::IpNet);

impl IpOrCidr {
    /// Returns the underlying `ipnet::IpNet`.
    pub fn as_net(&self) -> &ipnet::IpNet {
        &self.0
    }

    /// Returns `true` if `ip` is contained within this network.
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.0.contains(&ip)
    }

    /// Returns `true` if this network overlaps with `other`.
    ///
    /// Two networks overlap if either contains a host address of the other.
    /// `ipnet` does not provide a built-in `overlaps` method, so we check
    /// containment of the network address of each in the other.
    pub fn overlaps(&self, other: &Self) -> bool {
        self.0.contains(&other.0.addr()) || other.0.contains(&self.0.addr())
    }

    /// Consume and return the inner `ipnet::IpNet`.
    pub fn into_inner(self) -> ipnet::IpNet {
        self.0
    }
}

impl FromStr for IpOrCidr {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        // Try CIDR parsing first, then fall back to bare IP with host prefix.
        if let Ok(net) = ipnet::IpNet::from_str(s) {
            return Ok(Self(net));
        }
        let ip: IpAddr = s
            .parse()
            .map_err(|e| Error::InvalidIp(format!("invalid IP or CIDR {s:?}: {e}")))?;
        let net = match ip {
            IpAddr::V4(v4) => ipnet::IpNet::from(ipnet::Ipv4Net::new(v4, 32).expect("valid /32")),
            IpAddr::V6(v6) => ipnet::IpNet::from(ipnet::Ipv6Net::new(v6, 128).expect("valid /128")),
        };
        Ok(Self(net))
    }
}

impl fmt::Display for IpOrCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Serde helper for `ipnet::IpNet` using its `Display`/`FromStr` forms.
mod ipnet_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::str::FromStr;

    pub fn serialize<S: Serializer>(
        net: &ipnet::IpNet,
        s: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&net.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> std::result::Result<ipnet::IpNet, D::Error> {
        let st = String::deserialize(d)?;
        ipnet::IpNet::from_str(&st).map_err(serde::de::Error::custom)
    }
}

/// A validated log file path.
///
/// On construction, validates that the parent directory exists.
/// The file itself does not need to exist (it may be created later by the
/// application or log rotation).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LogPath(PathBuf);

impl LogPath {
    /// Construct a log path, validating that the parent directory exists and the
    /// path does not contain `..` (parent directory) components.
    pub fn new(path: &Path) -> Result<Self> {
        let p = path.to_path_buf();

        // Path traversal protection: reject any ".." components
        if p.components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(Error::Validation(format!(
                "log path must not contain \"..\" components: {}",
                p.display()
            )));
        }

        match p.parent() {
            Some(parent) if parent.as_os_str().is_empty() => {}
            Some(parent) => {
                if !parent.exists() {
                    return Err(Error::InvalidConfig(format!(
                        "log path parent directory does not exist: {}",
                        parent.display()
                    )));
                }
            }
            None => {
                return Err(Error::InvalidConfig(format!(
                    "log path has no parent directory: {}",
                    p.display()
                )));
            }
        }
        Ok(Self(p))
    }

    /// Returns the path as a reference.
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// Consume and return the inner `PathBuf`.
    pub fn into_inner(self) -> PathBuf {
        self.0
    }
}

impl fmt::Display for LogPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.display())
    }
}

impl AsRef<Path> for LogPath {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl FromStr for LogPath {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::new(Path::new(s))
    }
}

/// A systemd journal match expression (e.g. `_SYSTEMD_UNIT=sshd.service`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JournalMatch(String);

impl JournalMatch {
    /// Construct a journal match, validating it is non-empty and contains at
    /// least one `=` character (systemd journal match syntax requires
    /// `field=value` format, e.g. `_SYSTEMD_UNIT=sshd.service`).
    pub fn new(s: &str) -> Result<Self> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidConfig(
                "JournalMatch must not be empty".into(),
            ));
        }
        if !trimmed.contains('=') {
            return Err(Error::Validation(format!(
                "JournalMatch must contain a '=' character (expected field=value format): {s:?}"
            )));
        }
        Ok(Self(trimmed.to_owned()))
    }

    /// Returns the match expression as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for JournalMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for JournalMatch {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::new(s)
    }
}

/// A Fail2Ban failregex line.
///
/// Validated on construction to contain the required `<HOST>` placeholder.
/// Fail2Ban uses `<HOST>` as an interpolation anchor for extracting the
/// offending IP address from log lines.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RegexLine(String);

impl RegexLine {
    /// Construct a regex line, validating that it contains `<HOST>`.
    pub fn new(s: &str) -> Result<Self> {
        if !s.contains("<HOST>") {
            return Err(Error::InvalidRegex(format!(
                "failregex must contain \"<HOST>\": {s:?}"
            )));
        }
        Ok(Self(s.to_owned()))
    }

    /// Returns the regex pattern as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RegexLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for RegexLine {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::new(s)
    }
}

/// A list of IP addresses and/or CIDR blocks to ignore (never ban).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct IgnoreIpList(Vec<IpOrCidr>);

impl IgnoreIpList {
    /// Construct a new ignore list.
    #[must_use]
    pub fn new(ips: Vec<IpOrCidr>) -> Self {
        Self(ips)
    }

    /// Returns `true` if the given IP is in the ignore list.
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.0.iter().any(|cidr| cidr.contains(ip))
    }

    /// Returns the number of entries in the ignore list.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the ignore list is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns an iterator over the entries.
    pub fn iter(&self) -> impl Iterator<Item = &IpOrCidr> {
        self.0.iter()
    }
}

impl fmt::Display for IgnoreIpList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for ip in &self.0 {
            if !first {
                write!(f, ", ")?;
            }
            write!(f, "{ip}")?;
            first = false;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Spec structs
// ---------------------------------------------------------------------------

/// Complete specification for a Fail2Ban jail.
///
/// Use [`JailSpec::builder()`] to construct with compile-time enforcement of
/// required fields.
#[derive(Debug, Clone, Serialize, Deserialize, typed_builder::TypedBuilder)]
pub struct JailSpec {
    /// Name of the jail (validated, no shell metacharacters).
    pub name: JailName,
    /// Whether the jail is enabled.
    #[builder(default = true)]
    pub enabled: bool,
    /// Filter definition for this jail.
    pub filter: FilterSpec,
    /// Actions to execute on ban/unban.
    #[builder(default = vec![])]
    pub actions: Vec<ActionSpec>,
    /// Log backend to use.
    #[builder(default)]
    pub backend: Backend,
    /// Log file paths to monitor (required for file-log backends).
    #[builder(default = vec![])]
    pub log_paths: Vec<LogPath>,
    /// Systemd journal match expressions (required for systemd backend).
    #[builder(default = vec![])]
    pub journal_matches: Vec<JournalMatch>,
    /// Ports to protect.
    #[builder(default = vec![])]
    pub ports: Vec<PortSpec>,
    /// Network protocol for port matching.
    #[builder(default)]
    pub protocol: Protocol,
    /// Duration for which an IP is banned.
    pub bantime: DurationSpec,
    /// Time window in which failures are counted.
    pub findtime: DurationSpec,
    /// Number of failures before a ban is triggered. Must be > 0.
    #[builder(default = 5)]
    pub maxretry: u32,
    /// IP addresses and CIDR blocks to never ban.
    #[builder(default)]
    pub ignore_ips: IgnoreIpList,
    /// DNS resolution policy for hostnames in logs.
    #[builder(default)]
    pub usedns: UseDns,
    /// Maximum number of log lines to buffer for multi-line regex matching.
    #[builder(default = None)]
    pub maxlines: Option<u32>,
    /// Whether permanent bans (`bantime = "permanent"` or `"-1"`) are allowed.
    /// Defaults to `false` for safety; must be explicitly opted-in.
    #[builder(default = false)]
    pub allow_permanent_ban: bool,
    /// Additional Fail2Ban jail options not covered by typed fields.
    #[builder(default = HashMap::new())]
    pub extra_options: HashMap<String, String>,
}

impl JailSpec {
    /// Validates cross-field constraints on this jail specification.
    ///
    /// Checks:
    /// - `maxretry > 0`
    /// - `findtime > 0` (zero duration from values like `"0s"` is rejected)
    /// - `bantime` should typically be >= `findtime`
    /// - permanent `bantime` requires `allow_permanent_ban`
    /// - `backend == Systemd` requires `journal_matches` to be non-empty and `log_paths` to be empty
    /// - file-log backends require at least one `log_path`
    pub fn validate(&self) -> Result<()> {
        if self.maxretry == 0 {
            return Err(Error::Validation(format!(
                "jail {:?}: maxretry must be > 0",
                self.name
            )));
        }

        // findtime must be greater than zero
        let findtime_dur = self.findtime.to_duration();
        if findtime_dur == std::time::Duration::ZERO {
            return Err(Error::Validation(
                "findtime must be greater than zero".into(),
            ));
        }

        // Permanent ban gating
        if self.bantime.is_permanent() && !self.allow_permanent_ban {
            return Err(Error::Validation(
                "permanent bans require explicit opt-in via allow_permanent_ban".into(),
            ));
        }

        // bantime should typically be >= findtime
        let bantime_dur = self.bantime.to_duration();
        if !self.bantime.is_permanent() && bantime_dur < findtime_dur {
            return Err(Error::Validation(format!(
                "jail {:?}: bantime should typically be >= findtime",
                self.name
            )));
        }

        match self.backend {
            Backend::Systemd => {
                if self.journal_matches.is_empty() {
                    return Err(Error::Validation(format!(
                        "jail {:?}: backend=systemd requires at least one journal_match",
                        self.name
                    )));
                }
                if !self.log_paths.is_empty() {
                    return Err(Error::Validation(format!(
                        "jail {:?}: backend=systemd must not use log_paths (use journal_matches instead)",
                        self.name
                    )));
                }
            }
            Backend::Auto | Backend::Polling => {
                if self.log_paths.is_empty() && self.journal_matches.is_empty() {
                    return Err(Error::Validation(format!(
                        "jail {:?}: file-log backend requires at least one log_path",
                        self.name
                    )));
                }
            }
        }

        Ok(())
    }
}

/// Specification for a Fail2Ban filter.
///
/// Use [`FilterSpec::builder()`] to construct with compile-time enforcement of
/// required fields.
#[derive(Debug, Clone, Serialize, Deserialize, typed_builder::TypedBuilder)]
pub struct FilterSpec {
    /// Name of the filter (validated).
    pub name: FilterName,
    /// Filters applied before this one.
    #[builder(default = vec![])]
    pub before: Vec<FilterName>,
    /// Filters applied after this one.
    #[builder(default = vec![])]
    pub after: Vec<FilterName>,
    /// Optional filter definition string (inline filter config).
    #[builder(default = None)]
    pub definition: Option<String>,
    /// Pre-filter regex applied before `failregex`.
    #[builder(default = None)]
    pub prefregex: Option<String>,
    /// One or more failregex patterns. Must not be empty.
    pub failregex: Vec<RegexLine>,
    /// Regex patterns for lines to ignore.
    #[builder(default = vec![])]
    pub ignoreregex: Vec<String>,
    /// Date pattern for log line timestamp parsing.
    #[builder(default = None)]
    pub datepattern: Option<String>,
    /// Journal match override for this filter.
    #[builder(default = None)]
    pub journalmatch: Option<JournalMatch>,
    /// Filter mode (e.g. "normal", "aggressive").
    #[builder(default = None)]
    pub mode: Option<String>,
    /// Additional filter options.
    #[builder(default = HashMap::new())]
    pub extra_options: HashMap<String, String>,
}

impl FilterSpec {
    /// Validates that this filter spec has at least one failregex pattern.
    pub fn validate(&self) -> Result<()> {
        if self.failregex.is_empty() {
            return Err(Error::InvalidConfig(format!(
                "filter {:?}: failregex must not be empty",
                self.name
            )));
        }
        Ok(())
    }

    /// Convenience constructor for referencing a named filter without inline
    /// regex patterns. The `failregex` field is set to an empty vec; the filter
    /// definition is expected to come from a stock or pre-existing filter file.
    pub fn named(name: &str) -> Result<Self> {
        Ok(Self::builder()
            .name(FilterName::new(name)?)
            .failregex(vec![])
            .build())
    }
}

/// Specification for a Fail2Ban action.
///
/// Use [`ActionSpec::builder()`] to construct with compile-time enforcement of
/// required fields.
#[derive(Debug, Clone, Serialize, Deserialize, typed_builder::TypedBuilder)]
pub struct ActionSpec {
    /// Name of the action (validated).
    pub name: ActionName,
    /// Whether this is a stock or custom action.
    #[builder(default)]
    pub kind: ActionKind,
    /// Stock action name (e.g. `"nftables-multiport"`) when `kind == Stock`.
    #[builder(default = None)]
    pub stock_name: Option<String>,
    /// Key-value parameters passed to the action template.
    #[builder(default = HashMap::new())]
    pub parameters: HashMap<String, String>,
    /// Command executed when the jail starts.
    #[builder(default = None)]
    pub actionstart: Option<String>,
    /// Command executed when the jail stops.
    #[builder(default = None)]
    pub actionstop: Option<String>,
    /// Command executed to check if the action is healthy.
    #[builder(default = None)]
    pub actioncheck: Option<String>,
    /// Command executed when an IP is banned.
    #[builder(default = None)]
    pub actionban: Option<String>,
    /// Command executed when an IP is unbanned.
    #[builder(default = None)]
    pub actionunban: Option<String>,
    /// Timeout for action command execution.
    #[builder(default = None)]
    pub timeout: Option<std::time::Duration>,
}

impl ActionSpec {
    /// Convenience constructor for referencing a stock Fail2Ban action.
    pub fn stock(name: &str) -> Result<Self> {
        Ok(Self::builder()
            .name(ActionName::new(name)?)
            .kind(ActionKind::Stock)
            .stock_name(Some(name.to_owned()))
            .build())
    }

    /// Convenience constructor for a custom action with ban/unban commands.
    pub fn custom(name: &str) -> Result<Self> {
        Ok(Self::builder()
            .name(ActionName::new(name)?)
            .kind(ActionKind::Custom)
            .build())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "spec.test.rs"]
mod tests;
