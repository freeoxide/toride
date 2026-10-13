//! Host destination grammar and host-key checking policy shared by the
//! `toride-ssh` sub-crates: [`HostSpec`] makes an invalid `[user@]host`
//! unrepresentable, and [`HostKeyPolicy`] names the `StrictHostKeyChecking`
//! posture an ssh invocation implies.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use toride_runner::policy::contains_shell_metachars;

use crate::{Error, Result};

/// Maximum accepted length, in bytes, of a host spec input.
pub const MAX_HOST_INPUT_LEN: usize = 255;

/// A validated `[user@]host` ssh destination.
///
/// Accepts bare hostnames (including fully-qualified names with a trailing
/// dot), IPv4 literals, bare and bracketed IPv6 literals (optionally with a
/// `%zone` scope id, e.g. `[fe80::1%eth0]`), each optionally prefixed with
/// `user@`; everything else: shell metacharacters, whitespace, control
/// characters, leading dashes, empty or overlong input: is a typed
/// [`Error::InvalidHost`] rejection and can never be constructed as a
/// `HostSpec`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HostSpec {
    user: Option<String>,
    host: String,
}

impl HostSpec {
    /// Parse and validate a `[user@]host` destination.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidHost`] when the input is empty, longer than
    /// [`MAX_HOST_INPUT_LEN`] bytes, or contains control characters,
    /// whitespace, shell metacharacters, a leading dash, a malformed
    /// bracketed address (including an invalid `%zone` scope id), or a
    /// hostname label that is empty, over 63 bytes, or not
    /// alphanumeric-plus-hyphen. The reason never echoes the input.
    pub fn parse(input: &str) -> Result<Self> {
        if input.is_empty() {
            return Err(Error::InvalidHost("must not be empty".to_owned()));
        }
        if input.len() > MAX_HOST_INPUT_LEN {
            return Err(Error::InvalidHost(format!(
                "must not exceed {MAX_HOST_INPUT_LEN} bytes"
            )));
        }
        if input.chars().any(char::is_control) {
            return Err(Error::InvalidHost(
                "must not contain control characters".to_owned(),
            ));
        }
        if input.chars().any(char::is_whitespace) {
            return Err(Error::InvalidHost("must not contain whitespace".to_owned()));
        }
        if contains_shell_metachars(input) {
            return Err(Error::InvalidHost(
                "must not contain shell metacharacters".to_owned(),
            ));
        }
        if input.matches('@').count() > 1 {
            return Err(Error::InvalidHost(
                "must not contain more than one '@'".to_owned(),
            ));
        }
        let (user, host) = match input.split_once('@') {
            Some((user, host)) => (Some(user), host),
            None => (None, input),
        };
        if let Some(user) = user {
            validate_user(user)?;
        }
        validate_host(host)?;
        Ok(Self {
            user: user.map(str::to_owned),
            host: host.to_owned(),
        })
    }

    /// The login user, if the spec carries one.
    #[must_use]
    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    /// The host spelling ssh expects as a single argv element, brackets kept
    /// for IPv6 literals.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The full `user@host` destination operand.
    #[must_use]
    pub fn destination(&self) -> String {
        let host = &self.host;
        match &self.user {
            Some(user) => format!("{user}@{host}"),
            None => host.clone(),
        }
    }
}

impl std::fmt::Display for HostSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.destination())
    }
}

impl FromStr for HostSpec {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl Serialize for HostSpec {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.destination())
    }
}

impl<'de> Deserialize<'de> for HostSpec {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let destination = String::deserialize(deserializer)?;
        HostSpec::parse(&destination).map_err(serde::de::Error::custom)
    }
}

fn validate_user(user: &str) -> Result<()> {
    if user.is_empty() {
        return Err(Error::InvalidHost(
            "user must not be empty when '@' is present".to_owned(),
        ));
    }
    if user.starts_with('-') {
        return Err(Error::InvalidHost(
            "user must not start with a dash".to_owned(),
        ));
    }
    if user.contains(['/', ':', ',']) {
        return Err(Error::InvalidHost(
            "user must not contain '/', ':', or ','".to_owned(),
        ));
    }
    Ok(())
}

fn validate_host(host: &str) -> Result<()> {
    if host.is_empty() {
        return Err(Error::InvalidHost(
            "host must not be empty when '@' is present".to_owned(),
        ));
    }
    if host.starts_with('-') {
        return Err(Error::InvalidHost(
            "host must not start with a dash".to_owned(),
        ));
    }
    if let Some(inner) = host.strip_prefix('[') {
        let Some(inner) = inner.strip_suffix(']') else {
            return Err(Error::InvalidHost(
                "bracketed address must end with ']'".to_owned(),
            ));
        };
        if inner.contains(['[', ']']) {
            return Err(Error::InvalidHost(
                "bracketed address must not contain nested brackets".to_owned(),
            ));
        }
        // A `%zone` scope id is only legal in the bracketed form
        // (`[fe80::1%eth0]`); ssh rejects it in the bare form.
        let (addr, zone) = match inner.split_once('%') {
            Some((addr, zone)) => (addr, Some(zone)),
            None => (inner, None),
        };
        if let Some(zone) = zone {
            validate_zone_id(zone)?;
        }
        return Ipv6Addr::from_str(addr).map(|_| ()).map_err(|err| {
            Error::InvalidHost(format!("bracketed address must be an IPv6 literal: {err}"))
        });
    }
    if host.contains(['[', ']']) {
        return Err(Error::InvalidHost(
            "brackets are only valid around an IPv6 literal".to_owned(),
        ));
    }
    if host.contains(':') {
        return Ipv6Addr::from_str(host).map(|_| ()).map_err(|err| {
            Error::InvalidHost(format!(
                "bare colon-bearing host must be an IPv6 literal: {err}"
            ))
        });
    }
    if Ipv4Addr::from_str(host).is_ok() {
        return Ok(());
    }
    validate_hostname(host)
}

fn validate_zone_id(zone: &str) -> Result<()> {
    if zone.is_empty() || zone.len() > 63 {
        return Err(Error::InvalidHost(
            "zone id must be between 1 and 63 bytes".to_owned(),
        ));
    }
    if zone.starts_with('-') || zone.starts_with('.') {
        return Err(Error::InvalidHost(
            "zone id must not start with '-' or '.'".to_owned(),
        ));
    }
    if !zone
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
    {
        return Err(Error::InvalidHost(
            "zone id must be alphanumeric, '-', '.', or '_'".to_owned(),
        ));
    }
    Ok(())
}

fn validate_hostname(host: &str) -> Result<()> {
    // A single trailing dot marks a fully-qualified domain name and is legal
    // ssh input; validate the labels that precede it.
    let host = host.strip_suffix('.').unwrap_or(host);
    for label in host.split('.') {
        if label.is_empty() {
            return Err(Error::InvalidHost(
                "hostname labels must not be empty".to_owned(),
            ));
        }
        if label.len() > 63 {
            return Err(Error::InvalidHost(
                "hostname labels must not exceed 63 bytes".to_owned(),
            ));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(Error::InvalidHost(
                "hostname labels must be alphanumeric or '-'".to_owned(),
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(Error::InvalidHost(
                "hostname labels must not start or end with '-'".to_owned(),
            ));
        }
    }
    Ok(())
}

/// The `StrictHostKeyChecking` posture an ssh invocation runs with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum HostKeyPolicy {
    /// Refuse unknown hosts: `-o StrictHostKeyChecking=yes`.
    #[default]
    Strict,
    /// Accept and record a first-seen host key, refuse changes afterwards:
    /// `-o StrictHostKeyChecking=accept-new`.
    AcceptNew,
}

impl HostKeyPolicy {
    /// The `Key=value` argument paired with `-o` for this policy.
    #[must_use]
    pub fn ssh_option(&self) -> &'static str {
        match self {
            Self::Strict => "StrictHostKeyChecking=yes",
            Self::AcceptNew => "StrictHostKeyChecking=accept-new",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_plain_hostname() {
        let spec = HostSpec::parse("vps.example.org").unwrap();
        assert_eq!(spec.user(), None);
        assert_eq!(spec.host(), "vps.example.org");
        assert_eq!(spec.destination(), "vps.example.org");
    }

    #[test]
    fn parse_accepts_single_label_hostname() {
        assert!(HostSpec::parse("myserver").is_ok());
    }

    #[test]
    fn parse_accepts_user_at_hostname() {
        let spec = HostSpec::parse("root@vps.example.org").unwrap();
        assert_eq!(spec.user(), Some("root"));
        assert_eq!(spec.host(), "vps.example.org");
        assert_eq!(spec.destination(), "root@vps.example.org");
    }

    #[test]
    fn parse_accepts_ipv4_literal() {
        assert!(HostSpec::parse("192.0.2.10").is_ok());
        assert!(HostSpec::parse("root@192.0.2.10").is_ok());
    }

    #[test]
    fn parse_accepts_bracketed_ipv6_literal() {
        let spec = HostSpec::parse("[2001:db8::1]").unwrap();
        assert_eq!(spec.host(), "[2001:db8::1]");
        assert_eq!(spec.destination(), "[2001:db8::1]");
    }

    #[test]
    fn parse_accepts_user_at_bracketed_ipv6_literal() {
        let spec = HostSpec::parse("root@[2001:db8::1]").unwrap();
        assert_eq!(spec.user(), Some("root"));
        assert_eq!(spec.destination(), "root@[2001:db8::1]");
    }

    #[test]
    fn parse_accepts_bare_ipv6_literal() {
        assert!(HostSpec::parse("2001:db8::1").is_ok());
        assert!(HostSpec::parse("deploy@2001:db8::1").is_ok());
    }

    #[test]
    fn parse_accepts_user_with_dot_and_dash() {
        assert!(HostSpec::parse("first.last-dep@vps.example.org").is_ok());
    }

    #[test]
    fn parse_rejects_empty_input() {
        assert!(matches!(
            HostSpec::parse(""),
            Err(Error::InvalidHost(reason)) if reason.contains("empty")
        ));
    }

    #[test]
    fn parse_rejects_whitespace_only_input() {
        assert!(matches!(
            HostSpec::parse("   "),
            Err(Error::InvalidHost(reason)) if reason.contains("whitespace")
        ));
    }

    #[test]
    fn parse_rejects_embedded_whitespace() {
        assert!(matches!(
            HostSpec::parse("vps example.org"),
            Err(Error::InvalidHost(reason)) if reason.contains("whitespace")
        ));
        assert!(matches!(
            HostSpec::parse("user name@host"),
            Err(Error::InvalidHost(reason)) if reason.contains("whitespace")
        ));
    }

    #[test]
    fn parse_rejects_shell_metacharacters() {
        assert!(matches!(
            HostSpec::parse("host;other"),
            Err(Error::InvalidHost(reason)) if reason.contains("metacharacter")
        ));
        for bad in [
            "host&&other",
            "host|other",
            "host`id`",
            "$(reboot)",
            "host>${out}",
            "a\nb",
            "a\rb",
        ] {
            assert!(HostSpec::parse(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn parse_rejects_leading_dash_option_injection() {
        let err = HostSpec::parse("-oProxyCommand=evil").unwrap_err();
        assert!(matches!(err, Error::InvalidHost(ref reason) if reason.contains("dash")));
        assert!(
            !err.to_string().contains("ProxyCommand"),
            "rejection must not echo the input: {err}"
        );
        assert!(HostSpec::parse("-o").is_err());
    }

    #[test]
    fn parse_rejects_leading_dash_in_host_and_user_positions() {
        assert!(HostSpec::parse("-host.example.org").is_err());
        assert!(HostSpec::parse("-user@host.example.org").is_err());
        assert!(HostSpec::parse("user@-host.example.org").is_err());
    }

    #[test]
    fn parse_rejects_control_characters() {
        for bad in ["host\tname", "host\0name", "host\x1bname"] {
            assert!(matches!(
                HostSpec::parse(bad),
                Err(Error::InvalidHost(reason)) if reason.contains("control")
            ));
        }
    }

    #[test]
    fn parse_rejects_overlong_input() {
        let overlong = format!("{}.example.org", "a".repeat(300));
        assert!(matches!(
            HostSpec::parse(&overlong),
            Err(Error::InvalidHost(reason)) if reason.contains("255")
        ));
    }

    #[test]
    fn parse_rejects_empty_user_or_host_around_at() {
        assert!(HostSpec::parse("user@").is_err());
        assert!(HostSpec::parse("@host").is_err());
        assert!(HostSpec::parse("@").is_err());
    }

    #[test]
    fn parse_rejects_multiple_at_signs() {
        assert!(matches!(
            HostSpec::parse("a@b@c"),
            Err(Error::InvalidHost(reason)) if reason.contains("one '@'")
        ));
    }

    #[test]
    fn parse_rejects_user_separators() {
        for bad in ["root:sa@host", "root/sa@host", "root,sa@host"] {
            assert!(HostSpec::parse(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn parse_rejects_malformed_brackets() {
        assert!(HostSpec::parse("[2001:db8::1").is_err());
        assert!(HostSpec::parse("2001:db8::1]").is_err());
        assert!(HostSpec::parse("[[2001:db8::1]]").is_err());
        assert!(HostSpec::parse("[not-an-address]").is_err());
    }

    #[test]
    fn parse_accepts_trailing_dot_fqdn() {
        let spec = HostSpec::parse("vps.example.org.").unwrap();
        assert_eq!(spec.host(), "vps.example.org.");
        assert_eq!(spec.destination(), "vps.example.org.");
        assert!(HostSpec::parse("singlelabel.").is_ok());
        assert!(HostSpec::parse("host..").is_err());
        assert!(HostSpec::parse(".").is_err());
    }

    #[test]
    fn parse_accepts_bracketed_ipv6_with_zone_id() {
        let spec = HostSpec::parse("[fe80::1%eth0]").unwrap();
        assert_eq!(spec.host(), "[fe80::1%eth0]");
        assert!(HostSpec::parse("root@[fe80::1%eth0]").is_ok());
        assert!(HostSpec::parse("[fe80::1%enp0s25.100]").is_ok());
    }

    #[test]
    fn parse_rejects_malformed_zone_ids() {
        for bad in [
            "[fe80::1%]",
            "[fe80::1%e t h0]",
            "[fe80::1%-eth]",
            "[fe80::1%eth;0]",
            "[fe80::1%a*b]",
            "fe80::1%eth0",
        ] {
            assert!(HostSpec::parse(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn parse_rejects_hostname_label_violations() {
        for bad in [
            "host..name",
            ".host",
            "-host",
            "host-",
            "sub.-host",
            "host_name",
            "host name",
        ] {
            assert!(HostSpec::parse(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn parse_rejects_bare_colon_bearing_non_ipv6() {
        assert!(HostSpec::parse("192.0.2.10:22").is_err());
        assert!(HostSpec::parse("host:22").is_err());
    }

    #[test]
    fn rejection_reasons_never_echo_the_input() {
        for bad in [
            "-oProxyCommand=evil",
            "host;other",
            "user@",
            "[not-an-address]",
            "host..name",
        ] {
            let err = HostSpec::parse(bad).unwrap_err();
            let rendered = err.to_string();
            for fragment in ["ProxyCommand", "evil", "other", "not-an-address"] {
                assert!(
                    !rendered.contains(fragment),
                    "error for {bad:?} leaked input: {rendered}"
                );
            }
        }
    }

    #[test]
    fn display_prints_the_destination_operand() {
        let spec = HostSpec::parse("root@[2001:db8::1]").unwrap();
        assert_eq!(spec.to_string(), "root@[2001:db8::1]");
    }

    #[test]
    fn from_str_delegates_to_parse() {
        let spec = "root@vps.example.org".parse::<HostSpec>().unwrap();
        assert_eq!(spec.destination(), "root@vps.example.org");
        assert!("bad host".parse::<HostSpec>().is_err());
    }

    #[test]
    fn strict_policy_maps_to_yes() {
        assert_eq!(
            HostKeyPolicy::Strict.ssh_option(),
            "StrictHostKeyChecking=yes"
        );
    }

    #[test]
    fn accept_new_policy_maps_to_accept_new() {
        assert_eq!(
            HostKeyPolicy::AcceptNew.ssh_option(),
            "StrictHostKeyChecking=accept-new"
        );
    }

    #[test]
    fn default_policy_is_strict() {
        assert_eq!(HostKeyPolicy::default(), HostKeyPolicy::Strict);
    }

    #[test]
    fn serde_round_trips_through_the_destination_string() {
        let spec = HostSpec::parse("root@[2001:db8::1]").unwrap();
        let json = serde_json::to_string(&spec).unwrap();
        assert_eq!(json, "\"root@[2001:db8::1]\"");
        let back: HostSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(back, spec);
    }

    #[test]
    fn deserialization_rejects_input_that_fails_the_grammar() {
        for bad in [
            r#""-oProxyCommand=evil""#,
            r#""host;other""#,
            r#""""#,
            r#""   ""#,
            r#""user@""#,
        ] {
            assert!(
                serde_json::from_str::<HostSpec>(bad).is_err(),
                "{bad} must not deserialize"
            );
        }
    }

    #[test]
    fn deserialization_rejects_field_shaped_payloads() {
        let payload = r#"{"user":null,"host":"-oProxyCommand=evil"}"#;
        assert!(
            serde_json::from_str::<HostSpec>(payload).is_err(),
            "serde must deserialize the destination string, never write fields directly"
        );
    }
}
