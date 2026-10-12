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
/// Accepts bare hostnames, IPv4 literals, bare and bracketed IPv6 literals,
/// each optionally prefixed with `user@`; everything else — shell
/// metacharacters, whitespace, control characters, leading dashes, empty or
/// overlong input — is a typed [`Error::InvalidHost`] rejection and can never
/// be constructed as a `HostSpec`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    /// bracketed address, or a hostname label that is empty, over 63 bytes,
    /// or not alphanumeric-plus-hyphen. The reason never echoes the input.
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
        return Ipv6Addr::from_str(inner).map(|_| ()).map_err(|err| {
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

fn validate_hostname(host: &str) -> Result<()> {
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
    fn parse_rejects_hostname_label_violations() {
        for bad in [
            "host..name",
            ".host",
            "host.",
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
}
