//! NAT and forwarding helpers.
//!
//! Provides typed specs for NAT masquerade and forwarding rules, plus sysctl
//! forwarding helpers. NAT blocks are rendered as managed framework blocks
//! that can be upserted into `before.rules`.

use crate::error::{Error, Result};
use crate::spec::FrameworkRuleBlock;

// ============================================================================
// Specs
// ============================================================================

/// IP version for NAT rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpVersion {
    /// IPv4.
    V4,
    /// IPv6.
    V6,
}

impl std::fmt::Display for IpVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V4 => f.write_str("ipv4"),
            Self::V6 => f.write_str("ipv6"),
        }
    }
}

/// A typed NAT masquerade specification.
///
/// Renders as a managed block in `before.rules` with a `*nat` table,
/// `POSTROUTING` chain, and a MASQUERADE rule.
///
/// # Example
///
/// ```rust
/// use ufw_kit::nat::{MasqueradeSpec, IpVersion};
///
/// let spec = MasqueradeSpec {
///     id: "wg-nat".into(),
///     source: "10.0.0.0/24".parse().unwrap(),
///     out_interface: "eth0".into(),
///     ip_version: IpVersion::V4,
/// };
/// let block = spec.to_framework_block();
/// assert_eq!(block.id, "wg-nat");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasqueradeSpec {
    /// Block identifier for the managed framework block.
    pub id: String,
    /// Source network to masquerade (e.g., `10.0.0.0/24`).
    pub source: ipnet::IpNet,
    /// Outgoing interface (e.g., `eth0`).
    pub out_interface: String,
    /// IP version (V4 or V6).
    pub ip_version: IpVersion,
}

impl MasqueradeSpec {
    /// Validate the spec.
    pub fn validate(&self) -> Result<()> {
        if self.id.is_empty() {
            return Err(Error::Validation("masquerade id must not be empty".into()));
        }
        if self.out_interface.is_empty() {
            return Err(Error::Validation(
                "masquerade out_interface must not be empty".into(),
            ));
        }
        validate_interface(&self.out_interface)?;

        // Check IP version consistency
        match self.ip_version {
            IpVersion::V4 => {
                if matches!(self.source, ipnet::IpNet::V6(_)) {
                    return Err(Error::Validation(
                        "masquerade source is IPv6 but ip_version is V4".into(),
                    ));
                }
            }
            IpVersion::V6 => {
                if matches!(self.source, ipnet::IpNet::V4(_)) {
                    return Err(Error::Validation(
                        "masquerade source is IPv4 but ip_version is V6".into(),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Render this spec as a framework block for `before.rules`.
    ///
    /// Produces a `*nat` table with a `POSTROUTING` MASQUERADE rule.
    #[must_use]
    pub fn to_framework_block(&self) -> FrameworkRuleBlock {
        FrameworkRuleBlock {
            id: self.id.clone(),
            content: self.render_iptables_content(),
            ipv6: self.ip_version == IpVersion::V6,
        }
    }

    /// Render the iptables content for the NAT block.
    fn render_iptables_content(&self) -> String {
        format!(
            "*nat\n\
             :POSTROUTING ACCEPT [0:0]\n\
             -A POSTROUTING -s {source} -o {out_iface} -j MASQUERADE\n\
             COMMIT",
            source = self.source,
            out_iface = self.out_interface,
        )
    }
}

/// A typed forwarding specification.
///
/// Describes a forwarding rule between two interfaces, typically used
/// alongside a NAT masquerade rule to allow traffic to flow from one
/// network to another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardSpec {
    /// Block identifier for the managed framework block.
    pub id: String,
    /// Incoming interface (e.g., `wg0`).
    pub in_interface: String,
    /// Outgoing interface (e.g., `eth0`).
    pub out_interface: String,
    /// Forwarding state: ACCEPT, DROP, etc.
    pub policy: ForwardPolicy,
    /// IP version.
    ip_version: IpVersion,
}

/// Forwarding policy within the filter table's FORWARD chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ForwardPolicy {
    /// Accept forwarded traffic.
    Accept,
    /// Drop forwarded traffic.
    Drop,
}

impl std::fmt::Display for ForwardPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Accept => f.write_str("ACCEPT"),
            Self::Drop => f.write_str("DROP"),
        }
    }
}

impl ForwardSpec {
    /// Create a new forwarding spec with the given parameters.
    pub fn new(
        id: impl Into<String>,
        in_interface: impl Into<String>,
        out_interface: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            in_interface: in_interface.into(),
            out_interface: out_interface.into(),
            policy: ForwardPolicy::Accept,
            ip_version: IpVersion::V4,
        }
    }

    /// Set the forwarding policy.
    #[must_use]
    pub fn with_policy(mut self, policy: ForwardPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Set the IP version.
    #[must_use]
    pub fn with_ip_version(mut self, version: IpVersion) -> Self {
        self.ip_version = version;
        self
    }

    /// Validate the spec.
    pub fn validate(&self) -> Result<()> {
        if self.id.is_empty() {
            return Err(Error::Validation("forward id must not be empty".into()));
        }
        validate_interface(&self.in_interface)?;
        validate_interface(&self.out_interface)?;
        if self.in_interface == self.out_interface {
            return Err(Error::Validation(
                "in_interface and out_interface must not be the same".into(),
            ));
        }
        Ok(())
    }

    /// Render as a framework block for `before.rules`.
    ///
    /// Produces a FORWARD rule in the filter table.
    #[must_use]
    pub fn to_framework_block(&self) -> FrameworkRuleBlock {
        FrameworkRuleBlock {
            id: self.id.clone(),
            content: self.render_filter_content(),
            ipv6: self.ip_version == IpVersion::V6,
        }
    }

    fn render_filter_content(&self) -> String {
        format!(
            "-A ufw-before-forward -i {in_iface} -o {out_iface} -j {policy}",
            in_iface = self.in_interface,
            out_iface = self.out_interface,
            policy = self.policy,
        )
    }
}

// ============================================================================
// Sysctl helpers
// ============================================================================

/// Sysctl keys related to IP forwarding.
pub mod sysctl {
    /// IPv4 forwarding key.
    pub const IPV4_FORWARD: &str = "net.ipv4.ip_forward";
    /// IPv6 forwarding key.
    pub const IPV6_FORWARD: &str = "net.ipv6.conf.all.forwarding";
}

/// Check whether a sysctl line enables forwarding.
///
/// Returns `true` if the line contains a forwarding key set to `1`.
#[must_use]
pub fn is_forwarding_enabled_line(line: &str, key: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return false;
    }
    // Format: "net.ipv4.ip_forward = 1" or "net.ipv4.ip_forward=1"
    let lower = trimmed.to_ascii_lowercase();
    if !lower.contains(key) {
        return false;
    }
    // Check for "= 1" or "=1"
    let after_key = lower.split(key).nth(1).unwrap_or("");
    let after_eq = after_key.trim_start();
    after_eq.starts_with("= 1") || after_eq.starts_with("=1")
}

/// Parse sysctl forwarding state from sysctl.conf content.
///
/// Returns `(ipv4_enabled, ipv6_enabled)` based on the last non-comment
/// setting for each key.
#[must_use]
pub fn parse_forwarding_state(sysctl_content: &str) -> (bool, bool) {
    let mut ipv4 = false;
    let mut ipv6 = false;

    for line in sysctl_content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower.contains(sysctl::IPV4_FORWARD) {
            ipv4 = parse_sysctl_bool(&lower, sysctl::IPV4_FORWARD);
        }
        if lower.contains(sysctl::IPV6_FORWARD) {
            ipv6 = parse_sysctl_bool(&lower, sysctl::IPV6_FORWARD);
        }
    }

    (ipv4, ipv6)
}

/// Parse a boolean sysctl value from a line.
fn parse_sysctl_bool(line_lower: &str, key: &str) -> bool {
    let after_key = line_lower.split(key).nth(1).unwrap_or("");
    let after_eq = after_key.trim_start();
    if let Some(val_part) = after_eq.strip_prefix('=') {
        let val = val_part.trim().chars().next().unwrap_or('0');
        val == '1'
    } else {
        false
    }
}

/// Render a sysctl line enabling forwarding for the given key.
#[must_use]
pub fn render_forwarding_enable(key: &str) -> String {
    format!("{key} = 1")
}

/// Render a sysctl line disabling forwarding for the given key.
#[must_use]
pub fn render_forwarding_disable(key: &str) -> String {
    format!("{key} = 0")
}

/// Ensure forwarding is enabled in sysctl content, adding or updating the line.
///
/// Returns the updated content.
#[must_use]
pub fn ensure_forwarding_enabled(content: &str, key: &str) -> String {
    let mut found = false;
    let mut lines: Vec<String> = content.lines().map(String::from).collect();

    for line in &mut lines {
        let trimmed = line.trim().to_ascii_lowercase();
        if trimmed.contains(key) && !trimmed.starts_with('#') {
            *line = render_forwarding_enable(key);
            found = true;
        }
    }

    if !found {
        lines.push(render_forwarding_enable(key));
    }

    let mut result = lines.join("\n");
    if !result.ends_with('\n') {
        result.push('\n');
    }
    result
}

// ============================================================================
// NAT apply helper
// ============================================================================

/// Result of applying a NAT configuration.
#[derive(Debug, Clone)]
pub struct NatApplyResult {
    /// Whether the NAT block was upserted.
    pub nat_block_applied: bool,
    /// Whether the forwarding block was applied (if any).
    pub forward_block_applied: Option<bool>,
    /// Whether sysctl was updated.
    pub sysctl_updated: bool,
    /// Any warnings generated.
    pub warnings: Vec<String>,
}

/// Validate interface name (shared with spec module).
fn validate_interface(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::InvalidInterface("empty interface name".into()));
    }
    if name.len() > 15 {
        return Err(Error::InvalidInterface(format!(
            "interface name too long: {name} (max 15 chars)"
        )));
    }
    if name.contains(|c: char| c.is_whitespace() || c == '/' || c == '\0') {
        return Err(Error::InvalidInterface(format!(
            "interface name contains invalid character: {name}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masquerade_spec_should_render_nat_block() {
        let spec = MasqueradeSpec {
            id: "wg-nat".into(),
            source: "10.0.0.0/24".parse().unwrap(),
            out_interface: "eth0".into(),
            ip_version: IpVersion::V4,
        };
        spec.validate().unwrap();
        let block = spec.to_framework_block();
        assert_eq!(block.id, "wg-nat");
        assert!(!block.ipv6);
        assert!(block.content.contains("*nat"));
        assert!(block.content.contains("POSTROUTING"));
        assert!(block.content.contains("MASQUERADE"));
        assert!(block.content.contains("10.0.0.0/24"));
        assert!(block.content.contains("eth0"));
        assert!(block.content.contains("COMMIT"));
    }

    #[test]
    fn masquerade_spec_v6_should_set_ipv6_flag() {
        let spec = MasqueradeSpec {
            id: "wg-nat-v6".into(),
            source: "fd00::/64".parse().unwrap(),
            out_interface: "eth0".into(),
            ip_version: IpVersion::V6,
        };
        spec.validate().unwrap();
        let block = spec.to_framework_block();
        assert!(block.ipv6);
    }

    #[test]
    fn masquerade_spec_should_reject_ipv4_source_with_v6() {
        let spec = MasqueradeSpec {
            id: "bad".into(),
            source: "10.0.0.0/24".parse().unwrap(),
            out_interface: "eth0".into(),
            ip_version: IpVersion::V6,
        };
        assert!(spec.validate().is_err());
    }

    #[test]
    fn forward_spec_should_render_filter_block() {
        let spec = ForwardSpec::new("wg-forward", "wg0", "eth0");
        spec.validate().unwrap();
        let block = spec.to_framework_block();
        assert_eq!(block.id, "wg-forward");
        assert!(block.content.contains("ufw-before-forward"));
        assert!(block.content.contains("-i wg0"));
        assert!(block.content.contains("-o eth0"));
        assert!(block.content.contains("ACCEPT"));
    }

    #[test]
    fn forward_spec_should_reject_same_interface() {
        let spec = ForwardSpec::new("bad", "eth0", "eth0");
        assert!(spec.validate().is_err());
    }

    #[test]
    fn sysctl_parsing_should_detect_forwarding() {
        let content = "# some comment\nnet.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 0\n";
        let (v4, v6) = parse_forwarding_state(content);
        assert!(v4);
        assert!(!v6);
    }

    #[test]
    fn sysctl_parsing_should_default_to_disabled() {
        let content = "# no forwarding settings\n";
        let (v4, v6) = parse_forwarding_state(content);
        assert!(!v4);
        assert!(!v6);
    }

    #[test]
    fn ensure_forwarding_should_add_if_missing() {
        let content = "# sysctl config\n";
        let result = ensure_forwarding_enabled(content, sysctl::IPV4_FORWARD);
        assert!(result.contains("net.ipv4.ip_forward = 1"));
    }

    #[test]
    fn ensure_forwarding_should_update_existing() {
        let content = "net.ipv4.ip_forward = 0\n";
        let result = ensure_forwarding_enabled(content, sysctl::IPV4_FORWARD);
        assert!(result.contains("net.ipv4.ip_forward = 1"));
        assert!(!result.contains("= 0"));
    }

    #[test]
    fn is_forwarding_enabled_line_should_parse_various_formats() {
        assert!(is_forwarding_enabled_line(
            "net.ipv4.ip_forward = 1",
            sysctl::IPV4_FORWARD
        ));
        assert!(is_forwarding_enabled_line(
            "net.ipv4.ip_forward=1",
            sysctl::IPV4_FORWARD
        ));
        assert!(!is_forwarding_enabled_line(
            "net.ipv4.ip_forward = 0",
            sysctl::IPV4_FORWARD
        ));
        assert!(!is_forwarding_enabled_line(
            "# net.ipv4.ip_forward = 1",
            sysctl::IPV4_FORWARD
        ));
        assert!(!is_forwarding_enabled_line("", sysctl::IPV4_FORWARD));
    }
}
