//! Specification types for cloud security groups and firewall rules.
//!
//! Provides the domain model for defining firewall rules and security groups
//! across cloud providers. These types are provider-agnostic and can be
//! translated to provider-specific formats.

use std::fmt;

// ---------------------------------------------------------------------------
// Protocol
// ---------------------------------------------------------------------------

/// Network protocol for a firewall rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// TCP protocol.
    Tcp,
    /// UDP protocol.
    Udp,
    /// ICMP protocol.
    Icmp,
    /// All protocols.
    All,
    /// A custom protocol by number.
    Other(u8),
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Udp => write!(f, "udp"),
            Self::Icmp => write!(f, "icmp"),
            Self::All => write!(f, "all"),
            Self::Other(n) => write!(f, "{n}"),
        }
    }
}

// ---------------------------------------------------------------------------
// PortRange
// ---------------------------------------------------------------------------

/// A port or port range for a firewall rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PortRange {
    /// Start of the port range (inclusive).
    pub start: u16,
    /// End of the port range (inclusive). Same as `start` for a single port.
    pub end: u16,
}

impl PortRange {
    /// Create a port range for a single port.
    #[must_use]
    pub const fn single(port: u16) -> Self {
        Self {
            start: port,
            end: port,
        }
    }

    /// Create a port range spanning `start` to `end` (inclusive).
    #[must_use]
    pub const fn range(start: u16, end: u16) -> Self {
        Self { start, end }
    }

    /// Returns `true` if this range covers a single port.
    #[must_use]
    pub const fn is_single(&self) -> bool {
        self.start == self.end
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_single() {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}

// ---------------------------------------------------------------------------
// FirewallRule
// ---------------------------------------------------------------------------

/// A single firewall rule in a security group.
///
/// Represents an ingress or egress rule with a protocol, port range,
/// and source/destination CIDR.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FirewallRule {
    /// Unique identifier for this rule (provider-assigned or generated).
    pub id: Option<String>,
    /// Human-readable description of the rule.
    pub description: String,
    /// Direction of the rule: `true` for ingress, `false` for egress.
    pub is_ingress: bool,
    /// Network protocol.
    pub protocol: Protocol,
    /// Port or port range.
    pub port_range: Option<PortRange>,
    /// Source CIDR for ingress rules, destination CIDR for egress.
    pub cidr: String,
    /// Rule action (allow or deny). Not all providers support deny.
    pub action: RuleAction,
}

// ---------------------------------------------------------------------------
// RuleAction
// ---------------------------------------------------------------------------

/// Action for a firewall rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuleAction {
    /// Allow the traffic.
    Allow,
    /// Deny the traffic.
    Deny,
}

impl fmt::Display for RuleAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Deny => write!(f, "deny"),
        }
    }
}

// ---------------------------------------------------------------------------
// SecurityGroup
// ---------------------------------------------------------------------------

/// A security group containing a set of firewall rules.
///
/// Maps to provider-specific concepts: AWS Security Group, GCP Firewall,
/// `DigitalOcean` Firewall, Hetzner Firewall.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityGroup {
    /// Unique identifier for this security group.
    pub id: Option<String>,
    /// Human-readable name.
    pub name: String,
    /// Description of the security group.
    pub description: String,
    /// The cloud provider this group belongs to.
    pub provider: crate::CloudProvider,
    /// List of firewall rules in this group.
    pub rules: Vec<FirewallRule>,
    /// Tags or labels applied to this security group.
    pub tags: Vec<(String, String)>,
}

impl SecurityGroup {
    /// Create a new security group with no rules.
    #[must_use]
    pub fn new(name: impl Into<String>, provider: crate::CloudProvider) -> Self {
        Self {
            id: None,
            name: name.into(),
            description: String::new(),
            provider,
            rules: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// Returns the ingress rules in this group.
    #[must_use]
    pub fn ingress_rules(&self) -> Vec<&FirewallRule> {
        self.rules.iter().filter(|r| r.is_ingress).collect()
    }

    /// Returns the egress rules in this group.
    #[must_use]
    pub fn egress_rules(&self) -> Vec<&FirewallRule> {
        self.rules.iter().filter(|r| !r.is_ingress).collect()
    }
}

// ---------------------------------------------------------------------------
// CloudSpec
// ---------------------------------------------------------------------------

/// Full specification of cloud firewall configuration.
///
/// Contains all security groups for a given cloud provider deployment.
#[derive(Debug, Clone)]
pub struct CloudSpec {
    /// The cloud provider this spec targets.
    pub provider: crate::CloudProvider,
    /// All security groups in this specification.
    pub security_groups: Vec<SecurityGroup>,
    /// Default ingress rules applied when no explicit rules match.
    pub default_deny_ingress: bool,
    /// Default egress rules applied when no explicit rules match.
    pub default_deny_egress: bool,
}

impl CloudSpec {
    /// Create an empty spec for the given provider.
    #[must_use]
    pub fn new(provider: crate::CloudProvider) -> Self {
        Self {
            provider,
            security_groups: Vec::new(),
            default_deny_ingress: true,
            default_deny_egress: false,
        }
    }
}
