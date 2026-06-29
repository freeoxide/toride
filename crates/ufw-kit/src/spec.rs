//! Strongly typed models for UFW configuration.
//!
//! All types in this module use the builder pattern for ergonomic construction
//! and include validation to prevent invalid configurations from reaching UFW.

use std::fmt;
use std::net::IpAddr;

use crate::error::{Error, Result};

// ============================================================================
// Enums
// ============================================================================

/// Firewall rule action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    /// Allow traffic matching the rule.
    Allow,
    /// Deny traffic matching the rule (silently drop).
    Deny,
    /// Reject traffic matching the rule (send ICMP unreachable).
    Reject,
    /// Rate-limit matching traffic (TCP only, uses `limit` keyword).
    Limit,
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => f.write_str("allow"),
            Self::Deny => f.write_str("deny"),
            Self::Reject => f.write_str("reject"),
            Self::Limit => f.write_str("limit"),
        }
    }
}

/// Traffic direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Inbound traffic.
    In,
    /// Outbound traffic.
    Out,
    /// Forwarded/routed traffic.
    Routed,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::In => f.write_str("in"),
            Self::Out => f.write_str("out"),
            Self::Routed => f.write_str("routed"),
        }
    }
}

/// Default policy for a direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Policy {
    /// Allow all traffic by default.
    Allow,
    /// Deny all traffic by default (silently drop).
    Deny,
    /// Reject all traffic by default (send ICMP unreachable).
    Reject,
}

impl fmt::Display for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => f.write_str("allow"),
            Self::Deny => f.write_str("deny"),
            Self::Reject => f.write_str("reject"),
        }
    }
}

/// Network protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// Authentication Header.
    Ah,
    /// Encapsulating Security Payload.
    Esp,
    /// Generic Routing Encapsulation.
    Gre,
    /// IPv6 encapsulation.
    Ipv6,
    /// Internet Group Management Protocol.
    Igmp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => f.write_str("tcp"),
            Self::Udp => f.write_str("udp"),
            Self::Ah => f.write_str("ah"),
            Self::Esp => f.write_str("esp"),
            Self::Gre => f.write_str("gre"),
            Self::Ipv6 => f.write_str("ipv6"),
            Self::Igmp => f.write_str("igmp"),
        }
    }
}

impl Protocol {
    /// Returns `true` if this protocol must not be combined with port clauses.
    #[must_use]
    pub fn rejects_ports(&self) -> bool {
        matches!(
            self,
            Self::Ah | Self::Esp | Self::Gre | Self::Ipv6 | Self::Igmp
        )
    }
}

/// Protocol filter — either any protocol or a specific one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolFilter {
    /// Match any protocol (renders as empty — never `proto any`).
    Any,
    /// Match a specific protocol.
    Specific(Protocol),
}

impl fmt::Display for ProtocolFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => Ok(()),
            Self::Specific(p) => fmt::Display::fmt(p, f),
        }
    }
}

/// Global logging level for UFW.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LoggingLevel {
    /// Logging disabled.
    Off,
    /// Standard logging.
    On,
    /// Low-rate logging.
    Low,
    /// Medium-rate logging.
    Medium,
    /// High-rate logging.
    High,
    /// Full packet logging.
    Full,
}

impl fmt::Display for LoggingLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Off => f.write_str("off"),
            Self::On => f.write_str("on"),
            Self::Low => f.write_str("low"),
            Self::Medium => f.write_str("medium"),
            Self::High => f.write_str("high"),
            Self::Full => f.write_str("full"),
        }
    }
}

/// Per-rule logging option.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuleLogging {
    /// No per-rule logging.
    None,
    /// Log matching packets.
    Log,
    /// Log all matching packets.
    LogAll,
}

impl fmt::Display for RuleLogging {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => Ok(()),
            Self::Log => f.write_str("log"),
            Self::LogAll => f.write_str("log-all"),
        }
    }
}

/// Application profile default policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AppDefaultPolicy {
    /// Skip new application profiles.
    Skip,
    /// Allow new application profiles.
    Allow,
    /// Deny new application profiles.
    Deny,
}

impl fmt::Display for AppDefaultPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Skip => f.write_str("skip"),
            Self::Allow => f.write_str("allow"),
            Self::Deny => f.write_str("deny"),
        }
    }
}

/// IP address or CIDR range.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Address {
    /// Match any address (`any`).
    Any,
    /// Match a specific IP address.
    Ip(IpAddr),
    /// Match a CIDR network range.
    Net(ipnet::IpNet),
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => f.write_str("any"),
            Self::Ip(ip) => fmt::Display::fmt(ip, f),
            Self::Net(net) => fmt::Display::fmt(net, f),
        }
    }
}

/// Port specification.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PortSpec {
    /// Match any port.
    Any,
    /// Match a single port.
    Single(u16),
    /// Match a port range (inclusive).
    Range {
        /// Start of range (inclusive).
        start: u16,
        /// End of range (inclusive).
        end: u16,
    },
    /// Match a comma-separated list of ports.
    List(Vec<PortSpec>),
    /// Match a named service.
    ServiceName(String),
}

impl fmt::Display for PortSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => Ok(()),
            Self::Single(p) => write!(f, "{p}"),
            Self::Range { start, end } => write!(f, "{start}:{end}"),
            Self::List(ports) => {
                for (i, p) in ports.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    fmt::Display::fmt(p, f)?;
                }
                Ok(())
            }
            Self::ServiceName(name) => f.write_str(name),
        }
    }
}

impl PortSpec {
    /// Validate that ports are in valid range (1..=65535).
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Any | Self::ServiceName(_) => Ok(()),
            Self::Single(p) => {
                if *p == 0 {
                    return Err(Error::InvalidPort(0));
                }
                Ok(())
            }
            Self::Range { start, end } => {
                if *start == 0 {
                    return Err(Error::InvalidPort(0));
                }
                if *end == 0 {
                    return Err(Error::InvalidPort(0));
                }
                if start > end {
                    return Err(Error::InvalidPortRange {
                        start: *start,
                        end: *end,
                    });
                }
                Ok(())
            }
            Self::List(ports) => {
                for p in ports {
                    p.validate()?;
                }
                Ok(())
            }
        }
    }

    /// Returns `true` if this is a range or list (requires protocol in UFW).
    #[must_use]
    pub fn requires_protocol(&self) -> bool {
        matches!(self, Self::Range { .. } | Self::List(_))
    }
}

/// Rule target — what the rule matches on.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RuleTarget {
    /// Match any traffic.
    Any,
    /// Match by port(s).
    Port(PortSpec),
    /// Match by application profile name.
    AppProfile(String),
}

impl RuleTarget {
    /// Validate this target.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Any => Ok(()),
            Self::Port(spec) => spec.validate(),
            Self::AppProfile(name) => validate_app_name(name),
        }
    }
}

/// Rule position in the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RulePosition {
    /// Append to the end (default).
    Append,
    /// Prepend to the beginning.
    Prepend,
    /// Insert at a specific position.
    Insert(u32),
}

/// UFW show report type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UfwReport {
    /// Raw iptables rules.
    Raw,
    /// Built-in chains.
    Builtins,
    /// Before-rules framework file.
    BeforeRules,
    /// User rules.
    UserRules,
    /// After-rules framework file.
    AfterRules,
    /// Logging rules.
    LoggingRules,
    /// Currently listening ports.
    Listening,
    /// Added rules (normalized commands).
    Added,
}

impl fmt::Display for UfwReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Raw => f.write_str("raw"),
            Self::Builtins => f.write_str("builtins"),
            Self::BeforeRules => f.write_str("before-rules"),
            Self::UserRules => f.write_str("user-rules"),
            Self::AfterRules => f.write_str("after-rules"),
            Self::LoggingRules => f.write_str("logging-rules"),
            Self::Listening => f.write_str("listening"),
            Self::Added => f.write_str("added"),
        }
    }
}

/// Severity level for doctor findings.
///
/// Re-exported from [`toride_diagnostic_types::Severity`]. The shared type
/// uses `Important` where earlier versions of ufw-kit used `Error`.
pub use toride_diagnostic_types::Severity;

// ============================================================================
// Structs — Rule Specs
// ============================================================================

/// A typed firewall rule specification.
///
/// Use the builder to construct rules:
///
/// ```rust
/// use ufw_kit::spec::*;
///
/// let rule = RuleSpec::builder(Action::Allow)
///     .direction(Direction::In)
///     .proto(Protocol::Tcp)
///     .to_port(443)
///     .comment("managed:https")
///     .build()
///     .unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSpec {
    /// Rule action.
    pub action: Action,
    /// Traffic direction (optional — omit for simple rules).
    pub direction: Option<Direction>,
    /// Network interface (optional).
    pub interface: Option<String>,
    /// Protocol filter.
    pub protocol: ProtocolFilter,
    /// Source address.
    pub from_addr: Address,
    /// Source port.
    pub from_port: PortSpec,
    /// Destination address.
    pub to_addr: Address,
    /// Destination port.
    pub to_port: PortSpec,
    /// Application profile target (mutually exclusive with port).
    pub app_profile: Option<String>,
    /// Per-rule logging.
    pub logging: RuleLogging,
    /// Comment attached to the rule.
    pub comment: Option<String>,
    /// Rule position.
    pub position: RulePosition,
    /// Whether this is a delete operation.
    pub delete: bool,
}

impl Default for RuleSpec {
    fn default() -> Self {
        Self {
            action: Action::Allow,
            direction: None,
            interface: None,
            protocol: ProtocolFilter::Any,
            from_addr: Address::Any,
            from_port: PortSpec::Any,
            to_addr: Address::Any,
            to_port: PortSpec::Any,
            app_profile: None,
            logging: RuleLogging::None,
            comment: None,
            position: RulePosition::Append,
            delete: false,
        }
    }
}

impl RuleSpec {
    /// Start building a rule with the given action.
    #[must_use]
    pub fn builder(action: Action) -> RuleSpecBuilder {
        RuleSpecBuilder {
            spec: Self {
                action,
                ..Self::default()
            },
        }
    }

    /// Shorthand: create an allow rule with default settings.
    pub fn allow_any() -> Self {
        Self::default()
    }

    /// Shorthand: create a deny rule with default settings.
    pub fn deny_any() -> Self {
        Self {
            action: Action::Deny,
            ..Self::default()
        }
    }

    /// Validate this rule spec.
    pub fn validate(&self) -> Result<()> {
        // Validate ports
        self.from_port.validate()?;
        self.to_port.validate()?;

        // Protocol is required for port ranges and port lists (UFW constraint)
        if self.protocol == ProtocolFilter::Any
            && (self.to_port.requires_protocol() || self.from_port.requires_protocol())
        {
            return Err(Error::Validation(
                "protocol is required for port ranges and port lists".into(),
            ));
        }

        // Validate protocol + port combos
        if let ProtocolFilter::Specific(proto) = &self.protocol {
            if proto.rejects_ports() {
                let has_ports = !matches!(self.to_port, PortSpec::Any)
                    || !matches!(self.from_port, PortSpec::Any);
                if has_ports {
                    return Err(Error::ProtocolNoPorts(proto.to_string()));
                }
            }
        }

        // Validate protocol + address consistency
        if let ProtocolFilter::Specific(proto) = &self.protocol {
            match proto {
                Protocol::Ipv6 => {
                    // All addresses must be IPv6
                    for (label, addr) in [("from", &self.from_addr), ("to", &self.to_addr)] {
                        if let Address::Ip(ip) = addr {
                            if ip.is_ipv4() {
                                return Err(Error::Validation(format!(
                                    "protocol ipv6 requires IPv6 addresses, but {label} address {ip} is IPv4"
                                )));
                            }
                        }
                        if let Address::Net(net) = addr {
                            if matches!(net, ipnet::IpNet::V4(_)) {
                                return Err(Error::Validation(format!(
                                    "protocol ipv6 requires IPv6 networks, but {label} network {net} is IPv4"
                                )));
                            }
                        }
                    }
                }
                Protocol::Igmp => {
                    // All addresses must be IPv4
                    for (label, addr) in [("from", &self.from_addr), ("to", &self.to_addr)] {
                        if let Address::Ip(ip) = addr {
                            if ip.is_ipv6() {
                                return Err(Error::Validation(format!(
                                    "protocol igmp requires IPv4 addresses, but {label} address {ip} is IPv6"
                                )));
                            }
                        }
                        if let Address::Net(net) = addr {
                            if matches!(net, ipnet::IpNet::V6(_)) {
                                return Err(Error::Validation(format!(
                                    "protocol igmp requires IPv4 networks, but {label} network {net} is IPv6"
                                )));
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // Validate interface name
        if let Some(iface) = &self.interface {
            validate_interface(iface)?;
        }

        // Validate comment
        if let Some(comment) = &self.comment {
            validate_comment(comment)?;
        }

        // Validate app profile name
        if let Some(name) = &self.app_profile {
            validate_app_name(name)?;
        }

        // App profile rules must not specify protocol
        if self.app_profile.is_some() && self.protocol != ProtocolFilter::Any {
            return Err(Error::Validation(
                "app profile rules must not specify a protocol".into(),
            ));
        }

        // App profile and port are mutually exclusive
        if self.app_profile.is_some()
            && (!matches!(self.to_port, PortSpec::Any) || !matches!(self.from_port, PortSpec::Any))
        {
            return Err(Error::Validation(
                "app profile and port specifications are mutually exclusive".into(),
            ));
        }

        // Limit should be TCP-only in common usage
        if self.action == Action::Limit {
            if let ProtocolFilter::Specific(proto) = &self.protocol {
                if *proto != Protocol::Tcp {
                    tracing::warn!("limit action with non-TCP protocol {} is unusual", proto);
                }
            }
        }

        Ok(())
    }
}

/// Builder for `RuleSpec`.
#[derive(Debug)]
pub struct RuleSpecBuilder {
    spec: RuleSpec,
}

impl RuleSpecBuilder {
    /// Set traffic direction.
    pub fn direction(mut self, dir: Direction) -> Self {
        self.spec.direction = Some(dir);
        self
    }

    /// Set network interface.
    pub fn on_interface(mut self, iface: impl Into<String>) -> Self {
        self.spec.interface = Some(iface.into());
        self
    }

    /// Set protocol filter.
    pub fn proto(mut self, proto: Protocol) -> Self {
        self.spec.protocol = ProtocolFilter::Specific(proto);
        self
    }

    /// Set any protocol (default).
    pub fn any_proto(mut self) -> Self {
        self.spec.protocol = ProtocolFilter::Any;
        self
    }

    /// Set source address.
    pub fn from(mut self, addr: Address) -> Self {
        self.spec.from_addr = addr;
        self
    }

    /// Set source port.
    pub fn from_port(mut self, port: impl Into<PortSpec>) -> Self {
        self.spec.from_port = port.into();
        self
    }

    /// Set destination address.
    pub fn to(mut self, addr: Address) -> Self {
        self.spec.to_addr = addr;
        self
    }

    /// Set destination port (single port number).
    pub fn to_port(mut self, port: u16) -> Self {
        self.spec.to_port = PortSpec::Single(port);
        self
    }

    /// Set destination port spec.
    pub fn to_port_spec(mut self, spec: PortSpec) -> Self {
        self.spec.to_port = spec;
        self
    }

    /// Set application profile target.
    pub fn app(mut self, name: impl Into<String>) -> Self {
        self.spec.app_profile = Some(name.into());
        self
    }

    /// Set per-rule logging.
    pub fn logging(mut self, level: RuleLogging) -> Self {
        self.spec.logging = level;
        self
    }

    /// Set comment.
    pub fn comment(mut self, text: impl Into<String>) -> Self {
        self.spec.comment = Some(text.into());
        self
    }

    /// Set rule position.
    pub fn position(mut self, pos: RulePosition) -> Self {
        self.spec.position = pos;
        self
    }

    /// Mark as a delete operation.
    pub fn delete(mut self) -> Self {
        self.spec.delete = true;
        self
    }

    /// Build and validate the rule spec.
    pub fn build(self) -> Result<RuleSpec> {
        self.spec.validate()?;
        Ok(self.spec)
    }

    /// Build without validation (for internal use).
    #[cfg(test)]
    pub(crate) fn build_unchecked(self) -> RuleSpec {
        self.spec
    }
}

// ============================================================================
// Structs — Route Rule Spec
// ============================================================================

/// A typed route rule specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRuleSpec {
    /// Rule action.
    pub action: Action,
    /// Incoming interface.
    pub in_interface: Option<String>,
    /// Outgoing interface.
    pub out_interface: Option<String>,
    /// Protocol filter.
    pub protocol: ProtocolFilter,
    /// Source address.
    pub from_addr: Address,
    /// Destination address.
    pub to_addr: Address,
    /// Destination port.
    pub to_port: PortSpec,
    /// Comment.
    pub comment: Option<String>,
    /// Whether this is a delete operation.
    pub delete: bool,
}

impl RouteRuleSpec {
    /// Start building a route rule.
    pub fn builder(action: Action) -> RouteRuleSpecBuilder {
        RouteRuleSpecBuilder {
            spec: Self {
                action,
                in_interface: None,
                out_interface: None,
                protocol: ProtocolFilter::Any,
                from_addr: Address::Any,
                to_addr: Address::Any,
                to_port: PortSpec::Any,
                comment: None,
                delete: false,
            },
        }
    }

    /// Validate this route rule spec.
    pub fn validate(&self) -> Result<()> {
        self.to_port.validate()?;

        if let Some(iface) = &self.in_interface {
            validate_interface(iface)?;
        }
        if let Some(iface) = &self.out_interface {
            validate_interface(iface)?;
        }
        if let Some(comment) = &self.comment {
            validate_comment(comment)?;
        }

        Ok(())
    }
}

/// Builder for `RouteRuleSpec`.
#[derive(Debug)]
pub struct RouteRuleSpecBuilder {
    spec: RouteRuleSpec,
}

impl RouteRuleSpecBuilder {
    /// Set incoming interface.
    pub fn in_interface(mut self, iface: impl Into<String>) -> Self {
        self.spec.in_interface = Some(iface.into());
        self
    }

    /// Set outgoing interface.
    pub fn out_interface(mut self, iface: impl Into<String>) -> Self {
        self.spec.out_interface = Some(iface.into());
        self
    }

    /// Set protocol.
    pub fn proto(mut self, proto: Protocol) -> Self {
        self.spec.protocol = ProtocolFilter::Specific(proto);
        self
    }

    /// Set source address.
    pub fn from(mut self, addr: Address) -> Self {
        self.spec.from_addr = addr;
        self
    }

    /// Set destination address.
    pub fn to(mut self, addr: Address) -> Self {
        self.spec.to_addr = addr;
        self
    }

    /// Set destination port.
    pub fn to_port(mut self, port: u16) -> Self {
        self.spec.to_port = PortSpec::Single(port);
        self
    }

    /// Set comment.
    pub fn comment(mut self, text: impl Into<String>) -> Self {
        self.spec.comment = Some(text.into());
        self
    }

    /// Mark as delete.
    pub fn delete(mut self) -> Self {
        self.spec.delete = true;
        self
    }

    /// Build and validate.
    pub fn build(self) -> Result<RouteRuleSpec> {
        self.spec.validate()?;
        Ok(self.spec)
    }
}

// ============================================================================
// Structs — Status
// ============================================================================

/// Parsed UFW status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UfwStatus {
    /// Whether UFW is active.
    pub active: bool,
    /// Default incoming policy.
    pub default_incoming: Option<Policy>,
    /// Default outgoing policy.
    pub default_outgoing: Option<Policy>,
    /// Default routed policy (if present).
    pub default_routed: Option<Policy>,
    /// Current logging level.
    pub logging_level: Option<LoggingLevel>,
    /// New application profiles policy.
    pub new_app_profiles: Option<AppDefaultPolicy>,
    /// Parsed rules.
    pub rules: Vec<ParsedRule>,
}

/// A single rule parsed from UFW status output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRule {
    /// Rule number (if from numbered status).
    pub number: Option<u32>,
    /// The raw rule text.
    pub raw: String,
    /// Parsed action (if parseable).
    pub action: Option<Action>,
    /// Direction (if present).
    pub direction: Option<Direction>,
    /// Protocol (if present).
    pub protocol: Option<Protocol>,
    /// Source (raw string).
    pub from: Option<String>,
    /// Destination (raw string).
    pub to: Option<String>,
    /// Comment (if present).
    pub comment: Option<String>,
    /// Whether this is an IPv6 rule.
    pub ipv6: bool,
    /// Whether this is a route rule.
    pub is_route: bool,
}

// ============================================================================
// Structs — Command
// ============================================================================

/// Specification for a command to execute.
#[derive(Debug, Clone)]
pub struct CommandSpec {
    /// Program name (e.g., "ufw").
    pub program: String,
    /// Arguments to pass.
    pub args: Vec<String>,
    /// Timeout duration.
    pub timeout: Option<std::time::Duration>,
    /// Whether this command requires root privileges.
    pub requires_root: bool,
    /// Force `LC_ALL=C` for stable output parsing.
    pub force_c_locale: bool,
    /// Whether to redact potentially sensitive values in logged args.
    ///
    /// When `true`, command runners apply redaction rules to arguments
    /// before writing them to logs or traces. See [`crate::command::redact_args`].
    pub redact_logs: bool,
}

impl CommandSpec {
    /// Create a new command spec for `ufw`.
    pub fn ufw(args: impl Into<Vec<String>>) -> Self {
        Self {
            program: "ufw".into(),
            args: args.into(),
            timeout: Some(std::time::Duration::from_secs(30)),
            requires_root: false,
            force_c_locale: true,
            redact_logs: false,
        }
    }

    /// Create a UFW command that requires root.
    pub fn ufw_root(args: impl Into<Vec<String>>) -> Self {
        Self {
            requires_root: true,
            ..Self::ufw(args)
        }
    }
}

/// Result of a command execution.
#[derive(Debug, Clone)]
pub struct CommandResult {
    /// Standard output.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
    /// Exit code.
    pub exit_code: Option<i32>,
}

// ============================================================================
// Structs — Doctor
// ============================================================================

/// A single finding from a doctor check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Unique identifier for this finding type.
    pub id: &'static str,
    /// Severity level.
    pub severity: Severity,
    /// Short title.
    pub title: String,
    /// Detailed explanation.
    pub detail: String,
    /// Suggested fix, if any.
    pub fix: Option<String>,
}

/// Scope for doctor checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoctorScope {
    /// Run all checks.
    All,
    /// Only binary checks.
    Binaries,
    /// Only service checks.
    Service,
    /// Only policy checks.
    Policy,
    /// Only rule checks.
    Rules,
    /// Only SSH checks.
    Ssh,
    /// Only IPv6 checks.
    Ipv6,
    /// Only logging checks.
    Logging,
    /// Only app profile checks.
    AppProfiles,
    /// Only permission checks.
    Permissions,
    /// Only Docker/container checks.
    Docker,
    /// Only routing/forwarding checks.
    Routing,
}

// ============================================================================
// Structs — App Profile
// ============================================================================

/// A typed application profile specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppProfileSpec {
    /// Profile name (used in `[Name]` section header).
    pub name: String,
    /// Human-readable title.
    pub title: String,
    /// Description.
    pub description: String,
    /// Port definitions (e.g., `80/tcp|443/tcp`).
    pub ports: Vec<AppPort>,
}

/// A single port definition in an app profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPort {
    /// Port number or range (e.g., "80" or "8000:9000").
    pub port: String,
    /// Protocol (tcp or udp).
    pub protocol: String,
}

impl fmt::Display for AppPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.port, self.protocol)
    }
}

impl AppProfileSpec {
    /// Render the profile as INI content.
    #[must_use]
    pub fn render(&self) -> String {
        let ports_str = self
            .ports
            .iter()
            .map(AppPort::to_string)
            .collect::<Vec<_>>()
            .join("|");

        format!(
            "# Managed by ufw-kit.\n\
             # Do not edit manually unless you also disable this manager.\n\n\
             [{}]\n\
             title={}\n\
             description={}\n\
             ports={}\n",
            self.name, self.title, self.description, ports_str
        )
    }

    /// Validate the profile.
    pub fn validate(&self) -> Result<()> {
        validate_app_name(&self.name)?;
        if self.ports.is_empty() {
            return Err(Error::Validation(
                "app profile must have at least one port".into(),
            ));
        }
        Ok(())
    }
}

// ============================================================================
// Structs — Config
// ============================================================================

/// UFW configuration from `/etc/default/ufw`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UfwConfig {
    /// Whether IPv6 is enabled.
    pub ipv6: Option<bool>,
    /// Default input policy string.
    pub default_input_policy: Option<String>,
    /// Default output policy string.
    pub default_output_policy: Option<String>,
    /// Default forward policy string.
    pub default_forward_policy: Option<String>,
    /// Whether UFW is enabled.
    pub enabled: Option<bool>,
    /// Sysctl config path.
    pub ipt_sysctl: Option<String>,
    /// IPT modules.
    pub ipt_modules: Option<String>,
    /// Whether to manage builtins.
    pub manage_builtins: Option<bool>,
}

/// UFW configuration from `/etc/ufw/ufw.conf`.
///
/// This file has a simpler format than `/etc/default/ufw` with only two
/// keys: `ENABLED` and `LOGLEVEL`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UfwConf {
    /// Whether UFW is enabled (`ENABLED=yes`).
    pub enabled: Option<bool>,
    /// Logging level (`LOGLEVEL=low`, etc.).
    pub loglevel: Option<String>,
}

/// Result of an SSH lockout safety check.
///
/// Returned by [`crate::client::Ufw::check_ssh_lockout_structured`] to provide
/// structured information about which SSH rules were found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshCheckResult {
    /// Whether an incoming SSH allow rule was found.
    pub has_incoming_ssh_allow: bool,
    /// Parsed rules that match SSH (port 22 or service name "ssh").
    pub matching_rules: Vec<ParsedRule>,
    /// Whether any matching rule is scoped to a specific interface.
    pub interface_scoped: bool,
    /// Ports that were checked.
    pub checked_ports: Vec<u16>,
}

// ============================================================================
// Structs — Options
// ============================================================================

/// Options for enabling UFW.
#[derive(Debug, Clone)]
pub struct EnableOptions {
    /// Require an SSH allow rule to exist before enabling.
    pub require_ssh_allow_rule: bool,
    /// SSH ports to check (default: [22]).
    pub ssh_ports: Vec<u16>,
    /// Trusted source IPs (if any).
    pub trusted_sources: Vec<IpAddr>,
    /// Force enable even if SSH lockout risk detected.
    pub allow_force: bool,
}

impl Default for EnableOptions {
    fn default() -> Self {
        Self {
            require_ssh_allow_rule: true,
            ssh_ports: vec![22],
            trusted_sources: Vec::new(),
            allow_force: false,
        }
    }
}

/// Options for disabling UFW.
#[derive(Debug, Clone, Default)]
pub struct DisableOptions {
    /// Require explicit confirmation.
    pub require_explicit_confirmation: bool,
}

/// Options for resetting UFW.
#[derive(Debug, Clone)]
pub struct ResetOptions {
    /// Force the reset.
    pub force: bool,
    /// Backup before resetting.
    pub backup_first: bool,
}

impl Default for ResetOptions {
    fn default() -> Self {
        Self {
            force: false,
            backup_first: true,
        }
    }
}

/// Options for deleting rules.
#[derive(Debug, Clone, Default)]
pub struct DeleteOptions {
    /// Allow deletion by rule number (dangerous — numbers shift).
    pub allow_numbered_delete: bool,
}

// ============================================================================
// Structs — Framework
// ============================================================================

/// A managed block within a UFW framework file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameworkRuleBlock {
    /// Block identifier (used in marker comments).
    pub id: String,
    /// The iptables/nftables content of the block.
    pub content: String,
    /// Whether this is for IPv6.
    pub ipv6: bool,
}

// ============================================================================
// Structs — Backup
// ============================================================================

/// A backup bundle of UFW configuration.
#[derive(Debug, Clone)]
pub struct BackupBundle {
    /// Timestamp of the backup.
    pub timestamp: String,
    /// Contents of `/etc/default/ufw`.
    pub default_ufw: Option<String>,
    /// Contents of `/etc/ufw/ufw.conf`.
    pub ufw_conf: Option<String>,
    /// Contents of `/etc/ufw/sysctl.conf`.
    pub sysctl_conf: Option<String>,
    /// Managed app profile files.
    pub app_profiles: Vec<(String, String)>,
    /// Framework rule files.
    pub framework_files: Vec<(String, String)>,
}

// ============================================================================
// Structs — Apply Report
// ============================================================================

/// Result of applying a change.
#[derive(Debug, Clone)]
pub struct ApplyReport {
    /// Whether the operation succeeded.
    pub success: bool,
    /// Description of what was done.
    pub action: String,
    /// Dry-run output (if performed).
    pub dry_run_output: Option<String>,
    /// Verification output.
    pub verification: Option<String>,
    /// Any warnings generated.
    pub warnings: Vec<String>,
}

// ============================================================================
// Validation helpers
// ============================================================================

/// Validate an interface name.
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
    // Reject shell metacharacters
    if name.contains(|c: char| {
        matches!(
            c,
            ';' | '&' | '|' | '$' | '`' | '(' | ')' | '{' | '}' | '<' | '>' | '!' | '*'
        )
    }) {
        return Err(Error::InvalidInterface(format!(
            "interface name contains shell metacharacter: {name}"
        )));
    }
    Ok(())
}

/// Validate a comment string.
fn validate_comment(comment: &str) -> Result<()> {
    if comment.contains('\n') {
        return Err(Error::InvalidComment(
            "comment must not contain newline".into(),
        ));
    }
    check_comment_for_secrets(comment)?;
    Ok(())
}

/// Check whether a comment contains patterns that look like secrets.
fn check_comment_for_secrets(comment: &str) -> Result<()> {
    let lower = comment.to_ascii_lowercase();

    // Check for key=value patterns where value is non-whitespace
    for pattern in &[
        "password=",
        "passwd=",
        "secret=",
        "token=",
        "key=",
        "api_key=",
    ] {
        if let Some(pos) = lower.find(pattern) {
            let after = &comment[pos + pattern.len()..];
            // If there is a non-empty run of non-whitespace after the =, reject
            let value_part = after.split_whitespace().next().unwrap_or("");
            if !value_part.is_empty() {
                return Err(Error::InvalidComment(
                    "comment contains what appears to be a secret (key=value pattern)".into(),
                ));
            }
        }
    }

    // Check for base64-looking strings of 20+ chars
    let mut base64_run = 0usize;
    for ch in comment.chars() {
        if ch.is_ascii_alphanumeric() || ch == '+' || ch == '/' || ch == '=' {
            base64_run += 1;
        } else {
            if base64_run >= 20 {
                return Err(Error::InvalidComment(
                    "comment contains what appears to be a base64-encoded secret".into(),
                ));
            }
            base64_run = 0;
        }
    }
    if base64_run >= 20 {
        return Err(Error::InvalidComment(
            "comment contains what appears to be a base64-encoded secret".into(),
        ));
    }

    // Check for long hex strings (32+ hex chars in a row)
    let mut hex_run = 0usize;
    for ch in comment.chars() {
        if ch.is_ascii_hexdigit() {
            hex_run += 1;
        } else {
            if hex_run >= 32 {
                return Err(Error::InvalidComment(
                    "comment contains what appears to be a hex-encoded secret".into(),
                ));
            }
            hex_run = 0;
        }
    }
    if hex_run >= 32 {
        return Err(Error::InvalidComment(
            "comment contains what appears to be a hex-encoded secret".into(),
        ));
    }

    Ok(())
}

/// Validate an app profile name.
fn validate_app_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::InvalidAppName("empty app profile name".into()));
    }
    if name.contains('\n') {
        return Err(Error::InvalidAppName(
            "app profile name must not contain newline".into(),
        ));
    }
    if name.contains("..") || name.contains('/') {
        return Err(Error::InvalidAppName(
            "app profile name must not contain path traversal".into(),
        ));
    }
    Ok(())
}

/// Public wrapper for secret detection in comments, used by the doctor module.
///
/// Returns `true` if the comment appears to contain a secret pattern.
#[must_use]
pub fn validate_comment_for_secrets_doctor(comment: &str) -> bool {
    check_comment_for_secrets(comment).is_err()
}

// ============================================================================
// Structs — Show Reports
// ============================================================================

/// A listening port entry from `ufw show listening`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ListeningPort {
    /// Protocol (tcp/udp).
    pub proto: String,
    /// Address (e.g. "0.0.0.0:22" or "[::]:22").
    pub address: String,
}

/// A normalized rule from `ufw show added`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AddedRule {
    /// The full normalized rule text.
    pub raw: String,
}

// ============================================================================
// Conversions
// ============================================================================

impl From<u16> for PortSpec {
    fn from(port: u16) -> Self {
        Self::Single(port)
    }
}

impl From<(u16, u16)> for PortSpec {
    fn from((start, end): (u16, u16)) -> Self {
        Self::Range { start, end }
    }
}

impl From<String> for PortSpec {
    fn from(name: String) -> Self {
        Self::ServiceName(name)
    }
}

impl From<&str> for PortSpec {
    fn from(name: &str) -> Self {
        Self::ServiceName(name.to_owned())
    }
}

#[cfg(test)]
#[path = "spec.test.rs"]
mod tests;

#[cfg(test)]
#[path = "proptest.test.rs"]
mod proptest_tests;
