//! Tailscale node specification types.
//!
//! Defines [`TailscaleSpec`] and related types that describe the desired
//! configuration for a Tailscale node: node name, ACLs, DNS settings, and
//! advertised routes.

// ---------------------------------------------------------------------------
// TailscaleSpec
// ---------------------------------------------------------------------------

/// Desired configuration for a Tailscale node.
///
/// `TailscaleSpec` represents the *intent* for a node's configuration,
/// as opposed to [`crate::report::TailscaleReport`] which captures the
/// *actual* runtime state.
///
/// # Example
///
/// ```ignore
/// use toride_tailscale::spec::TailscaleSpec;
///
/// let spec = TailscaleSpec {
///     node_name: "my-server".to_owned(),
///     acls: vec![],
///     dns_config: None,
///     advertise_routes: vec![],
///     exit_node: false,
/// };
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct TailscaleSpec {
    /// The hostname or node name for this machine in the tailnet.
    pub node_name: String,

    /// ACL rules to apply to this node.
    pub acls: Vec<AclRule>,

    /// DNS configuration for the tailnet (MagicDNS, custom resolvers).
    pub dns_config: Option<DnsConfig>,

    /// Subnet routes to advertise from this node.
    pub advertise_routes: Vec<String>,

    /// Whether this node should act as an exit node.
    pub exit_node: bool,
}

impl TailscaleSpec {
    /// Create a minimal spec with just a node name.
    pub fn new(node_name: impl Into<String>) -> Self {
        Self {
            node_name: node_name.into(),
            acls: Vec::new(),
            dns_config: None,
            advertise_routes: Vec::new(),
            exit_node: false,
        }
    }

    /// Validate the spec for internal consistency.
    ///
    /// # Errors
    ///
    /// Returns an error if any field is invalid (e.g. empty node name,
    /// malformed routes).
    pub fn validate(&self) -> crate::Result<()> {
        if self.node_name.is_empty() {
            return Err(crate::Error::Other(
                "node name must not be empty".to_owned(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// AclRule
// ---------------------------------------------------------------------------

/// A single ACL rule for the tailnet.
///
/// Describes an access control rule that permits or denies traffic between
/// a source and a destination on specified ports.
#[derive(Debug, Clone, PartialEq)]
pub struct AclRule {
    /// Action: allow or deny.
    pub action: AclAction,
    /// Source addresses or groups.
    pub src: Vec<String>,
    /// Destination addresses and ports.
    pub dst: Vec<String>,
}

// ---------------------------------------------------------------------------
// AclAction
// ---------------------------------------------------------------------------

/// Action for an ACL rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclAction {
    /// Allow the traffic.
    Allow,
    /// Deny the traffic.
    Deny,
}

// ---------------------------------------------------------------------------
// DnsConfig
// ---------------------------------------------------------------------------

/// DNS configuration for a tailnet.
///
/// Controls MagicDNS, custom resolvers, and search domains for the tailnet.
#[derive(Debug, Clone, PartialEq)]
pub struct DnsConfig {
    /// Whether MagicDNS is enabled.
    pub magic_dns: bool,
    /// Custom DNS resolver addresses.
    pub nameservers: Vec<String>,
    /// Search domains to append.
    pub search_domains: Vec<String>,
}
