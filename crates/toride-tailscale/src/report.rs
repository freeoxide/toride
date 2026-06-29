//! Structured report types for Tailscale status, diagnostics, and operations.
//!
//! Every diagnostic or status query in the crate returns one of these report
//! types so that callers can inspect results programmatically and produce
//! human-readable output independently.

// ---------------------------------------------------------------------------
// TailscaleReport
// ---------------------------------------------------------------------------

/// Summary report of a Tailscale node's runtime state.
///
/// Captures the current connection status, node identity, and key
/// configuration details. Produced by querying the local Tailscale daemon.
///
/// # Example
///
/// ```ignore
/// use toride_tailscale::report::TailscaleReport;
///
/// let report = TailscaleReport {
///     connected: true,
///     node_name: "my-server".to_owned(),
///     tailnet: "example.com".to_owned(),
///     ip_addresses: vec!["100.64.0.1".to_owned()],
///     exit_node: None,
///     dns_enabled: true,
/// };
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct TailscaleReport {
    /// Whether the node is connected to the tailnet.
    pub connected: bool,

    /// The hostname of this node as seen in the tailnet.
    pub node_name: String,

    /// The tailnet name (e.g. `example.com`).
    pub tailnet: String,

    /// Tailscale IP addresses assigned to this node.
    pub ip_addresses: Vec<String>,

    /// The exit node this node is using, if any.
    pub exit_node: Option<String>,

    /// Whether MagicDNS is enabled.
    pub dns_enabled: bool,
}

// ---------------------------------------------------------------------------
// ConnectionStatus
// ---------------------------------------------------------------------------

/// Detailed connection status for the Tailscale daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionStatus {
    /// The daemon is running and connected to the tailnet.
    Connected,
    /// The daemon is running but not connected.
    Disconnected,
    /// The daemon is starting up and establishing a connection.
    Starting,
    /// The connection state could not be determined.
    Unknown,
}

impl std::fmt::Display for ConnectionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connected => write!(f, "connected"),
            Self::Disconnected => write!(f, "disconnected"),
            Self::Starting => write!(f, "starting"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ---------------------------------------------------------------------------
// PeerInfo
// ---------------------------------------------------------------------------

/// Information about a peer in the tailnet.
#[derive(Debug, Clone, PartialEq)]
pub struct PeerInfo {
    /// The hostname of the peer.
    pub name: String,

    /// The Tailscale IP addresses of the peer.
    pub ip_addresses: Vec<String>,

    /// Whether the peer is currently online and reachable.
    pub online: bool,

    /// Whether the peer is an exit node.
    pub exit_node: bool,
}

// ---------------------------------------------------------------------------
// NetcheckReport
// ---------------------------------------------------------------------------

/// Report from a network connectivity check.
#[derive(Debug, Clone, PartialEq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "mirrors the tailscale netcheck payload; bools are independent capability flags"
)]
pub struct NetcheckReport {
    /// Whether the node can reach the Tailscale coordination server.
    pub connectivity: bool,

    /// The preferred DERP relay region.
    pub derp_region: Option<String>,

    /// Latency to each DERP region, in milliseconds.
    pub derp_latency: Vec<(String, f64)>,

    /// Whether UDP is available for direct connections.
    pub udp: bool,

    /// Whether IPv6 is available.
    pub ipv6: bool,

    /// Whether Hairpin NAT is working (for LAN connectivity).
    pub hairpin: bool,

    /// Mapping of port numbers to whether they are open.
    pub port_mapping: Vec<(String, bool)>,
}
