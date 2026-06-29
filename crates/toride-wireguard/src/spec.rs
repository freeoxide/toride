//! Data types describing WireGuard interfaces and peers.
//!
//! [`WireguardSpec`] holds the full specification for a WireGuard interface
//! (address, listen port, DNS, private key, peers). [`PeerSpec`] describes a
//! single peer with its public key, allowed IPs, endpoint, and keepalive.

// ---------------------------------------------------------------------------
// PeerSpec
// ---------------------------------------------------------------------------

/// Specification for a single WireGuard peer.
///
/// A peer is identified by its public key and carries traffic-routing rules
/// (`allowed_ips`), an optional endpoint address, and an optional persistent
/// keepalive interval.
#[derive(Debug, Clone)]
pub struct PeerSpec {
    /// The peer's Base64-encoded public key.
    pub public_key: String,

    /// Comma-separated list of IP/CIDR ranges routed to this peer
    /// (e.g. `["10.0.0.2/32", "fd00::2/128"]`).
    pub allowed_ips: Vec<String>,

    /// Optional endpoint address (`host:port`) for the peer.
    pub endpoint: Option<String>,

    /// Optional persistent keepalive interval in seconds.
    pub persistent_keepalive: Option<u32>,
}

impl PeerSpec {
    /// Create a new peer spec with the given public key and allowed IPs.
    pub fn new(public_key: String, allowed_ips: Vec<String>) -> Self {
        Self {
            public_key,
            allowed_ips,
            endpoint: None,
            persistent_keepalive: None,
        }
    }

    /// Set the peer's endpoint address.
    #[must_use]
    pub fn with_endpoint(mut self, endpoint: String) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    /// Set the persistent keepalive interval in seconds.
    #[must_use]
    pub fn with_persistent_keepalive(mut self, seconds: u32) -> Self {
        self.persistent_keepalive = Some(seconds);
        self
    }
}

// ---------------------------------------------------------------------------
// WireguardSpec
// ---------------------------------------------------------------------------

/// Full specification for a WireGuard interface.
///
/// Contains all data needed to render a complete WireGuard configuration file
/// (`wg0.conf`), including the interface section and all peer sections.
#[derive(Debug, Clone)]
pub struct WireguardSpec {
    /// Interface name (e.g. `wg0`).
    pub name: String,

    /// Interface address(es), comma-separated (e.g. `10.0.0.1/24`).
    pub address: String,

    /// UDP listen port (0 = kernel-assigned).
    pub listen_port: u16,

    /// DNS server(s) for the interface.
    pub dns: Option<String>,

    /// Base64-encoded private key.
    pub private_key: Option<String>,

    /// List of peers for this interface.
    pub peers: Vec<PeerSpec>,
}

impl WireguardSpec {
    /// Create a new interface spec with the given name and address.
    pub fn new(name: String, address: String) -> Self {
        Self {
            name,
            address,
            listen_port: 0,
            dns: None,
            private_key: None,
            peers: Vec::new(),
        }
    }

    /// Set the listen port.
    #[must_use]
    pub fn with_listen_port(mut self, port: u16) -> Self {
        self.listen_port = port;
        self
    }

    /// Set the DNS server(s).
    #[must_use]
    pub fn with_dns(mut self, dns: String) -> Self {
        self.dns = Some(dns);
        self
    }

    /// Set the private key.
    #[must_use]
    pub fn with_private_key(mut self, key: String) -> Self {
        self.private_key = Some(key);
        self
    }

    /// Add a peer to this interface.
    #[must_use]
    pub fn with_peer(mut self, peer: PeerSpec) -> Self {
        self.peers.push(peer);
        self
    }

    /// Find a peer by public key.
    pub fn find_peer(&self, public_key: &str) -> Option<&PeerSpec> {
        self.peers.iter().find(|p| p.public_key == public_key)
    }

    /// Find a peer by public key (mutable).
    pub fn find_peer_mut(&mut self, public_key: &str) -> Option<&mut PeerSpec> {
        self.peers.iter_mut().find(|p| p.public_key == public_key)
    }
}
