//! Tailnet network topology and peer discovery.
//!
//! Provides types and operations for inspecting the tailnet topology,
//! listing peers, and querying the network layout.
//!
//! Peer entries are parsed from the `Peer` map of a `tailscale status --json`
//! (or local API `/status`) document. Each peer contributes a [`PeerInfo`]
//! with its hostname, Tailscale IPs, online state, and whether it is an exit
//! node.

use crate::report::PeerInfo;
use crate::Result;

// ---------------------------------------------------------------------------
// TailnetTopology
// ---------------------------------------------------------------------------

/// Represents the network topology of a tailnet.
///
/// Contains information about all peers in the tailnet, their connection
/// status, and the DERP relay configuration.
///
/// # Example
///
/// ```ignore
/// use toride_tailscale::tailnet::TailnetTopology;
/// use toride_tailscale::api::TailscaleApi;
///
/// let api = TailscaleApi::new();
/// let topology = TailnetTopology::from_api(&api).await?;
/// for peer in topology.peers() {
///     println!("{}: {} (online={})", peer.name, peer.ip_addresses.join(", "), peer.online);
/// }
/// ```
#[derive(Debug, Clone)]
pub struct TailnetTopology {
    /// The name of this tailnet.
    tailnet_name: String,

    /// The current node's name.
    self_name: String,

    /// All peers in the tailnet.
    peers: Vec<PeerInfo>,
}

impl TailnetTopology {
    /// Create a new `TailnetTopology`.
    pub fn new(tailnet_name: String, self_name: String, peers: Vec<PeerInfo>) -> Self {
        Self {
            tailnet_name,
            self_name,
            peers,
        }
    }

    /// Fetch the tailnet topology from the local API.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails or the response cannot
    /// be parsed.
    pub async fn from_api(api: &crate::api::TailscaleApi) -> Result<Self> {
        let status = api.get_status().await?;
        Self::from_status_json(status)
    }

    /// Build a topology from a parsed `tailscale status --json` document.
    ///
    /// This is the shared parser used by both the HTTP API path
    /// ([`from_api`](Self::from_api)) and the CLI path
    /// ([`crate::service::TailscaleService::status_json`]).
    ///
    /// # Errors
    ///
    /// Never returns an error: missing fields degrade gracefully to
    /// `"unknown"` names and empty peer lists.
    pub fn from_status_json(status: serde_json::Value) -> Result<Self> {
        let tailnet_name = status
            .get("CurrentTailnet")
            .and_then(|t| t.get("Name"))
            .and_then(|n| n.as_str())
            .unwrap_or("unknown")
            .to_owned();

        let self_name = status
            .get("Self")
            .and_then(|s| s.get("HostName"))
            .and_then(|n| n.as_str())
            .unwrap_or("unknown")
            .to_owned();

        let peers = parse_peers(&status);

        Ok(Self {
            tailnet_name,
            self_name,
            peers,
        })
    }

    /// Returns the tailnet name.
    pub fn tailnet_name(&self) -> &str {
        &self.tailnet_name
    }

    /// Returns the current node's name.
    pub fn self_name(&self) -> &str {
        &self.self_name
    }

    /// Returns the list of all peers in the tailnet.
    pub fn peers(&self) -> &[PeerInfo] {
        &self.peers
    }

    /// Returns only the online (reachable) peers.
    pub fn online_peers(&self) -> Vec<&PeerInfo> {
        self.peers.iter().filter(|p| p.online).collect()
    }

    /// Returns only the exit nodes.
    pub fn exit_nodes(&self) -> Vec<&PeerInfo> {
        self.peers.iter().filter(|p| p.exit_node).collect()
    }
}

// ---------------------------------------------------------------------------
// JSON parsing helpers
// ---------------------------------------------------------------------------

/// Parse the `Peer` map of a `tailscale status --json` document into
/// [`PeerInfo`] values.
///
/// Each peer object typically contains:
/// - `HostName` -- the peer's hostname
/// - `TailscaleIPs` -- array of IP strings
/// - `Online` -- boolean
/// - `ExitNodeOption` -- boolean (this peer is *available* as an exit node)
/// - `ExitNodeOption` is also used as the "is exit node" signal; a peer that
///   the current node is actively routing through appears with `ExitNodeOption`
///   set. We treat a truthy `ExitNodeOption` as "exit node".
///
/// Peers missing a hostname are skipped.
pub(crate) fn parse_peers(status: &serde_json::Value) -> Vec<PeerInfo> {
    let Some(peers) = status.get("Peer").and_then(|p| p.as_object()) else {
        return Vec::new();
    };

    let mut out = Vec::with_capacity(peers.len());
    for peer in peers.values() {
        let Some(name) = peer.get("HostName").and_then(|n| n.as_str()) else {
            continue;
        };

        let ip_addresses = peer
            .get("TailscaleIPs")
            .and_then(|i| i.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let online = peer.get("Online").and_then(|o| o.as_bool()).unwrap_or(false);
        let exit_node = peer
            .get("ExitNodeOption")
            .and_then(|e| e.as_bool())
            .unwrap_or(false);

        out.push(PeerInfo {
            name: name.to_owned(),
            ip_addresses,
            online,
            exit_node,
        });
    }

    // Stable ordering by hostname for deterministic output and tests.
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_status() -> serde_json::Value {
        serde_json::json!({
            "CurrentTailnet": { "Name": "example.ts.net" },
            "Self": { "HostName": "my-host", "TailscaleIPs": ["100.64.0.1"] },
            "Peer": {
                "nodeKey1": {
                    "HostName": "exit-box",
                    "TailscaleIPs": ["100.64.0.2", "fd7a::2"],
                    "Online": true,
                    "ExitNodeOption": true
                },
                "nodeKey2": {
                    "HostName": "laptop",
                    "TailscaleIPs": ["100.64.0.3"],
                    "Online": false,
                    "ExitNodeOption": false
                },
                "nodeKey3": {
                    "HostName": "bare-peer-no-ips"
                }
            }
        })
    }

    #[test]
    fn parses_all_peers_from_status_json() {
        let topo = TailnetTopology::from_status_json(sample_status()).unwrap();
        assert_eq!(topo.tailnet_name(), "example.ts.net");
        assert_eq!(topo.self_name(), "my-host");
        assert_eq!(topo.peers().len(), 3);
    }

    #[test]
    fn online_peers_filters_correctly() {
        let topo = TailnetTopology::from_status_json(sample_status()).unwrap();
        let online = topo.online_peers();
        assert_eq!(online.len(), 1);
        assert_eq!(online[0].name, "exit-box");
    }

    #[test]
    fn exit_nodes_filters_correctly() {
        let topo = TailnetTopology::from_status_json(sample_status()).unwrap();
        let exits = topo.exit_nodes();
        assert_eq!(exits.len(), 1);
        assert_eq!(exits[0].name, "exit-box");
        assert_eq!(exits[0].ip_addresses, vec!["100.64.0.2", "fd7a::2"]);
    }

    #[test]
    fn peer_missing_fields_degrades_gracefully() {
        let topo = TailnetTopology::from_status_json(sample_status()).unwrap();
        let bare = topo
            .peers()
            .iter()
            .find(|p| p.name == "bare-peer-no-ips")
            .unwrap();
        assert!(bare.ip_addresses.is_empty());
        assert!(!bare.online);
        assert!(!bare.exit_node);
    }

    #[test]
    fn empty_peer_map_yields_empty_topology() {
        let status = serde_json::json!({ "Self": { "HostName": "solo" } });
        let topo = TailnetTopology::from_status_json(status).unwrap();
        assert!(topo.peers().is_empty());
        assert_eq!(topo.self_name(), "solo");
    }

    #[test]
    fn missing_tailnet_defaults_to_unknown() {
        let status = serde_json::json!({ "Self": { "HostName": "h" }, "Peer": {} });
        let topo = TailnetTopology::from_status_json(status).unwrap();
        assert_eq!(topo.tailnet_name(), "unknown");
    }

    #[test]
    fn parse_peers_skips_entries_without_hostname() {
        let status = serde_json::json!({
            "Peer": {
                "k1": { "TailscaleIPs": ["1.2.3.4"] },
                "k2": { "HostName": "real-peer" }
            }
        });
        let peers = parse_peers(&status);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].name, "real-peer");
    }

    #[test]
    fn parse_peers_returns_empty_when_no_peer_key() {
        let status = serde_json::json!({ "BackendState": "Running" });
        assert!(parse_peers(&status).is_empty());
    }

    #[test]
    fn peers_are_sorted_by_name_for_determinism() {
        let status = serde_json::json!({
            "Peer": {
                "z": { "HostName": "zeta" },
                "a": { "HostName": "alpha" },
                "m": { "HostName": "mid" }
            }
        });
        let peers = parse_peers(&status);
        let names: Vec<&str> = peers.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "mid", "zeta"]);
    }
}
