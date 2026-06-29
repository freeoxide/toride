//! Node status and connection state.
//!
//! Provides [`NodeStatus`] for querying the current state of the Tailscale
//! daemon: whether it is connected, the node's identity, IP addresses, and
//! the active exit node.

use crate::Result;
use crate::report::{ConnectionStatus, TailscaleReport};

// ---------------------------------------------------------------------------
// NodeStatus
// ---------------------------------------------------------------------------

/// Current status of the local Tailscale node.
///
/// Wraps the raw API response into a structured type with typed accessors.
///
/// # Example
///
/// ```ignore
/// use toride_tailscale::status::NodeStatus;
/// use toride_tailscale::api::TailscaleApi;
///
/// let api = TailscaleApi::new();
/// let status = NodeStatus::from_api(&api).await?;
/// println!("Connected as {} ({})", status.name(), status.connection());
/// ```
#[derive(Debug, Clone)]
pub struct NodeStatus {
    /// The raw JSON status response from the local API.
    raw: serde_json::Value,
}

impl NodeStatus {
    /// Create a `NodeStatus` from a raw API response.
    pub fn from_raw(raw: serde_json::Value) -> Self {
        Self { raw }
    }

    /// Fetch the node status from the local API.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails.
    pub async fn from_api(api: &crate::api::TailscaleApi) -> Result<Self> {
        let raw = api.get_status().await?;
        Ok(Self { raw })
    }

    /// Returns the node's hostname.
    pub fn name(&self) -> &str {
        self.raw
            .get("Self")
            .and_then(|s| s.get("HostName"))
            .and_then(|n| n.as_str())
            .unwrap_or("unknown")
    }

    /// Returns the node's Tailscale IP addresses.
    pub fn ip_addresses(&self) -> Vec<String> {
        let mut ips = Vec::new();

        if let Some(addrs) = self.raw.get("Self").and_then(|s| s.get("TailscaleIPs"))
            && let Some(arr) = addrs.as_array()
        {
            for ip in arr {
                if let Some(s) = ip.as_str() {
                    ips.push(s.to_owned());
                }
            }
        }

        ips
    }

    /// Returns the connection status.
    pub fn connection(&self) -> ConnectionStatus {
        match self
            .raw
            .get("BackendState")
            .and_then(|v| v.as_str())
            .unwrap_or("")
        {
            "Running" => ConnectionStatus::Connected,
            "NeedsLogin" | "Stopped" => ConnectionStatus::Disconnected,
            "Starting" => ConnectionStatus::Starting,
            _ => ConnectionStatus::Unknown,
        }
    }

    /// Returns the tailnet name.
    pub fn tailnet(&self) -> &str {
        self.raw
            .get("CurrentTailnet")
            .and_then(|t| t.get("Name"))
            .and_then(|n| n.as_str())
            .unwrap_or("unknown")
    }

    /// Convert this status into a [`TailscaleReport`].
    ///
    /// The exit-node field is populated from the first online peer that
    /// advertises itself as an exit node (`ExitNodeOption == true`). MagicDNS
    /// is derived from the top-level `MagicDNSEnabled` boolean.
    pub fn to_report(&self) -> TailscaleReport {
        let exit_node = self.exit_node_in_use();
        let dns_enabled = self.magic_dns_enabled();

        TailscaleReport {
            connected: self.connection() == ConnectionStatus::Connected,
            node_name: self.name().to_owned(),
            tailnet: self.tailnet().to_owned(),
            ip_addresses: self.ip_addresses(),
            exit_node,
            dns_enabled,
        }
    }

    /// Returns the IP of the exit node currently advertised by an online peer,
    /// if any.
    ///
    /// A peer with `ExitNodeOption == true` is one that this tailnet exposes as
    /// an exit node; we report its first Tailscale IP. `None` when no such peer
    /// is online.
    fn exit_node_in_use(&self) -> Option<String> {
        let peers = self.raw.get("Peer").and_then(|p| p.as_object())?;
        for peer in peers.values() {
            let is_exit = peer
                .get("ExitNodeOption")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let online = peer
                .get("Online")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            if is_exit
                && online
                && let Some(ip) = peer
                    .get("TailscaleIPs")
                    .and_then(|i| i.as_array())
                    .and_then(|arr| arr.first())
                    .and_then(|v| v.as_str())
            {
                return Some(ip.to_owned());
            }
        }
        None
    }

    /// Returns whether MagicDNS is enabled, parsed from the top-level
    /// `MagicDNSEnabled` boolean (defaults to `false` when absent).
    fn magic_dns_enabled(&self) -> bool {
        self.raw
            .get("MagicDNSEnabled")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    }

    /// Returns the raw JSON value for direct inspection.
    pub fn raw(&self) -> &serde_json::Value {
        &self.raw
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::ConnectionStatus;

    fn sample() -> serde_json::Value {
        serde_json::json!({
            "BackendState": "Running",
            "MagicDNSEnabled": true,
            "CurrentTailnet": { "Name": "example.ts.net" },
            "Self": {
                "HostName": "my-host",
                "TailscaleIPs": ["100.64.0.1"]
            },
            "Peer": {
                "k1": {
                    "HostName": "exit-box",
                    "TailscaleIPs": ["100.64.0.9"],
                    "Online": true,
                    "ExitNodeOption": true
                },
                "k2": {
                    "HostName": "laptop",
                    "TailscaleIPs": ["100.64.0.5"],
                    "Online": true,
                    "ExitNodeOption": false
                }
            }
        })
    }

    #[test]
    fn report_exits_node_and_dns_from_raw_json() {
        let status = NodeStatus::from_raw(sample());
        let report = status.to_report();
        assert!(report.connected);
        assert_eq!(report.node_name, "my-host");
        assert_eq!(report.tailnet, "example.ts.net");
        assert_eq!(report.ip_addresses, vec!["100.64.0.1"]);
        assert_eq!(report.exit_node, Some("100.64.0.9".to_owned()));
        assert!(report.dns_enabled);
    }

    #[test]
    fn exit_node_none_when_no_online_exit_peer() {
        let mut raw = sample();
        // Mark the only exit node offline.
        raw["Peer"]["k1"]["Online"] = serde_json::json!(false);
        let report = NodeStatus::from_raw(raw).to_report();
        assert_eq!(report.exit_node, None);
    }

    #[test]
    fn dns_defaults_false_when_field_absent() {
        let mut raw = sample();
        raw.as_object_mut().unwrap().remove("MagicDNSEnabled");
        let report = NodeStatus::from_raw(raw).to_report();
        assert!(!report.dns_enabled);
    }

    #[test]
    fn connection_state_maps_backend_state() {
        let cases = [
            ("Running", ConnectionStatus::Connected),
            ("NeedsLogin", ConnectionStatus::Disconnected),
            ("Stopped", ConnectionStatus::Disconnected),
            ("Starting", ConnectionStatus::Starting),
            ("Weird", ConnectionStatus::Unknown),
        ];
        for (state, expected) in cases {
            let raw = serde_json::json!({ "BackendState": state });
            assert_eq!(
                NodeStatus::from_raw(raw).connection(),
                expected,
                "state={state}"
            );
        }
    }
}
