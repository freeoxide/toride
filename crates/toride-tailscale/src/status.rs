//! Node status and connection state.
//!
//! Provides [`NodeStatus`] for querying the current state of the Tailscale
//! daemon: whether it is connected, the node's identity, IP addresses, and
//! the active exit node.

use crate::Result;
use crate::models::StatusDocument;
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

    /// Build the report from the typed status document, the fetch path the
    /// [`crate::client::TailscaleClient`] uses: no `serde_json::Value` DOM is
    /// built. Field semantics match [`NodeStatus::to_report`] exactly.
    pub(crate) fn report_from_document(doc: &StatusDocument) -> TailscaleReport {
        let exit_node = doc
            .exit_node_status
            .as_ref()
            .and_then(|status| status.tailscale_ips.first())
            .filter(|ip| !ip.is_empty())
            .cloned();
        let ip_addresses = doc
            .self_node
            .as_ref()
            .map(|n| n.tailscale_ips.clone())
            .unwrap_or_default();
        TailscaleReport {
            connected: doc.is_connected(),
            node_name: doc.self_name().to_owned(),
            tailnet: doc.tailnet_name().to_owned(),
            ip_addresses,
            exit_node,
            dns_enabled: doc.magic_dns_enabled,
        }
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
    /// The exit-node field is the node this machine actively routes through,
    /// parsed from the top-level `ExitNodeStatus` object. A peer advertising
    /// `ExitNodeOption` is only available as an exit node
    /// ([`PeerInfo::exit_node`](crate::report::PeerInfo)); availability does
    /// not imply use. MagicDNS is derived from the top-level
    /// `MagicDNSEnabled` boolean.
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

    /// Returns the IP of the exit node this node actively routes through, if
    /// any.
    ///
    /// The in-use signal is the top-level `ExitNodeStatus.TailscaleIPs`
    /// object `tailscale status --json` emits; it is absent (or carries no
    /// usable IP) when this node is not using an exit node.
    fn exit_node_in_use(&self) -> Option<String> {
        let ip = self
            .raw
            .get("ExitNodeStatus")
            .and_then(|s| s.get("TailscaleIPs"))
            .and_then(serde_json::Value::as_array)
            .and_then(|ips| ips.first())
            .and_then(serde_json::Value::as_str)?;
        if ip.is_empty() {
            return None;
        }
        Some(ip.to_owned())
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
            "ExitNodeStatus": { "TailscaleIPs": ["100.64.0.9"] },
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

    /// The typed fetch path must produce the same report as the raw-JSON
    /// path for the same document.
    #[test]
    fn typed_report_matches_the_raw_json_report() {
        let doc: crate::models::StatusDocument =
            serde_json::from_value(sample()).expect("sample parses as typed document");
        assert_eq!(
            NodeStatus::report_from_document(&doc),
            NodeStatus::from_raw(sample()).to_report()
        );
    }

    #[test]
    fn exit_node_none_when_no_exit_node_status() {
        let mut raw = sample();
        raw.as_object_mut().unwrap().remove("ExitNodeStatus");
        let report = NodeStatus::from_raw(raw).to_report();
        assert_eq!(
            report.exit_node, None,
            "an offered-but-unused exit node must not be reported as in use"
        );
    }

    #[test]
    fn exit_node_none_when_status_ips_empty() {
        let mut raw = sample();
        raw["ExitNodeStatus"] = serde_json::json!({ "TailscaleIPs": [] });
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
