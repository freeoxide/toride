//! Typed local-API response documents.
//!
//! Deserialization targets for the LocalAPI endpoints
//! [`crate::api::TailscaleApi`] queries; the client path parses responses
//! straight into these instead of a `serde_json::Value` DOM. Fields the crate does not consume
//! are ignored by serde, so a newer tailscaled adding keys stays parseable;
//! fields the crate consumes all default, so an older tailscaled omitting
//! them degrades the same way the raw-JSON path degrades.

use std::collections::HashMap;

/// `GET /localapi/v0/status`, the same document `tailscale status --json`
/// prints.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct StatusDocument {
    /// `BackendState`: `Running`, `NeedsLogin`, `Stopped`, `Starting`, ...
    #[serde(rename = "BackendState", default)]
    pub backend_state: String,
    /// `MagicDNSEnabled`.
    #[serde(rename = "MagicDNSEnabled", default)]
    pub magic_dns_enabled: bool,
    /// `CurrentTailnet`.
    #[serde(rename = "CurrentTailnet", default)]
    pub current_tailnet: Option<TailnetName>,
    /// `Self`, this node's identity.
    #[serde(rename = "Self", default)]
    pub self_node: Option<NodeIdentity>,
    /// `ExitNodeStatus`, present only while routing through an exit node.
    #[serde(rename = "ExitNodeStatus", default)]
    pub exit_node_status: Option<ExitNodeStatus>,
    /// `Peer`, keyed by node key.
    #[serde(rename = "Peer", default)]
    pub peer: HashMap<String, PeerEntry>,
}

impl StatusDocument {
    /// Whether the backend reports `Running` (connected to the tailnet).
    pub fn is_connected(&self) -> bool {
        self.backend_state == "Running"
    }

    /// This node's hostname, or `"unknown"` when the field is absent.
    pub fn self_name(&self) -> &str {
        self.self_node
            .as_ref()
            .and_then(|n| n.host_name.as_deref())
            .filter(|n| !n.is_empty())
            .unwrap_or("unknown")
    }

    /// The tailnet's name, or `"unknown"` when the field is absent.
    pub fn tailnet_name(&self) -> &str {
        self.current_tailnet
            .as_ref()
            .and_then(|t| t.name.as_deref())
            .filter(|n| !n.is_empty())
            .unwrap_or("unknown")
    }
}

/// `CurrentTailnet { Name }`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct TailnetName {
    /// The tailnet's display name.
    #[serde(rename = "Name", default)]
    pub name: Option<String>,
}

/// The `Self` object: this node's hostname and Tailscale IPs.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct NodeIdentity {
    /// `HostName`.
    #[serde(rename = "HostName", default)]
    pub host_name: Option<String>,
    /// `TailscaleIPs`.
    #[serde(rename = "TailscaleIPs", default)]
    pub tailscale_ips: Vec<String>,
}

/// `ExitNodeStatus { TailscaleIPs }`, the in-use exit node's addresses.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ExitNodeStatus {
    /// `TailscaleIPs` of the exit node this node routes through.
    #[serde(rename = "TailscaleIPs", default)]
    pub tailscale_ips: Vec<String>,
}

/// One entry of the `Peer` map.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PeerEntry {
    /// `HostName`; peers without one are skipped by consumers.
    #[serde(rename = "HostName", default)]
    pub host_name: Option<String>,
    /// `TailscaleIPs`.
    #[serde(rename = "TailscaleIPs", default)]
    pub tailscale_ips: Vec<String>,
    /// `Online`.
    #[serde(rename = "Online", default)]
    pub online: bool,
    /// `ExitNodeOption`: the peer is available as an exit node. Availability
    /// only; the in-use signal is `ExitNodeStatus`.
    #[serde(rename = "ExitNodeOption", default)]
    pub exit_node_option: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_document_parses_the_canonical_shape() {
        let doc: StatusDocument = serde_json::from_str(
            r#"{
                "BackendState": "Running",
                "MagicDNSEnabled": true,
                "CurrentTailnet": { "Name": "example.ts.net" },
                "Self": { "HostName": "my-host", "TailscaleIPs": ["100.64.0.1"] },
                "ExitNodeStatus": { "TailscaleIPs": ["100.64.0.9"] },
                "Peer": {
                    "k1": {
                        "HostName": "exit-box",
                        "TailscaleIPs": ["100.64.0.9"],
                        "Online": true,
                        "ExitNodeOption": true,
                        "PeerPlatform": "linux"
                    }
                }
            }"#,
        )
        .expect("canonical document parses");
        assert!(doc.is_connected());
        assert!(doc.magic_dns_enabled);
        assert_eq!(doc.self_name(), "my-host");
        assert_eq!(doc.tailnet_name(), "example.ts.net");
        assert_eq!(doc.peer.len(), 1);
        assert!(doc.peer["k1"].exit_node_option);
    }

    /// Unknown keys (newer tailscaled) and absent optional objects (older
    /// tailscaled, offline states) must both parse with the documented
    /// defaults.
    #[test]
    fn status_document_degrades_on_missing_fields() {
        let doc: StatusDocument =
            serde_json::from_str(r#"{ "BackendState": "Stopped", "FutureField": 7 }"#)
                .expect("unknown keys are ignored");
        assert!(!doc.is_connected());
        assert!(!doc.magic_dns_enabled);
        assert_eq!(doc.self_name(), "unknown");
        assert_eq!(doc.tailnet_name(), "unknown");
        assert!(doc.peer.is_empty());
        assert!(doc.exit_node_status.is_none());
    }

    #[test]
    fn empty_strings_fall_back_to_unknown_names() {
        let doc: StatusDocument = serde_json::from_str(
            r#"{ "Self": { "HostName": "" }, "CurrentTailnet": { "Name": "" } }"#,
        )
        .unwrap();
        assert_eq!(doc.self_name(), "unknown");
        assert_eq!(doc.tailnet_name(), "unknown");
    }
}
