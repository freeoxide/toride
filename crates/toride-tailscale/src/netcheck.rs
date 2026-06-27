//! Network connectivity and DERP relay checks.
//!
//! Provides [`NetcheckRunner`] for performing network connectivity checks
//! through the Tailscale local API. Reports UDP availability, IPv6 support,
//! DERP relay latency, and NAT traversal capabilities.

use crate::report::NetcheckReport;
use crate::Result;

// ---------------------------------------------------------------------------
// NetcheckRunner
// ---------------------------------------------------------------------------

/// Runs network connectivity checks via the Tailscale local API.
///
/// `NetcheckRunner` queries the local API for the latest netcheck results
/// and parses them into a structured [`NetcheckReport`].
///
/// # Example
///
/// ```ignore
/// use toride_tailscale::netcheck::NetcheckRunner;
/// use toride_tailscale::api::TailscaleApi;
///
/// let api = TailscaleApi::new();
/// let runner = NetcheckRunner::new(&api);
/// let report = runner.run().await?;
/// println!("UDP: {}, IPv6: {}", report.udp, report.ipv6);
/// ```
pub struct NetcheckRunner<'a> {
    /// Reference to the Tailscale API client.
    api: &'a crate::api::TailscaleApi,
}

impl<'a> NetcheckRunner<'a> {
    /// Create a new `NetcheckRunner` with the given API client.
    pub fn new(api: &'a crate::api::TailscaleApi) -> Self {
        Self { api }
    }

    /// Run a network connectivity check and return the report.
    ///
    /// Queries `GET /localapi/v0/netcheck` and parses the response into
    /// a structured [`NetcheckReport`].
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails or the response cannot
    /// be parsed.
    pub async fn run(&self) -> Result<NetcheckReport> {
        let raw = self.api.get_netcheck().await?;
        Ok(Self::parse(&raw))
    }

    /// Parse a raw netcheck JSON document into a [`NetcheckReport`].
    ///
    /// Exposed so the same parser covers the HTTP API path (`run`) and the
    /// CLI path (`tailscale netcheck --format=json`).
    pub fn parse(raw: &serde_json::Value) -> NetcheckReport {
        let udp = raw.get("UDP").and_then(|v| v.as_bool()).unwrap_or(false);
        let ipv6 = raw.get("IPv6").and_then(|v| v.as_bool()).unwrap_or(false);
        let hairpin = raw.get("HairPinning").and_then(|v| v.as_bool()).unwrap_or(false);

        let derp_region = raw
            .get("PreferredDERP")
            .and_then(|v| v.as_i64())
            .map(|id| format!("DERP-{id}"));

        // Parse DERP latency map.
        let mut derp_latency = Vec::new();
        if let Some(latency_map) = raw.get("DERPLatency").and_then(|v| v.as_object()) {
            for (region, latency) in latency_map {
                if let Some(ms) = latency.as_f64() {
                    derp_latency.push((region.clone(), ms));
                }
            }
        }
        derp_latency.sort_by(|a, b| a.0.cmp(&b.0));

        // Connectivity is "true" when the node has a usable transport to the
        // coordination server: UDP works *and* a preferred DERP region is
        // available. `MappingVariesByDestIP` describes NAT-mapping variance,
        // not overall reachability, so it is not used here.
        let connectivity = udp && derp_region.is_some();

        // Port-mapping: the netcheck payload reports UPnP/PMP/PCP availability
        // under the `Portmap` object as boolean sub-fields.
        let port_mapping = parse_port_mapping(raw);

        NetcheckReport {
            connectivity,
            derp_region,
            derp_latency,
            udp,
            ipv6,
            hairpin,
            port_mapping,
        }
    }
}

/// Parse the `Portmap` object (UPnP / NAT-PMP / PCP availability) into
/// `(name, available)` pairs.
fn parse_port_mapping(raw: &serde_json::Value) -> Vec<(String, bool)> {
    let Some(map) = raw.get("Portmap").and_then(|p| p.as_object()) else {
        return Vec::new();
    };
    // The three well-known port-mapping mechanisms reported by tailscale.
    let keys = ["UPnP", "PMP", "PCP"];
    let mut out = Vec::with_capacity(keys.len());
    for key in keys {
        if let Some(val) = map.get(key) {
            if let Some(b) = val.as_bool() {
                out.push((key.to_owned(), b));
            } else if let Some(s) = val.as_str() {
                // Some versions emit "true"/"false" strings.
                out.push((key.to_owned(), s.eq_ignore_ascii_case("true")));
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> serde_json::Value {
        serde_json::json!({
            "UDP": true,
            "IPv6": false,
            "HairPinning": true,
            "PreferredDERP": 7,
            "MappingVariesByDestIP": false,
            "DERPLatency": { "region-3": 12.5, "region-7": 9.0 },
            "Portmap": { "UPnP": true, "PMP": false, "PCP": true }
        })
    }

    #[test]
    fn connectivity_requires_udp_and_derp() {
        // Full sample: UDP + preferred DERP -> connectivity true.
        let report = NetcheckRunner::parse(&sample());
        assert!(report.connectivity);
        assert_eq!(report.derp_region.as_deref(), Some("DERP-7"));
    }

    #[test]
    fn connectivity_false_without_udp() {
        let mut raw = sample();
        raw["UDP"] = serde_json::json!(false);
        let report = NetcheckRunner::parse(&raw);
        assert!(!report.connectivity, "no UDP must mean not connected");
    }

    #[test]
    fn connectivity_false_without_derp_even_with_udp() {
        let mut raw = sample();
        raw.as_object_mut().unwrap().remove("PreferredDERP");
        let report = NetcheckRunner::parse(&raw);
        assert!(!report.connectivity);
    }

    #[test]
    fn mapping_varies_by_dest_does_not_imply_connectivity() {
        // Regression: previously `connectivity = MappingVariesByDestIP.is_boolean()`
        // returned true even when the value was `false`. With no UDP/DERP,
        // connectivity must be false regardless of this field.
        let raw = serde_json::json!({ "MappingVariesByDestIP": false });
        assert!(!NetcheckRunner::parse(&raw).connectivity);

        let raw_true = serde_json::json!({ "MappingVariesByDestIP": true });
        assert!(!NetcheckRunner::parse(&raw_true).connectivity);
    }

    #[test]
    fn port_mapping_parsed_from_portmap_object() {
        let report = NetcheckRunner::parse(&sample());
        assert_eq!(
            report.port_mapping,
            vec![
                ("UPnP".to_owned(), true),
                ("PMP".to_owned(), false),
                ("PCP".to_owned(), true),
            ]
        );
    }

    #[test]
    fn port_mapping_empty_when_no_portmap_key() {
        let raw = serde_json::json!({ "UDP": true });
        assert!(NetcheckRunner::parse(&raw).port_mapping.is_empty());
    }

    #[test]
    fn derp_latency_sorted_by_region_name() {
        let report = NetcheckRunner::parse(&sample());
        let names: Vec<&str> = report.derp_latency.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(names, vec!["region-3", "region-7"]);
        assert_eq!(report.derp_latency[1].1, 9.0);
    }
}
