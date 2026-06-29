//! DNS configuration and MagicDNS management.
//!
//! Provides types and operations for inspecting and managing Tailscale DNS
//! settings, including MagicDNS, custom resolvers, and split DNS
//! configurations.

use crate::Result;

// ---------------------------------------------------------------------------
// DnsManager
// ---------------------------------------------------------------------------

/// Manager for Tailscale DNS configuration.
///
/// `DnsManager` queries the local API for the current DNS configuration
/// and provides typed access to nameservers, search domains, and MagicDNS
/// status.
///
/// # Example
///
/// ```ignore
/// use toride_tailscale::dns::DnsManager;
/// use toride_tailscale::api::TailscaleApi;
///
/// let api = TailscaleApi::new();
/// let dns = DnsManager::new(&api);
/// let config = dns.get_config().await?;
/// println!("MagicDNS: {}", config.magic_dns);
/// println!("Nameservers: {:?}", config.nameservers);
/// ```
pub struct DnsManager<'a> {
    /// Reference to the Tailscale API client.
    api: &'a crate::api::TailscaleApi,
}

// ---------------------------------------------------------------------------
// DnsConfigInfo
// ---------------------------------------------------------------------------

/// Parsed DNS configuration from the Tailscale local API.
#[derive(Debug, Clone, PartialEq)]
pub struct DnsConfigInfo {
    /// Whether MagicDNS is enabled.
    pub magic_dns: bool,

    /// Custom DNS resolver addresses.
    pub nameservers: Vec<String>,

    /// Search domains appended to DNS queries.
    pub search_domains: Vec<String>,

    /// Split DNS configurations: domain -> nameserver.
    pub split_dns: Vec<(String, String)>,
}

impl<'a> DnsManager<'a> {
    /// Create a new `DnsManager` with the given API client.
    pub fn new(api: &'a crate::api::TailscaleApi) -> Self {
        Self { api }
    }

    /// Fetch and parse the current DNS configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails or the response cannot
    /// be parsed.
    pub async fn get_config(&self) -> Result<DnsConfigInfo> {
        let raw = self.api.get_dns_config().await?;
        Ok(Self::parse(&raw))
    }

    /// Parse a raw DNS-config JSON document into a [`DnsConfigInfo`].
    ///
    /// Shared between the HTTP API path (`get_config`) and any CLI path that
    /// returns the same document.
    pub fn parse(raw: &serde_json::Value) -> DnsConfigInfo {
        let magic_dns = raw
            .get("MagicDNS")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);

        let nameservers = raw
            .get("Nameservers")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let search_domains = raw
            .get("SearchDomains")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let split_dns = parse_split_dns(raw);

        DnsConfigInfo {
            magic_dns,
            nameservers,
            search_domains,
            split_dns,
        }
    }

    /// Check if MagicDNS is currently enabled.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails.
    pub async fn is_magic_dns_enabled(&self) -> Result<bool> {
        let config = self.get_config().await?;
        Ok(config.magic_dns)
    }

    /// Validate a DNS configuration for correctness.
    ///
    /// Checks that nameserver addresses are valid IP addresses and that
    /// search domains are well-formed.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::DnsError`] if any value is invalid.
    pub fn validate_config(config: &DnsConfigInfo) -> Result<()> {
        for ns in &config.nameservers {
            if ns.parse::<std::net::IpAddr>().is_err() {
                return Err(crate::Error::DnsError(format!(
                    "invalid nameserver address: {ns}"
                )));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// JSON parsing helpers
// ---------------------------------------------------------------------------

/// Parse the `SplitDNS` field into `(domain, nameserver)` pairs.
///
/// The Tailscale API encodes split DNS as an object mapping a domain route to
/// an array of nameserver IPs, e.g.
/// `{"internal.example.com": ["100.100.100.100"]}`. The first nameserver for
/// each domain is reported (the list is ordered by preference).
fn parse_split_dns(raw: &serde_json::Value) -> Vec<(String, String)> {
    let Some(map) = raw.get("SplitDNS").and_then(|s| s.as_object()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (domain, servers) in map {
        if let Some(arr) = servers.as_array() {
            if let Some(first) = arr.first().and_then(|v| v.as_str()) {
                out.push((domain.clone(), first.to_owned()));
            }
        } else if let Some(single) = servers.as_str() {
            // Some payloads use a bare string instead of an array.
            out.push((domain.clone(), single.to_owned()));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
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
            "MagicDNS": true,
            "Nameservers": ["1.1.1.1", "8.8.8.8"],
            "SearchDomains": ["tailnet.example.com"],
            "SplitDNS": {
                "internal.example.com": ["100.100.100.100"],
                "corp.local": ["10.0.0.53", "10.0.0.54"]
            }
        })
    }

    #[test]
    fn parses_all_dns_fields() {
        let config = DnsManager::parse(&sample());
        assert!(config.magic_dns);
        assert_eq!(config.nameservers, vec!["1.1.1.1", "8.8.8.8"]);
        assert_eq!(config.search_domains, vec!["tailnet.example.com"]);
        assert_eq!(
            config.split_dns,
            vec![
                ("corp.local".to_owned(), "10.0.0.53".to_owned()),
                (
                    "internal.example.com".to_owned(),
                    "100.100.100.100".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn split_dns_uses_first_nameserver_per_domain() {
        let config = DnsManager::parse(&sample());
        // corp.local had two nameservers; only the first is reported.
        let corp = config
            .split_dns
            .iter()
            .find(|(d, _)| d == "corp.local")
            .unwrap();
        assert_eq!(corp.1, "10.0.0.53");
    }

    #[test]
    fn split_dns_empty_when_field_absent() {
        let raw = serde_json::json!({ "MagicDNS": false });
        let config = DnsManager::parse(&raw);
        assert!(config.split_dns.is_empty());
        assert!(!config.magic_dns);
    }

    #[test]
    fn split_dns_handles_bare_string_values() {
        let raw = serde_json::json!({
            "SplitDNS": { "alt.example.com": "9.9.9.9" }
        });
        let config = DnsManager::parse(&raw);
        assert_eq!(
            config.split_dns,
            vec![("alt.example.com".to_owned(), "9.9.9.9".to_owned())]
        );
    }

    #[test]
    fn validate_config_rejects_bad_nameserver() {
        let config = DnsConfigInfo {
            magic_dns: true,
            nameservers: vec!["not-an-ip".to_owned()],
            search_domains: vec![],
            split_dns: vec![],
        };
        assert!(DnsManager::validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_accepts_valid_ips() {
        let config = DnsConfigInfo {
            magic_dns: true,
            nameservers: vec!["1.1.1.1".to_owned(), "::1".to_owned()],
            search_domains: vec![],
            split_dns: vec![],
        };
        assert!(DnsManager::validate_config(&config).is_ok());
    }
}
