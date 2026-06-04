//! Rendering functions for Tailscale ACL policies and DNS configurations.
//!
//! Generates JSON representations suitable for the Tailscale API or
//! configuration files.

use crate::spec::{AclAction, AclRule, DnsConfig};

/// Render a list of ACL rules as a JSON string.
///
/// Produces a JSON array of objects, each with `action`, `src`, and `dst` fields.
///
/// # Example
///
/// ```
/// use toride_tailscale::render::render_acl_json;
/// use toride_tailscale::spec::{AclAction, AclRule};
///
/// let rules = vec![AclRule {
///     action: AclAction::Allow,
///     src: vec!["*".into()],
///     dst: vec!["*:*".into()],
/// }];
/// let json = render_acl_json(&rules);
/// assert!(json.contains("\"action\""));
/// assert!(json.contains("\"accept\""));
/// ```
pub fn render_acl_json(rules: &[AclRule]) -> String {
    let entries: Vec<serde_json::Value> = rules
        .iter()
        .map(|rule| {
            let action_str = match rule.action {
                AclAction::Allow => "accept",
                AclAction::Deny => "deny",
            };
            serde_json::json!({
                "action": action_str,
                "src": rule.src,
                "dst": rule.dst,
            })
        })
        .collect();

    serde_json::to_string_pretty(&entries).unwrap_or_else(|e| {
        serde_json::json!({"error": format!("failed to serialize ACL: {e}")}).to_string()
    })
}

/// Render a DNS configuration as a JSON string.
///
/// Produces a JSON object with `magicDNS`, `nameservers`, and `searchDomains` fields.
///
/// # Example
///
/// ```
/// use toride_tailscale::render::render_dns_config;
/// use toride_tailscale::spec::DnsConfig;
///
/// let dns = DnsConfig {
///     magic_dns: true,
///     nameservers: vec!["1.1.1.1".into()],
///     search_domains: vec!["example.com".into()],
/// };
/// let json = render_dns_config(&dns);
/// assert!(json.contains("\"magicDNS\""));
/// assert!(json.contains("1.1.1.1"));
/// ```
pub fn render_dns_config(dns: &DnsConfig) -> String {
    let obj = serde_json::json!({
        "magicDNS": dns.magic_dns,
        "nameservers": dns.nameservers,
        "searchDomains": dns.search_domains,
    });

    serde_json::to_string_pretty(&obj).unwrap_or_else(|e| {
        serde_json::json!({"error": format!("failed to serialize DNS config: {e}")}).to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_acl_json_allow_rule() {
        let rules = vec![AclRule {
            action: AclAction::Allow,
            src: vec!["100.64.0.1".into()],
            dst: vec!["10.0.0.0/8:443".into()],
        }];
        let json = render_acl_json(&rules);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed[0]["action"], "accept");
        assert_eq!(parsed[0]["src"][0], "100.64.0.1");
    }

    #[test]
    fn render_acl_json_deny_rule() {
        let rules = vec![AclRule {
            action: AclAction::Deny,
            src: vec!["*".into()],
            dst: vec!["*:*".into()],
        }];
        let json = render_acl_json(&rules);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed[0]["action"], "deny");
    }

    #[test]
    fn render_acl_json_empty() {
        let json = render_acl_json(&[]);
        assert_eq!(json, "[]");
    }

    #[test]
    fn render_dns_config_full() {
        let dns = DnsConfig {
            magic_dns: true,
            nameservers: vec!["1.1.1.1".into(), "8.8.8.8".into()],
            search_domains: vec!["tailnet.example.com".into()],
        };
        let json = render_dns_config(&dns);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["magicDNS"], true);
        assert_eq!(parsed["nameservers"][0], "1.1.1.1");
        assert_eq!(parsed["searchDomains"][0], "tailnet.example.com");
    }

    #[test]
    fn render_dns_config_magic_dns_off() {
        let dns = DnsConfig {
            magic_dns: false,
            nameservers: vec![],
            search_domains: vec![],
        };
        let json = render_dns_config(&dns);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["magicDNS"], false);
    }
}
