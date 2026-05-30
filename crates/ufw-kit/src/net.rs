//! Network types and validators.
//!
//! Provides helpers for IP/CIDR validation, private network detection,
//! and rule safety analysis.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::spec::{Address, PortSpec, RuleSpec};

/// Check if an IP address is a private/internal address.
#[must_use]
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || is_link_local_v4(v4),
        IpAddr::V6(v6) => v6.is_loopback() || is_link_local_v6(v6) || is_unique_local_v6(v6),
    }
}

/// Check if an IPv4 address is link-local (169.254.0.0/16).
#[must_use]
pub fn is_link_local_v4(ip: Ipv4Addr) -> bool {
    ip.octets()[0] == 169 && ip.octets()[1] == 254
}

/// Check if an IPv6 address is link-local (`fe80::/10`).
#[must_use]
pub fn is_link_local_v6(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

/// Check if an IPv6 address is unique local (`fc00::/7`).
#[must_use]
pub fn is_unique_local_v6(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

/// Check if an address is unspecified (0.0.0.0 or ::).
#[must_use]
pub fn is_unspecified(ip: IpAddr) -> bool {
    ip.is_unspecified()
}

/// Check if an address is multicast.
#[must_use]
pub fn is_multicast(ip: IpAddr) -> bool {
    ip.is_multicast()
}

/// Check if an address is loopback.
#[must_use]
pub fn is_loopback(ip: IpAddr) -> bool {
    ip.is_loopback()
}

/// Check if an address is public (not private, loopback, link-local, etc.).
#[must_use]
pub fn is_public_ip(ip: IpAddr) -> bool {
    !is_private_ip(ip) && !is_multicast(ip) && !is_unspecified(ip)
}

/// Check if an address is IPv6.
#[must_use]
pub fn is_ipv6(addr: &Address) -> bool {
    match addr {
        Address::Ip(IpAddr::V6(_)) => true,
        Address::Net(net) => matches!(net, ipnet::IpNet::V6(_)),
        Address::Ip(_) | Address::Any => false,
    }
}

/// Check if an address is IPv4.
#[must_use]
pub fn is_ipv4(addr: &Address) -> bool {
    match addr {
        Address::Ip(IpAddr::V4(_)) => true,
        Address::Net(net) => matches!(net, ipnet::IpNet::V4(_)),
        Address::Ip(_) | Address::Any => false,
    }
}

/// Check if a rule exposes a specific port from any address.
#[must_use]
pub fn rule_exposes_port(spec: &RuleSpec, port: u16) -> bool {
    if spec.from_addr != Address::Any {
        return false;
    }
    match &spec.to_port {
        PortSpec::Single(p) => *p == port,
        PortSpec::Range { start, end } => *start <= port && port <= *end,
        PortSpec::List(ports) => ports.iter().any(|p| match p {
            PortSpec::Single(p) => *p == port,
            PortSpec::Range { start, end } => *start <= port && port <= *end,
            _ => false,
        }),
        _ => false,
    }
}

/// Check if a rule allows traffic from anywhere.
#[must_use]
pub fn rule_allows_from_anywhere(spec: &RuleSpec) -> bool {
    spec.from_addr == Address::Any
}

/// List of commonly dangerous ports that should trigger warnings.
pub const DANGEROUS_PORTS: &[(u16, &str)] = &[
    (22, "SSH"),
    (2375, "Docker API plaintext"),
    (2376, "Docker API TLS"),
    (5432, "Postgres"),
    (3306, "MySQL"),
    (6379, "Redis"),
    (27017, "MongoDB"),
    (9200, "Elasticsearch"),
    (9300, "Elasticsearch transport"),
    (11211, "Memcached"),
    (8080, "common admin/dev"),
    (9000, "MinIO/admin/dev"),
    (9090, "Prometheus"),
    (3000, "Grafana/dev"),
];

/// Check if a rule exposes any dangerous ports.
#[must_use]
pub fn check_dangerous_ports(spec: &RuleSpec) -> Vec<(u16, &'static str)> {
    DANGEROUS_PORTS
        .iter()
        .filter(|(port, _)| rule_exposes_port(spec, *port))
        .copied()
        .collect()
}

/// Check if two addresses are in different IP families (IPv4 vs IPv6).
#[must_use]
pub fn is_ipv4_ipv6_mismatch(a: &Address, b: &Address) -> bool {
    (is_ipv4(a) && is_ipv6(b)) || (is_ipv6(a) && is_ipv4(b))
}

/// Parse an IP address string.
pub fn parse_ip(s: &str) -> Result<IpAddr, String> {
    s.parse::<IpAddr>().map_err(|e| format!("invalid IP address '{s}': {e}"))
}

/// Parse a CIDR string.
pub fn parse_cidr(s: &str) -> Result<ipnet::IpNet, String> {
    s.parse::<ipnet::IpNet>().map_err(|e| format!("invalid CIDR '{s}': {e}"))
}

#[cfg(test)]
#[path = "net.test.rs"]
mod tests;
