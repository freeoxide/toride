//! Preset firewall rule templates.
//!
//! Provides ready-made rule sets for common server configurations.
//! Each preset returns a [`Preset`] containing a list of [`RuleSpec`]
//! values that can be applied via the client.

use crate::spec::{Action, Address, Direction, Protocol, RuleSpec};

/// A named preset with a description and list of rules.
#[derive(Debug, Clone)]
pub struct Preset {
    /// Preset identifier.
    pub id: &'static str,
    /// Human-readable name.
    pub name: &'static str,
    /// Description of what this preset does.
    pub description: String,
    /// The rules this preset would apply.
    pub rules: Vec<RuleSpec>,
}

/// SSH server preset: allow SSH (port 22) with rate limiting.
pub fn ssh() -> Preset {
    Preset {
        id: "ssh",
        name: "SSH Server",
        description: "Allow inbound SSH with rate limiting to prevent brute force.".into(),
        rules: vec![
            RuleSpec::builder(Action::Limit)
                .direction(Direction::In)
                .proto(Protocol::Tcp)
                .to_port(22)
                .comment("preset:ssh")
                .build()
                .expect("ssh preset rule should validate"),
        ],
    }
}

/// Web server (public) preset: allow SSH + HTTP + HTTPS.
pub fn web_public() -> Preset {
    Preset {
        id: "web-public",
        name: "Web Server (Public)",
        description: "Allow inbound SSH, HTTP (80), and HTTPS (443).".into(),
        rules: vec![
            RuleSpec::builder(Action::Limit)
                .direction(Direction::In)
                .proto(Protocol::Tcp)
                .to_port(22)
                .comment("preset:web:ssh")
                .build()
                .expect("preset rule should validate"),
            RuleSpec::builder(Action::Allow)
                .direction(Direction::In)
                .proto(Protocol::Tcp)
                .to_port(80)
                .comment("preset:web:http")
                .build()
                .expect("preset rule should validate"),
            RuleSpec::builder(Action::Allow)
                .direction(Direction::In)
                .proto(Protocol::Tcp)
                .to_port(443)
                .comment("preset:web:https")
                .build()
                .expect("preset rule should validate"),
        ],
    }
}

/// Reverse proxy preset: SSH + HTTP + HTTPS (same as web-public, explicit name).
pub fn reverse_proxy() -> Preset {
    Preset {
        id: "reverse-proxy",
        name: "Reverse Proxy",
        description: "Allow inbound SSH, HTTP, and HTTPS for reverse proxy (nginx/caddy/traefik)."
            .into(),
        rules: vec![
            RuleSpec::builder(Action::Limit)
                .direction(Direction::In)
                .proto(Protocol::Tcp)
                .to_port(22)
                .comment("preset:proxy:ssh")
                .build()
                .expect("preset rule should validate"),
            RuleSpec::builder(Action::Allow)
                .direction(Direction::In)
                .proto(Protocol::Tcp)
                .to_port(80)
                .comment("preset:proxy:http")
                .build()
                .expect("preset rule should validate"),
            RuleSpec::builder(Action::Allow)
                .direction(Direction::In)
                .proto(Protocol::Tcp)
                .to_port(443)
                .comment("preset:proxy:https")
                .build()
                .expect("preset rule should validate"),
        ],
    }
}

/// Tailscale VPN preset: allow Tailscale UDP port (41641) and SSH.
pub fn tailscale() -> Preset {
    Preset {
        id: "tailscale",
        name: "Tailscale VPN",
        description: "Allow Tailscale UDP (41641) and SSH for VPN mesh access.".into(),
        rules: vec![
            RuleSpec::builder(Action::Limit)
                .direction(Direction::In)
                .proto(Protocol::Tcp)
                .to_port(22)
                .comment("preset:tailscale:ssh")
                .build()
                .expect("preset rule should validate"),
            RuleSpec::builder(Action::Allow)
                .direction(Direction::In)
                .proto(Protocol::Udp)
                .to_port(41641)
                .comment("preset:tailscale:udp")
                .build()
                .expect("preset rule should validate"),
        ],
    }
}

/// `WireGuard` VPN preset: allow `WireGuard` UDP port (51820) and SSH.
pub fn wireguard() -> Preset {
    Preset {
        id: "wireguard",
        name: "WireGuard VPN",
        description: "Allow WireGuard UDP (51820) and SSH.".into(),
        rules: vec![
            RuleSpec::builder(Action::Limit)
                .direction(Direction::In)
                .proto(Protocol::Tcp)
                .to_port(22)
                .comment("preset:wg:ssh")
                .build()
                .expect("preset rule should validate"),
            RuleSpec::builder(Action::Allow)
                .direction(Direction::In)
                .proto(Protocol::Udp)
                .to_port(51820)
                .comment("preset:wg:vpn")
                .build()
                .expect("preset rule should validate"),
        ],
    }
}

/// Database server preset: SSH + a configurable database port.
///
/// Common ports: `PostgreSQL` (5432), `MySQL` (3306).
pub fn database(db_port: u16) -> Preset {
    Preset {
        id: "database",
        name: "Database Server",
        description: format!("Allow SSH and database port {db_port}."),
        rules: vec![
            RuleSpec::builder(Action::Limit)
                .direction(Direction::In)
                .proto(Protocol::Tcp)
                .to_port(22)
                .comment("preset:db:ssh")
                .build()
                .expect("preset rule should validate"),
            RuleSpec::builder(Action::Allow)
                .direction(Direction::In)
                .proto(Protocol::Tcp)
                .to_port(db_port)
                .comment("preset:db:db-port")
                .build()
                .expect("preset rule should validate"),
        ],
    }
}

/// Monitoring server preset: SSH + Prometheus (9090) + Grafana (3000) + Node Exporter (9100).
pub fn monitoring() -> Preset {
    Preset {
        id: "monitoring",
        name: "Monitoring Server",
        description: "Allow SSH, Prometheus (9090), Grafana (3000), and Node Exporter (9100)."
            .into(),
        rules: vec![
            RuleSpec::builder(Action::Limit)
                .direction(Direction::In)
                .proto(Protocol::Tcp)
                .to_port(22)
                .comment("preset:mon:ssh")
                .build()
                .expect("preset rule should validate"),
            RuleSpec::builder(Action::Allow)
                .direction(Direction::In)
                .proto(Protocol::Tcp)
                .to_port(3000)
                .comment("preset:mon:grafana")
                .build()
                .expect("preset rule should validate"),
            RuleSpec::builder(Action::Allow)
                .direction(Direction::In)
                .proto(Protocol::Tcp)
                .to_port(9090)
                .comment("preset:mon:prometheus")
                .build()
                .expect("preset rule should validate"),
            RuleSpec::builder(Action::Allow)
                .direction(Direction::In)
                .proto(Protocol::Tcp)
                .to_port(9100)
                .comment("preset:mon:node-exporter")
                .build()
                .expect("preset rule should validate"),
        ],
    }
}

/// Tailscale interface preset: allow SSH via `tailscale0` interface and
/// Tailscale UDP port (41641).
///
/// Unlike [`tailscale()`], this preset scopes SSH to the Tailscale interface,
/// restricting SSH access to VPN peers only.
pub fn tailscale_interface() -> Preset {
    Preset {
        id: "tailscale-interface",
        name: "Tailscale Interface (SSH scoped)",
        description: "Allow SSH only via tailscale0 interface and Tailscale UDP (41641). \
            Restricts SSH to Tailscale VPN peers."
            .into(),
        rules: vec![
            RuleSpec::builder(Action::Allow)
                .direction(Direction::In)
                .on_interface("tailscale0")
                .proto(Protocol::Tcp)
                .to_port(22)
                .comment("preset:ts-iface:ssh")
                .build()
                .expect("preset rule should validate"),
            RuleSpec::builder(Action::Allow)
                .direction(Direction::In)
                .proto(Protocol::Udp)
                .to_port(41641)
                .comment("preset:ts-iface:udp")
                .build()
                .expect("preset rule should validate"),
        ],
    }
}

/// `WireGuard` interface preset: allow SSH via `wg0` interface and
/// `WireGuard` UDP port (51820).
///
/// Unlike [`wireguard()`], this preset scopes SSH to the `WireGuard` interface,
/// restricting SSH access to VPN peers only.
pub fn wireguard_interface() -> Preset {
    Preset {
        id: "wireguard-interface",
        name: "WireGuard Interface (SSH scoped)",
        description: "Allow SSH only via wg0 interface and WireGuard UDP (51820). \
            Restricts SSH to WireGuard VPN peers."
            .into(),
        rules: vec![
            RuleSpec::builder(Action::Allow)
                .direction(Direction::In)
                .on_interface("wg0")
                .proto(Protocol::Tcp)
                .to_port(22)
                .comment("preset:wg-iface:ssh")
                .build()
                .expect("preset rule should validate"),
            RuleSpec::builder(Action::Allow)
                .direction(Direction::In)
                .proto(Protocol::Udp)
                .to_port(51820)
                .comment("preset:wg-iface:vpn")
                .build()
                .expect("preset rule should validate"),
        ],
    }
}

/// Cloudflare IP allowlist preset: allow SSH + HTTP + HTTPS from Cloudflare IP ranges.
///
/// Designed for servers behind Cloudflare proxy. Only Cloudflare's IP ranges
/// are allowed on ports 80/443, and SSH is allowed with rate limiting.
/// This protects the origin server by only accepting traffic from Cloudflare.
pub fn cloudflare_allowlist() -> Preset {
    // Cloudflare IPv4 ranges (as of 2024)
    let cf_ranges = [
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
    ];

    let mut rules = Vec::new();

    // SSH with rate limiting from anywhere (admin access)
    rules.push(
        RuleSpec::builder(Action::Limit)
            .direction(Direction::In)
            .proto(Protocol::Tcp)
            .to_port(22)
            .comment("preset:cf:ssh")
            .build()
            .expect("preset rule should validate"),
    );

    // HTTP/HTTPS from each Cloudflare range
    for (idx, range) in cf_ranges.iter().enumerate() {
        let net = range.parse::<ipnet::IpNet>().expect("valid CIDR");
        rules.push(
            RuleSpec::builder(Action::Allow)
                .direction(Direction::In)
                .from(Address::Net(net))
                .proto(Protocol::Tcp)
                .to_port(80)
                .comment(format!("preset:cf:http:{idx}"))
                .build()
                .expect("preset rule should validate"),
        );
        rules.push(
            RuleSpec::builder(Action::Allow)
                .direction(Direction::In)
                .from(Address::Net(
                    range.parse::<ipnet::IpNet>().expect("valid CIDR"),
                ))
                .proto(Protocol::Tcp)
                .to_port(443)
                .comment(format!("preset:cf:https:{idx}"))
                .build()
                .expect("preset rule should validate"),
        );
    }

    Preset {
        id: "cloudflare-allowlist",
        name: "Cloudflare Allowlist",
        description: "Allow SSH with rate limiting and HTTP/HTTPS only from Cloudflare IP ranges. \
            Designed for origin servers behind Cloudflare proxy."
            .into(),
        rules,
    }
}

/// Traefik/Dokploy preset: allow SSH + HTTP + HTTPS with internal app ports.
///
/// Designed for servers running Traefik as reverse proxy (e.g., Dokploy).
/// Only exposes SSH (rate-limited), HTTP (80), and HTTPS (443) publicly.
/// Application containers should be bound to Docker internal networks or
/// localhost — this preset does NOT open application ports.
pub fn traefik_dokploy() -> Preset {
    Preset {
        id: "traefik-dokploy",
        name: "Traefik / Dokploy",
        description: "Allow SSH with rate limiting, HTTP, and HTTPS for Traefik/Dokploy \
            reverse proxy setups. App containers should bind to internal Docker networks."
            .into(),
        rules: vec![
            RuleSpec::builder(Action::Limit)
                .direction(Direction::In)
                .proto(Protocol::Tcp)
                .to_port(22)
                .comment("preset:td:ssh")
                .build()
                .expect("preset rule should validate"),
            RuleSpec::builder(Action::Allow)
                .direction(Direction::In)
                .proto(Protocol::Tcp)
                .to_port(80)
                .comment("preset:td:http")
                .build()
                .expect("preset rule should validate"),
            RuleSpec::builder(Action::Allow)
                .direction(Direction::In)
                .proto(Protocol::Tcp)
                .to_port(443)
                .comment("preset:td:https")
                .build()
                .expect("preset rule should validate"),
        ],
    }
}

/// Monitoring private preset: allow SSH + monitoring ports from trusted CIDR only.
///
/// Prometheus (9090), Grafana (3000), and Node Exporter (9100) are restricted
/// to a trusted CIDR. SSH is rate-limited from anywhere.
pub fn monitoring_private(trusted_cidr: &str) -> Preset {
    let net = trusted_cidr
        .parse::<ipnet::IpNet>()
        .expect("invalid trusted CIDR");

    Preset {
        id: "monitoring-private",
        name: "Monitoring Server (Private)",
        description: format!(
            "Allow SSH with rate limiting, and Prometheus/Grafana/Node Exporter \
             only from trusted CIDR {trusted_cidr}."
        ),
        rules: vec![
            RuleSpec::builder(Action::Limit)
                .direction(Direction::In)
                .proto(Protocol::Tcp)
                .to_port(22)
                .comment("preset:mon-pvt:ssh")
                .build()
                .expect("preset rule should validate"),
            RuleSpec::builder(Action::Allow)
                .direction(Direction::In)
                .from(Address::Net(net))
                .proto(Protocol::Tcp)
                .to_port(3000)
                .comment("preset:mon-pvt:grafana")
                .build()
                .expect("preset rule should validate"),
            RuleSpec::builder(Action::Allow)
                .direction(Direction::In)
                .from(Address::Net(net))
                .proto(Protocol::Tcp)
                .to_port(9090)
                .comment("preset:mon-pvt:prometheus")
                .build()
                .expect("preset rule should validate"),
            RuleSpec::builder(Action::Allow)
                .direction(Direction::In)
                .from(Address::Net(net))
                .proto(Protocol::Tcp)
                .to_port(9100)
                .comment("preset:mon-pvt:node-exporter")
                .build()
                .expect("preset rule should validate"),
        ],
    }
}

/// List all available presets with their default parameters.
pub fn all_default_presets() -> Vec<Preset> {
    vec![
        ssh(),
        web_public(),
        reverse_proxy(),
        tailscale(),
        wireguard(),
        database(5432), // PostgreSQL default
        monitoring(),
        tailscale_interface(),
        wireguard_interface(),
        cloudflare_allowlist(),
        traefik_dokploy(),
        monitoring_private("10.0.0.0/8"),
    ]
}

#[cfg(test)]
#[path = "presets.test.rs"]
mod tests;
