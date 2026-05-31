//! Preset firewall rule templates.
//!
//! Provides ready-made rule sets for common server configurations.
//! Each preset returns a [`Preset`] containing a list of [`RuleSpec`](crate::spec::RuleSpec)
//! values that can be applied via the client.

use crate::spec::{Action, Direction, Protocol, RuleSpec};

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
    ]
}

#[cfg(test)]
#[path = "presets.test.rs"]
mod tests;
