//! Docker-aware firewall checks.
//!
//! Detects Docker installations, firewall backend configuration, published
//! container ports, and common reverse proxy setups (Traefik, Dokploy).
//! All findings are informational or warnings — this module never mutates state.

use crate::command::CommandRunner;
use crate::spec::{Finding, Severity};
use std::time::Duration;

/// Check if Docker is installed on the system.
pub fn is_docker_installed<R: CommandRunner + ?Sized>(runner: &R) -> bool {
    runner.binary_exists("docker")
}

/// Check if Traefik is likely installed.
pub fn is_traefik_installed<R: CommandRunner + ?Sized>(runner: &R) -> bool {
    runner.binary_exists("traefik") || runner.binary_exists("traefik-client")
}

/// Check if Dokploy is likely installed by looking for its common paths.
pub fn is_dokploy_installed() -> bool {
    std::path::Path::new("/etc/dokploy").exists()
        || std::path::Path::new("/opt/dokploy").exists()
        || std::path::Path::new("/root/.dokploy").exists()
}

/// Docker firewall backend type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DockerFirewallBackend {
    /// Docker manages iptables rules directly.
    Iptables,
    /// Docker uses nftables backend.
    Nftables,
    /// Docker firewall management is disabled.
    None,
    /// Could not determine the backend.
    Unknown,
}

/// Information about a published Docker port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedPort {
    /// Container port.
    pub container_port: u16,
    /// Host IP address (e.g., "0.0.0.0", "::", "127.0.0.1").
    pub host_ip: String,
    /// Host port.
    pub host_port: u16,
    /// Protocol (tcp/udp).
    pub protocol: String,
}

/// Docker inspection result.
#[derive(Debug, Clone)]
pub struct DockerInspection {
    /// Whether Docker is installed.
    pub installed: bool,
    /// Detected firewall backend.
    pub firewall_backend: DockerFirewallBackend,
    /// Whether iptables management is enabled in Docker daemon config.
    pub iptables_enabled: Option<bool>,
    /// Published ports from running containers.
    pub published_ports: Vec<PublishedPort>,
    /// Whether Traefik appears to be running.
    pub traefik_detected: bool,
    /// Whether Dokploy appears to be installed.
    pub dokploy_detected: bool,
}

/// Inspect Docker configuration and running containers.
pub fn inspect_docker<R: CommandRunner + ?Sized>(runner: &R) -> DockerInspection {
    let installed = is_docker_installed(runner);

    if !installed {
        return DockerInspection {
            installed: false,
            firewall_backend: DockerFirewallBackend::Unknown,
            iptables_enabled: None,
            published_ports: Vec::new(),
            traefik_detected: false,
            dokploy_detected: false,
        };
    }

    let firewall_backend = detect_docker_firewall_backend(runner);
    let iptables_enabled = detect_iptables_management(runner);
    let published_ports = detect_published_ports(runner);
    let traefik_detected = is_traefik_installed(runner);
    let dokploy_detected = is_dokploy_installed();

    DockerInspection {
        installed,
        firewall_backend,
        iptables_enabled,
        published_ports,
        traefik_detected,
        dokploy_detected,
    }
}

/// Detect Docker's firewall backend by reading daemon.json.
fn detect_docker_firewall_backend<R: CommandRunner + ?Sized>(runner: &R) -> DockerFirewallBackend {
    // Check daemon.json for firewall-backend setting
    let daemon_json_paths = ["/etc/docker/daemon.json", "/etc/docker/daemon.jsonc"];

    for path in &daemon_json_paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            let lower = content.to_ascii_lowercase();
            if lower.contains("\"firewall-backend\"") {
                if lower.contains("\"nftables\"") {
                    return DockerFirewallBackend::Nftables;
                }
                if lower.contains("\"iptables\"") {
                    return DockerFirewallBackend::Iptables;
                }
                if lower.contains("\"none\"") {
                    return DockerFirewallBackend::None;
                }
            }
        }
    }

    // Fallback: if iptables binary exists, Docker likely uses iptables
    if runner.binary_exists("iptables") {
        DockerFirewallBackend::Iptables
    } else if runner.binary_exists("nft") {
        DockerFirewallBackend::Nftables
    } else {
        DockerFirewallBackend::Unknown
    }
}

/// Detect whether Docker iptables management is enabled.
fn detect_iptables_management<R: CommandRunner + ?Sized>(runner: &R) -> Option<bool> {
    // Check daemon.json for "iptables": false
    let daemon_json_paths = ["/etc/docker/daemon.json"];

    for path in &daemon_json_paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            let lower = content.to_ascii_lowercase();
            if lower.contains("\"iptables\"") {
                if lower.contains("\"iptables\": false") || lower.contains("\"iptables\":false") {
                    return Some(false);
                }
                if lower.contains("\"iptables\": true") || lower.contains("\"iptables\":true") {
                    return Some(true);
                }
            }
        }
    }

    // Default: Docker enables iptables management unless explicitly disabled
    if runner.binary_exists("docker") {
        Some(true)
    } else {
        None
    }
}

/// Detect published ports from running Docker containers.
fn detect_published_ports<R: CommandRunner + ?Sized>(runner: &R) -> Vec<PublishedPort> {
    let spec = crate::spec::CommandSpec {
        program: "docker".into(),
        args: vec!["ps".into(), "--format".into(), "{{.Ports}}".into()],
        timeout: Some(Duration::from_secs(10)),
        requires_root: false,
        force_c_locale: true,
        redact_logs: false,
    };

    let output = match runner.run(&spec) {
        Ok(result) if result.exit_code == Some(0) => result.stdout,
        _ => return Vec::new(),
    };

    parse_docker_port_output(&output)
}

/// Parse Docker port output from `docker ps --format {{.Ports}}`.
fn parse_docker_port_output(output: &str) -> Vec<PublishedPort> {
    let mut ports = Vec::new();

    for line in output.lines() {
        // Docker format: "0.0.0.0:8080->80/tcp, :::9090->9090/tcp"
        // or single: "0.0.0.0:5432->5432/tcp"
        for port_mapping in line.split(", ") {
            if let Some(parsed) = parse_single_port_mapping(port_mapping.trim()) {
                ports.push(parsed);
            }
        }
    }

    ports
}

/// Parse a single port mapping like `"0.0.0.0:8080->80/tcp"` or `":::9090->9090/tcp"`.
#[allow(clippy::similar_names)]
fn parse_single_port_mapping(mapping: &str) -> Option<PublishedPort> {
    // Split on "->" to get host and container sides
    let parts: Vec<&str> = mapping.split("->").collect();
    if parts.len() != 2 {
        return None;
    }

    let host_side = parts[0].trim();
    let container_side = parts[1].trim();

    // Container side: "80/tcp" or "53/udp"
    let csplit: Vec<&str> = container_side.split('/').collect();
    if csplit.len() != 2 {
        return None;
    }
    let c_port = csplit[0].parse::<u16>().ok()?;
    let proto = csplit[1].to_string();

    // Host side: "0.0.0.0:8080" or "[::]:9090" or ":::9090" or "127.0.0.1:3000"
    let (hip, hport) = parse_host_binding(host_side)?;

    Some(PublishedPort {
        container_port: c_port,
        host_ip: hip,
        host_port: hport,
        protocol: proto,
    })
}

/// Parse host binding like `"0.0.0.0:8080"`, `"[::]:9090"`, `":::9090"`.
fn parse_host_binding(binding: &str) -> Option<(String, u16)> {
    // Handle ":::PORT" (IPv6 all-interfaces shorthand)
    if let Some(rest) = binding.strip_prefix(":::") {
        let port = rest.parse::<u16>().ok()?;
        return Some(("[::]".into(), port));
    }

    // Handle "[::]:PORT"
    if binding.starts_with('[') {
        if let Some(bracket_end) = binding.find(']') {
            let ip = &binding[1..bracket_end];
            let after = &binding[bracket_end + 1..];
            if let Some(port_str) = after.strip_prefix(':') {
                let port = port_str.parse::<u16>().ok()?;
                return Some((ip.to_string(), port));
            }
        }
        return None;
    }

    // Handle "IP:PORT"
    let colon_pos = binding.rfind(':')?;
    let ip = &binding[..colon_pos];
    let port_str = &binding[colon_pos + 1..];
    let port = port_str.parse::<u16>().ok()?;
    Some((ip.to_string(), port))
}

/// Check for Docker-related findings and return them.
///
/// This is the main entry point for the doctor module to call.
#[allow(clippy::too_many_lines)]
pub fn check_docker<R: CommandRunner + ?Sized>(runner: &R) -> Vec<Finding> {
    let mut findings = Vec::new();
    let info = inspect_docker(runner);

    if !info.installed {
        // Docker not installed — nothing to check
        return findings;
    }

    findings.push(Finding {
        id: "docker:installed",
        severity: Severity::Info,
        title: "Docker is installed on this system".into(),
        detail: "Docker is detected. Docker may bypass UFW rules when publishing ports. \
                 Review Docker firewall configuration carefully."
            .into(),
        fix: None,
    });

    // Check firewall backend
    match info.firewall_backend {
        DockerFirewallBackend::Iptables => {
            findings.push(Finding {
                id: "docker:backend:iptables",
                severity: Severity::Warning,
                title: "Docker uses iptables backend".into(),
                detail: "Docker is managing iptables rules directly. Published container ports \
                         may bypass UFW rules because Docker inserts its own iptables chains \
                         (DOCKER-USER, DOCKER, etc.) before UFW's rules."
                    .into(),
                fix: Some(
                    "Consider using Docker's --iptables=false with manual UFW rules, \
                     or use the DOCKER-USER chain for custom firewall rules."
                        .into(),
                ),
            });
        }
        DockerFirewallBackend::Nftables => {
            findings.push(Finding {
                id: "docker:backend:nftables",
                severity: Severity::Info,
                title: "Docker uses nftables backend".into(),
                detail: "Docker is configured to use the nftables backend. This is the newer \
                         approach and may interact differently with UFW."
                    .into(),
                fix: None,
            });
        }
        DockerFirewallBackend::None => {
            findings.push(Finding {
                id: "docker:backend:disabled",
                severity: Severity::Warning,
                title: "Docker firewall management is disabled".into(),
                detail: "Docker's iptables management is disabled. Bridge networking may not \
                         function correctly unless replacement rules are in place."
                    .into(),
                fix: Some(
                    "Ensure UFW or manual iptables rules cover Docker's bridge networking needs."
                        .into(),
                ),
            });
        }
        DockerFirewallBackend::Unknown => {
            findings.push(Finding {
                id: "docker:backend:unknown",
                severity: Severity::Info,
                title: "Could not determine Docker firewall backend".into(),
                detail: "The Docker firewall backend could not be determined. \
                         Docker is likely using the default iptables backend."
                    .into(),
                fix: None,
            });
        }
    }

    // Check published ports
    let public_ports: Vec<_> = info
        .published_ports
        .iter()
        .filter(|p| p.host_ip == "0.0.0.0" || p.host_ip == "[::]" || p.host_ip == "::")
        .collect();

    if !public_ports.is_empty() {
        let port_list: String = public_ports
            .iter()
            .map(|p| {
                format!(
                    "{}:{}->{} ({} on {})",
                    p.host_ip, p.host_port, p.container_port, p.protocol, p.host_ip
                )
            })
            .collect::<Vec<_>>()
            .join(", ");

        findings.push(Finding {
            id: "docker:ports:public",
            severity: Severity::Warning,
            title: format!("{} Docker port(s) published publicly", public_ports.len()),
            detail: format!(
                "Docker containers are publishing ports to all interfaces. \
                 These ports may bypass UFW rules: {port_list}"
            ),
            fix: Some(
                "Bind containers to 127.0.0.1 when behind a reverse proxy: \
                 docker run -p 127.0.0.1:3000:3000 ..."
                    .into(),
            ),
        });
    }

    // Check for Traefik
    if info.traefik_detected {
        findings.push(Finding {
            id: "docker:traefik:detected",
            severity: Severity::Info,
            title: "Traefik reverse proxy detected".into(),
            detail: "Traefik appears to be installed. Ensure only ports 80/443 are \
                     exposed publicly and app containers bind to internal Docker networks."
                .into(),
            fix: Some(
                "Use Traefik's Docker provider with internal networks. \
                 Bind app containers to 127.0.0.1 or internal Docker networks only."
                    .into(),
            ),
        });
    }

    // Check for Dokploy
    if info.dokploy_detected {
        findings.push(Finding {
            id: "docker:dokploy:detected",
            severity: Severity::Warning,
            title: "Dokploy installation detected".into(),
            detail: "Dokploy manages Docker deployments with Traefik. Published ports from \
                     Dokploy-managed containers may bypass UFW rules."
                .into(),
            fix: Some(
                "Bind apps to internal Docker networks. Expose only Traefik on 80/443. \
                 Bind admin dashboards to localhost or Tailscale. \
                 Use provider firewall where possible."
                    .into(),
            ),
        });
    }

    // Docker daemon port warning
    if let Some(true) = info.iptables_enabled {
        findings.push(Finding {
            id: "docker:iptables:enabled",
            severity: Severity::Warning,
            title: "Docker iptables management is enabled".into(),
            detail: "Docker is managing iptables rules. UFW rules may not protect published \
                     Docker ports as expected. Docker adds its own DOCKER chain that takes \
                     priority over UFW's rules in the FORWARD chain."
                .into(),
            fix: Some(
                "Use the DOCKER-USER chain for custom rules, or set --iptables=false in \
                 /etc/docker/daemon.json and manage Docker networking rules manually."
                    .into(),
            ),
        });
    }

    findings
}

/// Check for reverse proxy issues (NGINX, Traefik, Caddy, Dokploy).
pub fn check_reverse_proxy(runner: &dyn CommandRunner) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut detected_proxies: Vec<&str> = Vec::new();

    if runner.binary_exists("nginx") {
        detected_proxies.push("NGINX");
    }
    if is_traefik_installed(runner) {
        detected_proxies.push("Traefik");
    }
    if runner.binary_exists("caddy") {
        detected_proxies.push("Caddy");
    }
    if is_dokploy_installed() {
        detected_proxies.push("Dokploy");
    }

    if detected_proxies.is_empty() {
        return findings;
    }

    let proxy_list = detected_proxies.join(", ");
    findings.push(Finding {
        id: "proxy:detected",
        severity: Severity::Info,
        title: format!("Reverse proxy(es) detected: {proxy_list}"),
        detail: "Reverse proxy software is installed. Ensure only ports 80/443 are \
                 exposed publicly and application ports are bound to localhost or \
                 internal networks."
            .into(),
        fix: Some(
            "Only expose 80/443 publicly via UFW. Bind application ports to 127.0.0.1 \
             or Docker internal networks behind the reverse proxy."
                .into(),
        ),
    });

    findings
}

/// Check for routing/forwarding issues.
#[allow(clippy::too_many_lines)]
pub fn check_routing(_runner: &dyn CommandRunner) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check sysctl forwarding state
    let sysctl_paths = ["/etc/ufw/sysctl.conf", "/etc/sysctl.conf"];
    let mut ipv4_forwarding = false;
    let mut ipv6_forwarding = false;

    for path in &sysctl_paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            let (v4, v6) = crate::nat::parse_forwarding_state(&content);
            ipv4_forwarding = ipv4_forwarding || v4;
            ipv6_forwarding = ipv6_forwarding || v6;
        }
    }

    // Also check the running kernel state
    if let Ok(content) = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward") {
        let val = content.trim();
        if val == "1" {
            ipv4_forwarding = true;
        }
    }
    if let Ok(content) = std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/forwarding") {
        let val = content.trim();
        if val == "1" {
            ipv6_forwarding = true;
        }
    }

    if ipv4_forwarding {
        findings.push(Finding {
            id: "routing:ipv4:forwarding-on",
            severity: Severity::Info,
            title: "IPv4 forwarding is enabled".into(),
            detail: "IPv4 packet forwarding is enabled. Ensure UFW route rules are \
                     configured correctly and DEFAULT_FORWARD_POLICY is appropriate."
                .into(),
            fix: None,
        });
    }

    if ipv6_forwarding {
        findings.push(Finding {
            id: "routing:ipv6:forwarding-on",
            severity: Severity::Info,
            title: "IPv6 forwarding is enabled".into(),
            detail: "IPv6 packet forwarding is enabled. Ensure UFW route rules are \
                     configured correctly for IPv6."
                .into(),
            fix: None,
        });
    }

    // Check if DEFAULT_FORWARD_POLICY is set when forwarding is enabled
    if ipv4_forwarding {
        if let Ok(content) = std::fs::read_to_string("/etc/default/ufw") {
            let config = crate::config::parse_default_ufw(&content);
            match &config.default_forward_policy {
                Some(policy) => {
                    let lower = policy.to_lowercase();
                    if lower == "accept" {
                        findings.push(Finding {
                            id: "routing:forward-policy:accept",
                            severity: Severity::Warning,
                            title: "DEFAULT_FORWARD_POLICY is ACCEPT with forwarding enabled"
                                .into(),
                            detail: "IPv4 forwarding is enabled and the default forward policy \
                                     is ACCEPT. This may allow unintended forwarded traffic."
                                .into(),
                            fix: Some(
                                "Set DEFAULT_FORWARD_POLICY=\"DROP\" in /etc/default/ufw and \
                                 use explicit route rules for allowed forwarding."
                                    .into(),
                            ),
                        });
                    }
                }
                None => {
                    findings.push(Finding {
                        id: "routing:forward-policy:unset",
                        severity: Severity::Info,
                        title: "DEFAULT_FORWARD_POLICY not set with forwarding enabled".into(),
                        detail: "IPv4 forwarding is enabled but DEFAULT_FORWARD_POLICY is not \
                                 explicitly set in /etc/default/ufw."
                            .into(),
                        fix: Some(
                            "Consider setting DEFAULT_FORWARD_POLICY=\"DROP\" in /etc/default/ufw."
                                .into(),
                        ),
                    });
                }
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_port_mapping_should_handle_common_formats() {
        let mapping = parse_single_port_mapping("0.0.0.0:8080->80/tcp").unwrap();
        assert_eq!(mapping.host_ip, "0.0.0.0");
        assert_eq!(mapping.host_port, 8080);
        assert_eq!(mapping.container_port, 80);
        assert_eq!(mapping.protocol, "tcp");

        let mapping = parse_single_port_mapping("127.0.0.1:3000->3000/tcp").unwrap();
        assert_eq!(mapping.host_ip, "127.0.0.1");
        assert_eq!(mapping.host_port, 3000);

        let mapping = parse_single_port_mapping(":::9090->9090/tcp").unwrap();
        assert_eq!(mapping.host_ip, "[::]");
        assert_eq!(mapping.host_port, 9090);
    }

    #[test]
    fn parse_single_port_mapping_should_return_none_for_invalid() {
        assert!(parse_single_port_mapping("").is_none());
        assert!(parse_single_port_mapping("invalid").is_none());
        assert!(parse_single_port_mapping("abc->def").is_none());
    }

    #[test]
    fn parse_docker_port_output_should_parse_multiple_ports() {
        let output = "0.0.0.0:8080->80/tcp, 0.0.0.0:8443->443/tcp\n0.0.0.0:5432->5432/tcp\n";
        let ports = parse_docker_port_output(output);
        assert_eq!(ports.len(), 3);
        assert_eq!(ports[0].container_port, 80);
        assert_eq!(ports[1].container_port, 443);
        assert_eq!(ports[2].container_port, 5432);
    }

    #[test]
    fn parse_host_binding_should_handle_all_formats() {
        let (ip, port) = parse_host_binding("0.0.0.0:8080").unwrap();
        assert_eq!(ip, "0.0.0.0");
        assert_eq!(port, 8080);

        let (ip, port) = parse_host_binding("[::]:9090").unwrap();
        assert_eq!(ip, "::");
        assert_eq!(port, 9090);

        let (ip, port) = parse_host_binding(":::3000").unwrap();
        assert_eq!(ip, "[::]");
        assert_eq!(port, 3000);

        let (ip, port) = parse_host_binding("127.0.0.1:5432").unwrap();
        assert_eq!(ip, "127.0.0.1");
        assert_eq!(port, 5432);
    }
}
