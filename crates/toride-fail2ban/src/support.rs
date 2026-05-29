//! Platform detection for firewalls, init systems, and OS capabilities.

use serde::{Deserialize, Serialize};

use crate::types::PlatformCommands;

/// Detected firewall type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Firewall {
    /// Linux iptables.
    Iptables,
    /// Linux nftables.
    Nftables,
    /// macOS/BSD packet filter.
    Pf,
    /// firewalld (CentOS/Fedora/RHEL).
    Firewalld,
    /// Windows Firewall (placeholder).
    WindowsFirewall,
    /// Unknown or unsupported firewall.
    Unknown,
}

/// Detected init system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InitSystem {
    /// systemd.
    Systemd,
    /// OpenRC.
    OpenRC,
    /// macOS launchd.
    Launchd,
    /// FreeBSD rc.d.
    Rc,
    /// Unknown init system.
    Unknown,
}

/// Full platform detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformInfo {
    /// Detected operating system.
    pub os: String,
    /// OS version.
    pub version: String,
    /// Architecture.
    pub arch: String,
    /// Detected firewall.
    pub firewall: Firewall,
    /// Detected init system.
    pub init_system: InitSystem,
}

/// Detect the active firewall on this system.
pub fn detect_firewall() -> Firewall {
    if cfg!(target_os = "linux") {
        // Check for nftables first, then iptables, then firewalld.
        if which_exists("nft") {
            return Firewall::Nftables;
        }
        if which_exists("iptables") {
            return Firewall::Iptables;
        }
        if which_exists("firewall-cmd") {
            return Firewall::Firewalld;
        }
    } else if cfg!(target_os = "macos") || cfg!(target_os = "freebsd") {
        if which_exists("pfctl") {
            return Firewall::Pf;
        }
    }
    Firewall::Unknown
}

/// Detect the init system on this system.
pub fn detect_init() -> InitSystem {
    if cfg!(target_os = "macos") {
        if which_exists("launchctl") {
            return InitSystem::Launchd;
        }
    } else if cfg!(target_os = "freebsd") {
        return InitSystem::Rc;
    } else if cfg!(target_os = "linux") {
        if which_exists("systemctl") {
            return InitSystem::Systemd;
        }
        if which_exists("rc-service") {
            return InitSystem::OpenRC;
        }
    }
    InitSystem::Unknown
}

/// Full platform detection.
pub fn detect_platform() -> PlatformInfo {
    PlatformInfo {
        os: std::env::consts::OS.to_string(),
        version: "unknown".to_string(),
        arch: std::env::consts::ARCH.to_string(),
        firewall: detect_firewall(),
        init_system: detect_init(),
    }
}

/// Get the default ban commands for the detected firewall.
pub fn default_ban_commands(firewall: Firewall) -> PlatformCommands {
    match firewall {
        Firewall::Iptables => PlatformCommands::new(
            vec!["iptables -I INPUT -s <ip> -j DROP".to_string()],
            vec![],
            vec![],
        ),
        Firewall::Nftables => PlatformCommands::new(
            vec!["nft add rule ip filter INPUT ip saddr <ip> drop".to_string()],
            vec![],
            vec![],
        ),
        Firewall::Pf => PlatformCommands::new(
            vec![],
            vec!["echo 'block in from <ip>' | pfctl -f -".to_string()],
            vec!["echo 'block in from <ip>' | pfctl -f -".to_string()],
        ),
        Firewall::Firewalld => PlatformCommands::new(
            vec!["firewall-cmd --add-source=<ip>".to_string()],
            vec![],
            vec![],
        ),
        Firewall::WindowsFirewall => PlatformCommands::new(
            vec!["netsh advfirewall firewall add rule name=\"toride-f2b\" dir=in action=block remoteip=<ip>".to_string()],
            vec![],
            vec![],
        ),
        Firewall::Unknown => PlatformCommands::new(vec![], vec![], vec![]),
    }
}

/// Get the default unban commands for the detected firewall.
pub fn default_unban_commands(firewall: Firewall) -> PlatformCommands {
    match firewall {
        Firewall::Iptables => PlatformCommands::new(
            vec!["iptables -D INPUT -s <ip> -j DROP".to_string()],
            vec![],
            vec![],
        ),
        Firewall::Nftables => PlatformCommands::new(
            vec!["nft delete rule ip filter INPUT handle <ip>".to_string()],
            vec![],
            vec![],
        ),
        Firewall::Pf => PlatformCommands::new(
            vec![],
            vec!["echo '' | pfctl -f -".to_string()],
            vec!["echo '' | pfctl -f -".to_string()],
        ),
        Firewall::Firewalld => PlatformCommands::new(
            vec!["firewall-cmd --remove-source=<ip>".to_string()],
            vec![],
            vec![],
        ),
        Firewall::WindowsFirewall => PlatformCommands::new(
            vec!["netsh advfirewall firewall delete rule name=\"toride-f2b\" remoteip=<ip>".to_string()],
            vec![],
            vec![],
        ),
        Firewall::Unknown => PlatformCommands::new(vec![], vec![], vec![]),
    }
}

/// Get iptables commands for banning/unbanning.
pub fn iptables_commands(action: &str, ip: &str) -> Vec<String> {
    match action {
        "ban" => vec![format!("iptables -I INPUT -s {ip} -j DROP")],
        "unban" => vec![format!("iptables -D INPUT -s {ip} -j DROP")],
        _ => vec![],
    }
}

/// Get pf commands for banning/unbanning.
pub fn pf_commands(action: &str, ip: &str) -> Vec<String> {
    match action {
        "ban" => vec![format!("echo 'block in from {ip}' | pfctl -f -")],
        "unban" => vec![format!("echo 'block in from {ip}' | pfctl -f -")],
        _ => vec![],
    }
}

fn which_exists(name: &str) -> bool {
    which::which(name).is_ok()
}

#[cfg(test)]
#[path = "support.test.rs"]
mod tests;
