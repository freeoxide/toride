//! Platform detection for firewalls, init systems, and OS capabilities.

use serde::{Deserialize, Serialize};

use crate::types::PlatformCommands;

/// Detected firewall type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

impl std::fmt::Display for Firewall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Iptables => write!(f, "iptables"),
            Self::Nftables => write!(f, "nftables"),
            Self::Pf => write!(f, "pf"),
            Self::Firewalld => write!(f, "firewalld"),
            Self::WindowsFirewall => write!(f, "windows-firewall"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

impl std::fmt::Display for InitSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Systemd => write!(f, "systemd"),
            Self::OpenRC => write!(f, "openrc"),
            Self::Launchd => write!(f, "launchd"),
            Self::Rc => write!(f, "rc"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Full platform detection result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformInfo {
    /// Detected operating system.
    pub os: String,
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
    } else if (cfg!(target_os = "macos") || cfg!(target_os = "freebsd")) && which_exists("pfctl") {
        return Firewall::Pf;
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
        arch: std::env::consts::ARCH.to_string(),
        firewall: detect_firewall(),
        init_system: detect_init(),
    }
}

/// Get the default ban commands for the detected firewall.
///
/// The Linux templates are self-expiring where the firewall supports it:
/// nft elements carry `timeout <ban-time>s`, and iptables rules carry a
/// `toride-f2b-<jail>` comment tag so the matching unban template can delete
/// every copy of the rule by tag.
pub fn default_ban_commands(firewall: Firewall) -> PlatformCommands {
    match firewall {
        Firewall::Iptables => PlatformCommands::new(
            vec!["if echo '<ip>' | grep -q ':'; then ip6tables -I INPUT -s <ip> -m comment --comment toride-f2b-<jail> -j DROP; else iptables -I INPUT -s <ip> -m comment --comment toride-f2b-<jail> -j DROP; fi".to_string()],
            vec![],
            vec![],
        ),
        Firewall::Nftables => PlatformCommands::new(
            vec![
                "if echo '<ip>' | grep -q ':'; then nft add set ip6 filter toride_banned \\{ type ipv6_addr \\; flags timeout \\; \\} 2>/dev/null; nft add element ip6 filter toride_banned \\{ <ip> timeout <ban-time>s \\}; else nft add set ip filter toride_banned \\{ type ipv4_addr \\; flags timeout \\; \\} 2>/dev/null; nft add element ip filter toride_banned \\{ <ip> timeout <ban-time>s \\}; fi".to_string(),
            ],
            vec![],
            vec![],
        ),
        Firewall::Pf => PlatformCommands::new(
            vec![],
            vec!["pfctl -t toride -T add <ip>".to_string()],
            vec!["pfctl -t toride -T add <ip>".to_string()],
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
///
/// The iptables template deletes every copy of the tagged rule (a re-ban
/// after a partial unban can leave duplicates that a single `-D` miss).
/// The nft delete is best-effort because the element may already have
/// self-expired through its `timeout`.
pub fn default_unban_commands(firewall: Firewall) -> PlatformCommands {
    match firewall {
        Firewall::Iptables => PlatformCommands::new(
            vec!["if echo '<ip>' | grep -q ':'; then while ip6tables -C INPUT -s <ip> -m comment --comment toride-f2b-<jail> -j DROP 2>/dev/null; do ip6tables -D INPUT -s <ip> -m comment --comment toride-f2b-<jail> -j DROP; done; else while iptables -C INPUT -s <ip> -m comment --comment toride-f2b-<jail> -j DROP 2>/dev/null; do iptables -D INPUT -s <ip> -m comment --comment toride-f2b-<jail> -j DROP; done; fi".to_string()],
            vec![],
            vec![],
        ),
        Firewall::Nftables => PlatformCommands::new(
            vec!["if echo '<ip>' | grep -q ':'; then nft delete element ip6 filter toride_banned \\{ <ip> \\} 2>/dev/null || true; else nft delete element ip filter toride_banned \\{ <ip> \\} 2>/dev/null || true; fi".to_string()],
            vec![],
            vec![],
        ),
        Firewall::Pf => PlatformCommands::new(
            vec![],
            vec!["pfctl -t toride -T delete <ip>".to_string()],
            vec!["pfctl -t toride -T delete <ip>".to_string()],
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

fn which_exists(name: &str) -> bool {
    which::which(name).is_ok()
}

#[cfg(test)]
#[path = "support.test.rs"]
mod tests;
