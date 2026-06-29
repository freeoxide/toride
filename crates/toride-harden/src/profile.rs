//! CIS/STIG hardening profiles for kernel security parameters.
//!
//! Provides predefined profiles for Desktop, Server, and Router use cases,
//! each with a curated set of sysctl parameters based on CIS benchmarks
//! and DISA STIG guidance.

use crate::spec::SysctlParam;

/// A hardening profile with pre-defined kernel parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum HardeningProfile {
    /// Desktop workstation profile — balanced security and usability.
    Desktop,
    /// Server profile — stricter security, suitable for production servers.
    Server,
    /// Router profile — enables IP forwarding with hardening.
    Router,
}

impl HardeningProfile {
    /// Return the sysctl parameters for this profile.
    pub fn params(&self) -> Vec<SysctlParam> {
        match self {
            Self::Desktop => desktop_params(),
            Self::Server => server_params(),
            Self::Router => router_params(),
        }
    }

    /// Return the profile name as a static string.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Desktop => "desktop",
            Self::Server => "server",
            Self::Router => "router",
        }
    }

    /// Parse a profile name string.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "desktop" => Some(Self::Desktop),
            "server" => Some(Self::Server),
            "router" => Some(Self::Router),
            _ => None,
        }
    }

    /// List all available profile names.
    pub fn all_names() -> &'static [&'static str] {
        &["desktop", "server", "router"]
    }
}

impl std::fmt::Display for HardeningProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Desktop profile parameters — balanced for daily workstation use.
///
/// - ASLR enabled (level 2)
/// - `kptr_restrict` enabled
/// - `dmesg_restrict` enabled
/// - Protected hardlinks/symlinks/fifos/regular files
/// - ICMP redirects disabled
/// - Source routing disabled
fn desktop_params() -> Vec<SysctlParam> {
    vec![
        // ── Kernel security ──────────────────────────────────────
        SysctlParam::new(
            "kernel.randomize_va_space",
            "2",
            "Enable full ASLR (randomize mmap, stack, VDSO, heap)",
        ),
        SysctlParam::new(
            "kernel.kptr_restrict",
            "1",
            "Restrict kernel pointer exposure to unprivileged users",
        ),
        SysctlParam::new(
            "kernel.dmesg_restrict",
            "1",
            "Restrict dmesg output to privileged users",
        ),
        SysctlParam::new(
            "kernel.yama.ptrace_scope",
            "1",
            "Restrict ptrace to direct parent processes",
        ),
        // ── Filesystem protections ───────────────────────────────
        SysctlParam::new(
            "fs.protected_hardlinks",
            "1",
            "Enable protected hardlinks (CIS 1.1.1)",
        ),
        SysctlParam::new(
            "fs.protected_symlinks",
            "1",
            "Enable protected symlinks (CIS 1.1.2)",
        ),
        SysctlParam::new(
            "fs.protected_fifos",
            "2",
            "Enable protected fifos (strict mode)",
        ),
        SysctlParam::new(
            "fs.protected_regular",
            "2",
            "Enable protected regular files (strict mode)",
        ),
        // ── Network hardening ────────────────────────────────────
        SysctlParam::new(
            "net.ipv4.conf.all.accept_redirects",
            "0",
            "Disable ICMP redirect acceptance",
        ),
        SysctlParam::new(
            "net.ipv4.conf.default.accept_redirects",
            "0",
            "Disable ICMP redirect acceptance (default)",
        ),
        SysctlParam::new(
            "net.ipv4.conf.all.accept_source_route",
            "0",
            "Disable source routed packets",
        ),
        SysctlParam::new(
            "net.ipv4.conf.default.accept_source_route",
            "0",
            "Disable source routed packets (default)",
        ),
        SysctlParam::new(
            "net.ipv4.conf.all.send_redirects",
            "0",
            "Disable ICMP redirect sending",
        ),
        SysctlParam::new(
            "net.ipv4.conf.default.send_redirects",
            "0",
            "Disable ICMP redirect sending (default)",
        ),
        SysctlParam::new(
            "net.ipv6.conf.all.accept_redirects",
            "0",
            "Disable IPv6 ICMP redirect acceptance",
        ),
        // ── IP forwarding disabled (desktop) ─────────────────────
        SysctlParam::new(
            "net.ipv4.ip_forward",
            "0",
            "Disable IP forwarding (not a router)",
        ),
    ]
}

/// Server profile parameters — stricter security for production servers.
///
/// Includes all Desktop parameters plus additional server-specific hardening.
fn server_params() -> Vec<SysctlParam> {
    let mut params = desktop_params();

    // Override the desktop ptrace_scope (1) with the stricter server value (2).
    // Drop the inherited entry first so we don't emit a duplicate key: the
    // direct-apply path iterates and writes every entry (so `sysctl -w
    // kernel.yama.ptrace_scope=1` then `=2` would run), and the c62c8d5
    // dedup_by_key_last_wins only covers the spec-expansion path, not this
    // list. Mirror the `ip_forward` retain used in `router_params`.
    params.retain(|p| p.key != "kernel.yama.ptrace_scope");
    params.push(SysctlParam::new(
        "kernel.yama.ptrace_scope",
        "2",
        "Restrict ptrace to CAP_SYS_PTRACE (server: stricter than desktop)",
    ));
    params.push(SysctlParam::new(
        "net.ipv4.tcp_syncookies",
        "1",
        "Enable TCP SYN cookies (SYN flood protection)",
    ));
    params.push(SysctlParam::new(
        "net.ipv4.conf.all.log_martians",
        "1",
        "Log packets with impossible addresses",
    ));
    params.push(SysctlParam::new(
        "net.ipv4.conf.default.log_martians",
        "1",
        "Log packets with impossible addresses (default)",
    ));
    params.push(SysctlParam::new(
        "net.ipv4.icmp_echo_ignore_broadcasts",
        "1",
        "Ignore ICMP broadcast echo requests (Smurf attack prevention)",
    ));
    params.push(SysctlParam::new(
        "net.ipv4.icmp_ignore_bogus_error_responses",
        "1",
        "Ignore bogus ICMP error responses",
    ));
    params.push(SysctlParam::new(
        "net.ipv4.tcp_rfc1337",
        "1",
        "Enable TCP RFC 1337 TIME_WAIT protection",
    ));
    params.push(SysctlParam::new(
        "net.ipv4.conf.all.rp_filter",
        "1",
        "Enable reverse path filtering (source validation)",
    ));
    params.push(SysctlParam::new(
        "net.ipv4.conf.default.rp_filter",
        "1",
        "Enable reverse path filtering (default)",
    ));

    params
}

/// Router profile parameters — enables IP forwarding with hardening.
///
/// Includes all Server parameters but enables IP forwarding and adjusts
/// related parameters for routing use cases.
fn router_params() -> Vec<SysctlParam> {
    let mut params = server_params();

    // Remove the ip_forward=0 entry and replace with ip_forward=1
    params.retain(|p| p.key != "net.ipv4.ip_forward");
    params.push(SysctlParam::new(
        "net.ipv4.ip_forward",
        "1",
        "Enable IP forwarding (router mode)",
    ));
    params.push(SysctlParam::new(
        "net.ipv6.conf.all.forwarding",
        "1",
        "Enable IPv6 forwarding (router mode)",
    ));

    params
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_profiles_produce_params() {
        for profile in &[
            HardeningProfile::Desktop,
            HardeningProfile::Server,
            HardeningProfile::Router,
        ] {
            let params = profile.params();
            assert!(
                !params.is_empty(),
                "{} profile should have parameters",
                profile.name()
            );
        }
    }

    /// Regression for the c62c8d5 duplicate-key fix and its sibling on the
    /// direct-apply path: every profile's param list MUST have unique keys, or
    /// `apply_profile` writes the same sysctl twice (e.g. the old Server list
    /// emitted `kernel.yama.ptrace_scope=1` then `=2`).
    #[test]
    fn profiles_have_no_duplicate_keys() {
        for profile in &[
            HardeningProfile::Desktop,
            HardeningProfile::Server,
            HardeningProfile::Router,
        ] {
            let params = profile.params();
            let mut keys: Vec<String> = params.iter().map(|p| p.key.clone()).collect();
            let total = keys.len();
            keys.sort();
            keys.dedup();
            assert_eq!(
                keys.len(),
                total,
                "{} profile has duplicate sysctl keys",
                profile.name()
            );
        }
    }

    #[test]
    fn server_is_stricter_than_desktop() {
        let desktop = HardeningProfile::Desktop.params();
        let server = HardeningProfile::Server.params();
        assert!(server.len() > desktop.len());
    }

    #[test]
    fn router_enables_forwarding() {
        let params = HardeningProfile::Router.params();
        let fwd = params.iter().find(|p| p.key == "net.ipv4.ip_forward");
        assert!(fwd.is_some());
        assert_eq!(fwd.unwrap().value, "1");
    }

    #[test]
    fn desktop_disables_forwarding() {
        let params = HardeningProfile::Desktop.params();
        let fwd = params.iter().find(|p| p.key == "net.ipv4.ip_forward");
        assert!(fwd.is_some());
        assert_eq!(fwd.unwrap().value, "0");
    }

    #[test]
    fn from_name_roundtrip() {
        assert_eq!(
            HardeningProfile::from_name("desktop"),
            Some(HardeningProfile::Desktop)
        );
        assert_eq!(
            HardeningProfile::from_name("SERVER"),
            Some(HardeningProfile::Server)
        );
        assert_eq!(HardeningProfile::from_name("unknown"), None);
    }

    #[test]
    fn display_matches_name() {
        assert_eq!(HardeningProfile::Desktop.to_string(), "desktop");
        assert_eq!(HardeningProfile::Server.to_string(), "server");
        assert_eq!(HardeningProfile::Router.to_string(), "router");
    }
}
