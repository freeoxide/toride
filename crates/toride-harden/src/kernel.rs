//! Kernel security parameter helpers.
//!
//! Provides constants and convenience functions for the most common
//! kernel hardening parameters: ASLR, `kptr_restrict`, `dmesg_restrict`,
//! protected links, etc.

use crate::error::Result;
use crate::spec::SysctlParam;
use crate::sysctl;
use toride_runner::Runner;

/// Well-known kernel security parameter keys.
pub mod keys {
    /// Address Space Layout Randomization.
    pub const ASLR: &str = "kernel.randomize_va_space";
    /// Restrict kernel pointer exposure.
    pub const KPTR_RESTRICT: &str = "kernel.kptr_restrict";
    /// Restrict dmesg to privileged users.
    pub const DMESG_RESTRICT: &str = "kernel.dmesg_restrict";
    /// Yama ptrace scope.
    pub const PTRACE_SCOPE: &str = "kernel.yama.ptrace_scope";
    /// Protected hardlinks.
    pub const PROTECTED_HARDLINKS: &str = "fs.protected_hardlinks";
    /// Protected symlinks.
    pub const PROTECTED_SYMLINKS: &str = "fs.protected_symlinks";
    /// Protected fifos.
    pub const PROTECTED_FIFOS: &str = "fs.protected_fifos";
    /// Protected regular files.
    pub const PROTECTED_REGULAR: &str = "fs.protected_regular";
    /// IPv4 IP forwarding.
    pub const IP_FORWARD: &str = "net.ipv4.ip_forward";
    /// IPv6 forwarding.
    pub const IPV6_FORWARD: &str = "net.ipv6.conf.all.forwarding";
    /// Accept ICMP redirects (IPv4, all interfaces).
    pub const ACCEPT_REDIRECTS: &str = "net.ipv4.conf.all.accept_redirects";
    /// Send ICMP redirects (IPv4, all interfaces).
    pub const SEND_REDIRECTS: &str = "net.ipv4.conf.all.send_redirects";
    /// Accept source route (IPv4, all interfaces).
    pub const ACCEPT_SOURCE_ROUTE: &str = "net.ipv4.conf.all.accept_source_route";
    /// TCP SYN cookies.
    pub const SYNCOOKIES: &str = "net.ipv4.tcp_syncookies";
    /// Reverse path filtering (all interfaces).
    pub const RP_FILTER: &str = "net.ipv4.conf.all.rp_filter";
    /// Log martians.
    pub const LOG_MARTIANS: &str = "net.ipv4.conf.all.log_martians";
    /// Ignore ICMP echo broadcasts.
    pub const IGNORE_BROADCAST_ECHO: &str = "net.ipv4.icmp_echo_ignore_broadcasts";
}

/// Return a minimal set of kernel security parameters suitable for all profiles.
pub fn baseline_params() -> Vec<SysctlParam> {
    vec![
        SysctlParam::new(keys::ASLR, "2", "Full ASLR"),
        SysctlParam::new(keys::KPTR_RESTRICT, "1", "Restrict kernel pointers"),
        SysctlParam::new(keys::DMESG_RESTRICT, "1", "Restrict dmesg"),
        SysctlParam::new(keys::PROTECTED_HARDLINKS, "1", "Protected hardlinks"),
        SysctlParam::new(keys::PROTECTED_SYMLINKS, "1", "Protected symlinks"),
    ]
}

/// Read the current ASLR setting.
///
/// Returns `0` (off), `1` (conservative), or `2` (full).
pub fn read_aslr(runner: &dyn Runner) -> Result<String> {
    sysctl::read_sysctl(runner, keys::ASLR)
}

/// Check if ASLR is enabled (value is `1` or `2`).
pub fn is_aslr_enabled(runner: &dyn Runner) -> bool {
    matches!(read_aslr(runner).as_deref(), Ok("1" | "2"))
}

/// Read `kptr_restrict` status.
pub fn read_kptr_restrict(runner: &dyn Runner) -> Result<String> {
    sysctl::read_sysctl(runner, keys::KPTR_RESTRICT)
}

/// Check if `kptr_restrict` is enabled.
pub fn is_kptr_restrict_enabled(runner: &dyn Runner) -> bool {
    matches!(read_kptr_restrict(runner).as_deref(), Ok("1"))
}

/// Read `dmesg_restrict` status.
pub fn read_dmesg_restrict(runner: &dyn Runner) -> Result<String> {
    sysctl::read_sysctl(runner, keys::DMESG_RESTRICT)
}

/// Check if `dmesg_restrict` is enabled.
pub fn is_dmesg_restrict_enabled(runner: &dyn Runner) -> bool {
    matches!(read_dmesg_restrict(runner).as_deref(), Ok("1"))
}

/// Read IP forwarding status.
pub fn read_ip_forward(runner: &dyn Runner) -> Result<String> {
    sysctl::read_sysctl(runner, keys::IP_FORWARD)
}

/// Check if IP forwarding is enabled.
pub fn is_ip_forward_enabled(runner: &dyn Runner) -> bool {
    matches!(read_ip_forward(runner).as_deref(), Ok("1"))
}

/// Read `accept_redirects` status.
pub fn read_accept_redirects(runner: &dyn Runner) -> Result<String> {
    sysctl::read_sysctl(runner, keys::ACCEPT_REDIRECTS)
}

/// Check if ICMP redirects are accepted (should be false on servers).
pub fn is_accepting_redirects(runner: &dyn Runner) -> bool {
    matches!(read_accept_redirects(runner).as_deref(), Ok("1"))
}

/// Read the status of protected hardlinks.
pub fn read_protected_hardlinks(runner: &dyn Runner) -> Result<String> {
    sysctl::read_sysctl(runner, keys::PROTECTED_HARDLINKS)
}

/// Check if protected hardlinks is enabled.
pub fn is_protected_hardlinks_enabled(runner: &dyn Runner) -> bool {
    matches!(read_protected_hardlinks(runner).as_deref(), Ok("1" | "2"))
}

/// Read the status of protected symlinks.
pub fn read_protected_symlinks(runner: &dyn Runner) -> Result<String> {
    sysctl::read_sysctl(runner, keys::PROTECTED_SYMLINKS)
}

/// Check if protected symlinks is enabled.
pub fn is_protected_symlinks_enabled(runner: &dyn Runner) -> bool {
    matches!(read_protected_symlinks(runner).as_deref(), Ok("1" | "2"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_params_are_nonempty() {
        let params = baseline_params();
        assert!(!params.is_empty());
        assert!(params.iter().any(|p| p.key == keys::ASLR));
        assert!(params.iter().any(|p| p.key == keys::KPTR_RESTRICT));
    }

    #[test]
    fn keys_are_well_formed() {
        // All keys should start with a recognized top-level domain
        let all_keys = [
            keys::ASLR,
            keys::KPTR_RESTRICT,
            keys::DMESG_RESTRICT,
            keys::PTRACE_SCOPE,
            keys::PROTECTED_HARDLINKS,
            keys::PROTECTED_SYMLINKS,
            keys::IP_FORWARD,
            keys::ACCEPT_REDIRECTS,
            keys::SEND_REDIRECTS,
            keys::SYNCOOKIES,
            keys::RP_FILTER,
        ];
        for key in &all_keys {
            assert!(
                crate::validate::validate_sysctl_key(key).is_ok(),
                "key {key} should be valid"
            );
        }
    }
}
