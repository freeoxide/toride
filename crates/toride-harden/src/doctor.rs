//! Doctor module — structured diagnostic checks for kernel hardening.
//!
//! Returns findings as [`toride_diagnostic_types::Finding`] values, each
//! with a unique ID, severity, message, and optional fix hint.

use crate::kernel;
use crate::shm;
use toride_diagnostic_types::{Finding, Severity};
use toride_runner::Runner;

/// Run all hardening doctor checks and return findings.
pub fn doctor(runner: &dyn Runner) -> Vec<Finding> {
    let mut findings = Vec::new();

    findings.extend(check_aslr(runner));
    findings.extend(check_dmesg_restrict(runner));
    findings.extend(check_kptr_restrict(runner));
    findings.extend(check_ip_forward(runner));
    findings.extend(check_accept_redirects(runner));
    findings.extend(check_shm_mounts(runner));
    findings.extend(check_protected_hardlinks(runner));
    findings.extend(check_protected_symlinks(runner));

    findings
}

/// Check that ASLR is enabled (kernel.randomize_va_space >= 1).
fn check_aslr(runner: &dyn Runner) -> Vec<Finding> {
    match kernel::read_aslr(runner) {
        Ok(val) => match val.as_str() {
            "2" => vec![Finding::new("kernel.aslr", Severity::Ok, "ASLR is fully enabled (level 2)")
                .domain("harden")
                .detail("kernel.randomize_va_space = 2: full ASLR is active.")],
            "1" => vec![Finding::new("kernel.aslr.partial", Severity::Warning, "ASLR is only partially enabled")
                .domain("harden")
                .detail("kernel.randomize_va_space = 1: conservative ASLR. Set to 2 for full protection.")
                .fix_hint("sysctl -w kernel.randomize_va_space=2")],
            "0" => vec![Finding::new("kernel.aslr.disabled", Severity::Critical, "ASLR is disabled")
                .domain("harden")
                .detail("kernel.randomize_va_space = 0: Address Space Layout Randomization is off.")
                .fix_hint("sysctl -w kernel.randomize_va_space=2")],
            _ => vec![Finding::new("kernel.aslr.unknown", Severity::Warning, format!("Unexpected ASLR value: {val}"))
                .domain("harden")],
        },
        Err(e) => vec![Finding::new("kernel.aslr.error", Severity::Important, format!("Cannot read ASLR: {e}"))
            .domain("harden")],
    }
}

/// Check that dmesg is restricted to privileged users.
fn check_dmesg_restrict(runner: &dyn Runner) -> Vec<Finding> {
    match kernel::read_dmesg_restrict(runner) {
        Ok(val) => match val.as_str() {
            "1" => vec![Finding::new("kernel.dmesg.restrict", Severity::Ok, "dmesg is restricted to privileged users")
                .domain("harden")],
            "0" => vec![Finding::new("kernel.dmesg.restrict", Severity::Important, "dmesg is unrestricted")
                .domain("harden")
                .detail("kernel.dmesg_restrict = 0: any user can read kernel ring buffer, potentially leaking addresses.")
                .fix_hint("sysctl -w kernel.dmesg_restrict=1")],
            _ => vec![],
        },
        Err(e) => vec![Finding::new("kernel.dmesg.error", Severity::Important, format!("Cannot read dmesg_restrict: {e}"))
            .domain("harden")],
    }
}

/// Check that kernel pointer exposure is restricted.
fn check_kptr_restrict(runner: &dyn Runner) -> Vec<Finding> {
    match kernel::read_kptr_restrict(runner) {
        Ok(val) => match val.as_str() {
            "1" | "2" => vec![
                Finding::new(
                    "kernel.kptr-restrict",
                    Severity::Ok,
                    "kptr_restrict is enabled",
                )
                .domain("harden"),
            ],
            "0" => vec![
                Finding::new(
                    "kernel.kptr-restrict.disabled",
                    Severity::Important,
                    "kptr_restrict is disabled",
                )
                .domain("harden")
                .detail(
                    "kernel.kptr_restrict = 0: kernel pointers are exposed to unprivileged users.",
                )
                .fix_hint("sysctl -w kernel.kptr_restrict=1"),
            ],
            _ => vec![],
        },
        Err(e) => vec![
            Finding::new(
                "kernel.kptr-restrict.error",
                Severity::Important,
                format!("Cannot read kptr_restrict: {e}"),
            )
            .domain("harden"),
        ],
    }
}

/// Check IP forwarding status.
fn check_ip_forward(runner: &dyn Runner) -> Vec<Finding> {
    match kernel::read_ip_forward(runner) {
        Ok(val) => match val.as_str() {
            "0" => vec![Finding::new("net.ipv4.ip-forward", Severity::Ok, "IP forwarding is disabled")
                .domain("harden")
                .detail("This is appropriate for non-router systems.")],
            "1" => vec![Finding::new("net.ipv4.ip-forward.enabled", Severity::Warning, "IP forwarding is enabled")
                .domain("harden")
                .detail("net.ipv4.ip_forward = 1: the system will forward packets. Ensure this is intentional (e.g., router/VPN use case).")
                .fix_hint("If not a router: sysctl -w net.ipv4.ip_forward=0")],
            _ => vec![],
        },
        Err(e) => vec![Finding::new("net.ipv4.ip-forward.error", Severity::Important, format!("Cannot read ip_forward: {e}"))
            .domain("harden")],
    }
}

/// Check that ICMP redirects are not accepted.
fn check_accept_redirects(runner: &dyn Runner) -> Vec<Finding> {
    match kernel::read_accept_redirects(runner) {
        Ok(val) => match val.as_str() {
            "0" => vec![
                Finding::new(
                    "net.ipv4.accept-redirects",
                    Severity::Ok,
                    "ICMP redirects are rejected",
                )
                .domain("harden"),
            ],
            "1" => vec![
                Finding::new(
                    "net.ipv4.conf.all.accept-redirects.enabled",
                    Severity::Warning,
                    "ICMP redirects are accepted",
                )
                .domain("harden")
                .detail("Accepting ICMP redirects allows potential man-in-the-middle attacks.")
                .fix_hint("sysctl -w net.ipv4.conf.all.accept_redirects=0"),
            ],
            _ => vec![],
        },
        Err(e) => vec![
            Finding::new(
                "net.ipv4.accept-redirects.error",
                Severity::Important,
                format!("Cannot read accept_redirects: {e}"),
            )
            .domain("harden"),
        ],
    }
}

/// Check shared memory mount security.
fn check_shm_mounts(runner: &dyn Runner) -> Vec<Finding> {
    match shm::check_shm_mounts(runner) {
        Ok(mounts) => {
            if mounts.is_empty() {
                return vec![
                    Finding::new(
                        "shm.dev-shm",
                        Severity::Info,
                        "No dedicated /dev/shm mount found",
                    )
                    .domain("harden")
                    .detail("/dev/shm may be on the root filesystem without nosuid/nodev/noexec."),
                ];
            }

            let mut findings = Vec::new();
            for mount in &mounts {
                let missing = shm::missing_security_options(mount);
                if missing.is_empty() {
                    findings.push(
                        Finding::new(
                            "shm.dev-shm",
                            Severity::Ok,
                            format!("{} is properly hardened", mount.target),
                        )
                        .domain("harden"),
                    );
                } else {
                    let missing_str = missing.join(", ");
                    findings.push(
                        Finding::new(
                            "shm.dev-shm.noexec.missing",
                            Severity::Warning,
                            format!(
                                "{} is missing security options: {}",
                                mount.target, missing_str
                            ),
                        )
                        .domain("harden")
                        .detail(format!(
                            "{} should be mounted with nosuid,nodev,noexec.",
                            mount.target
                        ))
                        .fix_hint(&format!(
                            "mount -o remount,nosuid,nodev,noexec {}",
                            mount.target
                        )),
                    );
                }
            }
            findings
        }
        Err(e) => vec![
            Finding::new(
                "shm.dev-shm.error",
                Severity::Important,
                format!("Cannot check shm mounts: {e}"),
            )
            .domain("harden"),
        ],
    }
}

/// Check that protected hardlinks are enabled.
fn check_protected_hardlinks(runner: &dyn Runner) -> Vec<Finding> {
    match kernel::read_protected_hardlinks(runner) {
        Ok(val) => match val.as_str() {
            "1" | "2" => vec![
                Finding::new(
                    "fs.protected-hardlinks",
                    Severity::Ok,
                    "Protected hardlinks are enabled",
                )
                .domain("harden"),
            ],
            "0" => vec![
                Finding::new(
                    "fs.protected-hardlinks.disabled",
                    Severity::Important,
                    "Protected hardlinks are disabled",
                )
                .domain("harden")
                .detail(
                    "fs.protected_hardlinks = 0: hardlink-based privilege escalation is possible.",
                )
                .fix_hint("sysctl -w fs.protected_hardlinks=1"),
            ],
            _ => vec![],
        },
        Err(e) => vec![
            Finding::new(
                "fs.protected-hardlinks.error",
                Severity::Important,
                format!("Cannot read: {e}"),
            )
            .domain("harden"),
        ],
    }
}

/// Check that protected symlinks are enabled.
fn check_protected_symlinks(runner: &dyn Runner) -> Vec<Finding> {
    match kernel::read_protected_symlinks(runner) {
        Ok(val) => match val.as_str() {
            "1" | "2" => vec![
                Finding::new(
                    "fs.protected-symlinks",
                    Severity::Ok,
                    "Protected symlinks are enabled",
                )
                .domain("harden"),
            ],
            "0" => vec![
                Finding::new(
                    "fs.protected-symlinks.disabled",
                    Severity::Important,
                    "Protected symlinks are disabled",
                )
                .domain("harden")
                .detail(
                    "fs.protected_symlinks = 0: symlink-based privilege escalation is possible.",
                )
                .fix_hint("sysctl -w fs.protected_symlinks=1"),
            ],
            _ => vec![],
        },
        Err(e) => vec![
            Finding::new(
                "fs.protected-symlinks.error",
                Severity::Important,
                format!("Cannot read: {e}"),
            )
            .domain("harden"),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use toride_runner::CommandOutput;
    use toride_runner::fake::FakeRunner;

    /// Build a FakeRunner that returns specific values for sysctl -n queries.
    ///
    /// Each call to `sysctl -n <key>` consumes one response in order.
    /// After that, `findmnt` gets one response.
    fn build_runner(responses: &[&str]) -> FakeRunner {
        let mut runner = FakeRunner::new();
        for &resp in responses {
            runner = runner.push_response(CommandOutput::from_stdout(format!("{resp}\n")));
        }
        // findmnt response (for shm checks)
        runner = runner.push_response(CommandOutput::from_stdout(
            "TARGET SOURCE FSTYPE OPTIONS\n/dev/shm tmpfs tmpfs rw,nosuid,nodev,noexec\n",
        ));
        runner
    }

    #[test]
    fn doctor_with_hardened_system() {
        // Responses in order: ASLR, dmesg, kptr, ip_forward, accept_redirects,
        // protected_hardlinks, protected_symlinks
        let runner = build_runner(&["2", "1", "1", "0", "0", "1", "1"]);

        let findings = doctor(&runner);
        let ok_count = findings
            .iter()
            .filter(|f| f.severity == Severity::Ok)
            .count();
        assert!(
            ok_count >= 5,
            "Expected at least 5 OK findings, got {ok_count}"
        );
    }

    #[test]
    fn doctor_detects_aslr_disabled() {
        let runner = build_runner(&["0", "1", "1", "0", "0", "1", "1"]);

        let findings = doctor(&runner);
        assert!(findings.iter().any(|f| f.id == "kernel.aslr.disabled"));
    }

    #[test]
    fn doctor_detects_kptr_disabled() {
        let runner = build_runner(&["2", "1", "0", "0", "0", "1", "1"]);

        let findings = doctor(&runner);
        assert!(
            findings
                .iter()
                .any(|f| f.id == "kernel.kptr-restrict.disabled")
        );
    }

    #[test]
    fn doctor_detects_ip_forward_enabled() {
        let runner = build_runner(&["2", "1", "1", "1", "0", "1", "1"]);

        let findings = doctor(&runner);
        assert!(
            findings
                .iter()
                .any(|f| f.id == "net.ipv4.ip-forward.enabled")
        );
    }
}
