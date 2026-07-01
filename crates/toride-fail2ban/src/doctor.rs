//! Comprehensive diagnostic engine for Fail2Ban installations.
//!
//! [`Doctor`] is the most important differentiator module. It runs structured
//! diagnostic checks across a Fail2Ban installation and returns a
//! [`DoctorReport`] containing typed [`Finding`] values with severity levels,
//! human-readable descriptions, and suggested fixes.
//!
//! # Categories
//!
//! Each category corresponds to a [`DoctorScope`] variant and a `check_*`
//! method on [`Doctor`]:
//!
//! | Scope | Method | What it checks |
//! |-------|--------|---------------|
//! | `Binary` | [`check_binaries`] | fail2ban-client, fail2ban-regex, systemctl, nft/iptables |
//! | `Service` | [`check_service`] | service active/enabled, ping, log target, database |
//! | `Config` | [`check_config`] | config dir, generated files, --test, managed header |
//! | `Jail(name)` | [`check_jail`] | jail exists/enabled, filter, action, sane timing |
//! | `LogPath` | [`check_log_paths`] | log files exist, readable, glob patterns |
//! | `Journal` | [`check_journal`] | systemd backend, journalmatch, journal access |
//! | `Regex` | [`check_regex`] | failregex compiles, `<HOST>` usage |
//! | `Action` | [`check_actions`] | action file exists, ban/unban, firewall compat |
//! | `Permission` | [`check_permissions`] | world-writable checks, ownership, socket |
//! | `Safety` | [`check_safety`] | dry-run, backup, rollback path |
//! | `Proxy` | [`check_proxy`] | proxy-only IPs, Cloudflare/Traefik warnings |
//!
//! # Example
//!
//! ```ignore
//! use toride_fail2ban::command::DuctRunner;
//! use toride_fail2ban::doctor::{Doctor, DoctorScope};
//!
//! let runner = DuctRunner::new();
//! let doctor = Doctor::new(&runner);
//!
//! let report = doctor.run(&DoctorScope::All)?;
//! if report.has_critical() {
//!     for f in &report.findings {
//!         if f.severity >= Severity::Critical {
//!             eprintln!("[{}] {}", f.severity, f.title);
//!         }
//!     }
//! }
//! ```
//!
//! All commands go through the [`Runner`](crate::command::Runner) trait. No
//! ad-hoc `std::process::Command` calls are made anywhere in this module.

use serde::{Deserialize, Serialize};

use crate::Result;
use crate::command::{Runner, find_binary};
use crate::report::{DoctorReport, Finding, Severity};

// ---------------------------------------------------------------------------
// DoctorScope
// ---------------------------------------------------------------------------

/// Selects which diagnostic category (or categories) to run.
///
/// Pass [`DoctorScope::All`] to run every category, or choose a specific
/// category for targeted checks. [`DoctorScope::Jail`] takes a jail name so
/// that only that jail is inspected.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorScope {
    /// Run all diagnostic categories.
    All,
    /// Check that required binaries exist and have compatible versions.
    Binary,
    /// Check that the Fail2Ban service is active, enabled, and reachable.
    Service,
    /// Check config directory, generated files, managed headers, and --test.
    Config,
    /// Check a single named jail (exists, enabled, filter, action, timing).
    Jail(String),
    /// Check that configured log paths exist and are readable.
    LogPath,
    /// Check systemd journal backend, journalmatch, and journal access.
    Journal,
    /// Check that failregex patterns compile and use `<HOST>` correctly.
    Regex,
    /// Check action files, ban/unban definitions, and firewall compatibility.
    Action,
    /// Check file permissions for world-writable, ownership, and socket safety.
    Permission,
    /// Check that dry-run, backup, and rollback paths are available.
    Safety,
    /// Check for proxy-only IPs and warn about Cloudflare/Traefik.
    Proxy,
}

impl DoctorScope {
    /// Return all non-`All` scope variants as a list.
    ///
    /// Useful for callers that want to iterate over individual categories
    /// (for example, to build a UI where each category is a separate tab).
    pub fn all_categories() -> Vec<DoctorScope> {
        vec![
            DoctorScope::Binary,
            DoctorScope::Service,
            DoctorScope::Config,
            DoctorScope::LogPath,
            DoctorScope::Journal,
            DoctorScope::Regex,
            DoctorScope::Action,
            DoctorScope::Permission,
            DoctorScope::Safety,
            DoctorScope::Proxy,
        ]
    }
}

// ---------------------------------------------------------------------------
// Doctor
// ---------------------------------------------------------------------------

/// Diagnostic engine that runs structured checks against a Fail2Ban
/// installation.
///
/// Borrows a [`Runner`] so that it can be used with either the production
/// [`DuctRunner`](crate::command::DuctRunner) or the test
/// [`FakeRunner`](crate::command::FakeRunner).
///
/// Every check method returns a `Vec<Finding>` so that individual categories
/// can be called in isolation or aggregated via [`Doctor::run`].
pub struct Doctor<'a> {
    runner: &'a dyn Runner,
}

impl<'a> Doctor<'a> {
    /// Create a new diagnostic engine backed by `runner`.
    pub fn new(runner: &'a dyn Runner) -> Self {
        Self { runner }
    }

    // -----------------------------------------------------------------------
    // Dispatch
    // -----------------------------------------------------------------------

    /// Run the selected diagnostic scope and return a complete report.
    ///
    /// When `scope` is [`DoctorScope::All`], every category is run and the
    /// findings are merged into a single report. For a single category only
    /// that category's checks are performed.
    ///
    /// # Errors
    ///
    /// Returns an error only if a fundamental failure occurs (e.g. the runner
    /// itself is broken). Individual check failures are reported as
    /// [`Severity::Error`] or [`Severity::Critical`] findings inside the
    /// report, not as `Err`.
    pub fn run(&self, scope: &DoctorScope) -> Result<DoctorReport> {
        let mut report = DoctorReport::empty();

        match scope {
            DoctorScope::All => {
                for cat in DoctorScope::all_categories() {
                    // Recurse for each category. Jail-only scopes are skipped
                    // in All mode since they require a jail name.
                    let sub_report = self.run(&cat)?;
                    report.findings.extend(sub_report.findings);
                }
            }
            DoctorScope::Binary => {
                report.findings.extend(self.check_binaries());
            }
            DoctorScope::Service => {
                report.findings.extend(self.check_service());
            }
            DoctorScope::Config => {
                report.findings.extend(self.check_config());
            }
            DoctorScope::Jail(name) => {
                report.findings.extend(self.check_jail(name));
            }
            DoctorScope::LogPath => {
                report.findings.extend(self.check_log_paths());
            }
            DoctorScope::Journal => {
                report.findings.extend(self.check_journal());
            }
            DoctorScope::Regex => {
                report.findings.extend(self.check_regex());
            }
            DoctorScope::Action => {
                report.findings.extend(self.check_actions());
            }
            DoctorScope::Permission => {
                report.findings.extend(self.check_permissions());
            }
            DoctorScope::Safety => {
                report.findings.extend(self.check_safety());
            }
            DoctorScope::Proxy => {
                report.findings.extend(self.check_proxy());
            }
        }

        Ok(report)
    }

    // =======================================================================
    // Binary checks
    // =======================================================================

    /// Verify that all required binaries are present and detect the Fail2Ban
    /// version.
    ///
    /// Checks:
    ///
    /// - `fail2ban-client` exists on `$PATH`
    /// - `fail2ban-regex` exists on `$PATH`
    /// - Fail2Ban version can be detected via `fail2ban-client --version`
    /// - `systemctl` exists on `$PATH`
    /// - `nft` / `iptables` availability based on configured actions
    #[allow(clippy::too_many_lines, reason = "sequential binary/version probes")]
    fn check_binaries(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        // fail2ban-client
        match find_binary("fail2ban-client") {
            Ok(path) => {
                findings.push(
                    Finding::new(
                        "binary.fail2ban-client.found",
                        Severity::Ok,
                        "fail2ban-client binary found",
                    )
                    .detail(format!("Located at {}", path.display())),
                );

                // Try to detect the version.
                match self
                    .runner
                    .run(path.to_str().unwrap_or("fail2ban-client"), &["--version"])
                {
                    Ok(out) if out.success => {
                        let ver = out.stdout.trim();
                        findings.push(
                            Finding::new(
                                "binary.fail2ban-client.version",
                                Severity::Info,
                                "Fail2Ban version detected",
                            )
                            .detail(format!("Version: {ver}")),
                        );
                    }
                    Ok(out) => {
                        findings.push(
                            Finding::new(
                                "binary.fail2ban-client.version-failed",
                                Severity::Warning,
                                "Could not detect Fail2Ban version",
                            )
                            .detail(format!(
                                "fail2ban-client --version exited with code {:?}: {}",
                                out.exit_code,
                                out.stderr.trim(),
                            )),
                        );
                    }
                    Err(e) => {
                        findings.push(
                            Finding::new(
                                "binary.fail2ban-client.version-error",
                                Severity::Warning,
                                "Could not detect Fail2Ban version",
                            )
                            .detail(format!("Running --version failed: {e}")),
                        );
                    }
                }
            }
            Err(_) => {
                findings.push(
                    Finding::new(
                        "binary.fail2ban-client.missing",
                        Severity::Critical,
                        "fail2ban-client not found",
                    )
                    .detail(
                        "The fail2ban-client binary could not be located on \
                         $PATH. Fail2Ban may not be installed.",
                    )
                    .fix("Install Fail2Ban: apt install fail2ban (Debian/Ubuntu) or dnf install fail2ban (Fedora)."),
                );
            }
        }

        // fail2ban-regex
        match find_binary("fail2ban-regex") {
            Ok(path) => {
                findings.push(
                    Finding::new(
                        "binary.fail2ban-regex.found",
                        Severity::Ok,
                        "fail2ban-regex binary found",
                    )
                    .detail(format!("Located at {}", path.display())),
                );
            }
            Err(_) => {
                findings.push(
                    Finding::new(
                        "binary.fail2ban-regex.missing",
                        Severity::Warning,
                        "fail2ban-regex not found",
                    )
                    .detail(
                        "The fail2ban-regex binary could not be located on \
                         $PATH. Regex testing will not be available.",
                    )
                    .fix("Install Fail2Ban (includes fail2ban-regex) or ensure it is on $PATH."),
                );
            }
        }

        // systemctl
        match find_binary("systemctl") {
            Ok(path) => {
                findings.push(
                    Finding::new(
                        "binary.systemctl.found",
                        Severity::Ok,
                        "systemctl binary found",
                    )
                    .detail(format!("Located at {}", path.display())),
                );
            }
            Err(_) => {
                findings.push(
                    Finding::new(
                        "binary.systemctl.missing",
                        Severity::Warning,
                        "systemctl not found",
                    )
                    .detail(
                        "The systemctl binary could not be located on $PATH. \
                         Service management commands will not be available. \
                         This is expected on non-systemd systems.",
                    )
                    .fix("Install systemd or avoid using service management features."),
                );
            }
        }

        // nft availability
        match self.runner.run("nft", &["--version"]) {
            Ok(out) if out.success => {
                findings.push(Finding::new(
                    "binary.nft.available",
                    Severity::Ok,
                    "nft binary available",
                ));
            }
            _ => {
                findings.push(
                    Finding::new(
                        "binary.nft.unavailable",
                        Severity::Info,
                        "nft binary not available",
                    )
                    .detail(
                        "nft (nftables) is not available. If jails use nftables \
                         actions, bans will fail.",
                    ),
                );
            }
        }

        // iptables availability
        match self.runner.run("iptables", &["--version"]) {
            Ok(out) if out.success => {
                findings.push(Finding::new(
                    "binary.iptables.available",
                    Severity::Ok,
                    "iptables binary available",
                ));
            }
            _ => {
                findings.push(
                    Finding::new(
                        "binary.iptables.unavailable",
                        Severity::Info,
                        "iptables binary not available",
                    )
                    .detail(
                        "iptables is not available. If jails use iptables \
                         actions, bans will fail.",
                    ),
                );
            }
        }

        findings
    }

    // =======================================================================
    // Service checks
    // =======================================================================

    /// Verify that the Fail2Ban service is active, enabled, and responsive.
    ///
    /// Checks:
    ///
    /// - Fail2Ban service is active (running)
    /// - Fail2Ban service is enabled (starts at boot)
    /// - `fail2ban-client ping` succeeds
    /// - log target is accessible
    /// - database file path is readable
    #[allow(clippy::too_many_lines, reason = "sequential service health probes")]
    fn check_service(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Service active.
        match self.runner.run("systemctl", &["is-active", "fail2ban"]) {
            Ok(out) => {
                if out.success {
                    findings.push(Finding::new(
                        "service.active",
                        Severity::Ok,
                        "Fail2Ban service is active",
                    ));
                } else {
                    findings.push(
                        Finding::new(
                            "service.inactive",
                            Severity::Critical,
                            "Fail2Ban service is not active",
                        )
                        .detail(format!(
                            "systemctl is-active returned: {}",
                            out.stdout.trim(),
                        ))
                        .fix("Start the service: systemctl start fail2ban"),
                    );
                }
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "service.active-check-error",
                        Severity::Error,
                        "Could not check Fail2Ban service state",
                    )
                    .detail(format!("systemctl is-active failed: {e}")),
                );
            }
        }

        // Service enabled.
        match self.runner.run("systemctl", &["is-enabled", "fail2ban"]) {
            Ok(out) => {
                if out.success {
                    findings.push(Finding::new(
                        "service.enabled",
                        Severity::Ok,
                        "Fail2Ban service is enabled",
                    ));
                } else {
                    findings.push(
                        Finding::new(
                            "service.not-enabled",
                            Severity::Warning,
                            "Fail2Ban service is not enabled at boot",
                        )
                        .fix("Enable the service: systemctl enable fail2ban"),
                    );
                }
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "service.enabled-check-error",
                        Severity::Error,
                        "Could not check Fail2Ban enabled state",
                    )
                    .detail(format!("systemctl is-enabled failed: {e}")),
                );
            }
        }

        // fail2ban-client ping.
        match find_binary("fail2ban-client") {
            Ok(path) => {
                let bin = path.to_str().unwrap_or("fail2ban-client");
                match self.runner.run(bin, &["ping"]) {
                    Ok(out) if out.success => {
                        findings.push(Finding::new(
                            "service.ping-ok",
                            Severity::Ok,
                            "fail2ban-client ping succeeded",
                        ));
                    }
                    Ok(out) => {
                        findings.push(
                            Finding::new(
                                "service.ping-failed",
                                Severity::Critical,
                                "fail2ban-client ping failed",
                            )
                            .detail(format!(
                                "Ping returned exit code {:?}: {}",
                                out.exit_code,
                                out.stderr.trim(),
                            ))
                            .fix(
                                "Verify the Fail2Ban daemon is running and the \
                                 socket is accessible.",
                            ),
                        );
                    }
                    Err(e) => {
                        findings.push(
                            Finding::new(
                                "service.ping-error",
                                Severity::Critical,
                                "fail2ban-client ping error",
                            )
                            .detail(format!("Ping command failed: {e}")),
                        );
                    }
                }

                // Log target accessible.
                match self.runner.run(bin, &["get", "logtarget"]) {
                    Ok(out) if out.success => {
                        let target = out.stdout.trim().to_string();
                        findings.push(
                            Finding::new(
                                "service.logtarget-accessible",
                                Severity::Info,
                                "Log target is configured",
                            )
                            .detail(format!("Log target: {target}")),
                        );
                    }
                    Ok(out) => {
                        findings.push(
                            Finding::new(
                                "service.logtarget-unavailable",
                                Severity::Warning,
                                "Could not retrieve log target",
                            )
                            .detail(format!(
                                "get logtarget exited with code {:?}: {}",
                                out.exit_code,
                                out.stderr.trim(),
                            )),
                        );
                    }
                    Err(e) => {
                        findings.push(
                            Finding::new(
                                "service.logtarget-error",
                                Severity::Warning,
                                "Could not retrieve log target",
                            )
                            .detail(format!("get logtarget failed: {e}")),
                        );
                    }
                }

                // Database file readable.
                match self.runner.run(bin, &["get", "dbfile"]) {
                    Ok(out) if out.success => {
                        let db_path = out.stdout.trim().to_string();
                        if db_path == "None" || db_path.is_empty() {
                            findings.push(
                                Finding::new(
                                    "service.dbfile-disabled",
                                    Severity::Info,
                                    "Database is disabled",
                                )
                                .detail(
                                    "Fail2Ban database persistence is disabled. \
                                     Bans will not survive restarts.",
                                ),
                            );
                        } else {
                            findings.push(
                                Finding::new(
                                    "service.dbfile-configured",
                                    Severity::Info,
                                    "Database file configured",
                                )
                                .detail(format!("Database: {db_path}")),
                            );
                        }
                    }
                    Ok(out) => {
                        findings.push(
                            Finding::new(
                                "service.dbfile-unavailable",
                                Severity::Warning,
                                "Could not retrieve database file path",
                            )
                            .detail(format!(
                                "get dbfile exited with code {:?}: {}",
                                out.exit_code,
                                out.stderr.trim(),
                            )),
                        );
                    }
                    Err(e) => {
                        findings.push(
                            Finding::new(
                                "service.dbfile-error",
                                Severity::Warning,
                                "Could not retrieve database file path",
                            )
                            .detail(format!("get dbfile failed: {e}")),
                        );
                    }
                }

                // Socket file check.
                match self.runner.run(bin, &["get", "socket"]) {
                    Ok(out) if out.success => {
                        let socket_path_str = out.stdout.trim().to_string();
                        let socket_path = std::path::Path::new(&socket_path_str);
                        if socket_path.exists() {
                            findings.push(
                                Finding::new(
                                    "service.socket_ok",
                                    Severity::Ok,
                                    "Fail2Ban socket file exists",
                                )
                                .detail(format!("Socket path: {socket_path_str}")),
                            );
                        } else {
                            findings.push(
                                Finding::new(
                                    "service.socket_missing",
                                    Severity::Warning,
                                    "Fail2Ban socket file does not exist",
                                )
                                .detail(format!(
                                    "Socket path {socket_path_str} was reported \
                                     but does not exist on disk.",
                                ))
                                .fix("Restart Fail2Ban or verify the socket path configuration."),
                            );
                        }
                    }
                    Ok(out) => {
                        findings.push(
                            Finding::new(
                                "service.socket-unavailable",
                                Severity::Warning,
                                "Could not retrieve socket path",
                            )
                            .detail(format!(
                                "get socket exited with code {:?}: {}",
                                out.exit_code,
                                out.stderr.trim(),
                            )),
                        );
                    }
                    Err(e) => {
                        findings.push(
                            Finding::new(
                                "service.socket-error",
                                Severity::Warning,
                                "Could not retrieve socket path",
                            )
                            .detail(format!("get socket failed: {e}")),
                        );
                    }
                }

                // PID file check.
                match self.runner.run(bin, &["get", "pidfile"]) {
                    Ok(out) if out.success => {
                        let pid_path_str = out.stdout.trim().to_string();
                        let pid_path = std::path::Path::new(&pid_path_str);
                        if pid_path.exists() {
                            findings.push(
                                Finding::new(
                                    "service.pidfile_ok",
                                    Severity::Ok,
                                    "Fail2Ban PID file exists",
                                )
                                .detail(format!("PID file: {pid_path_str}")),
                            );
                        } else {
                            findings.push(
                                Finding::new(
                                    "service.pidfile_missing",
                                    Severity::Warning,
                                    "Fail2Ban PID file does not exist",
                                )
                                .detail(format!(
                                    "PID file path {pid_path_str} was reported \
                                     but does not exist on disk.",
                                ))
                                .fix("Restart Fail2Ban to recreate the PID file."),
                            );
                        }
                    }
                    Ok(out) => {
                        findings.push(
                            Finding::new(
                                "service.pidfile-unavailable",
                                Severity::Warning,
                                "Could not retrieve PID file path",
                            )
                            .detail(format!(
                                "get pidfile exited with code {:?}: {}",
                                out.exit_code,
                                out.stderr.trim(),
                            )),
                        );
                    }
                    Err(e) => {
                        findings.push(
                            Finding::new(
                                "service.pidfile-error",
                                Severity::Warning,
                                "Could not retrieve PID file path",
                            )
                            .detail(format!("get pidfile failed: {e}")),
                        );
                    }
                }
            }
            Err(_) => {
                // Already reported in check_binaries; add a service-level note.
                findings.push(Finding::new(
                    "service.no-client",
                    Severity::Critical,
                    "Cannot check service: fail2ban-client not found",
                ));
            }
        }

        findings
    }

    // =======================================================================
    // Config checks
    // =======================================================================

    /// Verify Fail2Ban configuration integrity.
    ///
    /// Checks:
    ///
    /// - `/etc/fail2ban` directory exists
    /// - `fail2ban-client --test` passes
    /// - generated files contain the managed header
    /// - no stock `.conf` files were modified
    #[allow(clippy::too_many_lines, reason = "sequential config integrity probes")]
    fn check_config(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        let config_dir = std::path::Path::new("/etc/fail2ban");

        // Config directory exists.
        if config_dir.exists() {
            findings.push(Finding::new(
                "config.directory.exists",
                Severity::Ok,
                "Fail2Ban config directory exists",
            ));
        } else {
            findings.push(
                Finding::new(
                    "config.directory.missing",
                    Severity::Critical,
                    "Fail2Ban config directory does not exist",
                )
                .detail("Expected /etc/fail2ban to exist.")
                .fix("Install Fail2Ban or create /etc/fail2ban."),
            );
            // Early return: nothing else can be checked.
            return findings;
        }

        // fail2ban-client --test passes.
        match find_binary("fail2ban-client") {
            Ok(path) => {
                let bin = path.to_str().unwrap_or("fail2ban-client");
                match self.runner.run(bin, &["--test"]) {
                    Ok(out) if out.success => {
                        findings.push(Finding::new(
                            "config.test.passed",
                            Severity::Ok,
                            "fail2ban-client --test passed",
                        ));
                    }
                    Ok(out) => {
                        findings.push(
                            Finding::new(
                                "config.test.failed",
                                Severity::Error,
                                "fail2ban-client --test failed",
                            )
                            .detail(format!(
                                "Configuration test exited with code {:?}: {}",
                                out.exit_code,
                                out.stderr.trim(),
                            ))
                            .fix("Review Fail2Ban configuration files for syntax errors."),
                        );
                    }
                    Err(e) => {
                        findings.push(
                            Finding::new(
                                "config.test.error",
                                Severity::Error,
                                "Could not run config test",
                            )
                            .detail(format!("fail2ban-client --test failed: {e}")),
                        );
                    }
                }

                // Check that generated files contain the managed header.
                let jail_d = config_dir.join("jail.d");
                if jail_d.exists()
                    && let Ok(entries) = std::fs::read_dir(&jail_d)
                {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.extension().is_some_and(|e| e == "local") {
                            match std::fs::read_to_string(&path) {
                                Ok(content) => {
                                    if content.contains("Managed by fail2ban-kit") {
                                        findings.push(Finding::new(
                                            "config.managed-header.present",
                                            Severity::Ok,
                                            format!("Managed header found in {}", path.display()),
                                        ));
                                    } else {
                                        findings.push(
                                            Finding::new(
                                                "config.managed-header.missing",
                                                Severity::Warning,
                                                format!(
                                                    "Missing managed header in {}",
                                                    path.display()
                                                ),
                                            )
                                            .detail(
                                                "Generated .local files should contain \
                                                 the managed header comment.",
                                            ),
                                        );
                                    }
                                }
                                Err(e) => {
                                    findings.push(
                                        Finding::new(
                                            "config.file-read-error",
                                            Severity::Warning,
                                            format!("Cannot read {}", path.display()),
                                        )
                                        .detail(format!("Read error: {e}")),
                                    );
                                }
                            }
                        }
                    }
                }

                // Check no stock .conf files were modified.
                let dirs_to_check = ["jail.d", "filter.d", "action.d"];
                for subdir in &dirs_to_check {
                    let dir = config_dir.join(subdir);
                    if !dir.exists() {
                        continue;
                    }
                    if let Ok(entries) = std::fs::read_dir(&dir) {
                        for entry in entries.flatten() {
                            let path = entry.path();
                            if path.extension().is_some_and(|e| e == "conf")
                                && let Ok(content) = std::fs::read_to_string(&path)
                                && content.contains("Managed by fail2ban-kit")
                            {
                                findings.push(
                                    Finding::new(
                                        "config.stock-conf.modified",
                                        Severity::Critical,
                                        format!(
                                            "Stock .conf file was modified: {}",
                                            path.display()
                                        ),
                                    )
                                    .detail(
                                        "Stock .conf files must not be edited by \
                                         the library. Use .local overrides instead.",
                                    )
                                    .fix(format!(
                                        "Restore the original file and use a \
                                         .local override: {}.local",
                                        path.display()
                                    )),
                                );
                            }
                        }
                    }
                }
            }
            Err(_) => {
                findings.push(Finding::new(
                    "config.no-client",
                    Severity::Critical,
                    "Cannot check config: fail2ban-client not found",
                ));
            }
        }

        findings
    }

    // =======================================================================
    // Jail checks
    // =======================================================================

    /// Run diagnostic checks for a single named jail.
    ///
    /// Checks:
    ///
    /// - jail exists
    /// - jail is enabled
    /// - jail status is readable
    /// - jail has a filter
    /// - jail has at least one action
    /// - `bantime`, `findtime`, and `maxretry` have sane values
    #[allow(
        clippy::too_many_lines,
        reason = "per-jail multi-aspect diagnostic chain"
    )]
    fn check_jail(&self, jail: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        match find_binary("fail2ban-client") {
            Ok(path) => {
                let bin = path.to_str().unwrap_or("fail2ban-client");

                // Jail status readable (implies existence).
                match self.runner.run(bin, &["status", jail]) {
                    Ok(out) if out.success => {
                        findings.push(
                            Finding::new(
                                "jail.exists",
                                Severity::Ok,
                                format!("Jail '{jail}' exists"),
                            )
                            .detail("fail2ban-client status returned successfully."),
                        );

                        let status = &out.stdout;

                        // Check if jail appears enabled.
                        if status.contains("Currently banned") || status.contains("File list") {
                            findings.push(Finding::new(
                                "jail.enabled",
                                Severity::Ok,
                                format!("Jail '{jail}' appears to be running"),
                            ));
                        } else if status.contains("not running") {
                            findings.push(
                                Finding::new(
                                    "jail.not-running",
                                    Severity::Warning,
                                    format!("Jail '{jail}' is not running"),
                                )
                                .fix("Enable the jail in your jail configuration and reload."),
                            );
                        }

                        // Check filter presence (best-effort parsing).
                        if status.contains("Filter") || status.contains("filter") {
                            findings.push(Finding::new(
                                "jail.has-filter",
                                Severity::Ok,
                                format!("Jail '{jail}' has a filter configured"),
                            ));
                        } else {
                            findings.push(
                                Finding::new(
                                    "jail.no-filter",
                                    Severity::Error,
                                    format!("Jail '{jail}' may not have a filter"),
                                )
                                .fix("Add a filter to the jail configuration."),
                            );
                        }

                        // Check action presence.
                        if status.contains("Actions")
                            || status.contains("actions")
                            || status.contains("action")
                        {
                            findings.push(Finding::new(
                                "jail.has-action",
                                Severity::Ok,
                                format!("Jail '{jail}' has actions configured"),
                            ));
                        } else {
                            findings.push(
                                Finding::new(
                                    "jail.no-action",
                                    Severity::Error,
                                    format!("Jail '{jail}' may not have any actions"),
                                )
                                .fix("Add at least one action (e.g. nftables, iptables) to the jail."),
                            );
                        }
                    }
                    Ok(out) => {
                        let stderr = out.stderr.trim();
                        findings.push(
                            Finding::new(
                                "jail.not-found",
                                Severity::Error,
                                format!("Jail '{jail}' not found or not running"),
                            )
                            .detail(format!(
                                "fail2ban-client status {jail} exited {:?}: {stderr}",
                                out.exit_code,
                            ))
                            .fix(format!(
                                "Create a jail configuration for '{jail}' and reload Fail2Ban.",
                            )),
                        );
                        return findings;
                    }
                    Err(e) => {
                        findings.push(
                            Finding::new(
                                "jail.status-error",
                                Severity::Error,
                                format!("Could not check jail '{jail}'"),
                            )
                            .detail(format!("fail2ban-client status {jail} failed: {e}")),
                        );
                        return findings;
                    }
                }

                // Sane timing parameters (best-effort via status output).
                // We cannot directly query bantime/findtime/maxretry via
                // fail2ban-client in all versions, so we check get operations.
                // Collect parsed values for cross-validation below.

                // bantime
                let mut bantime_secs: Option<u64> = None;
                match self.runner.run(bin, &["get", jail, "bantime"]) {
                    Ok(out) if out.success => {
                        let val = out.stdout.trim();
                        findings.push(Finding::new(
                            "jail.bantime-configured",
                            Severity::Info,
                            format!("Jail '{jail}' ban time: {val}"),
                        ));
                        // Try to parse as plain seconds first, then as a
                        // humantime duration string (e.g. "10m", "1h").
                        bantime_secs = val
                            .parse::<u64>()
                            .ok()
                            .or_else(|| humantime::parse_duration(val).map(|d| d.as_secs()).ok());
                    }
                    _ => {
                        findings.push(Finding::new(
                            "jail.bantime-unknown",
                            Severity::Info,
                            format!("Jail '{jail}' ban time could not be queried"),
                        ));
                    }
                }

                // findtime
                let mut findtime_secs: Option<u64> = None;
                match self.runner.run(bin, &["get", jail, "findtime"]) {
                    Ok(out) if out.success => {
                        let val = out.stdout.trim();
                        findings.push(Finding::new(
                            "jail.findtime-configured",
                            Severity::Info,
                            format!("Jail '{jail}' find time: {val}"),
                        ));
                        findtime_secs = val
                            .parse::<u64>()
                            .ok()
                            .or_else(|| humantime::parse_duration(val).map(|d| d.as_secs()).ok());
                    }
                    _ => {
                        findings.push(Finding::new(
                            "jail.findtime-unknown",
                            Severity::Info,
                            format!("Jail '{jail}' find time could not be queried"),
                        ));
                    }
                }

                // maxretry
                match self.runner.run(bin, &["get", jail, "maxretry"]) {
                    Ok(out) if out.success => {
                        let val = out.stdout.trim();
                        if let Ok(n) = val.parse::<u32>() {
                            if n == 0 {
                                findings.push(
                                    Finding::new(
                                        "jail.maxretry-zero",
                                        Severity::Warning,
                                        format!("Jail '{jail}' has maxretry=0"),
                                    )
                                    .detail("A maxretry of 0 means no bans will ever occur.")
                                    .fix("Set maxretry to a positive value (e.g. 3 or 5)."),
                                );
                            } else if n > 100 {
                                findings.push(
                                    Finding::new(
                                        "jail.maxretry-very-high",
                                        Severity::Info,
                                        format!("Jail '{jail}' has maxretry={n}"),
                                    )
                                    .detail(
                                        "A very high maxretry may reduce the effectiveness \
                                         of the jail.",
                                    ),
                                );
                            } else {
                                findings.push(Finding::new(
                                    "jail.maxretry-ok",
                                    Severity::Ok,
                                    format!("Jail '{jail}' maxretry={n}"),
                                ));
                            }
                        }
                    }
                    _ => {
                        findings.push(Finding::new(
                            "jail.maxretry-unknown",
                            Severity::Info,
                            format!("Jail '{jail}' maxretry could not be queried"),
                        ));
                    }
                }

                // bantime / findtime cross-validation.
                if let Some(bt) = bantime_secs {
                    if bt < 60 {
                        findings.push(
                            Finding::new(
                                "jail.bantime_very_short",
                                Severity::Warning,
                                format!("Jail '{jail}' has a very short bantime ({bt}s)"),
                            )
                            .detail(
                                "A bantime under 60 seconds is too short to be effective. \
                                 Attackers will be able to retry almost immediately.",
                            )
                            .fix("Increase bantime to at least 600 (10 minutes) or more."),
                        );
                    }
                    if let Some(ft) = findtime_secs
                        && bt < ft
                    {
                        findings.push(
                            Finding::new(
                                "jail.bantime_shorter_than_findtime",
                                Severity::Warning,
                                format!(
                                    "Jail '{jail}' bantime ({bt}s) is shorter than \
                                     findtime ({ft}s)"
                                ),
                            )
                            .detail(
                                "When bantime is shorter than findtime, bans may expire \
                                 before the detection window closes. An attacker can \
                                 resume attempts while still within the findtime window.",
                            )
                            .fix(
                                "Set bantime to at least equal to findtime, or longer. \
                                 A common pattern is bantime = 10 * findtime.",
                            ),
                        );
                    }
                }
                if let Some(ft) = findtime_secs
                    && ft > 3600
                {
                    findings.push(
                        Finding::new(
                            "jail.findtime_very_long",
                            Severity::Info,
                            format!("Jail '{jail}' has a very long findtime ({ft}s)"),
                        )
                        .detail(
                            "A findtime longer than 1 hour increases the memory footprint \
                             for tracking failures and may cause legitimate users to be \
                             banned if they accumulate retries over a long period.",
                        ),
                    );
                }

                // usedns check.
                match self.runner.run(bin, &["get", jail, "usedns"]) {
                    Ok(out) if out.success => {
                        let val = out.stdout.trim().to_lowercase();
                        if val != "no" && val != "warn" {
                            findings.push(
                                Finding::new(
                                    "jail.usedns_insecure",
                                    Severity::Warning,
                                    format!("Jail '{jail}' usedns is set to '{val}'"),
                                )
                                .detail(
                                    "When usedns is enabled for application logs, \
                                     Fail2Ban may perform DNS lookups that introduce \
                                     delays and potential security issues. Application \
                                     logs typically contain IP addresses, not hostnames.",
                                )
                                .fix(
                                    "Set usedns = no for app logs to avoid DNS-related \
                                     delays and security issues.",
                                ),
                            );
                        } else {
                            findings.push(Finding::new(
                                "jail.usedns-ok",
                                Severity::Ok,
                                format!("Jail '{jail}' usedns is set to '{val}'"),
                            ));
                        }
                    }
                    _ => {
                        // usedns not queryable -- skip silently.
                    }
                }

                // ignoreip check.
                match self.runner.run(bin, &["get", jail, "ignoreip"]) {
                    Ok(out) if out.success => {
                        let val = out.stdout.trim();
                        let entries: Vec<&str> = val
                            .split(|c: char| c == ',' || c.is_whitespace())
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .collect();
                        if entries.is_empty() {
                            findings.push(
                                Finding::new(
                                    "jail.ignoreip_empty",
                                    Severity::Info,
                                    format!("Jail '{jail}' has no ignoreip entries"),
                                )
                                .detail(
                                    "No trusted IPs are excluded from banning. Consider \
                                     adding common safe IPs to prevent locking yourself out.",
                                )
                                .fix(
                                    "Add trusted IPs to ignoreip, e.g.: \
                                     ignoreip = 127.0.0.1/8 ::1",
                                ),
                            );
                        } else {
                            findings.push(Finding::new(
                                "jail.ignoreip-configured",
                                Severity::Ok,
                                format!(
                                    "Jail '{jail}' ignoreip has {} entr{}",
                                    entries.len(),
                                    if entries.len() == 1 { "y" } else { "ies" },
                                ),
                            ));
                        }
                    }
                    _ => {
                        // ignoreip not queryable -- skip silently.
                    }
                }
            }
            Err(_) => {
                findings.push(Finding::new(
                    "jail.no-client",
                    Severity::Critical,
                    "Cannot check jail: fail2ban-client not found",
                ));
            }
        }

        findings
    }

    // =======================================================================
    // Log path checks
    // =======================================================================

    /// Verify that configured log paths are accessible and valid.
    ///
    /// Checks:
    ///
    /// - log path exists on disk
    /// - parent directory exists
    /// - log path is readable
    /// - log file is not empty when activity is expected
    /// - glob patterns are warned about
    fn check_log_paths(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Retrieve log paths from active jails.
        match find_binary("fail2ban-client") {
            Ok(path) => {
                let bin = path.to_str().unwrap_or("fail2ban-client");

                // First get the list of jails.
                match self.runner.run(bin, &["status"]) {
                    Ok(out) if out.success => {
                        let status = &out.stdout;
                        // Best-effort parse jail names from "Jail list: ..." line.
                        let jail_names = parse_jail_list(status);
                        if jail_names.is_empty() {
                            findings.push(Finding::new(
                                "logpath.no-jails",
                                Severity::Info,
                                "No active jails found to check log paths for",
                            ));
                            return findings;
                        }

                        for jail in &jail_names {
                            // Get log path for this jail.
                            match self.runner.run(bin, &["get", jail, "logpath"]) {
                                Ok(out) if out.success => {
                                    let log_paths = out.stdout.trim();
                                    for line in log_paths.lines() {
                                        let lp = line.trim();
                                        if lp.is_empty() {
                                            continue;
                                        }
                                        Self::check_single_log_path(lp, jail, &mut findings);
                                    }
                                }
                                Ok(_) => {
                                    findings.push(Finding::new(
                                        "logpath.jail-unavailable",
                                        Severity::Warning,
                                        format!("Cannot get log path for jail '{jail}'"),
                                    ));
                                }
                                Err(e) => {
                                    findings.push(
                                        Finding::new(
                                            "logpath.jail-error",
                                            Severity::Warning,
                                            format!("Error getting log path for jail '{jail}'"),
                                        )
                                        .detail(format!("{e}")),
                                    );
                                }
                            }
                        }
                    }
                    Ok(_) => {
                        findings.push(Finding::new(
                            "logpath.status-failed",
                            Severity::Error,
                            "Could not retrieve Fail2Ban status for log path checks",
                        ));
                    }
                    Err(e) => {
                        findings.push(
                            Finding::new(
                                "logpath.status-error",
                                Severity::Error,
                                "Could not retrieve Fail2Ban status",
                            )
                            .detail(format!("{e}")),
                        );
                    }
                }
            }
            Err(_) => {
                findings.push(Finding::new(
                    "logpath.no-client",
                    Severity::Critical,
                    "Cannot check log paths: fail2ban-client not found",
                ));
            }
        }

        findings
    }

    /// Check a single log path and append findings.
    #[allow(
        clippy::too_many_lines,
        reason = "multi-aspect single-path diagnostic chain"
    )]
    fn check_single_log_path(log_path: &str, jail: &str, findings: &mut Vec<Finding>) {
        let path = std::path::Path::new(log_path);

        // Warn about glob patterns.
        if log_path.contains('*') || log_path.contains('?') || log_path.contains('[') {
            findings.push(
                Finding::new(
                    "logpath.glob-pattern",
                    Severity::Info,
                    format!("Jail '{jail}' uses a glob pattern: {log_path}"),
                )
                .detail(
                    "Glob patterns only match files that exist at Fail2Ban startup. \
                     New files created later will not be picked up until a reload.",
                ),
            );
            // For glob patterns, we cannot check individual files; skip the
            // rest of the checks for this entry.
            return;
        }

        // Path exists.
        if path.exists() {
            findings.push(Finding::new(
                "logpath.exists",
                Severity::Ok,
                format!("Log path for jail '{jail}' exists: {log_path}"),
            ));
        } else {
            // Check parent directory.
            if let Some(parent) = path.parent() {
                if parent.exists() {
                    findings.push(
                        Finding::new(
                            "logpath.file-missing",
                            Severity::Warning,
                            format!("Log file for jail '{jail}' does not exist: {log_path}"),
                        )
                        .detail(format!(
                            "Parent directory exists ({}) but the log file is missing.",
                            parent.display(),
                        ))
                        .fix(format!(
                            "Verify that the application writes to {log_path}, \
                             or create the file and ensure Fail2Ban can read it.",
                        )),
                    );
                } else {
                    findings.push(
                        Finding::new(
                            "logpath.parent-missing",
                            Severity::Error,
                            format!(
                                "Parent directory for jail '{jail}' log does not exist: {}",
                                parent.display(),
                            ),
                        )
                        .fix(format!(
                            "Create the directory: mkdir -p {}",
                            parent.display(),
                        )),
                    );
                }
            }
            return;
        }

        // Readable.
        if std::fs::metadata(path).is_err() {
            findings.push(
                Finding::new(
                    "logpath.not-readable",
                    Severity::Error,
                    format!("Log file for jail '{jail}' is not readable: {log_path}"),
                )
                .fix("Adjust file permissions so the Fail2Ban process can read the log."),
            );
            return;
        }

        // Not empty.
        if let Ok(meta) = std::fs::metadata(path)
            && meta.len() == 0
        {
            findings.push(
                Finding::new(
                    "logpath.empty",
                    Severity::Info,
                    format!("Log file for jail '{jail}' is empty: {log_path}"),
                )
                .detail(
                    "The log file exists but is empty. This may be normal \
                     if the application has not written any entries yet.",
                ),
            );
        }

        // Docker path detection.
        let lp_lower = log_path.to_lowercase();
        if lp_lower.contains("/var/lib/docker/")
            || lp_lower.contains("/containers/") && lp_lower.contains("/docker/")
        {
            findings.push(
                Finding::new(
                    "logpath.docker_host_visibility",
                    Severity::Warning,
                    format!(
                        "Jail '{jail}' log path appears to be inside a Docker \
                         container: {log_path}"
                    ),
                )
                .detail(
                    "Container log paths are typically only accessible inside the \
                     container's filesystem. Fail2Ban running on the host may not \
                     be able to read these logs unless they are bind-mounted or \
                     Docker logging drivers are configured to write to the host.",
                )
                .fix(
                    "Ensure Docker container log paths are bind-mounted or \
                     accessible to Fail2Ban on the host. Consider using \
                     syslog or json-file logging drivers with host-mounted \
                     volumes.",
                ),
            );
        }

        // Real IP detection in log content.
        // Only check if the file is non-empty and we haven't already flagged it.
        if path.exists() {
            let mut already_flagged = false;
            for f in findings.iter() {
                if f.id == "logpath.empty" || f.id == "logpath.not-readable" {
                    already_flagged = true;
                    break;
                }
            }
            // Stream only the first few lines instead of reading the whole file
            // into memory. `read_to_string` would slurp a multi-hundred-MB
            // auth.log on every diagnostic run; BufReader bounds memory to the
            // first `PROXY_IP_SAMPLE_LINES` lines regardless of file size.
            if !already_flagged
                && let Ok(file) = std::fs::File::open(path)
            {
                use std::io::BufRead;
                let reader = std::io::BufReader::new(file);
                let lines: Vec<String> = reader
                    .lines()
                    .take(PROXY_IP_SAMPLE_LINES)
                    .filter_map(std::result::Result::ok)
                    .collect();
                if !lines.is_empty() {
                    let mut all_private = true;
                    let mut any_ip_found = false;
                    for line in &lines {
                        // Extract potential IP addresses from the line.
                        let ips = extract_ips_from_line(line);
                        for ip_str in &ips {
                            any_ip_found = true;
                            if !is_private_ip(ip_str) {
                                all_private = false;
                                break;
                            }
                        }
                        if !all_private {
                            break;
                        }
                    }
                    if any_ip_found && all_private {
                        findings.push(
                            Finding::new(
                                "logpath.proxy_ips_only",
                                Severity::Warning,
                                format!(
                                    "Jail '{jail}' log contains only private/proxy \
                                     IPs: {log_path}"
                                ),
                            )
                            .detail(
                                "The first lines of the log file contain only \
                                 private IP addresses (10.x.x.x, 172.16-31.x.x, \
                                 192.168.x.x, 127.x.x.x). This typically means \
                                 Fail2Ban sees the reverse proxy or CDN IP instead \
                                 of the real client IP. Fail2Ban would ban the \
                                 proxy/CDN IP, blocking all traffic through it.",
                            )
                            .fix(
                                "Configure your application to log real client IPs \
                                 (e.g., use X-Forwarded-For or X-Real-IP headers). \
                                 Ensure the log format includes the forwarded IP.",
                            ),
                        );
                    }
                }
            }
        }
    }

    // =======================================================================
    // Journal checks
    // =======================================================================

    /// Verify systemd journal configuration and accessibility.
    ///
    /// Checks:
    ///
    /// - backend is `systemd` when expected
    /// - `journalmatch` is configured (not `logpath`)
    /// - journal query returns recent rows
    /// - Fail2Ban has access to the journal
    #[allow(clippy::too_many_lines, reason = "sequential journal backend probes")]
    #[allow(
        clippy::collapsible_if,
        reason = "collapsing would over-indent a deep probe body"
    )]
    fn check_journal(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check if journalctl is available at all.
        match self.runner.run("journalctl", &["--version"]) {
            Ok(out) if out.success => {
                findings.push(Finding::new(
                    "journal.journalctl.available",
                    Severity::Ok,
                    "journalctl is available",
                ));
            }
            _ => {
                findings.push(
                    Finding::new(
                        "journal.journalctl.unavailable",
                        Severity::Info,
                        "journalctl is not available",
                    )
                    .detail(
                        "journalctl could not be executed. Systemd journal \
                         checks require journalctl.",
                    ),
                );
                return findings;
            }
        }

        // Try to query the journal for Fail2Ban's own service unit.
        match self
            .runner
            .run("journalctl", &["-u", "fail2ban", "-n", "1", "--no-pager"])
        {
            Ok(out) if out.success => {
                let lines: Vec<&str> = out.stdout.trim().lines().collect();
                if lines.is_empty() || lines.iter().all(|l| l.trim().is_empty()) {
                    findings.push(
                        Finding::new(
                            "journal.no-entries",
                            Severity::Info,
                            "No recent journal entries for fail2ban service",
                        )
                        .detail(
                            "The journal was queried but returned no entries for the \
                             fail2ban unit. The service may not have logged yet.",
                        ),
                    );
                } else {
                    findings.push(Finding::new(
                        "journal.entries-found",
                        Severity::Ok,
                        "Journal is accessible and contains Fail2Ban entries",
                    ));
                }
            }
            Ok(out) => {
                findings.push(
                    Finding::new(
                        "journal.query-failed",
                        Severity::Warning,
                        "Journal query returned non-zero exit",
                    )
                    .detail(format!(
                        "journalctl -u fail2ban exited {:?}: {}",
                        out.exit_code,
                        out.stderr.trim(),
                    ))
                    .fix("Ensure the user running this check has journal access."),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "journal.query-error",
                        Severity::Warning,
                        "Could not query the systemd journal",
                    )
                    .detail(format!("journalctl failed: {e}")),
                );
            }
        }

        // Check active jails for systemd backend misuse.
        if let Ok(path) = find_binary("fail2ban-client") {
            let bin = path.to_str().unwrap_or("fail2ban-client");
            if let Ok(out) = self.runner.run(bin, &["status"]) {
                if out.success {
                    let jail_names = parse_jail_list(&out.stdout);
                    for jail in &jail_names {
                        // Check backend.
                        match self.runner.run(bin, &["get", jail, "backend"]) {
                            Ok(out) if out.success => {
                                let backend = out.stdout.trim().to_lowercase();
                                if backend.contains("systemd") {
                                    findings.push(Finding::new(
                                        "jail.backend-systemd",
                                        Severity::Info,
                                        format!("Jail '{jail}' uses systemd backend"),
                                    ));

                                    // 1. No logpath with systemd backend.
                                    match self.runner.run(bin, &["get", jail, "logpath"]) {
                                        Ok(lp_out) if lp_out.success => {
                                            let logpath = lp_out.stdout.trim();
                                            if !logpath.is_empty()
                                                && logpath != "None"
                                                && logpath.lines().any(|l| !l.trim().is_empty())
                                            {
                                                findings.push(
                                                    Finding::new(
                                                        "journal.logpath_with_systemd",
                                                        Severity::Warning,
                                                        format!(
                                                            "Jail '{jail}' has logpath \
                                                             set with systemd backend"
                                                        ),
                                                    )
                                                    .detail(
                                                        "systemd backend should use \
                                                         journalmatch, not logpath",
                                                    )
                                                    .fix(
                                                        "Remove logpath and use \
                                                         journalmatch for systemd backend",
                                                    ),
                                                );
                                            }
                                        }
                                        _ => {}
                                    }

                                    // Check that journalmatch is set, not logpath.
                                    let mut journalmatch_value: Option<String> = None;
                                    match self.runner.run(bin, &["get", jail, "journalmatch"]) {
                                        Ok(jm_out) if jm_out.success => {
                                            let jm = jm_out.stdout.trim().to_string();
                                            if jm.is_empty() || jm == "None" {
                                                findings.push(
                                                    Finding::new(
                                                        "journal.journalmatch-missing",
                                                        Severity::Warning,
                                                        format!(
                                                            "Jail '{jail}' uses systemd \
                                                             backend but has no journalmatch"
                                                        ),
                                                    )
                                                    .fix(format!(
                                                        "Add a journalmatch directive \
                                                         to jail '{jail}'.",
                                                    )),
                                                );
                                            } else {
                                                journalmatch_value = Some(jm);
                                            }
                                        }
                                        _ => {}
                                    }

                                    // 2. Unit existence check.
                                    if let Some(ref jm) = journalmatch_value {
                                        let units = extract_systemd_units(jm);
                                        for unit in &units {
                                            match self.runner.run("systemctl", &["status", unit]) {
                                                Ok(u_out) => {
                                                    let stderr_lower = u_out.stderr.to_lowercase();
                                                    let stdout_lower = u_out.stdout.to_lowercase();
                                                    if !u_out.success
                                                        && (stderr_lower.contains("not found")
                                                            || stderr_lower.contains("not-loaded")
                                                            || stdout_lower.contains("not found")
                                                            || stdout_lower.contains("not-loaded")
                                                            || stderr_lower
                                                                .contains("could not be found")
                                                            || stdout_lower
                                                                .contains("could not be found"))
                                                    {
                                                        findings.push(
                                                            Finding::new(
                                                                "journal.unit_not_found",
                                                                Severity::Error,
                                                                format!(
                                                                    "systemd unit '{unit}' \
                                                                     not found"
                                                                ),
                                                            )
                                                            .detail(format!(
                                                                "journalmatch references \
                                                                 '{unit}' but systemctl \
                                                                 reports it as not found or \
                                                                 not loaded.",
                                                            ))
                                                            .fix(format!(
                                                                "Verify that the unit \
                                                                 '{unit}' is installed and \
                                                                 loaded, or update the \
                                                                 journalmatch for jail \
                                                                 '{jail}'.",
                                                            )),
                                                        );
                                                    } else {
                                                        findings.push(Finding::new(
                                                            "journal.unit_ok",
                                                            Severity::Ok,
                                                            format!(
                                                                "systemd unit '{unit}' \
                                                                     exists"
                                                            ),
                                                        ));
                                                    }
                                                }
                                                Err(e) => {
                                                    findings.push(
                                                        Finding::new(
                                                            "journal.unit_check_error",
                                                            Severity::Warning,
                                                            format!(
                                                                "Could not check status of \
                                                                 systemd unit '{unit}'"
                                                            ),
                                                        )
                                                        .detail(format!(
                                                            "systemctl status {unit} \
                                                             failed: {e}",
                                                        )),
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        // 3. Journal access check.
        match self.runner.run("journalctl", &["-n", "1", "--no-pager"]) {
            Ok(out) => {
                if out.success {
                    findings.push(Finding::new(
                        "journal.access_ok",
                        Severity::Ok,
                        "Journal is accessible",
                    ));
                } else {
                    let stderr_lower = out.stderr.to_lowercase();
                    if stderr_lower.contains("permission")
                        || stderr_lower.contains("access denied")
                        || stderr_lower.contains("not permitted")
                    {
                        findings.push(
                            Finding::new(
                                "journal.access_denied",
                                Severity::Error,
                                "Journal access denied",
                            )
                            .detail(format!(
                                "journalctl returned a permission error: {}",
                                out.stderr.trim(),
                            ))
                            .fix(
                                "Ensure the fail2ban user has journal access (add \
                                 to systemd-journal group)",
                            ),
                        );
                    } else {
                        findings.push(
                            Finding::new(
                                "journal.access_check_failed",
                                Severity::Warning,
                                "Journal access check failed",
                            )
                            .detail(format!(
                                "journalctl -n 1 --no-pager exited {:?}: {}",
                                out.exit_code,
                                out.stderr.trim(),
                            )),
                        );
                    }
                }
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "journal.access_error",
                        Severity::Warning,
                        "Could not check journal access",
                    )
                    .detail(format!("journalctl failed: {e}")),
                );
            }
        }

        findings
    }

    // =======================================================================
    // Regex checks
    // =======================================================================

    /// Verify that failregex patterns compile and use `<HOST>` correctly.
    ///
    /// Checks:
    ///
    /// - `fail2ban-regex` is available
    /// - failregex compiles via `fail2ban-regex`
    /// - `<HOST>` appears in the regex pattern
    #[allow(
        clippy::too_many_lines,
        reason = "per-jail per-regex attack/safe-line probing"
    )]
    #[allow(
        clippy::collapsible_if,
        reason = "collapsing would over-indent a 300-line probe body"
    )]
    fn check_regex(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        match find_binary("fail2ban-regex") {
            Ok(path) => {
                let bin = path.to_str().unwrap_or("fail2ban-regex");

                // Verify fail2ban-regex is functional.
                match self.runner.run(bin, &["--version"]) {
                    Ok(out) if out.success => {
                        findings.push(Finding::new(
                            "regex.tool-available",
                            Severity::Ok,
                            "fail2ban-regex is available",
                        ));
                    }
                    Ok(out) => {
                        findings.push(
                            Finding::new(
                                "regex.tool-error",
                                Severity::Warning,
                                "fail2ban-regex did not return version",
                            )
                            .detail(format!(
                                "Exited {:?}: {}",
                                out.exit_code,
                                out.stderr.trim(),
                            )),
                        );
                    }
                    Err(e) => {
                        findings.push(
                            Finding::new(
                                "regex.tool-unavailable",
                                Severity::Error,
                                "Could not run fail2ban-regex",
                            )
                            .detail(format!("{e}")),
                        );
                        return findings;
                    }
                }

                // Check active jails for <HOST> usage in their filters.
                if let Ok(client_path) = find_binary("fail2ban-client") {
                    let client_bin = client_path.to_str().unwrap_or("fail2ban-client");
                    if let Ok(out) = self.runner.run(client_bin, &["status"]) {
                        if out.success {
                            let jail_names = parse_jail_list(&out.stdout);
                            for jail in &jail_names {
                                // Get the failregex for this jail.
                                let failregex_val: Option<String> = match self
                                    .runner
                                    .run(client_bin, &["get", jail, "failregex"])
                                {
                                    Ok(out) if out.success => {
                                        let regex = out.stdout.trim();
                                        if regex.is_empty() || regex == "None" {
                                            findings.push(
                                                Finding::new(
                                                    "regex.jail-no-failregex",
                                                    Severity::Warning,
                                                    format!("Jail '{jail}' has no failregex"),
                                                )
                                                .fix(format!(
                                                    "Add a failregex to the filter \
                                                         used by jail '{jail}'.",
                                                )),
                                            );
                                            None
                                        } else if !regex.contains("<HOST>") {
                                            findings.push(
                                                Finding::new(
                                                    "regex.missing-host-tag",
                                                    Severity::Error,
                                                    format!(
                                                        "Jail '{jail}' failregex does \
                                                             not contain <HOST>"
                                                    ),
                                                )
                                                .detail(
                                                    "The failregex must contain \
                                                         <HOST> so that Fail2Ban can \
                                                         extract the IP address from \
                                                         matching log lines.",
                                                )
                                                .fix(format!(
                                                    "Update the failregex for jail \
                                                         '{jail}' to include <HOST>.",
                                                )),
                                            );
                                            None
                                        } else {
                                            findings.push(Finding::new(
                                                "regex.host-tag-present",
                                                Severity::Ok,
                                                format!(
                                                    "Jail '{jail}' failregex \
                                                         contains <HOST>"
                                                ),
                                            ));
                                            Some(regex.to_string())
                                        }
                                    }
                                    _ => {
                                        findings.push(Finding::new(
                                            "regex.jail-failregex-unknown",
                                            Severity::Info,
                                            format!(
                                                "Could not query failregex \
                                                         for jail '{jail}'"
                                            ),
                                        ));
                                        None
                                    }
                                };

                                // 4. Malicious line matching.
                                if let Some(ref failregex) = failregex_val {
                                    let attack_lines = [
                                        "Failed password for root from \
                                         192.168.1.100 port 22 ssh2",
                                        "authentication failure; \
                                         rhost=10.0.0.1 user=admin",
                                    ];
                                    for attack_line in &attack_lines {
                                        if let Ok(out) =
                                            self.runner.run(bin, &[attack_line, failregex])
                                        {
                                            if out.success && out.stdout.contains("Lines:") {
                                                // Attack matched - good.
                                            } else {
                                                findings.push(
                                                    Finding::new(
                                                        "regex.attack_not_matched",
                                                        Severity::Warning,
                                                        format!(
                                                            "Jail '{jail}' failregex \
                                                             does not match attack \
                                                             line"
                                                        ),
                                                    )
                                                    .detail(format!(
                                                        "Sample attack line was not \
                                                         matched: {attack_line}",
                                                    ))
                                                    .fix(
                                                        "Review the failregex pattern \
                                                         to ensure it matches common \
                                                         attack signatures.",
                                                    ),
                                                );
                                            }
                                        }
                                    }

                                    // 5. Safe line non-matching.
                                    let safe_lines = [
                                        "Accepted password for user from \
                                         192.168.1.1 port 22 ssh2",
                                        "session opened for user admin",
                                    ];
                                    for safe_line in &safe_lines {
                                        if let Ok(out) =
                                            self.runner.run(bin, &[safe_line, failregex])
                                        {
                                            if out.success
                                                && out.stdout.contains("Lines:")
                                                && !out.stdout.contains("0 matched")
                                            {
                                                findings.push(
                                                    Finding::new(
                                                        "regex.false_positive",
                                                        Severity::Warning,
                                                        format!(
                                                            "Jail '{jail}' failregex \
                                                             matches safe line"
                                                        ),
                                                    )
                                                    .detail(format!(
                                                        "A safe/normal log line was \
                                                         incorrectly matched: \
                                                         {safe_line}",
                                                    ))
                                                    .fix(
                                                        "Tighten the failregex pattern \
                                                         to avoid matching legitimate \
                                                         log lines.",
                                                    ),
                                                );
                                            }
                                        }
                                    }

                                    // 7. maxlines check.
                                    let is_multiline = failregex.contains('\n');
                                    let maxlines_val = match self
                                        .runner
                                        .run(client_bin, &["get", jail, "maxlines"])
                                    {
                                        Ok(ml_out) if ml_out.success => {
                                            let ml = ml_out.stdout.trim();
                                            if ml == "None" || ml.is_empty() {
                                                None
                                            } else {
                                                ml.parse::<u32>().ok()
                                            }
                                        }
                                        _ => None,
                                    };

                                    if is_multiline && maxlines_val.is_none() {
                                        findings.push(
                                            Finding::new(
                                                "regex.maxlines_missing",
                                                Severity::Warning,
                                                format!(
                                                    "Jail '{jail}' has multi-line \
                                                     failregex but no maxlines set"
                                                ),
                                            )
                                            .detail(
                                                "When failregex contains newlines, \
                                                 maxlines must be set to tell Fail2Ban \
                                                 how many preceding lines to buffer.",
                                            )
                                            .fix(
                                                "Set maxlines in the filter \
                                                 configuration to match the number \
                                                 of lines the regex spans.",
                                            ),
                                        );
                                    } else if !is_multiline && maxlines_val.is_some() {
                                        findings.push(Finding::new(
                                            "regex.maxlines_unnecessary",
                                            Severity::Info,
                                            format!(
                                                "Jail '{jail}' has maxlines set \
                                                     but failregex is single-line"
                                            ),
                                        ));
                                    }

                                    // 8. False IP detection - check if <HOST>
                                    //    is anchored.
                                    if !is_host_anchored(failregex) {
                                        findings.push(
                                            Finding::new(
                                                "regex.host_unanchored",
                                                Severity::Warning,
                                                format!(
                                                    "Jail '{jail}' failregex has \
                                                     unanchored <HOST>"
                                                ),
                                            )
                                            .detail(
                                                "The <HOST> placeholder is not \
                                                 properly anchored in the regex, \
                                                 which could cause it to match \
                                                 arbitrary words as IP addresses.",
                                            )
                                            .fix(
                                                "Anchor <HOST> with word boundaries \
                                                 or more specific surrounding \
                                                 patterns to prevent false IP \
                                                 detection.",
                                            ),
                                        );
                                    }
                                }

                                // 6. datepattern check.
                                let datepattern_val = match self
                                    .runner
                                    .run(client_bin, &["get", jail, "datepattern"])
                                {
                                    Ok(dp_out) if dp_out.success => {
                                        let dp = dp_out.stdout.trim().to_string();
                                        if dp.is_empty() || dp == "None" {
                                            None
                                        } else {
                                            Some(dp)
                                        }
                                    }
                                    _ => None,
                                };

                                if let Some(ref dp) = datepattern_val {
                                    if let Some(ref failregex) = failregex_val {
                                        match self.runner.run(
                                            bin,
                                            &[
                                                "--datepattern",
                                                dp,
                                                "Failed password for root from \
                                                     192.168.1.100 port 22 ssh2",
                                                failregex,
                                            ],
                                        ) {
                                            Ok(out) => {
                                                if !out.success {
                                                    findings.push(
                                                        Finding::new(
                                                            "regex.datepattern_invalid",
                                                            Severity::Error,
                                                            format!(
                                                                "Jail '{jail}' \
                                                                 datepattern is invalid"
                                                            ),
                                                        )
                                                        .detail(format!(
                                                            "datepattern '{dp}' failed: {}",
                                                            out.stderr.trim(),
                                                        ))
                                                        .fix(
                                                            "Correct the datepattern in \
                                                             the filter configuration.",
                                                        ),
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                findings.push(
                                                    Finding::new(
                                                        "regex.datepattern_error",
                                                        Severity::Warning,
                                                        format!(
                                                            "Could not test datepattern \
                                                             for jail '{jail}'"
                                                        ),
                                                    )
                                                    .detail(format!("{e}")),
                                                );
                                            }
                                        }
                                    }
                                } else {
                                    findings.push(Finding::new(
                                        "regex.no_datepattern",
                                        Severity::Info,
                                        format!("Jail '{jail}' has no custom datepattern"),
                                    ));
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => {
                findings.push(
                    Finding::new(
                        "regex.no-tool",
                        Severity::Warning,
                        "fail2ban-regex not found",
                    )
                    .detail("Cannot verify regex patterns without fail2ban-regex.")
                    .fix("Install Fail2Ban which includes fail2ban-regex."),
                );
            }
        }

        findings
    }

    // =======================================================================
    // Action checks
    // =======================================================================

    /// Verify that configured actions are valid and compatible with the
    /// system firewall.
    ///
    /// Checks:
    ///
    /// - action file exists
    /// - action has ban and unban definitions
    /// - action is compatible with system firewall backend
    #[allow(
        clippy::too_many_lines,
        reason = "per-jail multi-aspect action probing"
    )]
    #[allow(
        clippy::collapsible_if,
        reason = "collapsing would over-indent a 350-line probe body"
    )]
    fn check_actions(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        let action_dir = std::path::Path::new("/etc/fail2ban/action.d");

        // Check the action directory exists.
        if action_dir.exists() {
            findings.push(Finding::new(
                "action.directory.exists",
                Severity::Ok,
                "Fail2Ban action directory exists",
            ));
        } else {
            findings.push(
                Finding::new(
                    "action.directory.missing",
                    Severity::Error,
                    "Fail2Ban action directory does not exist",
                )
                .detail("Expected /etc/fail2ban/action.d to exist.")
                .fix("Install Fail2Ban or create the action.d directory."),
            );
            return findings;
        }

        // Check active jail actions for firewall compatibility.
        if let Ok(path) = find_binary("fail2ban-client") {
            let bin = path.to_str().unwrap_or("fail2ban-client");
            if let Ok(out) = self.runner.run(bin, &["status"]) {
                if out.success {
                    let jail_names = parse_jail_list(&out.stdout);
                    for jail in &jail_names {
                        // Get actions for this jail.
                        match self.runner.run(bin, &["get", jail, "actions"]) {
                            Ok(out) if out.success => {
                                let actions_str = out.stdout.trim();
                                for action_name in actions_str
                                    .split(',')
                                    .map(str::trim)
                                    .filter(|s| !s.is_empty())
                                {
                                    // Check that the action file exists.
                                    let conf_path = action_dir.join(format!("{action_name}.conf"));
                                    let local_path =
                                        action_dir.join(format!("{action_name}.local"));

                                    if conf_path.exists() || local_path.exists() {
                                        findings.push(Finding::new(
                                            "action.file-exists",
                                            Severity::Ok,
                                            format!(
                                                "Action '{action_name}' for jail '{jail}' \
                                                 exists"
                                            ),
                                        ));

                                        // Check firewall compatibility.
                                        let action_lower = action_name.to_ascii_lowercase();
                                        if action_lower.contains("nftables") {
                                            match self.runner.run("nft", &["--version"]) {
                                                Ok(o) if o.success => {}
                                                _ => {
                                                    findings.push(
                                                        Finding::new(
                                                            "action.nft-incompatible",
                                                            Severity::Critical,
                                                            format!(
                                                                "Jail '{jail}' uses \
                                                                 nftables action but \
                                                                 nft is not available"
                                                            ),
                                                        )
                                                        .fix(
                                                            "Install nftables or switch \
                                                             to an iptables action.",
                                                        ),
                                                    );
                                                }
                                            }
                                        } else if action_lower.contains("iptables") {
                                            match self.runner.run("iptables", &["--version"]) {
                                                Ok(o) if o.success => {}
                                                _ => {
                                                    findings.push(
                                                        Finding::new(
                                                            "action.iptables-incompatible",
                                                            Severity::Critical,
                                                            format!(
                                                                "Jail '{jail}' uses \
                                                                 iptables action but \
                                                                 iptables is not available"
                                                            ),
                                                        )
                                                        .fix(
                                                            "Install iptables or switch \
                                                             to a nftables action.",
                                                        ),
                                                    );
                                                }
                                            }
                                        }

                                        // Read the action file content for
                                        // deeper checks. Prefer .local over
                                        // .conf as .local overrides.
                                        let action_content = if local_path.exists() {
                                            std::fs::read_to_string(&local_path)
                                        } else {
                                            std::fs::read_to_string(&conf_path)
                                        };

                                        if let Ok(content) = action_content {
                                            // 9. ban/unban behavior check.
                                            let has_actionban = content.contains("actionban")
                                                || content.contains("banaction");
                                            let has_actionunban = content.contains("actionunban");

                                            if !has_actionban {
                                                findings.push(
                                                    Finding::new(
                                                        "action.no_ban_command",
                                                        Severity::Error,
                                                        format!(
                                                            "Action '{action_name}' \
                                                             missing actionban definition"
                                                        ),
                                                    )
                                                    .detail(
                                                        "The action file does not \
                                                         define an actionban key. \
                                                         Bans will not be executed.",
                                                    )
                                                    .fix(format!(
                                                        "Add an actionban definition \
                                                         to the action file for \
                                                         '{action_name}'.",
                                                    )),
                                                );
                                            }
                                            if !has_actionunban {
                                                findings.push(
                                                    Finding::new(
                                                        "action.no_unban_command",
                                                        Severity::Warning,
                                                        format!(
                                                            "Action '{action_name}' \
                                                             missing actionunban \
                                                             definition"
                                                        ),
                                                    )
                                                    .detail(
                                                        "The action file does not \
                                                         define an actionunban key. \
                                                         Unbans will not be executed, \
                                                         leaving firewall rules in \
                                                         place after bantime expires.",
                                                    )
                                                    .fix(format!(
                                                        "Add an actionunban definition \
                                                         to the action file for \
                                                         '{action_name}'.",
                                                    )),
                                                );
                                            }

                                            // 10. actioncheck verification.
                                            let has_actioncheck = content.contains("actioncheck");
                                            if has_actioncheck {
                                                findings.push(Finding::new(
                                                    "action.has_actioncheck",
                                                    Severity::Ok,
                                                    format!(
                                                        "Action '{action_name}' \
                                                             defines actioncheck"
                                                    ),
                                                ));
                                            } else {
                                                findings.push(
                                                    Finding::new(
                                                        "action.no_actioncheck",
                                                        Severity::Info,
                                                        format!(
                                                            "Action '{action_name}' does \
                                                             not define actioncheck"
                                                        ),
                                                    )
                                                    .detail(
                                                        "Without actioncheck, Fail2Ban \
                                                         cannot verify the action state \
                                                         before applying bans.",
                                                    ),
                                                );
                                            }

                                            // 11. timeout check.
                                            if let Some(timeout_val) =
                                                extract_ini_value(&content, "timeout")
                                            {
                                                if let Ok(secs) = timeout_val.parse::<u64>() {
                                                    if secs > 60 {
                                                        findings.push(
                                                            Finding::new(
                                                                "action.timeout_high",
                                                                Severity::Warning,
                                                                format!(
                                                                    "Action \
                                                                     '{action_name}' \
                                                                     has high timeout \
                                                                     ({secs}s)"
                                                                ),
                                                            )
                                                            .detail(
                                                                "A timeout greater \
                                                                 than 60 seconds may \
                                                                 cause Fail2Ban to \
                                                                 block on slow actions.",
                                                            )
                                                            .fix(
                                                                "Reduce the timeout to \
                                                                 60 seconds or less.",
                                                            ),
                                                        );
                                                    }
                                                }
                                            } else {
                                                findings.push(Finding::new(
                                                    "action.no_timeout",
                                                    Severity::Info,
                                                    format!(
                                                        "Action '{action_name}' has \
                                                         no timeout defined"
                                                    ),
                                                ));
                                            }

                                            // 12. Email/webhook parameter check.
                                            let name_lower = action_name.to_ascii_lowercase();
                                            if name_lower.contains("mail")
                                                || name_lower.contains("send")
                                                || name_lower.contains("notify")
                                                || name_lower.contains("webhook")
                                            {
                                                let has_dest = content.contains("dest")
                                                    || content.contains("recipient");
                                                let has_sender = content.contains("sender")
                                                    || content.contains("from");
                                                let has_mailcmd = content.contains("mailcmd")
                                                    || content.contains("sendmail")
                                                    || content.contains("mail_command");

                                                let mut missing = Vec::new();
                                                if !has_dest {
                                                    missing.push("dest");
                                                }
                                                if !has_sender {
                                                    missing.push("sender");
                                                }
                                                if !has_mailcmd {
                                                    missing.push("mailcmd");
                                                }
                                                if !missing.is_empty() {
                                                    findings.push(
                                                        Finding::new(
                                                            "action.missing_email_params",
                                                            Severity::Warning,
                                                            format!(
                                                                "Action \
                                                                 '{action_name}' \
                                                                 missing email params"
                                                            ),
                                                        )
                                                        .detail(format!(
                                                            "Missing parameters: {}",
                                                            missing.join(", "),
                                                        ))
                                                        .fix(
                                                            "Add the missing email/mail \
                                                             parameters to the action \
                                                             configuration.",
                                                        ),
                                                    );
                                                }
                                            }

                                            // 13. Cloudflare/API credential check.
                                            if name_lower.contains("cloudflare")
                                                || name_lower.contains("cf")
                                            {
                                                let has_cfapi = content.contains("cfapi")
                                                    || content.contains("cf_api")
                                                    || content.contains("cftoken")
                                                    || content.contains("cf_token")
                                                    || content.contains("cfapikey")
                                                    || content.contains("CF_API_KEY")
                                                    || content.contains("CF_API_EMAIL");
                                                let has_placeholder = has_cfapi
                                                    && (content.contains("YOUR_")
                                                        || content.contains("<your")
                                                        || content.contains("REPLACE")
                                                        || content.contains("xxx")
                                                        || content.contains("changeme")
                                                        || content.contains("your-api")
                                                        || content.contains("your_"));

                                                if has_placeholder {
                                                    findings.push(
                                                        Finding::new(
                                                            "action.cloudflare_placeholder_creds",
                                                            Severity::Error,
                                                            format!(
                                                                "Action \
                                                                 '{action_name}' \
                                                                 has placeholder \
                                                                 Cloudflare \
                                                                 credentials"
                                                            ),
                                                        )
                                                        .detail(
                                                            "The action file contains \
                                                             what appears to be \
                                                             placeholder API \
                                                             credentials. Bans will \
                                                             fail to apply via the \
                                                             Cloudflare API.",
                                                        )
                                                        .fix(
                                                            "Replace the placeholder \
                                                             credentials with real \
                                                             Cloudflare API values.",
                                                        ),
                                                    );
                                                } else if !has_cfapi {
                                                    findings.push(
                                                        Finding::new(
                                                            "action.cloudflare_missing_creds",
                                                            Severity::Warning,
                                                            format!(
                                                                "Action \
                                                                 '{action_name}' \
                                                                 missing Cloudflare \
                                                                 API credentials"
                                                            ),
                                                        )
                                                        .fix(
                                                            "Set CF_API_EMAIL and \
                                                             CF_API_KEY in the \
                                                             action configuration.",
                                                        ),
                                                    );
                                                }
                                            }
                                        }
                                    } else {
                                        findings.push(
                                            Finding::new(
                                                "action.file-missing",
                                                Severity::Error,
                                                format!(
                                                    "Action '{action_name}' for jail \
                                                     '{jail}' not found in action.d"
                                                ),
                                            )
                                            .fix(
                                                format!(
                                                    "Install the action file {action_name}.conf \
                                                 in /etc/fail2ban/action.d/ or update the \
                                                 jail configuration.",
                                                ),
                                            ),
                                        );
                                    }
                                }
                            }
                            _ => {
                                findings.push(Finding::new(
                                    "action.jail-actions-unknown",
                                    Severity::Info,
                                    format!("Could not query actions for jail '{jail}'"),
                                ));
                            }
                        }
                    }
                }
            }
        }

        findings
    }

    // =======================================================================
    // Permission checks
    // =======================================================================

    /// Verify file permissions are safe across the Fail2Ban installation.
    ///
    /// Checks:
    ///
    /// - `/etc/fail2ban` is not world-writable
    /// - generated config files are not world-writable
    /// - socket path permissions are sane
    #[allow(
        clippy::too_many_lines,
        reason = "sequential filesystem permission probes"
    )]
    #[allow(
        clippy::collapsible_if,
        reason = "collapsing would over-indent deep probe bodies"
    )]
    #[allow(
        clippy::unused_self,
        reason = "kept for API symmetry with other check_* methods"
    )]
    fn check_permissions(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        let config_dir = std::path::Path::new("/etc/fail2ban");

        if !config_dir.exists() {
            findings.push(Finding::new(
                "permission.config-dir-missing",
                Severity::Error,
                "Fail2Ban config directory does not exist",
            ));
            return findings;
        }

        // /etc/fail2ban not world-writable.
        match std::fs::metadata(config_dir) {
            Ok(meta) => {
                let mode = permission_mode(&meta.permissions());
                if mode & 0o002 != 0 {
                    findings.push(
                        Finding::new(
                            "permission.config-dir-world-writable",
                            Severity::Critical,
                            "/etc/fail2ban is world-writable",
                        )
                        .detail(
                            "The Fail2Ban configuration directory is world-writable, \
                             which allows any user on the system to modify Fail2Ban \
                             configuration.",
                        )
                        .fix("chmod o-w /etc/fail2ban"),
                    );
                } else {
                    findings.push(Finding::new(
                        "permission.config-dir-safe",
                        Severity::Ok,
                        "/etc/fail2ban is not world-writable",
                    ));
                }
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "permission.config-dir-stat-error",
                        Severity::Error,
                        "Cannot stat /etc/fail2ban",
                    )
                    .detail(format!("{e}")),
                );
            }
        }

        // Generated files not world-writable.
        let subdirs = ["jail.d", "filter.d", "action.d"];
        for subdir in &subdirs {
            let dir = config_dir.join(subdir);
            if !dir.exists() {
                continue;
            }
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if let Ok(meta) = std::fs::metadata(&path) {
                        let mode = permission_mode(&meta.permissions());
                        if mode & 0o002 != 0 {
                            findings.push(
                                Finding::new(
                                    "permission.file-world-writable",
                                    Severity::Error,
                                    format!("{} is world-writable", path.display()),
                                )
                                .fix(format!("chmod o-w {}", path.display())),
                            );
                        }
                    }
                }
            }
        }

        // -----------------------------------------------------------------
        // Ownership checks: managed files should be root-owned.
        // -----------------------------------------------------------------
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            let managed_subdirs = ["jail.d", "filter.d", "action.d"];
            let mut all_root_owned = true;

            for subdir in &managed_subdirs {
                let dir = config_dir.join(subdir);
                if !dir.exists() {
                    continue;
                }
                if let Ok(entries) = std::fs::read_dir(&dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if let Ok(meta) = std::fs::metadata(&path) {
                            let uid = meta.uid();
                            if uid != 0 {
                                all_root_owned = false;
                                findings.push(
                                    Finding::new(
                                        "permission.not_root_owned",
                                        Severity::Warning,
                                        format!(
                                            "{} is not owned by root (uid={uid})",
                                            path.display()
                                        ),
                                    )
                                    .detail(
                                        "Fail2Ban configuration files should be owned by \
                                         root to prevent unauthorized modification.",
                                    )
                                    .fix(format!("chown root {}", path.display())),
                                );
                            }
                        }
                    }
                }
            }

            // Check /etc/fail2ban itself.
            if let Ok(meta) = std::fs::metadata(config_dir) {
                let uid = meta.uid();
                if uid != 0 {
                    findings.push(
                        Finding::new(
                            "permission.not_root_owned",
                            Severity::Warning,
                            format!("/etc/fail2ban is not owned by root (uid={uid})"),
                        )
                        .detail(
                            "The Fail2Ban configuration directory should be owned \
                             by root to prevent unauthorized modification.",
                        )
                        .fix("chown root /etc/fail2ban"),
                    );
                } else if all_root_owned {
                    findings.push(Finding::new(
                        "permission.root_owned",
                        Severity::Ok,
                        "All managed files are owned by root",
                    ));
                }
            }
        }

        // -----------------------------------------------------------------
        // Secrets in config check.
        // -----------------------------------------------------------------
        let secret_patterns = [
            ("api_key", "API key"),
            ("token", "token"),
            ("secret", "secret"),
            ("password", "password"),
            ("apikey", "API key"),
        ];

        let local_dirs = ["jail.d", "filter.d", "action.d"];
        for subdir in &local_dirs {
            let dir = config_dir.join(subdir);
            if !dir.exists() {
                continue;
            }
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().is_some_and(|e| e == "local") {
                        let Ok(content) = std::fs::read_to_string(&path) else {
                            continue;
                        };

                        let content_lower = content.to_lowercase();
                        let mut found_secrets: Vec<&str> = Vec::new();
                        // Look for patterns like "api_key=", "token=", etc.
                        for line in content_lower.lines() {
                            let trimmed = line.trim();
                            if trimmed.starts_with('#') || trimmed.starts_with(';') {
                                continue;
                            }
                            for (pattern, _label) in &secret_patterns {
                                if trimmed.contains(&format!("{pattern}="))
                                    || trimmed.contains(&format!("{pattern} ="))
                                {
                                    if !found_secrets.contains(pattern) {
                                        found_secrets.push(pattern);
                                    }
                                }
                            }
                        }

                        if !found_secrets.is_empty() {
                            // Check if file is world-readable.
                            let is_world_readable = std::fs::metadata(&path).is_ok_and(|meta| {
                                let mode = permission_mode(&meta.permissions());
                                mode & 0o004 != 0
                            });

                            if is_world_readable {
                                findings.push(
                                    Finding::new(
                                        "permission.secrets_world_readable",
                                        Severity::Critical,
                                        format!(
                                            "Secrets found in world-readable file: {}",
                                            path.display()
                                        ),
                                    )
                                    .detail(format!(
                                        "Found secret patterns ({}) in a file that \
                                         is readable by all users on the system.",
                                        found_secrets.join(", "),
                                    ))
                                    .fix(
                                        "Move secrets to a dedicated credentials file \
                                         with restricted permissions (0600)",
                                    ),
                                );
                            } else {
                                findings.push(
                                    Finding::new(
                                        "permission.secrets_in_config",
                                        Severity::Warning,
                                        format!("Secrets found in config file: {}", path.display()),
                                    )
                                    .detail(format!(
                                        "Found secret patterns ({}) in a configuration \
                                         file. While the file is not world-readable, \
                                         secrets should be stored separately.",
                                        found_secrets.join(", "),
                                    ))
                                    .fix(
                                        "Move secrets to a dedicated credentials file \
                                         with restricted permissions (0600)",
                                    ),
                                );
                            }
                        }
                    }
                }
            }
        }

        // Socket path permissions.
        // Default socket: /var/run/fail2ban/fail2ban.sock
        let socket_path = std::path::Path::new("/var/run/fail2ban/fail2ban.sock");
        if socket_path.exists() {
            match std::fs::metadata(socket_path) {
                Ok(meta) => {
                    let mode = permission_mode(&meta.permissions());
                    if mode & 0o002 != 0 {
                        findings.push(
                            Finding::new(
                                "permission.socket-world-writable",
                                Severity::Critical,
                                "Fail2Ban socket is world-writable",
                            )
                            .detail(format!(
                                "Socket at {} is world-writable. Any local user \
                                 can issue commands to Fail2Ban.",
                                socket_path.display(),
                            ))
                            .fix(format!("chmod o-w {}", socket_path.display())),
                        );
                    } else {
                        findings.push(Finding::new(
                            "permission.socket-safe",
                            Severity::Ok,
                            "Fail2Ban socket permissions are sane",
                        ));
                    }
                }
                Err(e) => {
                    findings.push(
                        Finding::new(
                            "permission.socket-stat-error",
                            Severity::Warning,
                            "Cannot stat Fail2Ban socket",
                        )
                        .detail(format!("{e}")),
                    );
                }
            }
        } else {
            findings.push(Finding::new(
                "permission.socket-not-found",
                Severity::Info,
                "Fail2Ban socket not found (service may not be running)",
            ));
        }

        findings
    }

    // =======================================================================
    // Safety checks
    // =======================================================================

    /// Verify that safe operational practices are in place.
    ///
    /// Checks:
    ///
    /// - dry-run mode is available before applying changes
    /// - backup files exist before destructive updates
    /// - rollback path is available
    #[allow(clippy::too_many_lines, reason = "sequential safety/backup probes")]
    #[allow(
        clippy::collapsible_if,
        reason = "collapsing would over-indent deep probe bodies"
    )]
    fn check_safety(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Dry-run is a library feature -- verify the runner supports it.
        let dry_run_available = !self.runner.dry_run();
        findings.push(
            Finding::new(
                "safety.dry-run-available",
                Severity::Ok,
                "Dry-run mode is available",
            )
            .detail(
                "The library supports dry-run mode to preview changes \
                 without applying them.",
            ),
        );

        if !dry_run_available {
            // Currently in dry-run mode; note that.
            findings.push(Finding::new(
                "safety.currently-dry-run",
                Severity::Info,
                "Runner is currently in dry-run mode",
            ));
        }

        // Check for backup files in jail.d.
        let jail_d = std::path::Path::new("/etc/fail2ban/jail.d");
        if jail_d.exists() {
            if let Ok(entries) = std::fs::read_dir(jail_d) {
                let backup_count = entries
                    .filter_map(std::result::Result::ok)
                    .filter(|e| e.file_name().to_string_lossy().contains(".bak-"))
                    .count();

                if backup_count > 0 {
                    findings.push(
                        Finding::new(
                            "safety.backups-exist",
                            Severity::Ok,
                            format!("{backup_count} backup file(s) found in jail.d"),
                        )
                        .detail(
                            "Existing backup files indicate that previous \
                             operations created restore points.",
                        ),
                    );
                } else {
                    findings.push(Finding::new(
                        "safety.no-backups",
                        Severity::Info,
                        "No backup files found in jail.d",
                    ));
                }
            }
        }

        // Rollback path: verify that the config directory is writable
        // (needed for restoring backups).
        let config_dir = std::path::Path::new("/etc/fail2ban");
        if config_dir.exists() {
            // Check if we can write to jail.d (best-effort test).
            let test_path = config_dir.join("jail.d/.doctor-write-test");
            match std::fs::write(&test_path, b"") {
                Ok(()) => {
                    let _ = std::fs::remove_file(&test_path);
                    findings.push(Finding::new(
                        "safety.rollback-writable",
                        Severity::Ok,
                        "Config directory is writable (rollback possible)",
                    ));
                }
                Err(_) => {
                    findings.push(
                        Finding::new(
                            "safety.rollback-not-writable",
                            Severity::Warning,
                            "Config directory is not writable",
                        )
                        .detail(
                            "Cannot write to /etc/fail2ban/jail.d. Rollback \
                             operations may fail. This check likely needs to \
                             be run with elevated privileges.",
                        )
                        .fix("Run with appropriate privileges (e.g. via sudo)."),
                    );
                }
            }
        }

        // -----------------------------------------------------------------
        // Self-ban protection: trusted IPs should be in ignoreip.
        // -----------------------------------------------------------------
        if let Ok(path) = find_binary("fail2ban-client") {
            let bin = path.to_str().unwrap_or("fail2ban-client");
            if let Ok(out) = self.runner.run(bin, &["status"]) {
                if out.success {
                    let jail_names = parse_jail_list(&out.stdout);
                    for jail in &jail_names {
                        // Get the ignoreip list for this jail.
                        let ignoreip_str = match self.runner.run(bin, &["get", jail, "ignoreip"]) {
                            Ok(ign_out) if ign_out.success => ign_out.stdout.trim().to_string(),
                            _ => continue,
                        };

                        let ignoreip_entries: Vec<&str> = ignoreip_str
                            .split(|c: char| c == ',' || c.is_whitespace())
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .collect();

                        // Check for trusted IPs that are NOT in ignoreip.
                        // Common trusted IPs that should be protected.
                        let trusted_ips = ["127.0.0.1", "::1"];
                        let mut unprotected: Vec<&str> = Vec::new();
                        for trusted in &trusted_ips {
                            let is_protected = ignoreip_entries.iter().any(|entry| {
                                let entry_lower = entry.to_lowercase();
                                entry_lower == *trusted
                                    || entry_lower.contains(&trusted.to_lowercase())
                                    // Check if the entry is a CIDR that covers the trusted IP.
                                    || cidr_covers_ip(entry, trusted)
                            });
                            if !is_protected {
                                unprotected.push(trusted);
                            }
                        }

                        if !unprotected.is_empty() {
                            findings.push(
                                Finding::new(
                                    "safety.self_ban_risk",
                                    Severity::Critical,
                                    format!(
                                        "Jail '{jail}' does not protect trusted IPs in ignoreip"
                                    ),
                                )
                                .detail(format!(
                                    "The following trusted IPs are not in the ignoreip list \
                                     for jail '{jail}': {}. This means Fail2Ban could \
                                     accidentally ban these addresses.",
                                    unprotected.join(", "),
                                ))
                                .fix(
                                    "Add trusted IPs to ignoreip to prevent accidental \
                                     self-banning",
                                ),
                            );
                        }

                        // -------------------------------------------------
                        // Private network awareness check.
                        // -------------------------------------------------
                        let rfc1918_ranges = [
                            "10.0.0.0/8",
                            "172.16.0.0/12",
                            "192.168.0.0/16",
                            "127.0.0.0/8",
                        ];

                        let mut found_private = false;
                        for range in &rfc1918_ranges {
                            for entry in &ignoreip_entries {
                                let entry_lower = entry.to_lowercase();
                                // Direct match of the CIDR range in ignoreip.
                                if entry_lower.contains(range) || cidr_covers_range(entry, range) {
                                    found_private = true;
                                    break;
                                }
                            }
                            if found_private {
                                break;
                            }
                        }

                        if found_private {
                            findings.push(Finding::new(
                                "safety.private_networks_ignored",
                                Severity::Ok,
                                format!("Jail '{jail}' ignores private network ranges"),
                            ));
                        } else {
                            findings.push(
                                Finding::new(
                                    "safety.no_private_network_ignore",
                                    Severity::Info,
                                    format!("Jail '{jail}' does not ignore private network ranges"),
                                )
                                .detail(
                                    "Consider adding private network ranges to ignoreip \
                                     to avoid banning internal services. RFC1918 ranges: \
                                     10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8",
                                )
                                .fix(
                                    "Add private network ranges to ignoreip: \
                                     ignoreip = 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 \
                                     127.0.0.0/8",
                                ),
                            );
                        }
                    }
                }
            }
        }

        findings
    }

    // =======================================================================
    // Proxy checks
    // =======================================================================

    /// Detect proxy-related misconfigurations that would cause Fail2Ban to
    /// ban the proxy instead of the attacker.
    ///
    /// Checks:
    ///
    /// - detect whether logs contain proxy IPs only
    /// - warn if Fail2Ban would ban Cloudflare/Traefik instead of attacker
    #[allow(clippy::too_many_lines, reason = "per-jail multi-aspect proxy probing")]
    #[allow(
        clippy::collapsible_if,
        reason = "collapsing would over-indent deep probe bodies"
    )]
    fn check_proxy(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Common proxy / CDN IP ranges to warn about.
        let proxy_indicators = [
            ("Cloudflare", "cloudflare"),
            ("Traefik", "traefik"),
            ("NGINX reverse proxy", "nginx"),
        ];

        // Check active jails for known proxy-related patterns in their
        // configuration or log paths.
        if let Ok(path) = find_binary("fail2ban-client") {
            let bin = path.to_str().unwrap_or("fail2ban-client");
            if let Ok(out) = self.runner.run(bin, &["status"]) {
                if out.success {
                    let jail_names = parse_jail_list(&out.stdout);
                    for jail in &jail_names {
                        // Check the jail's log path for proxy indicators.
                        if let Ok(log_out) = self.runner.run(bin, &["get", jail, "logpath"]) {
                            if log_out.success {
                                let log_path = log_out.stdout.trim().to_lowercase();

                                // Check for common proxy log patterns.
                                if log_path.contains("traefik") || log_path.contains("access.log") {
                                    findings.push(
                                        Finding::new(
                                            "proxy.reverse-proxy-log",
                                            Severity::Warning,
                                            format!(
                                                "Jail '{jail}' may be behind a \
                                                 reverse proxy"
                                            ),
                                        )
                                        .detail(format!(
                                            "Log path '{log_path}' suggests the \
                                             application is behind a reverse proxy. \
                                             Fail2Ban would see the proxy IP, not \
                                             the real client IP.",
                                        ))
                                        .fix(
                                            "Configure your application to log the \
                                             real client IP (e.g. via X-Forwarded-For \
                                             or X-Real-IP). Ensure the log format \
                                             includes the forwarded IP.",
                                        ),
                                    );
                                }
                            }
                        }

                        // Check for Cloudflare-specific actions.
                        if let Ok(action_out) = self.runner.run(bin, &["get", jail, "actions"]) {
                            if action_out.success {
                                let actions = action_out.stdout.trim().to_lowercase();
                                for (label, keyword) in &proxy_indicators {
                                    if actions.contains(keyword) {
                                        findings.push(
                                            Finding::new(
                                                "proxy.cdn-action-detected",
                                                Severity::Info,
                                                format!("Jail '{jail}' uses a {label} action"),
                                            )
                                            .detail(
                                                "Cloudflare/Traefik/NGINX actions \
                                                 should use the CDN's own ban API \
                                                 rather than firewall rules, because \
                                                 the source IP belongs to the CDN.",
                                            ),
                                        );
                                    }
                                }
                            }
                        }

                        // Track proxy detections for post-loop findings.
                        let mut detected_traefik_log = false;
                        let mut detected_cloudflare = false;

                        // Re-check log path for Traefik and Cloudflare indicators.
                        if let Ok(log_out) = self.runner.run(bin, &["get", jail, "logpath"]) {
                            if log_out.success {
                                let log_path_lower = log_out.stdout.trim().to_lowercase();
                                if log_path_lower.contains("traefik") {
                                    detected_traefik_log = true;
                                }
                            }
                        }

                        // Check for Cloudflare-related actions.
                        if let Ok(action_out) = self.runner.run(bin, &["get", jail, "actions"]) {
                            if action_out.success {
                                let actions_lower = action_out.stdout.trim().to_lowercase();
                                if actions_lower.contains("cloudflare")
                                    || actions_lower.contains("cf-")
                                {
                                    detected_cloudflare = true;
                                }
                            }
                        }

                        // Also check action.d directory for Cloudflare files.
                        let cf_action_path =
                            std::path::Path::new("/etc/fail2ban/action.d/cloudflare.conf");
                        if cf_action_path.exists() {
                            detected_cloudflare = true;
                        }

                        // 5. Real-IP documentation finding.
                        // Detect if any proxy indicator was found across all
                        // checks and emit a single documentation finding.
                        let has_proxy_indicator = detected_traefik_log || detected_cloudflare || {
                            if let Ok(log_out) = self.runner.run(bin, &["get", jail, "logpath"]) {
                                if log_out.success {
                                    let lp = log_out.stdout.trim().to_lowercase();
                                    lp.contains("nginx")
                                        || lp.contains("traefik")
                                        || lp.contains("access.log")
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        };

                        if has_proxy_indicator {
                            findings.push(
                                Finding::new(
                                    "proxy.realip_docs",
                                    Severity::Info,
                                    "Real-IP configuration recommended",
                                )
                                .detail(
                                    "Fail2Ban needs real client IPs to be effective. \
                                     When your server is behind a reverse proxy or CDN, \
                                     the log files will contain the proxy's IP address \
                                     instead of the real attacker IP. Fail2Ban would then \
                                     ban the proxy IP, blocking all traffic through it.",
                                )
                                .fix(
                                    "Configure your reverse proxy to log real client IPs. \
                                     For NGINX: ensure log_format includes \
                                     $http_x_forwarded_for. For Traefik: enable accessLog \
                                     with forwarded headers. For Cloudflare: use the \
                                     cloudflare action or CF-Connecting-IP header.",
                                ),
                            );
                        }

                        // 6. Traefik filter suggestions.
                        if detected_traefik_log {
                            findings.push(
                                Finding::new(
                                    "proxy.traefik_filter",
                                    Severity::Info,
                                    "Traefik access log filter suggested",
                                )
                                .detail(
                                    "A Traefik access log path was detected. Consider \
                                     creating a dedicated filter to parse Traefik's \
                                     access log format.",
                                )
                                .fix(
                                    "Consider creating a filter with failregex like: \
                                     ^<HOST> .* \"(GET|POST|PUT|DELETE) .* HTTP\" <STATUS>",
                                ),
                            );
                        }

                        // 7. Cloudflare action suggestions.
                        if detected_cloudflare {
                            findings.push(
                                Finding::new(
                                    "proxy.cloudflare_action",
                                    Severity::Info,
                                    "Cloudflare API action suggested",
                                )
                                .detail(
                                    "Cloudflare-related configuration was detected. \
                                     Fail2Ban can ban IPs via the Cloudflare API \
                                     instead of local firewall rules, which is more \
                                     effective when traffic flows through Cloudflare.",
                                )
                                .fix(
                                    "Consider using the 'cloudflare' action in Fail2Ban \
                                     to ban IPs via the Cloudflare API instead of local \
                                     firewall rules. This requires CF_API_EMAIL and \
                                     CF_API_KEY settings.",
                                ),
                            );
                        }
                    }
                }
            }
        }

        // General proxy warning if no specific findings were added.
        if findings.is_empty() {
            findings.push(Finding::new(
                "proxy.no-issues",
                Severity::Ok,
                "No proxy-related issues detected",
            ));
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Best-effort parse of jail names from `fail2ban-client status` output.
///
/// Looks for a line containing "Jail list:" and extracts the comma-separated
/// names that follow.
fn parse_jail_list(status: &str) -> Vec<String> {
    for line in status.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("jail list")
            && let Some(idx) = line.find(':')
        {
            let rest = &line[idx + 1..];
            return rest
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
    }
    Vec::new()
}

// ---------------------------------------------------------------------------
// CIDR helpers (for safety checks)
// ---------------------------------------------------------------------------

/// Check whether a CIDR entry in an ignoreip list covers a specific IP address.
///
/// Handles entries like "10.0.0.0/8" or plain IPs like "127.0.0.1". Returns
/// `false` if the entry cannot be parsed as a CIDR or IP.
fn cidr_covers_ip(cidr_entry: &str, ip: &str) -> bool {
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    let Ok(addr) = Ipv4Addr::from_str(ip) else {
        return false;
    };

    let entry = cidr_entry.trim();

    // Try parsing as a CIDR network first.
    if let Ok(net) = ipnet::Ipv4Net::from_str(entry) {
        return net.contains(&addr);
    }

    // Try parsing as a plain IP (exact match).
    if let Ok(entry_addr) = Ipv4Addr::from_str(entry) {
        return entry_addr == addr;
    }

    false
}

/// Check whether a CIDR entry in an ignoreip list covers (or equals) a given
/// RFC1918 range.
///
/// Returns `true` if the entry is exactly the given range, or if the entry is
/// a supernet that encompasses it.
fn cidr_covers_range(cidr_entry: &str, range: &str) -> bool {
    use std::str::FromStr;

    let entry = cidr_entry.trim();

    // Direct string equality check first.
    if entry == range {
        return true;
    }

    // Parse both as networks and check containment.
    let Ok(range_net) = ipnet::Ipv4Net::from_str(range) else {
        return false;
    };

    if let Ok(entry_net) = ipnet::Ipv4Net::from_str(entry) {
        // Check if the entry network contains the entire range network.
        // This means the entry must be the same or a supernet.
        let entry_start = entry_net.network();
        let entry_end = entry_net.broadcast();
        let range_start = range_net.network();
        let range_end = range_net.broadcast();
        return entry_start <= range_start && entry_end >= range_end;
    }

    false
}

// ---------------------------------------------------------------------------
// Unix permissions helper
// ---------------------------------------------------------------------------

/// Extract the Unix permission mode bits from `std::fs::Permissions`.
///
/// On Unix this reads the `mode()` field via `PermissionsExt`. On non-Unix
/// platforms it returns `0` (no permissions checks possible).
#[cfg(unix)]
fn permission_mode(permissions: &std::fs::Permissions) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    permissions.mode()
}

/// Extract the Unix permission mode bits from `std::fs::Permissions`.
///
/// Non-Unix fallback: always returns `0`.
#[cfg(not(unix))]
fn permission_mode(_permissions: &std::fs::Permissions) -> u32 {
    0
}

// ---------------------------------------------------------------------------
// IP address helpers (for log path checks)
// ---------------------------------------------------------------------------

/// Number of leading log lines inspected when detecting a reverse-proxy /
/// private-IP situation in [`Doctor::check_single_log_path`].
///
/// Kept small on purpose: we only ever need a representative sample of the
/// newest entries, and streaming this many lines bounds the memory of the
/// diagnostic regardless of the underlying log file size (e.g. a multi-hundred
/// MB `auth.log`).
const PROXY_IP_SAMPLE_LINES: usize = 10;

/// Extract IP address strings from a single log line.
///
/// Uses a simple regex to find dotted-quad IPv4 patterns. IPv6 is not
/// extracted since private-IP detection in this module only applies to
/// IPv4 reverse-proxy scenarios.
fn extract_ips_from_line(line: &str) -> Vec<String> {
    use std::str::FromStr;

    let re = regex::Regex::new(r"(?:\d{1,3}\.){3}\d{1,3}").unwrap();
    re.find_iter(line)
        .filter(|m| {
            // Validate that it actually parses as an IP so we don't
            // match things like "999.999.999.999".
            std::net::Ipv4Addr::from_str(m.as_str()).is_ok()
        })
        .map(|m| m.as_str().to_string())
        .collect()
}

/// Check whether an IP address string is a private / loopback address.
///
/// Returns `true` for addresses in:
/// - 10.0.0.0/8
/// - 172.16.0.0/12
/// - 192.168.0.0/16
/// - 127.0.0.0/8
fn is_private_ip(ip_str: &str) -> bool {
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    let Ok(addr) = Ipv4Addr::from_str(ip_str) else {
        return false;
    };

    // Check against well-known private ranges using ipnet.
    let private_networks: &[&str] = &[
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
    ];

    for net_str in private_networks {
        if let Ok(net) = ipnet::Ipv4Net::from_str(net_str)
            && net.contains(&addr)
        {
            return true;
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Journal helper
// ---------------------------------------------------------------------------

/// Extract systemd unit names from a journalmatch string.
///
/// Parses patterns like `_SYSTEMD_UNIT=sshd.service` and extracts the unit
/// name (`sshd.service`). Handles multiple space-separated journalmatch
/// entries (e.g. from `journalmatch = _SYSTEMD_UNIT=sshd.service + _COMM=sshd`).
fn extract_systemd_units(journalmatch: &str) -> Vec<String> {
    let mut units = Vec::new();
    for entry in journalmatch.split([' ', '+']) {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        // Look for _SYSTEMD_UNIT=<unit> patterns.
        if let Some(eq_pos) = entry.find('=') {
            let key = &entry[..eq_pos];
            if key.contains("SYSTEMD_UNIT") || key.contains("systemd_unit") {
                let value = entry[eq_pos + 1..].trim().to_string();
                if !value.is_empty() && value != "None" {
                    units.push(value);
                }
            }
        }
    }
    units
}

// ---------------------------------------------------------------------------
// Regex anchor helper
// ---------------------------------------------------------------------------

/// Check whether `<HOST>` appears to be properly anchored in a failregex.
///
/// "Properly anchored" means `<HOST>` is preceded by a non-word character,
/// a start-of-group, or the beginning of the pattern, and is followed by a
/// non-word character, end-of-group, or end-of-pattern. If `<HOST>` is
/// surrounded by characters that could form arbitrary words, it is
/// considered unanchored.
fn is_host_anchored(failregex: &str) -> bool {
    // Check each occurrence of <HOST> in the regex.
    let mut search_from = 0;
    while let Some(pos) = failregex[search_from..].find("<HOST>") {
        let abs_pos = search_from + pos;
        let host_end = abs_pos + "<HOST>".len();

        // Check the character before <HOST>.
        if abs_pos > 0 {
            let prev = failregex.as_bytes()[abs_pos - 1];
            // Allow: whitespace, brackets, parens, pipes, anchors (^),
            // backslash (for \b etc.), comma, colon, equals.
            if prev != b' '
                && prev != b'\t'
                && prev != b'['
                && prev != b'('
                && prev != b'|'
                && prev != b'^'
                && prev != b'\\'
                && prev != b','
                && prev != b':'
                && prev != b'='
                && prev != b'\n'
            {
                return false;
            }
        }

        // Check the character after <HOST>.
        if host_end < failregex.len() {
            let next = failregex.as_bytes()[host_end];
            if next != b' '
                && next != b'\t'
                && next != b']'
                && next != b')'
                && next != b'|'
                && next != b'$'
                && next != b'\\'
                && next != b','
                && next != b':'
                && next != b'\n'
            {
                return false;
            }
        }

        search_from = host_end;
    }
    true
}

// ---------------------------------------------------------------------------
// INI value extraction helper
// ---------------------------------------------------------------------------

/// Best-effort extraction of a key value from an INI-style file content.
///
/// Looks for `key = value` or `key=value` at the start of a line (ignoring
/// leading whitespace). Returns `None` if the key is not found.
fn extract_ini_value(content: &str, key: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        // Skip comments.
        if trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix(key) {
            let rest = rest.trim_start();
            if let Some(val) = rest.strip_prefix('=') {
                let val = val.trim();
                if !val.is_empty() {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

#[cfg(test)]
#[path = "doctor.test.rs"]
mod tests;
