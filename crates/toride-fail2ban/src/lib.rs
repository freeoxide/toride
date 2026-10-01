//! Fail2ban-style intrusion prevention library for toride: log parsing,
//! IP banning, and automated response via iptables/nftables/pf/firewalld.

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![expect(
    clippy::must_use_candidate,
    reason = "constructors and getters are obvious"
)]
#![expect(clippy::missing_errors_doc, reason = "library is internal")]
#![expect(clippy::doc_markdown, reason = "Fail2Ban is a well-known name")]
#![cfg_attr(
    test,
    expect(
        clippy::uninlined_format_args,
        clippy::redundant_closure_for_method_calls,
        clippy::unnecessary_literal_unwrap,
        clippy::unnecessary_wraps,
        clippy::io_other_error,
        clippy::op_ref,
        reason = "test code tolerates stricter lint patterns"
    )
)]

pub mod command;
pub mod error;
pub mod report;
pub mod types;

#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "client")]
pub mod firewall;
#[cfg(feature = "client")]
pub mod service;

#[cfg(feature = "doctor")]
pub mod doctor;

/// Spawn-counting oracle for `DoctorScope::All`; unit tests only.
#[cfg(all(test, feature = "doctor"))]
pub mod spawn_oracle;

#[cfg(feature = "config")]
pub mod action;
#[cfg(feature = "config")]
pub mod ban;
#[cfg(feature = "config")]
pub mod config;
#[cfg(feature = "config")]
pub mod detector;
#[cfg(feature = "config")]
pub mod jail;
#[cfg(feature = "config")]
pub mod manager;
#[cfg(feature = "config")]
pub mod paths;
#[cfg(feature = "config")]
pub mod store;
#[cfg(feature = "config")]
pub mod support;

#[cfg(feature = "jail-lifecycle")]
pub mod ini;
#[cfg(feature = "jail-lifecycle")]
pub mod render;
#[cfg(feature = "jail-lifecycle")]
pub mod spec;

#[cfg(feature = "regex-test")]
pub mod regex_test;

#[cfg(feature = "cli")]
pub mod cli;

pub use error::{Error, Result};

use std::path::PathBuf;

/// Resolved paths to the system `/etc/fail2ban` tree used by the daemon,
/// unlike [`paths::Fail2BanPaths`] (XDG user-local paths for toride's own data).
#[derive(Debug, Clone)]
pub struct SystemPaths {
    /// Root Fail2Ban configuration directory (e.g. `/etc/fail2ban`).
    pub config_dir: PathBuf,
    /// Jail drop-in directory (`{config_dir}/jail.d`).
    pub jail_d: PathBuf,
    /// Filter drop-in directory (`{config_dir}/filter.d`).
    pub filter_d: PathBuf,
    /// Action drop-in directory (`{config_dir}/action.d`).
    pub action_d: PathBuf,
}

impl SystemPaths {
    /// Create a `SystemPaths` from the default `/etc/fail2ban` location.
    /// Errors with [`Error::InvalidConfig`] if the config directory does not exist.
    #[allow(
        clippy::should_implement_trait,
        reason = "returns Result, cannot implement Default trait"
    )]
    pub fn default() -> Result<Self> {
        Self::with_config_dir(PathBuf::from("/etc/fail2ban"))
    }

    /// Create a `SystemPaths` from an explicit config directory.
    /// Errors with [`Error::InvalidConfig`] if `dir` does not exist on disk.
    pub fn with_config_dir(dir: PathBuf) -> Result<Self> {
        if !dir.is_dir() {
            return Err(Error::InvalidConfig(format!(
                "Fail2Ban config directory does not exist: {}",
                dir.display()
            )));
        }
        Ok(Self {
            jail_d: dir.join("jail.d"),
            filter_d: dir.join("filter.d"),
            action_d: dir.join("action.d"),
            config_dir: dir,
        })
    }

    /// Returns the path for a managed jail config file.
    pub fn jail_path(&self, name: &str, namespace: &str) -> PathBuf {
        self.jail_d.join(format!("{namespace}-{name}.local"))
    }

    /// Returns the path for a managed filter config file.
    pub fn filter_path(&self, name: &str, namespace: &str) -> PathBuf {
        self.filter_d.join(format!("{namespace}-{name}.local"))
    }

    /// Returns the path for a managed action config file.
    pub fn action_path(&self, name: &str, namespace: &str) -> PathBuf {
        self.action_d.join(format!("{namespace}-{name}.local"))
    }
}

/// High-level Fail2Ban management facade: owns a command runner and system
/// paths, composing the client/service/doctor/jail-lifecycle modules.
pub struct Fail2Ban {
    runner: Box<dyn command::Runner>,
    #[expect(dead_code, reason = "kept for future path-aware operations")]
    paths: SystemPaths,
    dry_run: bool,
}

impl Fail2Ban {
    /// Create a `Fail2Ban` instance with production defaults: a [`command::DuctRunner`]
    /// (30s timeout) and `/etc/fail2ban` paths; errors if that directory is missing.
    #[cfg(feature = "client")]
    pub fn system() -> Result<Self> {
        let runner = command::DuctRunner::new();
        let paths = SystemPaths::default()?;
        Ok(Self {
            runner: Box::new(runner),
            paths,
            dry_run: false,
        })
    }

    /// Create a `Fail2Ban` instance with explicit system paths and a default
    /// [`command::DuctRunner`]; errors if `paths.config_dir` does not exist.
    #[cfg(feature = "client")]
    pub fn with_paths(paths: SystemPaths) -> Result<Self> {
        let runner = command::DuctRunner::new();
        Ok(Self {
            runner: Box::new(runner),
            paths,
            dry_run: false,
        })
    }

    /// Create a `Fail2Ban` instance with a custom runner and `/etc/fail2ban`
    /// paths; the config directory need not exist (useful for testing).
    pub fn with_runner(runner: Box<dyn command::Runner>) -> Self {
        let paths = SystemPaths {
            config_dir: PathBuf::from("/etc/fail2ban"),
            jail_d: PathBuf::from("/etc/fail2ban/jail.d"),
            filter_d: PathBuf::from("/etc/fail2ban/filter.d"),
            action_d: PathBuf::from("/etc/fail2ban/action.d"),
        };
        Self {
            runner,
            paths,
            dry_run: false,
        }
    }

    /// Set dry-run mode: commands are logged but not executed.
    #[must_use]
    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    /// Return a [`client::Fail2BanClient`] borrowing this instance's runner.
    #[cfg(feature = "client")]
    pub fn client(&self) -> Result<client::Fail2BanClient<'_>> {
        client::Fail2BanClient::new(self.runner.as_ref())
    }

    /// Return a [`service::ServiceManager`] borrowing this instance's runner.
    #[cfg(feature = "client")]
    pub fn service(&self) -> service::ServiceManager<'_> {
        service::ServiceManager::new(self.runner.as_ref())
    }

    /// Return a [`firewall::FirewallChecker`] borrowing this instance's runner.
    #[cfg(feature = "client")]
    pub fn firewall(&self) -> firewall::FirewallChecker<'_> {
        firewall::FirewallChecker::new(self.runner.as_ref())
    }

    /// Return a [`regex_test::RegexTester`] borrowing this instance's runner;
    /// errors with [`Error::NotFound`] if `fail2ban-regex` is not on `$PATH`.
    #[cfg(feature = "regex-test")]
    pub fn regex_tester(&self) -> Result<regex_test::RegexTester<'_>> {
        regex_test::RegexTester::new(self.runner.as_ref())
    }

    /// Run the diagnostic engine and return a [`report::DoctorReport`]; errors
    /// only on fundamental failures — check failures arrive as [`report::Finding`]s.
    #[cfg(feature = "doctor")]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "matches by-value doctor() API across toride crates"
    )]
    pub fn doctor(&self, scope: doctor::DoctorScope) -> Result<report::DoctorReport> {
        let doc = doctor::Doctor::new(self.runner.as_ref());
        doc.run(&scope)
    }

    /// Write a jail specification to disk, validate it, test the config, and
    /// reload the jail; errors at the first failing step.
    #[cfg(all(feature = "jail-lifecycle", feature = "client"))]
    pub fn ensure_jail(&self, spec: spec::JailSpec) -> Result<report::ApplyReport> {
        spec.validate()?;

        let mgr = ini::IniManager::new(&self.paths.config_dir)?;
        let mut report = mgr.write_jail(&spec)?;

        match self.test_config() {
            Ok(()) => {
                report.test_passed = true;
            }
            Err(e) => {
                report.test_passed = false;
                report.findings.push(
                    report::Finding::new(
                        "apply.test-config-failed",
                        report::Severity::Error,
                        "Config test failed after writing jail",
                    )
                    .detail(format!("{e}"))
                    .fix("Review the generated config and fix any syntax errors."),
                );
                return Ok(report);
            }
        }

        match self.reload_jail(spec.name.as_str()) {
            Ok(()) => {
                report.reload_result = Some("ok".to_owned());
            }
            Err(e) => {
                report.reload_result = Some(format!("reload failed: {e}"));
                report.findings.push(
                    report::Finding::new(
                        "apply.reload-failed",
                        report::Severity::Warning,
                        "Reload failed after writing jail",
                    )
                    .detail(format!("{e}"))
                    .fix("Try reloading manually: fail2ban-client reload"),
                );
            }
        }

        Ok(report)
    }

    /// Remove a managed jail configuration, then test and reload; errors if
    /// the file is not managed, missing, or the reload fails.
    #[cfg(all(feature = "jail-lifecycle", feature = "client"))]
    pub fn remove_jail(&self, name: &str) -> Result<report::ApplyReport> {
        let mgr = ini::IniManager::new(&self.paths.config_dir)?;
        let mut report = mgr.remove_jail(name)?;

        match self.test_config() {
            Ok(()) => {
                report.test_passed = true;
            }
            Err(e) => {
                report.test_passed = false;
                report.reload_result = Some(format!("test failed: {e}"));
            }
        }

        if report.test_passed {
            match self.reload() {
                Ok(()) => {
                    report.reload_result = Some("ok".to_owned());
                }
                Err(e) => {
                    report.reload_result = Some(format!("reload failed: {e}"));
                }
            }
        }

        Ok(report)
    }

    /// Validate the current Fail2Ban configuration (`fail2ban-client --test`).
    #[cfg(feature = "client")]
    pub fn test_config(&self) -> Result<()> {
        self.client()?.test_config()
    }

    /// Reload the entire Fail2Ban configuration (`fail2ban-client reload`).
    #[cfg(feature = "client")]
    pub fn reload(&self) -> Result<()> {
        self.client()?.reload()
    }

    /// Reload a single jail (`fail2ban-client reload <name>`).
    #[cfg(feature = "client")]
    pub fn reload_jail(&self, name: &str) -> Result<()> {
        self.client()?.reload_jail(name)
    }

    /// Manually ban an IP in the given jail (`fail2ban-client set <jail> banip <ip>`).
    #[cfg(feature = "client")]
    pub fn ban_ip(&self, jail: &str, ip: &str) -> Result<()> {
        self.client()?.ban_ip(jail, ip)
    }

    /// Manually unban an IP in the given jail (`fail2ban-client set <jail> unbanip <ip>`).
    #[cfg(feature = "client")]
    pub fn unban_ip(&self, jail: &str, ip: &str) -> Result<()> {
        self.client()?.unban_ip(jail, ip)
    }
}
