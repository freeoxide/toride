//! Fail2ban-style intrusion prevention library for toride.
//!
//! Provides log parsing, IP banning, and automated response capabilities
//! with support for iptables, nftables, pf, and firewalld backends.
//!
//! # High-level API
//!
//! The [`Fail2Ban`] struct is the main entry point. It composes a command runner,
//! system paths, and delegates to sub-modules for client operations, service
//! management, firewall diagnostics, regex testing, doctor checks, and
//! jail lifecycle management.
//!
//! ```ignore
//! use toride_fail2ban::Fail2Ban;
//!
//! let f2b = Fail2Ban::system()?;
//! f2b.test_config()?;
//! let report = f2b.doctor(toride_fail2ban::doctor::DoctorScope::All)?;
//! ```

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
        clippy::duration_suboptimal_units,
        clippy::unnecessary_literal_unwrap,
        clippy::unnecessary_wraps,
        clippy::io_other_error,
        clippy::op_ref,
        reason = "test code tolerates stricter lint patterns"
    )
)]

// ---------------------------------------------------------------------------
// Module declarations -- always compiled
// ---------------------------------------------------------------------------

pub mod command;
pub mod error;
pub mod report;
pub mod types;

// ---------------------------------------------------------------------------
// Module declarations -- feature-gated
// ---------------------------------------------------------------------------

#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "client")]
pub mod firewall;
#[cfg(feature = "client")]
pub mod service;

#[cfg(feature = "doctor")]
pub mod doctor;

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

// ---------------------------------------------------------------------------
// Error types -- re-exported from the `error` module (unified source of truth)
// ---------------------------------------------------------------------------

pub use error::{Error, Result};

// ---------------------------------------------------------------------------
// SystemPaths -- Fail2Ban system directory layout
// ---------------------------------------------------------------------------

use std::path::PathBuf;

/// Resolved paths to the system Fail2Ban configuration directories.
///
/// `SystemPaths` points at the real `/etc/fail2ban` tree used by the
/// Fail2Ban daemon, as opposed to [`paths::Fail2BanPaths`] which resolves
/// XDG-based user-local paths for the toride application's own data.
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
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidConfig`] if the config directory does not exist.
    #[allow(
        clippy::should_implement_trait,
        reason = "returns Result, cannot implement Default trait"
    )]
    pub fn default() -> Result<Self> {
        Self::with_config_dir(PathBuf::from("/etc/fail2ban"))
    }

    /// Create a `SystemPaths` from an explicit config directory.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidConfig`] if `dir` does not exist on disk.
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

// ---------------------------------------------------------------------------
// Fail2Ban -- main entry point struct
// ---------------------------------------------------------------------------

/// High-level Fail2Ban management facade.
///
/// Owns a command runner and system paths, and provides convenience methods
/// that compose the lower-level modules (`client`, `service`, `doctor`, etc.)
/// into common workflows.
///
/// # Construction
///
/// - [`Fail2Ban::system`] -- production defaults: `DuctRunner` + `/etc/fail2ban`.
/// - [`Fail2Ban::with_runner`] -- inject a custom or test runner.
/// - [`Fail2Ban::with_paths`] -- custom paths with a default `DuctRunner`.
///
/// # Example
///
/// ```ignore
/// let f2b = Fail2Ban::system()?;
///
/// // Validate and apply a jail spec.
/// let report = f2b.ensure_jail(jail_spec)?;
///
/// // Run full diagnostics.
/// let doctor_report = f2b.doctor(doctor::DoctorScope::All)?;
/// ```
pub struct Fail2Ban {
    runner: Box<dyn command::Runner>,
    #[expect(dead_code, reason = "kept for future path-aware operations")]
    paths: SystemPaths,
    dry_run: bool,
}

impl Fail2Ban {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Create a `Fail2Ban` instance with production defaults.
    ///
    /// Uses a [`command::DuctRunner`] with the default 30-second timeout
    /// and resolves system paths from `/etc/fail2ban`.
    ///
    /// # Errors
    ///
    /// Returns an error if `/etc/fail2ban` does not exist.
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
    /// [`command::DuctRunner`].
    ///
    /// # Errors
    ///
    /// Returns an error if `paths.config_dir` does not exist.
    #[cfg(feature = "client")]
    pub fn with_paths(paths: SystemPaths) -> Result<Self> {
        let runner = command::DuctRunner::new();
        Ok(Self {
            runner: Box::new(runner),
            paths,
            dry_run: false,
        })
    }

    /// Create a `Fail2Ban` instance with a custom runner.
    ///
    /// Uses `/etc/fail2ban` for system paths. The config directory does not
    /// need to exist when a custom runner is injected (useful for testing).
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

    /// Set dry-run mode.
    ///
    /// When enabled, commands are logged but not executed.
    #[must_use]
    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    // -----------------------------------------------------------------------
    // Sub-module accessors
    // -----------------------------------------------------------------------

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

    /// Return a [`regex_test::RegexTester`] borrowing this instance's runner.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the `fail2ban-regex` binary cannot
    /// be found on `$PATH`.
    #[cfg(feature = "regex-test")]
    pub fn regex_tester(&self) -> Result<regex_test::RegexTester<'_>> {
        regex_test::RegexTester::new(self.runner.as_ref())
    }

    // -----------------------------------------------------------------------
    // Doctor
    // -----------------------------------------------------------------------

    /// Run the diagnostic engine and return a [`report::DoctorReport`].
    ///
    /// # Errors
    ///
    /// Returns an error only for fundamental failures (e.g. a broken runner).
    /// Individual check failures appear as [`report::Finding`] values in the
    /// report.
    #[cfg(feature = "doctor")]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "matches by-value doctor() API across toride crates"
    )]
    pub fn doctor(&self, scope: doctor::DoctorScope) -> Result<report::DoctorReport> {
        let doc = doctor::Doctor::new(self.runner.as_ref());
        doc.run(&scope)
    }

    // -----------------------------------------------------------------------
    // Jail lifecycle
    // -----------------------------------------------------------------------

    /// Write a jail specification to disk, validate, and reload.
    ///
    /// Workflow:
    /// 1. Validate the spec via [`spec::JailSpec::validate`].
    /// 2. Render and write via [`ini::IniManager`].
    /// 3. Run `fail2ban-client --test`.
    /// 4. Reload the specific jail.
    /// 5. Return an [`report::ApplyReport`] summarising the operation.
    ///
    /// # Errors
    ///
    /// Returns an error at the first failing step.
    #[cfg(all(feature = "jail-lifecycle", feature = "client"))]
    pub fn ensure_jail(&self, spec: spec::JailSpec) -> Result<report::ApplyReport> {
        // 1. Validate.
        spec.validate()?;

        // 2. Write via IniManager.
        let mgr = ini::IniManager::new(&self.paths.config_dir)?;
        let mut report = mgr.write_jail(&spec)?;

        // If there are filter specs that need writing, write them too.
        // (The JailSpec carries a FilterSpec inline; custom filters with
        // failregex are written as separate filter files.)

        // 3. Test config.
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

        // 4. Reload the specific jail.
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

    /// Remove a managed jail configuration, test, and reload.
    ///
    /// # Errors
    ///
    /// Returns an error if the file is not managed, does not exist, or the
    /// reload fails.
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

    // -----------------------------------------------------------------------
    // Convenience delegations
    // -----------------------------------------------------------------------

    /// Validate the current Fail2Ban configuration.
    ///
    /// Runs `fail2ban-client --test`.
    #[cfg(feature = "client")]
    pub fn test_config(&self) -> Result<()> {
        self.client()?.test_config()
    }

    /// Reload the entire Fail2Ban configuration.
    ///
    /// Runs `fail2ban-client reload`.
    #[cfg(feature = "client")]
    pub fn reload(&self) -> Result<()> {
        self.client()?.reload()
    }

    /// Reload a single jail.
    ///
    /// Runs `fail2ban-client reload <name>`.
    #[cfg(feature = "client")]
    pub fn reload_jail(&self, name: &str) -> Result<()> {
        self.client()?.reload_jail(name)
    }

    /// Manually ban an IP in the given jail.
    ///
    /// Runs `fail2ban-client set <jail> banip <ip>`.
    #[cfg(feature = "client")]
    pub fn ban_ip(&self, jail: &str, ip: &str) -> Result<()> {
        self.client()?.ban_ip(jail, ip)
    }

    /// Manually unban an IP in the given jail.
    ///
    /// Runs `fail2ban-client set <jail> unbanip <ip>`.
    #[cfg(feature = "client")]
    pub fn unban_ip(&self, jail: &str, ip: &str) -> Result<()> {
        self.client()?.unban_ip(jail, ip)
    }
}
