//! Linux audit daemon, file integrity monitoring, and log management for toride.
//!
//! Provides audit rule management, AIDE file integrity monitoring, log
//! aggregation via rsyslog/journald, and intrusion detection integration.
//!
//! # High-level API
//!
//! The [`Audit`] struct is the main entry point. It composes a command runner,
//! system paths, and delegates to sub-modules for auditd operations, integrity
//! checks, log management, doctor diagnostics, and configuration management.
//!
//! ```ignore
//! use toride_audit::Audit;
//!
//! let audit = Audit::system()?;
//! let report = audit.doctor(toride_audit::doctor::DoctorScope::All)?;
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![expect(
    clippy::must_use_candidate,
    reason = "constructors and getters are obvious"
)]
#![expect(clippy::missing_errors_doc, reason = "library is internal")]

// ---------------------------------------------------------------------------
// Module declarations -- always compiled
// ---------------------------------------------------------------------------

pub mod backup;
pub mod diff;
pub mod error;
pub mod parse;
pub mod paths;
pub mod render;
pub mod report;
pub mod spec;
pub mod validate;

// ---------------------------------------------------------------------------
// Module declarations -- feature-gated: client
// ---------------------------------------------------------------------------

#[cfg(feature = "client")]
pub mod client;

// ---------------------------------------------------------------------------
// Module declarations -- feature-gated: service
// ---------------------------------------------------------------------------

#[cfg(feature = "service")]
pub mod service;

// ---------------------------------------------------------------------------
// Module declarations -- feature-gated: doctor
// ---------------------------------------------------------------------------

#[cfg(feature = "doctor")]
pub mod doctor;

// ---------------------------------------------------------------------------
// Module declarations -- feature-gated: config
// ---------------------------------------------------------------------------

#[cfg(feature = "config")]
pub mod config;

// ---------------------------------------------------------------------------
// Module declarations -- feature-gated: auditd
// ---------------------------------------------------------------------------

#[cfg(feature = "auditd")]
pub mod auditd;
#[cfg(feature = "auditd")]
pub mod auditd_config;
#[cfg(feature = "auditd")]
pub mod auditd_presets;
#[cfg(feature = "auditd")]
pub mod auditd_rules;

// ---------------------------------------------------------------------------
// Module declarations -- feature-gated: integrity
// ---------------------------------------------------------------------------

#[cfg(feature = "integrity")]
pub mod integrity;
#[cfg(feature = "integrity")]
pub mod integrity_config;
#[cfg(feature = "integrity")]
pub mod integrity_parse;

// ---------------------------------------------------------------------------
// Module declarations -- feature-gated: logs
// ---------------------------------------------------------------------------

#[cfg(feature = "logs")]
pub mod logs;
#[cfg(feature = "logs")]
pub mod logs_journald;
#[cfg(feature = "logs")]
pub mod logs_rotation;
#[cfg(feature = "logs")]
pub mod logs_rsyslog;

// ---------------------------------------------------------------------------
// Module declarations -- feature-gated: ids
// ---------------------------------------------------------------------------

#[cfg(feature = "ids")]
pub mod ids;

// ---------------------------------------------------------------------------
// Module declarations -- feature-gated: cli
// ---------------------------------------------------------------------------

#[cfg(feature = "cli")]
pub mod cli;

// ---------------------------------------------------------------------------
// Error types -- re-exported from the `error` module (unified source of truth)
// ---------------------------------------------------------------------------

pub use error::{Error, Result};

// ---------------------------------------------------------------------------
// AuditPaths -- Audit system directory layout
// ---------------------------------------------------------------------------

use std::path::PathBuf;

/// Resolved paths to the system audit configuration directories.
///
/// `AuditPaths` points at the real `/etc/audit`, `/etc/aide.conf`, and
/// related configuration files used by the audit daemon, AIDE, and
/// log aggregation services.
#[derive(Debug, Clone)]
pub struct AuditPaths {
    /// Audit daemon configuration directory (e.g. `/etc/audit`).
    pub audit_dir: PathBuf,
    /// Audit rules directory (`{audit_dir}/rules.d`).
    pub rules_d: PathBuf,
    /// AIDE configuration file path (e.g. `/etc/aide.conf`).
    pub aide_conf: PathBuf,
    /// AIDE database directory (e.g. `/var/lib/aide`).
    pub aide_db_dir: PathBuf,
    /// rsyslog configuration file path (e.g. `/etc/rsyslog.conf`).
    pub rsyslog_conf: PathBuf,
    /// rsyslog drop-in directory (`/etc/rsyslog.d`).
    pub rsyslog_d: PathBuf,
    /// Logrotate configuration directory (`/etc/logrotate.d`).
    pub logrotate_d: PathBuf,
}

impl AuditPaths {
    /// Create an `AuditPaths` with default system paths.
    ///
    /// Uses standard Linux FHS paths for audit, AIDE, rsyslog, and logrotate.
    #[must_use]
    pub fn default_system() -> Self {
        Self {
            audit_dir: PathBuf::from("/etc/audit"),
            rules_d: PathBuf::from("/etc/audit/rules.d"),
            aide_conf: PathBuf::from("/etc/aide.conf"),
            aide_db_dir: PathBuf::from("/var/lib/aide"),
            rsyslog_conf: PathBuf::from("/etc/rsyslog.conf"),
            rsyslog_d: PathBuf::from("/etc/rsyslog.d"),
            logrotate_d: PathBuf::from("/etc/logrotate.d"),
        }
    }

    /// Create an `AuditPaths` with an explicit audit directory.
    #[must_use]
    pub fn with_audit_dir(dir: PathBuf) -> Self {
        Self {
            rules_d: dir.join("rules.d"),
            audit_dir: dir,
            ..Self::default_system()
        }
    }

    /// Returns the path for a managed audit rules file.
    #[must_use]
    pub fn rules_path(&self, name: &str) -> PathBuf {
        self.rules_d.join(format!("{name}.rules"))
    }
}

// ---------------------------------------------------------------------------
// Audit -- main entry point struct
// ---------------------------------------------------------------------------

/// High-level audit management facade.
///
/// Owns a command runner and system paths, and provides convenience methods
/// that compose the lower-level modules (`client`, `service`, `doctor`, etc.)
/// into common workflows.
///
/// # Construction
///
/// - [`Audit::system`] -- production defaults: `DuctRunner` + default system paths.
/// - [`Audit::with_runner`] -- inject a custom or test runner.
/// - [`Audit::with_paths`] -- custom paths with a default `DuctRunner`.
///
/// # Example
///
/// ```ignore
/// let audit = Audit::system()?;
///
/// // Run full diagnostics.
/// let report = audit.doctor(doctor::DoctorScope::All)?;
/// ```
pub struct Audit {
    runner: Box<dyn toride_runner::Runner>,
    paths: AuditPaths,
    dry_run: bool,
}

impl Audit {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Create an `Audit` instance with production defaults.
    ///
    /// Uses a [`toride_runner::DuctRunner`] with the default 60-second timeout
    /// and resolves system paths from standard Linux locations.
    #[cfg(feature = "client")]
    pub fn system() -> Result<Self> {
        let runner = Box::new(toride_runner::DuctRunner);
        let paths = AuditPaths::default_system();
        Ok(Self {
            runner,
            paths,
            dry_run: false,
        })
    }

    /// Create an `Audit` instance with explicit paths and a default
    /// [`toride_runner::DuctRunner`].
    #[cfg(feature = "client")]
    pub fn with_paths(paths: AuditPaths) -> Result<Self> {
        let runner = Box::new(toride_runner::DuctRunner);
        Ok(Self {
            runner,
            paths,
            dry_run: false,
        })
    }

    /// Create an `Audit` instance with a custom runner.
    ///
    /// Uses default system paths. The config directories do not need to exist
    /// when a custom runner is injected (useful for testing).
    pub fn with_runner(runner: Box<dyn toride_runner::Runner>) -> Self {
        let paths = AuditPaths::default_system();
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

    /// Override the resolved system paths.
    ///
    /// Primarily useful in tests to point the facade at a temp directory so
    /// that file-based operations (rule writes, log listings) do not touch
    /// the real `/etc`.
    #[must_use]
    pub fn with_paths_override(mut self, paths: AuditPaths) -> Self {
        self.paths = paths;
        self
    }

    // -----------------------------------------------------------------------
    // Sub-module accessors
    // -----------------------------------------------------------------------

    /// Return a reference to the underlying runner.
    pub fn runner(&self) -> &dyn toride_runner::Runner {
        self.runner.as_ref()
    }

    /// Return a reference to the system paths.
    pub fn paths(&self) -> &AuditPaths {
        &self.paths
    }

    /// Return whether dry-run mode is enabled.
    pub fn dry_run(&self) -> bool {
        self.dry_run
    }

    /// Return an [`auditd::AuditdManager`] borrowing this instance's runner.
    #[cfg(feature = "auditd")]
    pub fn auditd(&self) -> auditd::AuditdManager<'_> {
        auditd::AuditdManager::new(self.runner.as_ref(), &self.paths)
    }

    /// Return an [`integrity::IntegrityManager`] borrowing this instance's runner.
    #[cfg(feature = "integrity")]
    pub fn integrity(&self) -> integrity::IntegrityManager<'_> {
        integrity::IntegrityManager::new(self.runner.as_ref(), &self.paths)
    }

    /// Return a [`logs::LogManager`] borrowing this instance's runner.
    #[cfg(feature = "logs")]
    pub fn logs(&self) -> logs::LogManager<'_> {
        logs::LogManager::new(self.runner.as_ref(), &self.paths)
    }

    // -----------------------------------------------------------------------
    // Doctor
    // -----------------------------------------------------------------------

    /// Run the diagnostic engine and return an [`report::AuditReport`].
    ///
    /// # Errors
    ///
    /// Returns an error only for fundamental failures (e.g. a broken runner).
    /// Individual check failures appear as findings in the report.
    #[cfg(feature = "doctor")]
    pub fn doctor(&self, scope: doctor::DoctorScope) -> Result<report::AuditReport> {
        let doc = doctor::Doctor::new(self.runner.as_ref(), &self.paths);
        doc.run(&scope)
    }
}
