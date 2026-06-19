//! High-level proxy client.
//!
//! The main entry point for proxy management. Owns a command runner and
//! proxy paths, and delegates to sub-modules for proxy operations.

use crate::error::Result;
use crate::paths::ProxyPaths;
use toride_runner::Runner;

/// High-level proxy management facade.
///
/// Owns a command runner and proxy paths, providing convenience methods
/// that compose the lower-level modules into common workflows.
///
/// # Construction
///
/// - [`ProxyClient::system`] -- production defaults: `DuctRunner` + system paths.
/// - [`ProxyClient::with_runner`] -- inject a custom or test runner.
/// - [`ProxyClient::with_paths`] -- custom paths with a default runner.
pub struct ProxyClient {
    runner: Box<dyn Runner>,
    paths: ProxyPaths,
    dry_run: bool,
}

impl ProxyClient {
    /// Create a `ProxyClient` with production defaults.
    ///
    /// Uses a [`toride_runner::DuctRunner`] with the default timeout
    /// and resolves system paths.
    ///
    /// Construction never fails on a missing `nginx` binary: this method only
    /// builds the runner and resolves default [`ProxyPaths`] — it does NOT
    /// shell out and does NOT check for `nginx`. A missing binary is surfaced
    /// later by the doctor as a `Critical` finding rather than as a
    /// construction error. The only way construction returns an error is a
    /// genuine I/O failure in path resolution.
    ///
    /// # Errors
    ///
    /// Returns an error only on a genuine I/O failure while resolving system
    /// paths. A missing `nginx` binary is NOT an error here.
    #[cfg(feature = "client")]
    pub fn system() -> Result<Self> {
        let runner = toride_runner::duct_runner::DuctRunner;
        Ok(Self {
            runner: Box::new(runner),
            paths: ProxyPaths::default(),
            dry_run: false,
        })
    }

    /// Create a `ProxyClient` with explicit proxy paths and a default runner.
    pub fn with_paths(paths: ProxyPaths) -> Result<Self> {
        let runner = toride_runner::duct_runner::DuctRunner;
        Ok(Self {
            runner: Box::new(runner),
            paths,
            dry_run: false,
        })
    }

    /// Create a `ProxyClient` with a custom runner.
    pub fn with_runner(runner: Box<dyn Runner>) -> Self {
        Self {
            runner,
            paths: ProxyPaths::default(),
            dry_run: false,
        }
    }

    /// Set dry-run mode.
    ///
    /// When enabled, commands are logged but not executed.
    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    /// Return a reference to the proxy paths.
    pub fn paths(&self) -> &ProxyPaths {
        &self.paths
    }

    /// Return a reference to the command runner.
    pub fn runner(&self) -> &dyn Runner {
        self.runner.as_ref()
    }

    // -----------------------------------------------------------------------
    // Nginx sub-module accessor
    // -----------------------------------------------------------------------

    /// Return an [`crate::nginx::NginxManager`] borrowing this instance's runner.
    #[cfg(feature = "nginx")]
    pub fn nginx(&self) -> crate::nginx::NginxManager<'_> {
        crate::nginx::NginxManager::new(self.runner.as_ref(), &self.paths)
    }

    // -----------------------------------------------------------------------
    // Caddy sub-module accessor
    // -----------------------------------------------------------------------

    /// Return a [`crate::caddy::CaddyManager`] borrowing this instance's runner.
    #[cfg(feature = "caddy")]
    pub fn caddy(&self) -> crate::caddy::CaddyManager<'_> {
        crate::caddy::CaddyManager::new(self.runner.as_ref(), &self.paths)
    }

    // -----------------------------------------------------------------------
    // Certificate sub-module accessor
    // -----------------------------------------------------------------------

    /// Return a [`crate::certs::CertManager`] borrowing this instance's runner.
    #[cfg(feature = "certs")]
    pub fn certs(&self) -> crate::certs::CertManager<'_> {
        crate::certs::CertManager::new(self.runner.as_ref(), &self.paths)
    }

    // -----------------------------------------------------------------------
    // Doctor
    // -----------------------------------------------------------------------

    /// Run the diagnostic engine and return a report.
    #[cfg(feature = "doctor")]
    pub fn doctor(
        &self,
        scope: crate::doctor::DoctorScope,
    ) -> Result<crate::report::ProxyReport> {
        let doc = crate::doctor::Doctor::new(self.runner.as_ref(), &self.paths);
        doc.run(&scope)
    }
}
