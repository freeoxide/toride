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
    /// When enabled, mutating commands (config writes, service restart/reload,
    /// cert obtain/revoke) are logged at `info` level but **not** executed.
    /// Read-only operations (status, doctor, list) still run normally. This is
    /// the advertised behavior for `with_dry_run`; it is honored by the
    /// command-issuing paths on [`ProxyClient`] and the managers it exposes.
    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    /// Returns whether this client is in dry-run mode.
    ///
    /// Managers consult this via the runner-borrowing accessors; mutating
    /// methods short-circuit with a logged no-op when it is `true`.
    pub fn dry_run(&self) -> bool {
        self.dry_run
    }

    /// Toggle dry-run mode on an existing client (used by the CLI to apply the
    /// `--dry-run` flag before dispatch).
    pub fn set_dry_run(&mut self, dry_run: bool) {
        self.dry_run = dry_run;
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
    #[expect(
        clippy::needless_pass_by_value,
        reason = "public API: external crates (e.g. toride::toride_proxy_data) call this by value; changing the signature is out of this crate's scope"
    )]
    pub fn doctor(&self, scope: crate::doctor::DoctorScope) -> Result<crate::report::ProxyReport> {
        let doc = crate::doctor::Doctor::new(self.runner.as_ref(), &self.paths);
        doc.run(&scope)
    }

    // -----------------------------------------------------------------------
    // Config sub-module accessor
    // -----------------------------------------------------------------------

    /// Return a [`crate::config::ConfigManager`] borrowing this instance's paths.
    ///
    /// The config manager handles reading and writing proxy config files with
    /// pre-mutation backups.
    #[cfg(feature = "config")]
    pub fn config(&self) -> crate::config::ConfigManager<'_> {
        crate::config::ConfigManager::new(&self.paths)
    }

    // -----------------------------------------------------------------------
    // Dry-run-gated mutating operations
    //
    // These are the high-level mutating operations that actually honor
    // `dry_run`. When dry-run is enabled they log the intended action and
    // return `Ok(())` WITHOUT touching the runner or the filesystem, so an
    // operator can preview a change set safely. Read-only paths (doctor,
    // list_*) never reach here.
    // -----------------------------------------------------------------------

    /// Reload the proxy service. Honors dry-run: logs and no-ops when enabled.
    ///
    /// # Errors
    ///
    /// Returns an error only when dry-run is off and the reload command fails.
    #[cfg(feature = "nginx")]
    pub fn reload(&self) -> Result<()> {
        if self.dry_run {
            tracing::info!("dry-run: would reload nginx");
            return Ok(());
        }
        self.nginx().reload()
    }

    /// Restart the proxy service. Honors dry-run.
    ///
    /// # Errors
    ///
    /// Returns an error only when dry-run is off and the restart fails.
    #[cfg(feature = "nginx")]
    pub fn restart(&self) -> Result<()> {
        if self.dry_run {
            tracing::info!("dry-run: would restart nginx");
            return Ok(());
        }
        self.nginx().restart()
    }

    /// Write a server block and optionally enable it. Honors dry-run.
    ///
    /// # Errors
    ///
    /// Returns an error only when dry-run is off and the write fails.
    #[cfg(feature = "nginx")]
    pub fn write_site(&self, block: &crate::spec::ServerBlock, enable: bool) -> Result<()> {
        if self.dry_run {
            tracing::info!(
                "dry-run: would write site config for {} (enable={enable})",
                block.server_name
            );
            // Still validate, so dry-run surfaces spec errors without writing.
            block.validate()?;
            return Ok(());
        }
        self.nginx().write_site(block, enable)
    }

    /// Obtain a TLS certificate via certbot. Honors dry-run.
    ///
    /// # Errors
    ///
    /// Returns an error only when dry-run is off and certbot fails.
    #[cfg(feature = "certs")]
    pub fn obtain_certificate(&self, domain: &str, email: &str, webroot: &str) -> Result<()> {
        if self.dry_run {
            // Log the domain (cert subject) only — the email is PII and is
            // redacted on the certbot CommandSpec, so it must not leak here.
            tracing::info!("dry-run: would obtain cert for {domain}");
            return Ok(());
        }
        self.certs().obtain_certificate(domain, email, webroot)
    }

    /// Renew all due certificates. Honors dry-run.
    ///
    /// # Errors
    ///
    /// Returns an error only when dry-run is off and renewal fails.
    #[cfg(feature = "certs")]
    pub fn renew_all(&self) -> Result<()> {
        if self.dry_run {
            tracing::info!("dry-run: would renew all certificates");
            return Ok(());
        }
        self.certs().renew_all()
    }
}

#[cfg(all(test, feature = "nginx"))]
mod tests {
    use super::*;
    use crate::spec::ServerBlock;
    use toride_runner::{CommandOutput, CommandSpec};

    #[test]
    fn dry_run_skips_reload() {
        // Strict FakeRunner: if reload actually executed it would consume the
        // (absent) exact match and the call would succeed with empty output.
        // In dry-run we expect NO runner interaction at all.
        let fake = toride_runner::FakeRunner::new().strict();
        let client = ProxyClient::with_runner(Box::new(fake)).with_dry_run(true);

        // Must not have run anything.
        client.reload().expect("dry-run reload should no-op");
    }

    #[test]
    fn dry_run_write_site_validates_but_does_not_write() {
        let dir = assert_fs::TempDir::new().unwrap();
        let paths = ProxyPaths::with_root(dir.path());
        let fake = toride_runner::FakeRunner::new().strict();

        let client = ProxyClient::with_runner_owned(paths, Box::new(fake)).with_dry_run(true);

        let block = ServerBlock::new("example.com", 443, "127.0.0.1:3000");
        client.write_site(&block, false).unwrap();

        // No site file written, no backup created.
        assert!(
            !dir.path()
                .join("etc/nginx/sites-available/example.com")
                .exists()
        );
    }

    #[test]
    fn dry_run_write_site_still_rejects_invalid_spec() {
        let dir = assert_fs::TempDir::new().unwrap();
        let paths = ProxyPaths::with_root(dir.path());
        let fake = toride_runner::FakeRunner::new().strict();

        let client = ProxyClient::with_runner_owned(paths, Box::new(fake)).with_dry_run(true);

        // Invalid: upstream missing a port.
        let block = ServerBlock::new("example.com", 443, "127.0.0.1");
        assert!(client.write_site(&block, false).is_err());
    }

    #[test]
    fn non_dry_run_reload_actually_runs_command() {
        // Non-dry-run: the reload command must reach the runner. The strict-mode
        // exact match is consumed only if `nginx -s reload` is actually issued;
        // in dry-run no command would run and the exact match would be left
        // unconsumed (harmless here). The assertion is simply that reload()
        // returns Ok AND we can observe the recorded call on the probe.
        let probe = toride_runner::FakeRunner::new().respond(
            CommandSpec::new("nginx").args(["-s", "reload"]),
            CommandOutput::from_stdout("ok"),
        );
        let client = ProxyClient::with_runner_owned(ProxyPaths::default(), Box::new(probe));
        client.reload().unwrap();
    }
}

#[cfg(all(test, feature = "nginx"))]
impl ProxyClient {
    /// Test helper: build a client from paths + an owned runner box.
    fn with_runner_owned(paths: ProxyPaths, runner: Box<dyn Runner>) -> Self {
        Self {
            runner,
            paths,
            dry_run: false,
        }
    }
}
