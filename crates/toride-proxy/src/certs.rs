//! TLS certificate management.
//!
//! Provides high-level operations for managing TLS certificates via
//! certbot/Let's Encrypt and OpenSSL.

use crate::error::{Error, Result};
use crate::parse::parse_certbot_certs;
use crate::paths::ProxyPaths;
use crate::report::CertInfo;
use toride_runner::{CommandSpec, Runner};

/// Certificate management facade.
///
/// Owns a command runner and proxy paths, providing convenience methods for
/// certificate operations like listing, obtaining, and renewing certificates.
pub struct CertManager<'a> {
    runner: &'a dyn Runner,
    paths: &'a ProxyPaths,
}

impl<'a> CertManager<'a> {
    /// Create a new certificate manager.
    pub fn new(runner: &'a dyn Runner, paths: &'a ProxyPaths) -> Self {
        Self { runner, paths }
    }

    /// List all certificates managed by certbot.
    ///
    /// Runs `certbot certificates` and parses the output.
    ///
    /// # Errors
    ///
    /// Returns an error if the certbot command fails.
    pub fn list_certificates(&self) -> Result<Vec<CertInfo>> {
        let spec = CommandSpec::new("certbot").arg("certificates");
        let output = self.runner.run(&spec)?;

        if !output.success {
            return Err(Error::CommandFailed {
                program: "certbot".into(),
                code: output.exit_code,
                stderr: output.stderr,
            });
        }

        Ok(parse_certbot_certs(&output.stdout))
    }

    /// Obtain a new certificate for a domain using certbot.
    ///
    /// Uses the webroot authenticator with the specified webroot path.
    ///
    /// # Errors
    ///
    /// Returns an error if the certbot command fails.
    pub fn obtain_certificate(
        &self,
        domain: &str,
        email: &str,
        webroot: &str,
    ) -> Result<()> {
        // `--email` carries a registration/recovery contact address (PII), so
        // the spec must opt into redaction: `redact(true)` ensures the email is
        // scrubbed from any error messages and log output produced by runners.
        // Real certbot invocation (see certbot(1) man page, `-m EMAIL`,
        // `--email EMAIL`): "Email used for registration and recovery contact."
        let spec = CommandSpec::new("certbot")
            .args(["certonly", "--webroot", "-w"])
            .arg(webroot)
            .args(["-d"])
            .arg(domain)
            .args(["--email"])
            .arg(email)
            .args(["--agree-tos", "--non-interactive"])
            .redact(true);

        let output = self.runner.run(&spec)?;

        if !output.success {
            return Err(Error::CertRenewal(format!(
                "failed to obtain certificate for {domain}: {}",
                output.stderr.trim()
            )));
        }

        tracing::info!("certs: obtained certificate for {}", domain);
        Ok(())
    }

    /// Renew all certificates that are due for renewal.
    ///
    /// Runs `certbot renew`.
    ///
    /// # Errors
    ///
    /// Returns an error if the renewal command fails.
    pub fn renew_all(&self) -> Result<()> {
        let spec = CommandSpec::new("certbot")
            .args(["renew", "--non-interactive"]);

        let output = self.runner.run(&spec)?;

        if !output.success {
            return Err(Error::CertRenewal(format!(
                "certificate renewal failed: {}",
                output.stderr.trim()
            )));
        }

        tracing::info!("certs: renewed certificates");
        Ok(())
    }

    /// Revoke a certificate for a domain.
    ///
    /// # Errors
    ///
    /// Returns an error if the revocation command fails.
    pub fn revoke_certificate(&self, domain: &str) -> Result<()> {
        let cert_path = self.paths.cert_live_path(domain).join("cert.pem");
        let spec = CommandSpec::new("certbot")
            .args(["revoke", "--cert-path"])
            .arg(cert_path.to_str().unwrap_or_default())
            .arg("--non-interactive");

        let output = self.runner.run(&spec)?;

        if !output.success {
            return Err(Error::CertRenewal(format!(
                "failed to revoke certificate for {domain}: {}",
                output.stderr.trim()
            )));
        }

        tracing::info!("certs: revoked certificate for {}", domain);
        Ok(())
    }

    /// Check if a certificate exists for a domain.
    pub fn certificate_exists(&self, domain: &str) -> bool {
        self.paths.cert_live_path(domain).join("fullchain.pem").exists()
    }

    /// Get the path to the full certificate chain for a domain.
    pub fn fullchain_path(&self, domain: &str) -> std::path::PathBuf {
        self.paths.cert_live_path(domain).join("fullchain.pem")
    }

    /// Get the path to the private key for a domain.
    pub fn privkey_path(&self, domain: &str) -> std::path::PathBuf {
        self.paths.cert_live_path(domain).join("privkey.pem")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_exists_checks_path() {
        let dir = assert_fs::TempDir::new().unwrap();
        let paths = ProxyPaths::with_root(dir.path());

        let fake = toride_runner::fake::FakeRunner::new();
        let mgr = CertManager::new(&fake, &paths);

        assert!(!mgr.certificate_exists("example.com"));

        // Create the cert file
        let cert_dir = paths.cert_live_path("example.com");
        std::fs::create_dir_all(&cert_dir).unwrap();
        std::fs::write(cert_dir.join("fullchain.pem"), "fake cert").unwrap();

        assert!(mgr.certificate_exists("example.com"));
    }

    /// `obtain_certificate` must build the certbot invocation with `redact(true)`
    /// because `--email` carries a registration/recovery contact address (PII).
    ///
    /// The exact arg shape comes from the certbot(1) man page
    /// (https://man.archlinux.org/man/certbot.1): `-m EMAIL, --email EMAIL` —
    /// "Email used for registration and recovery contact." Non-interactive
    /// certificate issuance requires `--agree-tos` + `--non-interactive`
    /// alongside the webroot authenticator (`--webroot -w PATH -d DOMAIN`),
    /// matching real-world documented usage.
    ///
    /// `specs_match` now enforces the `redact` field, so asserting a spec with
    /// `redact(true)` is non-vacuous: if the production builder forgets
    /// `.redact(true)`, this test fails.
    #[test]
    fn obtain_certificate_redacts_pii_email() {
        let dir = assert_fs::TempDir::new().unwrap();
        let paths = ProxyPaths::with_root(dir.path());

        let fake = toride_runner::fake::FakeRunner::new()
            .push_response(toride_runner::CommandOutput::from_stdout(""));
        let mgr = CertManager::new(&fake, &paths);

        // A realistic-looking PII email value, to prove the builder accepts and
        // forwards it while still marking the spec for redaction.
        let result = mgr.obtain_certificate(
            "example.com",
            "webmaster@example.com",
            "/var/www/html",
        );
        assert!(result.is_ok(), "obtain_certificate should succeed with a fake runner");

        // Expected spec mirrors the real certbot invocation documented above.
        let expected = CommandSpec::new("certbot")
            .args(["certonly", "--webroot", "-w"])
            .arg("/var/www/html")
            .args(["-d"])
            .arg("example.com")
            .args(["--email"])
            .arg("webmaster@example.com")
            .args(["--agree-tos", "--non-interactive"])
            .redact(true);

        fake.assert_called_with(&expected);

        // Belt-and-suspenders: directly assert the recorded call carries
        // redact(true), so the intent is obvious if the assertion above is ever
        // weakened to ignore the redact field.
        let calls = fake.calls();
        assert_eq!(calls.len(), 1, "exactly one certbot call expected");
        assert!(
            calls[0].redact,
            "certbot obtain_certificate spec must carry redact(true) to scrub --email PII"
        );

        // Non-vacuous: prove the email VALUE is actually scrubbed from the
        // redacted display, not merely that redact==true. (Regression for the
        // REDACT_FLAGS gap that left --email unredacted despite redact(true).)
        let display = toride_runner::display::redacted_args_display(&expected);
        assert!(
            !display.contains("webmaster@example.com"),
            "certbot email leaked into redacted display: {display}"
        );
    }
}
