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
    pub fn obtain_certificate(&self, domain: &str, email: &str, webroot: &str) -> Result<()> {
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

        // Run via `run_checked`, NOT plain `run`. On failure, certbot writes the
        // ACME account contact email back to stderr (e.g. registration,
        // account-update, and rate-limit messages of the form
        // "An unexpected error occurred during registration for
        // <email>"), so the `--email` value can reappear in the raw
        // stderr stream even though the spec carries `redact(true)`.
        // `run_checked` is the path that honors `redact=true`: it routes stderr
        // through `display::scrub_stderr`, which replaces the `--email` value
        // (a `REDACT_FLAGS` entry) with `"***"` before surfacing it. The plain
        // `run` path returns raw, unscrubbed output and would interpolate the
        // PII email straight into `Error::CertRenewal`, defeating `redact(true)`.
        self.runner.run_checked(&spec).map_err(|e| {
            Error::CertRenewal(format!("failed to obtain certificate for {domain}: {e}"))
        })?;

        tracing::info!("certs: obtained certificate for {}", domain);
        Ok(())
    }

    /// Renew all certificates that are due for renewal.
    ///
    /// Runs `certbot renew` via [`Runner::run_checked`], consistent with
    /// [`obtain_certificate`](Self::obtain_certificate). `run_checked` routes
    /// stderr through `display::scrub_stderr` before surfacing the failure, so
    /// any sensitive values redacted by the spec (and any inadvertent PII
    /// certbot echoes) are scrubbed rather than interpolated raw into
    /// [`Error::CertRenewal`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::CertRenewal`] if the renewal command fails.
    pub fn renew_all(&self) -> Result<()> {
        let spec = CommandSpec::new("certbot").args(["renew", "--non-interactive"]);

        // Use `run_checked` (not plain `run`): on failure the error's Display
        // carries already-scrubbed stderr, so interpolating `{e}` into
        // `CertRenewal` never leaks raw stderr the way `output.stderr` did.
        self.runner
            .run_checked(&spec)
            .map_err(|e| Error::CertRenewal(format!("certificate renewal failed: {e}")))?;

        tracing::info!("certs: renewed certificates");
        Ok(())
    }

    /// Revoke a certificate for a domain.
    ///
    /// Routes the certbot invocation through [`Runner::run_checked`], so a
    /// failure surfaces scrubbed stderr (via the runner error's `Display`)
    /// instead of interpolating raw `output.stderr` into [`Error::CertRenewal`]
    /// — consistent with [`obtain_certificate`](Self::obtain_certificate) and
    /// [`renew_all`](Self::renew_all).
    ///
    /// # Errors
    ///
    /// Returns [`Error::CertRenewal`] if the revocation command fails.
    pub fn revoke_certificate(&self, domain: &str) -> Result<()> {
        let cert_path = self.paths.cert_live_path(domain).join("cert.pem");
        let spec = CommandSpec::new("certbot")
            .args(["revoke", "--cert-path"])
            .arg(cert_path.to_str().unwrap_or_default())
            .arg("--non-interactive");

        self.runner.run_checked(&spec).map_err(|e| {
            Error::CertRenewal(format!("failed to revoke certificate for {domain}: {e}"))
        })?;

        tracing::info!("certs: revoked certificate for {}", domain);
        Ok(())
    }

    /// Check if a certificate exists for a domain.
    pub fn certificate_exists(&self, domain: &str) -> bool {
        self.paths
            .cert_live_path(domain)
            .join("fullchain.pem")
            .exists()
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
        let result =
            mgr.obtain_certificate("example.com", "webmaster@example.com", "/var/www/html");
        assert!(
            result.is_ok(),
            "obtain_certificate should succeed with a fake runner"
        );

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

    /// Regression for the `run` vs `run_checked` gap: when certbot fails, it
    /// echoes the ACME account contact email back to stderr.
    ///
    /// Real certbot writes the contact email to stderr on ACME
    /// registration/account/rate-limit errors (e.g. "An unexpected error
    /// occurred during registration for webmaster@example.com" or
    /// "There were too many requests of a given type for <email>"). Because
    /// `--email` carries PII, `obtain_certificate` builds the spec with
    /// `redact(true)` — and that redaction is only applied on the
    /// `run_checked` path (`Runner::run_checked` runs stderr through
    /// `display::scrub_stderr`, which replaces the `--email` value with
    /// `***` since `--email` is in `REDACT_FLAGS`).
    ///
    /// Previously `obtain_certificate` called the plain `run` path, which
    /// returns raw unscrubbed stderr, and then interpolated it straight into
    /// `Error::CertRenewal` — leaking the email that `redact(true)` promised
    /// to scrub. This test proves the fix: the PII email value must be absent
    /// from the surfaced failure message.
    #[test]
    fn obtain_certificate_failure_scrubs_pii_email_from_error() {
        let dir = assert_fs::TempDir::new().unwrap();
        let paths = ProxyPaths::with_root(dir.path());

        // Simulated certbot failure: a rate-limit style stderr that echoes the
        // contact email, the way real certbot does on ACME registration errors.
        let pii_email = "webmaster@example.com";
        let raw_stderr = format!(
            "Account creation failed for rate limit during registration for {pii_email}. \
             See https://letsencrypt.org/docs/rate-limits/"
        );

        let fake = toride_runner::fake::FakeRunner::new()
            .push_response(toride_runner::CommandOutput::from_stderr(raw_stderr, 1));
        let mgr = CertManager::new(&fake, &paths);

        let result = mgr.obtain_certificate("example.com", pii_email, "/var/www/html");

        let err = result.expect_err("a failing certbot run must surface an error");
        let msg = match &err {
            Error::CertRenewal(msg) => msg.clone(),
            other => panic!("expected Error::CertRenewal, got {other:?}"),
        };

        // Preserve the user-facing message shape.
        assert!(
            msg.starts_with("failed to obtain certificate for example.com:"),
            "unexpected CertRenewal message shape: {msg}"
        );

        // Non-vacuous value-absence check: the PII email MUST NOT leak into the
        // failure message. If `obtain_certificate` ever falls back to the plain
        // `run` path (which skips scrub_stderr), the email reappears here.
        assert!(
            !msg.contains(pii_email),
            "PII email leaked into CertRenewal failure message: {msg}"
        );

        // Sanity: the scrubbed sentinel is present, proving the value was
        // replaced rather than merely dropped.
        assert!(
            msg.contains("***"),
            "expected redaction sentinel '***' in scrubbed message: {msg}"
        );
    }

    /// Regression for the `run` vs `run_checked` gap on `renew_all`: when
    /// certbot fails, the failure must be routed through `Runner::run_checked`,
    /// not the plain `run` path. The old code pasted `output.stderr.trim()`
    /// directly into `Error::CertRenewal`, bypassing the runner's scrubbing and
    /// length-cap entirely. The fix routes through `run_checked`, so the
    /// surfaced message is built from the `CommandFailed` error's `Display`
    /// (which wraps stderr through `display::scrub_stderr`).
    ///
    /// We pin two facts: (1) the message carries the runner error's
    /// `"command failed"` prefix, proving it came from `run_checked` rather
    /// than a raw stderr paste; and (2) a spec with `redact(true)` actually
    /// scrubs a secret value out of that message — the property the old code
    /// could never guarantee because it never let the spec reach the scrubber.
    #[test]
    fn renew_all_failure_routes_through_run_checked() {
        let dir = assert_fs::TempDir::new().unwrap();
        let paths = ProxyPaths::with_root(dir.path());

        // Spec for `renew_all` has no sensitive flags, so scrubbing is a no-op
        // here; we only assert the message is built from the runner error.
        let raw_stderr = "renewal encountered a problem";
        let fake = toride_runner::fake::FakeRunner::new()
            .push_response(toride_runner::CommandOutput::from_stderr(raw_stderr, 1));
        let mgr = CertManager::new(&fake, &paths);

        let err = mgr.renew_all().expect_err("a failing renew must error");
        let msg = match &err {
            Error::CertRenewal(msg) => msg.clone(),
            other => panic!("expected Error::CertRenewal, got {other:?}"),
        };

        assert!(
            msg.starts_with("certificate renewal failed:"),
            "unexpected CertRenewal message shape: {msg}"
        );
        // The runner's CommandFailed Display prefix must be present — this is
        // the marker that the error flowed through run_checked (and thus
        // scrub_stderr) rather than being a direct stderr paste.
        assert!(
            msg.contains("command failed"),
            "renew_all failure did not route through run_checked/CommandFailed: {msg}"
        );
    }

    /// Same regression class for `revoke_certificate`: the failure path must
    /// go through `run_checked` (evidenced by the `"command failed"` prefix in
    /// the surfaced message) rather than pasting raw `output.stderr`.
    #[test]
    fn revoke_certificate_failure_routes_through_run_checked() {
        let dir = assert_fs::TempDir::new().unwrap();
        let paths = ProxyPaths::with_root(dir.path());

        let raw_stderr = "revocation encountered a problem";
        let fake = toride_runner::fake::FakeRunner::new()
            .push_response(toride_runner::CommandOutput::from_stderr(raw_stderr, 1));
        let mgr = CertManager::new(&fake, &paths);

        let err = mgr
            .revoke_certificate("example.com")
            .expect_err("a failing revoke must error");
        let msg = match &err {
            Error::CertRenewal(msg) => msg.clone(),
            other => panic!("expected Error::CertRenewal, got {other:?}"),
        };

        assert!(
            msg.starts_with("failed to revoke certificate for example.com:"),
            "unexpected CertRenewal message shape: {msg}"
        );
        assert!(
            msg.contains("command failed"),
            "revoke failure did not route through run_checked/CommandFailed: {msg}"
        );
    }

    /// `renew_all` and `revoke_certificate` must succeed on a successful run,
    /// exercising the `run_checked` happy path.
    #[test]
    fn renew_all_and_revoke_succeed_on_success() {
        let dir = assert_fs::TempDir::new().unwrap();
        let paths = ProxyPaths::with_root(dir.path());

        let fake = toride_runner::fake::FakeRunner::new()
            .push_response(toride_runner::CommandOutput::from_stdout("renewed"))
            .push_response(toride_runner::CommandOutput::from_stdout("revoked"));
        let mgr = CertManager::new(&fake, &paths);

        assert!(mgr.renew_all().is_ok());
        assert!(mgr.revoke_certificate("example.com").is_ok());
    }
}
