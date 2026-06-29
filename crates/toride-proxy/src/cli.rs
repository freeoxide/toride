//! CLI argument definitions and dispatch.
//!
//! Provides clap-based argument parsing for the proxy management CLI, plus a
//! [`ProxyCli::run`] entry point that maps each parsed subcommand to the
//! corresponding [`ProxyClient`](crate::client::ProxyClient) call and returns a
//! human-readable result string. Previously the CLI was a pure data layer with
//! no dispatch; this wires it to the managers it should drive.

use crate::client::ProxyClient;
use crate::doctor::DoctorScope;
#[allow(unused_imports)]
use crate::error::{Error, Result};

/// Proxy CLI argument definitions.
#[derive(Debug, Clone, clap::Parser)]
#[command(name = "toride-proxy", about = "Reverse proxy management")]
pub struct ProxyCli {
    /// Subcommand to execute.
    #[command(subcommand)]
    pub command: ProxyCommand,

    /// Dry-run mode: log mutating commands without executing them.
    #[arg(long, global = true)]
    pub dry_run: bool,
}

/// Proxy subcommands.
#[derive(Debug, Clone, clap::Subcommand)]
pub enum ProxyCommand {
    /// Check proxy status and configuration.
    Status,

    /// Run diagnostic checks.
    Doctor {
        /// Scope of doctor checks (all, service, headers, certificates, config).
        #[arg(default_value = "all")]
        scope: String,
    },

    /// Nginx-related operations.
    Nginx {
        /// Nginx subcommand.
        #[command(subcommand)]
        action: NginxAction,
    },

    /// Caddy-related operations.
    Caddy {
        /// Caddy subcommand.
        #[command(subcommand)]
        action: CaddyAction,
    },

    /// Certificate management.
    Certs {
        /// Certificate subcommand.
        #[command(subcommand)]
        action: CertAction,
    },
}

/// Nginx subcommands.
#[derive(Debug, Clone, clap::Subcommand)]
pub enum NginxAction {
    /// Test Nginx configuration.
    Test,

    /// Reload Nginx configuration.
    Reload,

    /// Restart Nginx service.
    Restart,

    /// List configured sites.
    Sites,

    /// Enable a site.
    Enable {
        /// Domain to enable.
        domain: String,
    },

    /// Disable a site.
    Disable {
        /// Domain to disable.
        domain: String,
    },
}

/// Caddy subcommands.
#[derive(Debug, Clone, clap::Subcommand)]
pub enum CaddyAction {
    /// Validate Caddyfile.
    Validate,

    /// Reload Caddy configuration.
    Reload,

    /// Format Caddyfile.
    Format,
}

/// Certificate subcommands.
#[derive(Debug, Clone, clap::Subcommand)]
pub enum CertAction {
    /// List all certificates.
    List,

    /// Obtain a new certificate.
    Obtain {
        /// Domain name.
        domain: String,
        /// Email for registration.
        email: String,
        /// Webroot path for HTTP challenge.
        #[arg(long, default_value = "/var/www/html")]
        webroot: String,
    },

    /// Renew all due certificates.
    Renew,

    /// Check renewal status.
    Check,
}

/// Parse a doctor scope string into the typed enum.
///
/// Falls back to [`DoctorScope::All`] for any unrecognized value rather than
/// erroring, so the CLI stays forgiving.
fn parse_scope(s: &str) -> DoctorScope {
    match s.to_ascii_lowercase().as_str() {
        "service" => DoctorScope::Service,
        "headers" => DoctorScope::Headers,
        "certificates" | "certs" => DoctorScope::Certificates,
        "config" => DoctorScope::Config,
        _ => DoctorScope::All,
    }
}

impl ProxyCli {
    /// Execute the parsed command against a [`ProxyClient`] and return a
    /// human-readable result string.
    ///
    /// The client's dry-run flag is applied from the CLI `--dry-run` flag
    /// before dispatch, so mutating subcommands honor it. Read-only
    /// subcommands (status, doctor, list) always execute.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the underlying operation fails (e.g. nginx not
    /// installed, config syntax error). In dry-run mode mutating commands
    /// never error because they do not run.
    pub fn run(&self, client: &mut ProxyClient) -> Result<String> {
        if self.dry_run {
            client.set_dry_run(true);
        }

        match &self.command {
            ProxyCommand::Status => {
                let report = client.doctor(DoctorScope::Service)?;
                Ok(format!("Proxy status: {}", report.status))
            }
            ProxyCommand::Doctor { scope } => {
                let parsed = parse_scope(scope);
                let report = client.doctor(parsed)?;
                Ok(report.to_summary())
            }
            ProxyCommand::Nginx { action } => match action {
                NginxAction::Test => {
                    client.nginx().test_config()?;
                    Ok("nginx configuration is valid".into())
                }
                NginxAction::Reload => {
                    client.reload()?;
                    Ok("nginx reloaded".into())
                }
                NginxAction::Restart => {
                    client.restart()?;
                    Ok("nginx restarted".into())
                }
                NginxAction::Sites => {
                    #[cfg(feature = "config")]
                    {
                        let sites = client.config().list_enabled_sites()?;
                        if sites.is_empty() {
                            Ok("no enabled sites".into())
                        } else {
                            Ok(sites.join("\n"))
                        }
                    }
                    #[cfg(not(feature = "config"))]
                    {
                        Err(Error::Other(
                            "the 'config' feature is required for `nginx sites`".into(),
                        ))
                    }
                }
                NginxAction::Enable { domain } => {
                    #[cfg(feature = "config")]
                    {
                        client.config().enable_site(domain)?;
                        Ok(format!("enabled site {domain}"))
                    }
                    #[cfg(not(feature = "config"))]
                    {
                        let _ = domain;
                        Err(Error::Other(
                            "the 'config' feature is required for `nginx enable`".into(),
                        ))
                    }
                }
                NginxAction::Disable { domain } => {
                    #[cfg(feature = "config")]
                    {
                        client.config().disable_site(domain)?;
                        Ok(format!("disabled site {domain}"))
                    }
                    #[cfg(not(feature = "config"))]
                    {
                        let _ = domain;
                        Err(Error::Other(
                            "the 'config' feature is required for `nginx disable`".into(),
                        ))
                    }
                }
            },
            ProxyCommand::Caddy { action } => {
                #[cfg(not(feature = "caddy"))]
                {
                    let _ = action;
                    return Err(Error::Other(
                        "the 'caddy' feature is required for caddy subcommands".into(),
                    ));
                }
                #[cfg(feature = "caddy")]
                {
                    match action {
                        CaddyAction::Validate => {
                            client.caddy().validate_config()?;
                            Ok("Caddyfile is valid".into())
                        }
                        CaddyAction::Reload => {
                            client.caddy().reload()?;
                            Ok("caddy reloaded".into())
                        }
                        CaddyAction::Format => {
                            let formatted = client.caddy().format_config()?;
                            Ok(formatted)
                        }
                    }
                }
            }
            ProxyCommand::Certs { action } => {
                #[cfg(not(feature = "certs"))]
                {
                    let _ = action;
                    return Err(Error::Other(
                        "the 'certs' feature is required for cert subcommands".into(),
                    ));
                }
                #[cfg(feature = "certs")]
                {
                    match action {
                        CertAction::List => {
                            let certs = client.certs().list_certificates()?;
                            if certs.is_empty() {
                                Ok("no certificates".into())
                            } else {
                                Ok(certs
                                    .iter()
                                    .map(|c| {
                                        format!(
                                            "{} ({} days remaining, {})",
                                            c.domain,
                                            c.days_remaining,
                                            if c.is_valid { "valid" } else { "EXPIRED" }
                                        )
                                    })
                                    .collect::<Vec<_>>()
                                    .join("\n"))
                            }
                        }
                        CertAction::Obtain {
                            domain,
                            email,
                            webroot,
                        } => {
                            client.obtain_certificate(domain, email, webroot)?;
                            Ok(format!("obtained certificate for {domain}"))
                        }
                        CertAction::Renew => {
                            client.renew_all()?;
                            Ok("renewed certificates".into())
                        }
                        CertAction::Check => {
                            let certs = client.certs().list_certificates()?;
                            Ok(format!("{} certificate(s) managed by certbot", certs.len()))
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_scope_recognizes_keywords() {
        assert_eq!(parse_scope("all"), DoctorScope::All);
        assert_eq!(parse_scope("Service"), DoctorScope::Service);
        assert_eq!(parse_scope("HEADERS"), DoctorScope::Headers);
        assert_eq!(parse_scope("certs"), DoctorScope::Certificates);
        assert_eq!(parse_scope("config"), DoctorScope::Config);
        // Unknown -> All (forgiving).
        assert_eq!(parse_scope("nonsense"), DoctorScope::All);
    }

    /// End-to-end CLI dispatch for the read-only `doctor` command, driven by a
    /// FakeRunner so no real nginx/systemctl is required. Confirms the parsed
    /// ProxyCli actually reaches ProxyClient and returns a summary.
    #[test]
    fn cli_run_doctor_returns_summary() {
        let fake = toride_runner::FakeRunner::new();
        let mut client = ProxyClient::with_runner(Box::new(fake));

        let cli = ProxyCli {
            command: ProxyCommand::Doctor {
                scope: "certificates".into(),
            },
            dry_run: false,
        };
        let out = cli.run(&mut client).expect("doctor dispatch");
        assert!(out.contains("Certificates:"));
    }

    /// `--dry-run` must not execute the mutating reload command. Strict
    /// FakeRunner would error if any command ran; in dry-run nothing runs.
    #[test]
    fn cli_dry_run_reload_does_not_execute() {
        let fake = toride_runner::FakeRunner::new().strict();
        let mut client = ProxyClient::with_runner(Box::new(fake));

        let cli = ProxyCli {
            command: ProxyCommand::Nginx {
                action: NginxAction::Reload,
            },
            dry_run: true,
        };
        let out = cli.run(&mut client).expect("dry-run reload");
        assert!(out.contains("reloaded"));
    }

    /// `nginx test` dispatches to NginxManager::test_config and returns the
    /// success message when the (faked) nginx -t passes.
    #[test]
    fn cli_nginx_test_passes() {
        let fake = toride_runner::FakeRunner::new().respond(
            toride_runner::CommandSpec::new("nginx").arg("-t"),
            toride_runner::CommandOutput::from_stdout("syntax is ok"),
        );
        let mut client = ProxyClient::with_runner(Box::new(fake));

        let cli = ProxyCli {
            command: ProxyCommand::Nginx {
                action: NginxAction::Test,
            },
            dry_run: false,
        };
        let out = cli.run(&mut client).expect("nginx test");
        assert!(out.contains("valid"));
    }

    /// Smoke test: a representative argv round-trips through clap into the
    /// expected command tree, and `--dry-run` (a global flag) is captured on
    /// the top-level struct. Guards the `#[derive(Parser)]`/subcommand wiring
    /// that the dispatch tests above bypass by constructing `ProxyCli` by hand.
    #[test]
    fn cli_parses_argv_into_command_tree() {
        use clap::Parser;

        let cli = ProxyCli::try_parse_from([
            "toride-proxy",
            "--dry-run",
            "nginx",
            "enable",
            "example.com",
        ])
        .expect("argv parses");
        assert!(cli.dry_run, "global --dry-run must land on ProxyCli");
        match cli.command {
            ProxyCommand::Nginx {
                action: NginxAction::Enable { ref domain },
            } => {
                assert_eq!(domain, "example.com");
            }
            other => panic!("expected Nginx::Enable, got {other:?}"),
        }

        // A positionally-ambiguous argv must error rather than silently
        // mis-dispatching.
        assert!(
            ProxyCli::try_parse_from(["toride-proxy", "bogus"]).is_err(),
            "unknown subcommand should fail to parse"
        );
    }
}
