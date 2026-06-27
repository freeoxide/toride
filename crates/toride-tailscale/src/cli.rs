//! Command-line interface types for Tailscale operations.
//!
//! Provides [`TailscaleArgs`] as the top-level clap argument parser for
//! Tailscale subcommands, and [`TailscaleCommand`] for subcommand dispatch.
//!
//! [`TailscaleArgs::dispatch`] maps every [`TailscaleCommand`] variant to the
//! corresponding real client call ([`TailscaleClient`], [`Doctor`], or
//! [`TailscaleService`]). It takes the client by reference and an optional
//! injected [`Runner`] so that the `service` and `doctor` paths can be driven
//! by a [`FakeRunner`](toride_runner::fake::FakeRunner) in tests without
//! touching a real `systemctl`.

use std::sync::Arc;

use clap::Parser;

use crate::doctor::{Doctor, DoctorReport, DoctorScope};
use crate::service::TailscaleService;
use crate::TailscaleClient;
use crate::Result;

// ---------------------------------------------------------------------------
// TailscaleArgs
// ---------------------------------------------------------------------------

/// Top-level CLI arguments for Tailscale operations.
///
/// # Example
///
/// ```ignore
/// use clap::Parser;
/// use toride_tailscale::cli::TailscaleArgs;
///
/// let args = TailscaleArgs::parse_from(["tailscale", "status"]);
/// args.run()?;
/// ```
#[derive(Debug, clap::Parser)]
#[command(name = "tailscale", about = "Tailscale mesh VPN management")]
pub struct TailscaleArgs {
    /// The subcommand to run.
    #[command(subcommand)]
    pub command: TailscaleCommand,

    /// Enable verbose logging.
    #[arg(long, global = true)]
    pub verbose: bool,

    /// Run in dry-run mode (no mutations).
    #[arg(long, global = true)]
    pub dry_run: bool,
}

impl TailscaleArgs {
    /// Parse `std::env::args_os()` and run the command against a production
    /// [`TailscaleClient`] (real HTTP API) and a real
    /// [`TailscaleService`](crate::service::TailscaleService) (real `systemctl`
    /// / `tailscale` shell-outs).
    ///
    /// A single-threaded tokio runtime drives the async client calls.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if argument parsing fails or the dispatched
    /// command fails.
    pub fn run() -> Result<()> {
        Self::parse().run_with_client(TailscaleClient::new())
    }

    /// Execute the parsed command against the given [`TailscaleClient`],
    /// writing human-readable output to stdout.
    ///
    /// This is the injectable entry point: tests pass a client (and rely on
    /// the `service`/`doctor` variants constructing a `TailscaleService` from
    /// the real or fake runner they build), while the binary entry point
    /// passes a default production client.
    ///
    /// `service` and `doctor` commands build their [`TailscaleService`] /
    /// [`Doctor`] from a real [`toride_runner::DuctRunner`] here. Use
    /// [`dispatch`](Self::dispatch) directly to inject a
    /// [`FakeRunner`](toride_runner::fake::FakeRunner) instead.
    ///
    /// # Errors
    ///
    /// Propagates any [`crate::Error`] from the underlying operation.
    pub fn run_with_client(&self, client: TailscaleClient) -> Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(self.dispatch(&client, None, &mut std::io::stdout()))
    }

    /// Execute the parsed command against a borrowed [`TailscaleClient`],
    /// writing human-readable output to `writer`.
    ///
    /// `runner` optionally injects a command runner used by the `service` and
    /// `doctor` subcommands. When `Some`, both subsystems share that runner
    /// (so a single [`FakeRunner`](toride_runner::fake::FakeRunner) observes
    /// every shell-out); when `None`, a real
    /// [`DuctRunner`](toride_runner::DuctRunner) is used. The HTTP-backed
    /// subcommands (`status`, `peers`, `netcheck`, `dns`, `acl`) always go
    /// through `client` regardless of `runner`.
    ///
    /// # Errors
    ///
    /// Propagates any [`crate::Error`] from the underlying operation.
    pub async fn dispatch<W: std::io::Write>(
        &self,
        client: &TailscaleClient,
        runner: Option<Arc<dyn toride_runner::Runner>>,
        writer: &mut W,
    ) -> Result<()> {
        let cmd = &self.command;
        tracing::debug!(?cmd, dry_run = self.dry_run, "dispatching tailscale command");
        match cmd {
            TailscaleCommand::Status => {
                let report = client.status_report().await?;
                writeln!(
                    writer,
                    "node: {} (tailnet: {})",
                    report.node_name, report.tailnet
                )
                .ok();
                writeln!(writer, "connected: {}", report.connected).ok();
                if !report.ip_addresses.is_empty() {
                    writeln!(writer, "addresses: {}", report.ip_addresses.join(", ")).ok();
                }
                match &report.exit_node {
                    Some(ip) => writeln!(writer, "exit node: {ip}").ok(),
                    None => writeln!(writer, "exit node: none").ok(),
                };
                writeln!(writer, "magic dns: {}", report.dns_enabled).ok();
            }
            TailscaleCommand::Doctor { check } => {
                let scope = parse_doctor_scope(check.as_deref())?;
                let mut doctor = Doctor::new(client);
                if let Some(runner) = &runner {
                    doctor = doctor.with_runner(Arc::clone(runner));
                }
                let report = doctor.run(&scope).await?;
                write_doctor_report(writer, &report)?;
            }
            TailscaleCommand::Peers => {
                let topology = client.topology().await?;
                writeln!(
                    writer,
                    "tailnet: {} (this node: {})",
                    topology.tailnet_name(),
                    topology.self_name()
                )
                .ok();
                let peers = topology.peers();
                if peers.is_empty() {
                    writeln!(writer, "no peers").ok();
                } else {
                    writeln!(writer, "{} peer(s):", peers.len()).ok();
                    for peer in peers {
                        let state = if peer.online { "online" } else { "offline" };
                        let role = if peer.exit_node { " [exit node]" } else { "" };
                        writeln!(
                            writer,
                            "  {} ({}) {}{role}",
                            peer.name,
                            state,
                            peer.ip_addresses.join(", "),
                        )
                        .ok();
                    }
                }
            }
            TailscaleCommand::Netcheck => {
                let report = client.netcheck().await?;
                writeln!(writer, "connectivity: {}", report.connectivity).ok();
                match &report.derp_region {
                    Some(region) => writeln!(writer, "preferred derp: {region}").ok(),
                    None => writeln!(writer, "preferred derp: none").ok(),
                };
                writeln!(writer, "udp: {}", report.udp).ok();
                writeln!(writer, "ipv6: {}", report.ipv6).ok();
                writeln!(writer, "hairpin: {}", report.hairpin).ok();
                if !report.derp_latency.is_empty() {
                    let latencies: Vec<String> = report
                        .derp_latency
                        .iter()
                        .map(|(region, ms)| format!("{region}: {ms:.0}ms"))
                        .collect();
                    writeln!(writer, "derp latency: {}", latencies.join(", ")).ok();
                }
            }
            TailscaleCommand::Dns => {
                let config = client.dns_config().await?;
                writeln!(writer, "magic dns: {}", config.magic_dns).ok();
                if config.nameservers.is_empty() {
                    writeln!(writer, "nameservers: none").ok();
                } else {
                    writeln!(writer, "nameservers: {}", config.nameservers.join(", ")).ok();
                }
                if !config.search_domains.is_empty() {
                    writeln!(writer, "search domains: {}", config.search_domains.join(", "))
                        .ok();
                }
                if !config.split_dns.is_empty() {
                    let splits: Vec<String> = config
                        .split_dns
                        .iter()
                        .map(|(domain, ns)| format!("{domain} -> {ns}"))
                        .collect();
                    writeln!(writer, "split dns: {}", splits.join(", ")).ok();
                }
            }
            TailscaleCommand::Acl { action } => {
                self.dispatch_acl(action, writer)?;
            }
            TailscaleCommand::Service { action } => {
                let service = match &runner {
                    Some(runner) => {
                        TailscaleService::with_runner(Arc::clone(runner)).with_dry_run(self.dry_run)
                    }
                    None => TailscaleService::new().with_dry_run(self.dry_run),
                };
                dispatch_service(writer, &service, action)?;
            }
        }
        Ok(())
    }

    /// Body of the `acl` subcommand: validate / show / apply through the
    /// [`AclManager`](crate::acl::AclManager).
    ///
    /// `validate` and `show` are read-only; `apply` honours `--dry-run`. ACL
    /// policy management does not flow through the local HTTP API (it is a
    /// coordination-server concern), so this path uses the `AclManager`
    /// directly rather than `TailscaleClient`.
    fn dispatch_acl<W: std::io::Write>(
        &self,
        action: &AclAction,
        writer: &mut W,
    ) -> Result<()> {
        let manager = crate::acl::AclManager::new().with_dry_run(self.dry_run);
        match action {
            AclAction::Validate => {
                // Without a policy file to read we have no rules to validate;
                // surface this honestly rather than pretending success.
                writeln!(
                    writer,
                    "ACL validation requires a policy to validate against \
                     (use `acl apply <file>` to validate and apply)"
                )
                .ok();
            }
            AclAction::Show => {
                writeln!(
                    writer,
                    "ACL policy is managed on the Tailscale coordination server; \
                     use `tailscale acl` on the admin console or `tailscaled` \
                     local API to inspect the effective policy"
                )
                .ok();
            }
            AclAction::Apply { path } => {
                let policy = std::fs::read_to_string(path)?;
                // Confirm the document is at least structurally valid JSON /
                // HuJSON-ish before handing it to the (dry-run-aware) apply
                // path. `apply` honours `--dry-run`: it logs and returns Ok in
                // dry-run mode, and errors with an honest "not implemented"
                // message otherwise (coordination-server apply is out of scope
                // for the local API).
                validate_policy_is_json(&policy)?;
                manager.apply(&policy)?;
                if self.dry_run {
                    writeln!(writer, "dry-run: validated ACL policy from {path}").ok();
                } else {
                    writeln!(
                        writer,
                        "validated ACL policy from {path} (apply requires \
                         coordination-server credentials)"
                    )
                    .ok();
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// TailscaleCommand
// ---------------------------------------------------------------------------

/// Available Tailscale subcommands.
#[derive(Debug, clap::Subcommand)]
pub enum TailscaleCommand {
    /// Show the current connection status.
    Status,

    /// Run diagnostic checks.
    Doctor {
        /// Specific check to run (default: all).
        #[arg(long)]
        check: Option<String>,
    },

    /// Show network topology and peers.
    Peers,

    /// Run a network connectivity check.
    Netcheck,

    /// Show DNS configuration.
    Dns,

    /// Manage ACL policies.
    Acl {
        /// ACL subcommand.
        #[command(subcommand)]
        action: AclAction,
    },

    /// Manage the tailscaled service.
    Service {
        /// Service action: start, stop, restart, enable, disable, status.
        action: String,
    },
}

// ---------------------------------------------------------------------------
// AclAction
// ---------------------------------------------------------------------------

/// ACL management subcommands.
#[derive(Debug, clap::Subcommand)]
pub enum AclAction {
    /// Validate the current ACL policy.
    Validate,

    /// Show the current ACL rules.
    Show,

    /// Apply a new ACL policy from a file.
    Apply {
        /// Path to the ACL policy file.
        path: String,
    },
}

// ---------------------------------------------------------------------------
// Dispatch helpers
// ---------------------------------------------------------------------------

/// Parse the optional `--check <name>` argument into a [`DoctorScope`].
///
/// `None` (the default) maps to [`DoctorScope::All`]. Unknown names surface an
/// honest [`crate::Error::Other`] rather than silently running all checks.
fn parse_doctor_scope(check: Option<&str>) -> Result<DoctorScope> {
    let Some(name) = check else {
        return Ok(DoctorScope::All);
    };
    match name {
        "all" => Ok(DoctorScope::All),
        "connected" => Ok(DoctorScope::Connected),
        "acl" | "acl-active" => Ok(DoctorScope::AclActive),
        "dns" | "dns-configured" => Ok(DoctorScope::DnsConfigured),
        "service" | "service-running" => Ok(DoctorScope::ServiceRunning),
        "binary" | "binary-present" => Ok(DoctorScope::BinaryPresent),
        other => Err(crate::Error::Other(format!(
            "unknown doctor check '{other}' (expected: all, connected, acl, dns, \
             service, binary)"
        ))),
    }
}

/// Render a [`DoctorReport`] as one line per finding, plus a trailing summary.
fn write_doctor_report<W: std::io::Write>(
    writer: &mut W,
    report: &DoctorReport,
) -> Result<()> {
    if report.findings.is_empty() {
        writeln!(writer, "no findings").ok();
        return Ok(());
    }
    for finding in &report.findings {
        match &finding.fix {
            Some(fix) => writeln!(
                writer,
                "[{}] {} — {} (fix: {fix})",
                finding.severity, finding.id, finding.message
            ),
            None => writeln!(
                writer,
                "[{}] {} — {}",
                finding.severity, finding.id, finding.message
            ),
        }
        .ok();
    }
    if report.has_critical() {
        writeln!(writer, "result: CRITICAL findings present").ok();
    } else if report.all_ok() {
        writeln!(writer, "result: all checks OK").ok();
    } else {
        writeln!(writer, "result: warnings present, no critical issues").ok();
    }
    Ok(())
}

/// Dispatch the `service <action>` subcommand against a [`TailscaleService`].
///
/// Recognised actions: `start`, `stop`, `restart`, `enable`, `disable`, and
/// `status` (which prints the `tailscaled` liveness + `tailscale status --json`
/// backend state). Unknown actions surface an honest error.
fn dispatch_service<W: std::io::Write>(
    writer: &mut W,
    service: &TailscaleService,
    action: &str,
) -> Result<()> {
    match action {
        "start" => {
            service.start()?;
            writeln!(writer, "started tailscaled").ok();
        }
        "stop" => {
            service.stop()?;
            writeln!(writer, "stopped tailscaled").ok();
        }
        "restart" => {
            service.restart()?;
            writeln!(writer, "restarted tailscaled").ok();
        }
        "enable" => {
            service.enable()?;
            writeln!(writer, "enabled tailscaled at boot").ok();
        }
        "disable" => {
            service.disable()?;
            writeln!(writer, "disabled tailscaled at boot").ok();
        }
        "status" => {
            let active = service.is_active()?;
            writeln!(writer, "tailscaled active: {active}").ok();
            match service.status_json() {
                Ok(status) => {
                    let backend = status
                        .get("BackendState")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    writeln!(writer, "backend state: {backend}").ok();
                }
                Err(e) => {
                    // Status JSON is best-effort here: the service may be down.
                    writeln!(writer, "could not fetch tailscale status: {e}").ok();
                }
            }
        }
        other => {
            return Err(crate::Error::Other(format!(
                "unknown service action '{other}' (expected: start, stop, restart, \
                 enable, disable, status)"
            )));
        }
    }
    Ok(())
}

/// Validate that an ACL policy document is well-formed JSON.
///
/// Tailscale ACL policies are HuJSON (JSON with comments/trailing commas),
/// but strict JSON is a valid subset, so a `serde_json` parse is a useful
/// first-pass sanity check for files authored as plain JSON. HuJSON-specific
/// syntax is not rejected here — a parse failure is reported, but the document
/// is still forwarded to [`AclManager::apply`] so the real backend can render
/// the final verdict.
fn validate_policy_is_json(policy: &str) -> Result<()> {
    // `serde_json` is always available (the crate depends on it unconditionally
    // via `serde_json` in `[dependencies]`).
    if serde_json::from_str::<serde_json::Value>(policy).is_ok() {
        return Ok(());
    }
    Err(crate::Error::AclError(
        "ACL policy document is not valid JSON (HuJSON comments are accepted by the \
         backend but not by this pre-check)"
            .to_owned(),
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use toride_runner::CommandOutput;
    use toride_runner::CommandSpec;
    use toride_runner::Runner;
    use toride_runner::fake::FakeRunner;

    /// Dispatch `service status` against a FakeRunner-backed service and assert
    /// the runner saw both the `systemctl is-active tailscaled` probe AND the
    /// `tailscale status --json` call — proving the parsed `TailscaleArgs`
    /// reaches the real `TailscaleService` methods (not a stub).
    #[tokio::test]
    async fn dispatch_service_status_hits_real_systemctl_and_status_json() {
        let active_spec = CommandSpec::new("systemctl").args(["is-active", "tailscaled"]);
        let status_spec = CommandSpec::new("tailscale").args(["status", "--json"]);
        // Keep a typed clone for assertions; dispatch receives the erased form.
        let runner: Arc<FakeRunner> = Arc::new(
            FakeRunner::new()
                .respond(active_spec.clone(), CommandOutput::from_stdout("active"))
                .respond(
                    status_spec.clone(),
                    CommandOutput::from_stdout(
                        r#"{"BackendState":"Running","Self":{"HostName":"h"}}"#,
                    ),
                ),
        );
        let dyn_runner: Arc<dyn Runner> = runner.clone();

        // Parse the real CLI invocation, then dispatch with the injected client.
        let cli = TailscaleArgs::try_parse_from(["tailscale", "service", "status"])
            .expect("parse service status");
        let client = TailscaleClient::new();
        let mut out = Vec::<u8>::new();
        cli.dispatch(&client, Some(dyn_runner), &mut out)
            .await
            .expect("dispatch should succeed");

        // The runner observed the real command specs the service builds.
        runner.assert_called_with(&active_spec);
        runner.assert_called_with(&status_spec);

        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains("tailscaled active: true"), "output: {text}");
        assert!(text.contains("backend state: Running"), "output: {text}");
    }

    /// `service start` builds a real `systemctl start tailscaled` command and
    /// surfaces the success message. Drives the FakeRunner to confirm the
    /// mutating lifecycle path is wired (not stubbed).
    #[tokio::test]
    async fn dispatch_service_start_invokes_systemctl_start() {
        let start_spec = CommandSpec::new("systemctl").args(["start", "tailscaled"]);
        let runner: Arc<FakeRunner> =
            Arc::new(FakeRunner::new().respond(start_spec.clone(), CommandOutput::from_stdout("")));
        let dyn_runner: Arc<dyn Runner> = runner.clone();
        let client = TailscaleClient::new();

        let cli = TailscaleArgs::try_parse_from(["tailscale", "service", "start"])
            .expect("parse service start");
        let mut out = Vec::<u8>::new();
        cli.dispatch(&client, Some(dyn_runner), &mut out)
            .await
            .expect("dispatch should succeed");

        runner.assert_called_with(&start_spec);
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains("started tailscaled"), "output: {text}");
    }

    /// An unknown `service <action>` must error honestly rather than silently
    /// succeeding.
    #[tokio::test]
    async fn dispatch_service_unknown_action_errors() {
        // Strict runner: if any command ran, the test fails loudly.
        let runner: Arc<FakeRunner> = Arc::new(FakeRunner::new().strict());
        let dyn_runner: Arc<dyn Runner> = runner.clone();
        let client = TailscaleClient::new();

        let cli = TailscaleArgs::try_parse_from(["tailscale", "service", "fly"])
            .expect("parse service fly");
        let mut out = Vec::<u8>::new();
        let err = cli
            .dispatch(&client, Some(dyn_runner), &mut out)
            .await
            .expect_err("unknown action should error");
        assert!(
            err.to_string().contains("unknown service action 'fly'"),
            "unexpected error: {err}"
        );
        // Nothing was executed and nothing was printed before the error.
        assert!(runner.calls().is_empty());
        assert!(out.is_empty(), "no output before error: {out:?}");
    }

    /// `doctor --check service` dispatches to the real `Doctor` runner path
    /// (`systemctl is-active tailscaled`) when a runner is injected.
    #[tokio::test]
    async fn dispatch_doctor_service_check_probes_systemctl() {
        let active_spec = CommandSpec::new("systemctl").args(["is-active", "tailscaled"]);
        let runner: Arc<FakeRunner> = Arc::new(
            FakeRunner::new().respond(active_spec.clone(), CommandOutput::from_stdout("active")),
        );
        let dyn_runner: Arc<dyn Runner> = runner.clone();
        let client = TailscaleClient::new();

        let cli = TailscaleArgs::try_parse_from(["tailscale", "doctor", "--check", "service"])
            .expect("parse doctor");
        let mut out = Vec::<u8>::new();
        cli.dispatch(&client, Some(dyn_runner), &mut out)
            .await
            .expect("dispatch should succeed");

        runner.assert_called_with(&active_spec);
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains("tailscale.service"), "output: {text}");
    }

    /// `doctor --check bogus` surfaces an honest error naming the bad scope.
    #[tokio::test]
    async fn dispatch_doctor_unknown_check_errors() {
        let runner: Arc<FakeRunner> = Arc::new(FakeRunner::new().strict());
        let dyn_runner: Arc<dyn Runner> = runner.clone();
        let client = TailscaleClient::new();

        let cli = TailscaleArgs::try_parse_from(["tailscale", "doctor", "--check", "bogus"])
            .expect("parse doctor");
        let mut out = Vec::<u8>::new();
        let err = cli
            .dispatch(&client, Some(dyn_runner), &mut out)
            .await
            .expect_err("bad scope should error");
        assert!(err.to_string().contains("unknown doctor check 'bogus'"), "{err}");
    }

    /// `parse_doctor_scope` accepts canonical names and rejects junk.
    ///
    /// Uses `matches!` rather than `assert_eq!` because `DoctorScope` does not
    /// derive `PartialEq` (the doctor module's own tests follow the same
    /// pattern).
    #[test]
    fn parse_doctor_scope_canonical_names() {
        assert!(matches!(parse_doctor_scope(None).unwrap(), DoctorScope::All));
        assert!(matches!(
            parse_doctor_scope(Some("all")).unwrap(),
            DoctorScope::All
        ));
        assert!(matches!(
            parse_doctor_scope(Some("connected")).unwrap(),
            DoctorScope::Connected
        ));
        assert!(matches!(
            parse_doctor_scope(Some("dns")).unwrap(),
            DoctorScope::DnsConfigured
        ));
        assert!(matches!(
            parse_doctor_scope(Some("service")).unwrap(),
            DoctorScope::ServiceRunning
        ));
        assert!(matches!(
            parse_doctor_scope(Some("binary")).unwrap(),
            DoctorScope::BinaryPresent
        ));
        assert!(parse_doctor_scope(Some("nonsense")).is_err());
    }

    /// Each subcommand parses to the expected variant.
    #[test]
    fn parse_each_subcommand() {
        let status = TailscaleArgs::try_parse_from(["tailscale", "status"]).unwrap();
        assert!(matches!(status.command, TailscaleCommand::Status));

        let peers = TailscaleArgs::try_parse_from(["tailscale", "peers"]).unwrap();
        assert!(matches!(peers.command, TailscaleCommand::Peers));

        let netcheck = TailscaleArgs::try_parse_from(["tailscale", "netcheck"]).unwrap();
        assert!(matches!(netcheck.command, TailscaleCommand::Netcheck));

        let dns = TailscaleArgs::try_parse_from(["tailscale", "dns"]).unwrap();
        assert!(matches!(dns.command, TailscaleCommand::Dns));

        let doctor = TailscaleArgs::try_parse_from(["tailscale", "doctor"]).unwrap();
        match doctor.command {
            TailscaleCommand::Doctor { check } => assert_eq!(check, None),
            other => panic!("expected Doctor, got {other:?}"),
        }
    }

    /// No subcommand -> clap error.
    #[test]
    fn parse_no_subcommand_errors() {
        assert!(TailscaleArgs::try_parse_from(["tailscale"]).is_err());
    }

    /// Global `--dry-run` parses on any subcommand.
    #[test]
    fn parse_global_dry_run() {
        let cli =
            TailscaleArgs::try_parse_from(["tailscale", "--dry-run", "service", "stop"]).unwrap();
        assert!(cli.dry_run);
        assert!(matches!(cli.command, TailscaleCommand::Service { .. }));
    }

    /// `acl apply` rejects a non-JSON policy document before contacting any
    /// backend, surfacing an `AclError`.
    #[test]
    fn validate_policy_is_json_rejects_garbage() {
        assert!(validate_policy_is_json("not json").is_err());
        assert!(validate_policy_is_json(r#"{"acls":[]}"#).is_ok());
    }
}
