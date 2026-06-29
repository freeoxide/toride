//! Command-line interface for toride-cloud.
//!
//! Defines the CLI argument structure using clap, plus the dispatch layer that
//! maps each [`Commands`] variant to the corresponding [`CloudClient`] /
//! [`Doctor`] call. Only compiled when the `cli` feature is enabled.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::CloudProvider;
use crate::client::CloudClient;
use crate::doctor::{Doctor, DoctorScope};
use crate::error::Result;
use crate::render;
use crate::validate;

/// Cloud provider security group management CLI for toride.
#[derive(Parser, Debug)]
#[command(
    name = "toride-cloud",
    about = "Cloud provider security group and firewall management"
)]
pub struct Cli {
    /// Path to configuration file.
    #[arg(short, long, default_value = "~/.config/toride/cloud/config.json")]
    pub config: PathBuf,

    /// Enable verbose logging.
    #[arg(short, long)]
    pub verbose: bool,

    /// Cloud provider to use (overrides auto-detection).
    #[arg(short, long)]
    pub provider: Option<String>,

    /// The subcommand to execute.
    #[command(subcommand)]
    pub command: Commands,
}

impl Cli {
    /// Resolve the `--provider` flag into a [`CloudProvider`].
    ///
    /// Returns [`CloudProvider::Unknown`] when no override is given so that the
    /// dispatch layer can decide whether to auto-detect (`Detect`/`List`/...) or
    /// treat the absence as an error.
    pub fn resolve_provider(&self) -> CloudProvider {
        match &self.provider {
            Some(p) => CloudProvider::from_str_loose(p),
            None => CloudProvider::Unknown,
        }
    }

    /// Build the production [`CloudClient`] for this invocation.
    ///
    /// Uses the explicit `--provider` override when given, otherwise
    /// auto-detects via [`CloudClient::detect`].
    fn build_client(&self) -> Result<CloudClient> {
        match &self.provider {
            Some(p) => Ok(CloudClient::for_provider(CloudProvider::from_str_loose(p))),
            None => CloudClient::detect(),
        }
    }

    /// Run the selected subcommand against a production client.
    ///
    /// Constructs a [`CloudClient`] (auto-detecting or honouring `--provider`)
    /// and delegates to [`Self::run_with_client`].
    ///
    /// # Errors
    ///
    /// Propagates any [`crate::Error`] returned by the underlying client or
    /// diagnostic engine.
    pub fn run(&self) -> Result<()> {
        let client = self.build_client()?;
        self.run_with_client(&client)
    }

    /// Run the selected subcommand against an injected client.
    ///
    /// Exposed so tests (and future embedding callers) can drive the dispatch
    /// with a [`CloudClient`] backed by a `FakeRunner`, proving each variant
    /// reaches the correct provider-client call without shelling out.
    ///
    /// # Errors
    ///
    /// Propagates any [`crate::Error`] returned by the underlying client or
    /// diagnostic engine.
    pub fn run_with_client(&self, client: &CloudClient) -> Result<()> {
        match &self.command {
            Commands::Detect => {
                // Detection happens at client construction; here we just report
                // what the client resolved to so the operator can verify it.
                println!("{}", client.provider);
                Ok(())
            }

            Commands::List { format } => {
                let groups = client.list_security_groups()?;
                if format.eq_ignore_ascii_case("json") {
                    // The `serde` feature is optional and the spec types don't
                    // derive Serialize unconditionally, so emit a stable
                    // Debug-based view rather than pulling in a JSON dep here.
                    for group in &groups {
                        println!("{group:?}");
                    }
                } else {
                    if groups.is_empty() {
                        println!("No security groups found.");
                    }
                    for group in &groups {
                        print!("{}", render::render_security_group(group));
                    }
                }
                Ok(())
            }

            Commands::Show { name } => {
                let group = client.get_security_group(name)?;
                print!("{}", render::render_security_group(&group));
                Ok(())
            }

            Commands::Doctor { scope } => {
                let doctor = Doctor::new(client.provider);
                let scope = DoctorScope::from_cli_str(scope);
                let report = doctor.run(&scope)?;
                println!("{report}");
                Ok(())
            }

            Commands::Render { name: Some(id) } => {
                let group = client.get_security_group(id)?;
                print!("{}", render::render_security_group(&group));
                Ok(())
            }

            Commands::Render { name: None } => {
                let groups = client.list_security_groups()?;
                for group in &groups {
                    print!("{}", render::render_security_group(group));
                }
                Ok(())
            }

            Commands::Validate { name: Some(id) } => {
                let group = client.get_security_group(id)?;
                validate::validate_security_group(&group)?;
                println!("ok: {id} is valid");
                Ok(())
            }

            Commands::Validate { name: None } => {
                let groups = client.list_security_groups()?;
                let mut failures = 0usize;
                for group in &groups {
                    if let Err(e) = validate::validate_security_group(group) {
                        failures += 1;
                        eprintln!("invalid: {}: {e}", group.name);
                    }
                }
                if failures == 0 {
                    println!("ok: all {} group(s) are valid", groups.len());
                }
                Ok(())
            }
        }
    }
}

/// Available CLI subcommands.
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Detect the current cloud provider.
    Detect,

    /// List all security groups / firewalls.
    List {
        /// Output format (table, json).
        #[arg(short, long, default_value = "table")]
        format: String,
    },

    /// Show details of a specific security group.
    Show {
        /// Security group name or ID.
        name: String,
    },

    /// Run diagnostic checks.
    Doctor {
        /// Scope of checks (all, binaries, security-groups, agent).
        #[arg(short, long, default_value = "all")]
        scope: String,
    },

    /// Render firewall rules in human-readable format.
    Render {
        /// Security group name or ID (omit for all).
        name: Option<String>,
    },

    /// Validate firewall rules without applying changes.
    Validate {
        /// Security group name or ID (omit for all).
        name: Option<String>,
    },
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::CloudClient;
    use std::sync::Arc;
    use toride_runner::fake::FakeRunner;
    use toride_runner::{CommandOutput, CommandSpec, Runner};

    /// Real `aws ec2 describe-security-groups --output json` response.
    ///
    /// Source:
    /// <https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-security-groups.html>
    const AWS_DESCRIBE_SAMPLE: &str = r#"{
        "SecurityGroups": [
            {
                "Description": "Allows SSH access",
                "GroupName": "ssh-allowed",
                "IpPermissions": [
                    {
                        "FromPort": 22,
                        "IpProtocol": "tcp",
                        "IpRanges": [
                            { "CidrIp": "203.0.113.0/24", "Description": "SSH from corp" }
                        ],
                        "ToPort": 22
                    }
                ],
                "OwnerId": "123456789012",
                "GroupId": "sg-903004f8",
                "IpPermissionsEgress": [
                    {
                        "IpProtocol": "-1",
                        "IpRanges": [ { "CidrIp": "0.0.0.0/0" } ]
                    }
                ],
                "VpcId": "vpc-1a2b3c4d"
            }
        ]
    }"#;

    // -- resolve_provider -----------------------------------------------------

    #[test]
    fn resolve_provider_uses_explicit_override() {
        let cli = Cli::parse_from(["toride-cloud", "--provider", "aws", "detect"]);
        assert_eq!(cli.resolve_provider(), CloudProvider::Aws);
    }

    #[test]
    fn resolve_provider_defaults_to_unknown() {
        let cli = Cli::parse_from(["toride-cloud", "detect"]);
        assert_eq!(cli.resolve_provider(), CloudProvider::Unknown);
    }

    #[test]
    fn build_client_with_explicit_provider_skips_detection() {
        // An explicit --provider must build a client without touching the
        // filesystem or env (which detection would). AWS resolves cleanly.
        let cli = Cli::parse_from(["toride-cloud", "--provider", "aws", "detect"]);
        let client = cli.build_client().expect("explicit provider builds");
        assert_eq!(client.provider, CloudProvider::Aws);
    }

    // -- dispatch: Detect -----------------------------------------------------

    #[test]
    fn detect_dispatches_and_prints_resolved_provider() {
        // `Detect` honours an explicit --provider override and reports it. We
        // inject a FakeRunner-bearing client to prove the dispatch path runs
        // end-to-end without needing a real cloud environment.
        let runner = Arc::new(FakeRunner::new());
        let client = CloudClient::for_provider_with_runner(
            CloudProvider::Aws,
            runner.clone() as Arc<dyn Runner>,
        );
        let cli = Cli::parse_from(["toride-cloud", "--provider", "aws", "detect"]);
        cli.run_with_client(&client).expect("detect succeeds");
        // Detect performs no command execution, so the runner is untouched.
        assert!(runner.calls().is_empty(), "detect must not shell out");
    }

    // -- dispatch: List -> AwsClient::list_security_groups --------------------

    #[test]
    fn list_dispatches_to_aws_list_security_groups() {
        // Parse `list`, inject a FakeRunner-backed AWS client carrying a real
        // describe-security-groups JSON sample, and assert the dispatch reached
        // AwsClient::list_security_groups by inspecting the recorded command.
        let runner = Arc::new(
            FakeRunner::new().push_response(CommandOutput::from_stdout(AWS_DESCRIBE_SAMPLE)),
        );
        let client = CloudClient::for_provider_with_runner(
            CloudProvider::Aws,
            runner.clone() as Arc<dyn Runner>,
        );

        let cli = Cli::parse_from(["toride-cloud", "--provider", "aws", "list"]);
        cli.run_with_client(&client)
            .expect("list dispatch succeeds");

        let calls = runner.calls();
        assert_eq!(calls.len(), 1, "expected exactly one aws CLI call");
        let expected = CommandSpec::new("aws").args([
            "ec2",
            "describe-security-groups",
            "--region",
            "us-east-1",
            "--output",
            "json",
        ]);
        assert_eq!(calls[0].program, expected.program, "program mismatch");
        assert_eq!(calls[0].args, expected.args, "args mismatch");
    }

    #[test]
    fn list_with_unknown_provider_returns_error_without_shelling_out() {
        // An unknown provider must short-circuit in the facade before any
        // provider client is constructed, so the runner records no calls.
        let runner = Arc::new(FakeRunner::new().strict());
        let client = CloudClient::for_provider_with_runner(
            CloudProvider::Unknown,
            runner.clone() as Arc<dyn Runner>,
        );
        let cli = Cli::parse_from(["toride-cloud", "--provider", "doesnotexist", "list"]);
        let err = cli
            .run_with_client(&client)
            .expect_err("unknown provider must error");
        assert!(
            matches!(err, crate::Error::ProviderNotFound(_)),
            "expected ProviderNotFound, got {err:?}"
        );
        assert!(
            runner.calls().is_empty(),
            "must not shell out for unknown provider"
        );
    }

    // -- DoctorScope parsing --------------------------------------------------

    #[test]
    fn doctor_scope_parses_known_values() {
        assert_eq!(DoctorScope::from_cli_str("all"), DoctorScope::All);
        assert_eq!(DoctorScope::from_cli_str("Binaries"), DoctorScope::Binaries);
        assert_eq!(
            DoctorScope::from_cli_str("security-groups"),
            DoctorScope::SecurityGroups
        );
        assert_eq!(DoctorScope::from_cli_str("sg"), DoctorScope::SecurityGroups);
        assert_eq!(DoctorScope::from_cli_str("agent"), DoctorScope::Agent);
        assert_eq!(DoctorScope::from_cli_str("network"), DoctorScope::Network);
    }

    #[test]
    fn doctor_scope_unknown_falls_back_to_all() {
        // A typo must never silently run zero checks.
        assert_eq!(DoctorScope::from_cli_str("nonsense"), DoctorScope::All);
        assert_eq!(DoctorScope::from_cli_str(""), DoctorScope::All);
    }
}
