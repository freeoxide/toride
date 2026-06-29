//! Clap argument definitions for the WireGuard CLI.
//!
//! Provides structured argument parsing for WireGuard management commands
//! using the `clap` derive API, plus a [`WireguardCli::run`] dispatch that
//! maps every [`WireguardCommand`] to the corresponding real client call.
//!
//! The dispatch is split into two entry points:
//!
//! - [`WireguardCli::run`] -- constructs production clients backed by
//!   [`DuctRunner`](toride_runner::DuctRunner). Used by the `toride-wireguard`
//!   binary entry point.
//! - [`WireguardCli::run_with_runner`] -- accepts an injectable
//!   [`Runner`](toride_runner::Runner), so the entire dispatch (including the
//!   runner-backed `wg`/`wg-quick`/`wg genkey` commands) can be exercised with
//!   [`FakeRunner`](toride_runner::FakeRunner) in tests without root or a real
//!   `wg` binary.

use std::fs;

use clap::{Parser, Subcommand};

use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// WireguardCli
// ---------------------------------------------------------------------------

/// WireGuard tunnel management CLI.
#[derive(Debug, Parser)]
#[command(name = "wireguard", about = "WireGuard VPN tunnel management")]
pub struct WireguardCli {
    /// The subcommand to execute.
    #[command(subcommand)]
    pub command: WireguardCommand,

    /// Interface name (e.g. `wg0`).
    #[arg(short, long, global = true, default_value = "wg0")]
    pub interface: String,
}

// ---------------------------------------------------------------------------
// WireguardCommand
// ---------------------------------------------------------------------------

/// Available WireGuard management commands.
#[derive(Debug, Subcommand)]
pub enum WireguardCommand {
    /// Show interface status and peer information.
    Show,

    /// Bring up a WireGuard interface.
    Up,

    /// Bring down a WireGuard interface.
    Down,

    /// Generate a new key pair.
    Genkey,

    /// Run diagnostic checks.
    Doctor {
        /// Scope of diagnostics to run.
        #[arg(short, long, default_value = "all")]
        scope: String,
    },

    /// Manage interface configuration.
    Config {
        /// The configuration subcommand to run.
        #[command(subcommand)]
        action: ConfigAction,
    },
}

// ---------------------------------------------------------------------------
// ConfigAction
// ---------------------------------------------------------------------------

/// Configuration subcommands.
#[derive(Debug, Subcommand)]
pub enum ConfigAction {
    /// Show the current configuration.
    Show,

    /// Apply a new configuration from a file.
    Apply {
        /// Path to the configuration file.
        path: String,

        /// Preview changes before applying.
        #[arg(long)]
        dry_run: bool,
    },

    /// Backup the current configuration.
    Backup,

    /// Restore the most recent backup.
    Restore,
}

// ---------------------------------------------------------------------------
// Dispatch
//
// The `cli` feature pulls in clap *and* the runner-backed backing modules
// (`client`, `doctor`, `service` -- see `Cargo.toml`'s `cli` feature
// definition), so the dispatch below is free to call every backing method
// unconditionally.
//
// `Up`/`Down` route through `WireguardService` (which shells out to
// `wg-quick`), not `WireguardClient`, because the client intentionally only
// wraps the `wg` tool itself. `Genkey` calls the free function
// [`crate::key::generate_keypair_with`], which runs the real `wg genkey` /
// `wg pubkey` pair through the injected runner. `Config::Show`/`Apply` use the
// runner-backed `WireguardClient::showconf`/`setconf`; `Config::Backup`/
// `Restore` touch the filesystem via `BackupManager` (no `wg` call).
//
// The runner is taken *by value* and cloned into each subsystem, because
// `WireguardClient::with_runner`, `WireguardService::with_runner`, and
// `Doctor::with_runner` all own the runner they receive. The production
// [`DuctRunner`](toride_runner::DuctRunner) and the test
// [`FakeRunner`](toride_runner::FakeRunner) are both cheaply `Clone`, so this
// bound costs nothing in practice.
// ---------------------------------------------------------------------------

impl WireguardCli {
    /// Run the parsed command against production clients backed by a
    /// [`DuctRunner`](toride_runner::DuctRunner).
    ///
    /// This is the entry point used by the `toride-wireguard` binary. For
    /// testing, prefer [`WireguardCli::run_with_runner`].
    ///
    /// # Errors
    ///
    /// Propagates [`Error`] from any underlying client/service/doctor call.
    pub fn run(&self) -> Result<()> {
        self.run_with_runner(toride_runner::DuctRunner)
    }

    /// Run the parsed command using an explicit command [`Runner`].
    ///
    /// Every runner-backed subsystem (`WireguardClient`, `WireguardService`,
    /// `Doctor`, key generation) is constructed from the same injected runner,
    /// so a single [`FakeRunner`](toride_runner::FakeRunner) can drive the
    /// whole dispatch in tests without a real `wg` binary or root privileges.
    ///
    /// # Errors
    ///
    /// Propagates [`Error`] from any underlying call.
    pub fn run_with_runner<R>(&self, runner: R) -> Result<()>
    where
        R: toride_runner::Runner + Clone + Send + Sync + 'static,
    {
        let interface = self.interface.as_str();
        match &self.command {
            WireguardCommand::Show => {
                let client = crate::client::WireguardClient::with_runner(runner.clone());
                let entries = client.show()?;
                if entries.is_empty() {
                    println!("no WireGuard interfaces found");
                } else {
                    for entry in entries {
                        println!(
                            "{:<10} pub={} port={}",
                            entry.interface, entry.public_key, entry.listen_port
                        );
                    }
                }
                Ok(())
            }

            WireguardCommand::Up => {
                let svc = crate::service::WireguardService::with_runner(interface, runner.clone());
                svc.up()?;
                println!("brought up {interface}");
                Ok(())
            }

            WireguardCommand::Down => {
                let svc = crate::service::WireguardService::with_runner(interface, runner.clone());
                svc.down()?;
                println!("brought down {interface}");
                Ok(())
            }

            WireguardCommand::Genkey => {
                let (private, public) = crate::key::generate_keypair_with(&runner)?;
                println!("private: {private}");
                println!("public:  {public}");
                Ok(())
            }

            WireguardCommand::Doctor { scope } => {
                let scope = parse_scope(scope)?;
                let report = crate::doctor::Doctor::with_runner(runner.clone()).run(&scope)?;
                println!("{report:?}");
                Ok(())
            }

            WireguardCommand::Config { action } => match action {
                ConfigAction::Show => {
                    let client = crate::client::WireguardClient::with_runner(runner.clone());
                    let conf = client.showconf(interface)?;
                    // Never print a live private key to stdout -- redact the
                    // `PrivateKey = ...` value emitted by `wg showconf` so the
                    // displayed config is safe to share/log.
                    print!("{}", redact_private_key(&conf));
                    Ok(())
                }

                ConfigAction::Apply { path, dry_run } => {
                    let config = fs::read_to_string(path).map_err(|e| {
                        Error::ConfigParse(format!("failed to read config file {}: {e}", path))
                    })?;
                    if *dry_run {
                        println!(
                            "dry-run: would apply {path} ({}) to {interface}",
                            config.len()
                        );
                        return Ok(());
                    }
                    let client = crate::client::WireguardClient::with_runner(runner.clone());
                    client.setconf(interface, &config)?;
                    println!("applied {path} to {interface}");
                    Ok(())
                }

                ConfigAction::Backup => {
                    let paths = crate::paths::WireguardPaths::new();
                    let dest = crate::backup::BackupManager::new(&paths).backup(interface)?;
                    println!("backed up {interface} to {}", dest.display());
                    Ok(())
                }

                ConfigAction::Restore => {
                    let paths = crate::paths::WireguardPaths::new();
                    let dest =
                        crate::backup::BackupManager::new(&paths).restore_latest(interface)?;
                    println!("restored {interface} from {}", dest.display());
                    Ok(())
                }
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Dispatch helpers
// ---------------------------------------------------------------------------

/// Redact the `PrivateKey` value in `wg showconf` output before printing.
///
/// `wg showconf` emits an `[Interface]` section with a `PrivateKey = <key>`
/// line. Printing that verbatim would leak the live private key to stdout
/// (and into any shell scrollback / pipe capture). This replaces the value
/// with `***REDACTED***`, preserving the line structure so the output still
/// reads as a valid-looking config.
fn redact_private_key(conf: &str) -> String {
    let mut out = String::with_capacity(conf.len());
    for line in conf.lines() {
        let trimmed = line.trim_start();
        if trimmed
            .strip_prefix("PrivateKey")
            .is_some_and(|rest| rest.trim_start().starts_with('='))
        {
            // Preserve any leading indentation, then rewrite as
            // `PrivateKey = ***REDACTED***`.
            let indent = &line[..line.len() - trimmed.len()];
            out.push_str(indent);
            out.push_str("PrivateKey = ***REDACTED***");
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    // `conf.lines()` drops a trailing newline; if the original lacked one,
    // undo the extra newline we appended so we don't grow the output.
    if !conf.ends_with('\n') && out.ends_with('\n') {
        out.pop();
    }
    out
}

/// Translate the user-supplied `--scope` string into a [`DoctorScope`].
fn parse_scope(scope: &str) -> Result<crate::doctor::DoctorScope> {
    use crate::doctor::DoctorScope;
    match scope.to_ascii_lowercase().as_str() {
        "all" => Ok(DoctorScope::All),
        "setup" => Ok(DoctorScope::Setup),
        "connectivity" => Ok(DoctorScope::Connectivity),
        "security" => Ok(DoctorScope::Security),
        other => Err(Error::Other(format!(
            "unknown doctor scope `{other}` (expected: all, setup, connectivity, security)"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parse_show_command() {
        let cli = WireguardCli::try_parse_from(["wireguard", "show"]).unwrap();
        assert!(matches!(cli.command, WireguardCommand::Show));
        assert_eq!(cli.interface, "wg0");
    }

    #[test]
    fn parse_up_with_interface() {
        let cli = WireguardCli::try_parse_from(["wireguard", "-i", "wg1", "up"]).unwrap();
        assert!(matches!(cli.command, WireguardCommand::Up));
        assert_eq!(cli.interface, "wg1");
    }

    #[test]
    fn parse_genkey() {
        let cli = WireguardCli::try_parse_from(["wireguard", "genkey"]).unwrap();
        assert!(matches!(cli.command, WireguardCommand::Genkey));
    }

    #[test]
    fn parse_doctor() {
        let cli =
            WireguardCli::try_parse_from(["wireguard", "doctor", "--scope", "security"]).unwrap();
        assert!(matches!(cli.command, WireguardCommand::Doctor { .. }));
    }

    #[test]
    fn parse_config_show() {
        let cli = WireguardCli::try_parse_from(["wireguard", "config", "show"]).unwrap();
        assert!(matches!(
            cli.command,
            WireguardCommand::Config {
                action: ConfigAction::Show
            }
        ));
    }

    #[test]
    fn parse_config_apply_dry_run() {
        let cli = WireguardCli::try_parse_from([
            "wireguard",
            "config",
            "apply",
            "--dry-run",
            "/tmp/wg0.conf",
        ])
        .unwrap();
        if let WireguardCommand::Config {
            action: ConfigAction::Apply { path, dry_run },
        } = cli.command
        {
            assert_eq!(path, "/tmp/wg0.conf");
            assert!(dry_run);
        } else {
            panic!("expected ConfigAction::Apply");
        }
    }

    // -----------------------------------------------------------------------
    // Dispatch tests -- parse a command, run it against a FakeRunner, and
    // assert the dispatch reached the real client method by inspecting the
    // runner's recorded calls.
    // -----------------------------------------------------------------------

    use toride_runner::fake::FakeRunner;

    /// `show` must dispatch to `WireguardClient::show`, i.e. emit
    /// `wg show all dump` to the runner.
    #[cfg(feature = "client")]
    #[test]
    fn dispatch_show_runs_wg_show_all_dump() {
        // One interface row; the parser only surfaces 5-field interface rows.
        let canned = "wg0\tprivkeyAAAA\tpubkeyBBBB\t51820\toff\n";
        let runner =
            FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(canned));
        // Keep a clone so we can inspect recorded calls after dispatch.
        let recorder = runner.clone();
        let cli = WireguardCli::try_parse_from(["wireguard", "show"]).unwrap();
        cli.run_with_runner(runner).unwrap();

        let calls = recorder.calls();
        let matched = calls
            .iter()
            .any(|c| c.program == "wg" && c.args == vec!["show", "all", "dump"]);
        assert!(
            matched,
            "dispatch did not emit `wg show all dump`: {calls:?}"
        );
    }

    /// `genkey` must dispatch to [`crate::key::generate_keypair_with`], which
    /// runs `wg genkey` then `wg pubkey`. Both must be recorded by the runner.
    #[test]
    fn dispatch_genkey_runs_wg_genkey_and_pubkey() {
        // `wg genkey` prints a private key, `wg pubkey` prints a public key.
        // Both are valid 32-byte Base64 (44 chars, valid trailing symbol).
        // The runner serves them in FIFO order.
        let private = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        // A trailing symbol < 0x50 (e.g. '0') keeps the base64 block valid.
        let public = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC0=";
        let runner = FakeRunner::new()
            .push_response(toride_runner::CommandOutput::from_stdout(private))
            .push_response(toride_runner::CommandOutput::from_stdout(public));

        // Keep a clone so we can inspect recorded calls after dispatch.
        let recorder = runner.clone();
        let cli = WireguardCli::try_parse_from(["wireguard", "genkey"]).unwrap();
        cli.run_with_runner(runner).unwrap();

        let calls = recorder.calls();
        let saw_genkey = calls
            .iter()
            .any(|c| c.program == "wg" && c.args.first().is_some_and(|a| a == "genkey"));
        let saw_pubkey = calls
            .iter()
            .any(|c| c.program == "wg" && c.args.first().is_some_and(|a| a == "pubkey"));
        assert!(saw_genkey, "dispatch did not run `wg genkey`: {calls:?}");
        assert!(saw_pubkey, "dispatch did not run `wg pubkey`: {calls:?}");
    }

    /// `config show` must redact the live `PrivateKey` value before printing.
    #[cfg(feature = "client")]
    #[test]
    fn dispatch_config_show_redacts_private_key() {
        let conf = "[Interface]\nPrivateKey = s3cr3tbase64==\nListenPort = 51820\n";
        assert_eq!(
            redact_private_key(conf),
            "[Interface]\nPrivateKey = ***REDACTED***\nListenPort = 51820\n"
        );
    }

    /// `config show` must dispatch to `WireguardClient::showconf`, emitting
    /// `wg showconf <interface>` to the runner.
    #[cfg(feature = "client")]
    #[test]
    fn dispatch_config_show_runs_wg_showconf() {
        let conf = "[Interface]\nListenPort = 51820\n";
        let runner =
            FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(conf));
        let recorder = runner.clone();
        let cli =
            WireguardCli::try_parse_from(["wireguard", "-i", "wg2", "config", "show"]).unwrap();
        cli.run_with_runner(runner).unwrap();

        let expected = toride_runner::CommandSpec::new("wg").args(["showconf", "wg2"]);
        let calls = recorder.calls();
        let matched = calls
            .iter()
            .any(|c| c.program == expected.program && c.args == expected.args);
        assert!(
            matched,
            "dispatch did not emit `wg showconf wg2`: {calls:?}"
        );
    }

    /// `up` must dispatch to `WireguardService::up`, emitting
    /// `wg-quick up <interface>` to the runner. Requires the `service` feature.
    #[cfg(feature = "service")]
    #[test]
    fn dispatch_up_runs_wg_quick_up() {
        let runner = FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(""));
        let recorder = runner.clone();
        let cli = WireguardCli::try_parse_from(["wireguard", "-i", "wg0", "up"]).unwrap();
        // `wg-quick up` may also trigger a systemctl probe; we only assert the
        // primary `wg-quick up wg0` call was made.
        let result = cli.run_with_runner(runner);
        let _ = result;
        let calls = recorder.calls();
        let matched = calls
            .iter()
            .any(|c| c.program == "wg-quick" && c.args == vec!["up", "wg0"]);
        assert!(
            matched,
            "dispatch did not emit `wg-quick up wg0`: {calls:?}"
        );
    }
}
