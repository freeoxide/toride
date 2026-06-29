//! Firewall inspection module (read-only diagnostics).
//!
//! Provides raw inspection of nftables and iptables rules for diagnostic
//! purposes. This module does NOT write or modify any firewall state.
//! All mutations must go through the UFW CLI via the `client` module.

use crate::command::CommandRunner;
use crate::error::Result;
use crate::spec::CommandSpec;
use std::time::Duration;

/// Raw firewall inspection result.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FirewallInspection {
    /// The tool used for inspection (nft, iptables-save, ip6tables-save).
    pub tool: String,
    /// Raw output from the inspection command.
    pub raw_output: String,
    /// Whether the inspection succeeded.
    pub success: bool,
}

/// Check if nftables is available on the system.
pub fn has_nft<R: CommandRunner + ?Sized>(runner: &R) -> bool {
    runner.binary_exists("nft")
}

/// Check if iptables is available on the system.
pub fn has_iptables<R: CommandRunner + ?Sized>(runner: &R) -> bool {
    runner.binary_exists("iptables-save") || runner.binary_exists("iptables")
}

/// Check if ip6tables is available on the system.
pub fn has_ip6tables<R: CommandRunner + ?Sized>(runner: &R) -> bool {
    runner.binary_exists("ip6tables-save") || runner.binary_exists("ip6tables")
}

fn build_spec(program: &str, args: &[&str]) -> CommandSpec {
    CommandSpec {
        program: program.into(),
        args: args.iter().map(|s| (*s).to_string()).collect(),
        timeout: Some(Duration::from_secs(10)),
        requires_root: false,
        force_c_locale: true,
        redact_logs: false,
    }
}

/// Inspect nftables ruleset using `nft list ruleset`.
pub fn inspect_nftable_ruleset(runner: &dyn CommandRunner) -> Result<FirewallInspection> {
    let spec = build_spec("nft", &["list", "ruleset"]);
    match runner.run(&spec) {
        Ok(result) => Ok(FirewallInspection {
            tool: "nft".into(),
            raw_output: result.stdout,
            success: result.exit_code == Some(0),
        }),
        Err(e) => Ok(FirewallInspection {
            tool: "nft".into(),
            raw_output: format!("Error: {e}"),
            success: false,
        }),
    }
}

/// Inspect iptables rules using `iptables-save`.
pub fn inspect_iptables_save(runner: &dyn CommandRunner) -> Result<FirewallInspection> {
    let spec = build_spec("iptables-save", &[]);
    match runner.run(&spec) {
        Ok(result) => Ok(FirewallInspection {
            tool: "iptables-save".into(),
            raw_output: result.stdout,
            success: result.exit_code == Some(0),
        }),
        Err(e) => Ok(FirewallInspection {
            tool: "iptables-save".into(),
            raw_output: format!("Error: {e}"),
            success: false,
        }),
    }
}

/// Inspect ip6tables rules using `ip6tables-save`.
pub fn inspect_ip6tables_save(runner: &dyn CommandRunner) -> Result<FirewallInspection> {
    let spec = build_spec("ip6tables-save", &[]);
    match runner.run(&spec) {
        Ok(result) => Ok(FirewallInspection {
            tool: "ip6tables-save".into(),
            raw_output: result.stdout,
            success: result.exit_code == Some(0),
        }),
        Err(e) => Ok(FirewallInspection {
            tool: "ip6tables-save".into(),
            raw_output: format!("Error: {e}"),
            success: false,
        }),
    }
}

/// Run all available inspections, returning results for each tool found.
pub fn inspect_all(runner: &dyn CommandRunner) -> Vec<FirewallInspection> {
    let mut results = Vec::new();
    if has_nft(runner) {
        results.push(
            inspect_nftable_ruleset(runner).unwrap_or_else(|_| FirewallInspection {
                tool: "nft".into(),
                raw_output: "inspection failed".into(),
                success: false,
            }),
        );
    }
    if has_iptables(runner) {
        results.push(
            inspect_iptables_save(runner).unwrap_or_else(|_| FirewallInspection {
                tool: "iptables-save".into(),
                raw_output: "inspection failed".into(),
                success: false,
            }),
        );
    }
    if has_ip6tables(runner) {
        results.push(
            inspect_ip6tables_save(runner).unwrap_or_else(|_| FirewallInspection {
                tool: "ip6tables-save".into(),
                raw_output: "inspection failed".into(),
                success: false,
            }),
        );
    }
    results
}

/// Check if a UFW report type can be inspected via the firewall module.
pub fn can_inspect_report(report: &str) -> bool {
    matches!(
        report,
        "raw" | "listening" | "user-rules" | "before-rules" | "after-rules"
    )
}

#[cfg(test)]
#[path = "firewall.test.rs"]
mod tests;
