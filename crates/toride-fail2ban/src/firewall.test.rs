//! Comprehensive tests for the firewall diagnostics module.
//!
//! Every test uses [`FakeRunner`] to avoid spawning real processes. The tests
//! cover binary availability probes, nft set / iptables chain existence checks,
//! the aggregate `diagnose()` method, and edge cases such as missing binaries
//! and mixed backend configurations.

use super::*;
use crate::command::{CommandOutput, FakeRunner};

// ---------------------------------------------------------------------------
// Helpers -- pre-built FakeRunner configurations
// ---------------------------------------------------------------------------

/// Shorthand for a successful `CommandOutput`.
fn ok_output(stdout: &str) -> CommandOutput {
    CommandOutput {
        stdout: stdout.to_string(),
        stderr: String::new(),
        exit_code: Some(0),
        success: true,
    }
}

/// Shorthand for a failed `CommandOutput` with a given exit code.
fn fail_output(stderr: &str, exit_code: i32) -> CommandOutput {
    CommandOutput {
        stdout: String::new(),
        stderr: stderr.to_string(),
        exit_code: Some(exit_code),
        success: false,
    }
}

/// Build a `FakeRunner` pre-configured so that `nft --version` succeeds and
/// `nft list set inet fail2ban f2b-chain` succeeds (set present).
fn nft_ready_runner() -> FakeRunner {
    let mut fake = FakeRunner::new();
    fake.with_response("nft", &["--version"], ok_output("nftables v1.0.6"));
    fake.with_response(
        "nft",
        &["list", "set", "inet", NFT_TABLE, IPTABLES_CHAIN],
        ok_output(""),
    );
    fake
}

/// Build a `FakeRunner` pre-configured so that `iptables --version` succeeds,
/// `iptables -n -L f2b-chain` succeeds (chain present), and
/// `ip6tables --version` succeeds.
fn iptables_ready_runner() -> FakeRunner {
    let mut fake = FakeRunner::new();
    fake.with_response("iptables", &["--version"], ok_output("iptables v1.8.9"));
    fake.with_response("iptables", &["-n", "-L", IPTABLES_CHAIN], ok_output(""));
    fake.with_response("ip6tables", &["--version"], ok_output("ip6tables v1.8.9"));
    fake
}

// ---------------------------------------------------------------------------
// FirewallChecker construction
// ---------------------------------------------------------------------------

#[test]
fn firewall_checker_new_with_fake_runner() {
    let fake = FakeRunner::new();
    let _checker = FirewallChecker::new(&fake);
}

#[test]
fn firewall_checker_new_records_no_calls_at_construction() {
    let fake = FakeRunner::new();
    let _checker = FirewallChecker::new(&fake);
    // Construction should not invoke any commands.
    assert!(fake.calls().is_empty());
}

// ---------------------------------------------------------------------------
// check_nft_available()
// ---------------------------------------------------------------------------

#[test]
fn check_nft_available_succeeds() {
    let mut fake = FakeRunner::new();
    fake.with_response("nft", &["--version"], ok_output("nftables v1.0.6"));

    let checker = FirewallChecker::new(&fake);
    let result = checker.check_nft_available().unwrap();

    assert!(result);
    assert_eq!(fake.calls().len(), 1);
    assert_eq!(fake.calls()[0].0, "nft");
    assert_eq!(fake.calls()[0].1, vec!["--version"]);
}

#[test]
fn check_nft_available_missing_binary_returns_false() {
    let mut fake = FakeRunner::new();
    fake.with_response("nft", &["--version"], fail_output("nft: not found", 127));

    let checker = FirewallChecker::new(&fake);
    let result = checker.check_nft_available().unwrap();

    assert!(!result);
}

#[test]
fn check_nft_available_permission_denied_returns_false() {
    let mut fake = FakeRunner::new();
    fake.with_response("nft", &["--version"], fail_output("Permission denied", 126));

    let checker = FirewallChecker::new(&fake);
    let result = checker.check_nft_available().unwrap();

    assert!(!result);
}

// ---------------------------------------------------------------------------
// check_iptables_available()
// ---------------------------------------------------------------------------

#[test]
fn check_iptables_available_succeeds() {
    let mut fake = FakeRunner::new();
    fake.with_response("iptables", &["--version"], ok_output("iptables v1.8.9"));

    let checker = FirewallChecker::new(&fake);
    let result = checker.check_iptables_available().unwrap();

    assert!(result);
    assert_eq!(fake.calls().len(), 1);
    assert_eq!(fake.calls()[0].0, "iptables");
    assert_eq!(fake.calls()[0].1, vec!["--version"]);
}

#[test]
fn check_iptables_available_missing_binary_returns_false() {
    let mut fake = FakeRunner::new();
    fake.with_response(
        "iptables",
        &["--version"],
        fail_output("iptables: not found", 127),
    );

    let checker = FirewallChecker::new(&fake);
    let result = checker.check_iptables_available().unwrap();

    assert!(!result);
}

// ---------------------------------------------------------------------------
// check_ip6tables_available()
// ---------------------------------------------------------------------------

#[test]
fn check_ip6tables_available_succeeds() {
    let mut fake = FakeRunner::new();
    fake.with_response("ip6tables", &["--version"], ok_output("ip6tables v1.8.9"));

    let checker = FirewallChecker::new(&fake);
    let result = checker.check_ip6tables_available().unwrap();

    assert!(result);
    assert_eq!(fake.calls().len(), 1);
}

#[test]
fn check_ip6tables_available_missing_binary_returns_false() {
    let mut fake = FakeRunner::new();
    fake.with_response(
        "ip6tables",
        &["--version"],
        fail_output("ip6tables: not found", 127),
    );

    let checker = FirewallChecker::new(&fake);
    let result = checker.check_ip6tables_available().unwrap();

    assert!(!result);
}

// ---------------------------------------------------------------------------
// check_nft_set()
// ---------------------------------------------------------------------------

#[test]
fn check_nft_set_exists() {
    let mut fake = FakeRunner::new();
    fake.with_response(
        "nft",
        &["list", "set", "inet", NFT_TABLE, "recidive"],
        ok_output(""),
    );

    let checker = FirewallChecker::new(&fake);
    assert!(checker.check_nft_set("recidive").unwrap());
}

#[test]
fn check_nft_set_not_exists() {
    let mut fake = FakeRunner::new();
    fake.with_response(
        "nft",
        &["list", "set", "inet", NFT_TABLE, "nonexistent"],
        fail_output("Error: no such set", 1),
    );

    let checker = FirewallChecker::new(&fake);
    assert!(!checker.check_nft_set("nonexistent").unwrap());
}

#[test]
fn check_nft_set_default_chain_exists() {
    let mut fake = FakeRunner::new();
    fake.with_response(
        "nft",
        &["list", "set", "inet", NFT_TABLE, IPTABLES_CHAIN],
        ok_output(""),
    );

    let checker = FirewallChecker::new(&fake);
    assert!(checker.check_nft_set(IPTABLES_CHAIN).unwrap());
}

// ---------------------------------------------------------------------------
// check_iptables_chain()
// ---------------------------------------------------------------------------

#[test]
fn check_iptables_chain_exists() {
    let mut fake = FakeRunner::new();
    fake.with_response("iptables", &["-n", "-L", "INPUT"], ok_output(""));

    let checker = FirewallChecker::new(&fake);
    assert!(checker.check_iptables_chain("INPUT").unwrap());
}

#[test]
fn check_iptables_chain_not_exists() {
    let mut fake = FakeRunner::new();
    fake.with_response(
        "iptables",
        &["-n", "-L", "no-such-chain"],
        fail_output("iptables: No chain/target/match by that name.", 1),
    );

    let checker = FirewallChecker::new(&fake);
    assert!(!checker.check_iptables_chain("no-such-chain").unwrap());
}

#[test]
fn check_iptables_chain_default_f2b_exists() {
    let mut fake = FakeRunner::new();
    fake.with_response("iptables", &["-n", "-L", IPTABLES_CHAIN], ok_output(""));

    let checker = FirewallChecker::new(&fake);
    assert!(checker.check_iptables_chain(IPTABLES_CHAIN).unwrap());
}

// ---------------------------------------------------------------------------
// diagnose() -- no firewall action
// ---------------------------------------------------------------------------

#[test]
fn diagnose_no_firewall_action_produces_info() {
    let fake = FakeRunner::new();
    let checker = FirewallChecker::new(&fake);
    let findings = checker.diagnose(&["sendmail".to_string()]);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Info);
    assert!(findings[0].id.contains("no-firewall-action"));
    assert!(findings[0].title.to_ascii_lowercase().contains("firewall"));
}

#[test]
fn diagnose_empty_actions_produces_info() {
    let fake = FakeRunner::new();
    let checker = FirewallChecker::new(&fake);
    let findings = checker.diagnose(&[]);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Info);
    assert!(findings[0].id.contains("no-firewall-action"));
}

#[test]
fn diagnose_unrelated_actions_produces_info() {
    let fake = FakeRunner::new();
    let checker = FirewallChecker::new(&fake);
    let findings = checker.diagnose(&[
        "sendmail".to_string(),
        "complain".to_string(),
        "bsd-mail".to_string(),
    ]);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Info);
}

// ---------------------------------------------------------------------------
// diagnose() -- nftables action, nft available, set present
// ---------------------------------------------------------------------------

#[test]
fn diagnose_nftables_action_with_nft_available_and_set_present() {
    let fake = nft_ready_runner();
    let checker = FirewallChecker::new(&fake);
    let findings = checker.diagnose(&["nftables".to_string()]);

    assert!(findings.iter().any(|f| f.id == "firewall.nft.set-present"));
    let set_present = findings
        .iter()
        .find(|f| f.id == "firewall.nft.set-present")
        .unwrap();
    assert_eq!(set_present.severity, Severity::Ok);
    assert!(!findings.iter().any(|f| f.severity >= Severity::Error));
}

#[test]
fn diagnose_nftables_multiport_variant_matches() {
    let fake = nft_ready_runner();
    let checker = FirewallChecker::new(&fake);
    let findings = checker.diagnose(&["nftables-multiport".to_string()]);

    assert!(findings.iter().any(|f| f.id == "firewall.nft.set-present"));
}

#[test]
fn diagnose_nftables_action_case_insensitive() {
    let fake = nft_ready_runner();
    let checker = FirewallChecker::new(&fake);
    let findings = checker.diagnose(&["NfTaBleS".to_string()]);

    assert!(findings.iter().any(|f| f.id.contains("nft")));
}

// ---------------------------------------------------------------------------
// diagnose() -- nftables action, nft available, set NOT present
// ---------------------------------------------------------------------------

#[test]
fn diagnose_nftables_set_missing_produces_warning() {
    let mut fake = FakeRunner::new();
    fake.with_response("nft", &["--version"], ok_output("nftables v1.0.6"));
    fake.with_response(
        "nft",
        &["list", "set", "inet", NFT_TABLE, IPTABLES_CHAIN],
        fail_output("Error: no such set", 1),
    );

    let checker = FirewallChecker::new(&fake);
    let findings = checker.diagnose(&["nftables".to_string()]);

    assert!(findings.iter().any(|f| f.id == "firewall.nft.set-missing"));
    let set_missing = findings
        .iter()
        .find(|f| f.id == "firewall.nft.set-missing")
        .unwrap();
    assert_eq!(set_missing.severity, Severity::Warning);
    assert!(!set_missing.detail.is_empty());
    assert!(set_missing.fix.is_some());
}

// ---------------------------------------------------------------------------
// diagnose() -- nftables action, nft NOT available (missing binary)
// ---------------------------------------------------------------------------

#[test]
fn diagnose_nftables_nft_missing_produces_critical() {
    let mut fake = FakeRunner::new();
    fake.with_response("nft", &["--version"], fail_output("nft: not found", 127));

    let checker = FirewallChecker::new(&fake);
    let findings = checker.diagnose(&["nftables".to_string()]);

    assert!(findings.iter().any(|f| f.id == "firewall.nft.missing"));
    let missing = findings
        .iter()
        .find(|f| f.id == "firewall.nft.missing")
        .unwrap();
    assert_eq!(missing.severity, Severity::Critical);
    assert!(missing.detail.contains("nft"));
    assert!(missing.fix.is_some());
    assert!(missing.fix.as_ref().unwrap().contains("install"));
}

// ---------------------------------------------------------------------------
// diagnose() -- iptables action, iptables available, chain present, ip6tables available
// ---------------------------------------------------------------------------

#[test]
fn diagnose_iptables_action_all_ok() {
    let fake = iptables_ready_runner();
    let checker = FirewallChecker::new(&fake);
    let findings = checker.diagnose(&["iptables".to_string()]);

    assert!(
        findings
            .iter()
            .any(|f| f.id == "firewall.iptables.chain-present")
    );
    assert!(
        findings
            .iter()
            .any(|f| f.id == "firewall.ip6tables.available")
    );

    let chain_present = findings
        .iter()
        .find(|f| f.id == "firewall.iptables.chain-present")
        .unwrap();
    assert_eq!(chain_present.severity, Severity::Ok);

    let ip6_ok = findings
        .iter()
        .find(|f| f.id == "firewall.ip6tables.available")
        .unwrap();
    assert_eq!(ip6_ok.severity, Severity::Ok);

    assert!(!findings.iter().any(|f| f.severity >= Severity::Warning));
}

#[test]
fn diagnose_iptables_multiport_variant_matches() {
    let fake = iptables_ready_runner();
    let checker = FirewallChecker::new(&fake);
    let findings = checker.diagnose(&["iptables-multiport".to_string()]);

    assert!(
        findings
            .iter()
            .any(|f| f.id == "firewall.iptables.chain-present")
    );
}

// ---------------------------------------------------------------------------
// diagnose() -- iptables action, iptables available, chain NOT present
// ---------------------------------------------------------------------------

#[test]
fn diagnose_iptables_chain_missing_produces_warning() {
    let mut fake = FakeRunner::new();
    fake.with_response("iptables", &["--version"], ok_output("iptables v1.8.9"));
    fake.with_response(
        "iptables",
        &["-n", "-L", IPTABLES_CHAIN],
        fail_output("iptables: No chain/target/match by that name.", 1),
    );
    fake.with_response("ip6tables", &["--version"], ok_output("ip6tables v1.8.9"));

    let checker = FirewallChecker::new(&fake);
    let findings = checker.diagnose(&["iptables".to_string()]);

    assert!(
        findings
            .iter()
            .any(|f| f.id == "firewall.iptables.chain-missing")
    );
    let chain_missing = findings
        .iter()
        .find(|f| f.id == "firewall.iptables.chain-missing")
        .unwrap();
    assert_eq!(chain_missing.severity, Severity::Warning);
    assert!(!chain_missing.detail.is_empty());
    assert!(chain_missing.fix.is_some());
}

// ---------------------------------------------------------------------------
// diagnose() -- iptables action, iptables NOT available
// ---------------------------------------------------------------------------

#[test]
fn diagnose_iptables_missing_binary_produces_critical() {
    let mut fake = FakeRunner::new();
    fake.with_response(
        "iptables",
        &["--version"],
        fail_output("iptables: not found", 127),
    );

    let checker = FirewallChecker::new(&fake);
    let findings = checker.diagnose(&["iptables".to_string()]);

    assert!(findings.iter().any(|f| f.id == "firewall.iptables.missing"));
    let missing = findings
        .iter()
        .find(|f| f.id == "firewall.iptables.missing")
        .unwrap();
    assert_eq!(missing.severity, Severity::Critical);
    assert!(missing.detail.contains("iptables"));
    assert!(missing.fix.is_some());
}

// ---------------------------------------------------------------------------
// diagnose() -- iptables action, ip6tables NOT available (warning)
// ---------------------------------------------------------------------------

#[test]
fn diagnose_ip6tables_missing_produces_warning() {
    let mut fake = FakeRunner::new();
    fake.with_response("iptables", &["--version"], ok_output("iptables v1.8.9"));
    fake.with_response("iptables", &["-n", "-L", IPTABLES_CHAIN], ok_output(""));
    fake.with_response(
        "ip6tables",
        &["--version"],
        fail_output("ip6tables: not found", 127),
    );

    let checker = FirewallChecker::new(&fake);
    let findings = checker.diagnose(&["iptables".to_string()]);

    // iptables chain should be present (Ok).
    assert!(
        findings
            .iter()
            .any(|f| f.id == "firewall.iptables.chain-present")
    );
    // ip6tables should be missing (Warning).
    assert!(
        findings
            .iter()
            .any(|f| f.id == "firewall.ip6tables.missing")
    );
    let ip6_missing = findings
        .iter()
        .find(|f| f.id == "firewall.ip6tables.missing")
        .unwrap();
    assert_eq!(ip6_missing.severity, Severity::Warning);
    assert!(ip6_missing.detail.contains("IPv6"));
    assert!(ip6_missing.fix.is_some());
}

// ---------------------------------------------------------------------------
// diagnose() -- mixed actions: both nftables and iptables
// ---------------------------------------------------------------------------

#[test]
fn diagnose_mixed_actions_checks_both_backends() {
    let mut fake = nft_ready_runner();
    // Add iptables responses on top of nftables ones.
    fake.with_response("iptables", &["--version"], ok_output("iptables v1.8.9"));
    fake.with_response("iptables", &["-n", "-L", IPTABLES_CHAIN], ok_output(""));
    fake.with_response("ip6tables", &["--version"], ok_output("ip6tables v1.8.9"));

    let checker = FirewallChecker::new(&fake);
    let findings = checker.diagnose(&["nftables".to_string(), "iptables".to_string()]);

    // Should have at least one nft finding and one iptables finding.
    assert!(findings.iter().any(|f| f.id.contains("nft")));
    assert!(findings.iter().any(|f| f.id.contains("iptables")));
    // All findings should be Ok severity.
    assert!(findings.iter().all(|f| f.severity == Severity::Ok));
}

#[test]
fn diagnose_mixed_actions_nft_ok_iptables_missing() {
    let mut fake = nft_ready_runner();
    // iptables is missing.
    fake.with_response(
        "iptables",
        &["--version"],
        fail_output("iptables: not found", 127),
    );

    let checker = FirewallChecker::new(&fake);
    let findings = checker.diagnose(&["nftables".to_string(), "iptables".to_string()]);

    // nft should be fine.
    assert!(findings.iter().any(|f| f.id == "firewall.nft.set-present"));
    // iptables should be critical.
    assert!(findings.iter().any(|f| f.id == "firewall.iptables.missing"));
    assert!(findings.iter().any(|f| f.severity == Severity::Critical));
}

// ---------------------------------------------------------------------------
// diagnose() -- action name case sensitivity
// ---------------------------------------------------------------------------

#[test]
fn diagnose_action_matching_is_case_insensitive() {
    let fake = nft_ready_runner();
    let checker = FirewallChecker::new(&fake);
    let findings = checker.diagnose(&["NFTABLES".to_string()]);

    assert!(findings.iter().any(|f| f.id == "firewall.nft.set-present"));
}

// ---------------------------------------------------------------------------
// diagnose() -- correct commands are dispatched
// ---------------------------------------------------------------------------

#[test]
fn diagnose_nftables_dispatches_correct_commands() {
    let mut fake = nft_ready_runner();
    // Also register the set check so it does not fall through to the default.
    fake.with_response(
        "nft",
        &["list", "set", "inet", NFT_TABLE, IPTABLES_CHAIN],
        ok_output(""),
    );

    let checker = FirewallChecker::new(&fake);
    let _findings = checker.diagnose(&["nftables".to_string()]);

    let calls = fake.calls();
    assert!(
        calls
            .iter()
            .any(|(cmd, args)| { cmd == "nft" && args == &["--version".to_string()] })
    );
    assert!(calls.iter().any(|(cmd, args)| {
        cmd == "nft"
            && args
                == &[
                    "list".to_string(),
                    "set".to_string(),
                    "inet".to_string(),
                    NFT_TABLE.to_string(),
                    IPTABLES_CHAIN.to_string(),
                ]
    }));
}

#[test]
fn diagnose_iptables_dispatches_correct_commands() {
    let fake = iptables_ready_runner();
    let checker = FirewallChecker::new(&fake);
    let _findings = checker.diagnose(&["iptables".to_string()]);

    let calls = fake.calls();
    assert!(
        calls
            .iter()
            .any(|(cmd, args)| { cmd == "iptables" && args == &["--version".to_string()] })
    );
    assert!(calls.iter().any(|(cmd, args)| {
        cmd == "iptables"
            && args
                == &[
                    "-n".to_string(),
                    "-L".to_string(),
                    IPTABLES_CHAIN.to_string(),
                ]
    }));
    assert!(
        calls
            .iter()
            .any(|(cmd, args)| { cmd == "ip6tables" && args == &["--version".to_string()] })
    );
}

// ---------------------------------------------------------------------------
// diagnose() -- severity correctness
// ---------------------------------------------------------------------------

#[test]
fn diagnose_no_firewall_action_severity_is_info() {
    let fake = FakeRunner::new();
    let checker = FirewallChecker::new(&fake);
    let findings = checker.diagnose(&["some-action".to_string()]);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Info);
}

#[test]
fn diagnose_nft_set_present_severity_is_ok() {
    let fake = nft_ready_runner();
    let checker = FirewallChecker::new(&fake);
    let findings = checker.diagnose(&["nftables".to_string()]);

    let f = findings
        .iter()
        .find(|f| f.id == "firewall.nft.set-present")
        .unwrap();
    assert_eq!(f.severity, Severity::Ok);
}

#[test]
fn diagnose_nft_missing_severity_is_critical() {
    let mut fake = FakeRunner::new();
    fake.with_response("nft", &["--version"], fail_output("not found", 127));

    let checker = FirewallChecker::new(&fake);
    let findings = checker.diagnose(&["nftables".to_string()]);

    let f = findings
        .iter()
        .find(|f| f.id == "firewall.nft.missing")
        .unwrap();
    assert_eq!(f.severity, Severity::Critical);
}

#[test]
fn diagnose_nft_set_missing_severity_is_warning() {
    let mut fake = FakeRunner::new();
    fake.with_response("nft", &["--version"], ok_output("nftables v1.0.6"));
    fake.with_response(
        "nft",
        &["list", "set", "inet", NFT_TABLE, IPTABLES_CHAIN],
        fail_output("Error: no such set", 1),
    );

    let checker = FirewallChecker::new(&fake);
    let findings = checker.diagnose(&["nftables".to_string()]);

    let f = findings
        .iter()
        .find(|f| f.id == "firewall.nft.set-missing")
        .unwrap();
    assert_eq!(f.severity, Severity::Warning);
}

#[test]
fn diagnose_iptables_chain_present_severity_is_ok() {
    let fake = iptables_ready_runner();
    let checker = FirewallChecker::new(&fake);
    let findings = checker.diagnose(&["iptables".to_string()]);

    let f = findings
        .iter()
        .find(|f| f.id == "firewall.iptables.chain-present")
        .unwrap();
    assert_eq!(f.severity, Severity::Ok);
}

#[test]
fn diagnose_iptables_missing_severity_is_critical() {
    let mut fake = FakeRunner::new();
    fake.with_response("iptables", &["--version"], fail_output("not found", 127));

    let checker = FirewallChecker::new(&fake);
    let findings = checker.diagnose(&["iptables".to_string()]);

    let f = findings
        .iter()
        .find(|f| f.id == "firewall.iptables.missing")
        .unwrap();
    assert_eq!(f.severity, Severity::Critical);
}

#[test]
fn diagnose_iptables_chain_missing_severity_is_warning() {
    let mut fake = FakeRunner::new();
    fake.with_response("iptables", &["--version"], ok_output("iptables v1.8.9"));
    fake.with_response(
        "iptables",
        &["-n", "-L", IPTABLES_CHAIN],
        fail_output("No chain/target/match", 1),
    );
    fake.with_response("ip6tables", &["--version"], ok_output("ip6tables v1.8.9"));

    let checker = FirewallChecker::new(&fake);
    let findings = checker.diagnose(&["iptables".to_string()]);

    let f = findings
        .iter()
        .find(|f| f.id == "firewall.iptables.chain-missing")
        .unwrap();
    assert_eq!(f.severity, Severity::Warning);
}

#[test]
fn diagnose_ip6tables_available_severity_is_ok() {
    let fake = iptables_ready_runner();
    let checker = FirewallChecker::new(&fake);
    let findings = checker.diagnose(&["iptables".to_string()]);

    let f = findings
        .iter()
        .find(|f| f.id == "firewall.ip6tables.available")
        .unwrap();
    assert_eq!(f.severity, Severity::Ok);
}

#[test]
fn diagnose_ip6tables_missing_severity_is_warning() {
    let mut fake = FakeRunner::new();
    fake.with_response("iptables", &["--version"], ok_output("iptables v1.8.9"));
    fake.with_response("iptables", &["-n", "-L", IPTABLES_CHAIN], ok_output(""));
    fake.with_response("ip6tables", &["--version"], fail_output("not found", 127));

    let checker = FirewallChecker::new(&fake);
    let findings = checker.diagnose(&["iptables".to_string()]);

    let f = findings
        .iter()
        .find(|f| f.id == "firewall.ip6tables.missing")
        .unwrap();
    assert_eq!(f.severity, Severity::Warning);
}

// ---------------------------------------------------------------------------
// Finding structure: detail and fix fields
// ---------------------------------------------------------------------------

#[test]
fn diagnose_nft_missing_finding_has_detail_and_fix() {
    let mut fake = FakeRunner::new();
    fake.with_response("nft", &["--version"], fail_output("not found", 127));

    let checker = FirewallChecker::new(&fake);
    let findings = checker.diagnose(&["nftables".to_string()]);

    let f = findings
        .iter()
        .find(|f| f.id == "firewall.nft.missing")
        .unwrap();
    assert!(!f.detail.is_empty());
    assert!(f.fix.is_some());
    assert!(!f.fix.as_ref().unwrap().is_empty());
}

#[test]
fn diagnose_nft_set_missing_finding_has_detail_and_fix() {
    let mut fake = FakeRunner::new();
    fake.with_response("nft", &["--version"], ok_output("nftables v1.0.6"));
    fake.with_response(
        "nft",
        &["list", "set", "inet", NFT_TABLE, IPTABLES_CHAIN],
        fail_output("no such set", 1),
    );

    let checker = FirewallChecker::new(&fake);
    let findings = checker.diagnose(&["nftables".to_string()]);

    let f = findings
        .iter()
        .find(|f| f.id == "firewall.nft.set-missing")
        .unwrap();
    assert!(!f.detail.is_empty());
    assert!(f.fix.is_some());
}

#[test]
fn diagnose_iptables_missing_finding_has_detail_and_fix() {
    let mut fake = FakeRunner::new();
    fake.with_response("iptables", &["--version"], fail_output("not found", 127));

    let checker = FirewallChecker::new(&fake);
    let findings = checker.diagnose(&["iptables".to_string()]);

    let f = findings
        .iter()
        .find(|f| f.id == "firewall.iptables.missing")
        .unwrap();
    assert!(!f.detail.is_empty());
    assert!(f.fix.is_some());
    assert!(!f.fix.as_ref().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// Graceful-error contract for the not-yet-wired inspect_* stubs.
// Commit 3e5e085 replaced two todo!() panics with Error::CommandFailed
// returns. These lock that contract so the stubs cannot silently regress to
// a panic before the nft/iptables CLI integration lands.
// ---------------------------------------------------------------------------

#[test]
#[cfg(feature = "firewall-nft")]
fn inspect_nft_ruleset_json_returns_graceful_error() {
    let fake = FakeRunner::new();
    let checker = FirewallChecker::new(&fake);
    let err = checker.inspect_nft_ruleset_json().unwrap_err();
    assert!(matches!(err, Error::CommandFailed(_)), "got {err:?}");
}

#[test]
#[cfg(feature = "firewall-iptables")]
fn inspect_iptables_rules_returns_graceful_error() {
    let fake = FakeRunner::new();
    let checker = FirewallChecker::new(&fake);
    let err = checker.inspect_iptables_rules().unwrap_err();
    assert!(matches!(err, Error::CommandFailed(_)), "got {err:?}");
}
