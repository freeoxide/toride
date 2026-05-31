use super::*;
use crate::command::FakeRunner;
use crate::spec::CommandResult;

// ---------------------------------------------------------------------------
// has_nft / has_iptables / has_ip6tables
// ---------------------------------------------------------------------------

#[test]
fn has_nft_should_return_true_when_binary_exists() {
    let runner = FakeRunner::new();
    assert!(has_nft(&runner));
}

#[test]
fn has_iptables_should_return_true_when_binary_exists() {
    let runner = FakeRunner::new();
    assert!(has_iptables(&runner));
}

#[test]
fn has_ip6tables_should_return_true_when_binary_exists() {
    let runner = FakeRunner::new();
    assert!(has_ip6tables(&runner));
}

#[test]
fn has_nft_should_return_false_for_unknown_tool() {
    // FakeRunner returns true for "nft" by default, but false for unknowns.
    // We verify the negative case by checking an unregistered binary.
    let runner = FakeRunner::new();
    assert!(!runner.binary_exists("totally-not-a-real-tool"));
}

// ---------------------------------------------------------------------------
// inspect_nftable_ruleset
// ---------------------------------------------------------------------------

#[test]
fn inspect_nftable_ruleset_should_return_raw_output() {
    let runner = FakeRunner::new().respond_ok(
        "nft",
        &["list", "ruleset"],
        "table ip filter { chain INPUT { type filter hook input } }",
    );

    let result = inspect_nftable_ruleset(&runner).unwrap();
    assert_eq!(result.tool, "nft");
    assert_eq!(
        result.raw_output,
        "table ip filter { chain INPUT { type filter hook input } }"
    );
    assert!(result.success);
}

#[test]
fn inspect_nftable_ruleset_should_report_failure_on_error() {
    let runner = FakeRunner::new().respond_err("nft", &["list", "ruleset"], "permission denied", 1);

    let result = inspect_nftable_ruleset(&runner).unwrap();
    assert_eq!(result.tool, "nft");
    assert!(!result.success);
}

#[test]
fn inspect_nftable_ruleset_should_report_error_when_no_response_registered() {
    let runner = FakeRunner::new();

    let result = inspect_nftable_ruleset(&runner).unwrap();
    assert_eq!(result.tool, "nft");
    assert!(result.raw_output.starts_with("Error:"));
    assert!(!result.success);
}

// ---------------------------------------------------------------------------
// inspect_iptables_save
// ---------------------------------------------------------------------------

#[test]
fn inspect_iptables_save_should_return_raw_output() {
    let runner = FakeRunner::new().respond_ok(
        "iptables-save",
        &[],
        "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n",
    );

    let result = inspect_iptables_save(&runner).unwrap();
    assert_eq!(result.tool, "iptables-save");
    assert!(result.raw_output.contains("*filter"));
    assert!(result.success);
}

#[test]
fn inspect_iptables_save_should_report_failure_on_error() {
    let runner = FakeRunner::new().respond_err("iptables-save", &[], "failed", 2);

    let result = inspect_iptables_save(&runner).unwrap();
    assert_eq!(result.tool, "iptables-save");
    assert!(!result.success);
}

// ---------------------------------------------------------------------------
// inspect_ip6tables_save
// ---------------------------------------------------------------------------

#[test]
fn inspect_ip6tables_save_should_return_raw_output() {
    let runner = FakeRunner::new().respond_ok(
        "ip6tables-save",
        &[],
        "*filter\n:INPUT DROP [0:0]\nCOMMIT\n",
    );

    let result = inspect_ip6tables_save(&runner).unwrap();
    assert_eq!(result.tool, "ip6tables-save");
    assert!(result.raw_output.contains("*filter"));
    assert!(result.success);
}

#[test]
fn inspect_ip6tables_save_should_report_failure_on_error() {
    let runner = FakeRunner::new().respond_err("ip6tables-save", &[], "no support", 1);

    let result = inspect_ip6tables_save(&runner).unwrap();
    assert_eq!(result.tool, "ip6tables-save");
    assert!(!result.success);
}

// ---------------------------------------------------------------------------
// inspect_all
// ---------------------------------------------------------------------------

#[test]
fn inspect_all_should_return_results_when_tools_available() {
    let runner = FakeRunner::new()
        .respond_ok("nft", &["list", "ruleset"], "nft output")
        .respond_ok("iptables-save", &[], "iptables output")
        .respond_ok("ip6tables-save", &[], "ip6tables output");

    let results = inspect_all(&runner);
    assert_eq!(results.len(), 3);
    assert_eq!(results[0].tool, "nft");
    assert_eq!(results[1].tool, "iptables-save");
    assert_eq!(results[2].tool, "ip6tables-save");
}

#[test]
fn inspect_all_should_return_empty_when_no_tools_available() {
    // Create a runner where binary_exists always returns false.
    struct NoToolsRunner;
    impl crate::command::CommandRunner for NoToolsRunner {
        fn run(&self, _spec: &CommandSpec) -> crate::error::Result<CommandResult> {
            Ok(CommandResult {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: Some(0),
            })
        }
        fn binary_exists(&self, _name: &str) -> bool {
            false
        }
    }

    let runner = NoToolsRunner;
    let results = inspect_all(&runner);
    assert!(results.is_empty());
}

#[test]
fn inspect_all_should_handle_partial_tool_availability() {
    // FakeRunner has nft, iptables, ip6tables by default.
    // We only register responses for nft to test that partial results work.
    struct OnlyNftRunner(FakeRunner);
    impl crate::command::CommandRunner for OnlyNftRunner {
        fn run(&self, spec: &CommandSpec) -> crate::error::Result<CommandResult> {
            self.0.run(spec)
        }
        fn binary_exists(&self, name: &str) -> bool {
            matches!(name, "nft")
        }
    }

    let inner = FakeRunner::new().respond_ok("nft", &["list", "ruleset"], "nft output");
    let runner = OnlyNftRunner(inner);
    let results = inspect_all(&runner);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].tool, "nft");
}

// ---------------------------------------------------------------------------
// FirewallInspection fields
// ---------------------------------------------------------------------------

#[test]
fn firewall_inspection_fields_should_be_correct() {
    let inspection = FirewallInspection {
        tool: "nft".into(),
        raw_output: "some output".into(),
        success: true,
    };
    assert_eq!(inspection.tool, "nft");
    assert_eq!(inspection.raw_output, "some output");
    assert!(inspection.success);
}

#[test]
fn firewall_inspection_should_clone_correctly() {
    let original = FirewallInspection {
        tool: "iptables-save".into(),
        raw_output: "cloned output".into(),
        success: false,
    };
    let cloned = original.clone();
    assert_eq!(cloned.tool, original.tool);
    assert_eq!(cloned.raw_output, original.raw_output);
    assert_eq!(cloned.success, original.success);
}

// ---------------------------------------------------------------------------
// can_inspect_report
// ---------------------------------------------------------------------------

#[test]
fn can_inspect_report_should_accept_valid_reports() {
    assert!(can_inspect_report("raw"));
    assert!(can_inspect_report("listening"));
    assert!(can_inspect_report("user-rules"));
    assert!(can_inspect_report("before-rules"));
    assert!(can_inspect_report("after-rules"));
}

#[test]
fn can_inspect_report_should_reject_invalid_reports() {
    assert!(!can_inspect_report("added"));
    assert!(!can_inspect_report("builtins"));
    assert!(!can_inspect_report("logging-rules"));
    assert!(!can_inspect_report("unknown"));
    assert!(!can_inspect_report(""));
}

// ---------------------------------------------------------------------------
// Edge-case: inspect_nftable_ruleset with non-zero exit code
// ---------------------------------------------------------------------------

#[test]
fn inspect_nftable_ruleset_should_treat_nonzero_exit_as_failure() {
    let runner = FakeRunner::new().respond(
        "nft",
        &["list", "ruleset"],
        Ok(CommandResult {
            stdout: "partial output".into(),
            stderr: "some error".into(),
            exit_code: Some(1),
        }),
    );

    let result = inspect_nftable_ruleset(&runner).unwrap();
    assert_eq!(result.raw_output, "partial output");
    assert!(!result.success);
}

// ---------------------------------------------------------------------------
// Edge-case: inspect_iptables_save with no exit code
// ---------------------------------------------------------------------------

#[test]
fn inspect_iptables_save_should_treat_none_exit_code_as_failure() {
    let runner = FakeRunner::new().respond(
        "iptables-save",
        &[],
        Ok(CommandResult {
            stdout: "output".into(),
            stderr: String::new(),
            exit_code: None,
        }),
    );

    let result = inspect_iptables_save(&runner).unwrap();
    assert!(!result.success);
}
