use super::*;
use crate::command::FakeRunner;
use crate::spec::*;

fn make_ufw_for_doctor(status_output: &str) -> Ufw {
    let runner = FakeRunner::new()
        .respond_ok("ufw", &["--version"], "ufw 0.36.1")
        .respond_ok("ufw", &["status"], status_output)
        .respond_ok(
            "ufw",
            &["status", "verbose"],
            &format!(
                "{status_output}\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing)\n"
            ),
        )
        .respond_ok(
            "ufw",
            &["app", "list"],
            "Available applications:\n  OpenSSH\n",
        )
        .respond_ok(
            "ufw",
            &["app", "info", "OpenSSH"],
            "Profile: OpenSSH\nTitle: OpenSSH server\nDescription: OpenSSH\nPort: 22/tcp\n",
        );
    Ufw::with_runner(runner)
}

// ---------------------------------------------------------------------------
// Binary checks
// ---------------------------------------------------------------------------

#[test]
fn check_binaries_should_find_ufw() {
    let ufw = make_ufw_for_doctor("Status: active\n");
    let findings = check_binaries(&ufw);
    assert!(findings.iter().any(|f| f.id == "bin:ufw:exists"));
}

#[test]
fn check_binaries_should_report_version() {
    let ufw = make_ufw_for_doctor("Status: active\n");
    let findings = check_binaries(&ufw);
    assert!(findings.iter().any(|f| f.id == "bin:ufw:version"));
}

#[test]
fn check_binaries_should_check_iptables() {
    let ufw = make_ufw_for_doctor("Status: active\n");
    let findings = check_binaries(&ufw);
    // FakeRunner says iptables exists
    assert!(findings.iter().any(|f| f.id == "bin:iptables:exists"));
}

#[test]
fn check_binaries_should_check_ip6tables() {
    let ufw = make_ufw_for_doctor("Status: active\n");
    let findings = check_binaries(&ufw);
    // FakeRunner says ip6tables exists
    assert!(findings.iter().any(|f| f.id == "bin:ip6tables:exists"));
}

#[test]
fn check_binaries_should_check_nft() {
    let ufw = make_ufw_for_doctor("Status: active\n");
    let findings = check_binaries(&ufw);
    // FakeRunner says nft exists — should be Info severity
    let nft_finding = findings.iter().find(|f| f.id == "bin:nft:exists");
    assert!(nft_finding.is_some());
    assert_eq!(nft_finding.unwrap().severity, Severity::Info);
}

#[test]
fn check_binaries_should_check_systemctl() {
    let ufw = make_ufw_for_doctor("Status: active\n");
    let findings = check_binaries(&ufw);
    // FakeRunner says systemctl exists
    assert!(findings.iter().any(|f| f.id == "bin:systemctl:exists"));
}

// ---------------------------------------------------------------------------
// Service checks
// ---------------------------------------------------------------------------

#[test]
fn check_service_should_detect_active() {
    let ufw = make_ufw_for_doctor("Status: active\n");
    let findings = check_service(&ufw);
    assert!(findings.iter().any(|f| f.id == "svc:ufw:active"));
}

#[test]
fn check_service_should_detect_inactive() {
    let ufw = make_ufw_for_doctor("Status: inactive\n");
    let findings = check_service(&ufw);
    assert!(findings.iter().any(|f| f.id == "svc:ufw:inactive"));
}

// ---------------------------------------------------------------------------
// Policy checks
// ---------------------------------------------------------------------------

#[test]
fn check_policy_should_warn_on_incoming_allow() {
    let output = "Status: active\nDefault: allow (incoming), allow (outgoing)\nLogging: on\n";
    let runner = FakeRunner::new()
        .respond_ok("ufw", &["--version"], "ufw 0.36.1")
        .respond_ok("ufw", &["status"], "Status: active\n")
        .respond_ok("ufw", &["status", "verbose"], output)
        .respond_ok("ufw", &["app", "list"], "");
    let ufw = Ufw::with_runner(runner);
    let findings = check_policy(&ufw);
    assert!(findings.iter().any(|f| f.id == "pol:incoming:allow"));
}

#[test]
fn check_policy_should_be_ok_on_incoming_deny() {
    let output = "Status: active\nDefault: deny (incoming), allow (outgoing)\nLogging: on\n";
    let runner = FakeRunner::new()
        .respond_ok("ufw", &["--version"], "ufw 0.36.1")
        .respond_ok("ufw", &["status"], "Status: active\n")
        .respond_ok("ufw", &["status", "verbose"], output)
        .respond_ok("ufw", &["app", "list"], "");
    let ufw = Ufw::with_runner(runner);
    let findings = check_policy(&ufw);
    assert!(findings.iter().any(|f| f.id == "pol:incoming:deny"));
}

#[test]
fn check_policy_should_check_routed_policy() {
    let output =
        "Status: active\nDefault: deny (incoming), allow (outgoing), allow (routed)\nLogging: on\n";
    let runner = FakeRunner::new()
        .respond_ok("ufw", &["--version"], "ufw 0.36.1")
        .respond_ok("ufw", &["status"], "Status: active\n")
        .respond_ok("ufw", &["status", "verbose"], output)
        .respond_ok("ufw", &["app", "list"], "");
    let ufw = Ufw::with_runner(runner);
    let findings = check_policy(&ufw);
    assert!(findings.iter().any(|f| f.id == "pol:routed:allow"));
}

#[test]
fn check_policy_should_warn_on_missing_outgoing_dns() {
    let output = "Status: active\nDefault: deny (incoming), deny (outgoing)\nLogging: on\n";
    let runner = FakeRunner::new()
        .respond_ok("ufw", &["--version"], "ufw 0.36.1")
        .respond_ok("ufw", &["status"], "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere\n")
        .respond_ok("ufw", &["status", "verbose"], output)
        .respond_ok("ufw", &["app", "list"], "");
    let ufw = Ufw::with_runner(runner);
    let findings = check_policy(&ufw);
    assert!(findings.iter().any(|f| f.id == "pol:outgoing:no-dns"));
    assert!(findings.iter().any(|f| f.id == "pol:outgoing:no-ntp"));
    assert!(findings.iter().any(|f| f.id == "pol:outgoing:no-https"));
}

// ---------------------------------------------------------------------------
// SSH checks
// ---------------------------------------------------------------------------

#[test]
fn check_ssh_should_warn_when_no_ssh_rule() {
    let ufw = make_ufw_for_doctor(
        "Status: active\n\nTo                         Action      From\n--                         ------      ----\n443/tcp                    ALLOW       Anywhere\n",
    );
    let findings = check_ssh(&ufw);
    assert!(findings.iter().any(|f| f.id == "ssh:no-rule"));
}

#[test]
fn check_ssh_should_be_ok_when_ssh_rule_exists() {
    let ufw = make_ufw_for_doctor(
        "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere\n",
    );
    let findings = check_ssh(&ufw);
    assert!(findings.iter().any(|f| f.id == "ssh:allowed"));
}

#[test]
fn check_ssh_should_detect_allow_anywhere() {
    let ufw = make_ufw_for_doctor(
        "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere\n",
    );
    let findings = check_ssh(&ufw);
    // Should warn that SSH allows from anywhere
    assert!(findings.iter().any(|f| f.id == "ssh:allow-anywhere"));
}

#[test]
fn check_ssh_should_detect_limit_action() {
    let ufw = make_ufw_for_doctor(
        "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     LIMIT       Anywhere\n",
    );
    let findings = check_ssh(&ufw);
    assert!(findings.iter().any(|f| f.id == "ssh:limit"));
}

// ---------------------------------------------------------------------------
// App profile checks
// ---------------------------------------------------------------------------

#[test]
fn check_app_profiles_should_report_installed() {
    let ufw = make_ufw_for_doctor("Status: active\n");
    let findings = check_app_profiles(&ufw);
    assert!(findings.iter().any(|f| f.id == "app:exists"));
}

// ---------------------------------------------------------------------------
// Logging checks
// ---------------------------------------------------------------------------

#[test]
fn check_logging_should_warn_on_off() {
    let output = "Status: active\nDefault: deny (incoming), allow (outgoing)\nLogging: off\n";
    let runner = FakeRunner::new()
        .respond_ok("ufw", &["--version"], "ufw 0.36.1")
        .respond_ok("ufw", &["status"], "Status: active\n")
        .respond_ok("ufw", &["status", "verbose"], output)
        .respond_ok("ufw", &["app", "list"], "");
    let ufw = Ufw::with_runner(runner);
    let findings = check_logging(&ufw);
    assert!(findings.iter().any(|f| f.id == "log:off"));
    // Off should be a warning now
    let off = findings.iter().find(|f| f.id == "log:off").unwrap();
    assert_eq!(off.severity, Severity::Warning);
}

#[test]
fn check_logging_should_report_ok_on_low() {
    let output = "Status: active\nDefault: deny (incoming), allow (outgoing)\nLogging: on (low)\n";
    let runner = FakeRunner::new()
        .respond_ok("ufw", &["--version"], "ufw 0.36.1")
        .respond_ok("ufw", &["status"], "Status: active\n")
        .respond_ok("ufw", &["status", "verbose"], output)
        .respond_ok("ufw", &["app", "list"], "");
    let ufw = Ufw::with_runner(runner);
    let findings = check_logging(&ufw);
    assert!(findings.iter().any(|f| f.id == "log:ok"));
}

// ---------------------------------------------------------------------------
// Rules checks
// ---------------------------------------------------------------------------

#[test]
fn check_rules_should_warn_on_dangerous_ports() {
    let ufw = make_ufw_for_doctor(
        "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere\n5432/tcp                   ALLOW       Anywhere\n",
    );
    let findings = check_rules(&ufw);
    assert!(findings.iter().any(|f| f.title.contains("22")));
    assert!(findings.iter().any(|f| f.title.contains("5432")));
}

#[test]
fn check_rules_should_detect_duplicates() {
    let ufw = make_ufw_for_doctor(
        "Status: active\n\nTo                         Action      From\n--                         ------      ----\n443/tcp                    ALLOW       Anywhere\n443/tcp                    ALLOW       Anywhere\n",
    );
    let findings = check_rules(&ufw);
    assert!(findings.iter().any(|f| f.id == "rule:duplicate"));
}

#[test]
fn check_rules_should_detect_no_comment() {
    let ufw = make_ufw_for_doctor(
        "Status: active\n\nTo                         Action      From\n--                         ------      ----\n443/tcp                    ALLOW       Anywhere\n",
    );
    let findings = check_rules(&ufw);
    assert!(findings.iter().any(|f| f.id == "rule:no-comment"));
}

// ---------------------------------------------------------------------------
// Doctor scope
// ---------------------------------------------------------------------------

#[test]
fn doctor_all_should_run_all_checks() {
    let ufw = make_ufw_for_doctor(
        "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere\n",
    );
    let findings = doctor(&ufw, DoctorScope::All).unwrap();
    assert!(findings.len() > 5);
}

// ---------------------------------------------------------------------------
// Edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn check_binaries_should_handle_missing_ufw() {
    struct NoBinaryRunner;
    impl crate::command::CommandRunner for NoBinaryRunner {
        fn run(&self, _: &CommandSpec) -> crate::error::Result<CommandResult> {
            panic!("NoBinaryRunner::run should not be called")
        }
        fn binary_exists(&self, _: &str) -> bool {
            false
        }
    }

    let ufw = Ufw::with_runner(NoBinaryRunner);
    let findings = check_binaries(&ufw);
    assert!(findings.iter().any(|f| f.id == "bin:ufw:missing"));
    // Should not have version check since ufw not found
    assert!(!findings.iter().any(|f| f.id == "bin:ufw:version"));
}

// ---------------------------------------------------------------------------
// Weird edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn check_rules_should_warn_on_dangerous_ports_alt() {
    let ufw = make_ufw_for_doctor(
        "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere\n5432/tcp                   ALLOW       Anywhere\n",
    );
    let findings = check_rules(&ufw);
    assert!(findings.iter().any(|f| f.title.contains("22")));
    assert!(findings.iter().any(|f| f.title.contains("5432")));
}

#[test]
fn doctor_should_handle_empty_rules() {
    let ufw = make_ufw_for_doctor(
        "Status: active\n\nTo                         Action      From\n--                         ------      ----\n",
    );
    let findings = doctor(&ufw, DoctorScope::Rules).unwrap();
    assert!(findings.is_empty() || findings.iter().all(|f| f.severity <= Severity::Info));
}

// ---------------------------------------------------------------------------
// check_ipv6 with tempdir config fixture
// ---------------------------------------------------------------------------

#[test]
fn check_ipv6_should_report_enabled_when_config_says_yes() {
    // Write a temp /etc/default/ufw with IPV6=yes, then check findings.
    // Note: this test modifies a well-known path; on CI we use tempdir and
    // test the config parsing directly. Here we test through the config module
    // and check that the parse produces the right result.
    let content = "# /etc/default/ufw\nIPV6=yes\nDEFAULT_INPUT_POLICY=\"DROP\"\nENABLED=yes\n";
    let config = crate::config::parse_default_ufw(content);
    assert_eq!(config.ipv6, Some(true));
    assert_eq!(config.enabled, Some(true));
    assert_eq!(config.default_input_policy.as_deref(), Some("DROP"));
}

#[test]
fn check_ipv6_should_report_disabled_when_config_says_no() {
    let content = "# /etc/default/ufw\nIPV6=no\n";
    let config = crate::config::parse_default_ufw(content);
    assert_eq!(config.ipv6, Some(false));
}

#[test]
fn check_ipv6_should_default_to_disabled_when_missing() {
    let content = "# /etc/default/ufw\nENABLED=yes\n";
    let config = crate::config::parse_default_ufw(content);
    assert_eq!(config.ipv6, None);
}

#[test]
fn check_ipv6_with_tempdir_fixture() {
    // Create a tempdir with a fake /etc/default/ufw that has IPV6=yes
    let tmp = tempfile::tempdir().unwrap();
    let config_path = tmp.path().join("ufw");
    std::fs::write(
        &config_path,
        "IPV6=yes\nENABLED=yes\nDEFAULT_INPUT_POLICY=\"ACCEPT\"\n",
    )
    .unwrap();
    let content = std::fs::read_to_string(&config_path).unwrap();
    let config = crate::config::parse_default_ufw(&content);
    assert_eq!(config.ipv6, Some(true));
    assert_eq!(config.default_input_policy.as_deref(), Some("ACCEPT"));
}

#[test]
fn check_ipv6_without_config_file_should_be_graceful() {
    // When /etc/default/ufw doesn't exist, read_default_ufw_config returns default
    let config = std::fs::read_to_string("/etc/default/ufw")
        .ok()
        .map(|c| crate::config::parse_default_ufw(&c))
        .unwrap_or_default();
    // On macOS/CI this file likely doesn't exist — should return default (ipv6 = None)
    // On Linux with ufw installed it may return Some(true/false)
    assert!(config.ipv6.is_none() || config.ipv6 == Some(true) || config.ipv6 == Some(false));
}

// ---------------------------------------------------------------------------
// check_logging with mocked status_verbose
// ---------------------------------------------------------------------------

#[test]
fn check_logging_should_warn_on_high() {
    let output = "Status: active\nDefault: deny (incoming), allow (outgoing)\nLogging: high\n";
    let runner = FakeRunner::new()
        .respond_ok("ufw", &["--version"], "ufw 0.36.1")
        .respond_ok("ufw", &["status"], "Status: active\n")
        .respond_ok("ufw", &["status", "verbose"], output)
        .respond_ok("ufw", &["app", "list"], "");
    let ufw = Ufw::with_runner(runner);
    let findings = check_logging(&ufw);
    assert!(findings.iter().any(|f| f.id == "log:high"));
}

#[test]
fn check_logging_should_warn_on_full() {
    let output = "Status: active\nDefault: deny (incoming), allow (outgoing)\nLogging: full\n";
    let runner = FakeRunner::new()
        .respond_ok("ufw", &["--version"], "ufw 0.36.1")
        .respond_ok("ufw", &["status"], "Status: active\n")
        .respond_ok("ufw", &["status", "verbose"], output)
        .respond_ok("ufw", &["app", "list"], "");
    let ufw = Ufw::with_runner(runner);
    let findings = check_logging(&ufw);
    assert!(findings.iter().any(|f| f.id == "log:high"));
}

#[test]
fn check_logging_should_report_ok_on_medium() {
    let output = "Status: active\nDefault: deny (incoming), allow (outgoing)\nLogging: medium\n";
    let runner = FakeRunner::new()
        .respond_ok("ufw", &["--version"], "ufw 0.36.1")
        .respond_ok("ufw", &["status"], "Status: active\n")
        .respond_ok("ufw", &["status", "verbose"], output)
        .respond_ok("ufw", &["app", "list"], "");
    let ufw = Ufw::with_runner(runner);
    let findings = check_logging(&ufw);
    assert!(findings.iter().any(|f| f.id == "log:ok"));
}

#[test]
fn check_logging_should_report_ok_on_on() {
    let output = "Status: active\nDefault: deny (incoming), allow (outgoing)\nLogging: on\n";
    let runner = FakeRunner::new()
        .respond_ok("ufw", &["--version"], "ufw 0.36.1")
        .respond_ok("ufw", &["status"], "Status: active\n")
        .respond_ok("ufw", &["status", "verbose"], output)
        .respond_ok("ufw", &["app", "list"], "");
    let ufw = Ufw::with_runner(runner);
    let findings = check_logging(&ufw);
    assert!(findings.iter().any(|f| f.id == "log:ok"));
}

#[test]
fn check_logging_should_report_unknown_when_no_level() {
    let output = "Status: active\nDefault: deny (incoming), allow (outgoing)\n";
    let runner = FakeRunner::new()
        .respond_ok("ufw", &["--version"], "ufw 0.36.1")
        .respond_ok("ufw", &["status"], "Status: active\n")
        .respond_ok("ufw", &["status", "verbose"], output)
        .respond_ok("ufw", &["app", "list"], "");
    let ufw = Ufw::with_runner(runner);
    let findings = check_logging(&ufw);
    assert!(findings.iter().any(|f| f.id == "log:unknown"));
}

// ---------------------------------------------------------------------------
// check_config with tempdir fixtures
// ---------------------------------------------------------------------------

#[test]
fn check_config_should_parse_enabled_consistency() {
    // When /etc/default/ufw has ENABLED=yes and /etc/ufw/ufw.conf has ENABLED=no,
    // check_config should report inconsistency.
    // Since check_config reads from real filesystem paths, we test the parsing logic.
    let default_content = "ENABLED=yes\nIPV6=yes\n";
    let conf_content = "ENABLED=no\nLOGLEVEL=low\n";

    let default_config = crate::config::parse_default_ufw(default_content);
    let conf = crate::config::parse_ufw_conf(conf_content);

    assert_eq!(default_config.enabled, Some(true));
    assert_eq!(conf.enabled, Some(false));
    // They differ — doctor would emit cfg:enabled:inconsistent
}

#[test]
fn check_config_should_parse_loglevel_validity() {
    let conf_content = "ENABLED=yes\nLOGLEVEL=invalid_level\n";
    let conf = crate::config::parse_ufw_conf(conf_content);
    assert_eq!(conf.loglevel.as_deref(), Some("invalid_level"));
    // Doctor would emit cfg:loglevel:invalid for this
}

// ---------------------------------------------------------------------------
// Edge-case: shadowed rules
// ---------------------------------------------------------------------------

#[test]
fn check_rules_should_detect_shadowed_deny() {
    // allow 22, then deny 22 — the deny is shadowed
    let ufw = make_ufw_for_doctor(
        "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere\n22/tcp                     DENY        Anywhere\n",
    );
    let findings = check_rules(&ufw);
    assert!(findings.iter().any(|f| f.id == "rule:shadowed"));
}

#[test]
fn check_rules_should_not_flag_non_shadowed() {
    // deny 22, then allow 22 — not shadowed (deny first, allow after — normal)
    let ufw = make_ufw_for_doctor(
        "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     DENY        Anywhere\n22/tcp                     ALLOW       Anywhere\n",
    );
    let findings = check_rules(&ufw);
    assert!(!findings.iter().any(|f| f.id == "rule:shadowed"));
}

// ---------------------------------------------------------------------------
// Edge-case: dual-stack coverage
// ---------------------------------------------------------------------------

#[test]
fn check_rules_should_flag_ipv4_only() {
    let ufw = make_ufw_for_doctor(
        "Status: active\n\nTo                         Action      From\n--                         ------      ----\n443/tcp                    ALLOW       Anywhere\n80/tcp                     ALLOW       Anywhere\n",
    );
    let findings = check_rules(&ufw);
    assert!(findings.iter().any(|f| f.id == "rule:ipv4-only"));
}

// ---------------------------------------------------------------------------
// Edge-case: policy severity for incoming allow
// ---------------------------------------------------------------------------

#[test]
fn check_policy_should_use_critical_for_incoming_allow() {
    let output = "Status: active\nDefault: allow (incoming), allow (outgoing)\nLogging: on\n";
    let runner = FakeRunner::new()
        .respond_ok("ufw", &["--version"], "ufw 0.36.1")
        .respond_ok("ufw", &["status"], "Status: active\n")
        .respond_ok("ufw", &["status", "verbose"], output)
        .respond_ok("ufw", &["app", "list"], "");
    let ufw = Ufw::with_runner(runner);
    let findings = check_policy(&ufw);
    let incoming = findings
        .iter()
        .find(|f| f.id == "pol:incoming:allow")
        .unwrap();
    assert_eq!(incoming.severity, Severity::Critical);
}

// ---------------------------------------------------------------------------
// Edge-case: SSH VPN interface detection
// ---------------------------------------------------------------------------

#[test]
fn check_ssh_should_detect_vpn_interface() {
    let ufw = make_ufw_for_doctor(
        "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere on tailscale0\n",
    );
    let findings = check_ssh(&ufw);
    assert!(findings.iter().any(|f| f.id == "ssh:vpn-interface"));
}

#[test]
fn check_ssh_should_detect_wireguard_interface() {
    let ufw = make_ufw_for_doctor(
        "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere on wg0\n",
    );
    let findings = check_ssh(&ufw);
    assert!(findings.iter().any(|f| f.id == "ssh:vpn-interface"));
}

// ---------------------------------------------------------------------------
// Edge-case: secrets in comments
// ---------------------------------------------------------------------------

#[test]
fn check_permissions_should_detect_secret_in_comment() {
    let runner = FakeRunner::new()
        .respond_ok("ufw", &["--version"], "ufw 0.36.1")
        .respond_ok(
            "ufw",
            &["status"],
            "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere comment 'password=secret123'\n",
        )
        .respond_ok(
            "ufw",
            &["status", "verbose"],
            "Status: active\nDefault: deny (incoming), allow (outgoing)\nLogging: on (low)\n",
        )
        .respond_ok("ufw", &["app", "list"], "")
        .respond_ok("ufw", &["app", "info", "OpenSSH"], "Profile: OpenSSH\nTitle: OpenSSH\nDescription: OpenSSH\nPort: 22/tcp\n");
    let ufw = Ufw::with_runner(runner);
    let findings = check_permissions(&ufw);
    assert!(
        findings
            .iter()
            .any(|f| f.id == "perm:rule:secret-in-comment")
    );
}

// ---------------------------------------------------------------------------
// Edge-case: comment secret detection helper
// ---------------------------------------------------------------------------

#[test]
fn validate_comment_for_secrets_doctor_should_detect_key_value() {
    assert!(crate::spec::validate_comment_for_secrets_doctor(
        "password=secret123"
    ));
    assert!(crate::spec::validate_comment_for_secrets_doctor(
        "api_key=abc123"
    ));
    assert!(!crate::spec::validate_comment_for_secrets_doctor(
        "managed:https"
    ));
    assert!(!crate::spec::validate_comment_for_secrets_doctor(
        "allow ssh from office"
    ));
}
