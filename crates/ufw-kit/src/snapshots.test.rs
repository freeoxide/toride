//! Snapshot tests using `insta`.
//!
//! These tests verify that the output of key functions remains stable
//! across code changes. Run `cargo insta review` to accept new snapshots.

use crate::report::{render_findings, render_findings_json, render_findings_markdown};
use crate::rule::*;
use crate::spec::*;
use crate::status::*;

#[cfg(feature = "app-profile")]
use crate::app_profile::render_profile;

// ---------------------------------------------------------------------------
// Rule rendering snapshots
// ---------------------------------------------------------------------------

#[test]
fn snapshot_rule_allow_22_tcp() {
    let spec = RuleSpec::builder(Action::Allow)
        .to_port(22)
        .proto(Protocol::Tcp)
        .build_unchecked();
    let args = render_rule_args(&spec);
    insta::assert_snapshot!("rule_allow_22_tcp", format!("{args:?}"));
}

#[test]
fn snapshot_rule_limit_ssh_in_eth0() {
    let spec = RuleSpec::builder(Action::Limit)
        .direction(Direction::In)
        .on_interface("eth0")
        .proto(Protocol::Tcp)
        .to_port(22)
        .comment("ufw-kit:ssh")
        .build_unchecked();
    let args = render_rule_args(&spec);
    insta::assert_snapshot!("rule_limit_ssh_in_eth0", format!("{args:?}"));
}

#[test]
fn snapshot_rule_allow_full_syntax() {
    let spec = RuleSpec::builder(Action::Allow)
        .direction(Direction::In)
        .on_interface("eth0")
        .proto(Protocol::Tcp)
        .from(Address::Net("10.0.0.0/8".parse().unwrap()))
        .to(Address::Any)
        .to_port(443)
        .logging(RuleLogging::Log)
        .comment("managed:web")
        .build_unchecked();
    let args = render_rule_args(&spec);
    insta::assert_snapshot!("rule_allow_full_syntax", format!("{args:?}"));
}

#[test]
fn snapshot_route_rule() {
    let spec = RouteRuleSpec::builder(Action::Allow)
        .in_interface("wg0")
        .out_interface("eth0")
        .proto(Protocol::Udp)
        .from(Address::Net("10.0.0.0/24".parse().unwrap()))
        .to(Address::Ip("8.8.8.8".parse().unwrap()))
        .to_port(53)
        .comment("dns-forward")
        .build()
        .unwrap();
    let args = render_route_rule_args(&spec);
    insta::assert_snapshot!("route_rule_dns_forward", format!("{args:?}"));
}

#[test]
fn snapshot_default_policy_args() {
    let args = render_default_policy_args(Direction::In, Policy::Deny);
    insta::assert_snapshot!("default_policy_in_deny", format!("{args:?}"));
}

#[test]
fn snapshot_logging_args() {
    let args = render_logging_args(LoggingLevel::Medium);
    insta::assert_snapshot!("logging_medium", format!("{args:?}"));
}

// ---------------------------------------------------------------------------
// App profile snapshots
// ---------------------------------------------------------------------------

#[cfg(feature = "app-profile")]
#[test]
fn snapshot_app_profile_web() {
    let spec = AppProfileSpec {
        name: "MyWebApp".into(),
        title: "My Web Application".into(),
        description: "Web server with HTTPS".into(),
        ports: vec![
            AppPort {
                port: "80".into(),
                protocol: "tcp".into(),
            },
            AppPort {
                port: "443".into(),
                protocol: "tcp".into(),
            },
        ],
    };
    insta::assert_snapshot!("app_profile_web", render_profile(&spec));
}

#[cfg(feature = "app-profile")]
#[test]
fn snapshot_app_profile_range() {
    let spec = AppProfileSpec {
        name: "DevServer".into(),
        title: "Development Server".into(),
        description: "Dev server with port range".into(),
        ports: vec![
            AppPort {
                port: "3000".into(),
                protocol: "tcp".into(),
            },
            AppPort {
                port: "8000:9000".into(),
                protocol: "tcp".into(),
            },
        ],
    };
    insta::assert_snapshot!("app_profile_range", render_profile(&spec));
}

// ---------------------------------------------------------------------------
// Status parsing snapshots
// ---------------------------------------------------------------------------

#[test]
fn snapshot_parse_status_verbose() {
    let output = "\
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
443/tcp                    ALLOW IN    Anywhere
22/tcp                     ALLOW IN    Anywhere (v6)
443/tcp                    ALLOW IN    Anywhere (v6)
";

    let status = parse_status_verbose(output).unwrap();
    insta::assert_snapshot!("status_verbose", format!("{status:#?}"));
}

#[test]
fn snapshot_parse_status_numbered() {
    let output = "\
Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 443/tcp                    ALLOW IN    Anywhere
[ 3] 22/tcp                     ALLOW IN    Anywhere (v6)
";

    let status = parse_status_numbered(output).unwrap();
    insta::assert_snapshot!("status_numbered", format!("{status:#?}"));
}

// ---------------------------------------------------------------------------
// Doctor report snapshots
// ---------------------------------------------------------------------------

#[test]
fn snapshot_doctor_report() {
    let findings = vec![
        Finding {
            id: "bin:ufw:exists",
            severity: Severity::Ok,
            title: "UFW binary found".into(),
            detail: "The ufw binary is available.".into(),
            fix: None,
        },
        Finding {
            id: "pol:incoming:deny",
            severity: Severity::Ok,
            title: "Default incoming policy is secure".into(),
            detail: "Default incoming policy: deny".into(),
            fix: None,
        },
        Finding {
            id: "ssh:allowed",
            severity: Severity::Ok,
            title: "SSH access is allowed".into(),
            detail: "An SSH allow rule exists.".into(),
            fix: None,
        },
        Finding {
            id: "rule:dangerous:5432",
            severity: Severity::Warning,
            title: "Port 5432 (Postgres) is exposed".into(),
            detail: "Rule exposes port 5432: ALLOW IN 5432/tcp from anywhere".into(),
            fix: Some("Restrict access to trusted IPs only.".into()),
        },
        Finding {
            id: "log:high",
            severity: Severity::Warning,
            title: "Logging level is high".into(),
            detail: "Logging level: high. This can generate significant disk I/O.".into(),
            fix: Some("Consider using 'low' or 'medium' logging.".into()),
        },
    ];

    insta::assert_snapshot!("doctor_report", render_findings(&findings));
}

// ---------------------------------------------------------------------------
// JSON and Markdown report snapshots
// ---------------------------------------------------------------------------

#[test]
fn snapshot_doctor_report_json() {
    let findings = vec![
        Finding {
            id: "bin:ufw:exists",
            severity: Severity::Ok,
            title: "UFW binary found".into(),
            detail: "The ufw binary is available.".into(),
            fix: None,
        },
        Finding {
            id: "ssh:no-rule",
            severity: Severity::Critical,
            title: "No SSH allow rule found".into(),
            detail: "UFW is active but no SSH allow rule exists.".into(),
            fix: Some("Add SSH allow rule: ufw allow 22/tcp".into()),
        },
        Finding {
            id: "rule:dangerous:5432",
            severity: Severity::Warning,
            title: "Port 5432 (Postgres) is exposed".into(),
            detail: "Rule exposes port 5432.".into(),
            fix: Some("Restrict access to trusted IPs only.".into()),
        },
    ];

    insta::assert_snapshot!("doctor_report_json", render_findings_json(&findings));
}

#[test]
fn snapshot_doctor_report_markdown() {
    let findings = vec![
        Finding {
            id: "bin:ufw:exists",
            severity: Severity::Ok,
            title: "UFW binary found".into(),
            detail: "The ufw binary is available.".into(),
            fix: None,
        },
        Finding {
            id: "ssh:no-rule",
            severity: Severity::Critical,
            title: "No SSH allow rule found".into(),
            detail: "UFW is active but no SSH allow rule exists.".into(),
            fix: Some("Add SSH allow rule: ufw allow 22/tcp".into()),
        },
        Finding {
            id: "rule:dangerous:5432",
            severity: Severity::Warning,
            title: "Port 5432 (Postgres) is exposed".into(),
            detail: "Rule exposes port 5432.".into(),
            fix: Some("Restrict access to trusted IPs only.".into()),
        },
    ];

    insta::assert_snapshot!(
        "doctor_report_markdown",
        render_findings_markdown(&findings)
    );
}
