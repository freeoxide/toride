//! Example: Ensure a web server firewall configuration.
//! Demonstrates dry-run, rule management, and policy configuration.

use ufw_kit::{
    Ufw,
    spec::{Action, Direction, Policy, Protocol, RuleSpec},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ufw = Ufw::system();

    // 1. Dry-run to preview what we'd do
    println!("=== Dry Run ===");
    let rules_to_add = [
        RuleSpec::builder(Action::Allow)
            .direction(Direction::In)
            .proto(Protocol::Tcp)
            .to_port(22)
            .comment("managed:ssh")
            .build()?,
        RuleSpec::builder(Action::Allow)
            .direction(Direction::In)
            .proto(Protocol::Tcp)
            .to_port(80)
            .comment("managed:http")
            .build()?,
        RuleSpec::builder(Action::Allow)
            .direction(Direction::In)
            .proto(Protocol::Tcp)
            .to_port(443)
            .comment("managed:https")
            .build()?,
    ];

    for rule in &rules_to_add {
        let preview = ufw.apply_rule(rule)?;
        if let Some(dry) = &preview.dry_run_output {
            println!("Dry-run output: {dry}");
        }
    }

    // 2. Apply rules idempotently
    println!("\n=== Applying Rules ===");
    for rule in &rules_to_add {
        let report = ufw.ensure_rule(rule)?;
        let label = rule.comment.as_deref().unwrap_or("(no comment)");
        if report.success {
            println!("OK: {label} — {}", report.action);
        }
    }

    // 3. Set default policies
    println!("\n=== Setting Default Policies ===");
    ufw.set_default_policy(Direction::In, Policy::Deny)?;
    println!("Default incoming: deny");
    ufw.set_default_policy(Direction::Out, Policy::Allow)?;
    println!("Default outgoing: allow");

    // 4. Verify
    println!("\n=== Final Status ===");
    let status = ufw.status()?;
    println!("Active: {}", status.active);
    println!("Rules: {} total", status.rules.len());
    for rule in &status.rules {
        println!("  {}", rule.raw);
    }

    Ok(())
}
