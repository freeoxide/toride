//! Example: Embed ufw-kit in a custom application.
//! Demonstrates checking UFW status and adding a basic rule.

use ufw_kit::{
    Ufw,
    spec::{Action, Direction, Protocol, RuleSpec},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ufw = Ufw::system();

    // Check if UFW is available
    println!("Checking for UFW...");
    ufw.find_ufw()?;
    println!("UFW found!");

    // Get version
    let version = ufw.version()?;
    println!("UFW version: {version}");

    // Check status
    let status = ufw.status()?;
    println!("UFW active: {}", status.active);
    println!("Rules: {} total", status.rules.len());

    // Ensure a rule exists (idempotent)
    let rule = RuleSpec::builder(Action::Allow)
        .direction(Direction::In)
        .proto(Protocol::Tcp)
        .to_port(8080)
        .comment("managed:myapp")
        .build()?;

    let report = ufw.ensure_rule(&rule)?;
    if report.success {
        println!("Rule ensured: {}", report.action);
    }

    Ok(())
}
