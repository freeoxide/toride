//! DoctorReport health check display with emoji-style icons and summary.
//!
//! Runs all health checks across system, daemon, and SSH subsystems
//! and displays each check with a status icon and summary counts.
//!
//! Run with: `cargo run --example doctor`

use toride_status::{CheckStatus, DoctorReport};

fn main() {
    println!("Running health checks...");
    println!();

    let report = DoctorReport::check();

    // Header
    println!("=== Doctor Report ===");
    println!();

    // Group checks by category
    let mut system_checks = Vec::new();
    let mut daemon_checks = Vec::new();
    let mut ssh_checks = Vec::new();
    let mut privacy_checks = Vec::new();

    for check in &report.checks {
        if check.name.starts_with("system.") {
            system_checks.push(check);
        } else if check.name.starts_with("daemon.") {
            daemon_checks.push(check);
        } else if check.name.starts_with("ssh.") {
            ssh_checks.push(check);
        } else if check.name.starts_with("privacy.") {
            privacy_checks.push(check);
        }
    }

    // Display grouped checks
    if !system_checks.is_empty() {
        println!("System:");
        for check in &system_checks {
            print_check(&check.name, check.status, &check.message);
        }
        println!();
    }

    if !daemon_checks.is_empty() {
        println!("Daemon:");
        for check in &daemon_checks {
            print_check(&check.name, check.status, &check.message);
        }
        println!();
    }

    if !ssh_checks.is_empty() {
        println!("SSH:");
        for check in &ssh_checks {
            print_check(&check.name, check.status, &check.message);
        }
        println!();
    }

    if !privacy_checks.is_empty() {
        println!("Privacy:");
        for check in &privacy_checks {
            print_check(&check.name, check.status, &check.message);
        }
        println!();
    }

    // Summary
    let (pass, warn, fail) = report.summary();
    let total = report.checks.len();

    println!("--- Summary ---");
    println!(
        "  {} passed, {} warnings, {} failures ({} total)",
        pass, warn, fail, total,
    );

    if report.all_passed() {
        println!("  Status: ALL CHECKS PASSED");
    } else {
        println!("  Status: ISSUES DETECTED");
        if fail > 0 {
            println!("  {} check(s) FAILED -- action required", fail);
        }
        if warn > 0 {
            println!("  {} check(s) have warnings -- review recommended", warn);
        }
    }
}

fn print_check(name: &str, status: CheckStatus, message: &str) {
    let icon = match status {
        CheckStatus::Pass => "\u{2705}", // green check
        CheckStatus::Warn => "\u{26a0}\u{fe0f}", // warning
        CheckStatus::Fail => "\u{274c}", // red X
    };
    // Shorten the name by stripping the category prefix for cleaner display
    let short_name = name.split('.').next_back().unwrap_or(name);
    println!("  {icon} {short_name:<25} {message}");
}
