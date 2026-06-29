//! Example: run a full doctor report and display the findings.
//!
//! Demonstrates creating a `Fail2Ban` instance, running diagnostics with
//! `DoctorScope::All`, grouping findings by severity, and displaying them
//! with fix suggestions. Exits with a non-zero code if critical issues are
//! found.
//!
//! # Running
//!
//! ```sh
//! cargo run -p toride-fail2ban --example doctor_report
//! ```

use toride_fail2ban::Fail2Ban;
use toride_fail2ban::doctor::DoctorScope;
use toride_fail2ban::report::{DoctorReport, Finding, Severity};

// ---------------------------------------------------------------------------
// Severity indicator for terminal output
// ---------------------------------------------------------------------------

/// Returns a short bracketed tag for each severity level.
fn severity_indicator(severity: Severity) -> &'static str {
    match severity {
        Severity::Ok => "[OK]",
        Severity::Info => "[--]",
        Severity::Warning => "[!!]",
        Severity::Error => "[EE]",
        Severity::Critical => "[CC]",
    }
}

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

/// Print a single finding to stdout.
fn print_finding(finding: &Finding) {
    let indicator = severity_indicator(finding.severity);
    println!("  {indicator} {}", finding.title);

    if !finding.detail.is_empty() {
        println!("       {}", finding.detail);
    }

    if let Some(ref fix) = finding.fix {
        println!("       Fix: {fix}");
    }

    println!();
}

/// Print findings grouped by severity level, starting with the most severe.
fn print_grouped_report(report: &DoctorReport) {
    let by_severity = report.summary_by_severity();

    // BTreeMap iterates in key order (Ok, Info, Warning, Error, Critical).
    // Reverse so that the most severe findings appear first.
    let ordered: Vec<_> = by_severity.into_iter().rev().collect();

    if ordered.is_empty() {
        println!("No findings -- everything looks good.");
        return;
    }

    for (severity, findings) in &ordered {
        let indicator = severity_indicator(*severity);
        let count = findings.len();
        let label = format!("{severity:?}").to_uppercase();
        println!("{indicator} {label} ({count} finding(s))");
        println!("{}", "-".repeat(40));

        for finding in findings {
            print_finding(finding);
        }
    }
}

/// Print a one-line summary at the bottom of the report.
fn print_summary(report: &DoctorReport) {
    let by_severity = report.summary_by_severity();

    let ok = by_severity.get(&Severity::Ok).map_or(0, Vec::len);
    let info = by_severity.get(&Severity::Info).map_or(0, Vec::len);
    let warn = by_severity.get(&Severity::Warning).map_or(0, Vec::len);
    let err = by_severity.get(&Severity::Error).map_or(0, Vec::len);
    let crit = by_severity.get(&Severity::Critical).map_or(0, Vec::len);

    println!("Summary: {crit} critical, {err} errors, {warn} warnings, {info} info, {ok} ok");
    println!("Total: {} finding(s)", report.len());
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    println!("Fail2Ban Doctor Report");
    println!("{}", "=".repeat(60));
    println!();

    // 1. Create a Fail2Ban instance using the default system configuration.
    let f2b = match Fail2Ban::system() {
        Ok(instance) => instance,
        Err(e) => {
            eprintln!("Failed to initialise Fail2Ban instance: {e}");
            eprintln!("Make sure /etc/fail2ban exists and Fail2Ban is installed.");
            std::process::exit(2);
        }
    };

    // 2. Run doctor with the full scope (all diagnostic categories).
    println!("Running diagnostics (scope: all)...");
    println!();

    let report = match f2b.doctor(DoctorScope::All) {
        Ok(report) => report,
        Err(e) => {
            eprintln!("Doctor run failed: {e}");
            std::process::exit(2);
        }
    };

    // 3 & 4. Display findings grouped by severity.
    print_grouped_report(&report);

    // Separator before summary.
    println!("{}", "=".repeat(60));

    // 5. Print summary counts.
    print_summary(&report);

    // Show fix suggestions for any actionable findings.
    let actionable: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.severity >= Severity::Warning && f.fix.is_some())
        .collect();

    if !actionable.is_empty() {
        println!();
        println!("Suggested fixes:");
        for finding in &actionable {
            let indicator = severity_indicator(finding.severity);
            // fix is guaranteed to be Some because of the filter above.
            println!(
                "  {indicator} {} -> {}",
                finding.title,
                finding.fix.as_deref().unwrap_or("")
            );
        }
    }

    // 6. Exit with an error code if critical issues were detected.
    if report.has_critical() {
        eprintln!();
        eprintln!("Critical issues detected. Please resolve them before proceeding.");
        std::process::exit(1);
    }

    if report.has_errors() {
        eprintln!();
        eprintln!("Errors detected. Review the findings above.");
        std::process::exit(1);
    }

    println!();
    println!("Doctor complete. No blocking issues found.");
}
