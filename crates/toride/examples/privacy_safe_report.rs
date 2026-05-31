//! Compare Safe vs Full privacy mode output as JSON.
//!
//! Collects the same system data with two different privacy modes
//! and prints both as JSON so you can see exactly what gets redacted.
//!
//! Run with: `cargo run --example privacy_safe_report`

use toride_status::{Preset, PrivacyMode, TorideStatus};

fn main() {
    println!("=== Privacy Mode Comparison ===");
    println!();

    // Collect with Safe mode (maximum redaction)
    let safe = TorideStatus::collect_with_options(Preset::Diagnostics, PrivacyMode::Safe);

    // Collect with Full mode (no redaction)
    let full = TorideStatus::collect_with_options(Preset::Diagnostics, PrivacyMode::Full);

    // Compare key fields side-by-side
    println!("Field-by-field comparison:");
    println!();

    println!(
        "  {:<25} {:<30} {}",
        "Field", "Safe Mode", "Full Mode"
    );
    println!("  {:->25} {:->30} {:->30}", "", "", "");

    println!(
        "  {:<25} {:<30} {}",
        "hostname", safe.system.hostname, full.system.hostname
    );
    println!(
        "  {:<25} {:<30} {}",
        "static_info.hostname", safe.system.static_info.hostname, full.system.static_info.hostname
    );
    println!(
        "  {:<25} {:<30} {}",
        "memory.total_bytes",
        safe.system.memory.total_bytes,
        full.system.memory.total_bytes,
    );
    println!(
        "  {:<25} {:<30} {}",
        "cpu_usage",
        format_opt(safe.system.cpu_usage),
        format_opt(full.system.cpu_usage),
    );
    println!(
        "  {:<25} {:<30} {}",
        "os_info.arch",
        safe.system.os_info.arch,
        full.system.os_info.arch,
    );
    println!(
        "  {:<25} {:<30} {}",
        "process count",
        safe.system.processes.total_count,
        full.system.processes.total_count,
    );
    println!(
        "  {:<25} {:<30} {}",
        "process names",
        safe.system.processes.processes.len(),
        full.system.processes.processes.len(),
    );

    // Check a process's command line
    if let (Some(safe_proc), Some(full_proc)) = (
        safe.system.processes.processes.first(),
        full.system.processes.processes.first(),
    ) {
        println!(
            "  {:<25} {:<30} {}",
            "proc[0].cmdline",
            safe_proc.command_line.as_deref().unwrap_or("None"),
            full_proc.command_line.as_deref().unwrap_or("None"),
        );
        println!(
            "  {:<25} {:<30} {}",
            "proc[0].user",
            safe_proc.user.as_deref().unwrap_or("None"),
            full_proc.user.as_deref().unwrap_or("None"),
        );
    }

    // Check MAC addresses
    if let (Some(safe_iface), Some(full_iface)) = (
        safe.system.network_interfaces.first(),
        full.system.network_interfaces.first(),
    ) {
        println!(
            "  {:<25} {:<30} {}",
            "iface[0].mac",
            safe_iface.mac_address.as_deref().unwrap_or("None"),
            full_iface.mac_address.as_deref().unwrap_or("None"),
        );
    }

    // Check disk serial numbers
    if let (Some(safe_disk), Some(full_disk)) = (
        safe.system.disks.first(),
        full.system.disks.first(),
    ) {
        println!(
            "  {:<25} {:<30} {}",
            "disk[0].serial",
            safe_disk.serial.as_deref().unwrap_or("None"),
            full_disk.serial.as_deref().unwrap_or("None"),
        );
    }

    println!();

    // Print full JSON for both modes
    println!("--- Safe Mode JSON ---");
    match serde_json::to_string_pretty(&safe) {
        Ok(json) => println!("{json}"),
        Err(e) => println!("Serialization error: {e}"),
    }

    println!();
    println!("--- Full Mode JSON ---");
    match serde_json::to_string_pretty(&full) {
        Ok(json) => println!("{json}"),
        Err(e) => println!("Serialization error: {e}"),
    }
}

fn format_opt(v: Option<f64>) -> String {
    match v {
        Some(f) => format!("{:.1}", f),
        None => "None".to_string(),
    }
}
