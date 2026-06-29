//! Collector loop showing disk I/O and rates.
//!
//! Displays disk usage, I/O counters, and computed read/write rates
//! from the Collector delta. Includes per-disk details.
//!
//! Run with: `cargo run --example disk_rates`

use std::time::Duration;

use toride_status::units::format_bytes;
use toride_status::{Collector, Preset};

fn main() {
    let mut collector = Collector::new(Duration::from_secs(1), Preset::TaskManager);
    let iterations = 5;

    println!("=== Disk I/O Rate Monitor ({iterations} iterations) ===");
    println!();

    // First collect for baseline
    let (status, _) = collector.collect();
    println!("Disks found: {}", status.system.disks.len());
    println!();

    for i in 0..iterations {
        let (status, delta) = collector.collect_after_interval();
        let sys = &status.system;

        println!("--- Sample {} ---", i + 1);

        // Root disk
        let disk = &sys.disk;
        println!(
            "  Root disk ({}): {} / {} ({:.1}%) [{}]",
            disk.mount_point,
            format_bytes(disk.used_bytes),
            format_bytes(disk.total_bytes),
            disk.percentage,
            disk.filesystem,
        );
        println!(
            "    Free: {}  Available: {}",
            format_bytes(disk.free_bytes),
            format_bytes(disk.available_bytes),
        );

        // All disks
        if sys.disks.len() > 1 {
            println!("  All disks:");
            for d in &sys.disks {
                println!(
                    "    {} ({}) [{}]: {} / {} ({:.1}%)",
                    d.mount_point,
                    d.name,
                    d.filesystem,
                    format_bytes(d.used_bytes),
                    format_bytes(d.total_bytes),
                    d.percentage,
                );
                if let Some(ref model) = d.model {
                    println!("      Model: {model}");
                }
                if let Some(ref dev) = d.physical_device_path {
                    println!("      Device: {dev}");
                }
                if d.is_removable {
                    println!("      [removable]");
                }
            }
        }

        // Disk I/O from snapshot
        let io = &sys.disk_io;
        if io.read_bytes > 0 || io.written_bytes > 0 {
            println!("  I/O totals:");
            println!(
                "    Read:  {} ({} ops)",
                format_bytes(io.read_bytes),
                io.read_ops,
            );
            println!(
                "    Write: {} ({} ops)",
                format_bytes(io.written_bytes),
                io.write_ops,
            );
            println!("    Busy:  {} ms", io.busy_time_ms);
        }

        // I/O rates from delta
        if let Some(dio) = delta.as_ref().and_then(|d| d.disk_io.as_ref()) {
            println!("  I/O rates:");
            println!(
                "    Read:  {:.1} B/s ({} delta, {} ops)",
                dio.read_bytes_rate,
                format_bytes(dio.read_bytes_delta),
                dio.read_ops_delta,
            );
            println!(
                "    Write: {:.1} B/s ({} delta, {} ops)",
                dio.written_bytes_rate,
                format_bytes(dio.written_bytes_delta),
                dio.write_ops_delta,
            );
            println!("    Busy delta: {} ms", dio.busy_time_ms_delta);
        } else if i == 0 {
            println!("  I/O rates: (waiting for second sample)");
        }

        println!();
    }

    println!("Done.");
}
