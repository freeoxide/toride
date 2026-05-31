//! Collector loop with deltas: 10 iterations at 1-second intervals.
//!
//! Demonstrates the advanced Collector API with delta tracking for
//! CPU changes, network rates, and disk I/O rates.
//!
//! Run with: `cargo run --example task_manager_loop`

use std::time::Duration;

use toride_status::units::format_bytes;
use toride_status::{Collector, Preset};

fn main() {
    let mut collector = Collector::new(Duration::from_secs(1), Preset::TaskManager);
    let iterations = 10;

    println!("=== Task Manager (10 iterations, 1s interval) ===");
    println!();

    for i in 0..iterations {
        let (status, delta) = collector.collect_after_interval();
        let sys = &status.system;

        println!("--- Iteration {} ---", i + 1);

        // CPU
        match sys.cpu_usage {
            Some(cpu) => print!("  CPU: {cpu:.1}%"),
            None => print!("  CPU: N/A"),
        }
        if let Some(ref d) = delta {
            if let Some(cdelta) = d.cpu_usage_delta {
                println!(" ({cdelta:+.1}%)");
            } else {
                println!();
            }
        } else {
            println!(" (first sample)");
        }

        // Memory
        println!(
            "  Memory: {} / {} ({:.1}%)",
            format_bytes(sys.memory.used_bytes),
            format_bytes(sys.memory.total_bytes),
            sys.memory.percentage,
        );

        // Network rates
        if let Some(ref d) = delta {
            println!(
                "  Net RX: {} ({:.1} B/s)",
                format_bytes(d.network.bytes_received_delta),
                d.network.bytes_received_rate,
            );
            println!(
                "  Net TX: {} ({:.1} B/s)",
                format_bytes(d.network.bytes_transmitted_delta),
                d.network.bytes_transmitted_rate,
            );
        }

        // Disk I/O rates
        if let Some(ref dio) = delta.as_ref().and_then(|d| d.disk_io.as_ref()) {
            println!(
                "  Disk read:  {} ({:.1} B/s)",
                format_bytes(dio.read_bytes_delta),
                dio.read_bytes_rate,
            );
            println!(
                "  Disk write: {} ({:.1} B/s)",
                format_bytes(dio.written_bytes_delta),
                dio.written_bytes_rate,
            );
        }

        // Process delta
        if let Some(ref proc) = delta.as_ref().and_then(|d| d.process.as_ref()) {
            println!(
                "  Processes: {:+} ({} new, {} exited)",
                proc.count_delta, proc.new_count, proc.exited_count,
            );
        }

        // Top 5 CPU consumers
        let top_cpu = sys.processes.top_by_cpu(5);
        if !top_cpu.is_empty() {
            println!("  Top CPU:");
            for p in &top_cpu {
                println!(
                    "    PID {:<7} {:>6.1}%  {}",
                    p.pid, p.cpu_usage, p.name,
                );
            }
        }

        println!();
    }

    println!("Done.");
}
