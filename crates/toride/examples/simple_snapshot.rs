//! Basic SysProbe usage: hostname, OS, CPU, memory, disk, processes, uptime.
//!
//! Run with: `cargo run --example simple_snapshot`

use toride_status::units::{format_bytes, format_duration};
use toride_status::SysProbe;

fn main() {
    let probe = SysProbe::new();
    let snapshot = probe.snapshot();
    let sys = &snapshot.system;

    println!("=== System Snapshot ===");
    println!();

    // Hostname
    println!("Hostname: {}", sys.hostname);

    // OS info
    let os_name = sys.os_info.name.as_deref().unwrap_or("Unknown");
    let os_ver = sys.os_info.version.as_deref().unwrap_or("?");
    let kernel = sys.os_info.kernel_version.as_deref().unwrap_or("?");
    println!("OS:       {os_name} {os_ver} (kernel {kernel}, {})", sys.os_info.arch);

    // CPU
    match sys.cpu_usage {
        Some(cpu) => println!("CPU:      {cpu:.1}%"),
        None => println!("CPU:      unavailable"),
    }
    if let Some(cores) = sys.physical_cores {
        println!("Cores:    {cores} physical, {} logical", sys.cpu_cores.len());
    }

    // Memory
    println!(
        "Memory:   {} / {} ({:.1}%)",
        format_bytes(sys.memory.used_bytes),
        format_bytes(sys.memory.total_bytes),
        sys.memory.percentage,
    );

    // Disk
    println!(
        "Disk:     {} / {} ({:.1}%) on {}",
        format_bytes(sys.disk.used_bytes),
        format_bytes(sys.disk.total_bytes),
        sys.disk.percentage,
        sys.disk.mount_point,
    );

    // Processes
    println!("Processes: {} running", sys.processes.total_count);

    // Uptime
    if let Some(secs) = sys.uptime_secs {
        println!("Uptime:   {}", format_duration(secs));
    } else {
        println!("Uptime:   unavailable");
    }

    // Load average
    if let Some(load) = &sys.load_average {
        println!("Load:     {:.2} / {:.2} / {:.2} (1/5/15m)", load.one, load.five, load.fifteen);
    }

    println!();
    println!("Capabilities: {:?}", snapshot.capabilities);
}
