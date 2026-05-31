//! Hardware inventory using the HardwareInventory preset.
//!
//! Shows static hardware info, all disks, GPUs, battery, sensors,
//! and per-core CPU data -- everything related to the physical machine.
//!
//! Run with: `cargo run --example hardware_inventory`

use toride_status::units::{format_bytes, Bytes, Celsius, Hertz};
use toride_status::{Preset, TorideStatus};

fn main() {
    let status = TorideStatus::collect_with_preset(Preset::HardwareInventory);
    let sys = &status.system;

    println!("=== Hardware Inventory ===");
    println!();

    // Static hardware info
    let si = &sys.static_info;
    println!("System:");
    println!("  Hostname:       {}", si.hostname);
    println!("  OS:             {} {}",
        si.os.name.as_deref().unwrap_or("Unknown"),
        si.os.version.as_deref().unwrap_or("?"),
    );
    println!("  Kernel:         {}", si.kernel_version.as_deref().unwrap_or("?"));
    println!("  Arch:           {}", si.os.arch);

    // CPU
    println!();
    println!("CPU:");
    println!("  Brand:          {}", si.cpu_brand);
    println!("  Vendor:         {}", si.cpu_vendor);
    println!("  Frequency:      {}", Hertz(si.cpu_frequency * 1_000_000));
    println!(
        "  Cores:          {} physical, {} logical",
        si.physical_cores.map_or("?".to_string(), |c| c.to_string()),
        si.logical_cores,
    );
    if let Some(cores) = sys.physical_cores {
        println!("  Physical cores: {cores}");
    }

    // Per-core CPU usage
    if !sys.cpu_cores.is_empty() {
        println!("  Per-core usage:");
        for core in &sys.cpu_cores {
            println!("    {}: {:.1}% ({} MHz)", core.name, core.usage, core.frequency);
        }
    }

    // Memory
    println!();
    println!("Memory:");
    println!("  Total: {}", Bytes(si.memory_total_bytes));
    println!(
        "  Used:  {} / {} ({:.1}%)",
        Bytes(sys.memory.used_bytes),
        Bytes(sys.memory.total_bytes),
        sys.memory.percentage,
    );
    if let Some(swap) = &sys.swap {
        println!(
            "  Swap:  {} / {} ({:.1}%)",
            Bytes(swap.used_bytes),
            Bytes(swap.total_bytes),
            swap.percentage,
        );
    }

    // All disks
    println!();
    println!("Disks ({}):", sys.disks.len());
    for disk in &sys.disks {
        println!(
            "  {} ({}) [{}] {}: {} / {} ({:.1}%)",
            disk.mount_point,
            disk.name,
            disk.filesystem,
            disk.disk_type,
            format_bytes(disk.used_bytes),
            format_bytes(disk.total_bytes),
            disk.percentage,
        );
        if let Some(ref model) = disk.model {
            println!("    Model:    {model}");
        }
        if let Some(temp) = disk.temperature {
            println!("    Temp:     {}", Celsius(temp));
        }
        if let Some(wear) = disk.wear_percent {
            println!("    Wear:     {wear:.1}%");
        }
        if disk.is_removable {
            println!("    Removable: yes");
        }
    }

    // GPUs
    println!();
    println!("GPUs ({}):", sys.gpu.len());
    for (i, gpu) in sys.gpu.iter().enumerate() {
        println!("  GPU {i}: {} ({})", gpu.name, gpu.vendor);
        if let Some(vram) = gpu.vram_bytes {
            println!("    VRAM:        {}", Bytes(vram));
        }
        if let Some(ref driver) = gpu.driver_version {
            println!("    Driver:      {driver}");
        }
        if let Some(ref gpu_type) = gpu.gpu_type {
            println!("    Type:        {gpu_type}");
        }
        if let Some(temp) = gpu.temperature {
            println!("    Temperature: {}", Celsius(temp));
        }
        if let Some(util) = gpu.utilization {
            println!("    Utilization: {util:.1}%");
        }
    }

    // Battery
    println!();
    if let Some(bat) = &sys.battery {
        println!("Battery:");
        println!("  Charge:  {:.0}%", bat.charge_percent);
        println!("  State:   {}", bat.state);
        if let Some(v) = bat.voltage {
            println!("  Voltage: {v:.2} V");
        }
        if let Some(cycles) = bat.cycle_count {
            println!("  Cycles:  {cycles}");
        }
        if let Some(health) = bat.health_percent {
            println!("  Health:  {health:.1}%");
        }
    } else {
        println!("Battery: not detected");
    }

    // Sensors
    println!();
    println!("Sensors ({}):", sys.sensors.len());
    for sensor in &sys.sensors {
        match sensor.temperature {
            Some(t) => println!("  {}: {}", sensor.label, Celsius(t)),
            None => println!("  {}: N/A", sensor.label),
        }
    }

}
