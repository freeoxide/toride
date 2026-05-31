//! GPU information with all available fields.
//!
//! Displays every GPU field the status system can detect, including
//! VRAM, temperature, utilization, power, and clock speed.
//!
//! Run with: `cargo run --example gpu_status`

use toride_status::units::{Bytes, Celsius};
use toride_status::TorideStatus;

fn main() {
    let status = TorideStatus::collect();
    let gpus = &status.system.gpu;

    println!("=== GPU Status ===");
    println!("Found {} GPU(s)", gpus.len());
    println!();

    if gpus.is_empty() {
        println!("No GPUs detected on this system.");
        println!("This may be because:");
        println!("  - No discrete GPU is installed");
        println!("  - nvidia-smi is not available (Linux)");
        println!("  - system_profiler returned no display data (macOS)");
        return;
    }

    for (i, gpu) in gpus.iter().enumerate() {
        println!("GPU {i}: {}", gpu.name);
        println!("  Vendor:             {}", gpu.vendor);

        // Type
        if let Some(ref gpu_type) = gpu.gpu_type {
            println!("  Type:               {gpu_type}");
        }

        // Driver
        if let Some(ref driver) = gpu.driver_version {
            println!("  Driver:             {driver}");
        }

        // PCI info
        if let Some(ref device_id) = gpu.device_id {
            println!("  Device ID:          {device_id}");
        }
        if let Some(ref bus_id) = gpu.pci_bus_id {
            println!("  PCI Bus:            {bus_id}");
        }

        // VRAM
        if let Some(vram) = gpu.vram_bytes {
            print!("  VRAM Total:         {}", Bytes(vram));
            if let Some(used) = gpu.used_vram_bytes {
                print!(" ({} used", Bytes(used));
                if let Some(free) = gpu.free_vram_bytes {
                    print!(", {} free", Bytes(free));
                }
                print!(")");
            }
            println!();
        }

        // Memory utilization
        if let Some(mem_util) = gpu.memory_utilization {
            println!("  Memory Utilization: {mem_util:.1}%");
        }

        // GPU utilization
        if let Some(util) = gpu.utilization {
            println!("  GPU Utilization:    {util:.1}%");
        }

        // Encoder/Decoder
        if let Some(enc) = gpu.encoder_utilization {
            println!("  Encoder Util:       {enc:.1}%");
        }
        if let Some(dec) = gpu.decoder_utilization {
            println!("  Decoder Util:       {dec:.1}%");
        }

        // Temperature
        if let Some(temp) = gpu.temperature {
            println!("  Temperature:        {} ({:.1} F)", Celsius(temp), Celsius(temp).to_fahrenheit());
        }

        // Fan
        if let Some(rpm) = gpu.fan_speed_rpm {
            println!("  Fan Speed:          {rpm} RPM");
        }

        // Power
        if let Some(draw) = gpu.power_draw_watts {
            print!("  Power Draw:         {draw:.1} W");
            if let Some(limit) = gpu.power_limit_watts {
                print!(" / {limit:.1} W limit");
            }
            println!();
        }

        // Clock
        if let Some(mhz) = gpu.clock_speed_mhz {
            println!("  Clock Speed:        {mhz} MHz");
        }

        println!();
    }
}
