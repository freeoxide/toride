//! Collector loop showing interface counters and network rates.
//!
//! Displays per-interface byte counters, packet counts, errors,
//! and computed RX/TX rates from the Collector delta.
//!
//! Run with: `cargo run --example network_rates`

use std::time::Duration;

use toride_status::units::format_bytes;
use toride_status::{Collector, Preset};

fn main() {
    let mut collector = Collector::new(Duration::from_secs(1), Preset::ServerMonitoring);
    let iterations = 5;

    println!("=== Network Rate Monitor ({iterations} iterations) ===");
    println!();

    // First collect to establish baseline
    let (status, _) = collector.collect();
    println!("Interfaces found: {}", status.system.network_interfaces.len());
    println!();

    for i in 0..iterations {
        let (status, delta) = collector.collect_after_interval();
        let sys = &status.system;

        println!("--- Sample {} ---", i + 1);

        // Aggregate
        println!(
            "  Aggregate: {} sent, {} received",
            format_bytes(sys.network.bytes_transmitted),
            format_bytes(sys.network.bytes_received),
        );

        // Rates from delta
        if let Some(ref d) = delta {
            println!(
                "  RX rate: {:.1} B/s ({})",
                d.network.bytes_received_rate,
                format_bytes(d.network.bytes_received_delta),
            );
            println!(
                "  TX rate: {:.1} B/s ({})",
                d.network.bytes_transmitted_rate,
                format_bytes(d.network.bytes_transmitted_delta),
            );
        }

        // Per-interface
        println!("  Interfaces:");
        for iface in &sys.network_interfaces {
            println!("    {}:", iface.name);
            println!(
                "      RX: {} ({} packets, {} errors, {} drops)",
                format_bytes(iface.bytes_received),
                iface.packets_received,
                iface.errors_received,
                iface.drops_received,
            );
            println!(
                "      TX: {} ({} packets, {} errors, {} drops)",
                format_bytes(iface.bytes_transmitted),
                iface.packets_transmitted,
                iface.errors_transmitted,
                iface.drops_transmitted,
            );
            if let Some(ref mac) = iface.mac_address {
                println!("      MAC: {mac}");
            }
            if let Some(mtu) = iface.mtu {
                println!("      MTU: {mtu}");
            }
            if let Some(ref status) = iface.link_status {
                println!("      Link: {status}");
            }
            if let Some(speed) = iface.speed_bps {
                println!("      Speed: {} bps", speed);
            }
        }

        println!();
    }

    println!("Done.");
}
