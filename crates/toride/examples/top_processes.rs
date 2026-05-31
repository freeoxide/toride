//! Top 10 processes by CPU and memory, plus first-level process tree.
//!
//! Run with: `cargo run --example top_processes`

use toride_status::units::format_bytes;
use toride_status::TorideStatus;

fn main() {
    let status = TorideStatus::collect();
    let procs = &status.system.processes;

    println!("=== Top Processes ({}) ===", procs.total_count);
    println!();

    // Top 10 by CPU
    println!("Top 10 by CPU:");
    println!("  {:<7} {:>6} {:>10}  {}", "PID", "CPU%", "RSS", "Name");
    println!("  {:->7} {:->6} {:->10}  {:->20}", "", "", "", "");
    for p in procs.top_by_cpu(10) {
        println!(
            "  {:<7} {:>5.1}% {:>10}  {}",
            p.pid,
            p.cpu_usage,
            format_bytes(p.memory_bytes),
            p.name,
        );
    }
    println!();

    // Top 10 by memory
    println!("Top 10 by Memory:");
    println!("  {:<7} {:>10} {:>6}  {}", "PID", "RSS", "CPU%", "Name");
    println!("  {:->7} {:->10} {:->6}  {:->20}", "", "", "", "");
    for p in procs.top_by_memory(10) {
        println!(
            "  {:<7} {:>10} {:>5.1}%  {}",
            p.pid,
            format_bytes(p.memory_bytes),
            p.cpu_usage,
            p.name,
        );
    }
    println!();

    // Process tree: group root processes and their direct children
    println!("Process Tree (first level):");
    let all = &procs.processes;

    // Find root processes (PID 1, or those whose parent is not in the list)
    let pid_set: std::collections::HashSet<u32> = all.iter().map(|p| p.pid).collect();
    let roots: Vec<_> = all
        .iter()
        .filter(|p| {
            p.parent_pid.is_none()
                || p.parent_pid == Some(0)
                || p.parent_pid == Some(1)
                || !pid_set.contains(&p.parent_pid.unwrap_or(0))
        })
        .collect();

    // Build children map
    let mut children: std::collections::HashMap<u32, Vec<_>> = std::collections::HashMap::new();
    for p in all {
        if let Some(ppid) = p.parent_pid {
            if pid_set.contains(&ppid) && p.pid != ppid {
                children.entry(ppid).or_default().push(p);
            }
        }
    }

    // Sort roots by CPU (descending)
    let mut sorted_roots = roots;
    sorted_roots.sort_by(|a, b| {
        b.cpu_usage
            .partial_cmp(&a.cpu_usage)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let max_roots = 20;
    for root in sorted_roots.iter().take(max_roots) {
        let child_count = children.get(&root.pid).map_or(0, |c| c.len());
        println!(
            "  {} (PID {}, {:.1}% CPU, {}, {} children)",
            root.name,
            root.pid,
            root.cpu_usage,
            format_bytes(root.memory_bytes),
            child_count,
        );
        // Show first 3 children
        if let Some(kids) = children.get(&root.pid) {
            let mut sorted_kids = kids.clone();
            sorted_kids.sort_by(|a, b| {
                b.cpu_usage
                    .partial_cmp(&a.cpu_usage)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            for child in sorted_kids.iter().take(3) {
                println!(
                    "    \u{251c}\u{2500} {} (PID {}, {:.1}% CPU, {})",
                    child.name,
                    child.pid,
                    child.cpu_usage,
                    format_bytes(child.memory_bytes),
                );
            }
            if sorted_kids.len() > 3 {
                println!("    \u{2514}\u{2500} ... and {} more", sorted_kids.len() - 3);
            }
        }
    }
}
