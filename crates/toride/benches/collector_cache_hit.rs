//! Steady-state cache-hit cost of every TTL collector:
//! each collector is primed on the stub fixture host, then one
//! start-plus-poll cycle is measured per iteration.
//!
//! A cycle that spawns zero stub subprocesses is cache-served: its cost is
//! the oneshot round trip plus the cached bundle's deep clone, which is the
//! allocation the Arc-bundle work removes. A cycle that still spawns probes
//! is TTL-missed or uncached (logs is excluded by design); the printed
//! per-cycle spawn count names which collectors re-probe every 2-second tick
//! on the fixture host.

mod common;

use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};

use common::fixture_host::FixtureHost;
use toride::fail2ban_data::Fail2banCollector;
use toride::setup_data::SetupCollector;
use toride::ssh_data::SshDataCollector;
use toride::templates_data::TemplatesCollector;
use toride::tools_data::ToolsCollector;
use toride::toride_audit_data::AuditCollector;
use toride::toride_backup_data::BackupCollector;
use toride::toride_cloud_data::CloudCollector;
use toride::toride_harden_data::HardenCollector;
use toride::toride_mise_data::MiseCollector;
use toride::toride_monitor_data::MonitorCollector;
use toride::toride_proxy_data::ProxyCollector;
use toride::toride_tailscale_data::TailscaleCollector;
use toride::toride_updates_data::UpdatesCollector;
use toride::toride_users_data::UsersCollector;
use toride::toride_wireguard_data::WireguardCollector;
use toride::ufw_kit_data::FirewallCollector;

macro_rules! sweep_arm {
    ($group:expr, $rt:expr, $host:expr, $id:literal, $collector:expr) => {{
        let mut collector = $collector;
        $rt.block_on(async {
            for _ in 0..2 {
                collector.start();
                let _ = collector.poll().await;
            }
        });
        $group.bench_function($id, |b| {
            b.iter(|| {
                $rt.block_on(async {
                    collector.start();
                    let _ = collector.poll().await;
                });
            });
        });
        let before = $host.spawn_count();
        let before_by_name: std::collections::HashMap<String, usize> =
            $host.spawn_breakdown().into_iter().collect();
        $rt.block_on(async {
            collector.start();
            let _ = collector.poll().await;
        });
        let spawns = $host.spawn_count() - before;
        if spawns == 0 {
            println!("collector_cache_hit: {} -> cache-served cycle", $id);
        } else {
            let names = $host
                .spawn_breakdown()
                .into_iter()
                .filter_map(|(name, total)| {
                    let delta = total - before_by_name.get(&name).copied().unwrap_or(0);
                    (delta > 0).then_some(format!("{name} x {delta}"))
                })
                .collect::<Vec<_>>()
                .join(", ");
            println!(
                "collector_cache_hit: {} -> {spawns} subprocess spawns per cycle ({names})",
                $id,
            );
        }
    }};
}

fn collector_cache_hit(c: &mut Criterion) {
    let host = FixtureHost::install();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("bench runtime");

    let mut group = c.benchmark_group("collector_cache_hit");
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(2));
    group.sample_size(20);

    sweep_arm!(group, rt, host, "fail2ban", Fail2banCollector::new());
    sweep_arm!(group, rt, host, "ufw_kit", FirewallCollector::new());
    sweep_arm!(group, rt, host, "harden", HardenCollector::new());
    sweep_arm!(group, rt, host, "wireguard", WireguardCollector::new());
    sweep_arm!(group, rt, host, "updates", UpdatesCollector::new());
    sweep_arm!(group, rt, host, "users", UsersCollector::new());
    sweep_arm!(group, rt, host, "audit", AuditCollector::new());
    sweep_arm!(group, rt, host, "monitor", MonitorCollector::new());
    sweep_arm!(group, rt, host, "backup", BackupCollector::new());
    sweep_arm!(group, rt, host, "proxy", ProxyCollector::new());
    sweep_arm!(group, rt, host, "cloud", CloudCollector::new());
    sweep_arm!(group, rt, host, "tailscale", TailscaleCollector::new());
    sweep_arm!(group, rt, host, "mise", MiseCollector::new());
    sweep_arm!(group, rt, host, "templates", TemplatesCollector::new());
    sweep_arm!(group, rt, host, "tools", ToolsCollector::new());
    sweep_arm!(group, rt, host, "setup", SetupCollector::new());
    sweep_arm!(group, rt, host, "ssh", SshDataCollector::new());

    group.finish();
}

criterion_group!(benches, collector_cache_hit);
criterion_main!(benches);
