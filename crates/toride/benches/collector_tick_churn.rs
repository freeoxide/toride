//! One 2-second refresh tick's worth of collector starts against the stub
//! fixture host (tui-3, tui-14): wall time per tick plus the exact count of
//! subprocesses spawned per tick.
//!
//! The tick mirrors the app's refresh arm at `app/mod.rs:656-689` (all 20
//! collector starts) followed by the status-poll arm's about re-dispatch
//! (`app/mod.rs:509-511`). The fixture host pins `PATH` to counting stubs,
//! so the printed per-tick spawn count is the churn oracle: per-section
//! gating and a logs TTL must shrink it without code changes here.

mod common;

use std::cell::Cell;
use std::collections::HashMap;
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};

use common::fixture_host::FixtureHost;
use toride::about_data::AboutCollector;
use toride::fail2ban_data::Fail2banCollector;
use toride::logs_data::LogsCollector;
use toride::settings_data::SettingsCollector;
use toride::setup_data::SetupCollector;
use toride::ssh_data::SshDataCollector;
use toride::status_collector::StatusCollector;
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

struct RefreshTick {
    status: StatusCollector,
    about: AboutCollector,
    ssh: SshDataCollector,
    fail2ban: Fail2banCollector,
    ufw_kit: FirewallCollector,
    harden: HardenCollector,
    wireguard: WireguardCollector,
    updates: UpdatesCollector,
    users: UsersCollector,
    audit: AuditCollector,
    monitor: MonitorCollector,
    backup: BackupCollector,
    proxy: ProxyCollector,
    cloud: CloudCollector,
    tailscale: TailscaleCollector,
    mise: MiseCollector,
    logs: LogsCollector,
    settings: SettingsCollector,
    templates: TemplatesCollector,
    tools: ToolsCollector,
    setup: SetupCollector,
}

impl RefreshTick {
    fn new() -> Self {
        Self {
            status: StatusCollector::new(),
            about: AboutCollector::new(),
            ssh: SshDataCollector::new(),
            fail2ban: Fail2banCollector::new(),
            ufw_kit: FirewallCollector::new(),
            harden: HardenCollector::new(),
            wireguard: WireguardCollector::new(),
            updates: UpdatesCollector::new(),
            users: UsersCollector::new(),
            audit: AuditCollector::new(),
            monitor: MonitorCollector::new(),
            backup: BackupCollector::new(),
            proxy: ProxyCollector::new(),
            cloud: CloudCollector::new(),
            tailscale: TailscaleCollector::new(),
            mise: MiseCollector::new(),
            logs: LogsCollector::new(),
            settings: SettingsCollector::new(),
            templates: TemplatesCollector::new(),
            tools: ToolsCollector::new(),
            setup: SetupCollector::new(),
        }
    }

    fn start_all(&mut self) {
        self.status.start();
        self.ssh.start();
        self.fail2ban.start();
        self.ufw_kit.start();
        self.harden.start();
        self.wireguard.start();
        self.updates.start();
        self.users.start();
        self.audit.start();
        self.monitor.start();
        self.backup.start();
        self.proxy.start();
        self.cloud.start();
        self.tailscale.start();
        self.mise.start();
        self.logs.start();
        self.settings.start();
        self.templates.start();
        self.tools.start();
        self.setup.start();
    }

    async fn poll_all(&mut self) {
        if let Some(status) = self.status.poll().await {
            self.about.start_with_status(status.clone());
        }
        let _ = self.about.poll().await;
        let _ = self.ssh.poll().await;
        let _ = self.fail2ban.poll().await;
        let _ = self.ufw_kit.poll().await;
        let _ = self.harden.poll().await;
        let _ = self.wireguard.poll().await;
        let _ = self.updates.poll().await;
        let _ = self.users.poll().await;
        let _ = self.audit.poll().await;
        let _ = self.monitor.poll().await;
        let _ = self.backup.poll().await;
        let _ = self.proxy.poll().await;
        let _ = self.cloud.poll().await;
        let _ = self.tailscale.poll().await;
        let _ = self.mise.poll().await;
        let _ = self.logs.poll().await;
        let _ = self.settings.poll().await;
        let _ = self.templates.poll().await;
        let _ = self.tools.poll().await;
        let _ = self.setup.poll().await;
    }

    async fn tick(&mut self) {
        self.start_all();
        self.poll_all().await;
    }
}

fn collector_tick_churn(c: &mut Criterion) {
    let host = FixtureHost::install();
    assert!(
        which::which("journalctl").is_ok(),
        "fixture PATH must resolve the journalctl stub"
    );
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("bench runtime");

    let mut tick = RefreshTick::new();
    rt.block_on(tick.tick());
    rt.block_on(tick.tick());

    let before_count = host.spawn_count();
    let before_by_name: HashMap<String, usize> =
        host.spawn_breakdown().into_iter().collect();
    let measured_ticks = Cell::new(0usize);

    let mut group = c.benchmark_group("collector_tick_churn");
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(20);
    group.bench_function("refresh_tick", |b| {
        b.iter_custom(|iters| {
            let iters = usize::try_from(iters).unwrap_or(usize::MAX);
            measured_ticks.set(measured_ticks.get().saturating_add(iters));
            let start = Instant::now();
            for _ in 0..iters {
                rt.block_on(tick.tick());
            }
            start.elapsed()
        });
    });
    group.finish();

    let ticks = measured_ticks.get();
    let spawns = host.spawn_count() - before_count;
    println!("collector_tick_churn: {spawns} subprocess spawns across {ticks} ticks");
    let per_tick = spawns.checked_div(ticks).unwrap_or(spawns);
    println!("collector_tick_churn: {per_tick} subprocess spawns per refresh tick");
    let scale = ticks.max(1);
    let mut delta: Vec<(String, usize)> = host
        .spawn_breakdown()
        .into_iter()
        .filter_map(|(name, count)| {
            let measured = count.saturating_sub(before_by_name.get(&name).copied().unwrap_or(0));
            (measured > 0).then_some((name, measured))
        })
        .collect();
    delta.sort();
    for (name, count) in delta {
        println!(
            "collector_tick_churn:   {name} x {count} total ({} per tick)",
            count / scale
        );
    }
}

criterion_group!(benches, collector_tick_churn);
criterion_main!(benches);
