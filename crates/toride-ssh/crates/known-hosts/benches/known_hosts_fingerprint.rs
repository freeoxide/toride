use std::hint::black_box;
use std::sync::OnceLock;
use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use toride_ssh_core::{MockCliRunner, SshPaths};
use toride_ssh_known_hosts::KnownHostsService;

const FIXTURE: &str = include_str!("../../../tests/fixtures/known_hosts_markers.txt");

const CONFIG_LINES: usize = 200;

const SAMPLE_SIZE: usize = 30;
const MEASUREMENT_TIME: Duration = Duration::from_secs(2);
const WARM_UP_TIME: Duration = Duration::from_millis(500);

fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| tokio::runtime::Runtime::new().expect("failed to build tokio runtime"))
}

struct Rig {
    _dir: tempfile::TempDir,
    service: KnownHostsService<'static>,
}

fn rig() -> Rig {
    let dir = tempfile::tempdir().expect("temp dir");
    std::fs::write(dir.path().join("known_hosts"), FIXTURE).expect("write known_hosts fixture");

    let paths: &'static SshPaths = Box::leak(Box::new(SshPaths::with_dir(dir.path())));
    let runner: &'static MockCliRunner = Box::leak(Box::new(MockCliRunner::new()));
    Rig {
        _dir: dir,
        service: KnownHostsService::new(paths, runner),
    }
}

fn known_hosts_fingerprint_pass(c: &mut Criterion) {
    let rig = rig();
    let rt = runtime();

    let entries = rt
        .block_on(rig.service.list())
        .expect("known_hosts fixture must parse");
    let expected_entries = entries
        .iter()
        .filter(|e| e.key_type == "ssh-ed25519")
        .count();
    assert_eq!(entries.len(), 9, "fixture must yield 9 entries");
    assert_eq!(expected_entries, 6, "fixture must yield 6 ed25519 entries");

    let config_dir = tempfile::tempdir().expect("temp dir");
    let config_path = config_dir.path().join("config");
    let mut config = String::with_capacity(CONFIG_LINES * 48);
    for index in 0..CONFIG_LINES {
        if index == CONFIG_LINES / 2 {
            config.push_str("Host bench\n    UserKnownHostsFile /custom/known_hosts\n");
        }
        if index == CONFIG_LINES / 2 + 1 {
            config.push_str("VerifyHostKeyDNS yes\n");
        }
        if index == CONFIG_LINES / 2 + 2 {
            config.push_str("UpdateHostKeys yes\n");
        }
        config.push_str(&format!(
            "Host filler-{index:03}\n    ServerAliveInterval 60\n    Compression no\n"
        ));
    }
    std::fs::write(&config_path, config).expect("write ssh config fixture");

    let config_paths: &'static SshPaths =
        Box::leak(Box::new(SshPaths::with_dir(config_dir.path())));
    let config_runner: &'static MockCliRunner = Box::leak(Box::new(MockCliRunner::new()));
    let config_service = KnownHostsService::new(config_paths, config_runner);

    assert!(
        rt.block_on(config_service.is_update_host_keys_enabled())
            .expect("config scan answers"),
        "the UpdateHostKeys line is found"
    );
    let resolved = rt
        .block_on(config_service.resolve_user_known_hosts_file("bench"))
        .expect("resolve answers");
    assert_eq!(
        resolved,
        std::path::PathBuf::from("/custom/known_hosts"),
        "the UserKnownHostsFile value resolves from the matching Host block"
    );

    let mut group = c.benchmark_group("known_hosts/config_scan");
    group.sample_size(SAMPLE_SIZE);
    group.measurement_time(MEASUREMENT_TIME);
    group.warm_up_time(WARM_UP_TIME);
    group.throughput(Throughput::Bytes(
        std::fs::metadata(&config_path).expect("config fixture present").len(),
    ));

    group.bench_function("update_host_keys_scan", |b| {
        b.iter(|| {
            let enabled = rt
                .block_on(config_service.is_update_host_keys_enabled())
                .expect("config scan answers");
            black_box(enabled)
        });
    });

    group.bench_function("verify_host_key_dns_scan", |b| {
        b.iter(|| {
            let status = rt
                .block_on(config_service.verify_host_key_dns_status())
                .expect("config scan answers");
            black_box(matches!(status, toride_ssh_known_hosts::DnsVerifyStatus::Enabled))
        });
    });

    group.bench_function("resolve_user_known_hosts_file_scan", |b| {
        b.iter(|| {
            let resolved = rt
                .block_on(config_service.resolve_user_known_hosts_file(black_box("bench")))
                .expect("config scan answers");
            black_box(resolved)
        });
    });

    group.finish();

    let mut group = c.benchmark_group("known_hosts/fingerprint_pass");
    group.sample_size(SAMPLE_SIZE);
    group.measurement_time(MEASUREMENT_TIME);
    group.warm_up_time(WARM_UP_TIME);
    group.throughput(Throughput::Bytes(FIXTURE.len() as u64));

    group.bench_function("parse_file", |b| {
        b.iter(|| {
            let entries = rt
                .block_on(rig.service.list())
                .expect("known_hosts fixture must parse");
            black_box(entries.len())
        });
    });

    group.bench_function("fingerprint_entries", |b| {
        b.iter(|| {
            let ok = entries
                .iter()
                .filter_map(|e| e.fingerprint().ok().map(|fp| fp.hash))
                .fold(0usize, |acc, hash| acc + hash.len());
            black_box(ok)
        });
    });

    group.bench_function("parse_and_fingerprint", |b| {
        b.iter(|| {
            let entries = rt
                .block_on(rig.service.list())
                .expect("known_hosts fixture must parse");
            let ok = entries
                .iter()
                .filter_map(|e| e.fingerprint().ok().map(|fp| fp.hash))
                .fold(0usize, |acc, hash| acc + hash.len());
            black_box(ok)
        });
    });

    group.finish();
}

criterion_group!(benches, known_hosts_fingerprint_pass);
criterion_main!(benches);
