use std::hint::black_box;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use toride_ssh_config::ConfigService;
use toride_ssh_core::SshPaths;

const FIXTURE: &str = include_str!("../tests/fixtures/ssh_config");

const SAMPLE_SIZE: usize = 30;
const MEASUREMENT_TIME: Duration = Duration::from_secs(2);
const WARM_UP_TIME: Duration = Duration::from_millis(500);

fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| tokio::runtime::Runtime::new().expect("failed to build tokio runtime"))
}

fn cached_ast(c: &mut Criterion) {
    let mut group = c.benchmark_group("config/ast");
    group.sample_size(SAMPLE_SIZE);
    group.measurement_time(MEASUREMENT_TIME);
    group.warm_up_time(WARM_UP_TIME);

    let ast = toride_ssh_config::ast::parse(FIXTURE);
    let hosts = ast
        .nodes
        .iter()
        .filter(|n| matches!(n, toride_ssh_config::ast::ConfigNode::HostBlock(_)))
        .count();
    assert_eq!(hosts, 4, "fixture must contain 4 host blocks");

    let dir = tempfile::tempdir().expect("tempdir");
    let path: PathBuf = dir.path().join("ssh_config");
    std::fs::write(&path, FIXTURE).expect("write fixture");

    group.throughput(Throughput::Bytes(FIXTURE.len() as u64));
    group.bench_function("parse_fresh", |b| {
        b.iter(|| toride_ssh_config::ast::parse(black_box(FIXTURE)));
    });

    toride_ssh_config::cache::load_cached_ast(&path).expect("warm the cache");
    group.bench_function("load_cached_hit", |b| {
        b.iter(|| {
            let ast =
                toride_ssh_config::cache::load_cached_ast(black_box(&path)).expect("cached load");
            black_box(ast)
        });
    });

    group.bench_function("content_cached_hit", |b| {
        b.iter(|| {
            let content = toride_ssh_config::cache::load_cached_content(black_box(&path))
                .expect("cached content");
            black_box(content)
        });
    });

    group.finish();
}

fn service_and_resolve(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("config/ast");
    group.sample_size(SAMPLE_SIZE);
    group.measurement_time(MEASUREMENT_TIME);
    group.warm_up_time(WARM_UP_TIME);

    let dir = tempfile::tempdir().expect("tempdir");
    let include_dir = tempfile::tempdir().expect("tempdir");
    let include_path: PathBuf = include_dir.path().join("bench-include");
    std::fs::write(
        &include_path,
        "Host included\n    HostName included.example\n    User bench\n",
    )
    .expect("write include fixture");
    let including_config = format!("Include {}\n\n{FIXTURE}", include_path.display());
    std::fs::write(include_dir.path().join("config"), &including_config)
        .expect("write including config");

    let service_paths: &'static SshPaths = Box::leak(Box::new(SshPaths::with_dir(dir.path())));
    std::fs::write(dir.path().join("config"), FIXTURE).expect("write service config fixture");
    let service = ConfigService::new(service_paths);
    rt.block_on(async {
        let loaded = service.load().await.expect("service loads the fixture");
        assert_eq!(
            loaded
                .nodes
                .iter()
                .filter(|n| matches!(n, toride_ssh_config::ast::ConfigNode::HostBlock(_)))
                .count(),
            4,
            "service load returns the same host blocks"
        );
    });
    group.bench_function("service_load", |b| {
        b.iter(|| {
            let ast = rt.block_on(service.load()).expect("service load answers");
            black_box(ast.nodes.len())
        });
    });

    let resolve_paths: &'static SshPaths =
        Box::leak(Box::new(SshPaths::with_dir(include_dir.path())));
    rt.block_on(async {
        let resolved = toride_ssh_config::resolve::resolve(resolve_paths.ssh_dir(), "github", None)
            .await
            .expect("resolve answers for the fixture host");
        assert_eq!(
            resolved.host_name.as_deref(),
            Some("github.com"),
            "resolve applies the Host github block"
        );
        assert_eq!(
            resolved.user.as_deref(),
            Some("git"),
            "resolve applies the block's User"
        );
        let included =
            toride_ssh_config::resolve::resolve(resolve_paths.ssh_dir(), "included", None)
                .await
                .expect("resolve answers through the Include");
        assert_eq!(
            included.host_name.as_deref(),
            Some("included.example"),
            "resolve follows the Include chain"
        );
    });
    group.bench_function("resolve_full", |b| {
        b.iter(|| {
            let resolved = rt
                .block_on(toride_ssh_config::resolve::resolve(
                    black_box(resolve_paths.ssh_dir()),
                    black_box("github"),
                    None,
                ))
                .expect("resolve answers");
            black_box((resolved.host_name.clone(), resolved.identity_files.len()))
        });
    });

    group.finish();
}

criterion_group!(benches, cached_ast, service_and_resolve);
criterion_main!(benches);
