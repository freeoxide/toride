use std::hint::black_box;
use std::path::Path;
use std::time::SystemTime;

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use tempfile::TempDir;
use toride_proxy::certs_parse::{list_live_certs, read_cert_expiry};

use toride_runner::CommandOutput;
use toride_runner::Runner;
use toride_runner::duct_runner::DuctRunner;
use toride_runner::fake::FakeRunner;

const FIXTURE_CERT: &str = include_str!("fixtures/certs/self_signed.pem");
const CERT_COUNTS: [usize; 3] = [1, 10, 50];
const DUCT_LEG_ENV: &str = "TORIDE_BENCH_CERT_SCAN_DUCT";

fn not_after_output() -> CommandOutput {
    CommandOutput::from_stdout("notAfter=Oct 10 03:47:30 2036 GMT\n")
}

fn live_tree(cert_count: usize) -> TempDir {
    let dir = TempDir::new().expect("cert_scan tempdir");
    for i in 0..cert_count {
        let site = dir.path().join(format!("site-{i}.example.com"));
        std::fs::create_dir_all(&site).expect("site dir");
        std::fs::write(site.join("fullchain.pem"), FIXTURE_CERT).expect("fullchain.pem");
    }
    dir
}

fn scan_expiry(live_dir: &Path, runner: &dyn Runner, now: SystemTime) -> usize {
    let certs = list_live_certs(live_dir).expect("live certs");
    let mut valid = 0;
    for cert in &certs {
        let expiry = read_cert_expiry(Path::new(&cert.path), runner, now).expect("expiry");
        if expiry.is_valid {
            valid += 1;
        }
    }
    valid
}

fn bench_cert_scan_fake(c: &mut Criterion, now: SystemTime) {
    let mut group = c.benchmark_group("cert_scan");

    if which::which("openssl").is_err() {
        println!(
            "cert_scan: openssl not on PATH; the FakeRunner leg would only measure the which-miss path, skipping"
        );
        group.finish();
        return;
    }

    for cert_count in CERT_COUNTS {
        let tree = live_tree(cert_count);
        let live_dir = tree.path().to_path_buf();

        let runner = FakeRunner::new().push_response(not_after_output());
        let valid = scan_expiry(&live_dir, &runner, now);
        assert_eq!(valid, cert_count, "every fixture cert must read as valid");

        group.throughput(Throughput::Elements(cert_count as u64));
        group.bench_with_input(
            criterion::BenchmarkId::new("scan_fake_runner", cert_count),
            &live_dir,
            |b, live_dir| {
                b.iter_batched(
                    || FakeRunner::new().push_response(not_after_output()),
                    |runner| black_box(scan_expiry(live_dir, &runner, now)),
                    BatchSize::NumIterations(1),
                );
            },
        );
    }

    group.throughput(Throughput::Elements(1));
    group.finish();
}

fn bench_cert_scan_duct(c: &mut Criterion, now: SystemTime) {
    if std::env::var_os(DUCT_LEG_ENV).is_none() {
        return;
    }

    let mut group = c.benchmark_group("cert_scan");
    group.sample_size(10);

    for cert_count in CERT_COUNTS {
        let tree = live_tree(cert_count);
        let live_dir = tree.path().to_path_buf();

        let runner = DuctRunner;
        let valid = scan_expiry(&live_dir, &runner, now);
        assert_eq!(
            valid, cert_count,
            "real openssl must validate every fixture cert"
        );

        group.throughput(Throughput::Elements(cert_count as u64));
        group.bench_with_input(
            criterion::BenchmarkId::new("scan_duct_runner", cert_count),
            &live_dir,
            |b, live_dir| b.iter(|| black_box(scan_expiry(live_dir, &runner, now))),
        );
    }

    group.throughput(Throughput::Elements(1));
    group.finish();
}

fn bench_cert_scan(c: &mut Criterion) {
    let now = SystemTime::now();
    bench_cert_scan_fake(c, now);
    bench_cert_scan_duct(c, now);
}

criterion_group!(benches, bench_cert_scan);
criterion_main!(benches);
