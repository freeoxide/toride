use std::hint::black_box;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use toride_harden::client::HardenClient;
use toride_harden::profile::HardeningProfile;
use toride_harden::spec::HardenSpec;
use toride_runner::fake::FakeRunner;

const SAMPLE_SIZE: usize = 30;
const MEASUREMENT_TIME: Duration = Duration::from_secs(2);
const WARM_UP_TIME: Duration = Duration::from_millis(500);

fn server_spec() -> HardenSpec {
    HardenSpec::builder()
        .profile(HardeningProfile::Server)
        .build()
}

fn counting_rig(spec: &HardenSpec) -> (FakeRunner, HardenClient) {
    let output = spec
        .all_parameters()
        .iter()
        .map(|param| format!("{} = 1", param.key))
        .collect::<Vec<_>>()
        .join("\n");
    let fake = FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(output));
    let client = HardenClient::with_runner(Box::new(fake.clone()));
    (fake, client)
}

fn sysctl_spawn_count(fake: &FakeRunner) -> usize {
    fake.calls()
        .iter()
        .filter(|spec| spec.program == "sysctl")
        .count()
}

fn oracle() {
    let spec = server_spec();
    let (fake, client) = counting_rig(&spec);

    let rows = client
        .status(&spec)
        .unwrap_or_else(|error| panic!("status failed: {error}"));
    assert_eq!(rows.len(), spec.all_parameters().len());
    assert!(
        rows.iter().all(|(_, value)| value == "1"),
        "every parameter value comes from the scripted `sysctl -a` output"
    );

    let spawns = sysctl_spawn_count(&fake);
    assert_eq!(
        spawns, 1,
        "status() must cover every Server-profile parameter with one `sysctl -a` read \
         (it previously spawned one `sysctl -n <key>` per parameter)"
    );
    assert_eq!(
        spec.all_parameters().len(),
        25,
        "the Server profile's parameter set is the spawn-count denominator"
    );
}

fn status_spawn_count(c: &mut Criterion) {
    oracle();

    let mut group = c.benchmark_group("status_spawn_count");
    group.sample_size(SAMPLE_SIZE);
    group.measurement_time(MEASUREMENT_TIME);
    group.warm_up_time(WARM_UP_TIME);

    group.bench_function("status_server_profile", |b| {
        b.iter(|| {
            let spec = server_spec();
            let (_fake, client) = counting_rig(&spec);
            let rows = client.status(black_box(&spec)).expect("status answers");
            black_box(rows.len())
        });
    });

    group.finish();
}

criterion_group!(benches, status_spawn_count);
criterion_main!(benches);
