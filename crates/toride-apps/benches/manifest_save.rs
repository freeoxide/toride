use std::hint::black_box;
use std::time::Duration;

use camino::Utf8PathBuf;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use toride_apps::manifest::{InstallRecord, NativeIds, RecordSnapshot};
use toride_apps::plan::{InstallOptions, Target, plan_install};
use toride_apps::store::{JsonRecordStore, RecordStore};
use toride_registry::model::{App, Availability, InstallMethod, SourceKind, SourceRef, TorideId};

const SAMPLE_SIZE: usize = 30;
const MEASUREMENT_TIME: Duration = Duration::from_secs(2);
const WARM_UP_TIME: Duration = Duration::from_millis(500);

const SIZES: [usize; 2] = [25, 200];

fn bench_app(index: usize) -> App {
    let token = format!("bench-app-{index:03}");
    App {
        id: TorideId::slugify(&token),
        name: format!("Bench App {index:03}"),
        aliases: Vec::new(),
        summary: Some("A bench formula".to_owned()),
        description: None,
        homepage: Some(format!("https://bench.example/{index:03}")),
        license: None,
        developer: None,
        binaries: Vec::new(),
        latest: None,
        platforms: Vec::new(),
        artifacts: Vec::new(),
        install: InstallMethod::Homebrew {
            cask: false,
            token: token.clone(),
        },
        sources: vec![SourceRef {
            source: SourceKind::HomebrewFormula,
            id: token,
            repo: None,
            version: None,
            provisional: false,
        }],
        availability: Availability::Available,
    }
}

fn snapshot(size: usize) -> RecordSnapshot {
    let target = Target::new(
        toride_registry::model::Os::Linux,
        toride_registry::model::Arch::X86_64,
    );
    let mut records = std::collections::BTreeMap::new();
    for index in 0..size {
        let app = bench_app(index);
        let plan = plan_install(&app, &target, &InstallOptions::new())
            .unwrap_or_else(|error| panic!("plan {index} failed: {error}"));
        let record = InstallRecord::new(
            plan,
            NativeIds::Homebrew {
                token: format!("bench-app-{index:03}"),
                cask: false,
            },
            Some(format!("1.0.{index}")),
        );
        records.insert(TorideId::slugify(&format!("bench-app-{index:03}")), record);
    }
    RecordSnapshot { records }
}

fn oracle(path: &std::path::Path) {
    let store = JsonRecordStore::at(
        Utf8PathBuf::from_path_buf(path.to_path_buf()).expect("temp path is valid UTF-8"),
    );
    let snapshot = snapshot(SIZES[0]);
    store
        .save(&snapshot)
        .unwrap_or_else(|error| panic!("save failed: {error}"));
    let reloaded = store
        .load()
        .unwrap_or_else(|error| panic!("load failed: {error}"));
    assert_eq!(
        reloaded.snapshot.records.len(),
        SIZES[0],
        "the saved ledger round-trips through the store"
    );
}

fn manifest_save(c: &mut Criterion) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("apps-manifest.json");
    oracle(&path);

    let mut group = c.benchmark_group("manifest_save");
    group.sample_size(SAMPLE_SIZE);
    group.measurement_time(MEASUREMENT_TIME);
    group.warm_up_time(WARM_UP_TIME);

    for size in SIZES {
        let store = JsonRecordStore::at(
            Utf8PathBuf::from_path_buf(path.clone()).expect("temp path is valid UTF-8"),
        );
        let snapshot = snapshot(size);
        group.throughput(Throughput::Elements(size as u64));
        group.bench_function(format!("json_record_store_save_{size}_records"), |b| {
            b.iter(|| {
                store.save(black_box(&snapshot)).expect("save succeeds");
            });
        });
    }

    group.finish();
}

criterion_group!(benches, manifest_save);
criterion_main!(benches);
