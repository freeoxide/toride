use std::hint::black_box;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use toride_apps::detect::{
    Detection, DetectionConfidence, DetectionSource, merge_by_canonical_path,
};

const SAMPLE_SIZE: usize = 30;
const MEASUREMENT_TIME: Duration = Duration::from_secs(2);
const WARM_UP_TIME: Duration = Duration::from_millis(500);

const FILES: usize = 50;
const SOURCES_PER_FILE: usize = 4;
const DETECTIONS: usize = FILES * SOURCES_PER_FILE;

fn detections(dir: &std::path::Path) -> Vec<Detection> {
    let mut rows = Vec::with_capacity(DETECTIONS);
    for file_index in 0..FILES {
        let path = dir.join(format!("bench-tool-{file_index:02}"));
        let path = path.to_str().expect("temp path is valid UTF-8").to_owned();
        for source_index in 0..SOURCES_PER_FILE {
            let confidence = if source_index % 2 == 0 {
                DetectionConfidence::High
            } else {
                DetectionConfidence::Medium
            };
            let mut detection = Detection::new(
                format!("bench-tool-{file_index:02}"),
                match source_index {
                    0 => DetectionSource::Homebrew,
                    1 => DetectionSource::Flatpak,
                    2 => DetectionSource::Npm,
                    _ => DetectionSource::Path,
                },
                confidence,
            )
            .with_path(path.clone());
            if source_index == 0 {
                detection = detection.with_version(format!("1.0.{file_index}"));
            }
            rows.push(detection);
        }
    }
    rows
}

fn oracle(dir: &std::path::Path) {
    let rows = detections(dir);
    assert_eq!(rows.len(), DETECTIONS);

    let merged = merge_by_canonical_path(rows.clone());
    assert_eq!(
        merged.len(),
        FILES,
        "all four sources ground at one of {FILES} canonical paths: {merged:?}"
    );
    assert!(
        merged.iter().all(|row| row.version.is_some()),
        "the path hit's reported version survives the merge"
    );
    assert!(
        merged
            .iter()
            .all(|row| row.confidence == DetectionConfidence::High),
        "the highest confidence across sources wins"
    );

    let pathless = vec![
        Detection::new("ghost", DetectionSource::Npm, DetectionConfidence::Low),
        Detection::new("ghost", DetectionSource::Npm, DetectionConfidence::High),
    ];
    assert_eq!(
        merge_by_canonical_path(pathless).len(),
        1,
        "path-less hits dedup by (source, name)"
    );
}

fn merge_detections(c: &mut Criterion) {
    let dir = tempfile::tempdir().expect("temp dir");
    for file_index in 0..FILES {
        let path = dir.path().join(format!("bench-tool-{file_index:02}"));
        std::fs::write(&path, b"#!/bin/sh\n").expect("bench tool file writable");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .expect("bench tool executable");
        }
    }
    oracle(dir.path());

    let rows = detections(dir.path());

    let mut group = c.benchmark_group("merge_detections");
    group.sample_size(SAMPLE_SIZE);
    group.measurement_time(MEASUREMENT_TIME);
    group.warm_up_time(WARM_UP_TIME);
    // Identical code measures within ±8% run-to-run on this host
    // (parallel build load), so deltas under 10% read as noise.
    group.noise_threshold(0.10);

    group.bench_function("merge_200_path_grounded", |b| {
        b.iter(|| {
            let merged = merge_by_canonical_path(black_box(rows.clone()));
            black_box(merged.len())
        });
    });

    group.finish();
}

criterion_group!(benches, merge_detections);
criterion_main!(benches);
