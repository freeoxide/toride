use std::hint::black_box;
use std::path::PathBuf;
use std::time::Duration;

use camino::Utf8PathBuf;
use criterion::{Criterion, criterion_group, criterion_main};
use toride_installer::status::{Detector, ToolStatus};
use toride_installer::tool::{ArtifactKind, Checksum, Tool};
use toride_runner::fake::FakeRunner;

const INSTALLED_TOOLS: usize = 100;
const ABSENT_TOOLS: usize = 25;

const SAMPLE_SIZE: usize = 30;
const MEASUREMENT_TIME: Duration = Duration::from_secs(2);
const WARM_UP_TIME: Duration = Duration::from_millis(500);

fn bench_tool(index: usize) -> Tool {
    Tool::builder()
        .name(format!("bench-tool-{index:03}"))
        .artifact(ArtifactKind::Binary)
        .bin_name(format!("bench-tool-{index:03}"))
        .checksum(Checksum::None)
        .build()
        .expect("synthetic bench tool validates")
}

fn write_managed_dummy(dir: &std::path::Path, index: usize) {
    let path = dir.join(format!("bench-tool-{index:03}"));
    std::fs::write(&path, b"#!/bin/sh\n").expect("managed dummy writable");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("managed dummy executable");
    }
}

struct PathGuard {
    original: Option<std::ffi::OsString>,
    empty_dir: PathBuf,
}

impl PathGuard {
    fn install() -> Self {
        let empty_dir = std::env::temp_dir().join(format!(
            "toride-installer-bench-empty-path-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&empty_dir).expect("empty PATH dir creatable");
        let original = std::env::var_os("PATH");
        unsafe { std::env::set_var("PATH", &empty_dir) };
        Self {
            original,
            empty_dir,
        }
    }
}

impl Drop for PathGuard {
    fn drop(&mut self) {
        if let Some(original) = self.original.take() {
            unsafe { std::env::set_var("PATH", original) };
        }
        let _ = std::fs::remove_dir_all(&self.empty_dir);
    }
}

fn oracle(managed_dir: &std::path::Path) {
    let detector = Detector::builder()
        .runner(std::sync::Arc::new(FakeRunner::new().push_response(
            toride_runner::CommandOutput::from_stdout("1.0.0\n"),
        )))
        .install_dir(Utf8PathBuf::from_path_buf(managed_dir.to_path_buf())
            .expect("temp path is valid UTF-8"))
        .build();

    let installed = detector.detect(&bench_tool(0));
    assert!(
        matches!(installed, ToolStatus::Managed { .. }),
        "an empty PATH with the managed file present classifies Managed: {installed:?}"
    );
    assert!(installed.version().is_some(), "the probe answers 1.0.0");

    let absent = detector.detect(&bench_tool(INSTALLED_TOOLS + 500));
    assert_eq!(
        absent,
        ToolStatus::NotInstalled,
        "no PATH hit and no managed file: honestly absent"
    );
}

fn detect_sweep(criterion: &mut Criterion) {
    let managed = tempfile::tempdir().expect("managed temp dir");
    for index in 0..INSTALLED_TOOLS {
        write_managed_dummy(managed.path(), index);
    }
    let _guard = PathGuard::install();
    oracle(managed.path());

    let detector = Detector::builder()
        .runner(std::sync::Arc::new(FakeRunner::new().push_response(
            toride_runner::CommandOutput::from_stdout("1.0.0\n"),
        )))
        .install_dir(Utf8PathBuf::from_path_buf(managed.path().to_path_buf())
            .expect("temp path is valid UTF-8"))
        .build();

    let installed_tools: Vec<Tool> = (0..INSTALLED_TOOLS).map(bench_tool).collect();
    let absent_tools: Vec<Tool> = (INSTALLED_TOOLS..INSTALLED_TOOLS + ABSENT_TOOLS)
        .map(bench_tool)
        .collect();

    let mut group = criterion.benchmark_group("detect_sweep");
    group.sample_size(SAMPLE_SIZE);
    group.measurement_time(MEASUREMENT_TIME);
    group.warm_up_time(WARM_UP_TIME);

    group.bench_function(format!("sweep_{INSTALLED_TOOLS}_managed_tools"), |b| {
        b.iter(|| {
            let mut managed_count = 0usize;
            for tool in &installed_tools {
                if matches!(detector.detect(black_box(tool)), ToolStatus::Managed { .. }) {
                    managed_count += 1;
                }
            }
            black_box(managed_count)
        });
    });

    group.bench_function(format!("sweep_{ABSENT_TOOLS}_absent_tools"), |b| {
        b.iter(|| {
            let mut absent_count = 0usize;
            for tool in &absent_tools {
                if detector.detect(black_box(tool)) == ToolStatus::NotInstalled {
                    absent_count += 1;
                }
            }
            black_box(absent_count)
        });
    });

    group.finish();
}

criterion_group!(benches, detect_sweep);
criterion_main!(benches);
