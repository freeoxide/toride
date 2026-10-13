use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use toride_apps::backends::flatpak::FlatpakBackend;
use toride_apps::backends::homebrew::HomebrewBackend;
use toride_apps::backends::npm::NpmBackend;
use toride_apps::detect::{Detector as _, MultiSourceDetector};
use toride_apps::{command, CommandRunner};
use toride_runner::CommandOutput;
use toride_runner::fake::FakeRunner;

const SAMPLE_SIZE: usize = 30;
const MEASUREMENT_TIME: Duration = Duration::from_secs(2);
const WARM_UP_TIME: Duration = Duration::from_millis(500);

const NAMES: usize = 25;

const BREW_LISTING_ARGS: [&str; 3] = ["info", "--json=v2", "--installed"];
const FLATPAK_LISTING_ARGS: [&str; 3] = [
    "list",
    "--app",
    "--columns=application,version,origin,installation",
];
const NPM_LISTING_ARGS: [&str; 4] = ["list", "--global", "--depth=0", "--json"];

fn tool_name(index: usize) -> String {
    format!("bench-tool-{index:02}")
}

fn brew_listing() -> String {
    let formulae: Vec<String> = (0..NAMES)
        .map(|index| {
            format!(
                r#"{{"name":"{}","versions":{{"stable":"1.0.{index}"}},"installed":[{{"version":"1.0.{index}"}}]}}"#,
                tool_name(index)
            )
        })
        .collect();
    format!(r#"{{"formulae":[{}],"casks":[]}}"#, formulae.join(","))
}

fn flatpak_listing() -> String {
    (0..NAMES)
        .map(|index| format!("{}\t1.0.{index}\tflathub\tuser\n", tool_name(index)))
        .collect()
}

fn npm_listing() -> String {
    let entries: Vec<String> = (0..NAMES)
        .map(|index| format!(r#""{}":{{"version":"1.0.{index}"}}"#, tool_name(index)))
        .collect();
    format!(r#"{{"dependencies":{{{}}}}}"#, entries.join(","))
}

fn detector(fake: &FakeRunner, path_dir: &std::path::Path) -> MultiSourceDetector {
    let runner = CommandRunner::new(Arc::new(fake.clone()));
    MultiSourceDetector::builder()
        .target(toride_apps::plan::Target::new(
            toride_registry::model::Os::Linux,
            toride_registry::model::Arch::X86_64,
        ))
        .runner(runner.clone())
        .path_dirs(vec![camino::Utf8PathBuf::from_path_buf(path_dir.to_path_buf())
            .expect("temp path is valid UTF-8")])
        .homebrew(HomebrewBackend::new(runner.clone()))
        .flatpak(FlatpakBackend::new(runner.clone()))
        .npm(NpmBackend::new(runner))
        .build()
}

fn rig(path_dir: &std::path::Path) -> (FakeRunner, MultiSourceDetector) {
    let mut fake = FakeRunner::new().strict();
    for _ in 0..=NAMES {
        fake = fake
            .respond(
                command("brew", BREW_LISTING_ARGS),
                CommandOutput::from_stdout(brew_listing()),
            )
            .respond(
                command("flatpak", FLATPAK_LISTING_ARGS),
                CommandOutput::from_stdout(flatpak_listing()),
            )
            .respond(
                command("npm", NPM_LISTING_ARGS),
                CommandOutput::from_stdout(npm_listing()),
            );
    }
    let detector = detector(&fake, path_dir);
    (fake, detector)
}

fn count(fake: &FakeRunner, program: &str, args: &[&str]) -> usize {
    fake.calls()
        .iter()
        .filter(|spec| {
            spec.program == program
                && spec.args.iter().map(String::as_str).collect::<Vec<_>>() == args
        })
        .count()
}

fn oracle(path_dir: &std::path::Path) {
    let (fake, detector) = rig(path_dir);

    let hits = detector.detect(&tool_name(0));
    assert_eq!(
        hits.len(),
        3,
        "one hit per backend: brew, flatpak, npm: {hits:?}"
    );
    assert!(hits.iter().all(|hit| hit.version.is_some()));

    let mut total = 0;
    for index in 0..NAMES {
        total += detector.detect(black_box(&tool_name(index))).len();
    }
    assert_eq!(total, NAMES * 3, "every name answers three hits");

    assert_eq!(
        count(&fake, "brew", &BREW_LISTING_ARGS),
        NAMES + 1,
        "one full brew listing per name probe: the detect-many target is one per backend"
    );
    assert_eq!(count(&fake, "flatpak", &FLATPAK_LISTING_ARGS), NAMES + 1);
    assert_eq!(count(&fake, "npm", &NPM_LISTING_ARGS), NAMES + 1);
    assert_eq!(
        fake.calls().len(),
        (NAMES + 1) * 3,
        "no other dispatches: the path dir carries none of the names"
    );
}

fn detect_bench(c: &mut Criterion) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path_dir = dir.path().join("bin");
    std::fs::create_dir_all(&path_dir).expect("empty path dir creatable");
    oracle(&path_dir);

    let mut group = c.benchmark_group("detect");
    group.sample_size(SAMPLE_SIZE);
    group.measurement_time(MEASUREMENT_TIME);
    group.warm_up_time(WARM_UP_TIME);

    group.bench_function("sweep_25_names_3_backends", |b| {
        b.iter(|| {
            let (_fake, detector) = rig(&path_dir);
            let mut hits = 0;
            for index in 0..NAMES {
                hits += detector.detect(black_box(&tool_name(index))).len();
            }
            black_box(hits)
        });
    });

    group.bench_function("single_name_3_backends", |b| {
        b.iter(|| {
            let (_fake, detector) = rig(&path_dir);
            let hits = detector.detect(black_box(&tool_name(0))).len();
            black_box(hits)
        });
    });

    group.finish();
}

criterion_group!(benches, detect_bench);
criterion_main!(benches);
