use std::hint::black_box;
use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use toride_registry::model::Arch;
use toride_registry::sources::appstream::{
    AppstreamAdapter, decode_catalog_arch, parse_dep11_catalog,
};

const FIXTURE: &str = include_str!("fixtures/dep11-synthetic.yml");

const EXPECTED_COMPONENTS: usize = 6;

const EXPECTED_ORIGIN: &str = "debian-bench-main";

const CATALOG_FILENAME: &str = "Components-amd64.yml";

fn oracle() {
    let arch = decode_catalog_arch(CATALOG_FILENAME);
    assert_eq!(
        arch,
        Some(Arch::X86_64),
        "arch must decode from the canonical catalog filename"
    );

    let catalog = parse_dep11_catalog(FIXTURE).expect("synthetic fixture parses");
    assert_eq!(catalog.header.file.as_deref(), Some("DEP-11"));
    assert_eq!(catalog.header.origin.as_deref(), Some(EXPECTED_ORIGIN));
    assert_eq!(
        catalog.components.len(),
        EXPECTED_COMPONENTS,
        "component count oracle: the stray empty document must be skipped"
    );
    assert_eq!(
        catalog.components[0].id.as_deref(),
        Some("org.toride.bench.Editor.desktop"),
        "component order preserves the catalog's"
    );

    let editor = &catalog.components[0];
    assert_eq!(
        editor
            .provides
            .as_ref()
            .map(|provides| provides.binaries.as_slice())
            .unwrap_or_default(),
        ["toride-bench-editor"],
        "Provides.binaries is the tool-detection join key"
    );
    let numeric = &catalog.components[2];
    assert_eq!(
        numeric.package.as_deref(),
        Some("2048"),
        "bare-numeric Package must degrade to text, never fail the catalog"
    );
    assert_eq!(
        numeric.name.get("C").map(String::as_str),
        Some("2048"),
        "bare-numeric locale value must degrade to text"
    );
    let clock = catalog.components.last().expect("six components indexed");
    assert_eq!(
        clock.releases[0].unix_timestamp,
        Some(1_789_344_000),
        "string-encoded unix-timestamp must parse to the same integer"
    );

    let reparsed = parse_dep11_catalog(FIXTURE).expect("second parse succeeds");
    assert_eq!(catalog, reparsed, "parse must be deterministic");

    let adapter = AppstreamAdapter::from_text(FIXTURE, arch).expect("adapter parses fixture");
    assert_eq!(
        adapter.catalog(),
        &catalog,
        "AppstreamAdapter::from_text must agree with parse_dep11_catalog"
    );
}

fn bench_dep11_parse(criterion: &mut Criterion) {
    oracle();

    let arch = decode_catalog_arch(CATALOG_FILENAME);
    let mut group = criterion.benchmark_group("dep11_parse");
    group.sample_size(30);
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(2));
    group.throughput(Throughput::Bytes(FIXTURE.len() as u64));

    group.bench_function("parse_dep11_catalog", |bencher| {
        bencher.iter(|| parse_dep11_catalog(black_box(FIXTURE)).expect("fixture parses"));
    });
    group.bench_function("adapter_from_text", |bencher| {
        bencher.iter(|| {
            AppstreamAdapter::from_text(black_box(FIXTURE), black_box(arch))
                .expect("fixture parses");
        });
    });
    group.finish();
}

#[cfg(feature = "http")]
fn bench_dep11_cache(criterion: &mut Criterion) {
    use std::io::Write as _;
    use toride_registry::sources::appstream::AppstreamClient;

    let cache_root = std::env::temp_dir().join(format!(
        "toride-registry-dep11-cache-bench-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&cache_root);
    std::fs::create_dir_all(&cache_root).expect("bench cache dir creatable");
    let client = AppstreamClient::new(cache_root.to_string_lossy().into_owned());

    let catalog_path = cache_root
        .join("appstream")
        .join("sid-main-Components-amd64.yml.gz");
    std::fs::create_dir_all(catalog_path.parent().expect("layout parent")).expect("layout dir");
    let file = std::fs::File::create(&catalog_path).expect("seed file creatable");
    let mut encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    encoder
        .write_all(FIXTURE.as_bytes())
        .expect("seed writable");
    encoder.finish().expect("seed finishable");

    assert_eq!(
        client
            .cached_catalog("sid", "main", "amd64")
            .expect("seeded scope reads")
            .as_deref(),
        Some(FIXTURE),
        "cached-vs-fresh parity: the gz round-trip must be lossless"
    );
    assert_eq!(
        client
            .cached_catalog("bookworm", "main", "amd64")
            .expect("uncached scope reads"),
        None,
        "an uncached scope is an honest None"
    );

    let mut group = criterion.benchmark_group("dep11_cache");
    group.sample_size(30);
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(2));
    group.throughput(Throughput::Bytes(FIXTURE.len() as u64));
    group.bench_function("cached_catalog", |bencher| {
        bencher.iter(|| {
            client
                .cached_catalog(black_box("sid"), black_box("main"), black_box("amd64"))
                .expect("seeded scope reads")
                .expect("seeded copy exists")
        });
    });
    group.finish();
}

fn bench_all(criterion: &mut Criterion) {
    bench_dep11_parse(criterion);
    #[cfg(feature = "http")]
    bench_dep11_cache(criterion);
}

criterion_group!(benches, bench_all);
criterion_main!(benches);
