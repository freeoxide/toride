//! Criterion bench pinning the DEP-11 **parse half** (campaign finding
//! F14): [`parse_dep11_catalog`] and its adapter wrapper
//! [`AppstreamAdapter::from_text`] over one small committed **synthetic**
//! catalog fixture — never a live ~27 MB catalog — so a change on the
//! fetch side (streaming, decompression, client) cannot quietly regress
//! parsing.
//!
//! Round 2 extends the pin to the F14 **fetch-side cache** (the `http`
//! feature's TTL serving path): `cached_catalog` over a seeded cache
//! directory — stat + open + full gzip inflate, exactly the work a
//! TTL-hit `fetch_catalog` performs off its async thread. The network
//! arms of the fix (conditional GET, `304` revalidation, the streamed
//! `BufWriter` download) are pinned offline by the crate's
//! `client_tests` (validator sidecar round-trip, conditional-header
//! construction, mtime-keyed probe) and live by `network_tests` — none
//! of them are benchable hermetically.
//!
//! Hermetic by construction: the fixture is `include_str!`-ed at compile
//! time (no runtime file access, no network, no clock), the parse half is
//! pure, and the groups are tuned (short warm-up, 2 s measurement window)
//! to keep the whole bench seconds-scale for per-round campaign re-runs.
//!
//! Deterministic oracle (runs before any timing): the fixture's parse is
//! pinned by exact count, header shape, numeric-scalar and
//! string-timestamp coercion, and the empty-document skip; two parses must
//! be bit-identical; and both entry points must agree ([`oracle`]). If the
//! fixture or the parser drifts, the bench fails fast instead of timing a
//! regression.
//!
//! Run scoped (never `--workspace`; the campaign saves its own baseline):
//!
//! ```text
//! cargo bench -p toride-registry --bench dep11_parse
//! ```

use std::hint::black_box;
use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use toride_registry::model::Arch;
use toride_registry::sources::appstream::{
    AppstreamAdapter, decode_catalog_arch, parse_dep11_catalog,
};

/// The synthetic benchmark catalog (see the fixture's header comment for
/// provenance and the wire edges it deliberately carries). Embedded at
/// compile time so the bench reads nothing at runtime.
const FIXTURE: &str = include_str!("fixtures/dep11-synthetic.yml");

/// Exact number of component documents the fixture must parse to — the
/// count oracle. Six real components; the stray empty document between the
/// `---` markers must be skipped, not counted.
const EXPECTED_COMPONENTS: usize = 6;

/// The header `Origin` the fixture carries (a `debian-` prefix so the
/// family decode stays on the Debian path, matching every real catalog).
const EXPECTED_ORIGIN: &str = "debian-bench-main";

/// The canonical DEP-11 catalog filename the bench decodes its arch claim
/// from (`Components-<arch>.yml.gz`, the fetch URL layout — the YAML names
/// no arch itself).
const CATALOG_FILENAME: &str = "Components-amd64.yml";

/// Deterministic count/parity oracle over the fixture: runs before any
/// benchmarking so a parser or fixture drift fails the bench loudly
/// instead of being timed.
fn oracle() {
    let arch = decode_catalog_arch(CATALOG_FILENAME);
    assert_eq!(
        arch,
        Some(Arch::X86_64),
        "arch must decode from the canonical catalog filename"
    );

    // Count + header-shape oracle over the pure parser.
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

    // Wire-edge oracles: the edges the bench must keep parsing (and keep
    // parsing FAST) are exactly the ones the live catalog exercises.
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

    // Determinism oracle: identical input, identical typed output.
    let reparsed = parse_dep11_catalog(FIXTURE).expect("second parse succeeds");
    assert_eq!(catalog, reparsed, "parse must be deterministic");

    // Parity oracle: the adapter entry point and the pure parser agree —
    // `from_text` must delegate to `parse_dep11_catalog`, never diverge.
    let adapter = AppstreamAdapter::from_text(FIXTURE, arch).expect("adapter parses fixture");
    assert_eq!(
        adapter.catalog(),
        &catalog,
        "AppstreamAdapter::from_text must agree with parse_dep11_catalog"
    );
}

/// The benchmark group: one bench per parse-half entry point, throughput in
/// fixture bytes so per-round runs read as MB/s of catalog text.
fn bench_dep11_parse(criterion: &mut Criterion) {
    // Correctness gate before timing: benchmarking a broken parse would be
    // a measurement of the wrong thing.
    oracle();

    let arch = decode_catalog_arch(CATALOG_FILENAME);
    let mut group = criterion.benchmark_group("dep11_parse");
    // Seconds-scale per round: 30 samples over a 2 s window (criterion's
    // minimum sample size is 10) with a short warm-up — the fixture is
    // small enough that every sample still runs thousands of iterations.
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

/// The F14 fetch-side cache group (`http` feature): the TTL-hit serving
/// path over a seeded cache directory. Seeding gzips the fixture to the
/// client's exact layout path (`<cache>/appstream/sid-main-Components-
/// amd64.yml.gz`, pinned by `client_tests::cache_path_is_layout_shaped`)
/// — byte-for-byte what a fresh download leaves behind.
///
/// Deterministic oracle before any timing (cached-vs-fresh parity, the
/// F14 round-2 requirement): the seeded scope must decompress back to the
/// fixture verbatim, and an uncached scope must answer `Ok(None)`.
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

    // Seed: the fixture gzipped to the layout path (flate2 write-through,
    // the same encoder shape the download's write-through produces).
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

    // Parity oracle before timing: benchmarking a broken cache read would
    // measure the wrong thing.
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

/// Register every group, keeping the `http`-gated cache group out of
/// `--no-default-features` builds.
fn bench_all(criterion: &mut Criterion) {
    bench_dep11_parse(criterion);
    #[cfg(feature = "http")]
    bench_dep11_cache(criterion);
}

criterion_group!(benches, bench_all);
criterion_main!(benches);
