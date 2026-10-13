use std::hint::black_box;
use std::sync::OnceLock;
use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use toride_registry::adapter::Adapter;
use toride_registry::model::Arch;
use toride_registry::sources::appstream::{AppstreamAdapter, parse_dep11_catalog};
use toride_registry::sources::homebrew::{MAX_SEARCH_HITS, parse_cask_index, search_index};

const DEP11_FIXTURE: &str = include_str!("fixtures/dep11-search-catalog.yml");
const CASK_INDEX_FIXTURE: &str = include_str!("fixtures/homebrew-cask-index-synthetic.json");

const DEP11_COMPONENTS: usize = 200;
const CASK_ENTRIES: usize = 150;

const SAMPLE_SIZE: usize = 30;
const MEASUREMENT_TIME: Duration = Duration::from_secs(2);
const WARM_UP_TIME: Duration = Duration::from_millis(500);

fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| tokio::runtime::Runtime::new().expect("failed to build tokio runtime"))
}

fn oracle() {
    let catalog = parse_dep11_catalog(DEP11_FIXTURE).expect("synthetic dep11 catalog parses");
    assert_eq!(
        catalog.components.len(),
        DEP11_COMPONENTS,
        "component count oracle over the committed synthetic catalog"
    );

    let rt = runtime();
    let adapter =
        AppstreamAdapter::from_text(DEP11_FIXTURE, Some(Arch::X86_64)).expect("adapter parses");
    let broad = rt
        .block_on(adapter.search("bench app"))
        .expect("broad query answers");
    assert_eq!(
        broad.len(),
        DEP11_COMPONENTS,
        "a name-substring query matches every component: appstream search serves no hit cap"
    );
    let narrow = rt
        .block_on(adapter.search("app 199"))
        .expect("narrow query answers");
    assert_eq!(narrow.len(), 1, "the narrow query matches exactly one name");

    let index = parse_cask_index(CASK_INDEX_FIXTURE).expect("synthetic cask index parses");
    assert_eq!(index.len(), CASK_ENTRIES);
    assert_eq!(
        search_index(&index, "bench app").len(),
        MAX_SEARCH_HITS,
        "homebrew search caps its hits"
    );
    assert_eq!(
        search_index(&index, "cask 149").len(),
        1,
        "the token-scoped query matches exactly one cask"
    );
}

fn source_search(c: &mut Criterion) {
    oracle();

    let rt = runtime();
    let adapter =
        AppstreamAdapter::from_text(DEP11_FIXTURE, Some(Arch::X86_64)).expect("adapter parses");
    let index = parse_cask_index(CASK_INDEX_FIXTURE).expect("synthetic cask index parses");

    let mut dep11 = c.benchmark_group("dep11_search");
    dep11.sample_size(SAMPLE_SIZE);
    dep11.measurement_time(MEASUREMENT_TIME);
    dep11.warm_up_time(WARM_UP_TIME);
    dep11.throughput(Throughput::Bytes(DEP11_FIXTURE.len() as u64));

    dep11.bench_function("broad_query_200_hits", |b| {
        b.iter(|| {
            let hits = rt
                .block_on(adapter.search(black_box("bench app")))
                .expect("broad query answers");
            black_box(hits.len())
        });
    });

    dep11.bench_function("narrow_query_1_hit", |b| {
        b.iter(|| {
            let hits = rt
                .block_on(adapter.search(black_box("app 199")))
                .expect("narrow query answers");
            black_box(hits.len())
        });
    });

    dep11.finish();

    let mut homebrew = c.benchmark_group("homebrew_search");
    homebrew.sample_size(SAMPLE_SIZE);
    homebrew.measurement_time(MEASUREMENT_TIME);
    homebrew.warm_up_time(WARM_UP_TIME);
    homebrew.throughput(Throughput::Bytes(CASK_INDEX_FIXTURE.len() as u64));

    homebrew.bench_function("broad_query_150_casks", |b| {
        b.iter(|| {
            let hits = search_index(black_box(&index), black_box("bench app"));
            black_box(hits.len())
        });
    });

    homebrew.bench_function("narrow_query_150_casks", |b| {
        b.iter(|| {
            let hits = search_index(black_box(&index), black_box("cask 149"));
            black_box(hits.len())
        });
    });

    homebrew.finish();
}

criterion_group!(benches, source_search);
criterion_main!(benches);
