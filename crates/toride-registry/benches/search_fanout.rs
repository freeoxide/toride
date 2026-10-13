use std::hint::black_box;
use std::sync::OnceLock;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use toride_registry::adapter::{Adapter as _, Registry};
use toride_registry::error::Result;
use toride_registry::model::{
    App, Availability, InstallMethod, SourceKind, SourceRef, TorideId,
};

const SAMPLE_SIZE: usize = 30;
const MEASUREMENT_TIME: Duration = Duration::from_secs(2);
const WARM_UP_TIME: Duration = Duration::from_millis(500);

const STAGGERED_DELAYS_MILLIS: [u64; 4] = [1, 2, 4, 8];

fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| tokio::runtime::Runtime::new().expect("failed to build tokio runtime"))
}

struct SleepingAdapter {
    source: SourceKind,
    delay: Duration,
    slug: &'static str,
}

impl SleepingAdapter {
    fn app(&self) -> App {
        App {
            id: TorideId::slugify(self.slug),
            name: self.slug.to_owned(),
            aliases: Vec::new(),
            summary: None,
            description: None,
            homepage: None,
            license: None,
            developer: None,
            binaries: Vec::new(),
            latest: None,
            platforms: Vec::new(),
            artifacts: Vec::new(),
            install: InstallMethod::Homebrew {
                cask: false,
                token: self.slug.to_owned(),
            },
            sources: vec![SourceRef {
                source: self.source,
                id: self.slug.to_owned(),
                repo: None,
                version: None,
                provisional: false,
            }],
            availability: Availability::Available,
        }
    }
}

#[async_trait::async_trait]
impl toride_registry::adapter::Adapter for SleepingAdapter {
    fn source(&self) -> SourceKind {
        self.source
    }

    async fn lookup(&self, _id: &SourceRef) -> Result<Option<App>> {
        tokio::time::sleep(self.delay).await;
        Ok(Some(self.app()))
    }

    async fn search(&self, _query: &str) -> Result<Vec<App>> {
        tokio::time::sleep(self.delay).await;
        Ok(vec![self.app()])
    }
}

fn adapters() -> Vec<std::sync::Arc<SleepingAdapter>> {
    STAGGERED_DELAYS_MILLIS
        .iter()
        .enumerate()
        .map(|(index, millis)| {
            std::sync::Arc::new(SleepingAdapter {
                source: match index % 4 {
                    0 => SourceKind::HomebrewCask,
                    1 => SourceKind::HomebrewFormula,
                    2 => SourceKind::Flathub,
                    _ => SourceKind::Distro,
                },
                delay: Duration::from_millis(*millis),
                slug: match index {
                    0 => "bench-alpha",
                    1 => "bench-beta",
                    2 => "bench-gamma",
                    _ => "bench-delta",
                },
            })
        })
        .collect()
}

fn dyn_adapters(
    adapters: &[std::sync::Arc<SleepingAdapter>],
) -> Vec<std::sync::Arc<dyn toride_registry::adapter::Adapter>> {
    adapters
        .iter()
        .map(|adapter| adapter.clone() as std::sync::Arc<dyn toride_registry::adapter::Adapter>)
        .collect()
}

fn oracle() {
    let rt = runtime();
    let adapters = adapters();
    let registry = Registry::new(dyn_adapters(&adapters));

    let outcome = rt
        .block_on(registry.search("bench"))
        .expect("fan-out answers");
    assert_eq!(outcome.apps.len(), 4, "one distinct row per adapter");
    assert!(
        outcome.failures.is_empty(),
        "healthy stubs never fail: {:?}",
        outcome.failures
    );
    assert_eq!(
        outcome
            .apps
            .iter()
            .map(|app| app.id.as_str())
            .collect::<Vec<_>>(),
        ["bench-alpha", "bench-beta", "bench-gamma", "bench-delta"],
        "registration order survives the merge"
    );

    let rows = rt
        .block_on(registry.resolve(&TorideId::slugify("bench-alpha")))
        .expect("resolve answers");
    assert_eq!(rows.len(), 4, "every adapter's lookup hit unions one row");
}

fn search_fanout(c: &mut Criterion) {
    oracle();

    let rt = runtime();
    let adapters = adapters();
    let registry = Registry::new(dyn_adapters(&adapters));

    let mut group = c.benchmark_group("search_fanout");
    group.sample_size(SAMPLE_SIZE);
    group.measurement_time(MEASUREMENT_TIME);
    group.warm_up_time(WARM_UP_TIME);

    group.bench_function("registry_search_4_adapters_staggered", |b| {
        b.iter(|| {
            let outcome = rt
                .block_on(registry.search(black_box("bench")))
                .expect("fan-out answers");
            black_box(outcome.apps.len())
        });
    });

    group.bench_function("registry_resolve_4_adapters_staggered", |b| {
        b.iter(|| {
            let rows = rt
                .block_on(registry.resolve(black_box(&TorideId::slugify("bench-alpha"))))
                .expect("resolve answers");
            black_box(rows.len())
        });
    });

    group.bench_function("adapters_joined_4_adapters_staggered", |b| {
        b.iter(|| {
            let joined = rt.block_on(async {
                tokio::join!(
                    adapters[0].search("bench"),
                    adapters[1].search("bench"),
                    adapters[2].search("bench"),
                    adapters[3].search("bench"),
                )
            });
            let total = joined.0.expect("a").len()
                + joined.1.expect("b").len()
                + joined.2.expect("c").len()
                + joined.3.expect("d").len();
            black_box(total)
        });
    });

    group.finish();
}

criterion_group!(benches, search_fanout);
criterion_main!(benches);
