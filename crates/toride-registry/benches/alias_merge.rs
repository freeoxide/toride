use std::hint::black_box;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use toride_registry::adapter::Registry;
use toride_registry::error::Result;
use toride_registry::model::{App, Availability, InstallMethod, SourceKind, SourceRef, TorideId};

const SIZES: [usize; 2] = [50, 200];

fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| tokio::runtime::Runtime::new().expect("failed to build tokio runtime"))
}

struct BucketAdapter {
    source: SourceKind,
    apps: Vec<App>,
}

#[async_trait::async_trait]
impl toride_registry::adapter::Adapter for BucketAdapter {
    fn source(&self) -> SourceKind {
        self.source
    }

    async fn lookup(&self, id: &SourceRef) -> Result<Option<App>> {
        Ok(self
            .apps
            .iter()
            .find(|app| app.id.as_str() == id.id)
            .cloned())
    }

    async fn search(&self, _query: &str) -> Result<Vec<App>> {
        Ok(self.apps.clone())
    }
}

fn bucket_row(index: usize, primary: SourceKind, extra: SourceKind) -> App {
    let name = format!("Bench App {index:03}");
    App {
        id: TorideId::slugify(&name),
        name,
        aliases: vec![format!("Bench Alias {index:03}")],
        summary: Some(format!("A synthetic bench row {index:03}")),
        description: None,
        homepage: Some(format!("https://bench.example/{index:03}")),
        license: None,
        developer: None,
        binaries: Vec::new(),
        latest: None,
        platforms: Vec::new(),
        artifacts: Vec::new(),
        install: match primary {
            SourceKind::HomebrewCask => InstallMethod::Homebrew {
                cask: true,
                token: format!("bench-app-{index:03}"),
            },
            _ => InstallMethod::Flatpak {
                app_id: format!("org.bench.App{index:03}"),
                remote: "flathub".to_owned(),
            },
        },
        sources: vec![
            SourceRef {
                source: primary,
                id: format!("bench-{index:03}"),
                repo: None,
                version: None,
                provisional: false,
            },
            SourceRef {
                source: extra,
                id: format!("bench-extra-{index:03}"),
                repo: None,
                version: None,
                provisional: false,
            },
        ],
        availability: Availability::Available,
    }
}

fn registry(size: usize) -> Registry {
    let left: Vec<App> = (0..size)
        .map(|index| bucket_row(index, SourceKind::HomebrewCask, SourceKind::HomebrewFormula))
        .collect();
    let right: Vec<App> = (0..size)
        .map(|index| bucket_row(index, SourceKind::Flathub, SourceKind::Distro))
        .collect();
    Registry::new(vec![
        Arc::new(BucketAdapter {
            source: SourceKind::HomebrewCask,
            apps: left,
        }) as Arc<dyn toride_registry::adapter::Adapter>,
        Arc::new(BucketAdapter {
            source: SourceKind::Flathub,
            apps: right,
        }) as Arc<dyn toride_registry::adapter::Adapter>,
    ])
}

fn oracle() {
    let rt = runtime();

    let small = registry(SIZES[0]);
    let outcome = rt
        .block_on(small.search("bench app"))
        .expect("merge answers");
    assert_eq!(
        outcome.apps.len(),
        SIZES[0],
        "each cross-bucket name pair merges into one row"
    );
    assert_eq!(
        outcome.apps[0].id.as_str(),
        "bench-app-000",
        "the registration-first bucket's id stays canonical"
    );
    assert_eq!(
        outcome.apps[0]
            .sources
            .iter()
            .map(|row| row.source)
            .collect::<Vec<_>>(),
        [
            SourceKind::HomebrewCask,
            SourceKind::HomebrewFormula,
            SourceKind::Flathub,
            SourceKind::Distro,
        ],
        "the absorbed row unions both buckets' source rows in bucket order"
    );
    assert_eq!(
        outcome.apps[0].homepage.as_deref(),
        Some("https://bench.example/000"),
        "identical homepages never conflict, so the pair joins"
    );

    let index = small.alias_index();
    assert_eq!(index.len(), SIZES[0], "every merged row is recorded");
}

fn alias_merge(c: &mut Criterion) {
    oracle();

    let rt = runtime();

    let mut group = c.benchmark_group("alias_merge");
    group.sample_size(100);
    group.measurement_time(Duration::from_secs(5));
    group.warm_up_time(Duration::from_secs(3));

    for size in SIZES {
        let registry = registry(size);
        group.bench_function(format!("merge_two_buckets_{size}_apps"), |b| {
            b.iter(|| {
                let outcome = rt
                    .block_on(registry.search(black_box("bench app")))
                    .expect("merge answers");
                black_box(outcome.apps.len())
            });
        });
    }

    group.finish();
}

criterion_group!(benches, alias_merge);
criterion_main!(benches);
