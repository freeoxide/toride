use std::hint::black_box;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use toride_apps::backends::flatpak::FlatpakBackend;
use toride_apps::backends::homebrew::HomebrewBackend;
use toride_apps::{AppInstallOptions, Apps, EnsureAppOutcome, command};
use toride_registry::adapter::Adapter;
use toride_registry::error::Result;
use toride_registry::model::{
    App, Availability, InstallMethod, SourceKind, SourceRef, TorideId,
};
use toride_runner::CommandOutput;
use toride_runner::fake::FakeRunner;

const SAMPLE_SIZE: usize = 30;
const MEASUREMENT_TIME: Duration = Duration::from_secs(2);
const WARM_UP_TIME: Duration = Duration::from_millis(500);

const BREW_APPS: usize = 10;
const FLATPAK_APPS: usize = 10;
const STATUS_BATCH_IDS: usize = 20;

const BREW_INSTALLS_PER_SWEEP: usize = BREW_APPS;
const BREW_INFO_LISTINGS_PER_SWEEP: usize = BREW_APPS;
const BREW_VERSION_PROBES_PER_SWEEP: usize = BREW_APPS * 2;
const FLATPAK_INSTALLS_PER_SWEEP: usize = FLATPAK_APPS;
const FLATPAK_USER_LISTINGS_PER_SWEEP: usize = FLATPAK_APPS * 2;
const FLATPAK_ALL_LISTINGS_PER_SWEEP: usize = FLATPAK_APPS;
const FLATPAK_REMOTE_PROBES_PER_SWEEP: usize = FLATPAK_APPS;
const STATUS_INFO_LISTINGS_PER_BATCH: usize = STATUS_BATCH_IDS;

const FLATPAK_USER_LIST_ARGS: [&str; 4] = [
    "list",
    "--user",
    "--app",
    "--columns=application,version,origin,installation",
];
const FLATPAK_ALL_LIST_ARGS: [&str; 3] = [
    "list",
    "--app",
    "--columns=application,version,origin,installation",
];

fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| tokio::runtime::Runtime::new().expect("failed to build tokio runtime"))
}

fn brew_token(index: usize) -> String {
    format!("bench-brew-{index:02}")
}

fn flatpak_app_id(index: usize) -> String {
    format!("org.bench.Flat{index:02}")
}

struct RegistryStub {
    source: SourceKind,
    brew: bool,
}

impl RegistryStub {
    fn app_for(&self, id: &str) -> Option<App> {
        if self.brew {
            let token = id.strip_prefix("bench-brew-")?;
            let _ = token.parse::<usize>();
            Some(App {
                id: TorideId::slugify(id),
                name: format!("Bench Brew {id}"),
                aliases: Vec::new(),
                summary: Some("A bench formula".to_owned()),
                description: None,
                homepage: Some(format!("https://bench.example/{id}")),
                license: None,
                developer: None,
                binaries: Vec::new(),
                latest: None,
                platforms: Vec::new(),
                artifacts: Vec::new(),
                install: InstallMethod::Homebrew {
                    cask: false,
                    token: id.to_owned(),
                },
                sources: vec![SourceRef {
                    source: self.source,
                    id: id.to_owned(),
                    repo: None,
                    version: None,
                    provisional: false,
                }],
                availability: Availability::Available,
            })
        } else {
            let suffix = id.strip_prefix("bench-flat-")?;
            let _ = suffix.parse::<usize>();
            let app_id = format!("org.bench.Flat{suffix}");
            Some(App {
                id: TorideId::slugify(id),
                name: format!("Bench Flatpak {id}"),
                aliases: Vec::new(),
                summary: Some("A bench flatpak".to_owned()),
                description: None,
                homepage: Some(format!("https://bench.example/{id}")),
                license: None,
                developer: None,
                binaries: Vec::new(),
                latest: None,
                platforms: Vec::new(),
                artifacts: Vec::new(),
                install: InstallMethod::Flatpak {
                    app_id,
                    remote: "flathub".to_owned(),
                },
                sources: vec![SourceRef {
                    source: self.source,
                    id: id.to_owned(),
                    repo: None,
                    version: None,
                    provisional: false,
                }],
                availability: Availability::Available,
            })
        }
    }
}

#[async_trait::async_trait]
impl Adapter for RegistryStub {
    fn source(&self) -> SourceKind {
        self.source
    }

    async fn lookup(&self, id: &SourceRef) -> Result<Option<App>> {
        Ok(self.app_for(&id.id))
    }

    async fn search(&self, _query: &str) -> Result<Vec<App>> {
        Ok(Vec::new())
    }
}

fn flatpak_listing_row(app_id: &str) -> String {
    format!("{app_id}\t1.2.3\tflathub\tuser\n")
}

fn sweep_rig(manifest: &std::path::Path) -> (FakeRunner, Apps) {
    let _ = std::fs::remove_file(manifest);
    let mut fake = FakeRunner::new().strict();

    for _ in 0..BREW_APPS {
        fake = fake.respond(
            command("brew", ["info", "--json=v2", "--installed"]),
            CommandOutput::from_stdout(r#"{"formulae":[],"casks":[]}"#),
        );
    }
    for index in 0..BREW_APPS {
        let token = brew_token(index);
        fake = fake.respond(
            command("brew", ["install", token.as_str()]),
            CommandOutput::from_stdout(""),
        );
        let probe = command("brew", ["list", "--formula", "--versions", token.as_str()]);
        fake = fake
            .respond(
                probe.clone(),
                CommandOutput::from_stdout(format!("{token} 1.2.3\n")),
            )
            .respond(probe, CommandOutput::from_stdout(format!("{token} 1.2.3\n")));
    }

    for _ in 0..FLATPAK_APPS {
        fake = fake.respond(
            command("flatpak", FLATPAK_ALL_LIST_ARGS),
            CommandOutput::from_stdout(""),
        );
    }
    for index in 0..FLATPAK_APPS {
        let app_id = flatpak_app_id(index);
        let listing = CommandOutput::from_stdout(flatpak_listing_row(&app_id));
        fake = fake
            .respond(
                command("flatpak", ["remotes", "--user", "--columns=name"]),
                CommandOutput::from_stdout("flathub\n"),
            )
            .respond(
                command(
                    "flatpak",
                    [
                        "install",
                        "--user",
                        "--or-update",
                        "--noninteractive",
                        "flathub",
                        format!("app/{app_id}/x86_64/stable").as_str(),
                    ],
                ),
                CommandOutput::from_stdout(""),
            )
            .respond(command("flatpak", FLATPAK_USER_LIST_ARGS), listing.clone())
            .respond(command("flatpak", FLATPAK_USER_LIST_ARGS), listing);
    }

    let runner = toride_apps::CommandRunner::new(Arc::new(fake.clone()));
    let apps = Apps::builder()
        .manifest_path(
            camino::Utf8Path::from_path(manifest).expect("temp path is valid UTF-8"),
        )
        .target(toride_apps::plan::Target::new(
            toride_registry::model::Os::Linux,
            toride_registry::model::Arch::X86_64,
        ))
        .homebrew(HomebrewBackend::new(runner.clone()))
        .flatpak(FlatpakBackend::new(runner.clone()))
        .adapter(Arc::new(RegistryStub {
            source: SourceKind::HomebrewFormula,
            brew: true,
        }))
        .adapter(Arc::new(RegistryStub {
            source: SourceKind::Flathub,
            brew: false,
        }))
        .build()
        .expect("facade builds");
    (fake, apps)
}

fn status_rig(manifest: &std::path::Path) -> (FakeRunner, Apps) {
    let _ = std::fs::remove_file(manifest);
    let fake = FakeRunner::new().push_response(CommandOutput::from_stdout(
        r#"{"formulae":[],"casks":[]}"#,
    ));
    let runner = toride_apps::CommandRunner::new(Arc::new(fake.clone()));
    let apps = Apps::builder()
        .manifest_path(
            camino::Utf8Path::from_path(manifest).expect("temp path is valid UTF-8"),
        )
        .target(toride_apps::plan::Target::new(
            toride_registry::model::Os::Linux,
            toride_registry::model::Arch::X86_64,
        ))
        .homebrew(HomebrewBackend::new(runner.clone()))
        .adapter(Arc::new(RegistryStub {
            source: SourceKind::HomebrewFormula,
            brew: true,
        }))
        .build()
        .expect("facade builds");
    (fake, apps)
}

fn count<'a>(fake: &FakeRunner, program: &str, args: &[&str]) -> usize {
    fake.calls()
        .iter()
        .filter(|spec| {
            spec.program == program
                && spec.args.iter().map(String::as_str).collect::<Vec<_>>() == args
        })
        .count()
}

fn oracle(dir: &std::path::Path) {
    let rt = runtime();
    let manifest = dir.join("apps-manifest.json");

    let (fake, mut apps) = sweep_rig(&manifest);
    let options = AppInstallOptions::new();
    for index in 0..BREW_APPS {
        let outcome = rt
            .block_on(apps.ensure_installed(&TorideId::slugify(&brew_token(index)), options.clone()))
            .unwrap_or_else(|error| panic!("brew install {index} failed: {error}"));
        assert!(
            matches!(outcome, EnsureAppOutcome::Installed { .. }),
            "{outcome:?}"
        );
    }
    for index in 0..FLATPAK_APPS {
        let outcome = rt
            .block_on(apps.ensure_installed(
                &TorideId::slugify(&format!("bench-flat-{index:02}")),
                options.clone(),
            ))
            .unwrap_or_else(|error| panic!("flatpak install {index} failed: {error}"));
        assert!(
            matches!(outcome, EnsureAppOutcome::Installed { .. }),
            "{outcome:?}"
        );
    }

    assert_eq!(
        fake.calls()
            .iter()
            .filter(|spec| spec.program == "brew" && spec.args.first().map(String::as_str) == Some("install"))
            .count(),
        BREW_INSTALLS_PER_SWEEP,
        "one brew install per app"
    );
    assert_eq!(
        count(&fake, "brew", &["info", "--json=v2", "--installed"]),
        BREW_INFO_LISTINGS_PER_SWEEP,
        "the foreign-presence probe rides the full brew info listing per app"
    );
    assert_eq!(
        fake.calls()
            .iter()
            .filter(|spec| spec.program == "brew"
                && spec.args.first().map(String::as_str) == Some("list")
                && spec.args.contains(&"--versions".to_owned()))
            .count(),
        BREW_VERSION_PROBES_PER_SWEEP,
        "two kind-scoped version probes per brew install: the backend's own plus the facade verify"
    );
    assert_eq!(
        fake.calls()
            .iter()
            .filter(|spec| spec.program == "flatpak"
                && spec.args.first().map(String::as_str) == Some("install"))
            .count(),
        FLATPAK_INSTALLS_PER_SWEEP,
        "one flatpak install per app"
    );
    assert_eq!(
        count(&fake, "flatpak", &FLATPAK_USER_LIST_ARGS),
        FLATPAK_USER_LISTINGS_PER_SWEEP,
        "two user-scoped listings per install: the backend's post-verify plus the facade verify"
    );
    assert_eq!(
        count(&fake, "flatpak", &FLATPAK_ALL_LIST_ARGS),
        FLATPAK_ALL_LISTINGS_PER_SWEEP,
        "the foreign-presence probe rides one unscoped listing per install"
    );
    assert_eq!(
        count(&fake, "flatpak", &["remotes", "--user", "--columns=name"]),
        FLATPAK_REMOTE_PROBES_PER_SWEEP,
        "the flathub remote probe re-runs per install"
    );
    assert_eq!(fake.calls().len(), 90, "total dispatches across the sweep");

    let (fake, apps) = status_rig(&manifest);
    for index in 0..STATUS_BATCH_IDS {
        let status = rt
            .block_on(apps.status(&TorideId::slugify(&brew_token(index % 10))))
            .unwrap_or_else(|error| panic!("status {index} failed: {error}"));
        black_box(&status);
    }
    assert_eq!(
        count(&fake, "brew", &["info", "--json=v2", "--installed"]),
        STATUS_INFO_LISTINGS_PER_BATCH,
        "one full brew info listing per unrecorded id: the batch's shared-listing target is 1"
    );
}

fn ensure_installed_bench(c: &mut Criterion) {
    let dir = tempfile::tempdir().expect("temp dir");
    oracle(dir.path());
    let manifest = dir.path().join("apps-manifest.json");

    let mut group = c.benchmark_group("ensure_installed");
    group.sample_size(SAMPLE_SIZE);
    group.measurement_time(MEASUREMENT_TIME);
    group.warm_up_time(WARM_UP_TIME);

    let rt = runtime();
    group.bench_function("brew_flow_10_apps", |b| {
        b.iter(|| {
            let (_fake, mut apps) = sweep_rig(&manifest);
            for index in 0..BREW_APPS {
                let outcome = rt
                    .block_on(apps.ensure_installed(
                        black_box(&TorideId::slugify(&brew_token(index))),
                        AppInstallOptions::new(),
                    ))
                    .expect("brew install succeeds");
                black_box(matches!(outcome, EnsureAppOutcome::Installed { .. }));
            }
        });
    });

    group.bench_function("flatpak_flow_10_apps", |b| {
        b.iter(|| {
            let (_fake, mut apps) = sweep_rig(&manifest);
            for index in 0..FLATPAK_APPS {
                let outcome = rt
                    .block_on(apps.ensure_installed(
                        black_box(&TorideId::slugify(&format!("bench-flat-{index:02}"))),
                        AppInstallOptions::new(),
                    ))
                    .expect("flatpak install succeeds");
                black_box(matches!(outcome, EnsureAppOutcome::Installed { .. }));
            }
        });
    });

    group.bench_function("status_batch_20_unrecorded_ids", |b| {
        b.iter(|| {
            let (_fake, apps) = status_rig(&manifest);
            for index in 0..STATUS_BATCH_IDS {
                let status = rt
                    .block_on(apps.status(black_box(&TorideId::slugify(&brew_token(index % 10)))))
                    .expect("status answers");
                black_box(&status);
            }
        });
    });

    group.finish();
}

criterion_group!(benches, ensure_installed_bench);
criterion_main!(benches);
