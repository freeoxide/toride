use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use ufw_kit::command::{CommandLog, CommandRunner, FakeRunner};
use ufw_kit::diff::diff_status_findings;
use ufw_kit::doctor::doctor;
use ufw_kit::spec::{CommandResult, CommandSpec, DoctorScope, ParsedRule};
use ufw_kit::status;
use ufw_kit::Ufw;

const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/benches/fixtures/status/");

const SAMPLE_SIZE: usize = 30;
const MEASUREMENT_TIME: Duration = Duration::from_secs(2);
const WARM_UP_TIME: Duration = Duration::from_millis(500);

const EXPECTED_STATUS_RULES: usize = 400;

const PROFILES: [&str; 6] = ["OpenSSH", "Nginx Full", "Apache", "Docker", "CUPS", "Samba"];

static ALLOCATED_BYTES: AtomicU64 = AtomicU64::new(0);
static FREED_BYTES: AtomicU64 = AtomicU64::new(0);

struct NetCountingAllocator;

unsafe impl GlobalAlloc for NetCountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATED_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATED_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATED_BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
        FREED_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        FREED_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: NetCountingAllocator = NetCountingAllocator;

fn net_allocated_bytes() -> u64 {
    ALLOCATED_BYTES.load(Ordering::Relaxed) - FREED_BYTES.load(Ordering::Relaxed)
}

#[derive(Clone)]
struct SharedFakeRunner {
    inner: Arc<FakeRunner>,
    calls: Arc<Mutex<Vec<CommandLog>>>,
}

impl SharedFakeRunner {
    fn wrap(inner: FakeRunner) -> Self {
        Self {
            inner: Arc::new(inner),
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn log(&self) -> Vec<CommandLog> {
        self.calls.lock().map(|log| log.clone()).unwrap_or_default()
    }

    fn ufw_calls_with(&self, args: &[&str]) -> usize {
        self.log()
            .iter()
            .filter(|entry| {
                entry.program == "ufw"
                    && entry.args.len() == args.len()
                    && entry.args.iter().zip(args).all(|(a, b)| a == b)
            })
            .count()
    }
}

impl CommandRunner for SharedFakeRunner {
    fn run(&self, spec: &CommandSpec) -> ufw_kit::Result<CommandResult> {
        if let Ok(mut calls) = self.calls.lock() {
            calls.push(CommandLog {
                program: spec.program.clone(),
                args: spec.args.clone(),
            });
        }
        self.inner.run(spec)
    }

    fn binary_exists(&self, name: &str) -> bool {
        self.inner.binary_exists(name)
    }
}

fn fixture(name: &str) -> String {
    let path = format!("{FIXTURE_DIR}{name}");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("bench fixture {path} should be committed and readable: {e}"))
}

fn doctor_responses(status_output: &str) -> FakeRunner {
    let app_list = format!(
        "Available applications:\n{}\n",
        PROFILES
            .iter()
            .map(|name| format!("  {name}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    let mut runner = FakeRunner::new()
        .respond_ok("ufw", &["--version"], "ufw 0.36.1")
        .respond_ok("ufw", &["status"], status_output)
        .respond_ok(
            "ufw",
            &["status", "verbose"],
            &format!(
                "{status_output}\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing)\n"
            ),
        )
        .respond_ok("ufw", &["app", "list"], &app_list);
    for (index, name) in PROFILES.iter().enumerate() {
        runner = runner.respond_ok(
            "ufw",
            &["app", "info", name],
            &format!(
                "Profile: {name}\nTitle: Bench profile {index}\nDescription: bench\nPort: {}/tcp\n",
                1000 + index
            ),
        );
    }
    runner
}

fn doctor_rig(status_output: &str) -> (SharedFakeRunner, Ufw) {
    let shared = SharedFakeRunner::wrap(doctor_responses(status_output));
    let ufw = Ufw::with_runner_and_status_ttl(shared.clone(), Duration::from_secs(600));
    (shared, ufw)
}

fn run_doctor_all(status_output: &str) -> usize {
    let (_shared, ufw) = doctor_rig(status_output);
    doctor(&ufw, DoctorScope::All)
        .expect("doctor(All) answers")
        .len()
}

fn status_rig() -> (SharedFakeRunner, Ufw) {
    let plain = fixture("status_plain_400.txt");
    let shared = SharedFakeRunner::wrap(FakeRunner::new().respond_ok("ufw", &["status"], &plain));
    let ufw = Ufw::with_runner_and_status_ttl(shared.clone(), Duration::from_secs(600));
    (shared, ufw)
}

fn doctor_repeat_oracle() {
    assert!(run_doctor_all("Status: active\n") > 0);
    drop(run_doctor_all("Status: active\n"));
    drop(run_doctor_all("Status: active\n"));

    let before_first = net_allocated_bytes();
    drop(run_doctor_all("Status: active\n"));
    let first_run_delta = net_allocated_bytes() - before_first;

    let before_second = net_allocated_bytes();
    drop(run_doctor_all("Status: active\n"));
    let second_run_delta = net_allocated_bytes() - before_second;

    assert_eq!(
        first_run_delta, second_run_delta,
        "each doctor(All) run retains the same constant byte count (the leaked finding ids)"
    );
    assert!(
        first_run_delta > 0,
        "pre-fix pin: every doctor(All) run leaks its formatted finding ids via Box::leak; \
         the intern-once fix drives this delta to ~0 (currently {first_run_delta} bytes per run)"
    );
}

fn app_info_spawn_oracle() {
    let (shared, ufw) = doctor_rig("Status: active\n");
    let findings = doctor(&ufw, DoctorScope::All).expect("doctor(All) answers");
    assert!(!findings.is_empty());
    for name in PROFILES {
        assert_eq!(
            shared.ufw_calls_with(&["app", "info", name]),
            2,
            "`ufw app info {name}` runs twice per profile today (validation loop plus port-conflict pass); the target is 1"
        );
    }
}

fn lockout_check_oracle() -> (SharedFakeRunner, Ufw) {
    let (shared, ufw) = status_rig();

    let first = ufw.check_ssh_lockout_structured(&[22]);
    assert_eq!(first.checked_ports, vec![22]);
    let second = ufw.check_ssh_lockout_structured(&[22]);
    assert_eq!(
        second.matching_rules.len(),
        first.matching_rules.len(),
        "the cached status serves a stable match set over the 400-rule fixture"
    );
    assert_eq!(
        shared.ufw_calls_with(&["status"]),
        1,
        "both lockout scans share one cached `ufw status` fetch"
    );
    (shared, ufw)
}

fn status_cache_oracle() -> (SharedFakeRunner, Ufw) {
    let (shared, ufw) = status_rig();
    for _ in 0..10 {
        assert_eq!(
            ufw.status().expect("status answers").rules.len(),
            EXPECTED_STATUS_RULES
        );
    }
    assert_eq!(
        shared.ufw_calls_with(&["status"]),
        1,
        "ten status reads within the TTL ride one cached fetch, deep-cloned per hit today"
    );
    (shared, ufw)
}

fn diff_status_oracle() -> (Vec<ParsedRule>, Vec<ParsedRule>) {
    let before = status::parse_status(&fixture("status_plain_400.txt"))
        .expect("plain fixture")
        .rules;
    let mut after = before.clone();
    for (index, rule) in after.iter_mut().enumerate().take(20) {
        rule.raw = format!("{index:05}/tcp                     ALLOW IN    203.0.113.{index}");
    }
    after.truncate(390);

    let findings = diff_status_findings(&before, &after);
    assert_eq!(
        findings.len(),
        46,
        "20 mutated rows (20 added) plus 26 removed raws: the fixture's 50-fold duplicate \
         `Nginx Full` row under-counts removals under raw-equality comparison"
    );
    (before, after)
}

fn doctor_and_status_bench(criterion: &mut Criterion) {
    doctor_repeat_oracle();
    app_info_spawn_oracle();
    lockout_check_oracle();
    status_cache_oracle();
    let (before_rules, after_rules) = diff_status_oracle();

    let mut group = criterion.benchmark_group("doctor_and_status");
    group.sample_size(SAMPLE_SIZE);
    group.measurement_time(MEASUREMENT_TIME);
    group.warm_up_time(WARM_UP_TIME);

    group.bench_function("doctor_repeat/all_run", |b| {
        b.iter(|| black_box(run_doctor_all(black_box("Status: active\n"))));
    });

    group.bench_function("lockout_check/scan_400_rules", |b| {
        let (_shared, ufw) = lockout_check_oracle();
        b.iter(|| {
            let result = ufw.check_ssh_lockout_structured(black_box(&[22]));
            black_box(result.matching_rules.len())
        });
    });

    group.bench_function("status_cache_hit/status_400_rules", |b| {
        let (_shared, ufw) = status_cache_oracle();
        b.iter(|| black_box(ufw.status().expect("status answers").rules.len()));
    });

    group.bench_function("diff_status_findings/400_rules", |b| {
        b.iter(|| {
            let findings = diff_status_findings(black_box(&before_rules), black_box(&after_rules));
            black_box(findings.len())
        });
    });

    group.finish();
}

criterion_group!(benches, doctor_and_status_bench);
criterion_main!(benches);
