use std::hint::black_box;
use std::path::Path;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use sysinfo::Components;
use tempfile::TempDir;
use toride_status::system::{SensorSnapshot, SensorStatus, StaticInfo, SystemStatus};
use toride_status::{Collector, Preset, TorideStatus};

const HWMON_CHIPS: usize = 6;

fn bench_status_collect_snapshot(c: &mut Criterion) {
    let mut group = c.benchmark_group("collect_cycle");
    group.sample_size(10);

    group.bench_function("status_collect_snapshot/minimal", |b| {
        b.iter(|| TorideStatus::collect_with_preset(black_box(Preset::Minimal)));
    });

    group.bench_function("status_collect_snapshot/diagnostics", |b| {
        b.iter(|| TorideStatus::collect_with_preset(black_box(Preset::Diagnostics)));
    });

    group.finish();
}

fn bench_collector_delta_cycle(c: &mut Criterion) {
    let mut group = c.benchmark_group("collect_cycle");
    group.sample_size(10);

    group.bench_function("collector_delta_cycle/second_collect", |b| {
        b.iter_batched(
            || {
                let mut collector = Collector::default_collector();
                let (_, first_delta) = collector.collect();
                assert!(first_delta.is_none());
                collector
            },
            |mut collector| {
                let (status, delta) = collector.collect();
                assert!(delta.is_some());
                black_box(status.system.hostname)
            },
            BatchSize::NumIterations(1),
        );
    });

    group.finish();
}

fn component_reading(c: &sysinfo::Component) -> SensorStatus {
    SensorStatus {
        label: c.label().to_string(),
        temperature: c.temperature().filter(|t| !t.is_nan()),
        fan_rpm: None,
        voltage: None,
        thermal_throttling: None,
    }
}

fn snapshot_from_readings(readings: &[SensorStatus]) -> SensorSnapshot {
    let cpu_temperature = readings.iter().find_map(|s| {
        if s.label.to_lowercase().contains("cpu") {
            s.temperature
        } else {
            None
        }
    });
    let gpu_temperature = readings.iter().find_map(|s| {
        if s.label.to_lowercase().contains("gpu") {
            s.temperature
        } else {
            None
        }
    });
    SensorSnapshot {
        readings: readings.to_vec(),
        cpu_temperature,
        gpu_temperature,
    }
}

fn sensor_pass_fused() -> (Vec<SensorStatus>, SensorSnapshot) {
    let components = Components::new_with_refreshed_list();
    let readings: Vec<SensorStatus> = components.iter().map(component_reading).collect();
    let snapshot = snapshot_from_readings(&readings);

    let mut sensors = readings;
    #[cfg(target_os = "linux")]
    {
        let root = Path::new("/sys/class/hwmon");
        sensors.extend(toride_status::system::read_hwmon_fans_at(root));
        sensors.extend(toride_status::system::read_hwmon_voltages_at(root));
    }

    (sensors, snapshot)
}

fn labels(sensors: &[SensorStatus]) -> Vec<&str> {
    sensors.iter().map(|s| s.label.as_str()).collect()
}

fn bench_sensor_read_once(c: &mut Criterion) {
    let mut group = c.benchmark_group("collect_cycle");

    let production_sensors = SystemStatus::read_sensors();
    let production_snapshot = SystemStatus::read_sensor_snapshot();
    let (fused_sensors, fused_snapshot) = sensor_pass_fused();
    assert_eq!(labels(&production_sensors), labels(&fused_sensors));
    assert_eq!(
        labels(&production_snapshot.readings),
        labels(&fused_snapshot.readings)
    );

    group.bench_function("sensor_read_once/two_passes_current", |b| {
        b.iter(|| {
            let sensors = SystemStatus::read_sensors();
            let snapshot = SystemStatus::read_sensor_snapshot();
            (black_box(sensors.len()), black_box(snapshot.readings.len()))
        });
    });

    group.bench_function("sensor_read_once/single_pass_fused", |b| {
        b.iter(|| {
            let (sensors, snapshot) = sensor_pass_fused();
            (black_box(sensors.len()), black_box(snapshot.readings.len()))
        });
    });

    group.finish();
}

fn hwmon_fixture_tree() -> TempDir {
    let dir = TempDir::new().expect("tempdir for hwmon tree");
    let chip_names = [
        "coretemp",
        "nvme-composite",
        "acpitz",
        "nouveau",
        "nct6775",
        "asusec",
    ];
    for (chip, name) in chip_names.iter().enumerate().take(HWMON_CHIPS) {
        let chip_dir = dir.path().join(format!("hwmon{chip}"));
        std::fs::create_dir_all(&chip_dir).expect("create hwmon chip dir");
        std::fs::write(chip_dir.join("name"), format!("{name}\n")).expect("write chip name");
        std::fs::write(chip_dir.join("fan1_input"), "1750\n").expect("write fan1");
        std::fs::write(chip_dir.join("fan2_input"), "1200\n").expect("write fan2");
        std::fs::write(chip_dir.join("in0_input"), "11840\n").expect("write in0");
        std::fs::write(chip_dir.join("in1_input"), "3300\n").expect("write in1");
    }
    dir
}

#[cfg(target_os = "linux")]
fn bench_hwmon_probe(c: &mut Criterion) {
    use toride_status::system::{read_hwmon_fans_at, read_hwmon_voltages_at};

    let mut group = c.benchmark_group("collect_cycle");

    let tree = hwmon_fixture_tree();
    let root = tree.path();

    let fans = read_hwmon_fans_at(root);
    let voltages = read_hwmon_voltages_at(root);
    assert_eq!(fans.len(), HWMON_CHIPS * 2, "two fans per chip");
    assert_eq!(voltages.len(), HWMON_CHIPS * 2, "two voltages per chip");

    group.bench_function("hwmon_probe/6_chips_fixed_name_opens", |b| {
        b.iter(|| {
            let fans = read_hwmon_fans_at(black_box(root));
            let voltages = read_hwmon_voltages_at(black_box(root));
            (black_box(fans.len()), black_box(voltages.len()))
        });
    });

    group.finish();
}

#[cfg(not(target_os = "linux"))]
fn bench_hwmon_probe(_c: &mut Criterion) {}

fn static_info_reads_x5(sys: &sysinfo::System) -> Vec<StaticInfo> {
    (0..5)
        .map(|_| SystemStatus::read_static_info(sys))
        .collect()
}

fn bench_static_info(c: &mut Criterion) {
    let mut group = c.benchmark_group("collect_cycle");

    let sys = sysinfo::System::new();
    let first = SystemStatus::read_static_info(&sys);
    assert_ne!(first.hostname, "");

    group.bench_function("static_info/read_once", |b| {
        b.iter(|| SystemStatus::read_static_info(black_box(&sys)));
    });

    group.bench_function("static_info/read_x5_serial", |b| {
        b.iter(|| black_box(static_info_reads_x5(black_box(&sys)).len()));
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_status_collect_snapshot,
    bench_collector_delta_cycle,
    bench_sensor_read_once,
    bench_hwmon_probe,
    bench_static_info,
);
criterion_main!(benches);
