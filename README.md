# toride

**toride** is a Rust library for collecting system status, hardware details, and live telemetry. It provides clean Rust APIs that other projects can embed.

It collects CPU, memory, disk, network, GPU, battery, sensor, and process metrics through a composable provider architecture. Snapshots are serializable (JSON/TOML), privacy-aware (three redaction modes), and filterable through presets that control which metrics are gathered.

## Library crates on crates.io

The app-management layer is released on crates.io as six versioned 0.x crates (the first 0.1.0 upload is performed by the Publish crates workflow, see [docs/publishing.md](docs/publishing.md)), so embedders can depend on it instead of vendoring:

| Crate | Role |
|-------|------|
| [`toride-runner`](https://crates.io/crates/toride-runner) | Command execution seam: sync `Runner`, policy knobs, `FakeRunner` |
| [`toride-fs`](https://crates.io/crates/toride-fs) | Atomic writes, fd locking, path expansion, permission audits |
| [`toride-registry`](https://crates.io/crates/toride-registry) | Homebrew/Flathub/AppStream/Repology normalized into one `App` model |
| [`toride-installer`](https://crates.io/crates/toride-installer) | Verified direct-download pipeline: resolve, download, digest, extract, install |
| [`toride-mise`](https://crates.io/crates/toride-mise) | Typed mise CLI integration |
| [`toride-apps`](https://crates.io/crates/toride-apps) | Execution facade: plan, run, and record installs across all backends |

The heavy features stay off the default sets so a minimal dependency graph is the default: `tokio-runner`, `stream`, and `serde` on toride-runner, `http` on toride-registry and toride-installer, `bootstrap` on toride-mise, and everything on toride-apps (`tokio`, `registry-http`, `direct`, `mise`).

```toml
[dependencies]
toride-apps = "0.2"
```

The release process (ordering, version lockstep, changelog conventions) is documented in [docs/publishing.md](docs/publishing.md).

## Quick Start

```rust
use toride::status::TorideStatus;

fn main() {
    let status = TorideStatus::collect();

    println!("Hostname: {}", status.system.hostname);
    println!("CPU:      {:.1}%", status.system.cpu_usage.unwrap_or(0.0));
    println!("Memory:   {} / {} bytes",
        status.system.memory.used_bytes,
        status.system.memory.total_bytes,
    );
    println!("Uptime:   {:?}s", status.system.uptime_secs);
}
```

Serialize to JSON for logging or transport:

```rust
use toride::status::TorideStatus;

let status = TorideStatus::collect();
let json = serde_json::to_string_pretty(&status).unwrap();
println!("{json}");
```

## Snapshot Example (SysProbe)

`SysProbe` is the primary entry point. Use its builder to select a preset and privacy mode:

```rust
use toride::status::{SysProbe, Preset, PrivacyMode};

let probe = SysProbe::builder()
    .preset(Preset::Diagnostics)
    .privacy(PrivacyMode::Diagnostics)
    .build();

let snapshot = probe.snapshot();

// Inspect the snapshot
println!("CPU: {:.1}%", snapshot.system.cpu_usage.unwrap_or(0.0));
println!("Memory: {:.1}%", snapshot.system.memory.percentage);
println!("Swap: {:?}", snapshot.system.swap);
println!("Processes: {}", snapshot.system.processes.total_count);

// Top 5 processes by CPU
for proc in snapshot.system.processes.top_by_cpu(5) {
    println!("  {}: {:.1}% CPU, {} bytes RSS", proc.name, proc.cpu_usage, proc.memory_bytes);
}
```

## Delta Example (Collector)

`Collector` tracks rate-based metrics (network throughput, disk I/O, process churn) by comparing consecutive snapshots:

```rust
use std::time::Duration;
use toride::status::Collector;

let mut collector = Collector::new(Duration::from_secs(1), Default::default());

// First collect: snapshot only, no delta.
let (status, delta) = collector.collect();
assert!(delta.is_none());

// Wait and collect again.
std::thread::sleep(Duration::from_secs(1));
let (status, delta) = collector.collect();

if let Some(d) = delta {
    println!("RX rate: {:.1} B/s", d.bytes_received_rate);
    println!("TX rate: {:.1} B/s", d.bytes_transmitted_rate);

    if let Some(cpu_delta) = d.cpu_usage_delta {
        println!("CPU delta: {cpu_delta:+.1}%");
    }

    if let Some(ref disk_io) = d.disk_io {
        println!("Disk read rate:  {:.1} B/s", disk_io.read_bytes_rate);
        println!("Disk write rate: {:.1} B/s", disk_io.written_bytes_rate);
    }

    if let Some(ref proc) = d.process {
        println!("Processes: {:+} new, {} exited", proc.new_count, proc.exited_count);
    }
}
```

Blocking variant that enforces the interval:

```rust
use std::time::Duration;
use toride::status::Collector;

let mut collector = Collector::new(Duration::from_secs(5), Default::default());
loop {
    let (status, delta) = collector.collect_after_interval();
    // Process status and delta...
}
```

## Task Manager Example (Top Processes)

```rust
use toride::status::{TorideStatus, Preset};

let status = TorideStatus::collect_with_preset(Preset::TaskManager);

println!("Total processes: {}", status.system.processes.total_count);

println!("\nTop 5 by CPU:");
for proc in status.system.processes.top_by_cpu(5) {
    println!("  {:>6} {:<20} CPU: {:5.1}%  Mem: {}",
        proc.pid, proc.name, proc.cpu_usage, proc.memory_bytes);
}

println!("\nTop 5 by Memory:");
for proc in status.system.processes.top_by_memory(5) {
    println!("  {:>6} {:<20} CPU: {:5.1}%  Mem: {}",
        proc.pid, proc.name, proc.cpu_usage, proc.memory_bytes);
}
```

## Supported Platforms

| Feature         | Linux                    | macOS            | Windows        |
|-----------------|:------------------------:|:----------------:|:--------------:|
| CPU usage       | Full                     | Full             | Full           |
| Per-core CPU    | Full                     | Full             | Full           |
| Memory          | Full + /proc/meminfo     | Full             | Full           |
| Swap            | Full                     | Full             | Full           |
| Disk usage      | Full + /proc/diskstats   | Full             | Full           |
| Network I/O     | Full + /sys/class/net    | Full             | Full           |
| Load average    | Full                     | Full             | Not available  |
| Uptime          | Full                     | Full             | Full           |
| Hostname        | Full                     | Full             | Full           |
| OS info         | Full + os-release        | Full             | Full           |
| Sensors         | sysinfo + /sys/class/hwmon | sysinfo (SMC)  | sysinfo        |
| Processes       | Full + /proc             | Full             | Full           |
| GPU             | nvidia-smi               | system_profiler  | Not available  |
| Battery         | starship-battery         | starship-battery | starship-battery |
| DMI/SMBIOS      | /sys/class/dmi/id        | static (Apple)   | Not read       |
| CPU topology    | /proc/cpuinfo + sysfs    | sysctl           | Not read       |
| Cgroups         | /proc/self/cgroup        | N/A              | N/A            |

**GPU support**: NVIDIA GPUs report through one `nvidia-smi` subprocess per collect (identity, VRAM, utilization, temperature, power draw, clocks, encoder/decoder utilization). NVML is not linked. macOS reports identity and VRAM via `system_profiler`. AMD and Intel GPUs are not probed, and Windows reports no GPUs.

## Feature Flags

`toride-status` has one optional feature: `battery` (on by default, backed by `starship-battery`). `sysinfo` is the only metrics backend; there are no backend-alternative features to enable.

## Privacy Model

The `PrivacyMode` enum controls which sensitive fields are redacted in status output. Redaction is applied before data is stored, not at display time.

| Mode          | Hostname    | MAC / Serial    | Command-line | Username    | UUID / Asset Tag |
|---------------|-------------|-----------------|--------------|-------------|------------------|
| `Safe`        | `[redacted]`| `[redacted]`    | `[redacted]` | `[redacted]`| `[redacted]`     |
| `Diagnostics` | shown       | `[redacted]`    | name only    | `[redacted]`| `[redacted]`     |
| `Full`        | shown       | shown           | shown        | shown       | shown            |

`Safe` is the default. Callers that forget to configure privacy still get safe output.

```rust
use toride::status::{TorideStatus, PrivacyMode};

// Safe mode: all sensitive fields redacted.
let status = TorideStatus::collect_with_privacy(PrivacyMode::Safe);
assert_eq!(status.system.hostname, "[redacted]");

// Diagnostics mode: hostnames visible, identifiers redacted.
let status = TorideStatus::collect_with_privacy(PrivacyMode::Diagnostics);

// Combine with presets.
let status = TorideStatus::collect_with_options(
    Preset::Minimal,
    PrivacyMode::Safe,
);
```

Redaction applies to: hostname, MAC addresses, serial numbers, UUIDs, asset tags, disk serial numbers, command-line arguments, and usernames.

## Provider Model

The provider system abstracts data sources behind composable traits. The default implementation (`SysinfoProvider`) uses the `sysinfo` crate. You can implement custom providers for mock testing or alternative data sources.

```
StatusProvider (composite, blanket-implemented)
  +-- CpuProvider        -> cpu_usage(), cpu_cores(), physical_cores()
  +-- MemoryProvider     -> memory(), swap()
  +-- DiskProvider       -> root_disk(), all_disks()
  +-- NetworkProvider    -> aggregate(), interfaces()
  +-- OsProvider         -> os_info(), hostname(), uptime(), boot_time(), load_average()
  +-- ProcessProvider    -> processes()
  +-- GpuProvider        -> gpus()
  +-- BatteryProvider    -> battery()
  +-- SensorProvider     -> sensors()
```

Implementing a custom provider:

```rust
use toride::status::provider::*;
use toride::status::system::*;
use toride::status::error::StatusResult;

struct MyMockProvider;

impl CpuProvider for MyMockProvider {
    fn cpu_usage(&mut self) -> StatusResult<Option<f64>> {
        Ok(Some(42.0))
    }
    fn cpu_cores(&mut self) -> StatusResult<Vec<CpuCore>> {
        Ok(vec![])
    }
    fn physical_cores(&self) -> StatusResult<Option<usize>> {
        Ok(Some(8))
    }
}

// Implement remaining traits...

// StatusProvider is automatically implemented via blanket impl:
fn use_provider<P: StatusProvider>(provider: &mut P) {
    let cpu = provider.cpu_usage().unwrap();
    let mem = provider.memory().unwrap();
}
```

The concrete `SysinfoProvider` struct wraps `sysinfo::System` and implements all nine traits:

```rust
use toride::status::system::SysinfoProvider;
use toride::status::provider::*;

let mut provider = SysinfoProvider::new();
let cpu = provider.cpu_usage().unwrap();
let mem = provider.memory().unwrap();
let procs = provider.processes().unwrap();
```

## Unsupported Metric Behavior

Metrics that are unavailable on the current platform return `None`, empty vectors, or zero-length snapshots. The library never fakes zeros for unavailable data.

| Return type        | Unavailable value          | Available zero case          |
|--------------------|----------------------------|------------------------------|
| `Option<f64>`      | `None`                     | `Some(0.0)`                  |
| `Option<T>`        | `None`                     | `Some(T { .. })`             |
| `Vec<T>`           | `vec![]` (empty)           | `vec![]` (empty, same)       |
| `String`           | `""` (empty)               | `"0"` (string "0")          |

Use `Capabilities::detect()` to check what is available before collecting:

```rust
use toride::status::Capabilities;

let caps = Capabilities::detect();

if caps.system.load_average {
    // Load average is available on this platform.
}

if caps.ssh.mux_check {
    // ssh binary found on PATH.
}
```

Capabilities are detected using compile-time `cfg!` macros for platform features and runtime binary detection for external tools (`ssh`, `ssh-add`).

## GPU Limitations

| Vendor  | Method          | Identity | VRAM | Utilization | Temperature | Power | Clock |
|---------|-----------------|:--------:|:----:|:-----------:|:-----------:|:-----:|:-----:|
| NVIDIA  | nvidia-smi      | Yes      | Yes  | Yes         | Yes         | Yes   | Yes   |
| Apple   | system_profiler | Yes      | Yes  | No          | No          | No    | No    |
| AMD     | not probed      | No       | No   | No          | No          | No    | No    |
| Intel   | not probed      | No       | No   | No          | No          | No    | No    |

NVIDIA data comes from one `nvidia-smi --query-gpu=...` subprocess per collect on Linux. NVML is not linked, and there is no GPU feature flag. Windows reports no GPUs.

Apple Silicon GPUs report through `system_profiler` but macOS does not expose utilization, temperature, or power draw through public APIs.

## Platform Notes

### Linux

Linux has the deepest support. Beyond sysinfo, the crate reads the kernel's own files directly:

- `/proc/meminfo` for cached and buffer memory.
- `/proc/diskstats` for disk I/O counters (base devices only; partitions are not double-counted).
- `/sys/class/net` for link state, speed, duplex, and drop counters.
- `/sys/class/hwmon` for fan and voltage readings.
- `/proc/cpuinfo` and `/sys/devices/system/cpu` for topology and frequencies.
- `/sys/class/dmi/id` for the hardware inventory.
- `/proc/<pid>` for per-process I/O, cwd, fd, and thread counts.

Virtualization detection (always available on Linux): Docker, LXC, containerd, Kubernetes, WSL, and VMs (VirtualBox, VMware, KVM, QEMU, Hyper-V).

### macOS

- Battery status via `starship-battery`.
- GPU detection via `system_profiler SPDisplaysDataType`.
- Load average available (Unix).

### Windows

- No load average (returns `None`).
- No GPU detection.
- Battery via `starship-battery`.
- Swap is reported as `None` when not configured.
- Sensors via sysinfo.

## Container and Cgroup Notes

The library detects container and virtualization environments automatically. Detection results are available in `status.system.virtualization`:

```rust
use toride::status::TorideStatus;

let status = TorideStatus::collect();
let virt = &status.system.virtualization;

if virt.in_docker {
    println!("Running in Docker");
}
if virt.in_kubernetes {
    println!("Running in Kubernetes");
}
if virt.in_wsl {
    println!("Running in WSL");
}

// Cgroup limit fields exist but stay None in this release.
if let Some(quota) = virt.cpu_quota {
    println!("CPU quota: {quota}");
}
if let Some(limit) = virt.memory_limit_bytes {
    println!("Memory limit: {limit} bytes");
}
```

| Detection        | Method                                      |
|------------------|---------------------------------------------|
| Docker           | `/.dockerenv` exists                        |
| LXC              | `/proc/self/cgroup` contains `/lxc/`        |
| containerd       | `/proc/self/cgroup` contains `containerd`   |
| Kubernetes       | `/proc/self/cgroup` contains `kubepods`     |
| WSL              | `/proc/version` contains `microsoft`/`wsl`  |
| VM               | `/sys/class/dmi/id/product_name` patterns   |
| Cgroup version   | `/proc/self/cgroup` prefix (`0::/` = v2)    |
| Podman           | Container runtime detection                 |

The limit fields on `VirtualizationSnapshot` (`cpu_quota`, `memory_limit_bytes`, `swap_limit`, `blkio_limit`, `cpuset_cpus`) stay `None` in this release. The crate reads only the detection flags above and the cgroup version from `/proc/self/cgroup`.

## Performance Notes

### Snapshot Timing

A single `SystemStatus::collect()` call includes a mandatory sleep (`sysinfo::MINIMUM_CPU_UPDATE_INTERVAL`, typically 200-300ms) to allow sysinfo to measure CPU usage accurately. The total time for a full snapshot is typically 250-400ms depending on the number of processes.

### Collector Interval

`Collector` compares consecutive snapshots to compute rates. The default interval is 1 second. Very short intervals (< 100ms) produce noisy rate data. Very long intervals (> 60s) smooth out bursts.

```rust
use std::time::Duration;
use toride::status::Collector;

// Good for dashboards: 2-second interval.
let collector = Collector::new(Duration::from_secs(2), Default::default());

// Good for logging: 30-second interval.
let collector = Collector::new(Duration::from_secs(30), Default::default());
```

### Process Scan Overhead

Process enumeration is the most expensive operation. On a system with 500+ processes, `processes()` can take 50-100ms. Use the `Minimal` preset to skip process scanning:

```rust
use toride::status::{TorideStatus, Preset};

// Fast: no process scan, no per-core CPU, no sensors.
let status = TorideStatus::collect_with_preset(Preset::Minimal);
```

### Preset Performance Characteristics

| Preset               | Relative Overhead | Includes Processes | Includes Sensors |
|----------------------|:-----------------:|:------------------:|:----------------:|
| Minimal              | Low               | No                 | No               |
| TaskManager          | Medium            | Yes                | Yes              |
| Diagnostics          | High              | Yes                | Yes              |
| ServerMonitoring     | Low-Medium        | No                 | No               |
| PrivacySafeBugReport | Low               | No                 | No               |
| HardwareInventory    | Medium            | No                 | Yes              |

## Doctor Module

`DoctorReport` runs health checks across system, daemon, and SSH subsystems. Each check reports Pass, Warn, or Fail status.

```rust
use toride::status::DoctorReport;

let report = DoctorReport::check();
println!("{report}");

if !report.all_passed() {
    let (pass, warn, fail) = report.summary();
    eprintln!("Issues: {warn} warnings, {fail} failures");
}
```

Check categories:
- **system**: hostname, CPU, memory, disks, OS info, GPU, battery, sensors, CPU sample quality, memory sanity, disk duplicates, virtualization, disk I/O
- **daemon**: PID liveness, stale socket detection
- **ssh**: ssh binary on PATH, ssh-add binary, config validation, agent status

Run checks against pre-collected snapshots:

```rust
use toride::status::{DoctorReport, TorideStatus};

let status = TorideStatus::collect();
let report = DoctorReport::check_with(&status.system, &status.daemon, &status.ssh);
```

## Presets

Presets control which metrics are collected, allowing you to optimize for your specific use case.

| Preset                  | Description                                              |
|-------------------------|----------------------------------------------------------|
| `Minimal`               | CPU, memory, disk, network totals, uptime                |
| `TaskManager`           | Per-core CPU, all disks, sensors, processes              |
| `Diagnostics`           | Everything (default)                                     |
| `ServerMonitoring`      | CPU, memory, network interfaces, swap, disk I/O          |
| `PrivacySafeBugReport`  | OS info, CPU family, memory total, GPU model only        |
| `HardwareInventory`     | Static info, all disks, sensors, GPU, battery            |

```rust
use toride::status::{TorideStatus, Preset};

// Lightweight monitoring
let status = TorideStatus::collect_with_preset(Preset::Minimal);

// Interactive task manager
let status = TorideStatus::collect_with_preset(Preset::TaskManager);

// Server monitoring with network interfaces
let status = TorideStatus::collect_with_preset(Preset::ServerMonitoring);

// Safe for sharing in bug reports
let status = TorideStatus::collect_with_preset(Preset::PrivacySafeBugReport);
```

## Capabilities

`Capabilities::detect()` reports which metrics are available on the current platform. Use it to build adaptive UIs or skip unavailable features.

```rust
use toride::status::Capabilities;

let caps = Capabilities::detect();

// System capabilities
if caps.system.load_average { /* show load average */ }
if caps.system.sensors { /* show temperature panel */ }
if caps.system.swap { /* show swap usage */ }

// Daemon capabilities
if caps.daemon.pid_check { /* check daemon liveness */ }
if caps.daemon.stale_socket_detection { /* check socket health */ }

// SSH capabilities (depends on ssh/ssh-add on PATH)
if caps.ssh.mux_check { /* check SSH mux master */ }
if caps.ssh.agent_check { /* check SSH agent */ }
```

## Type-Safe Units

The `units` module provides wrappers that prevent unit confusion:

```rust
use toride::status::units::{Bytes, Hertz, Celsius, Watts, Volts, Rpm};

let mem = Bytes(1073741824);
println!("{mem}");                  // "1.00 GiB"
println!("{}", mem.human_readable()); // "1.00 GiB"

let freq = Hertz(3200000000);
println!("{freq}");                 // "3.20 GHz"
println!("{:.0} MHz", freq.as_mhz()); // "3200 MHz"

let temp = Celsius(55.5);
println!("{temp}");                 // "55.5C"
println!("{:.1}F", temp.to_fahrenheit()); // "131.9F"

let power = Watts(75.5);
println!("{power}");                // "75.5 W"
```

## License

MIT: every published crate ships a `LICENSE-MIT`.
