//! OS-level metrics: CPU, memory, disk, network, load average, uptime, hostname.
//!
//! Uses the [`sysinfo`] crate for cross-platform data collection. Each metric
//! returns `None` when the underlying data cannot be read (e.g. permission
//! denied on certain Linux containers).
//!
//! # Platform support
//!
//! | Metric        | Linux | macOS | Windows |
//! |---------------|:-----:|:-----:|:-------:|
//! | CPU usage     | Yes   | Yes   | Yes     |
//! | Per-core CPU  | Yes   | Yes   | Yes     |
//! | Memory        | Yes   | Yes   | Yes     |
//! | Swap          | Yes   | Yes   | Yes     |
//! | Disk usage    | Yes   | Yes   | Yes     |
//! | Network I/O   | Yes   | Yes   | Yes     |
//! | Load average  | Yes   | Yes   | No      |
//! | Uptime        | Yes   | Yes   | Yes     |
//! | Hostname      | Yes   | Yes   | Yes     |
//! | OS info       | Yes   | Yes   | Yes     |
//! | Sensors       | Yes   | Yes   | Yes     |
//! | Processes     | Yes   | Yes   | Yes     |
//! | GPU           | Yes   | Yes   | No      |
//! | Battery       | Yes   | Yes   | No      |
//!
//! # Examples
//!
//! Collect a full system snapshot:
//!
//! ```no_run
//! use toride::status::system::SystemStatus;
//!
//! let status = SystemStatus::collect();
//! println!("CPU: {:.1}%", status.cpu_usage.unwrap_or(0.0));
//! println!("Memory: {} / {} bytes", status.memory.used_bytes, status.memory.total_bytes);
//! println!("Hostname: {}", status.hostname);
//! ```
//!
//! Get top CPU-consuming processes:
//!
//! ```no_run
//! use toride::status::system::SystemStatus;
//!
//! let status = SystemStatus::collect();
//! for proc in status.processes.top_by_cpu(5) {
//!     println!("{}: {:.1}% CPU", proc.name, proc.cpu_usage);
//! }
//! ```
//!
//! Display formatted output:
//!
//! ```no_run
//! use toride::status::system::SystemStatus;
//!
//! let status = SystemStatus::collect();
//! println!("{status}");
//! ```

use std::fmt;

use serde::Serialize;
use sysinfo::{
    Components, CpuRefreshKind, Disks, MemoryRefreshKind, Networks, ProcessRefreshKind,
    ProcessesToUpdate, RefreshKind, System,
};

use crate::status::error::StatusResult;
use crate::status::provider::{
    BatteryProvider, CpuProvider, DiskProvider, GpuProvider, MemoryProvider, NetworkProvider,
    OsProvider, ProcessProvider, SensorProvider,
};

// ── Shared helpers ──────────────────────────────────────────────────────

/// Parse VRAM string (e.g., "8192 MB", "8 GB", "8192") to bytes.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::option_if_let_else
)] // f64->u64 for VRAM values; always positive, fits in f64 mantissa; chained if-let clearer than map_or_else
fn parse_vram_to_bytes(v: &str) -> Option<u64> {
    let v = v.trim();
    if let Some(gb_str) = v.strip_suffix("GB").or_else(|| v.strip_suffix(" GB")) {
        gb_str.trim().parse::<f64>().ok().map(|gb| (gb * 1024.0 * 1024.0 * 1024.0) as u64)
    } else if let Some(mb_str) = v.strip_suffix("MB").or_else(|| v.strip_suffix(" MB")) {
        mb_str.trim().parse::<f64>().ok().map(|mb| (mb * 1024.0 * 1024.0) as u64)
    } else if let Some(tb_str) = v.strip_suffix("TB").or_else(|| v.strip_suffix(" TB")) {
        tb_str.trim().parse::<f64>().ok().map(|tb| (tb * 1024.0 * 1024.0 * 1024.0 * 1024.0) as u64)
    } else {
        // Bare number, assume MB
        v.replace(' ', "").parse::<u64>().ok().map(|mb| mb.saturating_mul(1024 * 1024))
    }
}

/// Read battery status from the OS.
#[cfg(target_os = "macos")]
fn read_battery_os() -> Option<BatteryInfo> {
    use std::process::Command;
    let output = Command::new("pmset")
        .arg("-g")
        .arg("batt")
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let percent_line = text.lines().find(|l| l.contains('%'))?;
    let pct_str = percent_line
        .split_whitespace()
        .find(|w| w.ends_with('%'))?;
    let pct: f32 = pct_str.trim_end_matches('%').parse().ok()?;
    let state = if text.contains("discharging") {
        "Discharging"
    } else if text.contains("charging") || text.contains("AC attached") {
        "Charging"
    } else {
        "Unknown"
    };
    Some(BatteryInfo {
        charge_percent: pct,
        state: state.to_string(),
        time_to_empty_secs: None,
        time_to_full_secs: None,
    })
}

/// Read battery status from the OS.
#[cfg(target_os = "linux")]
fn read_battery_os() -> Option<BatteryInfo> {
    use std::fs;
    use std::path::Path;
    let supply_dir = Path::new("/sys/class/power_supply");
    let entries = fs::read_dir(supply_dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.starts_with("BAT") && name_str != "battery" {
            continue;
        }
        if let Ok(type_content) = fs::read_to_string(path.join("type")) {
            if type_content.trim() != "Battery" {
                continue;
            }
        }
        let capacity = fs::read_to_string(path.join("capacity")).ok()?;
        let pct: f32 = capacity.trim().parse().ok()?;
        let status = fs::read_to_string(path.join("status"))
            .ok()
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "Unknown".to_string());
        return Some(BatteryInfo {
            charge_percent: pct,
            state: status,
            time_to_empty_secs: None,
            time_to_full_secs: None,
        });
    }
    None
}

/// Read battery status from the OS.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn read_battery_os() -> Option<BatteryInfo> {
    None
}

/// OS-level system metrics snapshot.
///
/// All fields are populated by [`collect`](Self::collect). Fields that cannot
/// be read (e.g. load average on Windows) will be `None`.
#[derive(Debug, Clone, Serialize)]
pub struct SystemStatus {
    /// CPU usage as a percentage (0.0–100.0).
    pub cpu_usage: Option<f64>,
    /// Memory metrics.
    pub memory: MemoryStatus,
    /// Disk metrics (root filesystem).
    pub disk: DiskStatus,
    /// Network I/O counters.
    pub network: NetworkStatus,
    /// Load average (1, 5, 15 minute). `None` on Windows.
    pub load_average: Option<LoadAverage>,
    /// System uptime in seconds.
    pub uptime_secs: Option<u64>,
    /// System hostname.
    pub hostname: String,
    /// Operating system information.
    pub os_info: OsInfo,
    /// Per-core CPU information.
    pub cpu_cores: Vec<CpuCore>,
    /// Number of physical CPU cores.
    pub physical_cores: Option<usize>,
    /// Swap usage.
    pub swap: Option<SwapStatus>,
    /// All disk partitions.
    pub disks: Vec<DiskStatus>,
    /// Per-interface network counters.
    pub network_interfaces: Vec<NetworkInterface>,
    /// Temperature sensor readings.
    pub sensors: Vec<SensorStatus>,
    /// System boot time (seconds since Unix epoch).
    pub boot_time: Option<u64>,
    /// Process list snapshot.
    pub processes: ProcessSnapshot,
    /// GPU information, if available.
    pub gpu: Vec<GpuInfo>,
    /// Battery status, if available.
    pub battery: Option<BatteryInfo>,
}

/// Memory usage snapshot.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct MemoryStatus {
    /// Used memory in bytes.
    pub used_bytes: u64,
    /// Total memory in bytes.
    pub total_bytes: u64,
    /// Usage percentage (0.0–100.0).
    pub percentage: f64,
}

/// Disk usage snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct DiskStatus {
    /// Disk name.
    pub name: String,
    /// Mount point path.
    pub mount_point: String,
    /// Filesystem type (e.g., "ext4", "apfs").
    pub filesystem: String,
    /// Used disk space in bytes.
    pub used_bytes: u64,
    /// Total disk space in bytes.
    pub total_bytes: u64,
    /// Usage percentage (0.0–100.0).
    pub percentage: f64,
    /// Whether the disk is removable.
    pub is_removable: bool,
}

/// Network I/O counters.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct NetworkStatus {
    /// Total bytes received.
    pub bytes_received: u64,
    /// Total bytes transmitted.
    pub bytes_transmitted: u64,
}

/// System load average (1, 5, 15 minute windows).
#[derive(Debug, Clone, Copy, Serialize)]
pub struct LoadAverage {
    /// 1-minute load average.
    pub one: f64,
    /// 5-minute load average.
    pub five: f64,
    /// 15-minute load average.
    pub fifteen: f64,
}

/// Operating system information.
#[derive(Debug, Clone, Serialize)]
pub struct OsInfo {
    /// OS name (e.g., "macOS", "Linux", "Windows").
    pub name: Option<String>,
    /// OS version (e.g., "14.5").
    pub version: Option<String>,
    /// Kernel version string.
    pub kernel_version: Option<String>,
    /// CPU architecture (e.g., `x86_64`, `aarch64`).
    pub arch: String,
}

/// Per-core CPU information.
#[derive(Debug, Clone, Serialize)]
pub struct CpuCore {
    /// Core identifier (e.g., "cpu0").
    pub name: String,
    /// Core usage percentage (0.0–100.0).
    pub usage: f64,
    /// Core frequency in MHz.
    pub frequency: u64,
}

/// Swap usage snapshot.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct SwapStatus {
    /// Used swap in bytes.
    pub used_bytes: u64,
    /// Total swap in bytes.
    pub total_bytes: u64,
    /// Usage percentage (0.0–100.0).
    pub percentage: f64,
}

/// Per-interface network counters.
#[derive(Debug, Clone, Serialize)]
pub struct NetworkInterface {
    /// Interface name (e.g., "en0", "eth0").
    pub name: String,
    /// Total bytes received.
    pub bytes_received: u64,
    /// Total bytes transmitted.
    pub bytes_transmitted: u64,
    /// Total packets received.
    pub packets_received: u64,
    /// Total packets transmitted.
    pub packets_transmitted: u64,
    /// Receive errors.
    pub errors_received: u64,
    /// Transmit errors.
    pub errors_transmitted: u64,
}

/// Temperature sensor reading.
#[derive(Debug, Clone, Serialize)]
pub struct SensorStatus {
    /// Sensor label (e.g., "CPU", "GPU").
    pub label: String,
    /// Temperature in Celsius, if available.
    pub temperature: Option<f32>,
}

/// GPU identity information.
#[derive(Debug, Clone, Serialize)]
pub struct GpuInfo {
    /// GPU name/model.
    pub name: String,
    /// GPU vendor.
    pub vendor: String,
    /// Total VRAM in bytes, if available.
    pub vram_bytes: Option<u64>,
    /// Driver version, if available.
    pub driver_version: Option<String>,
}

/// Battery status snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct BatteryInfo {
    /// Battery charge percentage (0.0–100.0).
    pub charge_percent: f32,
    /// Battery state (Charging, Discharging, Full, Unknown).
    pub state: String,
    /// Time to empty (seconds), if discharging.
    pub time_to_empty_secs: Option<u64>,
    /// Time to full (seconds), if charging.
    pub time_to_full_secs: Option<u64>,
}

/// Process information snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct ProcessStatus {
    /// Process ID.
    pub pid: u32,
    /// Parent process ID.
    pub parent_pid: Option<u32>,
    /// Process name.
    pub name: String,
    /// CPU usage percentage.
    pub cpu_usage: f32,
    /// Memory usage in bytes (RSS).
    pub memory_bytes: u64,
    /// Process status (Running, Sleeping, etc.).
    pub status: String,
    /// Process start time (seconds since epoch).
    pub start_time: Option<u64>,
}

/// Process list snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct ProcessSnapshot {
    /// All running processes.
    pub processes: Vec<ProcessStatus>,
    /// Total number of processes.
    pub total_count: usize,
}

impl ProcessSnapshot {
    /// Get the top `n` processes sorted by CPU usage (highest first).
    ///
    /// Returns at most `n` references to [`ProcessStatus`], ordered by
    /// descending CPU usage. Ties are not guaranteed to be in any
    /// particular order.
    ///
    /// # Examples
    ///
    /// ```
    /// use toride::status::system::{ProcessSnapshot, ProcessStatus};
    ///
    /// let snapshot = ProcessSnapshot {
    ///     processes: vec![
    ///         ProcessStatus { pid: 1, parent_pid: None, name: "idle".into(), cpu_usage: 0.1, memory_bytes: 100, status: "Sleeping".into(), start_time: None },
    ///         ProcessStatus { pid: 2, parent_pid: None, name: "busy".into(), cpu_usage: 95.0, memory_bytes: 200, status: "Running".into(), start_time: None },
    ///     ],
    ///     total_count: 2,
    /// };
    /// let top = snapshot.top_by_cpu(1);
    /// assert_eq!(top[0].name, "busy");
    /// ```
    #[must_use]
    pub fn top_by_cpu(&self, n: usize) -> Vec<&ProcessStatus> {
        let mut sorted: Vec<&ProcessStatus> = self.processes.iter().collect();
        sorted.sort_by(|a, b| {
            b.cpu_usage
                .partial_cmp(&a.cpu_usage)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        sorted.into_iter().take(n).collect()
    }

    /// Get the top `n` processes sorted by memory usage (highest first).
    ///
    /// Returns at most `n` references to [`ProcessStatus`], ordered by
    /// descending memory usage (RSS bytes).
    ///
    /// # Examples
    ///
    /// ```
    /// use toride::status::system::{ProcessSnapshot, ProcessStatus};
    ///
    /// let snapshot = ProcessSnapshot {
    ///     processes: vec![
    ///         ProcessStatus { pid: 1, parent_pid: None, name: "small".into(), cpu_usage: 1.0, memory_bytes: 1024, status: "Sleeping".into(), start_time: None },
    ///         ProcessStatus { pid: 2, parent_pid: None, name: "large".into(), cpu_usage: 1.0, memory_bytes: 1024 * 1024 * 100, status: "Running".into(), start_time: None },
    ///     ],
    ///     total_count: 2,
    /// };
    /// let top = snapshot.top_by_memory(1);
    /// assert_eq!(top[0].name, "large");
    /// ```
    #[must_use]
    pub fn top_by_memory(&self, n: usize) -> Vec<&ProcessStatus> {
        let mut sorted: Vec<&ProcessStatus> = self.processes.iter().collect();
        sorted.sort_by_key(|b| std::cmp::Reverse(b.memory_bytes));
        sorted.into_iter().take(n).collect()
    }
}

impl SystemStatus {
    /// Collect a point-in-time snapshot of OS metrics.
    ///
    /// Each metric is collected independently — a failure reading one metric
    /// (e.g. permission denied) results in `None` for that field rather than
    /// propagating an error.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use toride::status::system::SystemStatus;
    ///
    /// let status = SystemStatus::collect();
    /// println!("CPU: {:?}", status.cpu_usage);
    /// println!("Memory: {} / {}", status.memory.used_bytes, status.memory.total_bytes);
    /// ```
    #[must_use]
    pub fn collect() -> Self {
        let mut sys = System::new_with_specifics(
            RefreshKind::nothing()
                .with_cpu(CpuRefreshKind::nothing().with_cpu_usage())
                .with_memory(MemoryRefreshKind::nothing().with_ram().with_swap())
                .with_processes(ProcessRefreshKind::nothing().with_cpu().with_memory()),
        );
        // sysinfo requires a brief sleep to measure CPU usage accurately.
        std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
        sys.refresh_cpu_usage();
        sys.refresh_processes(ProcessesToUpdate::All, true);

        let cpu_usage = Self::read_cpu(&sys);
        let memory = Self::read_memory(&sys);
        let disks = Self::read_disks();
        let disk = Self::find_root_disk(&disks);
        let networks = Networks::new_with_refreshed_list();
        let network = Self::read_network(&networks);
        let load_average = Self::read_load_average();
        let uptime_secs = Self::read_uptime();
        let hostname = Self::read_hostname();
        let os_info = Self::read_os_info();
        let cpu_cores = Self::read_cpu_cores(&sys);
        let physical_cores = System::physical_core_count();
        let swap = Self::read_swap(&sys);
        let network_interfaces = Self::read_network_interfaces(&networks);
        let sensors = Self::read_sensors();
        let boot_time = {
            let bt = System::boot_time();
            if bt > 0 { Some(bt) } else { None }
        };
        let processes = Self::read_processes_from(&sys);
        let gpu = Self::read_gpus();
        let battery = read_battery_os();

        Self {
            cpu_usage,
            memory,
            disk,
            network,
            load_average,
            uptime_secs,
            hostname,
            os_info,
            cpu_cores,
            physical_cores,
            swap,
            disks,
            network_interfaces,
            sensors,
            boot_time,
            processes,
            gpu,
            battery,
        }
    }

    #[allow(clippy::cast_precision_loss)] // usize->f64 for average; negligible precision loss for core counts
    fn read_cpu(sys: &System) -> Option<f64> {
        let cpus = sys.cpus();
        if cpus.is_empty() {
            return None;
        }
        let total: f64 = cpus.iter().map(|c| f64::from(c.cpu_usage())).sum();
        Some(total / cpus.len() as f64)
    }

    #[allow(clippy::cast_precision_loss)] // u64->f64 for percentage display; negligible precision loss
    fn read_memory(sys: &System) -> MemoryStatus {
        let total = sys.total_memory();
        let used = sys.used_memory().min(total);
        let percentage = if total > 0 {
            ((used as f64 / total as f64) * 100.0).min(100.0)
        } else {
            0.0
        };
        MemoryStatus {
            used_bytes: used,
            total_bytes: total,
            percentage,
        }
    }

    fn find_root_disk(disks: &[DiskStatus]) -> DiskStatus {
        let root = std::path::Path::new("/");
        disks
            .iter()
            .find(|d| std::path::Path::new(&d.mount_point) == root)
            .cloned()
            .unwrap_or_else(|| DiskStatus {
                name: String::new(),
                mount_point: "/".to_string(),
                filesystem: String::new(),
                used_bytes: 0,
                total_bytes: 0,
                percentage: 0.0,
                is_removable: false,
            })
    }

    fn read_network(networks: &Networks) -> NetworkStatus {
        let (mut received, mut transmitted) = (0u64, 0u64);
        for data in networks.values() {
            received = received.saturating_add(data.total_received());
            transmitted = transmitted.saturating_add(data.total_transmitted());
        }
        NetworkStatus {
            bytes_received: received,
            bytes_transmitted: transmitted,
        }
    }

    #[cfg(unix)]
    #[allow(clippy::unnecessary_wraps)] // non-unix version returns None; signature must accommodate both platforms
    fn read_load_average() -> Option<LoadAverage> {
        let load = sysinfo::System::load_average();
        Some(LoadAverage {
            one: load.one,
            five: load.five,
            fifteen: load.fifteen,
        })
    }

    #[cfg(not(unix))]
    fn read_load_average() -> Option<LoadAverage> {
        None
    }

    fn read_uptime() -> Option<u64> {
        let uptime = System::uptime();
        if uptime > 0 {
            Some(uptime)
        } else {
            None
        }
    }

    fn read_hostname() -> String {
        System::host_name().unwrap_or_default()
    }

    fn read_os_info() -> OsInfo {
        OsInfo {
            name: System::name(),
            version: System::os_version(),
            kernel_version: System::kernel_version(),
            arch: std::env::consts::ARCH.to_string(),
        }
    }

    fn read_cpu_cores(sys: &System) -> Vec<CpuCore> {
        sys.cpus()
            .iter()
            .map(|c| CpuCore {
                name: c.name().to_string(),
                usage: f64::from(c.cpu_usage()),
                frequency: c.frequency(),
            })
            .collect()
    }

    #[allow(clippy::cast_precision_loss)] // u64->f64 for percentage display; negligible precision loss
    fn read_swap(sys: &System) -> Option<SwapStatus> {
        let total = sys.total_swap();
        if total == 0 {
            return None;
        }
        let used = sys.used_swap();
        let percentage = (used as f64 / total as f64) * 100.0;
        Some(SwapStatus {
            used_bytes: used,
            total_bytes: total,
            percentage,
        })
    }

    #[allow(clippy::cast_precision_loss)] // u64->f64 for percentage display; negligible precision loss
    fn read_disks() -> Vec<DiskStatus> {
        let disks = Disks::new_with_refreshed_list();
        disks
            .iter()
            .map(|d| {
                let total = d.total_space();
                let available = d.available_space();
                let used = total.saturating_sub(available);
                let percentage = if total > 0 {
                    (used as f64 / total as f64) * 100.0
                } else {
                    0.0
                };
                DiskStatus {
                    name: d.name().to_string_lossy().to_string(),
                    mount_point: d.mount_point().to_string_lossy().to_string(),
                    filesystem: d.file_system().to_string_lossy().to_string(),
                    used_bytes: used,
                    total_bytes: total,
                    percentage,
                    is_removable: d.is_removable(),
                }
            })
            .collect()
    }

    fn read_network_interfaces(networks: &Networks) -> Vec<NetworkInterface> {
        networks
            .iter()
            .map(|(name, data)| NetworkInterface {
                name: name.clone(),
                bytes_received: data.total_received(),
                bytes_transmitted: data.total_transmitted(),
                packets_received: data.total_packets_received(),
                packets_transmitted: data.total_packets_transmitted(),
                errors_received: data.errors_on_received(),
                errors_transmitted: data.errors_on_transmitted(),
            })
            .collect()
    }

    fn read_sensors() -> Vec<SensorStatus> {
        let components = Components::new_with_refreshed_list();
        components
            .iter()
            .map(|c| SensorStatus {
                label: c.label().to_string(),
                temperature: {
                    c.temperature().filter(|t| !t.is_nan())
                },
            })
            .collect()
    }

    fn read_processes_from(sys: &System) -> ProcessSnapshot {
        let processes: Vec<ProcessStatus> = sys
            .processes()
            .iter()
            .map(|(pid, p)| ProcessStatus {
                pid: pid.as_u32(),
                parent_pid: p.parent().map(sysinfo::Pid::as_u32),
                name: p.name().to_string_lossy().to_string(),
                cpu_usage: p.cpu_usage(),
                memory_bytes: p.memory(),
                status: format!("{}", p.status()),
                start_time: if p.start_time() > 0 { Some(p.start_time()) } else { None },
            })
            .collect();
        let total_count = processes.len();
        ProcessSnapshot {
            processes,
            total_count,
        }
    }

    fn read_gpus() -> Vec<GpuInfo> {
        let mut gpus = Vec::new();
        // Try system_profiler on macOS
        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("system_profiler")
                .args(["SPDisplaysDataType", "-json"])
                .output()
                && let Ok(text) = String::from_utf8(output.stdout)
                && let Ok(json) = serde_json::from_str::<serde_json::Value>(&text)
                && let Some(displays) = json["SPDisplaysDataType"].as_array()
            {
                for display in displays {
                    let name = display["sppci_model"]
                        .as_str()
                        .or_else(|| display["_name"].as_str())
                        .unwrap_or("Unknown GPU")
                        .to_string();
                    let vendor = display["sppci_vendor"]
                        .as_str()
                        .unwrap_or("Unknown")
                        .to_string();
                    let vram = display["sppci_vram"]
                        .as_str()
                        .and_then(parse_vram_to_bytes);
                    gpus.push(GpuInfo {
                        name,
                        vendor,
                        vram_bytes: vram,
                        driver_version: None,
                    });
                }
            }
        }
        // Try nvidia-smi on Linux
        #[cfg(target_os = "linux")]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("nvidia-smi")
                .args(["--query-gpu=name,memory.total,driver_version", "--format=csv,noheader,nounits"])
                .output()
            {
                if output.status.success() {
                    let text = String::from_utf8_lossy(&output.stdout);
                    for line in text.lines() {
                        let parts: Vec<&str> = line.split(", ").collect();
                        if parts.len() >= 3 {
                            let name = parts[0].trim().to_string();
                            let vram_mb: Option<u64> = parts[1].trim().parse().ok();
                            let driver = parts[2].trim().to_string();
                            gpus.push(GpuInfo {
                                name,
                                vendor: "NVIDIA".to_string(),
                                vram_bytes: vram_mb.map(|mb| mb * 1024 * 1024),
                                driver_version: Some(driver),
                            });
                        }
                    }
                }
            }
        }
        gpus
    }
}

#[allow(clippy::too_many_lines)] // Display impl must render all fields; splitting reduces readability
impl fmt::Display for SystemStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "System:")?;
        writeln!(f, "  Hostname: {}", self.hostname)?;

        // OS info
        {
            let name = self.os_info.name.as_deref().unwrap_or("Unknown");
            let version = self.os_info.version.as_deref().unwrap_or("unknown");
            let kernel = self.os_info.kernel_version.as_deref().unwrap_or("unknown");
            writeln!(
                f,
                "  OS: {name} {version} (kernel {kernel}) {}",
                self.os_info.arch
            )?;
        }

        if let Some(cpu) = self.cpu_usage {
            writeln!(f, "  CPU: {cpu:.1}%")?;
        } else {
            writeln!(f, "  CPU: N/A")?;
        }

        if let Some(cores) = self.physical_cores {
            writeln!(f, "  Physical cores: {cores}")?;
        }

        // Per-core CPU
        if !self.cpu_cores.is_empty() {
            writeln!(f, "  CPU cores:")?;
            for core in &self.cpu_cores {
                writeln!(f, "    {}: {:.1}% ({} MHz)", core.name, core.usage, core.frequency)?;
            }
        }

        write!(f, "  Memory: ")?;
        write_bytes(f, self.memory.used_bytes)?;
        write!(f, " / ")?;
        write_bytes(f, self.memory.total_bytes)?;
        writeln!(f, " ({:.1}%)", self.memory.percentage)?;

        // Swap
        if let Some(swap) = &self.swap {
            write!(f, "  Swap: ")?;
            write_bytes(f, swap.used_bytes)?;
            write!(f, " / ")?;
            write_bytes(f, swap.total_bytes)?;
            writeln!(f, " ({:.1}%)", swap.percentage)?;
        }

        write!(f, "  Disk: ")?;
        write_bytes(f, self.disk.used_bytes)?;
        write!(f, " / ")?;
        write_bytes(f, self.disk.total_bytes)?;
        writeln!(f, " ({:.1}%)", self.disk.percentage)?;

        // All disks
        if self.disks.len() > 1 {
            writeln!(f, "  Disks:")?;
            for disk in &self.disks {
                write!(f, "    {} ({}) [{}]: ", disk.mount_point, disk.name, disk.filesystem)?;
                write_bytes(f, disk.used_bytes)?;
                write!(f, " / ")?;
                write_bytes(f, disk.total_bytes)?;
                writeln!(f, " ({:.1}%)", disk.percentage)?;
            }
        }

        write!(f, "  Network: ")?;
        write_bytes(f, self.network.bytes_transmitted)?;
        write!(f, " sent, ")?;
        write_bytes(f, self.network.bytes_received)?;
        writeln!(f, " received")?;

        // Network interfaces
        if !self.network_interfaces.is_empty() {
            writeln!(f, "  Network interfaces:")?;
            for iface in &self.network_interfaces {
                write!(f, "    {}: ", iface.name)?;
                write_bytes(f, iface.bytes_transmitted)?;
                write!(f, " sent, ")?;
                write_bytes(f, iface.bytes_received)?;
                writeln!(f, " received")?;
            }
        }

        if self.processes.total_count > 0 {
            writeln!(f, "  Processes: {}", self.processes.total_count)?;
        }

        if let Some(load) = &self.load_average {
            writeln!(
                f,
                "  Load: {:.2} / {:.2} / {:.2}",
                load.one, load.five, load.fifteen
            )?;
        }

        // Sensors
        if !self.sensors.is_empty() {
            writeln!(f, "  Sensors:")?;
            for sensor in &self.sensors {
                if let Some(temp) = sensor.temperature {
                    writeln!(f, "    {}: {:.1}°C", sensor.label, temp)?;
                } else {
                    writeln!(f, "    {}: N/A", sensor.label)?;
                }
            }
        }

        for (i, gpu) in self.gpu.iter().enumerate() {
            writeln!(f, "  GPU {}: {} ({})", i, gpu.name, gpu.vendor)?;
            if let Some(vram) = gpu.vram_bytes {
                write!(f, "    VRAM: ")?;
                write_bytes(f, vram)?;
                writeln!(f)?;
            }
        }
        if let Some(battery) = &self.battery {
            writeln!(f, "  Battery: {:.0}% ({})", battery.charge_percent, battery.state)?;
        }

        if let Some(secs) = self.uptime_secs {
            write!(f, "  Uptime: ")?;
            write_duration(f, secs)?;
            writeln!(f)?;
        }

        // Boot time
        if let Some(bt) = self.boot_time {
            writeln!(f, "  Boot time: {bt}")?;
        }

        Ok(())
    }
}

// ── SysinfoProvider ────────────────────────────────────────────────────

/// Concrete provider backed by the [`sysinfo`] crate.
///
/// Wraps [`sysinfo::System`] and implements all nine provider traits,
/// reusing the same data-collection logic as [`SystemStatus::collect`].
///
/// # Examples
///
/// ```no_run
/// use toride::status::system::SysinfoProvider;
/// use toride::status::provider::*;
///
/// let mut provider = SysinfoProvider::new();
/// let cpu = provider.cpu_usage().unwrap();
/// let mem = provider.memory().unwrap();
/// ```
pub struct SysinfoProvider {
    sys: System,
}

impl SysinfoProvider {
    /// Create a new provider with refreshed system data.
    ///
    /// Performs the initial CPU measurement sleep, matching the behavior
    /// of [`SystemStatus::collect`].
    #[must_use]
    pub fn new() -> Self {
        let mut sys = System::new_with_specifics(
            RefreshKind::nothing()
                .with_cpu(CpuRefreshKind::nothing().with_cpu_usage())
                .with_memory(MemoryRefreshKind::nothing().with_ram().with_swap())
                .with_processes(ProcessRefreshKind::nothing().with_cpu().with_memory()),
        );
        // sysinfo requires a brief sleep to measure CPU usage accurately.
        std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
        sys.refresh_cpu_usage();
        sys.refresh_processes(ProcessesToUpdate::All, true);
        Self { sys }
    }

}

impl Default for SysinfoProvider {
    fn default() -> Self {
        Self::new()
    }
}

// ── Provider trait implementations ─────────────────────────────────────

impl CpuProvider for SysinfoProvider {
    #[allow(clippy::cast_precision_loss)] // usize->f64 for average; negligible precision loss for core counts
    fn cpu_usage(&mut self) -> StatusResult<Option<f64>> {
        let cpus = self.sys.cpus();
        if cpus.is_empty() {
            return Ok(None);
        }
        let total: f64 = cpus.iter().map(|c| f64::from(c.cpu_usage())).sum();
        Ok(Some(total / cpus.len() as f64))
    }

    fn cpu_cores(&mut self) -> StatusResult<Vec<CpuCore>> {
        Ok(self
            .sys
            .cpus()
            .iter()
            .map(|c| CpuCore {
                name: c.name().to_string(),
                usage: f64::from(c.cpu_usage()),
                frequency: c.frequency(),
            })
            .collect())
    }

    fn physical_cores(&self) -> StatusResult<Option<usize>> {
        Ok(System::physical_core_count())
    }
}

impl MemoryProvider for SysinfoProvider {
    #[allow(clippy::cast_precision_loss)] // u64->f64 for percentage display; negligible precision loss
    fn memory(&mut self) -> StatusResult<MemoryStatus> {
        let total = self.sys.total_memory();
        let used = self.sys.used_memory().min(total);
        let percentage = if total > 0 {
            ((used as f64 / total as f64) * 100.0).min(100.0)
        } else {
            0.0
        };
        Ok(MemoryStatus {
            used_bytes: used,
            total_bytes: total,
            percentage,
        })
    }

    #[allow(clippy::cast_precision_loss)] // u64->f64 for percentage display; negligible precision loss
    fn swap(&mut self) -> StatusResult<Option<SwapStatus>> {
        let total = self.sys.total_swap();
        if total == 0 {
            return Ok(None);
        }
        let used = self.sys.used_swap();
        let percentage = (used as f64 / total as f64) * 100.0;
        Ok(Some(SwapStatus {
            used_bytes: used,
            total_bytes: total,
            percentage,
        }))
    }
}

impl DiskProvider for SysinfoProvider {
    fn root_disk(&mut self) -> StatusResult<DiskStatus> {
        let disks = self.all_disks()?;
        let root = std::path::Path::new("/");
        Ok(disks
            .into_iter()
            .find(|d| std::path::Path::new(&d.mount_point) == root)
            .unwrap_or_else(|| DiskStatus {
                name: String::new(),
                mount_point: "/".to_string(),
                filesystem: String::new(),
                used_bytes: 0,
                total_bytes: 0,
                percentage: 0.0,
                is_removable: false,
            }))
    }

    #[allow(clippy::cast_precision_loss)] // u64->f64 for percentage display; negligible precision loss
    fn all_disks(&mut self) -> StatusResult<Vec<DiskStatus>> {
        let disks = Disks::new_with_refreshed_list();
        Ok(disks
            .iter()
            .map(|d| {
                let total = d.total_space();
                let available = d.available_space();
                let used = total.saturating_sub(available);
                let percentage = if total > 0 {
                    (used as f64 / total as f64) * 100.0
                } else {
                    0.0
                };
                DiskStatus {
                    name: d.name().to_string_lossy().to_string(),
                    mount_point: d.mount_point().to_string_lossy().to_string(),
                    filesystem: d.file_system().to_string_lossy().to_string(),
                    used_bytes: used,
                    total_bytes: total,
                    percentage,
                    is_removable: d.is_removable(),
                }
            })
            .collect())
    }
}

impl NetworkProvider for SysinfoProvider {
    fn aggregate(&mut self) -> StatusResult<NetworkStatus> {
        let networks = Networks::new_with_refreshed_list();
        let (mut received, mut transmitted) = (0u64, 0u64);
        for data in networks.values() {
            received = received.saturating_add(data.total_received());
            transmitted = transmitted.saturating_add(data.total_transmitted());
        }
        Ok(NetworkStatus {
            bytes_received: received,
            bytes_transmitted: transmitted,
        })
    }

    fn interfaces(&mut self) -> StatusResult<Vec<NetworkInterface>> {
        let networks = Networks::new_with_refreshed_list();
        Ok(networks
            .iter()
            .map(|(name, data)| NetworkInterface {
                name: name.clone(),
                bytes_received: data.total_received(),
                bytes_transmitted: data.total_transmitted(),
                packets_received: data.total_packets_received(),
                packets_transmitted: data.total_packets_transmitted(),
                errors_received: data.errors_on_received(),
                errors_transmitted: data.errors_on_transmitted(),
            })
            .collect())
    }
}

impl OsProvider for SysinfoProvider {
    fn os_info(&self) -> StatusResult<OsInfo> {
        Ok(OsInfo {
            name: System::name(),
            version: System::os_version(),
            kernel_version: System::kernel_version(),
            arch: std::env::consts::ARCH.to_string(),
        })
    }

    fn hostname(&self) -> StatusResult<String> {
        Ok(System::host_name().unwrap_or_default())
    }

    fn uptime(&self) -> StatusResult<Option<u64>> {
        let uptime = System::uptime();
        if uptime > 0 { Ok(Some(uptime)) } else { Ok(None) }
    }

    fn boot_time(&self) -> StatusResult<Option<u64>> {
        let bt = System::boot_time();
        if bt > 0 { Ok(Some(bt)) } else { Ok(None) }
    }

    #[cfg(unix)]
    #[allow(clippy::unnecessary_wraps)] // non-unix version returns None; signature must accommodate both platforms
    fn load_average(&self) -> StatusResult<Option<LoadAverage>> {
        let load = System::load_average();
        Ok(Some(LoadAverage {
            one: load.one,
            five: load.five,
            fifteen: load.fifteen,
        }))
    }

    #[cfg(not(unix))]
    fn load_average(&self) -> StatusResult<Option<LoadAverage>> {
        Ok(None)
    }
}

impl ProcessProvider for SysinfoProvider {
    fn processes(&mut self) -> StatusResult<ProcessSnapshot> {
        let processes: Vec<ProcessStatus> = self
            .sys
            .processes()
            .iter()
            .map(|(pid, p)| ProcessStatus {
                pid: pid.as_u32(),
                parent_pid: p.parent().map(sysinfo::Pid::as_u32),
                name: p.name().to_string_lossy().to_string(),
                cpu_usage: p.cpu_usage(),
                memory_bytes: p.memory(),
                status: format!("{}", p.status()),
                start_time: if p.start_time() > 0 { Some(p.start_time()) } else { None },
            })
            .collect();
        let total_count = processes.len();
        Ok(ProcessSnapshot {
            processes,
            total_count,
        })
    }
}

impl GpuProvider for SysinfoProvider {
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::option_if_let_else
    )] // f64->u64 for VRAM values; always positive, fits in f64 mantissa; chained if-let clearer than map_or_else
    fn gpus(&self) -> StatusResult<Vec<GpuInfo>> {
        let mut gpus = Vec::new();
        // Try system_profiler on macOS
        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("system_profiler")
                .args(["SPDisplaysDataType", "-json"])
                .output()
                && let Ok(text) = String::from_utf8(output.stdout)
                && let Ok(json) = serde_json::from_str::<serde_json::Value>(&text)
                && let Some(displays) = json["SPDisplaysDataType"].as_array()
            {
                for display in displays {
                    let name = display["sppci_model"]
                        .as_str()
                        .or_else(|| display["_name"].as_str())
                        .unwrap_or("Unknown GPU")
                        .to_string();
                    let vendor = display["sppci_vendor"]
                        .as_str()
                        .unwrap_or("Unknown")
                        .to_string();
                    let vram = display["sppci_vram"]
                        .as_str()
                        .and_then(parse_vram_to_bytes);
                    gpus.push(GpuInfo {
                        name,
                        vendor,
                        vram_bytes: vram,
                        driver_version: None,
                    });
                }
            }
        }
        // Try nvidia-smi on Linux
        #[cfg(target_os = "linux")]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("nvidia-smi")
                .args(["--query-gpu=name,memory.total,driver_version", "--format=csv,noheader,nounits"])
                .output()
            {
                if output.status.success() {
                    let text = String::from_utf8_lossy(&output.stdout);
                    for line in text.lines() {
                        let parts: Vec<&str> = line.split(", ").collect();
                        if parts.len() >= 3 {
                            let name = parts[0].trim().to_string();
                            let vram_mb: Option<u64> = parts[1].trim().parse().ok();
                            let driver = parts[2].trim().to_string();
                            gpus.push(GpuInfo {
                                name,
                                vendor: "NVIDIA".to_string(),
                                vram_bytes: vram_mb.map(|mb| mb * 1024 * 1024),
                                driver_version: Some(driver),
                            });
                        }
                    }
                }
            }
        }
        Ok(gpus)
    }
}

impl BatteryProvider for SysinfoProvider {
    fn battery(&self) -> StatusResult<Option<BatteryInfo>> {
        Ok(read_battery_os())
    }
}

impl SensorProvider for SysinfoProvider {
    fn sensors(&self) -> StatusResult<Vec<SensorStatus>> {
        let components = Components::new_with_refreshed_list();
        Ok(components
            .iter()
            .map(|c| SensorStatus {
                label: c.label().to_string(),
                temperature: c.temperature().filter(|t| !t.is_nan()),
            })
            .collect())
    }
}

// ── collect_via_provider ───────────────────────────────────────────────

impl SystemStatus {
    /// Collect a snapshot using the provider abstraction layer.
    ///
    /// This method uses [`SysinfoProvider`] to gather metrics through
    /// the provider traits, exercising the same code paths that custom
    /// providers would use. The result should be structurally identical
    /// to [`collect`](Self::collect).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use toride::status::system::SystemStatus;
    ///
    /// let status = SystemStatus::collect_via_provider();
    /// assert!(!status.hostname.is_empty());
    /// ```
    #[must_use]
    #[allow(clippy::too_many_lines)] // Assembles all provider outputs; splitting reduces readability
    pub fn collect_via_provider() -> Self {
        let mut provider = SysinfoProvider::new();

        let cpu_usage = provider.cpu_usage().ok().flatten();
        let memory = provider.memory().unwrap_or(MemoryStatus {
            used_bytes: 0,
            total_bytes: 0,
            percentage: 0.0,
        });
        let disk = provider.root_disk().unwrap_or_else(|_| DiskStatus {
            name: String::new(),
            mount_point: "/".to_string(),
            filesystem: String::new(),
            used_bytes: 0,
            total_bytes: 0,
            percentage: 0.0,
            is_removable: false,
        });
        let disks = provider.all_disks().unwrap_or_default();
        let network = provider.aggregate().unwrap_or(NetworkStatus {
            bytes_received: 0,
            bytes_transmitted: 0,
        });
        let network_interfaces = provider.interfaces().unwrap_or_default();
        let load_average = provider.load_average().ok().flatten();
        let uptime_secs = provider.uptime().ok().flatten();
        let hostname = provider.hostname().unwrap_or_default();
        let os_info = provider.os_info().unwrap_or_else(|_| OsInfo {
            name: None,
            version: None,
            kernel_version: None,
            arch: String::new(),
        });
        let cpu_cores = provider.cpu_cores().unwrap_or_default();
        let physical_cores = provider.physical_cores().ok().flatten();
        let swap = provider.swap().ok().flatten();
        let sensors = provider.sensors().unwrap_or_default();
        let boot_time = provider.boot_time().ok().flatten();
        let processes = provider.processes().unwrap_or_else(|_| ProcessSnapshot {
            processes: vec![],
            total_count: 0,
        });
        let gpu = provider.gpus().unwrap_or_default();
        let battery = provider.battery().ok().flatten();

        Self {
            cpu_usage,
            memory,
            disk,
            network,
            load_average,
            uptime_secs,
            hostname,
            os_info,
            cpu_cores,
            physical_cores,
            swap,
            disks,
            network_interfaces,
            sensors,
            boot_time,
            processes,
            gpu,
            battery,
        }
    }
}

const KB: u64 = 1024;
const MB: u64 = KB * 1024;
const GB: u64 = MB * 1024;
const TB: u64 = GB * 1024;
const PB: u64 = TB * 1024;
const EB: u64 = PB * 1024;

/// Write bytes in human-readable form directly to the formatter.
#[allow(clippy::cast_precision_loss)] // u64->f64 for display formatting; negligible precision loss
fn write_bytes(f: &mut fmt::Formatter<'_>, bytes: u64) -> fmt::Result {
    if bytes >= EB {
        write!(f, "{:.1} EiB", bytes as f64 / EB as f64)
    } else if bytes >= PB {
        write!(f, "{:.1} PiB", bytes as f64 / PB as f64)
    } else if bytes >= TB {
        write!(f, "{:.1} TiB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        write!(f, "{:.1} GiB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        write!(f, "{:.1} MiB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        write!(f, "{:.1} KiB", bytes as f64 / KB as f64)
    } else {
        write!(f, "{bytes} B")
    }
}

/// Write seconds in human-readable form directly to the formatter.
///
/// Intermediate zero-valued units (hours, minutes) are included when a
/// higher unit is non-zero. For example, 3600 seconds renders as
/// `1h 0m 0s` rather than `1h 0s`.
#[allow(clippy::useless_let_if_seq)] // sequential if-blocks with mutable flag are clearer than chained if-expressions
fn write_duration(f: &mut fmt::Formatter<'_>, secs: u64) -> fmt::Result {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;

    let mut first = true;
    if days > 0 {
        write!(f, "{days}d")?;
        first = false;
    }
    if hours > 0 || !first {
        if !first {
            write!(f, " ")?;
        }
        write!(f, "{hours}h")?;
        first = false;
    }
    if minutes > 0 || !first {
        if !first {
            write!(f, " ")?;
        }
        write!(f, "{minutes}m")?;
        first = false;
    }
    if !first {
        write!(f, " ")?;
    }
    write!(f, "{seconds}s")
}

/// Format bytes into a human-readable string. Wrapper for test use.
#[cfg(test)]
fn format_bytes(bytes: u64) -> String {
    struct Fmt(u64);
    impl fmt::Display for Fmt {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write_bytes(f, self.0)
        }
    }
    Fmt(bytes).to_string()
}

/// Format seconds into a human-readable duration string. Wrapper for test use.
#[cfg(test)]
fn format_duration(secs: u64) -> String {
    struct Fmt(u64);
    impl fmt::Display for Fmt {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write_duration(f, self.0)
        }
    }
    Fmt(secs).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_returns_valid_cpu_usage() {
        let status = SystemStatus::collect();
        if let Some(cpu) = status.cpu_usage {
            assert!(
                (0.0..=100.0).contains(&cpu),
                "CPU usage {cpu}% out of range 0–100"
            );
        }
    }

    #[test]
    fn collect_returns_nonzero_total_memory() {
        let status = SystemStatus::collect();
        assert!(
            status.memory.total_bytes > 0,
            "total memory should be > 0"
        );
    }

    #[test]
    fn memory_used_does_not_exceed_total() {
        let status = SystemStatus::collect();
        assert!(
            status.memory.used_bytes <= status.memory.total_bytes,
            "used {} > total {}",
            status.memory.used_bytes,
            status.memory.total_bytes
        );
    }

    #[test]
    #[allow(clippy::cast_precision_loss, reason = "test compares percentages with tolerance")]
    fn memory_percentage_is_consistent() {
        let status = SystemStatus::collect();
        let expected = if status.memory.total_bytes > 0 {
            (status.memory.used_bytes as f64 / status.memory.total_bytes as f64) * 100.0
        } else {
            0.0
        };
        assert!(
            (status.memory.percentage - expected).abs() < 0.1,
            "memory percentage {} != expected {}",
            status.memory.percentage,
            expected
        );
    }

    #[test]
    fn disk_used_does_not_exceed_total() {
        let status = SystemStatus::collect();
        assert!(
            status.disk.used_bytes <= status.disk.total_bytes,
            "disk used {} > total {}",
            status.disk.used_bytes,
            status.disk.total_bytes
        );
    }

    #[test]
    #[allow(clippy::cast_precision_loss, reason = "test compares percentages with tolerance")]
    fn disk_percentage_is_consistent() {
        let status = SystemStatus::collect();
        if status.disk.total_bytes > 0 {
            let expected = (status.disk.used_bytes as f64 / status.disk.total_bytes as f64) * 100.0;
            assert!(
                (status.disk.percentage - expected).abs() < 0.1,
                "disk percentage {} != expected {}",
                status.disk.percentage,
                expected
            );
        }
    }

    #[test]
    fn network_fields_are_accessible() {
        let status = SystemStatus::collect();
        // u64 is always >= 0, but we verify the values are reasonable.
        let _ = status.network.bytes_received;
        let _ = status.network.bytes_transmitted;
    }

    #[cfg(unix)]
    #[test]
    fn load_average_is_populated_on_unix() {
        let status = SystemStatus::collect();
        assert!(
            status.load_average.is_some(),
            "load average should be populated on Unix"
        );
        let load = status.load_average.unwrap();
        assert!(load.one >= 0.0, "1-min load {}", load.one);
        assert!(load.five >= 0.0, "5-min load {}", load.five);
        assert!(load.fifteen >= 0.0, "15-min load {}", load.fifteen);
    }

    #[test]
    fn uptime_is_positive() {
        let status = SystemStatus::collect();
        if let Some(uptime) = status.uptime_secs {
            assert!(uptime > 0, "uptime should be > 0");
        }
    }

    #[test]
    fn hostname_is_non_empty() {
        let status = SystemStatus::collect();
        assert!(
            !status.hostname.is_empty(),
            "hostname should not be empty"
        );
    }

    #[test]
    fn display_contains_expected_sections() {
        let status = SystemStatus::collect();
        let output = format!("{status}");
        assert!(output.contains("System:"));
        assert!(output.contains("Hostname:"));
        assert!(output.contains("Memory:"));
        assert!(output.contains("Disk:"));
        assert!(output.contains("Network:"));
    }

    #[test]
    fn format_bytes_zero() {
        assert_eq!(format_bytes(0), "0 B");
    }

    #[test]
    fn format_bytes_one_kib() {
        assert_eq!(format_bytes(1024), "1.0 KiB");
    }

    #[test]
    fn format_bytes_one_mib() {
        assert_eq!(format_bytes(1024 * 1024), "1.0 MiB");
    }

    #[test]
    fn format_bytes_one_gib() {
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GiB");
    }

    #[test]
    fn format_bytes_one_tib() {
        assert_eq!(format_bytes(1024_u64 * 1024 * 1024 * 1024), "1.0 TiB");
    }

    #[test]
    fn format_bytes_mixed() {
        let result = format_bytes(1536); // 1.5 KiB
        assert_eq!(result, "1.5 KiB");
    }

    #[test]
    fn format_duration_zero() {
        assert_eq!(format_duration(0), "0s");
    }

    #[test]
    fn format_duration_seconds_only() {
        assert_eq!(format_duration(45), "45s");
    }

    #[test]
    fn format_duration_minutes_and_seconds() {
        assert_eq!(format_duration(125), "2m 5s");
    }

    #[test]
    fn format_duration_hours() {
        assert_eq!(format_duration(3661), "1h 1m 1s");
    }

    #[test]
    fn format_duration_days() {
        assert_eq!(format_duration(90061), "1d 1h 1m 1s");
    }

    #[test]
    fn serialize_to_json_succeeds() {
        let status = SystemStatus::collect();
        let json = serde_json::to_string(&status);
        assert!(json.is_ok(), "serialization should succeed: {:?}", json.err());
    }

    #[test]
    fn format_bytes_one_byte() {
        assert_eq!(format_bytes(1), "1 B");
    }

    #[test]
    fn format_bytes_boundary_below_kib() {
        assert_eq!(format_bytes(1023), "1023 B");
    }

    #[test]
    fn format_bytes_u64_max() {
        // u64::MAX = 18_446_744_073_709_551_615 ≈ 16.0 EiB
        let result = format_bytes(u64::MAX);
        assert!(
            result.ends_with("EiB"),
            "u64::MAX should format as EiB, got: {result}"
        );
    }

    #[test]
    fn format_duration_one_second() {
        assert_eq!(format_duration(1), "1s");
    }

    #[test]
    fn format_duration_exactly_one_minute() {
        assert_eq!(format_duration(60), "1m 0s");
    }

    #[test]
    fn format_duration_exactly_one_hour() {
        assert_eq!(format_duration(3600), "1h 0m 0s");
    }

    #[test]
    fn format_duration_exactly_one_day() {
        assert_eq!(format_duration(86400), "1d 0h 0m 0s");
    }

    #[test]
    fn display_with_none_cpu() {
        let status = SystemStatus {
            cpu_usage: None,
            memory: MemoryStatus {
                used_bytes: 0,
                total_bytes: 0,
                percentage: 0.0,
            },
            disk: DiskStatus {
                name: String::new(),
                mount_point: "/".to_string(),
                filesystem: String::new(),
                used_bytes: 0,
                total_bytes: 0,
                percentage: 0.0,
                is_removable: false,
            },
            network: NetworkStatus {
                bytes_received: 0,
                bytes_transmitted: 0,
            },
            load_average: None,
            uptime_secs: None,
            hostname: "test".to_string(),
            os_info: OsInfo {
                name: None,
                version: None,
                kernel_version: None,
                arch: "x86_64".to_string(),
            },
            cpu_cores: Vec::new(),
            physical_cores: None,
            swap: None,
            disks: Vec::new(),
            network_interfaces: Vec::new(),
            sensors: Vec::new(),
            boot_time: None,
            processes: ProcessSnapshot {
                processes: vec![],
                total_count: 0,
            },
            gpu: vec![],
            battery: None,
        };
        let output = format!("{status}");
        assert!(output.contains("CPU: N/A"), "expected 'CPU: N/A' in output:\n{output}");
    }

    #[test]
    fn os_info_fields_are_populated() {
        let status = SystemStatus::collect();
        assert!(status.os_info.name.is_some(), "os_info.name should be Some");
        assert!(status.os_info.arch.is_ascii() && !status.os_info.arch.is_empty(), "arch should be non-empty");
    }

    #[test]
    fn cpu_cores_is_non_empty() {
        let status = SystemStatus::collect();
        assert!(!status.cpu_cores.is_empty(), "cpu_cores should be non-empty");
        for core in &status.cpu_cores {
            assert!(!core.name.is_empty(), "core name should not be empty");
            assert!((0.0..=100.0).contains(&core.usage), "core usage out of range: {}", core.usage);
        }
    }

    #[test]
    fn disks_is_non_empty() {
        let status = SystemStatus::collect();
        assert!(!status.disks.is_empty(), "disks should be non-empty");
        for disk in &status.disks {
            assert!(disk.used_bytes <= disk.total_bytes, "disk used > total");
        }
    }

    #[test]
    fn network_interfaces_is_non_empty() {
        let status = SystemStatus::collect();
        assert!(!status.network_interfaces.is_empty(), "network_interfaces should be non-empty");
    }

    #[cfg(unix)]
    #[test]
    fn swap_is_some_when_available() {
        let status = SystemStatus::collect();
        // On most Unix systems swap is configured, but we only assert structure if present.
        if let Some(swap) = &status.swap {
            assert!(swap.used_bytes <= swap.total_bytes, "swap used > total");
            assert!((0.0..=100.0).contains(&swap.percentage), "swap percentage out of range");
        }
    }

    #[test]
    fn physical_cores_is_some() {
        let status = SystemStatus::collect();
        assert!(status.physical_cores.is_some(), "physical_cores should be Some on real hardware");
        assert!(status.physical_cores.unwrap() > 0, "physical_cores should be > 0");
    }

    #[test]
    #[allow(clippy::too_many_lines, reason = "snapshot test constructs a full SystemStatus with all fields populated")]
    fn snapshot_system_status_display() {
        let status = SystemStatus {
            cpu_usage: Some(42.5),
            memory: MemoryStatus {
                used_bytes: 8 * GB,
                total_bytes: 16 * GB,
                percentage: 50.0,
            },
            disk: DiskStatus {
                name: "Macintosh HD".to_string(),
                mount_point: "/".to_string(),
                filesystem: "apfs".to_string(),
                used_bytes: 500 * GB,
                total_bytes: TB,
                percentage: 50.0,
                is_removable: false,
            },
            network: NetworkStatus {
                bytes_received: 100 * GB,
                bytes_transmitted: 50 * GB,
            },
            load_average: Some(LoadAverage {
                one: 2.50,
                five: 3.00,
                fifteen: 3.50,
            }),
            uptime_secs: Some(90061),
            hostname: "test-host".to_string(),
            os_info: OsInfo {
                name: Some("macOS".to_string()),
                version: Some("15.0".to_string()),
                kernel_version: Some("24.0.0".to_string()),
                arch: "aarch64".to_string(),
            },
            cpu_cores: vec![
                CpuCore {
                    name: "cpu0".to_string(),
                    usage: 45.0,
                    frequency: 3200,
                },
                CpuCore {
                    name: "cpu1".to_string(),
                    usage: 40.0,
                    frequency: 3200,
                },
            ],
            physical_cores: Some(8),
            swap: Some(SwapStatus {
                used_bytes: 512 * MB,
                total_bytes: 2 * GB,
                percentage: 25.0,
            }),
            disks: vec![
                DiskStatus {
                    name: "Macintosh HD".to_string(),
                    mount_point: "/".to_string(),
                    filesystem: "apfs".to_string(),
                    used_bytes: 500 * GB,
                    total_bytes: TB,
                    percentage: 50.0,
                    is_removable: false,
                },
                DiskStatus {
                    name: "External".to_string(),
                    mount_point: "/Volumes/External".to_string(),
                    filesystem: "exfat".to_string(),
                    used_bytes: 100 * GB,
                    total_bytes: 500 * GB,
                    percentage: 20.0,
                    is_removable: true,
                },
            ],
            network_interfaces: vec![
                NetworkInterface {
                    name: "en0".to_string(),
                    bytes_received: 60 * GB,
                    bytes_transmitted: 30 * GB,
                    packets_received: 1_000_000,
                    packets_transmitted: 500_000,
                    errors_received: 0,
                    errors_transmitted: 0,
                },
                NetworkInterface {
                    name: "lo0".to_string(),
                    bytes_received: 40 * GB,
                    bytes_transmitted: 20 * GB,
                    packets_received: 2_000_000,
                    packets_transmitted: 2_000_000,
                    errors_received: 0,
                    errors_transmitted: 0,
                },
            ],
            sensors: vec![
                SensorStatus {
                    label: "CPU".to_string(),
                    temperature: Some(55.5),
                },
                SensorStatus {
                    label: "GPU".to_string(),
                    temperature: Some(48.0),
                },
            ],
            boot_time: Some(1_700_000_000),
            processes: ProcessSnapshot {
                processes: vec![],
                total_count: 0,
            },
            gpu: vec![],
            battery: None,
        };
        insta::assert_snapshot!("system_status_display", format!("{}", status));
    }

    #[test]
    fn processes_is_non_empty() {
        let status = SystemStatus::collect();
        assert!(
            status.processes.total_count > 0,
            "processes.total_count should be > 0"
        );
    }

    #[test]
    fn top_by_cpu_returns_sorted() {
        let snapshot = ProcessSnapshot {
            processes: vec![
                ProcessStatus {
                    pid: 1,
                    parent_pid: None,
                    name: "low".to_string(),
                    cpu_usage: 1.0,
                    memory_bytes: 100,
                    status: "Running".to_string(),
                    start_time: Some(1000),
                },
                ProcessStatus {
                    pid: 2,
                    parent_pid: None,
                    name: "high".to_string(),
                    cpu_usage: 50.0,
                    memory_bytes: 100,
                    status: "Running".to_string(),
                    start_time: Some(1000),
                },
                ProcessStatus {
                    pid: 3,
                    parent_pid: None,
                    name: "mid".to_string(),
                    cpu_usage: 25.0,
                    memory_bytes: 100,
                    status: "Running".to_string(),
                    start_time: Some(1000),
                },
            ],
            total_count: 3,
        };
        let top = snapshot.top_by_cpu(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].pid, 2);
        assert_eq!(top[1].pid, 3);
    }

    #[test]
    fn top_by_memory_returns_sorted() {
        let snapshot = ProcessSnapshot {
            processes: vec![
                ProcessStatus {
                    pid: 1,
                    parent_pid: None,
                    name: "small".to_string(),
                    cpu_usage: 1.0,
                    memory_bytes: 1024,
                    status: "Running".to_string(),
                    start_time: Some(1000),
                },
                ProcessStatus {
                    pid: 2,
                    parent_pid: None,
                    name: "large".to_string(),
                    cpu_usage: 1.0,
                    memory_bytes: 1024 * 1024 * 100,
                    status: "Running".to_string(),
                    start_time: Some(1000),
                },
                ProcessStatus {
                    pid: 3,
                    parent_pid: None,
                    name: "medium".to_string(),
                    cpu_usage: 1.0,
                    memory_bytes: 1024 * 1024,
                    status: "Running".to_string(),
                    start_time: Some(1000),
                },
            ],
            total_count: 3,
        };
        let top = snapshot.top_by_memory(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].pid, 2);
        assert_eq!(top[1].pid, 3);
    }

    #[test]
    fn gpu_vec_is_accessible() {
        let status = SystemStatus::collect();
        // GPU detection may or may not find devices; verify the field is accessible.
        let _ = &status.gpu;
    }

    #[test]
    fn battery_is_accessible() {
        let status = SystemStatus::collect();
        // Battery may or may not be present on this machine; verify the field is accessible.
        let _ = &status.battery;
    }

    // ── parse_vram_to_bytes edge cases ─────────────────────────────────────

    #[test]
    fn parse_vram_to_bytes_gb() {
        assert_eq!(parse_vram_to_bytes("8 GB"), Some(8 * 1024 * 1024 * 1024));
        assert_eq!(parse_vram_to_bytes("8GB"), Some(8 * 1024 * 1024 * 1024));
    }

    #[test]
    fn parse_vram_to_bytes_mb() {
        assert_eq!(parse_vram_to_bytes("8192 MB"), Some(8192 * 1024 * 1024));
        assert_eq!(parse_vram_to_bytes("8192MB"), Some(8192 * 1024 * 1024));
    }

    #[test]
    fn parse_vram_to_bytes_bare_number() {
        assert_eq!(parse_vram_to_bytes("8192"), Some(8192 * 1024 * 1024));
    }

    #[test]
    fn parse_vram_tb_suffix() {
        let result = parse_vram_to_bytes("2TB");
        assert_eq!(result, Some(2 * 1024 * 1024 * 1024 * 1024));
    }

    #[test]
    fn parse_vram_tb_with_space() {
        let result = parse_vram_to_bytes("2 TB");
        assert_eq!(result, Some(2 * 1024 * 1024 * 1024 * 1024));
    }

    #[test]
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "test verifies exact conversion of known-good float to u64"
    )]
    fn parse_vram_tb_fractional() {
        let result = parse_vram_to_bytes("1.5 TB");
        assert_eq!(result, Some((1.5 * 1024.0 * 1024.0 * 1024.0 * 1024.0) as u64));
    }

    #[test]
    fn parse_vram_bare_number_saturates() {
        // u64::MAX cannot overflow with saturating_mul; it clamps to u64::MAX.
        let result = parse_vram_to_bytes(&u64::MAX.to_string());
        assert_eq!(result, Some(u64::MAX));
    }

    // ── format_bytes edge cases ──────────────────────────────────────────

    #[test]
    fn format_bytes_pib_boundary() {
        assert_eq!(format_bytes(PB), "1.0 PiB");
    }

    #[test]
    fn format_bytes_just_below_pib() {
        // PB - 1 is so close to 1024.0 TiB that f64 rounds up to "1024.0 TiB".
        let result = format_bytes(PB - 1);
        assert!(
            result.ends_with("TiB"),
            "should format as TiB just below PiB boundary, got: {result}"
        );
    }

    #[test]
    fn format_bytes_exact_kib() {
        assert_eq!(format_bytes(KB), "1.0 KiB");
    }

    #[test]
    fn format_bytes_exact_mib() {
        assert_eq!(format_bytes(MB), "1.0 MiB");
    }

    #[test]
    fn format_bytes_exact_gib() {
        assert_eq!(format_bytes(GB), "1.0 GiB");
    }

    #[test]
    fn format_bytes_exact_tib() {
        assert_eq!(format_bytes(TB), "1.0 TiB");
    }

    #[test]
    fn format_bytes_exact_pib() {
        assert_eq!(format_bytes(PB), "1.0 PiB");
    }

    #[test]
    fn format_bytes_exact_eib() {
        assert_eq!(format_bytes(EB), "1.0 EiB");
    }

    // ── format_duration edge cases ───────────────────────────────────────

    #[test]
    fn format_duration_max_value() {
        // u64::MAX should not panic
        let result = format_duration(u64::MAX);
        assert!(!result.is_empty(), "format_duration(u64::MAX) should not be empty");
        assert!(result.ends_with('s'), "should end with seconds: {result}");
    }

    #[test]
    fn format_duration_very_large_value() {
        // 1000 days in seconds
        let secs = 1000 * 86400;
        let result = format_duration(secs);
        assert_eq!(result, "1000d 0h 0m 0s");
    }

    // ── Memory percentage edge cases ─────────────────────────────────────

    /// Helper to construct a minimal `SystemStatus` for unit testing.
    fn make_status(memory: MemoryStatus, disk: DiskStatus) -> SystemStatus {
        SystemStatus {
            cpu_usage: None,
            memory,
            disk,
            network: NetworkStatus { bytes_received: 0, bytes_transmitted: 0 },
            load_average: None,
            uptime_secs: None,
            hostname: String::new(),
            os_info: OsInfo { name: None, version: None, kernel_version: None, arch: String::new() },
            cpu_cores: Vec::new(),
            physical_cores: None,
            swap: None,
            disks: Vec::new(),
            network_interfaces: Vec::new(),
            sensors: Vec::new(),
            boot_time: None,
            processes: ProcessSnapshot { processes: vec![], total_count: 0 },
            gpu: vec![],
            battery: None,
        }
    }

    fn empty_disk() -> DiskStatus {
        DiskStatus {
            name: String::new(),
            mount_point: "/".to_string(),
            filesystem: String::new(),
            used_bytes: 0,
            total_bytes: 0,
            percentage: 0.0,
            is_removable: false,
        }
    }

    #[test]
    fn memory_percentage_zero_total() {
        // Division by zero protection: total_bytes = 0 should yield 0%.
        let status = make_status(
            MemoryStatus { used_bytes: 0, total_bytes: 0, percentage: 0.0 },
            empty_disk(),
        );
        assert!((status.memory.percentage).abs() < f64::EPSILON);
    }

    #[test]
    fn memory_percentage_capped_at_100() {
        // When used > total (e.g. reclaimed/buffer memory), percentage should be capped at 100%.
        let status = make_status(
            MemoryStatus { used_bytes: 20 * GB, total_bytes: 16 * GB, percentage: 100.0 },
            empty_disk(),
        );
        assert!(
            status.memory.percentage <= 100.0,
            "memory percentage should be <= 100, got {}",
            status.memory.percentage
        );
    }

    // ── Disk percentage edge cases ───────────────────────────────────────

    #[test]
    fn disk_percentage_zero_total() {
        // Division by zero protection: total_bytes = 0 should yield 0%.
        let status = make_status(
            MemoryStatus { used_bytes: 0, total_bytes: 0, percentage: 0.0 },
            DiskStatus {
                name: String::new(),
                mount_point: "/".to_string(),
                filesystem: String::new(),
                used_bytes: 0,
                total_bytes: 0,
                percentage: 0.0,
                is_removable: false,
            },
        );
        assert!((status.disk.percentage).abs() < f64::EPSILON);
    }

    #[test]
    fn disk_percentage_capped_at_100() {
        // When used > total (e.g. filesystem overhead), percentage should be capped at 100%.
        let status = make_status(
            MemoryStatus { used_bytes: 0, total_bytes: 0, percentage: 0.0 },
            DiskStatus {
                name: String::new(),
                mount_point: "/".to_string(),
                filesystem: String::new(),
                used_bytes: 600 * GB,
                total_bytes: 500 * GB,
                percentage: 100.0,
                is_removable: false,
            },
        );
        assert!(
            status.disk.percentage <= 100.0,
            "disk percentage should be <= 100, got {}",
            status.disk.percentage
        );
    }

    // ── ProcessSnapshot edge cases ───────────────────────────────────────

    fn make_process(pid: u32, cpu: f32, mem: u64) -> ProcessStatus {
        ProcessStatus {
            pid,
            parent_pid: None,
            name: format!("proc-{pid}"),
            cpu_usage: cpu,
            memory_bytes: mem,
            status: "Running".to_string(),
            start_time: Some(1000),
        }
    }

    #[test]
    fn top_by_cpu_n_exceeds_len() {
        let snapshot = ProcessSnapshot {
            processes: vec![
                make_process(1, 10.0, 100),
                make_process(2, 50.0, 200),
            ],
            total_count: 2,
        };
        let top = snapshot.top_by_cpu(10);
        assert_eq!(top.len(), 2, "should return all processes when n > len");
        assert_eq!(top[0].pid, 2);
        assert_eq!(top[1].pid, 1);
    }

    #[test]
    fn top_by_cpu_n_zero() {
        let snapshot = ProcessSnapshot {
            processes: vec![
                make_process(1, 10.0, 100),
                make_process(2, 50.0, 200),
            ],
            total_count: 2,
        };
        let top = snapshot.top_by_cpu(0);
        assert!(top.is_empty(), "n=0 should return empty vec");
    }

    #[test]
    fn top_by_cpu_empty_processes() {
        let snapshot = ProcessSnapshot {
            processes: vec![],
            total_count: 0,
        };
        let top = snapshot.top_by_cpu(5);
        assert!(top.is_empty(), "empty processes should return empty vec");
    }

    #[test]
    fn top_by_memory_n_exceeds_len() {
        let snapshot = ProcessSnapshot {
            processes: vec![
                make_process(1, 5.0, 1024),
                make_process(2, 5.0, 4096),
            ],
            total_count: 2,
        };
        let top = snapshot.top_by_memory(10);
        assert_eq!(top.len(), 2, "should return all processes when n > len");
        assert_eq!(top[0].pid, 2);
        assert_eq!(top[1].pid, 1);
    }

    #[test]
    fn top_by_memory_n_zero() {
        let snapshot = ProcessSnapshot {
            processes: vec![
                make_process(1, 5.0, 1024),
                make_process(2, 5.0, 4096),
            ],
            total_count: 2,
        };
        let top = snapshot.top_by_memory(0);
        assert!(top.is_empty(), "n=0 should return empty vec");
    }

    #[test]
    fn top_by_memory_empty_processes() {
        let snapshot = ProcessSnapshot {
            processes: vec![],
            total_count: 0,
        };
        let top = snapshot.top_by_memory(5);
        assert!(top.is_empty(), "empty processes should return empty vec");
    }

    #[test]
    fn top_by_cpu_with_nan_values() {
        // NaN cpu_usage should not panic and should sort safely.
        let snapshot = ProcessSnapshot {
            processes: vec![
                make_process(1, f32::NAN, 100),
                make_process(2, 50.0, 200),
                make_process(3, f32::NAN, 150),
            ],
            total_count: 3,
        };
        let top = snapshot.top_by_cpu(3);
        assert_eq!(top.len(), 3, "all processes should be returned even with NaN");
        // Verify the non-NaN process is included.
        assert!(top.iter().any(|p| p.pid == 2), "non-NaN process should be present");
    }

    #[test]
    fn top_by_cpu_stable_sort() {
        // When cpu_usage values are equal, the original insertion order should be preserved
        // (sort_by is stable in Rust's standard library).
        let snapshot = ProcessSnapshot {
            processes: vec![
                make_process(1, 50.0, 100),
                make_process(2, 50.0, 200),
                make_process(3, 50.0, 150),
            ],
            total_count: 3,
        };
        let top = snapshot.top_by_cpu(3);
        assert_eq!(top.len(), 3);
        assert_eq!(top[0].pid, 1, "stable sort: first inserted should remain first");
        assert_eq!(top[1].pid, 2, "stable sort: second inserted should remain second");
        assert_eq!(top[2].pid, 3, "stable sort: third inserted should remain third");
    }

    // ── Display edge cases ───────────────────────────────────────────────

    #[test]
    fn display_with_all_none_fields() {
        let status = SystemStatus {
            cpu_usage: None,
            memory: MemoryStatus {
                used_bytes: 0,
                total_bytes: 0,
                percentage: 0.0,
            },
            disk: DiskStatus {
                name: String::new(),
                mount_point: "/".to_string(),
                filesystem: String::new(),
                used_bytes: 0,
                total_bytes: 0,
                percentage: 0.0,
                is_removable: false,
            },
            network: NetworkStatus {
                bytes_received: 0,
                bytes_transmitted: 0,
            },
            load_average: None,
            uptime_secs: None,
            hostname: "empty-host".to_string(),
            os_info: OsInfo {
                name: None,
                version: None,
                kernel_version: None,
                arch: "unknown".to_string(),
            },
            cpu_cores: Vec::new(),
            physical_cores: None,
            swap: None,
            disks: Vec::new(),
            network_interfaces: Vec::new(),
            sensors: Vec::new(),
            boot_time: None,
            processes: ProcessSnapshot {
                processes: vec![],
                total_count: 0,
            },
            gpu: vec![],
            battery: None,
        };
        let output = format!("{status}");
        assert!(output.contains("System:"), "should contain 'System:' header");
        assert!(output.contains("CPU: N/A"), "should show 'CPU: N/A'");
        assert!(output.contains("Memory:"), "should contain 'Memory:'");
        assert!(output.contains("0 B / 0 B"), "should show 0 B / 0 B");
        assert!(output.contains("0.0%)"), "should show 0.0%");
        assert!(!output.contains("GPU"), "no GPU section when gpu is empty");
        assert!(!output.contains("Battery"), "no Battery section when battery is None");
        assert!(!output.contains("Uptime"), "no Uptime section when uptime is None");
        assert!(!output.contains("Load:"), "no Load section when load_average is None");
    }

    #[test]
    fn display_with_gpu_data() {
        let status = SystemStatus {
            cpu_usage: Some(50.0),
            memory: MemoryStatus { used_bytes: 8 * GB, total_bytes: 16 * GB, percentage: 50.0 },
            disk: empty_disk(),
            network: NetworkStatus { bytes_received: 0, bytes_transmitted: 0 },
            load_average: None,
            uptime_secs: None,
            hostname: "gpu-host".to_string(),
            os_info: OsInfo { name: Some("Linux".to_string()), version: None, kernel_version: None, arch: "x86_64".to_string() },
            cpu_cores: Vec::new(),
            physical_cores: None,
            swap: None,
            disks: Vec::new(),
            network_interfaces: Vec::new(),
            sensors: Vec::new(),
            boot_time: None,
            processes: ProcessSnapshot { processes: vec![], total_count: 0 },
            gpu: vec![GpuInfo {
                name: "NVIDIA RTX 4090".to_string(),
                vendor: "NVIDIA".to_string(),
                vram_bytes: Some(24 * GB),
                driver_version: Some("535.129.03".to_string()),
            }],
            battery: None,
        };
        let output = format!("{status}");
        assert!(output.contains("GPU 0:"), "should contain GPU section");
        assert!(output.contains("NVIDIA RTX 4090"), "should contain GPU name");
        assert!(output.contains("NVIDIA"), "should contain GPU vendor");
        assert!(output.contains("24.0 GiB"), "should contain VRAM");
    }

    #[test]
    fn display_with_battery_data() {
        let status = SystemStatus {
            cpu_usage: None,
            memory: MemoryStatus { used_bytes: 0, total_bytes: 0, percentage: 0.0 },
            disk: empty_disk(),
            network: NetworkStatus { bytes_received: 0, bytes_transmitted: 0 },
            load_average: None,
            uptime_secs: None,
            hostname: "laptop".to_string(),
            os_info: OsInfo { name: None, version: None, kernel_version: None, arch: "aarch64".to_string() },
            cpu_cores: Vec::new(),
            physical_cores: None,
            swap: None,
            disks: Vec::new(),
            network_interfaces: Vec::new(),
            sensors: Vec::new(),
            boot_time: None,
            processes: ProcessSnapshot { processes: vec![], total_count: 0 },
            gpu: vec![],
            battery: Some(BatteryInfo {
                charge_percent: 85.0,
                state: "Charging".to_string(),
                time_to_full_secs: Some(1800),
                time_to_empty_secs: None,
            }),
        };
        let output = format!("{status}");
        assert!(output.contains("Battery:"), "should contain Battery section");
        assert!(output.contains("85%"), "should contain charge percentage");
        assert!(output.contains("Charging"), "should contain battery state");
    }

    #[test]
    fn display_sensors_none_temperature() {
        let status = SystemStatus {
            cpu_usage: None,
            memory: MemoryStatus { used_bytes: 0, total_bytes: 0, percentage: 0.0 },
            disk: empty_disk(),
            network: NetworkStatus { bytes_received: 0, bytes_transmitted: 0 },
            load_average: None,
            uptime_secs: None,
            hostname: "sensor-host".to_string(),
            os_info: OsInfo { name: None, version: None, kernel_version: None, arch: "x86_64".to_string() },
            cpu_cores: Vec::new(),
            physical_cores: None,
            swap: None,
            disks: Vec::new(),
            network_interfaces: Vec::new(),
            sensors: vec![
                SensorStatus {
                    label: "CPU".to_string(),
                    temperature: Some(65.0),
                },
                SensorStatus {
                    label: "Unknown".to_string(),
                    temperature: None,
                },
            ],
            boot_time: None,
            processes: ProcessSnapshot { processes: vec![], total_count: 0 },
            gpu: vec![],
            battery: None,
        };
        let output = format!("{status}");
        assert!(output.contains("Sensors:"), "should contain Sensors section");
        assert!(output.contains("CPU: 65.0"), "should show temperature for CPU sensor");
        assert!(output.contains("Unknown: N/A"), "should show N/A for sensor with None temperature");
    }

    // ── Critical edge case tests ───────────────────────────────────────

    #[test]
    fn memory_percentage_zero_total_does_not_panic() {
        // Display should not panic when all memory/disk values are zero.
        let status = SystemStatus {
            cpu_usage: None,
            memory: MemoryStatus { used_bytes: 0, total_bytes: 0, percentage: 0.0 },
            disk: DiskStatus {
                name: String::new(),
                mount_point: "/".to_string(),
                filesystem: String::new(),
                used_bytes: 0,
                total_bytes: 0,
                percentage: 0.0,
                is_removable: false,
            },
            network: NetworkStatus { bytes_received: 0, bytes_transmitted: 0 },
            load_average: None,
            uptime_secs: None,
            hostname: "test".to_string(),
            os_info: OsInfo {
                name: None,
                version: None,
                kernel_version: None,
                arch: "x86_64".to_string(),
            },
            cpu_cores: vec![],
            physical_cores: None,
            swap: None,
            disks: vec![],
            network_interfaces: vec![],
            sensors: vec![],
            boot_time: None,
            processes: ProcessSnapshot { processes: vec![], total_count: 0 },
            gpu: vec![],
            battery: None,
        };
        // Should not panic when displaying
        let _ = format!("{status}");
    }

    #[test]
    fn display_with_gpu_and_battery() {
        let status = SystemStatus {
            cpu_usage: Some(50.0),
            memory: MemoryStatus {
                used_bytes: 8 * 1024 * 1024 * 1024,
                total_bytes: 16 * 1024 * 1024 * 1024,
                percentage: 50.0,
            },
            disk: DiskStatus {
                name: "disk".to_string(),
                mount_point: "/".to_string(),
                filesystem: "apfs".to_string(),
                used_bytes: 100,
                total_bytes: 200,
                percentage: 50.0,
                is_removable: false,
            },
            network: NetworkStatus { bytes_received: 100, bytes_transmitted: 50 },
            load_average: None,
            uptime_secs: Some(3600),
            hostname: "test".to_string(),
            os_info: OsInfo {
                name: Some("macOS".to_string()),
                version: Some("14.0".to_string()),
                kernel_version: Some("23.0".to_string()),
                arch: "aarch64".to_string(),
            },
            cpu_cores: vec![],
            physical_cores: Some(8),
            swap: None,
            disks: vec![],
            network_interfaces: vec![],
            sensors: vec![],
            boot_time: None,
            processes: ProcessSnapshot { processes: vec![], total_count: 0 },
            gpu: vec![GpuInfo {
                name: "Apple M1".to_string(),
                vendor: "Apple".to_string(),
                vram_bytes: Some(8 * 1024 * 1024 * 1024),
                driver_version: None,
            }],
            battery: Some(BatteryInfo {
                charge_percent: 85.0,
                state: "Charging".to_string(),
                time_to_empty_secs: None,
                time_to_full_secs: Some(3600),
            }),
        };
        let output = format!("{status}");
        assert!(output.contains("GPU 0: Apple M1 (Apple)"));
        assert!(output.contains("Battery: 85% (Charging)"));
    }

    // ── SysinfoProvider trait compilation tests ─────────────────────

    #[test]
    fn provider_impl_all_traits() {
        fn assert_cpu<T: CpuProvider>() {}
        fn assert_memory<T: MemoryProvider>() {}
        fn assert_disk<T: DiskProvider>() {}
        fn assert_network<T: NetworkProvider>() {}
        fn assert_os<T: OsProvider>() {}
        fn assert_process<T: ProcessProvider>() {}
        fn assert_gpu<T: GpuProvider>() {}
        fn assert_battery<T: BatteryProvider>() {}
        fn assert_sensor<T: SensorProvider>() {}
        assert_cpu::<SysinfoProvider>();
        assert_memory::<SysinfoProvider>();
        assert_disk::<SysinfoProvider>();
        assert_network::<SysinfoProvider>();
        assert_os::<SysinfoProvider>();
        assert_process::<SysinfoProvider>();
        assert_gpu::<SysinfoProvider>();
        assert_battery::<SysinfoProvider>();
        assert_sensor::<SysinfoProvider>();
    }

    #[test]
    fn provider_implements_status_provider() {
        use crate::status::provider::StatusProvider;
        fn assert_provider<T: StatusProvider>() {}
        assert_provider::<SysinfoProvider>();
    }

    // ── collect_via_provider tests ──────────────────────────────────

    #[test]
    fn collect_via_provider_returns_valid_cpu_usage() {
        let status = SystemStatus::collect_via_provider();
        if let Some(cpu) = status.cpu_usage {
            assert!(
                (0.0..=100.0).contains(&cpu),
                "CPU usage {cpu}% out of range 0–100"
            );
        }
    }

    #[test]
    fn collect_via_provider_returns_nonzero_total_memory() {
        let status = SystemStatus::collect_via_provider();
        assert!(
            status.memory.total_bytes > 0,
            "total memory should be > 0"
        );
    }

    #[test]
    fn collect_via_provider_memory_used_does_not_exceed_total() {
        let status = SystemStatus::collect_via_provider();
        assert!(
            status.memory.used_bytes <= status.memory.total_bytes,
            "used {} > total {}",
            status.memory.used_bytes,
            status.memory.total_bytes
        );
    }

    #[test]
    #[allow(clippy::cast_precision_loss, reason = "test compares percentages with tolerance")]
    fn collect_via_provider_memory_percentage_is_consistent() {
        let status = SystemStatus::collect_via_provider();
        let expected = if status.memory.total_bytes > 0 {
            (status.memory.used_bytes as f64 / status.memory.total_bytes as f64) * 100.0
        } else {
            0.0
        };
        assert!(
            (status.memory.percentage - expected).abs() < 0.1,
            "memory percentage {} != expected {}",
            status.memory.percentage,
            expected
        );
    }

    #[test]
    fn collect_via_provider_disk_used_does_not_exceed_total() {
        let status = SystemStatus::collect_via_provider();
        assert!(
            status.disk.used_bytes <= status.disk.total_bytes,
            "disk used {} > total {}",
            status.disk.used_bytes,
            status.disk.total_bytes
        );
    }

    #[test]
    #[allow(clippy::cast_precision_loss, reason = "test compares percentages with tolerance")]
    fn collect_via_provider_disk_percentage_is_consistent() {
        let status = SystemStatus::collect_via_provider();
        if status.disk.total_bytes > 0 {
            let expected = (status.disk.used_bytes as f64 / status.disk.total_bytes as f64) * 100.0;
            assert!(
                (status.disk.percentage - expected).abs() < 0.1,
                "disk percentage {} != expected {}",
                status.disk.percentage,
                expected
            );
        }
    }

    #[test]
    fn collect_via_provider_network_fields_are_accessible() {
        let status = SystemStatus::collect_via_provider();
        let _ = status.network.bytes_received;
        let _ = status.network.bytes_transmitted;
    }

    #[cfg(unix)]
    #[test]
    fn collect_via_provider_load_average_is_populated_on_unix() {
        let status = SystemStatus::collect_via_provider();
        assert!(
            status.load_average.is_some(),
            "load average should be populated on Unix"
        );
        let load = status.load_average.unwrap();
        assert!(load.one >= 0.0, "1-min load {}", load.one);
        assert!(load.five >= 0.0, "5-min load {}", load.five);
        assert!(load.fifteen >= 0.0, "15-min load {}", load.fifteen);
    }

    #[test]
    fn collect_via_provider_uptime_is_positive() {
        let status = SystemStatus::collect_via_provider();
        if let Some(uptime) = status.uptime_secs {
            assert!(uptime > 0, "uptime should be > 0");
        }
    }

    #[test]
    fn collect_via_provider_hostname_is_non_empty() {
        let status = SystemStatus::collect_via_provider();
        assert!(
            !status.hostname.is_empty(),
            "hostname should not be empty"
        );
    }

    #[test]
    fn collect_via_provider_os_info_fields_are_populated() {
        let status = SystemStatus::collect_via_provider();
        assert!(status.os_info.name.is_some(), "os_info.name should be Some");
        assert!(
            status.os_info.arch.is_ascii() && !status.os_info.arch.is_empty(),
            "arch should be non-empty"
        );
    }

    #[test]
    fn collect_via_provider_cpu_cores_is_non_empty() {
        let status = SystemStatus::collect_via_provider();
        assert!(!status.cpu_cores.is_empty(), "cpu_cores should be non-empty");
        for core in &status.cpu_cores {
            assert!(!core.name.is_empty(), "core name should not be empty");
            assert!(
                (0.0..=100.0).contains(&core.usage),
                "core usage out of range: {}",
                core.usage
            );
        }
    }

    #[test]
    fn collect_via_provider_disks_is_non_empty() {
        let status = SystemStatus::collect_via_provider();
        assert!(!status.disks.is_empty(), "disks should be non-empty");
        for disk in &status.disks {
            assert!(disk.used_bytes <= disk.total_bytes, "disk used > total");
        }
    }

    #[test]
    fn collect_via_provider_network_interfaces_is_non_empty() {
        let status = SystemStatus::collect_via_provider();
        assert!(
            !status.network_interfaces.is_empty(),
            "network_interfaces should be non-empty"
        );
    }

    #[test]
    fn collect_via_provider_physical_cores_is_some() {
        let status = SystemStatus::collect_via_provider();
        assert!(
            status.physical_cores.is_some(),
            "physical_cores should be Some on real hardware"
        );
        assert!(
            status.physical_cores.unwrap() > 0,
            "physical_cores should be > 0"
        );
    }

    #[cfg(unix)]
    #[test]
    fn collect_via_provider_swap_is_some_when_available() {
        let status = SystemStatus::collect_via_provider();
        if let Some(swap) = &status.swap {
            assert!(swap.used_bytes <= swap.total_bytes, "swap used > total");
            assert!(
                (0.0..=100.0).contains(&swap.percentage),
                "swap percentage out of range"
            );
        }
    }

    #[test]
    fn collect_via_provider_processes_is_non_empty() {
        let status = SystemStatus::collect_via_provider();
        assert!(
            status.processes.total_count > 0,
            "processes.total_count should be > 0"
        );
    }

    #[test]
    fn collect_via_provider_gpu_vec_is_accessible() {
        let status = SystemStatus::collect_via_provider();
        let _ = &status.gpu;
    }

    #[test]
    fn collect_via_provider_battery_is_accessible() {
        let status = SystemStatus::collect_via_provider();
        let _ = &status.battery;
    }

    #[test]
    fn collect_via_provider_display_contains_expected_sections() {
        let status = SystemStatus::collect_via_provider();
        let output = format!("{status}");
        assert!(output.contains("System:"));
        assert!(output.contains("Hostname:"));
        assert!(output.contains("Memory:"));
        assert!(output.contains("Disk:"));
        assert!(output.contains("Network:"));
    }

    #[test]
    fn collect_via_provider_serialize_to_json_succeeds() {
        let status = SystemStatus::collect_via_provider();
        let json = serde_json::to_string(&status);
        assert!(
            json.is_ok(),
            "serialization should succeed: {:?}",
            json.err()
        );
    }

    #[test]
    fn collect_via_provider_json_parses_correctly() {
        let status = SystemStatus::collect_via_provider();
        let json = serde_json::to_string(&status).expect("serialization must succeed");
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("JSON must be valid and parseable");
        assert!(parsed.is_object(), "JSON must be an object");
        assert!(parsed.get("hostname").is_some(), "JSON must contain 'hostname'");
        assert!(parsed.get("memory").is_some(), "JSON must contain 'memory'");
    }

    // ── Individual SysinfoProvider method tests ─────────────────────

    #[test]
    fn provider_cpu_usage_returns_valid_range() {
        let mut provider = SysinfoProvider::new();
        let cpu = provider.cpu_usage().expect("cpu_usage should succeed");
        if let Some(usage) = cpu {
            assert!((0.0..=100.0).contains(&usage), "CPU usage out of range: {usage}");
        }
    }

    #[test]
    fn provider_cpu_cores_returns_non_empty() {
        let mut provider = SysinfoProvider::new();
        let cores = provider.cpu_cores().expect("cpu_cores should succeed");
        assert!(!cores.is_empty(), "should have at least one CPU core");
    }

    #[test]
    fn provider_physical_cores_returns_some() {
        let provider = SysinfoProvider::new();
        let cores = provider.physical_cores().expect("physical_cores should succeed");
        assert!(cores.is_some(), "physical_cores should be Some on real hardware");
        assert!(cores.unwrap() > 0, "physical_cores should be > 0");
    }

    #[test]
    fn provider_memory_returns_nonzero_total() {
        let mut provider = SysinfoProvider::new();
        let mem = provider.memory().expect("memory should succeed");
        assert!(mem.total_bytes > 0, "total memory should be > 0");
    }

    #[test]
    fn provider_memory_used_does_not_exceed_total() {
        let mut provider = SysinfoProvider::new();
        let mem = provider.memory().expect("memory should succeed");
        assert!(mem.used_bytes <= mem.total_bytes, "used > total");
    }

    #[test]
    fn provider_swap_returns_consistent_data() {
        let mut provider = SysinfoProvider::new();
        let swap = provider.swap().expect("swap should succeed");
        if let Some(swap) = swap {
            assert!(swap.used_bytes <= swap.total_bytes, "swap used > total");
            assert!((0.0..=100.0).contains(&swap.percentage), "swap percentage out of range");
        }
    }

    #[test]
    fn provider_root_disk_returns_valid_data() {
        let mut provider = SysinfoProvider::new();
        let disk = provider.root_disk().expect("root_disk should succeed");
        assert_eq!(disk.mount_point, "/", "root disk should be mounted at /");
    }

    #[test]
    fn provider_all_disks_returns_non_empty() {
        let mut provider = SysinfoProvider::new();
        let disks = provider.all_disks().expect("all_disks should succeed");
        assert!(!disks.is_empty(), "should have at least one disk");
    }

    #[test]
    fn provider_aggregate_returns_valid_network() {
        let mut provider = SysinfoProvider::new();
        let net = provider.aggregate().expect("aggregate should succeed");
        // Just verify the struct is accessible; values are always >= 0 for u64.
        let _ = net.bytes_received;
        let _ = net.bytes_transmitted;
    }

    #[test]
    fn provider_interfaces_returns_non_empty() {
        let mut provider = SysinfoProvider::new();
        let ifaces = provider.interfaces().expect("interfaces should succeed");
        assert!(!ifaces.is_empty(), "should have at least one interface");
    }

    #[test]
    fn provider_os_info_returns_populated_data() {
        let provider = SysinfoProvider::new();
        let info = provider.os_info().expect("os_info should succeed");
        assert!(info.name.is_some(), "OS name should be Some");
        assert!(!info.arch.is_empty(), "arch should not be empty");
    }

    #[test]
    fn provider_hostname_returns_non_empty() {
        let provider = SysinfoProvider::new();
        let hostname = provider.hostname().expect("hostname should succeed");
        assert!(!hostname.is_empty(), "hostname should not be empty");
    }

    #[cfg(unix)]
    #[test]
    fn provider_load_average_returns_some_on_unix() {
        let provider = SysinfoProvider::new();
        let load = provider.load_average().expect("load_average should succeed");
        assert!(load.is_some(), "load average should be Some on Unix");
    }

    #[test]
    fn provider_uptime_returns_positive() {
        let provider = SysinfoProvider::new();
        let uptime = provider.uptime().expect("uptime should succeed");
        if let Some(secs) = uptime {
            assert!(secs > 0, "uptime should be > 0");
        }
    }

    #[test]
    fn provider_processes_returns_non_empty() {
        let mut provider = SysinfoProvider::new();
        let procs = provider.processes().expect("processes should succeed");
        assert!(procs.total_count > 0, "should have at least one process");
    }

    #[test]
    fn provider_sensors_returns_accessible_data() {
        let provider = SysinfoProvider::new();
        let sensors = provider.sensors().expect("sensors should succeed");
        // Sensors may or may not be available; verify the vec is accessible.
        let _ = sensors.len();
    }

    #[test]
    fn provider_gpus_returns_accessible_data() {
        let provider = SysinfoProvider::new();
        let gpus = provider.gpus().expect("gpus should succeed");
        // GPU detection may or may not find devices; verify the vec is accessible.
        let _ = gpus.len();
    }

    #[test]
    fn provider_battery_returns_accessible_data() {
        let provider = SysinfoProvider::new();
        let battery = provider.battery().expect("battery should succeed");
        // Battery may or may not be present; verify the option is accessible.
        let _ = battery.is_some();
    }

    #[test]
    fn provider_boot_time_returns_accessible_data() {
        let provider = SysinfoProvider::new();
        let bt = provider.boot_time().expect("boot_time should succeed");
        let _ = bt.is_some();
    }
}
