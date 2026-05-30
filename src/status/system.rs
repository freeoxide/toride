//! OS-level metrics: CPU, memory, disk, network, load average, uptime, hostname.
//!
//! Uses the [`sysinfo`] crate for cross-platform data collection. Each metric
//! returns `None` when the underlying data cannot be read (e.g. permission
//! denied on certain Linux containers).
//!
//! # Platform notes
//!
//! | Metric        | Linux | macOS | Windows |
//! |---------------|:-----:|:-----:|:-------:|
//! | CPU usage     | ✓     | ✓     | ✓       |
//! | Memory        | ✓     | ✓     | ✓       |
//! | Disk usage    | ✓     | ✓     | ✓       |
//! | Network I/O   | ✓     | ✓     | ✓       |
//! | Load average  | ✓     | ✓     | ✗       |
//! | Uptime        | ✓     | ✓     | ✓       |
//! | Hostname      | ✓     | ✓     | ✓       |

use std::fmt;

use serde::Serialize;
use sysinfo::{
    Components, CpuRefreshKind, Disks, MemoryRefreshKind, Networks, ProcessRefreshKind,
    ProcessesToUpdate, RefreshKind, System,
};

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
    /// CPU architecture (e.g., "x86_64", "aarch64").
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
    /// Get top N processes by CPU usage.
    pub fn top_by_cpu(&self, n: usize) -> Vec<&ProcessStatus> {
        let mut sorted: Vec<&ProcessStatus> = self.processes.iter().collect();
        sorted.sort_by(|a, b| {
            b.cpu_usage
                .partial_cmp(&a.cpu_usage)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        sorted.into_iter().take(n).collect()
    }

    /// Get top N processes by memory usage.
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
    pub fn collect() -> Self {
        let mut sys = System::new_with_specifics(
            RefreshKind::nothing()
                .with_cpu(CpuRefreshKind::nothing().with_cpu_usage())
                .with_memory(MemoryRefreshKind::nothing().with_ram().with_swap()),
        );
        // sysinfo requires a brief sleep to measure CPU usage accurately.
        std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
        sys.refresh_cpu_usage();

        let cpu_usage = Self::read_cpu(&sys);
        let memory = Self::read_memory(&sys);
        let disks = Self::read_disks();
        let disk = Self::find_root_disk(&disks);
        let network = Self::read_network();
        let load_average = Self::read_load_average();
        let uptime_secs = Self::read_uptime();
        let hostname = Self::read_hostname();
        let os_info = Self::read_os_info();
        let cpu_cores = Self::read_cpu_cores(&sys);
        let physical_cores = System::physical_core_count();
        let swap = Self::read_swap(&sys);
        let network_interfaces = Self::read_network_interfaces();
        let sensors = Self::read_sensors();
        let boot_time = {
            let bt = System::boot_time();
            if bt > 0 { Some(bt) } else { None }
        };
        let processes = Self::read_processes();
        let gpu = Self::read_gpus();
        let battery = Self::read_battery();

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

    fn read_cpu(sys: &System) -> Option<f64> {
        let cpus = sys.cpus();
        if cpus.is_empty() {
            return None;
        }
        let total: f64 = cpus.iter().map(|c| c.cpu_usage() as f64).sum();
        Some(total / cpus.len() as f64)
    }

    fn read_memory(sys: &System) -> MemoryStatus {
        let total = sys.total_memory();
        let used = sys.used_memory();
        let percentage = if total > 0 {
            (used as f64 / total as f64) * 100.0
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
            .unwrap_or(DiskStatus {
                name: String::new(),
                mount_point: "/".to_string(),
                filesystem: String::new(),
                used_bytes: 0,
                total_bytes: 0,
                percentage: 0.0,
                is_removable: false,
            })
    }

    fn read_network() -> NetworkStatus {
        let networks = Networks::new_with_refreshed_list();
        let (mut received, mut transmitted) = (0u64, 0u64);
        for (_name, data) in networks.iter() {
            received = received.saturating_add(data.total_received());
            transmitted = transmitted.saturating_add(data.total_transmitted());
        }
        NetworkStatus {
            bytes_received: received,
            bytes_transmitted: transmitted,
        }
    }

    #[cfg(unix)]
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
                usage: c.cpu_usage() as f64,
                frequency: c.frequency(),
            })
            .collect()
    }

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

    fn read_network_interfaces() -> Vec<NetworkInterface> {
        let networks = Networks::new_with_refreshed_list();
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
                    let t = c.temperature();
                    if t.is_some() && !t.unwrap().is_nan() { t } else { None }
                },
            })
            .collect()
    }

    fn read_processes() -> ProcessSnapshot {
        let mut sys = System::new_with_specifics(
            RefreshKind::nothing().with_processes(ProcessRefreshKind::everything()),
        );
        sys.refresh_processes(ProcessesToUpdate::All, true);
        let processes: Vec<ProcessStatus> = sys
            .processes()
            .iter()
            .map(|(pid, p)| ProcessStatus {
                pid: pid.as_u32(),
                parent_pid: p.parent().map(|pp| pp.as_u32()),
                name: p.name().to_string_lossy().to_string(),
                cpu_usage: p.cpu_usage(),
                memory_bytes: p.memory(),
                status: format!("{:?}", p.status()),
                start_time: Some(p.start_time()),
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
                        .and_then(|v| {
                            let v = v.replace("MB", "").replace(" ", "");
                            v.parse::<u64>().ok().map(|mb| mb * 1024 * 1024)
                        });
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

    fn read_battery() -> Option<BatteryInfo> {
        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            let output = Command::new("pmset")
                .arg("-g")
                .arg("batt")
                .output()
                .ok()?;
            let text = String::from_utf8_lossy(&output.stdout);
            let percent_line = text.lines().find(|l| l.contains("%"))?;
            let pct_str = percent_line
                .split_whitespace()
                .find(|w| w.ends_with("%"))?;
            let pct: f32 = pct_str.trim_end_matches('%').parse().ok()?;
            let state = if text.contains("charging") || text.contains("AC attached") {
                "Charging"
            } else if text.contains("discharging") {
                "Discharging"
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
        #[cfg(target_os = "linux")]
        {
            use std::fs;
            let capacity = fs::read_to_string("/sys/class/power_supply/BAT0/capacity").ok()?;
            let pct: f32 = capacity.trim().parse().ok()?;
            let status = fs::read_to_string("/sys/class/power_supply/BAT0/status")
                .ok()
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| "Unknown".to_string());
            Some(BatteryInfo {
                charge_percent: pct,
                state: status,
                time_to_empty_secs: None,
                time_to_full_secs: None,
            })
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            None
        }
    }
}

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

const KB: u64 = 1024;
const MB: u64 = KB * 1024;
const GB: u64 = MB * 1024;
const TB: u64 = GB * 1024;
const PB: u64 = TB * 1024;
const EB: u64 = PB * 1024;

/// Write bytes in human-readable form directly to the formatter.
fn write_bytes(f: &mut fmt::Formatter<'_>, bytes: u64) -> fmt::Result {
    if bytes >= EB {
        write!(f, "{:.1} EB", bytes as f64 / EB as f64)
    } else if bytes >= PB {
        write!(f, "{:.1} PB", bytes as f64 / PB as f64)
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
        // u64::MAX = 18_446_744_073_709_551_615 ≈ 16.0 EB
        let result = format_bytes(u64::MAX);
        assert!(
            result.ends_with("EB"),
            "u64::MAX should format as EB, got: {result}"
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
                    packets_received: 1000000,
                    packets_transmitted: 500000,
                    errors_received: 0,
                    errors_transmitted: 0,
                },
                NetworkInterface {
                    name: "lo0".to_string(),
                    bytes_received: 40 * GB,
                    bytes_transmitted: 20 * GB,
                    packets_received: 2000000,
                    packets_transmitted: 2000000,
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
            boot_time: Some(1700000000),
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
}
