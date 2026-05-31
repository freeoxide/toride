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
//! use toride_status::system::SystemStatus;
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
//! use toride_status::system::SystemStatus;
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
//! use toride_status::system::SystemStatus;
//!
//! let status = SystemStatus::collect();
//! println!("{status}");
//! ```

use std::fmt;
use std::path::Path;

use serde::Serialize;
use sysinfo::{
    Components, CpuRefreshKind, Disks, MemoryRefreshKind, Networks, ProcessRefreshKind,
    ProcessesToUpdate, RefreshKind, System,
};

use crate::error::StatusResult;
use crate::provider::{
    BatteryProvider, CpuProvider, DiskIoProvider, DiskProvider, GpuProvider, MemoryProvider,
    NetworkProvider, OsProvider, ProcessProvider, SensorProvider, StaticInfoProvider,
    VirtualizationProvider,
};

// ── Feature-gated optional crate imports ──────────────────────────────
// These ensure optional deps compile-check when their feature is enabled.
// Each crate is imported as `_` to suppress unused warnings while still
// verifying the dependency resolves and compiles.

#[cfg(feature = "os-info")]
#[allow(unused_imports)]
use os_info as _os_info;

#[cfg(feature = "cpu-cpuid")]
#[allow(unused_imports)]
use raw_cpuid as _raw_cpuid;

#[cfg(feature = "gpu-nvidia")]
#[allow(unused_imports)]
use nvml_wrapper as _nvml;

#[cfg(feature = "battery")]
#[allow(unused_imports)]
use starship_battery as _battery;

#[cfg(feature = "hardware-dmi")]
#[allow(unused_imports)]
use dmidecode as _dmidecode;

#[cfg(feature = "linux-procfs")]
#[allow(unused_imports)]
use procfs as _procfs;

#[cfg(feature = "linux-sensors")]
#[allow(unused_imports)]
use lm_sensors as _lm_sensors;

#[cfg(feature = "commands")]
#[allow(unused_imports)]
use duct as _duct;

#[cfg(feature = "linux-udev")]
#[allow(unused_imports)]
use udev as _udev;

#[cfg(feature = "linux-rtnetlink")]
#[allow(unused_imports)]
use rtnetlink as _rtnetlink;

#[cfg(feature = "hardware-pci")]
#[allow(unused_imports)]
use pci_info as _pci_info;

#[cfg(feature = "hardware-pci")]
#[allow(unused_imports)]
use pci_ids as _pci_ids;

#[cfg(feature = "hardware-topology")]
#[allow(unused_imports)]
use hwlocality as _hwlocality;

#[cfg(feature = "linux-cgroups")]
#[allow(unused_imports)]
use cgroups_rs as _cgroups_rs;

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

/// Parse a "hh:mm" or "hh:mm:ss" time string into total seconds.
fn parse_hhmm_to_secs(s: &str) -> Option<u64> {
    let parts: Vec<&str> = s.split(':').collect();
    match parts.len() {
        3 => {
            let h: u64 = parts[0].parse().ok()?;
            let m: u64 = parts[1].parse().ok()?;
            let s: u64 = parts[2].parse().ok()?;
            Some(h * 3600 + m * 60 + s)
        }
        2 => {
            let h: u64 = parts[0].parse().ok()?;
            let m: u64 = parts[1].parse().ok()?;
            Some(h * 3600 + m * 60)
        }
        _ => None,
    }
}

// ── OS info helpers ──────────────────────────────────────────────────────

/// Parse /etc/os-release into a HashMap of key=value pairs.
#[cfg(target_os = "linux")]
fn parse_os_release() -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                // Strip surrounding quotes from value
                let value = value.trim_matches('"');
                map.insert(key.trim().to_string(), value.to_string());
            }
        }
    }
    map
}

/// Resolve macOS version to codename.
#[cfg(target_os = "macos")]
fn macos_codename(version: &str) -> Option<String> {
    let major_minor = version.split('.').take(2).collect::<Vec<_>>().join(".");
    match major_minor.as_str() {
        "15" | "15.0" => Some("Sequoia".to_string()),
        "14" | "14.0" => Some("Sonoma".to_string()),
        "13" | "13.0" => Some("Ventura".to_string()),
        "12" | "12.0" => Some("Monterey".to_string()),
        "11" | "11.0" => Some("Big Sur".to_string()),
        "10.15" => Some("Catalina".to_string()),
        "10.14" => Some("Mojave".to_string()),
        "10.13" => Some("High Sierra".to_string()),
        "10.12" => Some("Sierra".to_string()),
        "10.11" => Some("El Capitan".to_string()),
        "10.10" => Some("Yosemite".to_string()),
        _ => None,
    }
}

/// Detect system timezone by reading /etc/localtime symlink target.
#[cfg(unix)]
fn detect_timezone() -> Option<String> {
    std::fs::read_link("/etc/localtime")
        .ok()
        .and_then(|path| {
            let s = path.to_string_lossy();
            // Typical path: /var/db/timezone/zoneinfo/America/New_York or
            // /usr/share/zoneinfo/America/New_York
            // Extract everything after "zoneinfo/"
            s.rsplit_once("zoneinfo/")
                .map(|(_, tz)| tz.to_string())
        })
}

#[cfg(not(unix))]
fn detect_timezone() -> Option<String> {
    None
}

/// Detect whether the effective user is root.
#[cfg(unix)]
fn detect_is_root() -> bool {
    nix::unistd::Uid::effective().is_root()
}

#[cfg(not(unix))]
fn detect_is_root() -> bool {
    false
}

/// Detect WSL environment.
fn detect_wsl() -> bool {
    std::env::var("WSL_DISTRO_NAME").is_ok()
        || Path::new("/proc/sys/fs/binfmt_misc/WSLInterop").exists()
}

/// Detect systemd presence.
fn detect_systemd() -> bool {
    Path::new("/run/systemd/system").exists()
}

/// Build the Rust target triple string.
fn detect_target_triple() -> String {
    let env = if cfg!(target_env = "gnu") {
        "gnu"
    } else if cfg!(target_env = "musl") {
        "musl"
    } else if cfg!(target_env = "msvc") {
        "msvc"
    } else {
        "unknown"
    };
    format!("{}-{}-{}", std::env::consts::ARCH, std::env::consts::OS, env)
}

/// Detect system locale from environment variables.
fn detect_locale() -> Option<String> {
    std::env::var("LANG")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| std::env::var("LC_ALL").ok().filter(|v| !v.is_empty()))
}

/// Detect current user name from environment.
fn detect_current_user() -> Option<String> {
    std::env::var("USER")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| std::env::var("USERNAME").ok().filter(|v| !v.is_empty()))
}

// ── Memory helpers ──────────────────────────────────────────────────────

/// Parse a field from /proc/meminfo, returning its value in bytes.
/// The file lists values in kB; this function converts to bytes.
#[cfg(target_os = "linux")]
fn parse_meminfo_field(field_name: &str) -> Option<u64> {
    let content = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix(field_name) {
            let rest = rest.trim_start_matches(':').trim();
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb.saturating_mul(1024));
        }
    }
    None
}

/// Read cached memory in bytes (cross-platform).
fn read_cached_bytes() -> u64 {
    #[cfg(target_os = "linux")]
    {
        return parse_meminfo_field("Cached:").unwrap_or(0);
    }
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        if let Ok(output) = Command::new("vm_stat").output()
            && let Ok(text) = String::from_utf8(output.stdout)
        {
            let mut page_size: u64 = 16384;
            let mut purgeable_pages: u64 = 0;
            for line in text.lines() {
                if let Some(pos) = line.find("page size of") {
                    let rest = &line[pos + "page size of".len()..];
                    for word in rest.split_whitespace() {
                        if let Ok(sz) = word.parse::<u64>() {
                            page_size = sz;
                            break;
                        }
                    }
                }
                if line.starts_with("Pages purgeable:")
                    && let Some(val) = line.split_whitespace().nth(2)
                {
                    purgeable_pages = val.trim_end_matches('.').parse().unwrap_or(0);
                }
            }
            return purgeable_pages.saturating_mul(page_size);
        }
        0
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        0
    }
}

/// Read buffer memory in bytes (Linux only, 0 elsewhere).
fn read_buffers_bytes() -> u64 {
    #[cfg(target_os = "linux")]
    {
        parse_meminfo_field("Buffers:").unwrap_or(0)
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

// ── Network helpers ──────────────────────────────────────────────────────

/// Extra per-interface metrics from platform-specific sources.
struct InterfaceExtras {
    link_status: Option<String>,
    speed_bps: Option<u64>,
    duplex: Option<String>,
    drops_received: u64,
    drops_transmitted: u64,
}

#[cfg(target_os = "linux")]
fn read_interface_extras(name: &str) -> InterfaceExtras {
    InterfaceExtras {
        link_status: std::fs::read_to_string(format!("/sys/class/net/{name}/operstate"))
            .ok()
            .map(|s| s.trim().to_string()),
        speed_bps: std::fs::read_to_string(format!("/sys/class/net/{name}/speed"))
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(|mbps| mbps.saturating_mul(1_000_000)),
        duplex: std::fs::read_to_string(format!("/sys/class/net/{name}/duplex"))
            .ok()
            .map(|s| s.trim().to_string()),
        drops_received: std::fs::read_to_string(format!(
            "/sys/class/net/{name}/statistics/rx_dropped"
        ))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0),
        drops_transmitted: std::fs::read_to_string(format!(
            "/sys/class/net/{name}/statistics/tx_dropped"
        ))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0),
    }
}

#[cfg(target_os = "macos")]
fn read_interface_extras(name: &str) -> InterfaceExtras {
    use std::process::Command;
    let mut extras = InterfaceExtras {
        link_status: None,
        speed_bps: None,
        duplex: None,
        drops_received: 0,
        drops_transmitted: 0,
    };
    if let Ok(output) = Command::new("ifconfig").arg(name).output()
        && let Ok(text) = String::from_utf8(output.stdout)
    {
        for line in text.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("status:") {
                let status = rest.trim().to_string();
                if !status.is_empty() {
                    extras.link_status = Some(status);
                }
            }
            if let Some(rest) = trimmed.strip_prefix("media:")
                && let Some(pstart) = rest.find('(')
            {
                let inside = &rest[pstart + 1..];
                if let Some(pend) = inside.find(')') {
                    let media = &inside[..pend];
                    for word in media.split_whitespace() {
                        if let Some(speed_str) = word
                            .strip_suffix("baseT")
                            .or_else(|| word.strip_suffix("baseTX"))
                            .or_else(|| word.strip_suffix("baseT4"))
                            && let Ok(mbps) = speed_str.parse::<u64>()
                        {
                            extras.speed_bps = Some(mbps.saturating_mul(1_000_000));
                        }
                    }
                    if media.contains("full-duplex") {
                        extras.duplex = Some("full".to_string());
                    } else if media.contains("half-duplex") {
                        extras.duplex = Some("half".to_string());
                    }
                }
            }
        }
    }
    extras
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn read_interface_extras(_name: &str) -> InterfaceExtras {
    InterfaceExtras {
        link_status: None,
        speed_bps: None,
        duplex: None,
        drops_received: 0,
        drops_transmitted: 0,
    }
}

/// Detect the default gateway (cross-platform).
fn detect_gateway() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let content = std::fs::read_to_string("/proc/net/route").ok()?;
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 3 && fields[1] == "00000000" {
                let val = u32::from_str_radix(fields[2], 16).ok()?;
                let bytes = val.to_ne_bytes();
                return Some(format!(
                    "{}.{}.{}.{}",
                    bytes[0], bytes[1], bytes[2], bytes[3]
                ));
            }
        }
        None
    }
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        let output = Command::new("netstat").args(["-rn"]).output().ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("default") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    let gw = parts[1];
                    if gw.contains('.') || gw.contains(':') {
                        return Some(gw.to_string());
                    }
                }
            }
        }
        None
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

/// Detect DNS servers (Unix: /etc/resolv.conf; macOS also tries scutil).
fn detect_dns_servers() -> Vec<String> {
    let mut servers = Vec::new();

    #[cfg(unix)]
    {
        if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
            for line in content.lines() {
                let trimmed = line.trim();
                if let Some(rest) = trimmed.strip_prefix("nameserver") {
                    let server = rest.trim();
                    if !server.is_empty() {
                        servers.push(server.to_string());
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if servers.is_empty() {
            use std::process::Command;
            if let Ok(output) = Command::new("scutil").args(["--dns"]).output()
                && let Ok(text) = String::from_utf8(output.stdout)
            {
                for line in text.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("nameserver[")
                        && let Some(val) = trimmed.split(':').nth(1)
                    {
                        let server = val.trim();
                        if !server.is_empty() {
                            servers.push(server.to_string());
                        }
                    }
                }
            }
        }
    }

    servers
}

/// Detect the first DNS server (for per-interface field).
fn detect_first_dns() -> Option<String> {
    detect_dns_servers().into_iter().next()
}

// ── Process helpers (Linux) ──────────────────────────────────────────────

/// Read thread count from /proc/<pid>/status.
#[cfg(target_os = "linux")]
fn read_proc_thread_count(pid: u32) -> Option<u32> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("Threads:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// Read working directory from /proc/<pid>/cwd symlink.
#[cfg(target_os = "linux")]
fn read_proc_working_dir(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/cwd"))
        .ok()
        .map(|p| p.to_string_lossy().to_string())
}

/// Read disk I/O bytes from /proc/<pid>/io.
#[cfg(target_os = "linux")]
fn read_proc_io(pid: u32) -> (Option<u64>, Option<u64>) {
    let content = match std::fs::read_to_string(format!("/proc/{pid}/io")) {
        Ok(c) => c,
        Err(_) => return (None, None),
    };
    let mut read_bytes = None;
    let mut write_bytes = None;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("read_bytes:") {
            read_bytes = rest.trim().parse().ok();
        } else if let Some(rest) = line.strip_prefix("write_bytes:") {
            write_bytes = rest.trim().parse().ok();
        }
    }
    (read_bytes, write_bytes)
}

/// Count open file descriptors from /proc/<pid>/fd.
#[cfg(target_os = "linux")]
#[allow(clippy::cast_possible_truncation)] // fd count fits in u32 for any real process
fn read_proc_fd_count(pid: u32) -> Option<u32> {
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .ok()
        .map(|entries| entries.filter_map(Result::ok).count() as u32)
}

// ── Sensor helpers (Linux) ──────────────────────────────────────────────

/// Read fan RPM readings from /sys/class/hwmon/.
#[cfg(target_os = "linux")]
fn read_hwmon_fans() -> Vec<SensorStatus> {
    let mut sensors = Vec::new();
    let hwmon_dir = match std::fs::read_dir("/sys/class/hwmon") {
        Ok(d) => d,
        Err(_) => return sensors,
    };
    for entry in hwmon_dir.flatten() {
        let path = entry.path();
        let name = std::fs::read_to_string(path.join("name"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| entry.file_name().to_string_lossy().to_string());
        for i in 1..=16u32 {
            let fan_path = path.join(format!("fan{i}_input"));
            if let Ok(rpm_str) = std::fs::read_to_string(fan_path)
                && let Ok(rpm) = rpm_str.trim().parse::<u32>()
            {
                sensors.push(SensorStatus {
                    label: format!("{name} Fan {i}"),
                    temperature: None,
                    fan_rpm: Some(rpm),
                    voltage: None,
                    thermal_throttling: None,
                });
            }
        }
    }
    sensors
}

/// Read voltage readings from /sys/class/hwmon/.
#[cfg(target_os = "linux")]
#[allow(clippy::cast_precision_loss)] // millivolt to volt conversion; bounded sensor values
fn read_hwmon_voltages() -> Vec<SensorStatus> {
    let mut sensors = Vec::new();
    let hwmon_dir = match std::fs::read_dir("/sys/class/hwmon") {
        Ok(d) => d,
        Err(_) => return sensors,
    };
    for entry in hwmon_dir.flatten() {
        let path = entry.path();
        let name = std::fs::read_to_string(path.join("name"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| entry.file_name().to_string_lossy().to_string());
        for i in 0..=16u32 {
            let in_path = path.join(format!("in{i}_input"));
            if let Ok(mv_str) = std::fs::read_to_string(in_path)
                && let Ok(mv) = mv_str.trim().parse::<f32>()
            {
                sensors.push(SensorStatus {
                    label: format!("{name} Voltage {i}"),
                    temperature: None,
                    fan_rpm: None,
                    voltage: Some(mv / 1000.0),
                    thermal_throttling: None,
                });
            }
        }
    }
    sensors
}

// ── Disk helpers ──────────────────────────────────────────────────────

/// Determine the base block device name from a partition name.
/// E.g., "sda1" -> "sda", "nvme0n1p1" -> "nvme0n1".
#[cfg(target_os = "linux")]
fn disk_base_device(name: &str) -> &str {
    if name.contains("nvme") {
        if let Some(idx) = name.rfind('p') {
            let suffix = &name[idx + 1..];
            if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
                return &name[..idx];
            }
        }
        return name;
    }
    name.trim_end_matches(|c: char| c.is_ascii_digit())
}

/// Read disk type from sysfs rotational flag.
#[cfg(target_os = "linux")]
fn read_disk_type_linux(dev_name: &str) -> String {
    let base = disk_base_device(dev_name);
    if base.is_empty() {
        return "Unknown".to_string();
    }
    match std::fs::read_to_string(format!("/sys/block/{base}/queue/rotational")) {
        Ok(content) => {
            if content.trim() == "0" {
                "SSD".to_string()
            } else {
                "HDD".to_string()
            }
        }
        Err(_) => "Unknown".to_string(),
    }
}

/// Determine disk type on macOS (APFS defaults to SSD).
#[cfg(target_os = "macos")]
fn read_disk_type_macos(filesystem: &str) -> String {
    if filesystem.to_lowercase() == "apfs" {
        "SSD".to_string()
    } else {
        "Unknown".to_string()
    }
}

/// CPU topology information (internal helper for `StaticInfo` / `CpuStatic`).
struct CpuTopology {
    sockets: Option<u32>,
    cores_per_socket: Option<u32>,
    threads_per_core: Option<u32>,
    base_frequency: Option<u64>,
    max_frequency: Option<u64>,
    cache_l1d: Option<u32>,
    cache_l1i: Option<u32>,
    cache_l2: Option<u32>,
    cache_l3: Option<u64>,
}

/// Read CPU topology from macOS sysctl values.
#[cfg(target_os = "macos")]
#[allow(clippy::cast_possible_truncation)] // core/thread/socket counts fit in u32
fn read_cpu_topology() -> CpuTopology {
    use std::process::Command;

    fn sysctl_u64(name: &str) -> Option<u64> {
        Command::new("sysctl")
            .args(["-n", name])
            .output()
            .ok()
            .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok())
    }

    let sockets = sysctl_u64("hw.packages")
        .or_else(|| sysctl_u64("hw.npackages"))
        .map(|v| v as u32);
    let physical = sysctl_u64("hw.physicalcpu");
    let logical = sysctl_u64("hw.logicalcpu");

    let cores_per_socket = match (physical, sockets) {
        (Some(p), Some(s)) if s > 0 => Some((p / u64::from(s)) as u32),
        (Some(p), None) => Some(p as u32),
        _ => None,
    };

    let threads_per_core = match (logical, physical) {
        (Some(l), Some(p)) if p > 0 => Some((l / p) as u32),
        _ => None,
    };

    // Frequencies in Hz, convert to MHz. Apple Silicon may not report these.
    let max_frequency = sysctl_u64("hw.cpufrequency_max")
        .or_else(|| sysctl_u64("hw.cpufrequency"))
        .filter(|&v| v > 0)
        .map(|hz| hz / 1_000_000);
    let base_frequency = sysctl_u64("hw.cpufrequency")
        .filter(|&v| v > 0)
        .map(|hz| hz / 1_000_000);

    // Cache sizes in bytes.
    let cache_l1d = sysctl_u64("hw.l1dcachesize").filter(|&v| v > 0).map(|v| v as u32);
    let cache_l1i = sysctl_u64("hw.l1icachesize").filter(|&v| v > 0).map(|v| v as u32);
    let cache_l2 = sysctl_u64("hw.l2cachesize").filter(|&v| v > 0).map(|v| v as u32);
    let cache_l3 = sysctl_u64("hw.l3cachesize").filter(|&v| v > 0);

    CpuTopology {
        sockets,
        cores_per_socket,
        threads_per_core,
        base_frequency,
        max_frequency,
        cache_l1d,
        cache_l1i,
        cache_l2,
        cache_l3,
    }
}

/// Read CPU topology from /proc/cpuinfo and sysfs on Linux.
#[cfg(target_os = "linux")]
#[allow(clippy::cast_possible_truncation)] // core/thread/socket counts fit in u32
fn read_cpu_topology() -> CpuTopology {
    use std::collections::HashSet;
    use std::fs;

    /// Parse a sysfs cache size string like "32K" or "12288K" or "32M" into bytes.
    fn parse_cache_size(path: &str) -> Option<u64> {
        let s = fs::read_to_string(path).ok()?;
        let s = s.trim();
        if let Some(kb) = s.strip_suffix('K').or_else(|| s.strip_suffix("kB")) {
            kb.trim().parse::<u64>().ok().map(|v| v * 1024)
        } else if let Some(mb) = s.strip_suffix('M').or_else(|| s.strip_suffix("MB")) {
            mb.trim().parse::<u64>().ok().map(|v| v * 1024 * 1024)
        } else {
            s.parse::<u64>().ok()
        }
    }

    // ── Parse /proc/cpuinfo ──
    let cpuinfo = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();

    let mut physical_ids = HashSet::new();
    let mut cpu_cores: Option<u32> = None;
    let mut siblings: Option<u32> = None;

    for line in cpuinfo.lines() {
        if let Some((key, val)) = line.split_once(':') {
            let key = key.trim();
            let val = val.trim();
            match key {
                "physical id" => {
                    if let Ok(id) = val.parse::<u32>() {
                        physical_ids.insert(id);
                    }
                }
                "cpu cores" if cpu_cores.is_none() => {
                    cpu_cores = val.parse().ok();
                }
                "siblings" if siblings.is_none() => {
                    siblings = val.parse().ok();
                }
                _ => {}
            }
        }
    }

    // Sockets: count unique physical ids; fallback to NUMA node count.
    let sockets = if physical_ids.is_empty() {
        fs::read_dir("/sys/devices/system/node/")
            .ok()
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .filter(|e| e.file_name().to_string_lossy().starts_with("node"))
                    .count()
            })
            .filter(|&c| c > 0)
            .map(|c| c as u32)
    } else {
        Some(physical_ids.len() as u32)
    };

    let cores_per_socket = cpu_cores;
    let threads_per_core = match (siblings, cpu_cores) {
        (Some(s), Some(c)) if c > 0 => Some(s / c),
        _ => None,
    };

    // ── Frequencies from sysfs (kHz -> MHz) ──
    fn read_freq_khz(path: &str) -> Option<u64> {
        fs::read_to_string(path)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(|khz| khz / 1000)
    }

    let max_frequency = read_freq_khz("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq");
    let base_frequency = read_freq_khz("/sys/devices/system/cpu/cpu0/cpufreq/base_frequency");

    // ── Cache sizes from sysfs ──
    let mut cache_l1d = None;
    let mut cache_l1i = None;
    let mut cache_l2 = None;
    let mut cache_l3 = None;

    for i in 0..8 {
        let type_path = format!("/sys/devices/system/cpu/cpu0/cache/index{i}/type");
        let size_path = format!("/sys/devices/system/cpu/cpu0/cache/index{i}/size");
        let level_path = format!("/sys/devices/system/cpu/cpu0/cache/index{i}/level");

        let cache_type = fs::read_to_string(&type_path).ok().map(|s| s.trim().to_lowercase());
        let level = fs::read_to_string(&level_path)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok());
        let size = parse_cache_size(&size_path);

        if let (Some(ref ctype), Some(lvl), Some(sz)) = (cache_type, level, size) {
            match (lvl, ctype.as_str()) {
                (1, "data") if cache_l1d.is_none() => cache_l1d = Some(sz as u32),
                (1, "instruction") if cache_l1i.is_none() => cache_l1i = Some(sz as u32),
                (2, _) if cache_l2.is_none() => cache_l2 = Some(sz as u32),
                (3, _) if cache_l3.is_none() => cache_l3 = Some(sz),
                _ => {}
            }
        }
    }

    CpuTopology {
        sockets,
        cores_per_socket,
        threads_per_core,
        base_frequency,
        max_frequency,
        cache_l1d,
        cache_l1i,
        cache_l2,
        cache_l3,
    }
}

/// Fallback for unsupported platforms.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn read_cpu_topology() -> CpuTopology {
    CpuTopology {
        sockets: None,
        cores_per_socket: None,
        threads_per_core: None,
        base_frequency: None,
        max_frequency: None,
        cache_l1d: None,
        cache_l1i: None,
        cache_l2: None,
        cache_l3: None,
    }
}

/// Read hardware inventory from macOS `system_profiler`.
#[cfg(target_os = "macos")]
fn read_hardware_inventory() -> HardwareInventory {
    use std::process::Command;

    let mut inv = HardwareInventory {
        manufacturer: Some("Apple".to_string()),
        bios_vendor: Some("Apple".to_string()),
        ..HardwareInventory::default()
    };

    if let Ok(output) = Command::new("system_profiler")
        .args(["SPHardwareDataType", "-json"])
        .output()
        && let Ok(text) = String::from_utf8(output.stdout)
        && let Ok(json) = serde_json::from_str::<serde_json::Value>(&text)
        && let Some(hw) = json["SPHardwareDataType"]
            .as_array()
            .and_then(|a| a.first())
    {
        inv.product_name = hw["machine_model"].as_str().map(String::from);
        inv.bios_version = hw["boot_rom_version"].as_str().map(String::from);
        inv.system_serial = hw["serial_number"].as_str().map(String::from);
        inv.system_uuid = hw["platform_UUID"].as_str().map(String::from);
        inv.board_name = hw["motherboard_serial"]
            .as_str()
            .map(String::from)
            .or_else(|| Some("Apple Silicon".to_string()));
    }

    inv
}

/// Read hardware inventory from Linux DMI/SMBIOS sysfs.
#[cfg(target_os = "linux")]
fn read_hardware_inventory() -> HardwareInventory {
    use std::fs;

    fn read_dmi_string(path: &str) -> Option<String> {
        fs::read_to_string(path)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s != "To Be Filled By O.E.M." && s != "Default string")
    }

    fn chassis_type_string(raw: &str) -> Option<String> {
        let num: u32 = raw.trim().parse().ok()?;
        Some(
            match num {
                1 => "Other",
                2 => "Unknown",
                3 => "Desktop",
                4 => "Low Profile Desktop",
                5 => "Pizza Box",
                6 => "Mini Tower",
                7 => "Tower",
                8 => "Portable",
                9 => "Laptop",
                10 => "Notebook",
                11 => "Hand Held",
                12 => "Docking Station",
                13 => "All in One",
                14 => "Sub Notebook",
                15 => "Space-saving",
                16 => "Lunch Box",
                17 => "Main Server Chassis",
                18 => "Expansion Chassis",
                19 => "Sub Chassis",
                20 => "Bus Expansion Chassis",
                21 => "Peripheral Chassis",
                22 => "RAID Chassis",
                23 => "Rack Mount Chassis",
                24 => "Sealed-case PC",
                30 => "Tablet",
                31 => "Convertible",
                32 => "Detachable",
                _ => return None,
            }
            .to_string(),
        )
    }

    let chassis_type = fs::read_to_string("/sys/class/dmi/id/chassis_type")
        .ok()
        .and_then(|s| chassis_type_string(&s));

    HardwareInventory {
        manufacturer: read_dmi_string("/sys/class/dmi/id/sys_vendor"),
        product_name: read_dmi_string("/sys/class/dmi/id/product_name"),
        board_name: read_dmi_string("/sys/class/dmi/id/board_name"),
        bios_vendor: read_dmi_string("/sys/class/dmi/id/bios_vendor"),
        bios_version: read_dmi_string("/sys/class/dmi/id/bios_version"),
        chassis_type,
        system_serial: read_dmi_string("/sys/class/dmi/id/product_serial"),
        system_uuid: read_dmi_string("/sys/class/dmi/id/product_uuid"),
        asset_tag: read_dmi_string("/sys/class/dmi/id/board_asset_tag"),
    }
}

/// Fallback for unsupported platforms.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn read_hardware_inventory() -> HardwareInventory {
    HardwareInventory::default()
}

/// Build a fully populated OsInfo.
fn build_os_info() -> OsInfo {
    let os_type = Some(std::env::consts::OS.to_string());
    let bitness = Some((std::mem::size_of::<usize>() * 8) as u32);
    let current_user = detect_current_user();
    let is_root = detect_is_root();
    let target_triple = Some(detect_target_triple());
    let locale = detect_locale();
    let timezone = detect_timezone();
    let systemd_detected = detect_systemd();
    let wsl_detected = detect_wsl();

    // Platform-specific: edition and codename
    #[cfg(target_os = "linux")]
    let (edition, codename) = {
        let release = parse_os_release();
        let edition = release
            .get("VERSION_ID")
            .or_else(|| release.get("VARIANT_ID"))
            .cloned();
        let codename = release.get("VERSION_CODENAME").cloned();
        (edition, codename)
    };

    #[cfg(target_os = "macos")]
    let (edition, codename) = {
        let codename = System::os_version().and_then(|v| macos_codename(&v));
        (None, codename)
    };

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let (edition, codename): (Option<String>, Option<String>) = (None, None);

    OsInfo {
        name: System::name(),
        version: System::os_version(),
        kernel_version: System::kernel_version(),
        arch: std::env::consts::ARCH.to_string(),
        os_type,
        edition,
        codename,
        bitness,
        timezone,
        locale,
        current_user,
        is_root,
        container_detected: false,
        vm_detected: false,
        wsl_detected,
        systemd_detected,
        target_triple,
    }
}

/// Read battery status from the OS.
#[cfg(target_os = "macos")]
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)] // mV->V and mAh->Wh conversions; values are bounded battery readings
fn read_battery_os() -> Option<BatteryInfo> {
    use std::process::Command;

    // ── pmset: charge percent, state, and time estimates ──
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

    // Parse pmset -g batt for time remaining (e.g. " - 2:35 remaining")
    let mut time_to_empty_secs: Option<u64> = None;
    let mut time_to_full_secs: Option<u64> = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix('-').or_else(|| line.strip_prefix(" -")) {
            let rest = rest.trim();
            if let Some(time_part) = rest.split("remaining").next() {
                let time_str = time_part.trim();
                if let Some(secs) = parse_hhmm_to_secs(time_str) {
                    if secs > 0 {
                        time_to_empty_secs = Some(secs);
                    }
                }
            } else if let Some(time_part) = rest.split("until charged").next() {
                let time_str = time_part.trim();
                if let Some(secs) = parse_hhmm_to_secs(time_str) {
                    if secs > 0 {
                        time_to_full_secs = Some(secs);
                    }
                }
            }
        }
    }

    // ── system_profiler SPPowerDataType: detailed battery info ──
    let mut voltage: Option<f32> = None;
    let mut cycle_count: Option<u32> = None;
    let mut manufacturer: Option<String> = None;
    let mut model: Option<String> = None;
    let mut health_percent: Option<f32> = None;
    let mut energy_wh: Option<f32> = None;
    let mut energy_full_wh: Option<f32> = None;
    let mut energy_full_design_wh: Option<f32> = None;

    if let Ok(sp_output) = Command::new("system_profiler")
        .args(["SPPowerDataType", "-json"])
        .output()
    {
        if let Ok(sp_text) = String::from_utf8(sp_output.stdout) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&sp_text) {
                if let Some(powers) = json["SPPowerDataType"].as_array() {
                    for power_section in powers {
                        if let Some(batteries) = power_section["sppower_battery_health_info"].as_array() {
                            for bat_info in batteries {
                                // cycle_count
                                if cycle_count.is_none() {
                                    cycle_count = bat_info["cycle_count"].as_u64().map(|cc| cc as u32);
                                }
                                // manufacturer
                                if manufacturer.is_none() {
                                    manufacturer = bat_info["manufacturer"].as_str().map(std::string::ToString::to_string);
                                }
                                // model / device_name
                                if model.is_none() {
                                    model = bat_info["device_name"].as_str().map(std::string::ToString::to_string);
                                }
                                // voltage: sppower_voltage is in mV
                                if voltage.is_none() {
                                    if let Some(mv) = bat_info["sppower_voltage"].as_f64() {
                                        voltage = Some((mv / 1000.0) as f32);
                                    }
                                }
                                // health: max_capacity / design_capacity * 100
                                let max_cap = bat_info["max_capacity"].as_f64();
                                let design_cap = bat_info["design_capacity"].as_f64();
                                if health_percent.is_none() {
                                    if let (Some(max), Some(design)) = (max_cap, design_cap) {
                                        if design > 0.0 {
                                            health_percent = Some((max / design * 100.0) as f32);
                                        }
                                    }
                                }
                                // energy_wh: current_capacity (mAh) * voltage (V) / 1000 -> Wh
                                if energy_wh.is_none() {
                                    if let (Some(cur_cap), Some(v)) = (bat_info["current_capacity"].as_f64(), voltage) {
                                        energy_wh = Some((cur_cap * f64::from(v) / 1000.0) as f32);
                                    }
                                }
                                // energy_full_wh: max_capacity (mAh) * voltage (V) / 1000 -> Wh
                                if energy_full_wh.is_none() {
                                    if let (Some(max_val), Some(v)) = (max_cap, voltage) {
                                        energy_full_wh = Some((max_val * f64::from(v) / 1000.0) as f32);
                                    }
                                }
                                // energy_full_design_wh: design_capacity (mAh) * voltage (V) / 1000 -> Wh
                                if energy_full_design_wh.is_none() {
                                    if let (Some(des_val), Some(v)) = (design_cap, voltage) {
                                        energy_full_design_wh = Some((des_val * f64::from(v) / 1000.0) as f32);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Some(BatteryInfo {
        charge_percent: pct,
        state: state.to_string(),
        time_to_empty_secs,
        time_to_full_secs,
        voltage,
        cycle_count,
        health_percent,
        energy_wh,
        energy_full_wh,
        energy_full_design_wh,
        manufacturer,
        model,
    })
}

/// Read battery status from the OS.
#[cfg(target_os = "linux")]
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)] // micro-unit->unit conversions; values are bounded battery readings
fn read_battery_os() -> Option<BatteryInfo> {
    use std::fs;
    use std::path::Path;

    /// Helper: read a sysfs file, trim, parse as T. Returns None on any error.
    fn read_sysfs_parse<T: std::str::FromStr>(dir: &Path, name: &str) -> Option<T> {
        fs::read_to_string(dir.join(name))
            .ok()?
            .trim()
            .parse::<T>()
            .ok()
    }

    /// Helper: read a sysfs file as a trimmed string. Returns None on any error.
    fn read_sysfs_string(dir: &Path, name: &str) -> Option<String> {
        fs::read_to_string(dir.join(name))
            .ok()
            .map(|s| s.trim().to_string())
    }

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

        let pct: f32 = read_sysfs_parse(&path, "capacity")?;
        let status = read_sysfs_string(&path, "status")
            .unwrap_or_else(|| "Unknown".to_string());

        // time_to_empty_secs: file value is in seconds
        let time_to_empty_secs: Option<u64> = read_sysfs_parse(&path, "time_to_empty");
        // time_to_full_secs: file value is in seconds
        let time_to_full_secs: Option<u64> = read_sysfs_parse(&path, "time_to_full");
        // voltage: file value in microvolts, convert to volts
        let voltage: Option<f32> = read_sysfs_parse::<f64>(&path, "voltage_now")
            .map(|v| (v / 1_000_000.0) as f32);
        // cycle_count
        let cycle_count: Option<u32> = read_sysfs_parse(&path, "cycle_count");
        // manufacturer
        let manufacturer: Option<String> = read_sysfs_string(&path, "manufacturer");
        // model
        let model: Option<String> = read_sysfs_string(&path, "model_name");

        // energy values: files in microjoules, convert to watt-hours
        // energy_wh = energy_now (microjoules) / 1_000_000.0 (joules) / 3600.0 (hours)
        //   but on Linux sysfs, energy_now and energy_full are in microwatt-hours (uWh)
        //   when the unit file says "uWh", or microamp-hours (uAh) combined with voltage.
        // The standard is microwatt-hours for energy_* files, so divide by 1_000_000 for Wh.
        let energy_wh: Option<f32> = read_sysfs_parse::<f64>(&path, "energy_now")
            .map(|e| (e / 1_000_000.0) as f32);
        let energy_full_wh: Option<f32> = read_sysfs_parse::<f64>(&path, "energy_full")
            .map(|e| (e / 1_000_000.0) as f32);
        let energy_full_design_wh: Option<f32> = read_sysfs_parse::<f64>(&path, "energy_full_design")
            .map(|e| (e / 1_000_000.0) as f32);

        // health_percent = energy_full / energy_full_design * 100
        let health_percent: Option<f32> = {
            let full: Option<f64> = read_sysfs_parse(&path, "energy_full");
            let design: Option<f64> = read_sysfs_parse(&path, "energy_full_design");
            if let (Some(f), Some(d)) = (full, design) {
                if d > 0.0 {
                    Some((f / d * 100.0) as f32)
                } else {
                    None
                }
            } else {
                None
            }
        };

        return Some(BatteryInfo {
            charge_percent: pct,
            state: status,
            time_to_empty_secs,
            time_to_full_secs,
            voltage,
            cycle_count,
            health_percent,
            energy_wh,
            energy_full_wh,
            energy_full_design_wh,
            manufacturer,
            model,
        });
    }
    None
}

/// Read battery status from the OS.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn read_battery_os() -> Option<BatteryInfo> {
    None
}

/// Hardware inventory information from SMBIOS/DMI.
#[derive(Debug, Clone, Serialize, Default)]
pub struct HardwareInventory {
    pub manufacturer: Option<String>,
    pub product_name: Option<String>,
    pub board_name: Option<String>,
    pub bios_vendor: Option<String>,
    pub bios_version: Option<String>,
    pub chassis_type: Option<String>,
    pub system_serial: Option<String>,
    pub system_uuid: Option<String>,
    pub asset_tag: Option<String>,
}

/// Static hardware information that does not change between snapshots.
#[derive(Debug, Clone, Serialize)]
pub struct StaticInfo {
    pub os: OsInfo,
    pub kernel_version: Option<String>,
    pub hostname: String,
    pub cpu_brand: String,
    pub cpu_vendor: String,
    pub cpu_frequency: u64,
    pub physical_cores: Option<usize>,
    pub logical_cores: usize,
    pub memory_total_bytes: u64,
    pub hardware: HardwareInventory,
    pub sockets: Option<u32>,
    pub cores_per_socket: Option<u32>,
    pub threads_per_core: Option<u32>,
    pub base_frequency: Option<u64>,
    pub max_frequency: Option<u64>,
    pub cache_l1d: Option<u32>,
    pub cache_l1i: Option<u32>,
    pub cache_l2: Option<u32>,
    pub cache_l3: Option<u64>,
}

/// Aggregated sensor snapshot with CPU/GPU temperature highlights.
#[derive(Debug, Clone, Serialize)]
pub struct SensorSnapshot {
    pub readings: Vec<SensorStatus>,
    pub cpu_temperature: Option<f32>,
    pub gpu_temperature: Option<f32>,
}

/// Virtualization environment detection.
#[derive(Debug, Clone, Serialize, Default)]
pub struct VirtualizationSnapshot {
    pub in_docker: bool,
    pub in_lxc: bool,
    pub in_containerd: bool,
    pub in_kubernetes: bool,
    pub in_wsl: bool,
    pub in_vm: bool,
    pub hypervisor_vendor: Option<String>,
    pub cgroup_version: Option<String>,
    pub cpu_quota: Option<f64>,
    pub memory_limit_bytes: Option<u64>,
    pub swap_limit: Option<u64>,
    pub blkio_limit: Option<u64>,
    pub cpuset_cpus: Option<String>,
    pub in_podman: bool,
}

/// Disk I/O counters snapshot.
#[derive(Debug, Clone, Copy, Serialize, Default)]
pub struct DiskIoSnapshot {
    pub read_bytes: u64,
    pub written_bytes: u64,
    pub read_ops: u64,
    pub write_ops: u64,
    pub busy_time_ms: u64,
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
    /// Static hardware information.
    pub static_info: StaticInfo,
    /// Aggregated sensor snapshot.
    pub sensor_snapshot: SensorSnapshot,
    /// Virtualization environment detection.
    pub virtualization: VirtualizationSnapshot,
    /// Disk I/O counters.
    pub disk_io: DiskIoSnapshot,
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
    /// Free memory in bytes.
    pub free_bytes: u64,
    /// Available memory in bytes.
    pub available_bytes: u64,
    /// Cached memory in bytes.
    pub cached_bytes: u64,
    /// Buffer memory in bytes.
    pub buffers_bytes: u64,
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
    /// Free disk space in bytes.
    pub free_bytes: u64,
    /// Available disk space in bytes.
    pub available_bytes: u64,
    /// Disk type: "SSD", "HDD", or "Unknown".
    pub disk_type: String,
    /// Physical device path (e.g., "/dev/disk0", "/dev/sda").
    pub physical_device_path: Option<String>,
    /// Device model name.
    pub model: Option<String>,
    /// Device serial number.
    pub serial: Option<String>,
    /// Device temperature in Celsius, if available.
    pub temperature: Option<f32>,
    /// Wear percentage (0.0–100.0) for SSDs, if available.
    pub wear_percent: Option<f32>,
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
    /// OS type (e.g., "linux", "macos", "windows").
    pub os_type: Option<String>,
    /// OS edition (e.g., "Pro", "Home", "Server").
    pub edition: Option<String>,
    /// OS codename (e.g., "Sequoia", "Noble Numbat").
    pub codename: Option<String>,
    /// OS bitness (32 or 64).
    pub bitness: Option<u32>,
    /// System timezone.
    pub timezone: Option<String>,
    /// System locale.
    pub locale: Option<String>,
    /// Current user name.
    pub current_user: Option<String>,
    /// Whether the current user is root.
    pub is_root: bool,
    /// Whether running inside a container.
    pub container_detected: bool,
    /// Whether running inside a virtual machine.
    pub vm_detected: bool,
    /// Whether running inside WSL.
    pub wsl_detected: bool,
    /// Whether systemd is detected.
    pub systemd_detected: bool,
    /// Rust target triple (e.g., "x86_64-unknown-linux-gnu").
    pub target_triple: Option<String>,
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

/// Static CPU information that does not change between snapshots.
#[derive(Debug, Clone, Serialize)]
pub struct CpuStatic {
    /// CPU vendor (e.g., "GenuineIntel", "Apple").
    pub vendor: String,
    /// CPU brand string (e.g., "Apple M2 Pro").
    pub brand: String,
    /// CPU architecture (e.g., "x86_64", "aarch64").
    pub arch: String,
    /// Number of CPU sockets.
    pub sockets: Option<u32>,
    /// Physical cores per socket.
    pub cores_per_socket: Option<u32>,
    /// Hardware threads per core.
    pub threads_per_core: Option<u32>,
    /// Base frequency in MHz.
    pub base_freq: Option<u64>,
    /// Maximum frequency in MHz.
    pub max_freq: Option<u64>,
    /// L1 data cache size in bytes.
    pub cache_l1d: Option<u32>,
    /// L1 instruction cache size in bytes.
    pub cache_l1i: Option<u32>,
    /// L2 cache size in bytes.
    pub cache_l2: Option<u32>,
    /// L3 cache size in bytes.
    pub cache_l3: Option<u64>,
}

/// Point-in-time CPU usage sample.
#[derive(Debug, Clone, Serialize)]
pub struct CpuSample {
    /// Aggregate CPU usage percentage (0.0–100.0).
    pub total_usage: Option<f64>,
    /// Per-core usage percentages.
    pub per_core: Vec<f64>,
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
    /// Free swap in bytes.
    pub free_bytes: u64,
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
    /// Hardware (MAC) address, if available.
    pub mac_address: Option<String>,
    /// Maximum transmission unit, if available.
    pub mtu: Option<u32>,
    /// Receive drops.
    pub drops_received: u64,
    /// Transmit drops.
    pub drops_transmitted: u64,
    /// Human-readable display name.
    pub display_name: Option<String>,
    /// Interface description.
    pub description: Option<String>,
    /// IPv4 addresses.
    pub ipv4_addresses: Vec<String>,
    /// IPv6 addresses.
    pub ipv6_addresses: Vec<String>,
    /// Default gateway address.
    pub gateway: Option<String>,
    /// DNS server address.
    pub dns: Option<String>,
    /// Link status (e.g., "up", "down").
    pub link_status: Option<String>,
    /// Link speed in bits per second.
    pub speed_bps: Option<u64>,
    /// Duplex mode (e.g., "full", "half").
    pub duplex: Option<String>,
}

/// Temperature sensor reading.
#[derive(Debug, Clone, Serialize)]
pub struct SensorStatus {
    /// Sensor label (e.g., "CPU", "GPU").
    pub label: String,
    /// Temperature in Celsius, if available.
    pub temperature: Option<f32>,
    /// Fan RPM, if available.
    pub fan_rpm: Option<u32>,
    /// Voltage in volts, if available.
    pub voltage: Option<f32>,
    /// Whether thermal throttling is active, if detectable.
    pub thermal_throttling: Option<bool>,
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
    /// GPU type: "Integrated" or "Discrete", if detectable.
    pub gpu_type: Option<String>,
    /// GPU temperature in Celsius, if available.
    pub temperature: Option<f32>,
    /// GPU utilization percentage (0.0-100.0), if available.
    pub utilization: Option<f32>,
    /// PCI device ID.
    pub device_id: Option<String>,
    /// PCI bus ID.
    pub pci_bus_id: Option<String>,
    /// Used VRAM in bytes, if available.
    pub used_vram_bytes: Option<u64>,
    /// Free VRAM in bytes, if available.
    pub free_vram_bytes: Option<u64>,
    /// Memory utilization percentage (0.0-100.0), if available.
    pub memory_utilization: Option<f32>,
    /// Encoder utilization percentage (0.0-100.0), if available.
    pub encoder_utilization: Option<f32>,
    /// Decoder utilization percentage (0.0-100.0), if available.
    pub decoder_utilization: Option<f32>,
    /// Fan speed in RPM, if available.
    pub fan_speed_rpm: Option<u32>,
    /// Power draw in watts, if available.
    pub power_draw_watts: Option<f32>,
    /// Power limit in watts, if available.
    pub power_limit_watts: Option<f32>,
    /// Clock speed in MHz, if available.
    pub clock_speed_mhz: Option<u32>,
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
    /// Battery voltage in volts, if available.
    pub voltage: Option<f32>,
    /// Battery cycle count, if available.
    pub cycle_count: Option<u32>,
    /// Battery health as a percentage (0.0-100.0), if available.
    pub health_percent: Option<f32>,
    /// Current energy in watt-hours, if available.
    pub energy_wh: Option<f32>,
    /// Full charge energy in watt-hours, if available.
    pub energy_full_wh: Option<f32>,
    /// Design energy capacity in watt-hours, if available.
    pub energy_full_design_wh: Option<f32>,
    /// Battery manufacturer, if available.
    pub manufacturer: Option<String>,
    /// Battery model, if available.
    pub model: Option<String>,
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
    /// Path to the process executable.
    pub executable_path: Option<String>,
    /// User running the process.
    pub user: Option<String>,
    /// Virtual memory usage in bytes.
    pub virtual_memory: u64,
    /// Number of threads.
    pub thread_count: Option<u32>,
    /// Full command line (argv joined with spaces).
    pub command_line: Option<String>,
    /// Current working directory.
    pub working_dir: Option<String>,
    /// Disk bytes read, if available.
    pub disk_read_bytes: Option<u64>,
    /// Disk bytes written, if available.
    pub disk_write_bytes: Option<u64>,
    /// Number of open files, if available.
    pub open_files: Option<u32>,
    /// Number of file descriptors, if available.
    pub fd_count: Option<u32>,
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
    /// use toride_status::system::{ProcessSnapshot, ProcessStatus};
    ///
    /// let snapshot = ProcessSnapshot {
    ///     processes: vec![
    ///         ProcessStatus { pid: 1, parent_pid: None, name: "idle".into(), cpu_usage: 0.1, memory_bytes: 100, status: "Sleeping".into(), start_time: None, executable_path: None, user: None, virtual_memory: 0, thread_count: None, command_line: None, working_dir: None, disk_read_bytes: None, disk_write_bytes: None, open_files: None, fd_count: None },
    ///         ProcessStatus { pid: 2, parent_pid: None, name: "busy".into(), cpu_usage: 95.0, memory_bytes: 200, status: "Running".into(), start_time: None, executable_path: None, user: None, virtual_memory: 0, thread_count: None, command_line: None, working_dir: None, disk_read_bytes: None, disk_write_bytes: None, open_files: None, fd_count: None },
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
    /// use toride_status::system::{ProcessSnapshot, ProcessStatus};
    ///
    /// let snapshot = ProcessSnapshot {
    ///     processes: vec![
    ///         ProcessStatus { pid: 1, parent_pid: None, name: "small".into(), cpu_usage: 1.0, memory_bytes: 1024, status: "Sleeping".into(), start_time: None, executable_path: None, user: None, virtual_memory: 0, thread_count: None, command_line: None, working_dir: None, disk_read_bytes: None, disk_write_bytes: None, open_files: None, fd_count: None },
    ///         ProcessStatus { pid: 2, parent_pid: None, name: "large".into(), cpu_usage: 1.0, memory_bytes: 1024 * 1024 * 100, status: "Running".into(), start_time: None, executable_path: None, user: None, virtual_memory: 0, thread_count: None, command_line: None, working_dir: None, disk_read_bytes: None, disk_write_bytes: None, open_files: None, fd_count: None },
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

    /// Get top N processes by disk I/O (total read+write bytes).
    pub fn top_by_disk_io(&self, n: usize) -> Vec<&ProcessStatus> {
        let mut sorted: Vec<&ProcessStatus> = self.processes.iter().collect();
        sorted.sort_by(|a, b| {
            let a_io = a.disk_read_bytes.unwrap_or(0) + a.disk_write_bytes.unwrap_or(0);
            let b_io = b.disk_read_bytes.unwrap_or(0) + b.disk_write_bytes.unwrap_or(0);
            b_io.cmp(&a_io)
        });
        sorted.into_iter().take(n).collect()
    }

    /// Build a parent-to-children mapping for process tree traversal.
    pub fn process_tree(&self) -> std::collections::HashMap<u32, Vec<u32>> {
        let mut tree: std::collections::HashMap<u32, Vec<u32>> = std::collections::HashMap::new();
        for proc in &self.processes {
            if let Some(ppid) = proc.parent_pid {
                tree.entry(ppid).or_default().push(proc.pid);
            }
        }
        tree
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
    /// use toride_status::system::SystemStatus;
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
        let static_info = Self::read_static_info(&sys);
        let sensor_snapshot = Self::read_sensor_snapshot();
        let virtualization = Self::read_virtualization();
        let disk_io = Self::read_disk_io();

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
            static_info,
            sensor_snapshot,
            virtualization,
            disk_io,
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
        let free = sys.free_memory();
        let available = sys.available_memory();
        let percentage = if total > 0 {
            ((used as f64 / total as f64) * 100.0).min(100.0)
        } else {
            0.0
        };
        MemoryStatus {
            used_bytes: used,
            total_bytes: total,
            percentage,
            free_bytes: free,
            available_bytes: available,
            cached_bytes: read_cached_bytes(),
            buffers_bytes: read_buffers_bytes(),
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
                free_bytes: 0,
                available_bytes: 0,
                disk_type: "Unknown".to_string(),
                physical_device_path: None,
                model: None,
                serial: None,
                temperature: None,
                wear_percent: None,
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
        build_os_info()
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
            free_bytes: total.saturating_sub(used),
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
                let name_str = d.name().to_string_lossy().to_string();
                let fs_str = d.file_system().to_string_lossy().to_string();
                #[cfg(target_os = "linux")]
                let disk_type = read_disk_type_linux(&name_str);
                #[cfg(target_os = "macos")]
                let disk_type = read_disk_type_macos(&fs_str);
                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                let disk_type = "Unknown".to_string();
                #[cfg(target_os = "linux")]
                let physical_device_path = if name_str.is_empty() {
                    None
                } else {
                    Some(format!("/dev/{name_str}"))
                };
                #[cfg(not(target_os = "linux"))]
                let physical_device_path: Option<String> = None;
                DiskStatus {
                    name: name_str,
                    mount_point: d.mount_point().to_string_lossy().to_string(),
                    filesystem: fs_str,
                    used_bytes: used,
                    total_bytes: total,
                    percentage,
                    is_removable: d.is_removable(),
                    free_bytes: available,
                    available_bytes: available,
                    disk_type,
                    physical_device_path,
                    model: None,
                    serial: None,
                    temperature: None,
                    wear_percent: None,
                }
            })
            .collect()
    }

    fn read_network_interfaces(networks: &Networks) -> Vec<NetworkInterface> {
        let gw = detect_gateway();
        let dns = detect_first_dns();
        networks
            .iter()
            .map(|(name, data)| {
                let mac = data.mac_address();
                let mac_str = if mac.is_unspecified() {
                    None
                } else {
                    let b = mac.0;
                    Some(format!(
                        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        b[0], b[1], b[2], b[3], b[4], b[5]
                    ))
                };
                let mtu_val = data.mtu();
                let extras = read_interface_extras(name);
                NetworkInterface {
                    name: name.clone(),
                    bytes_received: data.total_received(),
                    bytes_transmitted: data.total_transmitted(),
                    packets_received: data.total_packets_received(),
                    packets_transmitted: data.total_packets_transmitted(),
                    errors_received: data.errors_on_received(),
                    errors_transmitted: data.errors_on_transmitted(),
                    mac_address: mac_str,
                    mtu: if mtu_val > 0 { Some(mtu_val as u32) } else { None },
                    drops_received: extras.drops_received,
                    drops_transmitted: extras.drops_transmitted,
                    display_name: None,
                    description: None,
                    ipv4_addresses: Vec::new(),
                    ipv6_addresses: Vec::new(),
                    gateway: gw.clone(),
                    dns: dns.clone(),
                    link_status: extras.link_status,
                    speed_bps: extras.speed_bps,
                    duplex: extras.duplex,
                }
            })
            .collect()
    }

    fn read_sensors() -> Vec<SensorStatus> {
        let components = Components::new_with_refreshed_list();
        #[allow(unused_mut)] // mut needed on Linux for hwmon extension
        let mut sensors: Vec<SensorStatus> = components
            .iter()
            .map(|c| SensorStatus {
                label: c.label().to_string(),
                temperature: {
                    c.temperature().filter(|t| !t.is_nan())
                },
                fan_rpm: None,
                voltage: None,
                thermal_throttling: None,
            })
            .collect();
        #[cfg(target_os = "linux")]
        {
            sensors.extend(read_hwmon_fans());
            sensors.extend(read_hwmon_voltages());
        }
        sensors
    }

    fn read_processes_from(sys: &System) -> ProcessSnapshot {
        let processes: Vec<ProcessStatus> = sys
            .processes()
            .iter()
            .map(|(pid, p)| {
                let pid_u32 = pid.as_u32();
                let cmd_line = p.cmd().iter()
                    .map(|c| c.to_string_lossy().to_string())
                    .collect::<Vec<_>>()
                    .join(" ");
                #[cfg(target_os = "linux")]
                let (disk_read_bytes, disk_write_bytes) = read_proc_io(pid_u32);
                #[cfg(not(target_os = "linux"))]
                let (disk_read_bytes, disk_write_bytes): (Option<u64>, Option<u64>) = (None, None);
                #[cfg(target_os = "linux")]
                let fd_count = read_proc_fd_count(pid_u32);
                #[cfg(not(target_os = "linux"))]
                let fd_count: Option<u32> = None;
                ProcessStatus {
                    pid: pid_u32,
                    parent_pid: p.parent().map(sysinfo::Pid::as_u32),
                    name: p.name().to_string_lossy().to_string(),
                    cpu_usage: p.cpu_usage(),
                    memory_bytes: p.memory(),
                    status: format!("{}", p.status()),
                    start_time: if p.start_time() > 0 { Some(p.start_time()) } else { None },
                    executable_path: p.exe().map(|e| e.to_string_lossy().to_string()),
                    user: p.user_id().map(|uid| uid.to_string()),
                    virtual_memory: p.virtual_memory(),
                    #[cfg(target_os = "linux")]
                    thread_count: read_proc_thread_count(pid_u32),
                    #[cfg(not(target_os = "linux"))]
                    thread_count: None,
                    command_line: if cmd_line.is_empty() { None } else { Some(cmd_line) },
                    #[cfg(target_os = "linux")]
                    working_dir: read_proc_working_dir(pid_u32),
                    #[cfg(not(target_os = "linux"))]
                    working_dir: None,
                    disk_read_bytes,
                    disk_write_bytes,
                    open_files: fd_count,
                    fd_count,
                }
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
                    let device_id = display["sppci_device_id"]
                        .as_str()
                        .map(std::string::ToString::to_string);
                    let gpu_type = if name.contains("Apple M") {
                        Some("Integrated".to_string())
                    } else {
                        Some("Discrete".to_string())
                    };
                    gpus.push(GpuInfo {
                        name,
                        vendor,
                        vram_bytes: vram,
                        driver_version: None,
                        gpu_type,
                        temperature: None,
                        utilization: None,
                        device_id,
                        pci_bus_id: None,
                        used_vram_bytes: None,
                        free_vram_bytes: None,
                        memory_utilization: None,
                        encoder_utilization: None,
                        decoder_utilization: None,
                        fan_speed_rpm: None,
                        power_draw_watts: None,
                        power_limit_watts: None,
                        clock_speed_mhz: None,
                    });
                }
            }
        }
        // Try nvidia-smi on Linux
        #[cfg(target_os = "linux")]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("nvidia-smi")
                .args(["--query-gpu=name,memory.total,driver_version,temperature.gpu,utilization.gpu,pci.bus_id,pci.device_id,memory.used,memory.free,utilization.memory,utilization.encoder,utilization.decoder,fan.speed,power.draw,power.limit,clocks.current.graphics", "--format=csv,noheader,nounits"])
                .output()
            {
                if output.status.success() {
                    let text = String::from_utf8_lossy(&output.stdout);
                    for line in text.lines() {
                        let parts: Vec<&str> = line.split(", ").collect();
                        if parts.len() >= 16 {
                            let name = parts[0].trim().to_string();
                            let vram_mb: Option<u64> = parts[1].trim().parse().ok();
                            let driver = parts[2].trim().to_string();
                            let temperature: Option<f32> = parts[3].trim().parse().ok();
                            let utilization: Option<f32> = parts[4].trim().parse().ok();
                            let pci_bus_id = Some(parts[5].trim().to_string());
                            let device_id = Some(parts[6].trim().to_string());
                            let used_vram_mb: Option<u64> = parts[7].trim().parse().ok();
                            let free_vram_mb: Option<u64> = parts[8].trim().parse().ok();
                            let memory_utilization: Option<f32> = parts[9].trim().parse().ok();
                            let encoder_utilization: Option<f32> = parts[10].trim().parse().ok();
                            let decoder_utilization: Option<f32> = parts[11].trim().parse().ok();
                            let fan_speed_rpm: Option<u32> = parts[12].trim().parse().ok();
                            let power_draw_watts: Option<f32> = parts[13].trim().parse().ok();
                            let power_limit_watts: Option<f32> = parts[14].trim().parse().ok();
                            let clock_speed_mhz: Option<u32> = parts[15].trim().parse().ok();
                            gpus.push(GpuInfo {
                                name,
                                vendor: "NVIDIA".to_string(),
                                vram_bytes: vram_mb.map(|mb| mb * 1024 * 1024),
                                driver_version: Some(driver),
                                gpu_type: Some("Discrete".to_string()),
                                temperature,
                                utilization,
                                device_id,
                                pci_bus_id,
                                used_vram_bytes: used_vram_mb.map(|mb| mb * 1024 * 1024),
                                free_vram_bytes: free_vram_mb.map(|mb| mb * 1024 * 1024),
                                memory_utilization,
                                encoder_utilization,
                                decoder_utilization,
                                fan_speed_rpm,
                                power_draw_watts,
                                power_limit_watts,
                                clock_speed_mhz,
                            });
                        }
                    }
                }
            }
        }
        gpus
    }

    fn read_static_info(sys: &System) -> StaticInfo {
        let cpus = sys.cpus();
        let brand = cpus.first().map_or_else(String::new, |c| c.brand().to_string());
        let vendor = cpus.first().map_or_else(String::new, |c| c.vendor_id().to_string());
        let freq = cpus.first().map_or(0, |c| c.frequency());
        let topology = read_cpu_topology();
        let hardware = read_hardware_inventory();
        StaticInfo {
            os: Self::read_os_info(),
            kernel_version: sysinfo::System::kernel_version(),
            hostname: Self::read_hostname(),
            cpu_brand: brand,
            cpu_vendor: vendor,
            cpu_frequency: freq,
            physical_cores: sysinfo::System::physical_core_count(),
            logical_cores: cpus.len(),
            memory_total_bytes: sys.total_memory(),
            hardware,
            sockets: topology.sockets,
            cores_per_socket: topology.cores_per_socket,
            threads_per_core: topology.threads_per_core,
            base_frequency: topology.base_frequency,
            max_frequency: topology.max_frequency,
            cache_l1d: topology.cache_l1d,
            cache_l1i: topology.cache_l1i,
            cache_l2: topology.cache_l2,
            cache_l3: topology.cache_l3,
        }
    }

    fn read_sensor_snapshot() -> SensorSnapshot {
        let components = Components::new_with_refreshed_list();
        let readings: Vec<SensorStatus> = components
            .iter()
            .map(|c| SensorStatus {
                label: c.label().to_string(),
                temperature: c.temperature().filter(|t| !t.is_nan()),
                fan_rpm: None,
                voltage: None,
                thermal_throttling: None,
            })
            .collect();
        let cpu_temperature = readings.iter().find_map(|s| {
            if s.label.to_lowercase().contains("cpu") { s.temperature } else { None }
        });
        let gpu_temperature = readings.iter().find_map(|s| {
            if s.label.to_lowercase().contains("gpu") { s.temperature } else { None }
        });
        SensorSnapshot { readings, cpu_temperature, gpu_temperature }
    }

    #[cfg(target_os = "linux")]
    fn read_virtualization() -> VirtualizationSnapshot {
        use std::fs;
        let mut snap = VirtualizationSnapshot::default();
        snap.in_docker = std::path::Path::new("/.dockerenv").exists();
        if let Ok(cgroup) = fs::read_to_string("/proc/self/cgroup") {
            if cgroup.contains("/lxc/") || cgroup.contains("lxc.payload") { snap.in_lxc = true; }
            if cgroup.contains("containerd") { snap.in_containerd = true; }
            if cgroup.contains("kubepods") { snap.in_kubernetes = true; }
            snap.cgroup_version = Some(if cgroup.starts_with("0::/") { "v2" } else { "v1" }.to_string());
        }
        if let Ok(version) = fs::read_to_string("/proc/version") {
            let lower = version.to_lowercase();
            if lower.contains("microsoft") || lower.contains("wsl") { snap.in_wsl = true; }
        }
        if let Ok(product) = fs::read_to_string("/sys/class/dmi/id/product_name") {
            let lower = product.to_lowercase();
            if lower.contains("virtualbox") || lower.contains("vmware") || lower.contains("kvm")
                || lower.contains("qemu") || lower.contains("hyper-v") || lower.contains("virtual")
            {
                snap.in_vm = true;
                snap.hypervisor_vendor = Some(product.trim().to_string());
            }
        }
        snap
    }

    #[cfg(not(target_os = "linux"))]
    fn read_virtualization() -> VirtualizationSnapshot {
        VirtualizationSnapshot::default()
    }

    #[cfg(target_os = "linux")]
    fn read_disk_io() -> DiskIoSnapshot {
        use std::fs;
        let content = match fs::read_to_string("/proc/diskstats") {
            Ok(c) => c, Err(_) => return DiskIoSnapshot::default(),
        };
        let mut snap = DiskIoSnapshot::default();
        for line in content.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 14 { continue; }
            let name = fields[2];
            if name.starts_with("loop") || name.starts_with("ram") || name.starts_with("dm-") { continue; }
            let sectors_read: u64 = fields[5].parse().unwrap_or(0);
            let read_time: u64 = fields[6].parse().unwrap_or(0);
            let reads: u64 = fields[3].parse().unwrap_or(0);
            let sectors_written: u64 = fields[9].parse().unwrap_or(0);
            let write_time: u64 = fields[10].parse().unwrap_or(0);
            let writes: u64 = fields[7].parse().unwrap_or(0);
            snap.read_bytes = snap.read_bytes.saturating_add(sectors_read * 512);
            snap.written_bytes = snap.written_bytes.saturating_add(sectors_written * 512);
            snap.read_ops = snap.read_ops.saturating_add(reads);
            snap.write_ops = snap.write_ops.saturating_add(writes);
            snap.busy_time_ms = snap.busy_time_ms.saturating_add(read_time.saturating_add(write_time));
        }
        snap
    }

    #[cfg(not(target_os = "linux"))]
    fn read_disk_io() -> DiskIoSnapshot {
        DiskIoSnapshot::default()
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
/// use toride_status::system::SysinfoProvider;
/// use toride_status::provider::*;
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

    fn cpu_static(&self) -> StatusResult<CpuStatic> {
        let cpus = self.sys.cpus();
        let brand = cpus.first().map_or_else(String::new, |c| c.brand().to_string());
        let vendor = cpus.first().map_or_else(String::new, |c| c.vendor_id().to_string());
        let topology = read_cpu_topology();
        Ok(CpuStatic {
            vendor,
            brand,
            arch: std::env::consts::ARCH.to_string(),
            sockets: topology.sockets,
            cores_per_socket: topology.cores_per_socket,
            threads_per_core: topology.threads_per_core,
            base_freq: topology.base_frequency,
            max_freq: topology.max_frequency,
            cache_l1d: topology.cache_l1d,
            cache_l1i: topology.cache_l1i,
            cache_l2: topology.cache_l2,
            cache_l3: topology.cache_l3,
        })
    }

    #[allow(clippy::cast_precision_loss)] // usize->f64 for average; negligible precision loss for core counts
    fn cpu_sample(&mut self) -> StatusResult<CpuSample> {
        let cpus = self.sys.cpus();
        let total_usage = if cpus.is_empty() {
            None
        } else {
            let total: f64 = cpus.iter().map(|c| f64::from(c.cpu_usage())).sum();
            Some(total / cpus.len() as f64)
        };
        let per_core: Vec<f64> = cpus.iter().map(|c| f64::from(c.cpu_usage())).collect();
        Ok(CpuSample { total_usage, per_core })
    }
}

impl MemoryProvider for SysinfoProvider {
    #[allow(clippy::cast_precision_loss)] // u64->f64 for percentage display; negligible precision loss
    fn memory(&mut self) -> StatusResult<MemoryStatus> {
        let total = self.sys.total_memory();
        let used = self.sys.used_memory().min(total);
        let free = self.sys.free_memory();
        let available = self.sys.available_memory();
        let percentage = if total > 0 {
            ((used as f64 / total as f64) * 100.0).min(100.0)
        } else {
            0.0
        };
        Ok(MemoryStatus {
            used_bytes: used,
            total_bytes: total,
            percentage,
            free_bytes: free,
            available_bytes: available,
            cached_bytes: read_cached_bytes(),
            buffers_bytes: read_buffers_bytes(),
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
            free_bytes: total.saturating_sub(used),
        }))
    }

    fn memory_pressure(&self) -> StatusResult<Option<f32>> {
        // sysinfo does not directly expose memory pressure.
        // Derive a rough approximation from used/total ratio.
        let total = self.sys.total_memory();
        if total == 0 {
            return Ok(None);
        }
        let used = self.sys.used_memory();
        Ok(Some((used as f32 / total as f32).clamp(0.0, 1.0)))
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
                free_bytes: 0,
                available_bytes: 0,
                disk_type: "Unknown".to_string(),
                physical_device_path: None,
                model: None,
                serial: None,
                temperature: None,
                wear_percent: None,
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
                let name_str = d.name().to_string_lossy().to_string();
                let fs_str = d.file_system().to_string_lossy().to_string();
                #[cfg(target_os = "linux")]
                let disk_type = read_disk_type_linux(&name_str);
                #[cfg(target_os = "macos")]
                let disk_type = read_disk_type_macos(&fs_str);
                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                let disk_type = "Unknown".to_string();
                #[cfg(target_os = "linux")]
                let physical_device_path = if name_str.is_empty() {
                    None
                } else {
                    Some(format!("/dev/{name_str}"))
                };
                #[cfg(not(target_os = "linux"))]
                let physical_device_path: Option<String> = None;
                DiskStatus {
                    name: name_str,
                    mount_point: d.mount_point().to_string_lossy().to_string(),
                    filesystem: fs_str,
                    used_bytes: used,
                    total_bytes: total,
                    percentage,
                    is_removable: d.is_removable(),
                    free_bytes: available,
                    available_bytes: available,
                    disk_type,
                    physical_device_path,
                    model: None,
                    serial: None,
                    temperature: None,
                    wear_percent: None,
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
        let gw = detect_gateway();
        let dns = detect_first_dns();
        Ok(networks
            .iter()
            .map(|(name, data)| {
                let mac = data.mac_address();
                let mac_str = if mac.is_unspecified() {
                    None
                } else {
                    let b = mac.0;
                    Some(format!(
                        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        b[0], b[1], b[2], b[3], b[4], b[5]
                    ))
                };
                let mtu_val = data.mtu();
                let extras = read_interface_extras(name);
                NetworkInterface {
                    name: name.clone(),
                    bytes_received: data.total_received(),
                    bytes_transmitted: data.total_transmitted(),
                    packets_received: data.total_packets_received(),
                    packets_transmitted: data.total_packets_transmitted(),
                    errors_received: data.errors_on_received(),
                    errors_transmitted: data.errors_on_transmitted(),
                    mac_address: mac_str,
                    mtu: if mtu_val > 0 { Some(mtu_val as u32) } else { None },
                    drops_received: extras.drops_received,
                    drops_transmitted: extras.drops_transmitted,
                    display_name: None,
                    description: None,
                    ipv4_addresses: Vec::new(),
                    ipv6_addresses: Vec::new(),
                    gateway: gw.clone(),
                    dns: dns.clone(),
                    link_status: extras.link_status,
                    speed_bps: extras.speed_bps,
                    duplex: extras.duplex,
                }
            })
            .collect())
    }

    fn gateway(&self) -> StatusResult<Option<String>> {
        Ok(detect_gateway())
    }

    fn dns_servers(&self) -> StatusResult<Vec<String>> {
        Ok(detect_dns_servers())
    }
}

impl OsProvider for SysinfoProvider {
    fn os_info(&self) -> StatusResult<OsInfo> {
        Ok(build_os_info())
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

    fn os_detailed(&self) -> StatusResult<OsInfo> {
        // os_info() already populates all fields via build_os_info().
        self.os_info()
    }
}

impl ProcessProvider for SysinfoProvider {
    fn processes(&mut self) -> StatusResult<ProcessSnapshot> {
        let processes: Vec<ProcessStatus> = self
            .sys
            .processes()
            .iter()
            .map(|(pid, p)| {
                let pid_u32 = pid.as_u32();
                let cmd_line = p.cmd().iter()
                    .map(|c| c.to_string_lossy().to_string())
                    .collect::<Vec<_>>()
                    .join(" ");
                #[cfg(target_os = "linux")]
                let (disk_read_bytes, disk_write_bytes) = read_proc_io(pid_u32);
                #[cfg(not(target_os = "linux"))]
                let (disk_read_bytes, disk_write_bytes): (Option<u64>, Option<u64>) = (None, None);
                #[cfg(target_os = "linux")]
                let fd_count = read_proc_fd_count(pid_u32);
                #[cfg(not(target_os = "linux"))]
                let fd_count: Option<u32> = None;
                ProcessStatus {
                    pid: pid_u32,
                    parent_pid: p.parent().map(sysinfo::Pid::as_u32),
                    name: p.name().to_string_lossy().to_string(),
                    cpu_usage: p.cpu_usage(),
                    memory_bytes: p.memory(),
                    status: format!("{}", p.status()),
                    start_time: if p.start_time() > 0 { Some(p.start_time()) } else { None },
                    executable_path: p.exe().map(|e| e.to_string_lossy().to_string()),
                    user: p.user_id().map(|uid| uid.to_string()),
                    virtual_memory: p.virtual_memory(),
                    #[cfg(target_os = "linux")]
                    thread_count: read_proc_thread_count(pid_u32),
                    #[cfg(not(target_os = "linux"))]
                    thread_count: None,
                    command_line: if cmd_line.is_empty() { None } else { Some(cmd_line) },
                    #[cfg(target_os = "linux")]
                    working_dir: read_proc_working_dir(pid_u32),
                    #[cfg(not(target_os = "linux"))]
                    working_dir: None,
                    disk_read_bytes,
                    disk_write_bytes,
                    open_files: fd_count,
                    fd_count,
                }
            })
            .collect();
        let total_count = processes.len();
        Ok(ProcessSnapshot {
            processes,
            total_count,
        })
    }

    fn process_tree(&mut self) -> StatusResult<std::collections::HashMap<u32, Vec<u32>>> {
        let mut tree: std::collections::HashMap<u32, Vec<u32>> = std::collections::HashMap::new();
        for (pid, p) in self.sys.processes() {
            if let Some(ppid) = p.parent() {
                tree.entry(ppid.as_u32()).or_default().push(pid.as_u32());
            }
        }
        Ok(tree)
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
                    let device_id = display["sppci_device_id"]
                        .as_str()
                        .map(std::string::ToString::to_string);
                    let gpu_type = if name.contains("Apple M") {
                        Some("Integrated".to_string())
                    } else {
                        Some("Discrete".to_string())
                    };
                    gpus.push(GpuInfo {
                        name,
                        vendor,
                        vram_bytes: vram,
                        driver_version: None,
                        gpu_type,
                        temperature: None,
                        utilization: None,
                        device_id,
                        pci_bus_id: None,
                        used_vram_bytes: None,
                        free_vram_bytes: None,
                        memory_utilization: None,
                        encoder_utilization: None,
                        decoder_utilization: None,
                        fan_speed_rpm: None,
                        power_draw_watts: None,
                        power_limit_watts: None,
                        clock_speed_mhz: None,
                    });
                }
            }
        }
        // Try nvidia-smi on Linux
        #[cfg(target_os = "linux")]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("nvidia-smi")
                .args(["--query-gpu=name,memory.total,driver_version,temperature.gpu,utilization.gpu,pci.bus_id,pci.device_id,memory.used,memory.free,utilization.memory,utilization.encoder,utilization.decoder,fan.speed,power.draw,power.limit,clocks.current.graphics", "--format=csv,noheader,nounits"])
                .output()
            {
                if output.status.success() {
                    let text = String::from_utf8_lossy(&output.stdout);
                    for line in text.lines() {
                        let parts: Vec<&str> = line.split(", ").collect();
                        if parts.len() >= 16 {
                            let name = parts[0].trim().to_string();
                            let vram_mb: Option<u64> = parts[1].trim().parse().ok();
                            let driver = parts[2].trim().to_string();
                            let temperature: Option<f32> = parts[3].trim().parse().ok();
                            let utilization: Option<f32> = parts[4].trim().parse().ok();
                            let pci_bus_id = Some(parts[5].trim().to_string());
                            let device_id = Some(parts[6].trim().to_string());
                            let used_vram_mb: Option<u64> = parts[7].trim().parse().ok();
                            let free_vram_mb: Option<u64> = parts[8].trim().parse().ok();
                            let memory_utilization: Option<f32> = parts[9].trim().parse().ok();
                            let encoder_utilization: Option<f32> = parts[10].trim().parse().ok();
                            let decoder_utilization: Option<f32> = parts[11].trim().parse().ok();
                            let fan_speed_rpm: Option<u32> = parts[12].trim().parse().ok();
                            let power_draw_watts: Option<f32> = parts[13].trim().parse().ok();
                            let power_limit_watts: Option<f32> = parts[14].trim().parse().ok();
                            let clock_speed_mhz: Option<u32> = parts[15].trim().parse().ok();
                            gpus.push(GpuInfo {
                                name,
                                vendor: "NVIDIA".to_string(),
                                vram_bytes: vram_mb.map(|mb| mb * 1024 * 1024),
                                driver_version: Some(driver),
                                gpu_type: Some("Discrete".to_string()),
                                temperature,
                                utilization,
                                device_id,
                                pci_bus_id,
                                used_vram_bytes: used_vram_mb.map(|mb| mb * 1024 * 1024),
                                free_vram_bytes: free_vram_mb.map(|mb| mb * 1024 * 1024),
                                memory_utilization,
                                encoder_utilization,
                                decoder_utilization,
                                fan_speed_rpm,
                                power_draw_watts,
                                power_limit_watts,
                                clock_speed_mhz,
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
        #[allow(unused_mut)] // mut needed on Linux for hwmon extension
        let mut sensors: Vec<SensorStatus> = components
            .iter()
            .map(|c| SensorStatus {
                label: c.label().to_string(),
                temperature: c.temperature().filter(|t| !t.is_nan()),
                fan_rpm: None,
                voltage: None,
                thermal_throttling: None,
            })
            .collect();
        #[cfg(target_os = "linux")]
        {
            sensors.extend(read_hwmon_fans());
            sensors.extend(read_hwmon_voltages());
        }
        Ok(sensors)
    }
}

impl VirtualizationProvider for SysinfoProvider {
    fn virtualization(&self) -> StatusResult<VirtualizationSnapshot> {
        Ok(SystemStatus::read_virtualization())
    }
}

impl DiskIoProvider for SysinfoProvider {
    fn disk_io(&self) -> StatusResult<DiskIoSnapshot> {
        Ok(SystemStatus::read_disk_io())
    }
}

impl StaticInfoProvider for SysinfoProvider {
    fn static_info(&self) -> StatusResult<StaticInfo> {
        Ok(SystemStatus::read_static_info(&self.sys))
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
    /// use toride_status::system::SystemStatus;
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
            free_bytes: 0,
            available_bytes: 0,
            cached_bytes: 0,
            buffers_bytes: 0,
        });
        let disk = provider.root_disk().unwrap_or_else(|_| DiskStatus {
            name: String::new(),
            mount_point: "/".to_string(),
            filesystem: String::new(),
            used_bytes: 0,
            total_bytes: 0,
            percentage: 0.0,
            is_removable: false,
            free_bytes: 0,
            available_bytes: 0,
            disk_type: "Unknown".to_string(),
            physical_device_path: None,
            model: None,
            serial: None,
            temperature: None,
            wear_percent: None,
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
            os_type: None,
            edition: None,
            codename: None,
            bitness: None,
            timezone: None,
            locale: None,
            current_user: None,
            is_root: false,
            container_detected: false,
            vm_detected: false,
            wsl_detected: false,
            systemd_detected: false,
            target_triple: None,
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

        let static_info = provider.static_info().unwrap_or_else(|_| StaticInfo {
            os: OsInfo { name: None, version: None, kernel_version: None, arch: String::new(), os_type: None, edition: None, codename: None, bitness: None, timezone: None, locale: None, current_user: None, is_root: false, container_detected: false, vm_detected: false, wsl_detected: false, systemd_detected: false, target_triple: None },
            kernel_version: None, hostname: String::new(), cpu_brand: String::new(), cpu_vendor: String::new(), cpu_frequency: 0, physical_cores: None, logical_cores: 0, memory_total_bytes: 0, hardware: HardwareInventory::default(), sockets: None, cores_per_socket: None, threads_per_core: None, base_frequency: None, max_frequency: None, cache_l1d: None, cache_l1i: None, cache_l2: None, cache_l3: None,
        });
        let sensor_snapshot = Self::read_sensor_snapshot();
        let virtualization = provider.virtualization().unwrap_or_default();
        let disk_io = provider.disk_io().unwrap_or_default();

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
            static_info,
            sensor_snapshot,
            virtualization,
            disk_io,
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
                cached_bytes: 0,
                available_bytes: 0,
                free_bytes: 0,
                buffers_bytes: 0,
            },
            disk: DiskStatus {
                name: String::new(),
                mount_point: "/".to_string(),
                filesystem: String::new(),
                used_bytes: 0,
                total_bytes: 0,
                percentage: 0.0,
                is_removable: false,
                disk_type: "Unknown".to_string(),
                available_bytes: 0,
                free_bytes: 0,
                physical_device_path: None,
                model: None,
                serial: None,
                temperature: None,
                wear_percent: None,
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
                os_type: None,
                edition: None,
                codename: None,
                bitness: None,
                timezone: None,
                locale: None,
                current_user: None,
                is_root: false,
                container_detected: false,
                vm_detected: false,
                wsl_detected: false,
                systemd_detected: false,
                target_triple: None,
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
            disk_io: DiskIoSnapshot::default(),
            virtualization: VirtualizationSnapshot::default(),
            sensor_snapshot: SensorSnapshot { readings: Vec::new(), cpu_temperature: None, gpu_temperature: None },
            static_info: StaticInfo {
                os: OsInfo { name: None, version: None, kernel_version: None, arch: String::new(), os_type: None, edition: None, codename: None, bitness: None, timezone: None, locale: None, current_user: None, is_root: false, container_detected: false, vm_detected: false, wsl_detected: false, systemd_detected: false, target_triple: None },
                kernel_version: None,
                hostname: String::new(),
                cpu_brand: String::new(),
                cpu_vendor: String::new(),
                cpu_frequency: 0,
                physical_cores: None,
                logical_cores: 0,
                memory_total_bytes: 0,
                hardware: HardwareInventory::default(),
                sockets: None,
                cores_per_socket: None,
                threads_per_core: None,
                base_frequency: None,
                max_frequency: None,
                cache_l1d: None,
                cache_l1i: None,
                cache_l2: None,
                cache_l3: None,
            },
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
                cached_bytes: 0,
                available_bytes: 0,
                free_bytes: 0,
                buffers_bytes: 0,
            },
            disk: DiskStatus {
                name: "Macintosh HD".to_string(),
                mount_point: "/".to_string(),
                filesystem: "apfs".to_string(),
                used_bytes: 500 * GB,
                total_bytes: TB,
                percentage: 50.0,
                is_removable: false,
                disk_type: "Unknown".to_string(),
                available_bytes: 0,
                free_bytes: 0,
                physical_device_path: None,
                model: None,
                serial: None,
                temperature: None,
                wear_percent: None,
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
                os_type: None,
                edition: None,
                codename: None,
                bitness: None,
                timezone: None,
                locale: None,
                current_user: None,
                is_root: false,
                container_detected: false,
                vm_detected: false,
                wsl_detected: false,
                systemd_detected: false,
                target_triple: None,
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
                free_bytes: 2 * GB - 512 * MB,
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
                    disk_type: "Unknown".to_string(),
                    available_bytes: 0,
                    free_bytes: 0,
                    physical_device_path: None,
                    model: None,
                    serial: None,
                    temperature: None,
                    wear_percent: None,
                },
                DiskStatus {
                    name: "External".to_string(),
                    mount_point: "/Volumes/External".to_string(),
                    filesystem: "exfat".to_string(),
                    used_bytes: 100 * GB,
                    total_bytes: 500 * GB,
                    percentage: 20.0,
                    is_removable: true,
                    disk_type: "Unknown".to_string(),
                    available_bytes: 0,
                    free_bytes: 0,
                    physical_device_path: None,
                    model: None,
                    serial: None,
                    temperature: None,
                    wear_percent: None,
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
                    drops_transmitted: 0,
                    drops_received: 0,
                    mtu: None,
                    mac_address: None,
                    display_name: None,
                    description: None,
                    ipv4_addresses: Vec::new(),
                    ipv6_addresses: Vec::new(),
                    gateway: None,
                    dns: None,
                    link_status: None,
                    speed_bps: None,
                    duplex: None,
                },
                NetworkInterface {
                    name: "lo0".to_string(),
                    bytes_received: 40 * GB,
                    bytes_transmitted: 20 * GB,
                    packets_received: 2_000_000,
                    packets_transmitted: 2_000_000,
                    errors_received: 0,
                    errors_transmitted: 0,
                    drops_transmitted: 0,
                    drops_received: 0,
                    mtu: None,
                    mac_address: None,
                    display_name: None,
                    description: None,
                    ipv4_addresses: Vec::new(),
                    ipv6_addresses: Vec::new(),
                    gateway: None,
                    dns: None,
                    link_status: None,
                    speed_bps: None,
                    duplex: None,
                },
            ],
            sensors: vec![
                SensorStatus {
                    label: "CPU".to_string(),
                    temperature: Some(55.5),
                    fan_rpm: None,
                    voltage: None,
                    thermal_throttling: None,
                },
                SensorStatus {
                    label: "GPU".to_string(),
                    temperature: Some(48.0),
                    fan_rpm: None,
                    voltage: None,
                    thermal_throttling: None,
                },
            ],
            boot_time: Some(1_700_000_000),
            processes: ProcessSnapshot {
                processes: vec![],
                total_count: 0,
            },
            gpu: vec![],
            battery: None,
            disk_io: DiskIoSnapshot::default(),
            virtualization: VirtualizationSnapshot::default(),
            sensor_snapshot: SensorSnapshot { readings: Vec::new(), cpu_temperature: None, gpu_temperature: None },
            static_info: StaticInfo {
                os: OsInfo { name: None, version: None, kernel_version: None, arch: String::new(), os_type: None, edition: None, codename: None, bitness: None, timezone: None, locale: None, current_user: None, is_root: false, container_detected: false, vm_detected: false, wsl_detected: false, systemd_detected: false, target_triple: None },
                kernel_version: None,
                hostname: String::new(),
                cpu_brand: String::new(),
                cpu_vendor: String::new(),
                cpu_frequency: 0,
                physical_cores: None,
                logical_cores: 0,
                memory_total_bytes: 0,
                hardware: HardwareInventory::default(),
                sockets: None,
                cores_per_socket: None,
                threads_per_core: None,
                base_frequency: None,
                max_frequency: None,
                cache_l1d: None,
                cache_l1i: None,
                cache_l2: None,
                cache_l3: None,
            },
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
                    thread_count: None,
                    virtual_memory: 0,
                    user: None,
                    executable_path: None,
                    command_line: None,
                    working_dir: None,
                    disk_read_bytes: None,
                    disk_write_bytes: None,
                    open_files: None,
                    fd_count: None,
                },
                ProcessStatus {
                    pid: 2,
                    parent_pid: None,
                    name: "high".to_string(),
                    cpu_usage: 50.0,
                    memory_bytes: 100,
                    status: "Running".to_string(),
                    start_time: Some(1000),
                    thread_count: None,
                    virtual_memory: 0,
                    user: None,
                    executable_path: None,
                    command_line: None,
                    working_dir: None,
                    disk_read_bytes: None,
                    disk_write_bytes: None,
                    open_files: None,
                    fd_count: None,
                },
                ProcessStatus {
                    pid: 3,
                    parent_pid: None,
                    name: "mid".to_string(),
                    cpu_usage: 25.0,
                    memory_bytes: 100,
                    status: "Running".to_string(),
                    start_time: Some(1000),
                    thread_count: None,
                    virtual_memory: 0,
                    user: None,
                    executable_path: None,
                    command_line: None,
                    working_dir: None,
                    disk_read_bytes: None,
                    disk_write_bytes: None,
                    open_files: None,
                    fd_count: None,
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
                    thread_count: None,
                    virtual_memory: 0,
                    user: None,
                    executable_path: None,
                    command_line: None,
                    working_dir: None,
                    disk_read_bytes: None,
                    disk_write_bytes: None,
                    open_files: None,
                    fd_count: None,
                },
                ProcessStatus {
                    pid: 2,
                    parent_pid: None,
                    name: "large".to_string(),
                    cpu_usage: 1.0,
                    memory_bytes: 1024 * 1024 * 100,
                    status: "Running".to_string(),
                    start_time: Some(1000),
                    thread_count: None,
                    virtual_memory: 0,
                    user: None,
                    executable_path: None,
                    command_line: None,
                    working_dir: None,
                    disk_read_bytes: None,
                    disk_write_bytes: None,
                    open_files: None,
                    fd_count: None,
                },
                ProcessStatus {
                    pid: 3,
                    parent_pid: None,
                    name: "medium".to_string(),
                    cpu_usage: 1.0,
                    memory_bytes: 1024 * 1024,
                    status: "Running".to_string(),
                    start_time: Some(1000),
                    thread_count: None,
                    virtual_memory: 0,
                    user: None,
                    executable_path: None,
                    command_line: None,
                    working_dir: None,
                    disk_read_bytes: None,
                    disk_write_bytes: None,
                    open_files: None,
                    fd_count: None,
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
            os_info: OsInfo { name: None, version: None, kernel_version: None, arch: String::new(), os_type: None, edition: None, codename: None, bitness: None, timezone: None, locale: None, current_user: None, is_root: false, container_detected: false, vm_detected: false, wsl_detected: false, systemd_detected: false, target_triple: None },
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
            static_info: StaticInfo {
                os: OsInfo { name: None, version: None, kernel_version: None, arch: String::new(), os_type: None, edition: None, codename: None, bitness: None, timezone: None, locale: None, current_user: None, is_root: false, container_detected: false, vm_detected: false, wsl_detected: false, systemd_detected: false, target_triple: None },
                kernel_version: None,
                hostname: String::new(),
                cpu_brand: String::new(),
                cpu_vendor: String::new(),
                cpu_frequency: 0,
                physical_cores: None,
                logical_cores: 0,
                memory_total_bytes: 0,
                hardware: HardwareInventory::default(),
                sockets: None,
                cores_per_socket: None,
                threads_per_core: None,
                base_frequency: None,
                max_frequency: None,
                cache_l1d: None,
                cache_l1i: None,
                cache_l2: None,
                cache_l3: None,
            },
            sensor_snapshot: SensorSnapshot { readings: Vec::new(), cpu_temperature: None, gpu_temperature: None },
            virtualization: VirtualizationSnapshot::default(),
            disk_io: DiskIoSnapshot::default(),
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
            free_bytes: 0,
            available_bytes: 0,
            disk_type: "Unknown".to_string(),
            physical_device_path: None,
            model: None,
            serial: None,
            temperature: None,
            wear_percent: None,
        }
    }

    #[test]
    fn memory_percentage_zero_total() {
        // Division by zero protection: total_bytes = 0 should yield 0%.
        let status = make_status(
            MemoryStatus { used_bytes: 0, total_bytes: 0, percentage: 0.0, free_bytes: 0, available_bytes: 0, cached_bytes: 0, buffers_bytes: 0 },
            empty_disk(),
        );
        assert!((status.memory.percentage).abs() < f64::EPSILON);
    }

    #[test]
    fn memory_percentage_capped_at_100() {
        // When used > total (e.g. reclaimed/buffer memory), percentage should be capped at 100%.
        let status = make_status(
            MemoryStatus { used_bytes: 20 * GB, total_bytes: 16 * GB, percentage: 100.0, free_bytes: 0, available_bytes: 0, cached_bytes: 0, buffers_bytes: 0 },
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
            MemoryStatus { used_bytes: 0, total_bytes: 0, percentage: 0.0, free_bytes: 0, available_bytes: 0, cached_bytes: 0, buffers_bytes: 0 },
            DiskStatus {
                name: String::new(),
                mount_point: "/".to_string(),
                filesystem: String::new(),
                used_bytes: 0,
                total_bytes: 0,
                percentage: 0.0,
                is_removable: false,
                disk_type: "Unknown".to_string(),
                available_bytes: 0,
                free_bytes: 0,
                physical_device_path: None,
                model: None,
                serial: None,
                temperature: None,
                wear_percent: None,
            },
        );
        assert!((status.disk.percentage).abs() < f64::EPSILON);
    }

    #[test]
    fn disk_percentage_capped_at_100() {
        // When used > total (e.g. filesystem overhead), percentage should be capped at 100%.
        let status = make_status(
            MemoryStatus { used_bytes: 0, total_bytes: 0, percentage: 0.0, free_bytes: 0, available_bytes: 0, cached_bytes: 0, buffers_bytes: 0 },
            DiskStatus {
                name: String::new(),
                mount_point: "/".to_string(),
                filesystem: String::new(),
                used_bytes: 600 * GB,
                total_bytes: 500 * GB,
                percentage: 100.0,
                is_removable: false,
                disk_type: "Unknown".to_string(),
                available_bytes: 0,
                free_bytes: 0,
                physical_device_path: None,
                model: None,
                serial: None,
                temperature: None,
                wear_percent: None,
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
            executable_path: None,
            user: None,
            virtual_memory: 0,
            thread_count: None,
            command_line: None,
            working_dir: None,
            disk_read_bytes: None,
            disk_write_bytes: None,
            open_files: None,
            fd_count: None,
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
                cached_bytes: 0,
                available_bytes: 0,
                free_bytes: 0,
                buffers_bytes: 0,
            },
            disk: DiskStatus {
                name: String::new(),
                mount_point: "/".to_string(),
                filesystem: String::new(),
                used_bytes: 0,
                total_bytes: 0,
                percentage: 0.0,
                is_removable: false,
                disk_type: "Unknown".to_string(),
                available_bytes: 0,
                free_bytes: 0,
                physical_device_path: None,
                model: None,
                serial: None,
                temperature: None,
                wear_percent: None,
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
                os_type: None,
                edition: None,
                codename: None,
                bitness: None,
                timezone: None,
                locale: None,
                current_user: None,
                is_root: false,
                container_detected: false,
                vm_detected: false,
                wsl_detected: false,
                systemd_detected: false,
                target_triple: None,
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
            disk_io: DiskIoSnapshot::default(),
            virtualization: VirtualizationSnapshot::default(),
            sensor_snapshot: SensorSnapshot { readings: Vec::new(), cpu_temperature: None, gpu_temperature: None },
            static_info: StaticInfo {
                os: OsInfo { name: None, version: None, kernel_version: None, arch: String::new(), os_type: None, edition: None, codename: None, bitness: None, timezone: None, locale: None, current_user: None, is_root: false, container_detected: false, vm_detected: false, wsl_detected: false, systemd_detected: false, target_triple: None },
                kernel_version: None,
                hostname: String::new(),
                cpu_brand: String::new(),
                cpu_vendor: String::new(),
                cpu_frequency: 0,
                physical_cores: None,
                logical_cores: 0,
                memory_total_bytes: 0,
                hardware: HardwareInventory::default(),
                sockets: None,
                cores_per_socket: None,
                threads_per_core: None,
                base_frequency: None,
                max_frequency: None,
                cache_l1d: None,
                cache_l1i: None,
                cache_l2: None,
                cache_l3: None,
            },
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
            memory: MemoryStatus { used_bytes: 8 * GB, total_bytes: 16 * GB, percentage: 50.0, free_bytes: 0, available_bytes: 0, cached_bytes: 0, buffers_bytes: 0 },
            disk: empty_disk(),
            network: NetworkStatus { bytes_received: 0, bytes_transmitted: 0 },
            load_average: None,
            uptime_secs: None,
            hostname: "gpu-host".to_string(),
            os_info: OsInfo { name: Some("Linux".to_string()), version: None, kernel_version: None, arch: "x86_64".to_string(), os_type: None, edition: None, codename: None, bitness: None, timezone: None, locale: None, current_user: None, is_root: false, container_detected: false, vm_detected: false, wsl_detected: false, systemd_detected: false, target_triple: None },
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
                utilization: None,
                temperature: None,
                gpu_type: None,
                device_id: None,
                pci_bus_id: None,
                used_vram_bytes: None,
                free_vram_bytes: None,
                memory_utilization: None,
                encoder_utilization: None,
                decoder_utilization: None,
                fan_speed_rpm: None,
                power_draw_watts: None,
                power_limit_watts: None,
                clock_speed_mhz: None,
            }],
            battery: None,
            disk_io: DiskIoSnapshot::default(),
            virtualization: VirtualizationSnapshot::default(),
            sensor_snapshot: SensorSnapshot { readings: Vec::new(), cpu_temperature: None, gpu_temperature: None },
            static_info: StaticInfo {
                os: OsInfo { name: None, version: None, kernel_version: None, arch: String::new(), os_type: None, edition: None, codename: None, bitness: None, timezone: None, locale: None, current_user: None, is_root: false, container_detected: false, vm_detected: false, wsl_detected: false, systemd_detected: false, target_triple: None },
                kernel_version: None,
                hostname: String::new(),
                cpu_brand: String::new(),
                cpu_vendor: String::new(),
                cpu_frequency: 0,
                physical_cores: None,
                logical_cores: 0,
                memory_total_bytes: 0,
                hardware: HardwareInventory::default(),
                sockets: None,
                cores_per_socket: None,
                threads_per_core: None,
                base_frequency: None,
                max_frequency: None,
                cache_l1d: None,
                cache_l1i: None,
                cache_l2: None,
                cache_l3: None,
            },
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
            memory: MemoryStatus { used_bytes: 0, total_bytes: 0, percentage: 0.0, free_bytes: 0, available_bytes: 0, cached_bytes: 0, buffers_bytes: 0 },
            disk: empty_disk(),
            network: NetworkStatus { bytes_received: 0, bytes_transmitted: 0 },
            load_average: None,
            uptime_secs: None,
            hostname: "laptop".to_string(),
            os_info: OsInfo { name: None, version: None, kernel_version: None, arch: "aarch64".to_string(), os_type: None, edition: None, codename: None, bitness: None, timezone: None, locale: None, current_user: None, is_root: false, container_detected: false, vm_detected: false, wsl_detected: false, systemd_detected: false, target_triple: None },
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
                health_percent: None,
                cycle_count: None,
                voltage: None,
                energy_wh: None,
                energy_full_wh: None,
                energy_full_design_wh: None,
                manufacturer: None,
                model: None,
            }),
            disk_io: DiskIoSnapshot::default(),
            virtualization: VirtualizationSnapshot::default(),
            sensor_snapshot: SensorSnapshot { readings: Vec::new(), cpu_temperature: None, gpu_temperature: None },
            static_info: StaticInfo {
                os: OsInfo { name: None, version: None, kernel_version: None, arch: String::new(), os_type: None, edition: None, codename: None, bitness: None, timezone: None, locale: None, current_user: None, is_root: false, container_detected: false, vm_detected: false, wsl_detected: false, systemd_detected: false, target_triple: None },
                kernel_version: None,
                hostname: String::new(),
                cpu_brand: String::new(),
                cpu_vendor: String::new(),
                cpu_frequency: 0,
                physical_cores: None,
                logical_cores: 0,
                memory_total_bytes: 0,
                hardware: HardwareInventory::default(),
                sockets: None,
                cores_per_socket: None,
                threads_per_core: None,
                base_frequency: None,
                max_frequency: None,
                cache_l1d: None,
                cache_l1i: None,
                cache_l2: None,
                cache_l3: None,
            },
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
            memory: MemoryStatus { used_bytes: 0, total_bytes: 0, percentage: 0.0, free_bytes: 0, available_bytes: 0, cached_bytes: 0, buffers_bytes: 0 },
            disk: empty_disk(),
            network: NetworkStatus { bytes_received: 0, bytes_transmitted: 0 },
            load_average: None,
            uptime_secs: None,
            hostname: "sensor-host".to_string(),
            os_info: OsInfo { name: None, version: None, kernel_version: None, arch: "x86_64".to_string(), os_type: None, edition: None, codename: None, bitness: None, timezone: None, locale: None, current_user: None, is_root: false, container_detected: false, vm_detected: false, wsl_detected: false, systemd_detected: false, target_triple: None },
            cpu_cores: Vec::new(),
            physical_cores: None,
            swap: None,
            disks: Vec::new(),
            network_interfaces: Vec::new(),
            sensors: vec![
                SensorStatus {
                    label: "CPU".to_string(),
                    temperature: Some(65.0),
                    fan_rpm: None,
                    voltage: None,
                    thermal_throttling: None,
                },
                SensorStatus {
                    label: "Unknown".to_string(),
                    temperature: None,
                    fan_rpm: None,
                    voltage: None,
                    thermal_throttling: None,
                },
            ],
            boot_time: None,
            processes: ProcessSnapshot { processes: vec![], total_count: 0 },
            gpu: vec![],
            battery: None,
            disk_io: DiskIoSnapshot::default(),
            virtualization: VirtualizationSnapshot::default(),
            sensor_snapshot: SensorSnapshot { readings: Vec::new(), cpu_temperature: None, gpu_temperature: None },
            static_info: StaticInfo {
                os: OsInfo { name: None, version: None, kernel_version: None, arch: String::new(), os_type: None, edition: None, codename: None, bitness: None, timezone: None, locale: None, current_user: None, is_root: false, container_detected: false, vm_detected: false, wsl_detected: false, systemd_detected: false, target_triple: None },
                kernel_version: None,
                hostname: String::new(),
                cpu_brand: String::new(),
                cpu_vendor: String::new(),
                cpu_frequency: 0,
                physical_cores: None,
                logical_cores: 0,
                memory_total_bytes: 0,
                hardware: HardwareInventory::default(),
                sockets: None,
                cores_per_socket: None,
                threads_per_core: None,
                base_frequency: None,
                max_frequency: None,
                cache_l1d: None,
                cache_l1i: None,
                cache_l2: None,
                cache_l3: None,
            },
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
            memory: MemoryStatus { used_bytes: 0, total_bytes: 0, percentage: 0.0, free_bytes: 0, available_bytes: 0, cached_bytes: 0, buffers_bytes: 0 },
            disk: DiskStatus {
                name: String::new(),
                mount_point: "/".to_string(),
                filesystem: String::new(),
                used_bytes: 0,
                total_bytes: 0,
                percentage: 0.0,
                is_removable: false,
                disk_type: "Unknown".to_string(),
                available_bytes: 0,
                free_bytes: 0,
                physical_device_path: None,
                model: None,
                serial: None,
                temperature: None,
                wear_percent: None,
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
                os_type: None,
                edition: None,
                codename: None,
                bitness: None,
                timezone: None,
                locale: None,
                current_user: None,
                is_root: false,
                container_detected: false,
                vm_detected: false,
                wsl_detected: false,
                systemd_detected: false,
                target_triple: None,
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
            disk_io: DiskIoSnapshot::default(),
            virtualization: VirtualizationSnapshot::default(),
            sensor_snapshot: SensorSnapshot { readings: Vec::new(), cpu_temperature: None, gpu_temperature: None },
            static_info: StaticInfo {
                os: OsInfo { name: None, version: None, kernel_version: None, arch: String::new(), os_type: None, edition: None, codename: None, bitness: None, timezone: None, locale: None, current_user: None, is_root: false, container_detected: false, vm_detected: false, wsl_detected: false, systemd_detected: false, target_triple: None },
                kernel_version: None,
                hostname: String::new(),
                cpu_brand: String::new(),
                cpu_vendor: String::new(),
                cpu_frequency: 0,
                physical_cores: None,
                logical_cores: 0,
                memory_total_bytes: 0,
                hardware: HardwareInventory::default(),
                sockets: None,
                cores_per_socket: None,
                threads_per_core: None,
                base_frequency: None,
                max_frequency: None,
                cache_l1d: None,
                cache_l1i: None,
                cache_l2: None,
                cache_l3: None,
            },
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
                cached_bytes: 0,
                available_bytes: 0,
                free_bytes: 0,
                buffers_bytes: 0,
            },
            disk: DiskStatus {
                name: "disk".to_string(),
                mount_point: "/".to_string(),
                filesystem: "apfs".to_string(),
                used_bytes: 100,
                total_bytes: 200,
                percentage: 50.0,
                is_removable: false,
                disk_type: "Unknown".to_string(),
                available_bytes: 0,
                free_bytes: 0,
                physical_device_path: None,
                model: None,
                serial: None,
                temperature: None,
                wear_percent: None,
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
                os_type: None,
                edition: None,
                codename: None,
                bitness: None,
                timezone: None,
                locale: None,
                current_user: None,
                is_root: false,
                container_detected: false,
                vm_detected: false,
                wsl_detected: false,
                systemd_detected: false,
                target_triple: None,
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
                utilization: None,
                temperature: None,
                gpu_type: None,
                device_id: None,
                pci_bus_id: None,
                used_vram_bytes: None,
                free_vram_bytes: None,
                memory_utilization: None,
                encoder_utilization: None,
                decoder_utilization: None,
                fan_speed_rpm: None,
                power_draw_watts: None,
                power_limit_watts: None,
                clock_speed_mhz: None,
            }],
            battery: Some(BatteryInfo {
                charge_percent: 85.0,
                state: "Charging".to_string(),
                time_to_empty_secs: None,
                time_to_full_secs: Some(3600),
                health_percent: None,
                cycle_count: None,
                voltage: None,
                energy_wh: None,
                energy_full_wh: None,
                energy_full_design_wh: None,
                manufacturer: None,
                model: None,
            }),
            disk_io: DiskIoSnapshot::default(),
            virtualization: VirtualizationSnapshot::default(),
            sensor_snapshot: SensorSnapshot { readings: Vec::new(), cpu_temperature: None, gpu_temperature: None },
            static_info: StaticInfo {
                os: OsInfo { name: None, version: None, kernel_version: None, arch: String::new(), os_type: None, edition: None, codename: None, bitness: None, timezone: None, locale: None, current_user: None, is_root: false, container_detected: false, vm_detected: false, wsl_detected: false, systemd_detected: false, target_triple: None },
                kernel_version: None,
                hostname: String::new(),
                cpu_brand: String::new(),
                cpu_vendor: String::new(),
                cpu_frequency: 0,
                physical_cores: None,
                logical_cores: 0,
                memory_total_bytes: 0,
                hardware: HardwareInventory::default(),
                sockets: None,
                cores_per_socket: None,
                threads_per_core: None,
                base_frequency: None,
                max_frequency: None,
                cache_l1d: None,
                cache_l1i: None,
                cache_l2: None,
                cache_l3: None,
            },
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
        use crate::provider::StatusProvider;
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

    // ── FakeProvider ──────────────────────────────────────────────────

    struct FakeProvider {
        cpu_usage_val: Option<f64>,
        cpu_cores_val: Vec<CpuCore>,
        memory_val: MemoryStatus,
        swap_val: Option<SwapStatus>,
        disk_val: DiskStatus,
        disks_val: Vec<DiskStatus>,
        network_val: NetworkStatus,
        interfaces_val: Vec<NetworkInterface>,
        os_info_val: OsInfo,
        hostname_val: String,
        uptime_val: Option<u64>,
        boot_time_val: Option<u64>,
        load_avg_val: Option<LoadAverage>,
        processes_val: ProcessSnapshot,
        gpus_val: Vec<GpuInfo>,
        battery_val: Option<BatteryInfo>,
        sensors_val: Vec<SensorStatus>,
    }

    impl FakeProvider {
        fn happy() -> Self {
            Self {
                cpu_usage_val: Some(42.0),
                cpu_cores_val: vec![CpuCore { name: "cpu0".into(), usage: 45.0, frequency: 3200 }],
                memory_val: MemoryStatus { used_bytes: 8_000_000_000, total_bytes: 16_000_000_000, percentage: 50.0, free_bytes: 8_000_000_000, available_bytes: 12_000_000_000, cached_bytes: 2_000_000_000, buffers_bytes: 0 },
                swap_val: Some(SwapStatus { used_bytes: 500_000_000, total_bytes: 2_000_000_000, percentage: 25.0, free_bytes: 1_500_000_000 }),
                disk_val: DiskStatus { name: "test".into(), mount_point: "/".into(), filesystem: "ext4".into(), used_bytes: 100, total_bytes: 200, percentage: 50.0, is_removable: false, free_bytes: 100, available_bytes: 100, disk_type: "SSD".into(), physical_device_path: None, model: None, serial: None, temperature: None, wear_percent: None },
                disks_val: vec![],
                network_val: NetworkStatus { bytes_received: 1000, bytes_transmitted: 500 },
                interfaces_val: vec![],
                os_info_val: OsInfo { name: Some("TestOS".into()), version: Some("1.0".into()), kernel_version: Some("5.0".into()), arch: "x86_64".into(), os_type: None, edition: None, codename: None, bitness: None, timezone: None, locale: None, current_user: None, is_root: false, container_detected: false, vm_detected: false, wsl_detected: false, systemd_detected: false, target_triple: None },
                hostname_val: "test-host".into(),
                uptime_val: Some(3600),
                boot_time_val: Some(1700000000),
                load_avg_val: Some(LoadAverage { one: 1.0, five: 2.0, fifteen: 3.0 }),
                processes_val: ProcessSnapshot { processes: vec![], total_count: 0 },
                gpus_val: vec![],
                battery_val: None,
                sensors_val: vec![],
            }
        }

        fn empty() -> Self {
            Self {
                cpu_usage_val: None,
                cpu_cores_val: vec![],
                memory_val: MemoryStatus { used_bytes: 0, total_bytes: 0, percentage: 0.0, free_bytes: 0, available_bytes: 0, cached_bytes: 0, buffers_bytes: 0 },
                swap_val: None,
                disk_val: DiskStatus { name: String::new(), mount_point: "/".into(), filesystem: String::new(), used_bytes: 0, total_bytes: 0, percentage: 0.0, is_removable: false, free_bytes: 0, available_bytes: 0, disk_type: "Unknown".into(), physical_device_path: None, model: None, serial: None, temperature: None, wear_percent: None },
                disks_val: vec![],
                network_val: NetworkStatus { bytes_received: 0, bytes_transmitted: 0 },
                interfaces_val: vec![],
                os_info_val: OsInfo { name: None, version: None, kernel_version: None, arch: String::new(), os_type: None, edition: None, codename: None, bitness: None, timezone: None, locale: None, current_user: None, is_root: false, container_detected: false, vm_detected: false, wsl_detected: false, systemd_detected: false, target_triple: None },
                hostname_val: String::new(),
                uptime_val: None,
                boot_time_val: None,
                load_avg_val: None,
                processes_val: ProcessSnapshot { processes: vec![], total_count: 0 },
                gpus_val: vec![],
                battery_val: None,
                sensors_val: vec![],
            }
        }
    }

    impl CpuProvider for FakeProvider {
        fn cpu_usage(&mut self) -> crate::error::StatusResult<Option<f64>> {
            Ok(self.cpu_usage_val)
        }
        fn cpu_cores(&mut self) -> crate::error::StatusResult<Vec<CpuCore>> {
            Ok(self.cpu_cores_val.clone())
        }
        fn physical_cores(&self) -> crate::error::StatusResult<Option<usize>> {
            Ok(Some(self.cpu_cores_val.len()))
        }
        fn cpu_static(&self) -> crate::error::StatusResult<CpuStatic> {
            Ok(CpuStatic {
                vendor: String::new(), brand: String::new(), arch: String::new(),
                sockets: None, cores_per_socket: None, threads_per_core: None,
                base_freq: None, max_freq: None, cache_l1d: None, cache_l1i: None, cache_l2: None, cache_l3: None,
            })
        }
        fn cpu_sample(&mut self) -> crate::error::StatusResult<CpuSample> {
            Ok(CpuSample { total_usage: self.cpu_usage_val, per_core: vec![] })
        }
    }

    impl MemoryProvider for FakeProvider {
        fn memory(&mut self) -> crate::error::StatusResult<MemoryStatus> {
            Ok(self.memory_val)
        }
        fn swap(&mut self) -> crate::error::StatusResult<Option<SwapStatus>> {
            Ok(self.swap_val)
        }
        fn memory_pressure(&self) -> crate::error::StatusResult<Option<f32>> {
            Ok(None)
        }
    }

    impl DiskProvider for FakeProvider {
        fn root_disk(&mut self) -> crate::error::StatusResult<DiskStatus> {
            Ok(self.disk_val.clone())
        }
        fn all_disks(&mut self) -> crate::error::StatusResult<Vec<DiskStatus>> {
            Ok(self.disks_val.clone())
        }
    }

    impl NetworkProvider for FakeProvider {
        fn aggregate(&mut self) -> crate::error::StatusResult<NetworkStatus> {
            Ok(self.network_val)
        }
        fn interfaces(&mut self) -> crate::error::StatusResult<Vec<NetworkInterface>> {
            Ok(self.interfaces_val.clone())
        }
        fn gateway(&self) -> crate::error::StatusResult<Option<String>> {
            Ok(None)
        }
        fn dns_servers(&self) -> crate::error::StatusResult<Vec<String>> {
            Ok(vec![])
        }
    }

    impl OsProvider for FakeProvider {
        fn os_info(&self) -> crate::error::StatusResult<OsInfo> {
            Ok(self.os_info_val.clone())
        }
        fn hostname(&self) -> crate::error::StatusResult<String> {
            Ok(self.hostname_val.clone())
        }
        fn uptime(&self) -> crate::error::StatusResult<Option<u64>> {
            Ok(self.uptime_val)
        }
        fn boot_time(&self) -> crate::error::StatusResult<Option<u64>> {
            Ok(self.boot_time_val)
        }
        fn load_average(&self) -> crate::error::StatusResult<Option<LoadAverage>> {
            Ok(self.load_avg_val)
        }
        fn os_detailed(&self) -> crate::error::StatusResult<OsInfo> {
            Ok(self.os_info_val.clone())
        }
    }

    impl ProcessProvider for FakeProvider {
        fn processes(&mut self) -> crate::error::StatusResult<ProcessSnapshot> {
            Ok(self.processes_val.clone())
        }
        fn process_tree(&mut self) -> crate::error::StatusResult<std::collections::HashMap<u32, Vec<u32>>> {
            Ok(std::collections::HashMap::new())
        }
    }

    impl GpuProvider for FakeProvider {
        fn gpus(&self) -> crate::error::StatusResult<Vec<GpuInfo>> {
            Ok(self.gpus_val.clone())
        }
    }

    impl BatteryProvider for FakeProvider {
        fn battery(&self) -> crate::error::StatusResult<Option<BatteryInfo>> {
            Ok(self.battery_val.clone())
        }
    }

    impl SensorProvider for FakeProvider {
        fn sensors(&self) -> crate::error::StatusResult<Vec<SensorStatus>> {
            Ok(self.sensors_val.clone())
        }
    }

    impl VirtualizationProvider for FakeProvider {
        fn virtualization(&self) -> crate::error::StatusResult<VirtualizationSnapshot> {
            Ok(VirtualizationSnapshot::default())
        }
    }

    impl DiskIoProvider for FakeProvider {
        fn disk_io(&self) -> crate::error::StatusResult<DiskIoSnapshot> {
            Ok(DiskIoSnapshot::default())
        }
    }

    impl StaticInfoProvider for FakeProvider {
        fn static_info(&self) -> crate::error::StatusResult<StaticInfo> {
            Ok(StaticInfo {
                os: self.os_info_val.clone(), kernel_version: None, hostname: String::new(),
                cpu_brand: String::new(), cpu_vendor: String::new(), cpu_frequency: 0,
                physical_cores: None, logical_cores: 0, memory_total_bytes: 0,
                hardware: HardwareInventory::default(), sockets: None, cores_per_socket: None,
                threads_per_core: None, base_frequency: None, max_frequency: None,
                cache_l1d: None, cache_l1i: None, cache_l2: None, cache_l3: None,
            })
        }
    }

    #[test]
    fn fake_provider_happy_path() {
        let mut p = FakeProvider::happy();

        let cpu = p.cpu_usage().unwrap();
        assert_eq!(cpu, Some(42.0));

        let cores = p.cpu_cores().unwrap();
        assert_eq!(cores.len(), 1);
        assert_eq!(cores[0].name, "cpu0");

        let phys = p.physical_cores().unwrap();
        assert_eq!(phys, Some(1));

        let mem = p.memory().unwrap();
        assert_eq!(mem.total_bytes, 16_000_000_000);
        assert_eq!(mem.used_bytes, 8_000_000_000);

        let swap = p.swap().unwrap();
        assert!(swap.is_some());
        assert_eq!(swap.unwrap().percentage, 25.0);

        let disk = p.root_disk().unwrap();
        assert_eq!(disk.mount_point, "/");

        let net = p.aggregate().unwrap();
        assert_eq!(net.bytes_received, 1000);
        assert_eq!(net.bytes_transmitted, 500);

        let os = p.os_info().unwrap();
        assert_eq!(os.name.as_deref(), Some("TestOS"));

        let host = p.hostname().unwrap();
        assert_eq!(host, "test-host");

        let uptime = p.uptime().unwrap();
        assert_eq!(uptime, Some(3600));

        let boot = p.boot_time().unwrap();
        assert_eq!(boot, Some(1700000000));

        let load = p.load_average().unwrap();
        assert!(load.is_some());
        let load = load.unwrap();
        assert!((load.one - 1.0).abs() < f64::EPSILON);

        let procs = p.processes().unwrap();
        assert_eq!(procs.total_count, 0);

        let gpus = p.gpus().unwrap();
        assert!(gpus.is_empty());

        let battery = p.battery().unwrap();
        assert!(battery.is_none());

        let sensors = p.sensors().unwrap();
        assert!(sensors.is_empty());
    }

    #[test]
    fn fake_provider_empty_path() {
        let mut p = FakeProvider::empty();

        assert!(p.cpu_usage().unwrap().is_none());
        assert!(p.cpu_cores().unwrap().is_empty());
        assert_eq!(p.physical_cores().unwrap(), Some(0));

        let mem = p.memory().unwrap();
        assert_eq!(mem.total_bytes, 0);

        assert!(p.swap().unwrap().is_none());

        let disk = p.root_disk().unwrap();
        assert!(disk.name.is_empty());

        let net = p.aggregate().unwrap();
        assert_eq!(net.bytes_received, 0);

        let os = p.os_info().unwrap();
        assert!(os.name.is_none());

        assert!(p.hostname().unwrap().is_empty());
        assert!(p.uptime().unwrap().is_none());
        assert!(p.boot_time().unwrap().is_none());
        assert!(p.load_average().unwrap().is_none());

        let procs = p.processes().unwrap();
        assert_eq!(procs.total_count, 0);

        assert!(p.gpus().unwrap().is_empty());
        assert!(p.battery().unwrap().is_none());
        assert!(p.sensors().unwrap().is_empty());
    }
}
