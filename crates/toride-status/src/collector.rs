//! Collector for periodic status snapshots and delta computation.
//!
//! [`Collector`] manages periodic collection of system status and
//! computes deltas between consecutive snapshots for rate-based metrics.
//!
//! # Delta computation
//!
//! When two consecutive snapshots are taken, [`SystemDelta`] computes:
//! - **CPU usage delta**: the change in CPU percentage between snapshots.
//! - **Network byte deltas**: the number of bytes received/transmitted
//!   since the last snapshot.
//! - **Network rates**: bytes per second, calculated as
//!   `delta_bytes / elapsed_seconds`.
//!
//! The first call to [`Collector::collect`] always returns `None` for the
//! delta because there is no previous snapshot to compare against.
//!
//! # Examples
//!
//! Periodic collection with delta tracking:
//!
//! ```no_run
//! use std::time::Duration;
//! use toride_status::collector::Collector;
//! use toride_status::presets::Preset;
//!
//! let mut collector = Collector::new(Duration::from_secs(1), Preset::Diagnostics);
//!
//! // First call: no delta available.
//! let (status, delta) = collector.collect();
//! assert!(delta.is_none());
//!
//! // Second call: delta computed from previous snapshot.
//! std::thread::sleep(Duration::from_secs(1));
//! let (status, delta) = collector.collect();
//! if let Some(d) = delta {
//!     println!("Network RX rate: {:.1} B/s", d.network.bytes_received_rate);
//! }
//! ```
//!
//! Blocking collection that waits for the interval:
//!
//! ```no_run
//! use std::time::Duration;
//! use toride_status::collector::Collector;
//!
//! let mut collector = Collector::default_collector();
//! loop {
//!     let (status, delta) = collector.collect_after_interval();
//!     // Process status and delta...
//!     break; // Remove this in real usage
//! }
//! ```

use std::time::{Duration, Instant};

use serde::Serialize;

use crate::presets::Preset;
use crate::system::SystemStatus;
use crate::TorideStatus;

/// Collector for periodic status snapshots.
pub struct Collector {
    interval: Duration,
    preset: Preset,
    previous: Option<(Instant, (std::time::SystemTime, SystemStatus))>,
}

/// Delta between two system snapshots, used for rate calculations.
///
/// Computed by [`Collector::collect`] when a previous snapshot exists.
/// Contains both absolute deltas (bytes received/transmitted) and
/// per-second rates for network I/O.
///
/// # Examples
///
/// ```no_run
/// use std::time::Duration;
/// use toride_status::collector::Collector;
///
/// let mut collector = Collector::default_collector();
/// collector.collect(); // First call, no delta.
/// std::thread::sleep(Duration::from_secs(1));
/// let (_, delta) = collector.collect();
///
/// if let Some(d) = delta {
///     println!("Elapsed: {:.2?}", d.elapsed);
///     println!("RX rate: {:.1} B/s", d.network.bytes_received_rate);
///     println!("TX rate: {:.1} B/s", d.network.bytes_transmitted_rate);
///     if let Some(cpu_delta) = d.cpu_usage_delta {
///         println!("CPU delta: {cpu_delta:+.1}%");
///     }
/// }
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct SystemDelta {
    /// Time elapsed between snapshots.
    pub elapsed: Duration,
    /// Wall-clock time of the previous snapshot.
    pub from: std::time::SystemTime,
    /// Wall-clock time of the current snapshot.
    pub to: std::time::SystemTime,
    /// CPU usage change.
    pub cpu_usage_delta: Option<f64>,
    /// Per-core CPU usage deltas (percentage points).
    pub per_core_cpu_delta: Vec<f64>,
    /// Network delta.
    pub network: NetworkDelta,
    /// Disk I/O delta, if available.
    pub disk_io: Option<DiskIoDelta>,
    /// Process count delta, if available.
    pub process: Option<ProcessDelta>,
    /// Per-GPU deltas, if available.
    pub gpu: Option<Vec<GpuDelta>>,
}

/// Delta between two disk I/O snapshots.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct DiskIoDelta {
    /// Bytes read since last snapshot.
    pub read_bytes_delta: u64,
    /// Bytes written since last snapshot.
    pub written_bytes_delta: u64,
    /// Read operations since last snapshot.
    pub read_ops_delta: u64,
    /// Write operations since last snapshot.
    pub write_ops_delta: u64,
    /// Busy time change in milliseconds.
    pub busy_time_ms_delta: u64,
    /// Read bytes per second.
    pub read_bytes_rate: f64,
    /// Written bytes per second.
    pub written_bytes_rate: f64,
}

/// Delta between two process snapshots.
#[derive(Debug, Clone, Serialize)]
pub struct ProcessDelta {
    /// Change in total process count.
    pub count_delta: i64,
    /// Number of new processes (PIDs in current but not in previous).
    pub new_count: u32,
    /// Number of exited processes (PIDs in previous but not in current).
    pub exited_count: u32,
}

/// Delta for a single GPU between two snapshots.
#[derive(Debug, Clone, Serialize)]
pub struct GpuDelta {
    /// Change in GPU utilization percentage.
    pub utilization_delta: Option<f32>,
    /// Change in GPU temperature in Celsius.
    pub temperature_delta: Option<f32>,
}

/// Network delta between two snapshots.
///
/// Contains both absolute deltas (bytes, packets) and per-second rates
/// for aggregate network I/O.
#[derive(Debug, Clone, Copy, Serialize, Default)]
pub struct NetworkDelta {
    /// Bytes received since last snapshot.
    pub bytes_received_delta: u64,
    /// Bytes transmitted since last snapshot.
    pub bytes_transmitted_delta: u64,
    /// Bytes received per second.
    pub bytes_received_rate: f64,
    /// Bytes transmitted per second.
    pub bytes_transmitted_rate: f64,
    /// Packets received since last snapshot.
    pub packets_received_delta: u64,
    /// Packets transmitted since last snapshot.
    pub packets_transmitted_delta: u64,
}

impl Collector {
    /// Create a new collector with the given interval and preset.
    ///
    /// The `interval` determines the minimum time between snapshots when
    /// using [`collect_after_interval`](Self::collect_after_interval).
    /// The `preset` controls which metrics are included in each snapshot.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// use toride_status::collector::Collector;
    /// use toride_status::presets::Preset;
    ///
    /// let collector = Collector::new(Duration::from_secs(5), Preset::Minimal);
    /// assert_eq!(collector.interval(), Duration::from_secs(5));
    /// assert_eq!(collector.preset(), Preset::Minimal);
    /// ```
    #[must_use]
    pub const fn new(interval: Duration, preset: Preset) -> Self {
        Self {
            interval,
            preset,
            previous: None,
        }
    }

    /// Create a collector with default settings (1 second interval, Diagnostics preset).
    ///
    /// This is a convenience constructor equivalent to:
    /// ```ignore
    /// Collector::new(Duration::from_secs(1), Preset::Diagnostics)
    /// ```
    ///
    /// # Examples
    ///
    /// ```
    /// use toride_status::collector::Collector;
    ///
    /// let collector = Collector::default_collector();
    /// ```
    #[must_use]
    pub fn default_collector() -> Self {
        Self::new(Duration::from_secs(1), Preset::default())
    }

    /// Get the collection interval.
    #[must_use]
    pub const fn interval(&self) -> Duration {
        self.interval
    }

    /// Get the current preset.
    #[must_use]
    pub const fn preset(&self) -> Preset {
        self.preset
    }

    /// Collect a snapshot and compute delta from the previous one.
    ///
    /// On the first call, returns `None` for the delta because there is
    /// no previous snapshot to compare against. Subsequent calls return
    /// a [`SystemDelta`] containing the differences and rates.
    ///
    /// This method returns immediately without waiting for the interval.
    /// Use [`collect_after_interval`](Self::collect_after_interval) to
    /// enforce the configured interval between snapshots.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use toride_status::collector::Collector;
    ///
    /// let mut collector = Collector::default_collector();
    /// let (status, delta) = collector.collect();
    /// assert!(delta.is_none()); // First call has no delta.
    /// ```
    pub fn collect(&mut self) -> (TorideStatus, Option<SystemDelta>) {
        let status = TorideStatus::collect();
        let now = Instant::now();
        let now_sys = std::time::SystemTime::now();
        let delta = self.previous.as_ref().map(|(prev_time, (_prev_sys, prev_status))| {
            compute_delta(prev_status, &status.system, prev_time.elapsed(), now_sys)
        });
        self.previous = Some((now, (now_sys, status.system.clone())));
        (status, delta)
    }

    /// Collect a snapshot, blocking until the interval has elapsed.
    ///
    /// If enough time has already passed since the last snapshot, this
    /// method returns immediately. Otherwise, it sleeps for the remaining
    /// duration before collecting.
    ///
    /// On the first call, collects immediately and returns `None` for delta.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::time::Duration;
    /// use toride_status::collector::Collector;
    ///
    /// let mut collector = Collector::new(Duration::from_millis(100), Default::default());
    /// let (status, delta) = collector.collect_after_interval();
    /// assert!(delta.is_none()); // First call.
    /// ```
    pub fn collect_after_interval(&mut self) -> (TorideStatus, Option<SystemDelta>) {
        if let Some((prev_time, _)) = &self.previous {
            let elapsed = prev_time.elapsed();
            if let Some(remaining) = self.interval.checked_sub(elapsed) {
                std::thread::sleep(remaining);
            }
        }
        self.collect()
    }

    /// Reset the collector, clearing the previous snapshot.
    ///
    /// After reset, the next call to [`collect`](Self::collect) will
    /// return `None` for the delta, as if it were the first call.
    ///
    /// # Examples
    ///
    /// ```
    /// use toride_status::collector::Collector;
    ///
    /// let mut collector = Collector::default_collector();
    /// collector.collect();
    /// collector.reset();
    /// let (_, delta) = collector.collect();
    /// assert!(delta.is_none());
    /// ```
    pub fn reset(&mut self) {
        self.previous = None;
    }
}

/// Builder for configuring a [`Collector`].
///
/// Supports per-metric toggles and a preset. When a metric toggle is set
/// to `false`, that metric is skipped during collection regardless of the
/// preset.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use toride_status::collector::Collector;
///
/// let collector = Collector::builder()
///     .interval(Duration::from_secs(2))
///     .cpu(true)
///     .memory(true)
///     .disks(false)
///     .network(true)
///     .processes(false)
///     .gpu(false)
///     .build();
/// ```
pub struct CollectorBuilder {
    interval: Duration,
    preset: Preset,
    collect_cpu: bool,
    collect_memory: bool,
    collect_disks: bool,
    collect_network: bool,
    collect_processes: bool,
    collect_gpu: bool,
}

impl CollectorBuilder {
    /// Set the collection interval.
    pub fn interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Set the collection preset.
    pub fn preset(mut self, preset: Preset) -> Self {
        self.preset = preset;
        self
    }

    /// Enable or disable CPU metric collection.
    pub fn cpu(mut self, enabled: bool) -> Self {
        self.collect_cpu = enabled;
        self
    }

    /// Enable or disable memory metric collection.
    pub fn memory(mut self, enabled: bool) -> Self {
        self.collect_memory = enabled;
        self
    }

    /// Enable or disable disk metric collection.
    pub fn disks(mut self, enabled: bool) -> Self {
        self.collect_disks = enabled;
        self
    }

    /// Enable or disable network metric collection.
    pub fn network(mut self, enabled: bool) -> Self {
        self.collect_network = enabled;
        self
    }

    /// Enable or disable process metric collection.
    pub fn processes(mut self, enabled: bool) -> Self {
        self.collect_processes = enabled;
        self
    }

    /// Enable or disable GPU metric collection.
    pub fn gpu(mut self, enabled: bool) -> Self {
        self.collect_gpu = enabled;
        self
    }

    /// Get whether CPU collection is enabled.
    #[must_use]
    pub const fn is_cpu_enabled(&self) -> bool {
        self.collect_cpu
    }

    /// Get whether memory collection is enabled.
    #[must_use]
    pub const fn is_memory_enabled(&self) -> bool {
        self.collect_memory
    }

    /// Get whether disk collection is enabled.
    #[must_use]
    pub const fn is_disks_enabled(&self) -> bool {
        self.collect_disks
    }

    /// Get whether network collection is enabled.
    #[must_use]
    pub const fn is_network_enabled(&self) -> bool {
        self.collect_network
    }

    /// Get whether process collection is enabled.
    #[must_use]
    pub const fn is_processes_enabled(&self) -> bool {
        self.collect_processes
    }

    /// Get whether GPU collection is enabled.
    #[must_use]
    pub const fn is_gpu_enabled(&self) -> bool {
        self.collect_gpu
    }

    /// Build the [`Collector`].
    #[must_use]
    pub fn build(self) -> Collector {
        Collector::new(self.interval, self.preset)
    }
}

impl Collector {
    /// Create a builder for configuring a [`Collector`].
    #[must_use]
    pub fn builder() -> CollectorBuilder {
        CollectorBuilder {
            interval: Duration::from_secs(1),
            preset: Preset::default(),
            collect_cpu: true,
            collect_memory: true,
            collect_disks: true,
            collect_network: true,
            collect_processes: true,
            collect_gpu: true,
        }
    }
}

#[allow(clippy::cast_precision_loss)] // u64->f64 for rate calculation display; negligible precision loss
fn compute_delta(prev: &SystemStatus, curr: &SystemStatus, elapsed: Duration, to: std::time::SystemTime) -> SystemDelta {
    let elapsed_secs = elapsed.as_secs_f64();

    // Network delta
    let bytes_received_delta = curr
        .network
        .bytes_received
        .saturating_sub(prev.network.bytes_received);
    let bytes_transmitted_delta = curr
        .network
        .bytes_transmitted
        .saturating_sub(prev.network.bytes_transmitted);

    // Packet deltas: sum across all interfaces
    let prev_rx_packets: u64 = prev.network_interfaces.iter().map(|i| i.packets_received).sum();
    let curr_rx_packets: u64 = curr.network_interfaces.iter().map(|i| i.packets_received).sum();
    let prev_tx_packets: u64 = prev.network_interfaces.iter().map(|i| i.packets_transmitted).sum();
    let curr_tx_packets: u64 = curr.network_interfaces.iter().map(|i| i.packets_transmitted).sum();

    let network = NetworkDelta {
        bytes_received_delta,
        bytes_transmitted_delta,
        bytes_received_rate: if elapsed_secs > 0.0 {
            bytes_received_delta as f64 / elapsed_secs
        } else {
            0.0
        },
        bytes_transmitted_rate: if elapsed_secs > 0.0 {
            bytes_transmitted_delta as f64 / elapsed_secs
        } else {
            0.0
        },
        packets_received_delta: curr_rx_packets.saturating_sub(prev_rx_packets),
        packets_transmitted_delta: curr_tx_packets.saturating_sub(prev_tx_packets),
    };

    // Per-core CPU delta
    let per_core_cpu_delta = if prev.cpu_cores.len() == curr.cpu_cores.len() && !prev.cpu_cores.is_empty() {
        prev.cpu_cores
            .iter()
            .zip(curr.cpu_cores.iter())
            .map(|(p, c)| c.usage - p.usage)
            .collect()
    } else {
        Vec::new()
    };

    // Disk I/O delta
    let has_prev_io = prev.disk_io.read_bytes > 0 || prev.disk_io.written_bytes > 0;
    let has_curr_io = curr.disk_io.read_bytes > 0 || curr.disk_io.written_bytes > 0;
    let disk_io = if has_prev_io && has_curr_io {
        let read_bytes_delta = curr.disk_io.read_bytes.saturating_sub(prev.disk_io.read_bytes);
        let written_bytes_delta = curr.disk_io.written_bytes.saturating_sub(prev.disk_io.written_bytes);
        Some(DiskIoDelta {
            read_bytes_delta,
            written_bytes_delta,
            read_ops_delta: curr.disk_io.read_ops.saturating_sub(prev.disk_io.read_ops),
            write_ops_delta: curr.disk_io.write_ops.saturating_sub(prev.disk_io.write_ops),
            busy_time_ms_delta: curr.disk_io.busy_time_ms.saturating_sub(prev.disk_io.busy_time_ms),
            read_bytes_rate: if elapsed_secs > 0.0 { read_bytes_delta as f64 / elapsed_secs } else { 0.0 },
            written_bytes_rate: if elapsed_secs > 0.0 { written_bytes_delta as f64 / elapsed_secs } else { 0.0 },
        })
    } else {
        None
    };

    // Process delta
    let process = if prev.processes.total_count > 0 && curr.processes.total_count > 0 {
        let prev_pids: std::collections::HashSet<u32> =
            prev.processes.processes.iter().map(|p| p.pid).collect();
        let curr_pids: std::collections::HashSet<u32> =
            curr.processes.processes.iter().map(|p| p.pid).collect();
        let new_count = curr_pids.difference(&prev_pids).count() as u32;
        let exited_count = prev_pids.difference(&curr_pids).count() as u32;
        Some(ProcessDelta {
            count_delta: curr.processes.total_count as i64 - prev.processes.total_count as i64,
            new_count,
            exited_count,
        })
    } else {
        None
    };

    // GPU delta
    let gpu = if !prev.gpu.is_empty() && !curr.gpu.is_empty() {
        let len = prev.gpu.len().min(curr.gpu.len());
        Some(
            (0..len)
                .map(|i| GpuDelta {
                    utilization_delta: match (prev.gpu[i].utilization, curr.gpu[i].utilization) {
                        (Some(p), Some(c)) => Some(c - p),
                        _ => None,
                    },
                    temperature_delta: match (prev.gpu[i].temperature, curr.gpu[i].temperature) {
                        (Some(p), Some(c)) => Some(c - p),
                        _ => None,
                    },
                })
                .collect(),
        )
    } else {
        None
    };

    let from = to - elapsed;

    SystemDelta {
        elapsed,
        from,
        to,
        cpu_usage_delta: match (prev.cpu_usage, curr.cpu_usage) {
            (Some(p), Some(c)) => Some(c - p),
            _ => None,
        },
        per_core_cpu_delta,
        network,
        disk_io,
        process,
        gpu,
    }
}

impl SystemStatus {
    /// Compute delta between this snapshot and a previous one.
    ///
    /// Delegates to the internal `compute_delta` logic. The caller must
    /// provide the elapsed duration and the wall-clock timestamp of the
    /// current snapshot.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::time::Duration;
    /// use toride_status::system::SystemStatus;
    ///
    /// let prev = SystemStatus::collect();
    /// std::thread::sleep(Duration::from_secs(1));
    /// let curr = SystemStatus::collect();
    /// let delta = curr.diff(&prev, Duration::from_secs(1));
    /// println!("RX rate: {:.1} B/s", delta.network.bytes_received_rate);
    /// ```
    #[must_use]
    pub fn diff(&self, previous: &SystemStatus, elapsed: Duration) -> SystemDelta {
        let to = std::time::SystemTime::now();
        compute_delta(previous, self, elapsed, to)
    }
}

impl std::fmt::Display for SystemDelta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=== System Delta ===")?;
        writeln!(f, "  Elapsed: {:.2?}", self.elapsed)?;
        if let Some(cpu) = self.cpu_usage_delta {
            writeln!(f, "  CPU delta: {cpu:+.1}%")?;
        }
        writeln!(f, "  Network RX: {} bytes ({:.1} B/s)", self.network.bytes_received_delta, self.network.bytes_received_rate)?;
        writeln!(
            f,
            "  Network TX: {} bytes ({:.1} B/s)",
            self.network.bytes_transmitted_delta, self.network.bytes_transmitted_rate
        )?;
        if let Some(ref dio) = self.disk_io {
            writeln!(
                f,
                "  Disk IO: {} read / {} written ({:.1} / {:.1} B/s)",
                dio.read_bytes_delta, dio.written_bytes_delta, dio.read_bytes_rate, dio.written_bytes_rate
            )?;
        }
        if let Some(ref proc) = self.process {
            writeln!(
                f,
                "  Processes: {:+} ({} new, {} exited)",
                proc.count_delta, proc.new_count, proc.exited_count
            )?;
        }
        if let Some(ref gpus) = self.gpu {
            for (i, g) in gpus.iter().enumerate() {
                if let Some(util) = g.utilization_delta {
                    write!(f, "  GPU {i}: util {util:+.1}%")?;
                    if let Some(temp) = g.temperature_delta {
                        write!(f, ", temp {temp:+.1}°C")?;
                    }
                    writeln!(f)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::{
        DiskIoSnapshot, DiskStatus, HardwareInventory, MemoryStatus, NetworkStatus, OsInfo,
        ProcessSnapshot, SensorSnapshot, StaticInfo, SystemStatus, VirtualizationSnapshot,
    };

    /// Helper to construct a minimal `SystemStatus` with specific `cpu_usage` and network values.
    fn make_system_status(cpu_usage: Option<f64>, rx: u64, tx: u64) -> SystemStatus {
        SystemStatus {
            cpu_usage,
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
            network: NetworkStatus { bytes_received: rx, bytes_transmitted: tx },
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
        }
    }

    // ── compute_delta edge cases ──────────────────────────────────────

    #[test]
    fn compute_delta_zero_elapsed_produces_zero_rates() {
        let prev = make_system_status(Some(50.0), 1000, 500);
        let curr = make_system_status(Some(60.0), 2000, 1500);
        let delta = compute_delta(&prev, &curr, Duration::ZERO, std::time::SystemTime::now());

        assert_eq!(delta.elapsed, Duration::ZERO);
        assert_eq!(delta.network.bytes_received_delta, 1000);
        assert_eq!(delta.network.bytes_transmitted_delta, 1000);
        // Rates must be 0, not NaN or Inf from division by zero.
        assert!((delta.network.bytes_received_rate).abs() < f64::EPSILON);
        assert!((delta.network.bytes_transmitted_rate).abs() < f64::EPSILON);
        assert_eq!(delta.cpu_usage_delta, Some(10.0));
    }

    #[test]
    fn compute_delta_network_counter_wrap() {
        // Simulate u64 wrap: prev > curr. saturating_sub yields 0.
        let prev = make_system_status(None, u64::MAX - 10, u64::MAX - 5);
        let curr = make_system_status(None, 100, 200);
        let delta = compute_delta(&prev, &curr, Duration::from_secs(1), std::time::SystemTime::now());

        // saturating_sub prevents underflow; returns 0 when curr < prev.
        assert_eq!(delta.network.bytes_received_delta, 0);
        assert_eq!(delta.network.bytes_transmitted_delta, 0);
        assert!((delta.network.bytes_received_rate).abs() < f64::EPSILON);
        assert!((delta.network.bytes_transmitted_rate).abs() < f64::EPSILON);
    }

    #[test]
    fn compute_delta_both_cpu_none() {
        let prev = make_system_status(None, 100, 200);
        let curr = make_system_status(None, 300, 600);
        let delta = compute_delta(&prev, &curr, Duration::from_secs(2), std::time::SystemTime::now());

        assert!(delta.cpu_usage_delta.is_none());
        assert_eq!(delta.network.bytes_received_delta, 200);
        assert_eq!(delta.network.bytes_transmitted_delta, 400);
        assert!((delta.network.bytes_received_rate - 100.0).abs() < f64::EPSILON);
        assert!((delta.network.bytes_transmitted_rate - 200.0).abs() < f64::EPSILON);
    }

    #[test]
    fn compute_delta_one_cpu_none_one_some() {
        // prev is None, curr is Some -> should yield None
        let prev = make_system_status(None, 100, 200);
        let curr = make_system_status(Some(75.0), 300, 600);
        let delta = compute_delta(&prev, &curr, Duration::from_secs(1), std::time::SystemTime::now());
        assert!(delta.cpu_usage_delta.is_none());

        // prev is Some, curr is None -> should also yield None
        let prev = make_system_status(Some(75.0), 100, 200);
        let curr = make_system_status(None, 300, 600);
        let delta = compute_delta(&prev, &curr, Duration::from_secs(1), std::time::SystemTime::now());
        assert!(delta.cpu_usage_delta.is_none());
    }

    #[test]
    fn compute_delta_very_large_network_deltas() {
        let prev = make_system_status(Some(0.0), 0, 0);
        let curr = make_system_status(Some(100.0), u64::MAX, u64::MAX);
        let delta = compute_delta(&prev, &curr, Duration::from_secs(1), std::time::SystemTime::now());

        assert_eq!(delta.network.bytes_received_delta, u64::MAX);
        assert_eq!(delta.network.bytes_transmitted_delta, u64::MAX);
        // Rate = u64::MAX as f64 / 1.0 -- large but finite.
        assert!(delta.network.bytes_received_rate.is_finite());
        assert!(delta.network.bytes_transmitted_rate.is_finite());
        assert!(delta.network.bytes_received_rate > 1.0e18);
    }

    // ── Collector edge cases ──────────────────────────────────────────

    #[test]
    fn multiple_rapid_collects() {
        let mut c = Collector::default_collector();
        // First collect: no delta.
        let (_, d1) = c.collect();
        assert!(d1.is_none());

        // Rapid subsequent collects should all produce deltas (no panic, no NaN).
        for _ in 0..5 {
            let (_, delta) = c.collect();
            let d = delta.expect("subsequent collect should produce delta");
            // Elapsed may be very small but rates should be finite.
            assert!(d.network.bytes_received_rate.is_finite());
            assert!(d.network.bytes_transmitted_rate.is_finite());
        }
    }

    #[test]
    fn collect_after_long_interval() {
        let mut c = Collector::default_collector();
        c.collect();

        // Simulate a long gap by manually computing delta with a large Duration.
        // We test compute_delta directly since we can't actually sleep 24 hours.
        let prev = make_system_status(Some(10.0), 1_000_000, 500_000);
        let curr = make_system_status(Some(50.0), 1_000_000 + 86_400 * 1000, 500_000 + 86_400 * 500);
        let long_elapsed = Duration::from_hours(24);
        let delta = compute_delta(&prev, &curr, long_elapsed, std::time::SystemTime::now());

        assert_eq!(delta.elapsed, long_elapsed);
        assert_eq!(delta.cpu_usage_delta, Some(40.0));
        assert_eq!(delta.network.bytes_received_delta, 86_400_000);
        assert_eq!(delta.network.bytes_transmitted_delta, 43_200_000);
        // Rates: 86_400_000 / 86_400 = 1000.0 B/s
        assert!((delta.network.bytes_received_rate - 1000.0).abs() < 0.01);
        assert!((delta.network.bytes_transmitted_rate - 500.0).abs() < 0.01);
    }

    #[test]
    fn reset_then_collect_gives_no_delta() {
        let mut c = Collector::default_collector();
        c.collect();
        std::thread::sleep(Duration::from_millis(10));
        let (_, delta) = c.collect();
        assert!(delta.is_some(), "should have delta before reset");

        c.reset();
        let (_, delta) = c.collect();
        assert!(delta.is_none(), "after reset, first collect should yield no delta");
    }

    // ── SystemDelta Display edge cases ────────────────────────────────

    #[test]
    fn display_with_negative_cpu_delta() {
        let d = SystemDelta {
            elapsed: Duration::from_secs(2),
            from: std::time::SystemTime::now(),
            to: std::time::SystemTime::now(),
            cpu_usage_delta: Some(-15.3),
            per_core_cpu_delta: Vec::new(),
            network: NetworkDelta::default(),
            disk_io: None,
            process: None,
            gpu: None,
        };
        let output = format!("{d}");
        assert!(output.contains("Delta"), "should contain header");
        assert!(output.contains("-15.3"), "should contain negative CPU delta");
        assert!(output.contains("Network RX"), "should contain RX line");
        assert!(output.contains("Network TX"), "should contain TX line");
    }

    #[test]
    fn display_with_zero_deltas() {
        let d = SystemDelta {
            elapsed: Duration::from_millis(100),
            from: std::time::SystemTime::now(),
            to: std::time::SystemTime::now(),
            cpu_usage_delta: Some(0.0),
            per_core_cpu_delta: Vec::new(),
            network: NetworkDelta::default(),
            disk_io: None,
            process: None,
            gpu: None,
        };
        let output = format!("{d}");
        assert!(output.contains("0.0"), "should display zero values");
        assert!(output.contains("0 bytes"), "should show 0 bytes");
        assert!(output.contains("0.0 B/s"), "should show 0.0 B/s");
    }

    #[test]
    fn display_with_very_large_values() {
        let d = SystemDelta {
            elapsed: Duration::from_secs(u64::MAX / 1_000_000_000),
            from: std::time::SystemTime::now(),
            to: std::time::SystemTime::now(),
            cpu_usage_delta: Some(100.0),
            per_core_cpu_delta: Vec::new(),
            network: NetworkDelta {
                bytes_received_delta: u64::MAX,
                bytes_transmitted_delta: u64::MAX,
                bytes_received_rate: 1_000_000_000.0,
                bytes_transmitted_rate: 1_000_000_000.0,
                packets_received_delta: 0,
                packets_transmitted_delta: 0,
            },
            disk_io: None,
            process: None,
            gpu: None,
        };
        let output = format!("{d}");
        assert!(output.contains("Delta"), "should contain header");
        assert!(output.contains("+100.0"), "should contain CPU delta with sign");
        // Should not panic on large values.
        assert!(!output.is_empty());
    }

    #[test]
    fn display_with_no_cpu_delta() {
        let d = SystemDelta {
            elapsed: Duration::from_secs(1),
            from: std::time::SystemTime::now(),
            to: std::time::SystemTime::now(),
            cpu_usage_delta: None,
            per_core_cpu_delta: Vec::new(),
            network: NetworkDelta {
                bytes_received_delta: 500,
                bytes_transmitted_delta: 300,
                bytes_received_rate: 500.0,
                bytes_transmitted_rate: 300.0,
                packets_received_delta: 0,
                packets_transmitted_delta: 0,
            },
            disk_io: None,
            process: None,
            gpu: None,
        };
        let output = format!("{d}");
        // CPU line should be absent when cpu_usage_delta is None.
        assert!(!output.contains("CPU delta"), "should not show CPU line when None");
        assert!(output.contains("Network RX"), "should still show RX");
        assert!(output.contains("Network TX"), "should still show TX");
    }

    #[test]
    fn collect_after_interval_returns_delta() {
        let mut c = Collector::default_collector();
        let (_, delta1) = c.collect_after_interval();
        assert!(delta1.is_none(), "first collect_after_interval should have no delta");
        let (_, delta2) = c.collect_after_interval();
        assert!(delta2.is_some(), "second collect_after_interval should have delta");
    }

    #[test]
    fn collector_new_sets_interval() {
        let c = Collector::new(Duration::from_secs(5), Preset::Minimal);
        assert_eq!(c.interval(), Duration::from_secs(5));
        assert_eq!(c.preset(), Preset::Minimal);
    }

    #[test]
    fn default_collector_has_one_second_interval() {
        let c = Collector::default_collector();
        assert_eq!(c.interval(), Duration::from_secs(1));
    }

    #[test]
    fn first_collect_returns_no_delta() {
        let mut c = Collector::default_collector();
        let (_, delta) = c.collect();
        assert!(delta.is_none(), "first collect should have no delta");
    }

    #[test]
    fn second_collect_returns_delta() {
        let mut c = Collector::default_collector();
        c.collect();
        std::thread::sleep(Duration::from_millis(50));
        let (_, delta) = c.collect();
        assert!(delta.is_some(), "second collect should have delta");
    }

    #[test]
    fn delta_has_nonzero_elapsed() {
        let mut c = Collector::default_collector();
        c.collect();
        std::thread::sleep(Duration::from_millis(50));
        let (_, delta) = c.collect();
        let d = delta.unwrap();
        assert!(d.elapsed >= Duration::from_millis(40));
    }

    #[test]
    fn reset_clears_previous() {
        let mut c = Collector::default_collector();
        c.collect();
        c.reset();
        let (_, delta) = c.collect();
        assert!(delta.is_none());
    }

    #[test]
    fn delta_display() {
        let d = SystemDelta {
            elapsed: Duration::from_secs(1),
            from: std::time::SystemTime::now(),
            to: std::time::SystemTime::now(),
            cpu_usage_delta: Some(5.0),
            per_core_cpu_delta: Vec::new(),
            network: NetworkDelta {
                bytes_received_delta: 1024,
                bytes_transmitted_delta: 512,
                bytes_received_rate: 1024.0,
                bytes_transmitted_rate: 512.0,
                packets_received_delta: 0,
                packets_transmitted_delta: 0,
            },
            disk_io: None,
            process: None,
            gpu: None,
        };
        let output = format!("{d}");
        assert!(output.contains("Delta"));
        assert!(output.contains("Network RX"));
    }

    #[test]
    fn serialize_to_json() {
        let d = SystemDelta {
            elapsed: Duration::from_secs(1),
            from: std::time::SystemTime::now(),
            to: std::time::SystemTime::now(),
            cpu_usage_delta: None,
            per_core_cpu_delta: Vec::new(),
            network: NetworkDelta::default(),
            disk_io: None,
            process: None,
            gpu: None,
        };
        assert!(serde_json::to_string(&d).is_ok());
    }

    #[test]
    fn compute_delta_zero_elapsed_no_panic() {
        let prev = make_system_status(Some(50.0), 1000, 500);
        let curr = prev.clone();
        // Zero elapsed with identical snapshots should not cause division by zero
        let delta = compute_delta(&prev, &curr, Duration::ZERO, std::time::SystemTime::now());
        assert!((delta.network.bytes_received_rate).abs() < f64::EPSILON);
        assert!((delta.network.bytes_transmitted_rate).abs() < f64::EPSILON);
        assert_eq!(delta.network.bytes_received_delta, 0);
        assert_eq!(delta.network.bytes_transmitted_delta, 0);
        assert_eq!(delta.cpu_usage_delta, Some(0.0));
    }

    #[test]
    fn compute_delta_network_counter_wrap_identical_prev() {
        let prev = make_system_status(None, u64::MAX - 100, u64::MAX - 50);
        let mut curr = prev.clone();
        curr.network.bytes_received = 50; // Wrapped around
        curr.network.bytes_transmitted = 25;
        let delta = compute_delta(&prev, &curr, Duration::from_secs(1), std::time::SystemTime::now());
        // saturating_sub yields 0 when curr < prev (counter wrap detected)
        assert_eq!(delta.network.bytes_received_delta, 0);
        assert_eq!(delta.network.bytes_transmitted_delta, 0);
        assert!((delta.network.bytes_received_rate).abs() < f64::EPSILON);
        assert!((delta.network.bytes_transmitted_rate).abs() < f64::EPSILON);
    }

    // ── CollectorBuilder tests ────────────────────────────────────────

    #[test]
    fn collector_builder_default() {
        let collector = Collector::builder().build();
        assert_eq!(collector.interval(), Duration::from_secs(1));
        assert_eq!(collector.preset(), Preset::default());
    }

    #[test]
    fn collector_builder_custom_interval() {
        let collector = Collector::builder()
            .interval(Duration::from_secs(5))
            .build();
        assert_eq!(collector.interval(), Duration::from_secs(5));
        assert_eq!(collector.preset(), Preset::default());
    }

    #[test]
    fn collector_builder_custom_preset() {
        let collector = Collector::builder()
            .preset(Preset::Minimal)
            .build();
        assert_eq!(collector.interval(), Duration::from_secs(1));
        assert_eq!(collector.preset(), Preset::Minimal);
    }
}
