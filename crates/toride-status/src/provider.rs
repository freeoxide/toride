//! Provider trait abstraction for status collection.
//!
//! Providers are the internal abstraction layer that allows swapping
//! data sources (sysinfo, /proc, commands, etc.) without changing the
//! public API. The default implementations use sysinfo.
//!
//! # Provider implementation guide
//!
//! To implement a custom provider, create a struct that implements the
//! individual provider traits ([`CpuProvider`], [`MemoryProvider`], etc.).
//! The [`StatusProvider`] trait is automatically implemented for any type
//! that implements all sub-providers via a blanket implementation.
//!
//! ## Trait hierarchy
//!
//! ```text
//! StatusProvider (composite)
//!   ├── CpuProvider
//!   ├── MemoryProvider
//!   ├── DiskProvider
//!   ├── NetworkProvider
//!   ├── OsProvider
//!   ├── ProcessProvider
//!   ├── GpuProvider
//!   ├── BatteryProvider
//!   ├── SensorProvider
//!   ├── VirtualizationProvider
//!   ├── DiskIoProvider
//!   └── StaticInfoProvider
//! ```
//!
//! ## Implementing a custom provider
//!
//! ```ignore
//! use toride_status::provider::*;
//! use toride_status::system::*;
//! use toride_status::error::StatusResult;
//!
//! struct MyProvider;
//!
//! impl CpuProvider for MyProvider {
//!     fn cpu_usage(&mut self) -> StatusResult<Option<f64>> {
//!         Ok(Some(42.0))
//!     }
//!     fn cpu_cores(&mut self) -> StatusResult<Vec<CpuCore>> {
//!         Ok(vec![])
//!     }
//!     fn physical_cores(&self) -> StatusResult<Option<usize>> {
//!         Ok(Some(4))
//!     }
//! }
//!
//! // ... implement remaining traits ...
//!
//! // StatusProvider is automatically implemented:
//! fn use_provider<P: StatusProvider>(provider: &mut P) {
//!     let usage = provider.cpu_usage().unwrap();
//! }
//! ```
//!
//! ## Error handling
//!
//! All provider methods return [`StatusResult<T>`](crate::error::StatusResult).
//! Implementations should return appropriate [`StatusError`](crate::error::StatusError)
//! variants when data cannot be read:
//!
//! - [`StatusError::PermissionDenied`](crate::error::StatusError::PermissionDenied)
//!   when access is denied
//! - [`StatusError::DataUnavailable`](crate::error::StatusError::DataUnavailable)
//!   when the metric is not available on this platform
//! - [`StatusError::Io`](crate::error::StatusError::Io) for filesystem errors

#![allow(clippy::missing_errors_doc)] // Internal trait methods; errors are documented via StatusResult

use std::collections::HashMap;

use crate::error::StatusResult;
use crate::system::{
    BatteryInfo, CpuCore, CpuSample, CpuStatic, DiskIoSnapshot, DiskStatus, GpuInfo, LoadAverage,
    MemoryStatus, NetworkInterface, NetworkStatus, OsInfo, ProcessSnapshot, SensorStatus,
    StaticInfo, SwapStatus, VirtualizationSnapshot,
};

/// Provider for CPU metrics.
///
/// Implement this trait to provide CPU usage data from a custom source.
pub trait CpuProvider {
    /// Get aggregate CPU usage (0.0-100.0).
    ///
    /// Returns `None` if CPU usage cannot be determined.
    fn cpu_usage(&mut self) -> StatusResult<Option<f64>>;
    /// Get per-core CPU data.
    ///
    /// Returns an empty vector if per-core data is unavailable.
    fn cpu_cores(&mut self) -> StatusResult<Vec<CpuCore>>;
    /// Get physical core count.
    ///
    /// Returns `None` if the core count cannot be determined.
    fn physical_cores(&self) -> StatusResult<Option<usize>>;
    /// Get static CPU information (vendor, brand, architecture, topology, frequencies, cache).
    fn cpu_static(&self) -> StatusResult<CpuStatic>;
    /// Get a point-in-time CPU sample with total usage and per-core data.
    fn cpu_sample(&mut self) -> StatusResult<CpuSample>;
}

/// Provider for memory metrics.
///
/// Implement this trait to provide memory and swap data from a custom source.
pub trait MemoryProvider {
    /// Get memory usage.
    fn memory(&mut self) -> StatusResult<MemoryStatus>;
    /// Get swap usage.
    ///
    /// Returns `None` if swap is not configured or unavailable.
    fn swap(&mut self) -> StatusResult<Option<SwapStatus>>;
    /// Get memory pressure as a value between 0.0 and 1.0.
    ///
    /// Returns `None` if memory pressure is not available on this platform.
    fn memory_pressure(&self) -> StatusResult<Option<f32>>;
}

/// Provider for disk metrics.
///
/// Implement this trait to provide disk usage data from a custom source.
pub trait DiskProvider {
    /// Get root disk usage.
    ///
    /// Returns the usage for the root filesystem (`/` on Unix, `C:\` on Windows).
    fn root_disk(&mut self) -> StatusResult<DiskStatus>;
    /// Get all disk partitions.
    ///
    /// Returns an empty vector if no disk information is available.
    fn all_disks(&mut self) -> StatusResult<Vec<DiskStatus>>;
}

/// Provider for network metrics.
///
/// Implement this trait to provide network I/O data from a custom source.
pub trait NetworkProvider {
    /// Get aggregate network counters.
    ///
    /// Returns the sum of bytes received and transmitted across all interfaces.
    fn aggregate(&mut self) -> StatusResult<NetworkStatus>;
    /// Get per-interface counters.
    ///
    /// Returns an empty vector if no interface data is available.
    fn interfaces(&mut self) -> StatusResult<Vec<NetworkInterface>>;
    /// Get the default gateway address.
    ///
    /// Returns `None` if no default gateway can be determined.
    fn gateway(&self) -> StatusResult<Option<String>>;
    /// Get the DNS server addresses.
    ///
    /// Returns an empty vector if no DNS servers can be determined.
    fn dns_servers(&self) -> StatusResult<Vec<String>>;
}

/// Provider for OS information.
///
/// Implement this trait to provide OS-level data from a custom source.
pub trait OsProvider {
    /// Get OS information.
    fn os_info(&self) -> StatusResult<OsInfo>;
    /// Get hostname.
    fn hostname(&self) -> StatusResult<String>;
    /// Get uptime in seconds.
    ///
    /// Returns `None` if uptime cannot be determined.
    fn uptime(&self) -> StatusResult<Option<u64>>;
    /// Get boot time as seconds since Unix epoch.
    ///
    /// Returns `None` if boot time cannot be determined.
    fn boot_time(&self) -> StatusResult<Option<u64>>;
    /// Get load average (1, 5, 15 minute windows).
    ///
    /// Returns `None` on platforms that do not support load average (e.g., Windows).
    fn load_average(&self) -> StatusResult<Option<LoadAverage>>;
    /// Get detailed OS information including extended fields.
    ///
    /// This is an expanded version of [`os_info`](Self::os_info) that may include
    /// additional platform-specific details.
    fn os_detailed(&self) -> StatusResult<OsInfo>;
}

/// Provider for process information.
///
/// Implement this trait to provide process list data from a custom source.
pub trait ProcessProvider {
    /// Get process snapshot.
    ///
    /// Returns a snapshot of all running processes with CPU and memory usage.
    fn processes(&mut self) -> StatusResult<ProcessSnapshot>;
    /// Get a process tree mapping parent PIDs to their children.
    ///
    /// Returns a map from parent PID to a vector of child PIDs.
    fn process_tree(&mut self) -> StatusResult<HashMap<u32, Vec<u32>>>;
}

/// Provider for GPU information.
///
/// Implement this trait to provide GPU data from a custom source.
pub trait GpuProvider {
    /// Get GPU information.
    ///
    /// Returns an empty vector if no GPU information is available.
    fn gpus(&self) -> StatusResult<Vec<GpuInfo>>;
}

/// Provider for battery information.
///
/// Implement this trait to provide battery data from a custom source.
pub trait BatteryProvider {
    /// Get battery status.
    ///
    /// Returns `None` if no battery is present or battery info is unavailable.
    fn battery(&self) -> StatusResult<Option<BatteryInfo>>;
}

/// Provider for sensor data.
///
/// Implement this trait to provide temperature sensor data from a custom source.
pub trait SensorProvider {
    /// Get temperature sensor readings.
    ///
    /// Returns an empty vector if no sensors are available.
    fn sensors(&self) -> StatusResult<Vec<SensorStatus>>;
}

/// Provider for virtualization environment detection.
///
/// Implement this trait to detect container and VM environments.
pub trait VirtualizationProvider {
    /// Get virtualization environment snapshot.
    fn virtualization(&self) -> StatusResult<VirtualizationSnapshot>;
}

/// Provider for disk I/O counters.
///
/// Implement this trait to provide disk I/O throughput data.
pub trait DiskIoProvider {
    /// Get disk I/O counters snapshot.
    fn disk_io(&self) -> StatusResult<DiskIoSnapshot>;
}

/// Provider for static system information.
///
/// Implement this trait to provide hardware and OS information that
/// does not change between snapshots.
pub trait StaticInfoProvider {
    /// Get static system information.
    fn static_info(&self) -> StatusResult<StaticInfo>;
}

/// Composite provider that combines all individual providers.
///
/// This trait is automatically implemented for any type that implements
/// all sub-providers ([`CpuProvider`], [`MemoryProvider`], [`DiskProvider`],
/// [`NetworkProvider`], [`OsProvider`], [`ProcessProvider`], [`GpuProvider`],
/// [`BatteryProvider`], [`SensorProvider`], [`VirtualizationProvider`],
/// [`DiskIoProvider`], and [`StaticInfoProvider`]).
///
/// Use this trait as a bound when you need access to all metrics:
///
/// ```ignore
/// fn collect_all<P: StatusProvider>(provider: &mut P) {
///     let cpu = provider.cpu_usage().unwrap();
///     let mem = provider.memory().unwrap();
///     // ...
/// }
/// ```
pub trait StatusProvider:
    CpuProvider
    + MemoryProvider
    + DiskProvider
    + NetworkProvider
    + OsProvider
    + ProcessProvider
    + GpuProvider
    + BatteryProvider
    + SensorProvider
    + VirtualizationProvider
    + DiskIoProvider
    + StaticInfoProvider
{}

// Blanket impl for any type that implements all sub-providers.
impl<T> StatusProvider for T where
    T: CpuProvider
    + MemoryProvider
    + DiskProvider
    + NetworkProvider
    + OsProvider
    + ProcessProvider
    + GpuProvider
    + BatteryProvider
    + SensorProvider
    + VirtualizationProvider
    + DiskIoProvider
    + StaticInfoProvider
{}

#[cfg(test)]
mod tests {
    use super::*;

    // Verify traits are object-safe (can be used as dyn).
    // Not all traits are object-safe due to Self: Sized methods,
    // but they should be usable as generic bounds.

    #[test]
    fn traits_exist() {
        // Compilation test: ensure the traits are defined correctly.
        fn _assert_cpu<T: CpuProvider>() {}
        fn _assert_memory<T: MemoryProvider>() {}
        fn _assert_disk<T: DiskProvider>() {}
        fn _assert_network<T: NetworkProvider>() {}
        fn _assert_os<T: OsProvider>() {}
        fn _assert_process<T: ProcessProvider>() {}
        fn _assert_gpu<T: GpuProvider>() {}
        fn _assert_battery<T: BatteryProvider>() {}
        fn _assert_sensor<T: SensorProvider>() {}
        fn _assert_virtualization<T: VirtualizationProvider>() {}
        fn _assert_disk_io<T: DiskIoProvider>() {}
        fn _assert_static_info<T: StaticInfoProvider>() {}
        fn _assert_status<T: StatusProvider>() {}
    }
}
