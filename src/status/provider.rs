//! Provider trait abstraction for status collection.
//!
//! Providers are the internal abstraction layer that allows swapping
//! data sources (sysinfo, /proc, commands, etc.) without changing the
//! public API. The default implementations use sysinfo.

use crate::status::error::StatusResult;
use crate::status::system::{
    BatteryInfo, CpuCore, DiskStatus, GpuInfo, LoadAverage, MemoryStatus,
    NetworkInterface, NetworkStatus, OsInfo, ProcessSnapshot, SensorStatus, SwapStatus,
};

/// Provider for CPU metrics.
pub trait CpuProvider {
    /// Get aggregate CPU usage (0.0-100.0).
    fn cpu_usage(&mut self) -> StatusResult<Option<f64>>;
    /// Get per-core CPU data.
    fn cpu_cores(&mut self) -> StatusResult<Vec<CpuCore>>;
    /// Get physical core count.
    fn physical_cores(&self) -> StatusResult<Option<usize>>;
}

/// Provider for memory metrics.
pub trait MemoryProvider {
    /// Get memory usage.
    fn memory(&mut self) -> StatusResult<MemoryStatus>;
    /// Get swap usage.
    fn swap(&mut self) -> StatusResult<Option<SwapStatus>>;
}

/// Provider for disk metrics.
pub trait DiskProvider {
    /// Get root disk usage.
    fn root_disk(&mut self) -> StatusResult<DiskStatus>;
    /// Get all disk partitions.
    fn all_disks(&mut self) -> StatusResult<Vec<DiskStatus>>;
}

/// Provider for network metrics.
pub trait NetworkProvider {
    /// Get aggregate network counters.
    fn aggregate(&mut self) -> StatusResult<NetworkStatus>;
    /// Get per-interface counters.
    fn interfaces(&mut self) -> StatusResult<Vec<NetworkInterface>>;
}

/// Provider for OS information.
pub trait OsProvider {
    /// Get OS information.
    fn os_info(&self) -> StatusResult<OsInfo>;
    /// Get hostname.
    fn hostname(&self) -> StatusResult<String>;
    /// Get uptime in seconds.
    fn uptime(&self) -> StatusResult<Option<u64>>;
    /// Get boot time.
    fn boot_time(&self) -> StatusResult<Option<u64>>;
    /// Get load average.
    fn load_average(&self) -> StatusResult<Option<LoadAverage>>;
}

/// Provider for process information.
pub trait ProcessProvider {
    /// Get process snapshot.
    fn processes(&mut self) -> StatusResult<ProcessSnapshot>;
}

/// Provider for GPU information.
pub trait GpuProvider {
    /// Get GPU information.
    fn gpus(&self) -> StatusResult<Vec<GpuInfo>>;
}

/// Provider for battery information.
pub trait BatteryProvider {
    /// Get battery status.
    fn battery(&self) -> StatusResult<Option<BatteryInfo>>;
}

/// Provider for sensor data.
pub trait SensorProvider {
    /// Get temperature sensor readings.
    fn sensors(&self) -> StatusResult<Vec<SensorStatus>>;
}

/// Composite provider that combines all individual providers.
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
        fn _assert_status<T: StatusProvider>() {}
    }
}
