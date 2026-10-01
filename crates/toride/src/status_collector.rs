//! Async status data collection.
//!
//! [`StatusCollector`] manages background collection of [`TorideStatus`]
//! via a tokio oneshot channel, spawning blocking work on the tokio thread pool.

use tokio::sync::oneshot;

use crate::status::TorideStatus;

/// Manages periodic async collection of system status.
pub struct StatusCollector {
    rx: Option<oneshot::Receiver<TorideStatus>>,
}

impl StatusCollector {
    /// Create a new collector with no pending collection.
    #[must_use]
    pub fn new() -> Self {
        Self { rx: None }
    }

    /// Whether a collection is currently in-flight.
    pub fn is_pending(&self) -> bool {
        self.rx.is_some()
    }

    /// Start a new background collection.
    ///
    /// If a collection is already in-flight, this is a no-op.
    pub fn start(&mut self) {
        if self.rx.is_some() {
            return;
        }
        let (tx, rx) = oneshot::channel();
        self.rx = Some(rx);
        tokio::spawn(async move {
            let status = tokio::task::spawn_blocking(TorideStatus::collect)
                .await
                .unwrap_or_else(|_| TorideStatus::collect());
            let _ = tx.send(status);
        });
    }

    #[cfg(test)]
    fn start_with(&mut self, status: TorideStatus) {
        if self.rx.is_some() {
            return;
        }
        let (tx, rx) = oneshot::channel();
        self.rx = Some(rx);
        tokio::spawn(async move {
            let _ = tx.send(status);
        });
    }

    /// Poll for a completed collection result.
    ///
    /// Returns `Some(status)` if the collection completed, `None` if still
    /// pending or if the collection failed.
    pub async fn poll(&mut self) -> Option<TorideStatus> {
        match &mut self.rx {
            Some(rx) => {
                let result = rx.await.ok();
                self.rx = None;
                result
            }
            None => None,
        }
    }
}

impl Default for StatusCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::status::{
        Capabilities, DaemonStatus, DiskIoSnapshot, DiskStatus, HardwareInventory, MemoryStatus,
        NetworkStatus, OsInfo, ProcessSnapshot, SensorSnapshot, SshStatus, StaticInfo,
        SystemStatus, VirtualizationSnapshot,
    };
    use std::time::{Duration, SystemTime};

    #[expect(
        clippy::too_many_lines,
        reason = "fixture builds a fully-populated status"
    )]
    #[expect(
        clippy::duration_suboptimal_units,
        reason = "stable std lacks larger-unit constructors"
    )]
    pub(crate) fn test_status(hostname: &str) -> TorideStatus {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        TorideStatus {
            system: SystemStatus {
                cpu_usage: Some(0.0),
                memory: MemoryStatus::default(),
                disk: DiskStatus::default(),
                network: NetworkStatus::default(),
                load_average: None,
                uptime_secs: None,
                hostname: hostname.to_string(),
                os_info: OsInfo {
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
                },
                cpu_cores: Vec::new(),
                physical_cores: None,
                swap: None,
                disks: Vec::new(),
                network_interfaces: Vec::new(),
                sensors: Vec::new(),
                boot_time: None,
                processes: ProcessSnapshot {
                    processes: Vec::new(),
                    total_count: 0,
                },
                gpu: Vec::new(),
                battery: None,
                disk_io: DiskIoSnapshot::default(),
                virtualization: VirtualizationSnapshot::default(),
                sensor_snapshot: SensorSnapshot {
                    readings: Vec::new(),
                    cpu_temperature: None,
                    gpu_temperature: None,
                },
                static_info: StaticInfo {
                    os: OsInfo {
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
                    },
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
            },
            daemon: DaemonStatus {
                alive: false,
                pid: None,
                uptime_secs: None,
                restart_count: 0,
                stale_socket: false,
            },
            ssh: SshStatus {
                mux_master_alive: false,
                control_path_valid: false,
                config_valid: false,
                agent_running: false,
                key_count: 0,
            },
            capabilities: Capabilities::detect(),
            warnings: Vec::new(),
            collected_at: now,
        }
    }

    #[test]
    fn new_is_not_pending() {
        let collector = StatusCollector::new();
        assert!(
            !collector.is_pending(),
            "new collector should not be pending"
        );
    }

    #[test]
    fn default_matches_new() {
        let new_collector = StatusCollector::new();
        let default_collector = StatusCollector::default();
        assert_eq!(new_collector.is_pending(), default_collector.is_pending());
    }

    #[tokio::test]
    async fn start_makes_pending() {
        let mut collector = StatusCollector::new();
        assert!(!collector.is_pending());
        collector.start();
        assert!(
            collector.is_pending(),
            "after start(), collector should be pending"
        );
    }

    #[tokio::test]
    async fn start_is_idempotent() {
        let mut collector = StatusCollector::new();
        collector.start();
        assert!(collector.is_pending());
        collector.start();
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn poll_returns_status_after_collection() {
        let mut collector = StatusCollector::new();
        collector.start_with(test_status("toride-test-host"));
        let result = collector.poll().await;
        assert!(
            result.is_some(),
            "poll should return Some after collection completes"
        );
        let status = result.expect("result checked Some above");
        assert_eq!(
            status.system.hostname, "toride-test-host",
            "poll must deliver the injected status unchanged"
        );
    }

    #[tokio::test]
    async fn poll_clears_pending() {
        let mut collector = StatusCollector::new();
        collector.start_with(test_status("toride-test-host"));
        let _ = collector.poll().await;
        assert!(!collector.is_pending(), "poll should clear pending state");
    }

    #[tokio::test]
    async fn poll_returns_none_when_not_started() {
        let mut collector = StatusCollector::new();
        let result = collector.poll().await;
        assert!(
            result.is_none(),
            "poll on unstarted collector should return None"
        );
    }
}
