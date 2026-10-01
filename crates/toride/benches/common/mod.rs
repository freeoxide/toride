use std::time::{Duration, UNIX_EPOCH};

use ratatui::{Terminal, backend::TestBackend};

use toride::status::TorideStatus;
use toride::status::capabilities::{
    BatteryCapabilities, DaemonCapabilities, GpuCapabilities, NetworkCapabilities, OsCapabilities,
    ProcessCapabilities, SensorCapabilities, SshCapabilities, StorageCapabilities,
    SystemCapabilities,
};
use toride::status::{
    Capabilities, DaemonStatus, DiskIoSnapshot, DiskStatus, HardwareInventory, LoadAverage,
    MemoryStatus, NetworkStatus, OsInfo, ProcessSnapshot, ProcessStatus, SensorSnapshot, SshStatus,
    StaticInfo, SwapStatus, SystemStatus, VirtualizationSnapshot,
};
use toride::ui::screens::AppScreen;
use toride::ui::screens::dashboard::DashboardScreen;
use toride::ui::theme::{CHARM, Palette, Theme};

pub const SIZES: [(u16, u16); 2] = [(80, 24), (200, 60)];

#[must_use]
pub fn render_palette() -> Palette {
    Palette {
        reduced_motion: true,
        ..CHARM
    }
}

#[must_use]
pub fn fixed_capabilities() -> Capabilities {
    Capabilities {
        system: SystemCapabilities {
            cpu_usage: true,
            per_core_cpu: true,
            memory: true,
            swap: true,
            disk: true,
            network: true,
            load_average: true,
            uptime: true,
            hostname: true,
            os_info: true,
            sensors: true,
            os: OsCapabilities {
                os_info: true,
                hostname: true,
                uptime: true,
                boot_time: true,
                load_average: true,
                virtualization: true,
            },
            gpu: GpuCapabilities {
                identity: true,
                nvidia_nvml: true,
                utilization: true,
                temperature: true,
                memory: true,
                per_process: true,
            },
            battery: BatteryCapabilities {
                available: true,
                charge_percent: true,
                time_remaining: true,
                cycle_count: true,
                health: true,
            },
            process: ProcessCapabilities {
                list: true,
                cpu_usage: true,
                memory_usage: true,
                command_line: true,
                thread_count: true,
                user: true,
                disk_io: true,
                tree: true,
            },
            storage: StorageCapabilities {
                disk_usage: true,
                disk_io: true,
                disk_type: true,
                model: true,
                smart: true,
                temperature: true,
            },
            network_caps: NetworkCapabilities {
                interfaces: true,
                counters: true,
                addresses: true,
                gateway: true,
                dns: true,
                link_status: true,
            },
            sensor: SensorCapabilities {
                cpu_temperature: true,
                gpu_temperature: true,
                fan_speed: true,
                voltage: true,
            },
        },
        daemon: DaemonCapabilities {
            pid_check: true,
            uptime_for_pid: true,
            stale_socket_detection: true,
        },
        ssh: SshCapabilities {
            mux_check: true,
            config_validation: true,
            agent_check: true,
            key_counting: true,
        },
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "struct-literal fixture, mirrors the in-repo snapshot fixture"
)]
#[expect(
    clippy::duration_suboptimal_units,
    reason = "fixed epoch offset in seconds, mirrors the in-repo fixture"
)]
#[must_use]
pub fn fixed_status() -> TorideStatus {
    let mk_proc = |pid: u32, name: &str, cpu: f32, mem: u64| ProcessStatus {
        pid,
        parent_pid: None,
        name: name.into(),
        cpu_usage: cpu,
        memory_bytes: mem,
        status: "Run".into(),
        start_time: None,
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
    };
    let processes = vec![
        mk_proc(101, "firefox", 87.4, 2_400_000_000),
        mk_proc(202, "cargo", 45.1, 900_000_000),
        mk_proc(303, "node", 12.0, 600_000_000),
        mk_proc(404, "sshd", 1.2, 40_000_000),
        mk_proc(505, "postgres", 7.7, 512_000_000),
        mk_proc(606, "nginx", 3.3, 120_000_000),
        mk_proc(707, "tailscaled", 0.8, 64_000_000),
        mk_proc(808, "systemd-journald", 0.4, 32_000_000),
    ];
    let root_disk = DiskStatus {
        name: "sda1".into(),
        mount_point: "/".into(),
        filesystem: "ext4".into(),
        used_bytes: 800_000_000_000,
        total_bytes: 1_000_000_000_000,
        percentage: 80.0,
        is_removable: false,
        free_bytes: 200_000_000_000,
        available_bytes: 200_000_000_000,
        disk_type: "SSD".into(),
        physical_device_path: None,
        model: None,
        serial: None,
        temperature: None,
        wear_percent: None,
    };
    let mut data_disk = root_disk.clone();
    data_disk.name = "sdb1".into();
    data_disk.mount_point = "/var".into();
    data_disk.filesystem = "xfs".into();
    data_disk.used_bytes = 3_600_000_000_000_u64;
    data_disk.total_bytes = 4_000_000_000_000_u64;
    data_disk.percentage = 90.0;
    data_disk.free_bytes = 400_000_000_000;
    data_disk.available_bytes = 400_000_000_000;
    data_disk.disk_type = "HDD".into();
    let mut boot_disk = root_disk.clone();
    boot_disk.name = "sda2".into();
    boot_disk.mount_point = "/boot".into();
    boot_disk.filesystem = "vfat".into();
    boot_disk.used_bytes = 300_000_000;
    boot_disk.total_bytes = 1_000_000_000;
    boot_disk.percentage = 30.0;
    boot_disk.free_bytes = 700_000_000;
    boot_disk.available_bytes = 700_000_000;
    let disks = vec![root_disk, data_disk, boot_disk];

    TorideStatus {
        system: SystemStatus {
            cpu_usage: Some(72.5),
            memory: MemoryStatus {
                used_bytes: 12 * 1024 * 1024 * 1024,
                total_bytes: 16 * 1024 * 1024 * 1024,
                percentage: 75.0,
                free_bytes: 4 * 1024 * 1024 * 1024,
                available_bytes: 4 * 1024 * 1024 * 1024,
                cached_bytes: 0,
                buffers_bytes: 0,
            },
            disk: disks[0].clone(),
            network: NetworkStatus {
                bytes_received: 1_000_000_000,
                bytes_transmitted: 500_000_000,
            },
            load_average: Some(LoadAverage {
                one: 1.5,
                five: 1.2,
                fifteen: 1.0,
            }),
            uptime_secs: Some(3600),
            hostname: "edge-prod-01".into(),
            os_info: OsInfo {
                name: Some("Ubuntu".into()),
                version: Some("24.04 LTS".into()),
                kernel_version: Some("6.8.0".into()),
                arch: "x86_64".into(),
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
            physical_cores: Some(4),
            swap: Some(SwapStatus {
                used_bytes: 0,
                total_bytes: 1_073_741_824,
                percentage: 0.0,
                free_bytes: 1_073_741_824,
            }),
            disks,
            network_interfaces: Vec::new(),
            sensors: Vec::new(),
            boot_time: None,
            processes: ProcessSnapshot {
                processes,
                total_count: 8,
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
                cpu_brand: "Intel Xeon E5-2680 v4".into(),
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
            alive: true,
            pid: Some(4242),
            uptime_secs: Some(7200),
            restart_count: 0,
            stale_socket: false,
        },
        ssh: SshStatus {
            mux_master_alive: true,
            control_path_valid: true,
            config_valid: true,
            agent_running: true,
            key_count: 2,
        },
        capabilities: fixed_capabilities(),
        warnings: Vec::new(),
        collected_at: UNIX_EPOCH + Duration::from_secs(1_800_000_000),
    }
}

#[must_use]
pub fn fixed_dashboard() -> DashboardScreen {
    let mut screen = DashboardScreen::new();
    screen.set_active_theme(Theme::Charm);
    let mut status = fixed_status();
    screen.set_status(status.clone());
    status.system.network.bytes_received = 1_050_000_000;
    status.system.network.bytes_transmitted = 520_000_000;
    status.collected_at += Duration::from_secs(2);
    screen.set_status(status);
    screen
}

#[allow(dead_code)]
#[must_use]
pub fn render_frame(
    screen: &mut DashboardScreen,
    width: u16,
    height: u16,
) -> ratatui::buffer::Buffer {
    let mut terminal = Terminal::new(TestBackend::new(width, height))
        .expect("TestBackend terminal construction cannot fail");
    terminal
        .draw(|f| screen.view(f, render_palette()))
        .expect("TestBackend draw cannot fail");
    terminal.backend().buffer().clone()
}
