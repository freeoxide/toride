pub mod about;
pub mod base;
pub mod dashboard;
pub mod fail2ban;
/// Shared severity styling + findings-grouping helpers.
pub mod findings;
/// Help modal overlay content renderer.
pub mod help;
pub mod logs;
pub mod quit;
pub mod section_overview;
pub mod settings;
pub mod ssh;
pub mod templates;
pub mod tools;
pub mod toride_audit;
pub mod toride_backup;
pub mod toride_cloud;
pub mod toride_harden;
pub mod toride_mise;
pub mod toride_monitor;
pub mod toride_proxy;
pub mod toride_tailscale;
pub mod toride_updates;
pub mod toride_users;
pub mod toride_wireguard;
pub mod ufw_kit;
/// Welcome splash screen.
pub mod welcome;

pub use crate::ssh_data::{SecurityCheck, SecurityGrade, SshSecurityData};
pub use base::ScreenBase;
pub use dashboard::DashboardScreen;
pub use help::HelpScreen;
pub use quit::QuitModal;
pub use ssh::{
    AgentKeyEntry, AgentStatus, AuthorizedKeyEntry, CertificateEntry, ConfigHostEntry,
    DiagnosticEntry, ForwardEntry, ForwardSessionEntry, KnownHostEntry, SshContent, SshKeyEntry,
};
pub use welcome::WelcomeScreen;

use crossterm::event::{KeyCode, MouseEvent};
use ratatui::Frame;

use crate::action::Action;
use crate::ui::theme::Palette;

/// Shared interface for all TUI screens.
///
/// Each screen implements this trait so that [`App`](crate::app::App) can
/// dispatch input events, rendering, and lifecycle calls through a single
/// consistent API instead of scattered `match` blocks.
///
/// The name `AppScreen` avoids collision with [`crate::navigation::Screen`]
/// (the routing enum).
pub trait AppScreen {
    /// Handle a key press, returning an [`Action`] if the screen requests
    /// navigation or a global behaviour.
    fn handle_key(&mut self, code: KeyCode) -> Option<Action>;

    /// Handle a mouse event. Default: ignore.
    fn handle_mouse(&mut self, _mouse: MouseEvent) -> Option<Action> {
        None
    }

    /// Handle an action that was *not* consumed by [`App::update`](crate::app::App::update).
    /// Screens use this to route internally-handled actions like [`Action::ScrollDown`]
    /// / [`Action::ScrollUp`]. Default: no-op.
    fn handle_action(&mut self, _action: Action) {}

    /// Render the full screen (background gradient + content).
    fn view(&mut self, frame: &mut Frame, palette: Palette);

    /// Render only the foreground layer (content over an existing background).
    /// Used during animated transitions.
    fn view_foreground(&mut self, frame: &mut Frame, palette: Palette);

    /// Invalidate cached rendering data (e.g. gradient background).
    fn invalidate_cache(&mut self);

    /// Whether this screen has a modal open (form, confirm, detail, etc.).
    /// Used by the global input handler to suppress shortcuts like `q` and `?`
    /// while the user is interacting with a modal.
    fn has_modal(&self) -> bool {
        false
    }

    /// Whether this screen currently needs animation ticks.
    /// Return `true` when the screen has an active animation (shimmer,
    /// spinner, etc.). Default: `false`.
    fn needs_animation(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use crate::ui::screens::AppScreen;
    use crate::ui::theme::CHARM;

    /// Helper: create a test terminal with the given viewport size.
    fn test_terminal(w: u16, h: u16) -> Terminal<TestBackend> {
        let backend = TestBackend::new(w, h);
        Terminal::new(backend).unwrap()
    }

    /// Render a screen into a test terminal and return the buffer as a string.
    fn render_to_string<S: AppScreen>(screen: &mut S, w: u16, h: u16) -> String {
        let mut terminal = test_terminal(w, h);
        terminal.draw(|f| screen.view(f, CHARM)).unwrap();
        terminal.backend().to_string()
    }

    // ── WelcomeScreen snapshot ──────────────────────────────────────────────

    #[test]
    fn welcome_screen_snapshot() {
        let mut screen = super::welcome::WelcomeScreen::new();
        let output = render_to_string(&mut screen, 80, 24);
        insta::assert_snapshot!("welcome_screen_80x24", output);
    }

    #[test]
    fn welcome_screen_too_small() {
        let mut screen = super::welcome::WelcomeScreen::new();
        let output = render_to_string(&mut screen, 20, 8);
        // Should show "Terminal too small" message
        assert!(
            output.contains("too small"),
            "expected 'too small' message, got: {output}"
        );
    }

    #[test]
    fn welcome_screen_minimal_viewport() {
        let mut screen = super::welcome::WelcomeScreen::new();
        let output = render_to_string(&mut screen, 30, 10);
        insta::assert_snapshot!("welcome_screen_30x10", output);
    }

    // ── HelpScreen modal snapshot ────────────────────────────────────────────

    #[test]
    fn help_screen_snapshot() {
        use crate::ui::responsive::Viewport;
        use crate::ui::widgets::Modal;

        let mut terminal = test_terminal(80, 24);
        terminal
            .draw(|f| {
                let viewport = Viewport::from_area(f.area());
                Modal::new("Help").render(f, CHARM, |f, content| {
                    super::help::HelpScreen::render(f, content, CHARM, viewport);
                });
            })
            .unwrap();
        let output = terminal.backend().to_string();
        insta::assert_snapshot!("help_screen_80x24", output);
    }

    #[test]
    fn help_screen_minimal_viewport() {
        use crate::ui::responsive::Viewport;
        use crate::ui::widgets::Modal;

        let mut terminal = test_terminal(35, 12);
        terminal
            .draw(|f| {
                let viewport = Viewport::from_area(f.area());
                Modal::new("Help").render(f, CHARM, |f, content| {
                    super::help::HelpScreen::render(f, content, CHARM, viewport);
                });
            })
            .unwrap();
        let output = terminal.backend().to_string();
        insta::assert_snapshot!("help_screen_35x12", output);
    }

    // ── DashboardScreen snapshots ───────────────────────────────────────────

    #[test]
    fn dashboard_screen_full_snapshot() {
        let mut screen = super::dashboard::DashboardScreen::new();
        let output = render_to_string(&mut screen, 160, 44);
        insta::assert_snapshot!("dashboard_screen_160x44", output);
    }

    #[test]
    fn dashboard_screen_compact_snapshot() {
        let mut screen = super::dashboard::DashboardScreen::new();
        let output = render_to_string(&mut screen, 90, 30);
        insta::assert_snapshot!("dashboard_screen_90x30", output);
    }

    #[test]
    fn dashboard_screen_has_chrome_and_content() {
        let mut screen = super::dashboard::DashboardScreen::new();
        let output = render_to_string(&mut screen, 160, 44);
        // Real chrome: header logo, sidebar, and the three panel titles. The
        // dashboard no longer carries fabricated module cards ("ssh hardening")
        // or a "RECENTLY INSTALLED" panel at cold start — those were mock data.
        assert!(output.contains("toride"), "header logo: {output}");
        assert!(output.contains("MODULES"), "modules panel title/label");
        assert!(
            output.contains("STORAGE & NETWORK"),
            "updates->storage panel"
        );
        assert!(
            output.contains("TOP PROCESSES"),
            "activity->top processes panel"
        );
        // Honest cold-start sentinel (replaces the fabricated "ssh hardening" card).
        assert!(
            output.contains("collecting system status"),
            "cold-start sentinel module: {output}"
        );
    }

    #[test]
    fn dashboard_screen_too_small() {
        let mut screen = super::dashboard::DashboardScreen::new();
        let output = render_to_string(&mut screen, 20, 8);
        assert!(
            output.contains("too small"),
            "expected 'too small' message, got: {output}"
        );
    }

    #[test]
    #[expect(
        clippy::duration_suboptimal_units,
        reason = "stable std lacks larger-unit constructors"
    )]
    #[expect(clippy::too_many_lines, reason = "test fixture")]
    fn dashboard_screen_live_snapshot() {
        use crate::status::{
            DaemonStatus, DiskIoSnapshot, DiskStatus, HardwareInventory, LoadAverage, MemoryStatus,
            NetworkStatus, OsInfo, ProcessSnapshot, ProcessStatus, SensorSnapshot, SshStatus,
            StaticInfo, SwapStatus, SystemStatus, TorideStatus, VirtualizationSnapshot,
        };
        use std::time::{Duration, SystemTime};

        // Minimal live status: one disk with high usage, a couple of processes,
        // memory/load populated. Mirrors the construction pattern at
        // toride-status/src/doctor.rs (snapshot_toride_status_display test).
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
        ];
        let disks = vec![DiskStatus {
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
        }];

        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let mut status = TorideStatus {
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
                    total_count: 4,
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
            capabilities: crate::status::Capabilities::detect(),
            warnings: Vec::new(),
            collected_at: now,
        };

        let mut screen = super::dashboard::DashboardScreen::new();
        // Set twice so net throughput rates are computed from the delta.
        screen.set_status(status.clone());
        status.system.network.bytes_received = 1_050_000_000;
        status.system.network.bytes_transmitted = 520_000_000;
        status.collected_at = now + Duration::from_secs(2);
        screen.set_status(status);

        // Mark a few sections available so the managed grid shows live badges.
        screen.fail2ban_set_available_for_test(true);
        screen.toride_updates_set_available_for_test(true, 7, 2);
        screen.ufw_kit_set_available_for_test(true);

        let output = render_to_string(&mut screen, 160, 44);
        // Sanity assertions on the live path before snapshotting.
        assert!(output.contains("MANAGED"), "live stat card label: {output}");
        assert!(output.contains("FINDINGS"), "findings stat card: {output}");
        assert!(
            output.contains("MANAGED SERVICES"),
            "live panel title: {output}"
        );
        assert!(
            output.contains("STORAGE & NETWORK"),
            "storage panel title: {output}"
        );
        assert!(
            output.contains("TOP PROCESSES"),
            "processes panel title: {output}"
        );
        assert!(output.contains("firefox"), "top process row: {output}");
        assert!(output.contains("edge-prod-01"), "live hostname: {output}");
        // Compact daemon/ssh health glyphs appear on the uptime line.
        assert!(
            output.contains('d') && output.contains("✓"),
            "health glyphs: {output}"
        );
        insta::assert_snapshot!("dashboard_screen_live", output);
    }

    #[test]
    #[expect(
        clippy::duration_suboptimal_units,
        reason = "stable std lacks larger-unit constructors"
    )]
    #[expect(clippy::too_many_lines, reason = "test fixture")]
    fn dashboard_screen_live_empty_disks_and_processes_does_not_panic() {
        // Adversarial edge case: live status with no disks, no processes, no
        // network rates (macOS degradation / preset-gated empty fields). The
        // live panels must render their "no data" placeholders without panicking.
        use crate::status::{
            DaemonStatus, DiskIoSnapshot, HardwareInventory, MemoryStatus, NetworkStatus, OsInfo,
            ProcessSnapshot, SensorSnapshot, SshStatus, StaticInfo, SystemStatus, TorideStatus,
            VirtualizationSnapshot,
        };
        use std::time::{Duration, SystemTime};

        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let status = TorideStatus {
            system: SystemStatus {
                cpu_usage: Some(10.0),
                memory: MemoryStatus {
                    used_bytes: 1024,
                    total_bytes: 2048,
                    percentage: 50.0,
                    free_bytes: 1024,
                    available_bytes: 1024,
                    cached_bytes: 0,
                    buffers_bytes: 0,
                },
                disk: crate::status::DiskStatus {
                    name: String::new(),
                    mount_point: String::new(),
                    filesystem: String::new(),
                    used_bytes: 0,
                    total_bytes: 0,
                    percentage: 0.0,
                    is_removable: false,
                    free_bytes: 0,
                    available_bytes: 0,
                    disk_type: "Unknown".into(),
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
                hostname: "empty-host".into(),
                os_info: OsInfo {
                    name: None,
                    version: None,
                    kernel_version: None,
                    arch: "aarch64".into(),
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
            capabilities: crate::status::Capabilities::detect(),
            warnings: Vec::new(),
            collected_at: now,
        };

        let mut screen = super::dashboard::DashboardScreen::new();
        screen.set_status(status);
        // Must not panic: empty disks → placeholder, empty processes → placeholder.
        let output = render_to_string(&mut screen, 160, 44);
        assert!(
            output.contains("no storage/network data"),
            "storage placeholder: {output}"
        );
        assert!(
            output.contains("no process data"),
            "process placeholder: {output}"
        );
    }
}
