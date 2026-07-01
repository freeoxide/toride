//! Convert [`crate::status::TorideStatus`] + environment context to About UI
//! presentation types.
//!
//! This is the ONLY module that maps the live status / env readout into the
//! About presentation structs — mirroring `toride_harden_convert.rs`'s role as
//! the single boundary between backend and presentation. Each field degrades
//! gracefully: an unreadable probe yields a placeholder
//! (`"(unknown)"` / `"(none)"`) rather than an empty string, and the functions
//! NEVER return `Err` / never skip a row (the read-only section must never
//! crash the TUI). A genuinely empty required field is logged at `warn`.
//!
//! App build metadata is sourced from compile-time `env!` macros
//! (`CARGO_PKG_*`) and `cfg!(debug_assertions)`; the convert layer is the
//! natural place to assemble it so the screen module stays layout-only.

use crate::status::TorideStatus;
use crate::ui::helpers::{format_bytes, format_duration};
use crate::ui::screens::about::{AboutApp, AboutRuntime, AboutSystem};
use crate::version;

/// Convert a [`TorideStatus`] snapshot into the live host/system identity
/// block.
///
/// Every field degrades to a placeholder when its source probe returned `None`
/// / empty (e.g. `load_average` is `None` on Windows; `cpu_brand` may be empty
/// on a minimal kernel). The function never returns `Err` and never leaves a
/// field blank — a blank row would be ambiguous in the rendered output.
pub fn convert_system(status: &TorideStatus) -> AboutSystem {
    let sys = &status.system;

    // ── hostname ─────────────────────────────────────────────────────────
    let hostname = if sys.hostname.is_empty() {
        tracing::warn!("about: status hostname is empty");
        "(unknown)".into()
    } else {
        sys.hostname.clone()
    };

    // ── os (name + version) ──────────────────────────────────────────────
    let os_name = sys.os_info.name.clone().unwrap_or_default();
    let os_version = sys.os_info.version.clone().unwrap_or_default();
    let os = if os_name.is_empty() && os_version.is_empty() {
        tracing::warn!("about: status os_info name+version both empty");
        "(unknown)".into()
    } else if os_version.is_empty() {
        os_name
    } else if os_name.is_empty() {
        os_version
    } else {
        format!("{os_name} {os_version}")
    };

    // ── kernel version ──────────────────────────────────────────────────
    let kernel = sys
        .os_info
        .kernel_version
        .clone()
        .or_else(|| sys.static_info.kernel_version.clone())
        .unwrap_or_else(|| {
            tracing::warn!("about: status kernel_version is None");
            "(unknown)".into()
        });

    // ── arch ────────────────────────────────────────────────────────────
    let arch = if sys.os_info.arch.is_empty() {
        // Fallback to the static_info arch (may itself be empty on a stripped
        // build) before declaring the probe unreadable.
        let fallback = sys.static_info.os.arch.clone();
        if fallback.is_empty() {
            tracing::warn!("about: status arch is empty");
            "(unknown)".into()
        } else {
            fallback
        }
    } else {
        sys.os_info.arch.clone()
    };

    // ── cpu brand ───────────────────────────────────────────────────────
    let cpu_brand = if sys.static_info.cpu_brand.is_empty() {
        tracing::warn!("about: status cpu_brand is empty");
        "(unknown)".into()
    } else {
        sys.static_info.cpu_brand.clone()
    };

    // ── cores (physical, falling back to logical) ───────────────────────
    // Physical count is the more meaningful figure; fall back to the logical
    // count (always known) before declaring the probe unreadable.
    let cores = if let Some(phys) = sys.physical_cores.or(sys.static_info.physical_cores) {
        phys.to_string()
    } else if sys.static_info.logical_cores > 0 {
        format!("{} (logical)", sys.static_info.logical_cores)
    } else {
        tracing::warn!("about: status core counts all zero/None");
        "(unknown)".into()
    };

    // ── memory total ────────────────────────────────────────────────────
    // Prefer the live memory.total_bytes; fall back to the static baseline
    // before formatting.
    let mem_bytes = if sys.memory.total_bytes > 0 {
        sys.memory.total_bytes
    } else if sys.static_info.memory_total_bytes > 0 {
        sys.static_info.memory_total_bytes
    } else {
        tracing::warn!("about: status memory_total_bytes is 0");
        0
    };
    let mem_total = if mem_bytes == 0 {
        "(unknown)".into()
    } else {
        format_bytes(mem_bytes)
    };

    // ── uptime ──────────────────────────────────────────────────────────
    let uptime = if let Some(secs) = sys.uptime_secs {
        format_duration(secs)
    } else {
        tracing::warn!("about: status uptime_secs is None");
        "(unknown)".into()
    };

    // ── load average ────────────────────────────────────────────────────
    let load = if let Some(la) = sys.load_average {
        format!("{:.2} {:.2} {:.2}", la.one, la.five, la.fifteen)
    } else {
        // load_average is legitimately None on some platforms (Windows);
        // debug-log rather than warn to avoid noise on those hosts.
        tracing::debug!("about: status load_average is None (platform-specific)");
        "(unknown)".into()
    };

    AboutSystem {
        hostname,
        os,
        kernel,
        arch,
        cpu_brand,
        cores,
        mem_total,
        uptime,
        load,
    }
}

/// Assemble the compile-time application build-metadata block.
///
/// Sourced from `env!("CARGO_PKG_*")` and `cfg!(debug_assertions)` so it is
/// always populated (these are compile-time constants). The homepage / authors
/// may legitimately be unset in `Cargo.toml`; those degrade to `"(none)"`
/// rather than leaving a blank row.
pub fn convert_app() -> AboutApp {
    AboutApp {
        name: version::NAME.to_string(),
        version: version::VERSION.to_string(),
        profile: if cfg!(debug_assertions) {
            "debug".into()
        } else {
            "release".into()
        },
        homepage: {
            let h = env!("CARGO_PKG_HOMEPAGE");
            if h.is_empty() {
                "(none)".into()
            } else {
                h.to_string()
            }
        },
        authors: {
            // CARGO_PKG_AUTHORS is a colon-separated list at compile time; a
            // comma-joined form reads better in the UI.
            let a = env!("CARGO_PKG_AUTHORS");
            if a.is_empty() {
                "(none)".into()
            } else {
                a.replace(':', ", ")
            }
        },
    }
}

/// Assemble the runtime environment block from `std::env` and the `dirs` crate.
///
/// Every var read degrades to `"(none)"` when unset (a missing `$TERM` is
/// normal in some embedded contexts) so no row is ever blank. Config / data
/// dirs degrade to `"(none)"` when `dirs` cannot resolve them (rare, but
/// possible on platforms without a conventions-compliant home). The log path
/// uses the SAME resolution as the Logs screen / `main.rs`: `$TORIDE_LOG_FILE`
/// else the OS cache dir.
pub fn convert_runtime() -> AboutRuntime {
    AboutRuntime {
        term: env_or_none("TERM"),
        term_program: env_or_none("TERM_PROGRAM"),
        shell: env_or_none("SHELL"),
        // USER is the conventional var; LOGNAME is the POSIX fallback.
        user: env_or("USER", "LOGNAME"),
        // LANG is the conventional var; LC_ALL takes precedence when set.
        lang: env_or("LC_ALL", "LANG"),
        home: env_or_none("HOME"),
        cwd: match std::env::var("PWD") {
            Ok(v) if !v.is_empty() => v,
            _ => std::env::current_dir()
                .map_or_else(|_| "(none)".into(), |p| p.display().to_string()),
        },
        config_dir: dirs::config_dir().map_or_else(
            || {
                tracing::warn!("about: dirs::config_dir() returned None");
                "(none)".into()
            },
            |p| p.display().to_string(),
        ),
        data_dir: dirs::data_dir().map_or_else(
            || {
                tracing::warn!("about: dirs::data_dir() returned None");
                "(none)".into()
            },
            |p| p.display().to_string(),
        ),
        log_path: log_file_path().map_or_else(
            || {
                tracing::warn!("about: could not resolve toride log path");
                "(none)".into()
            },
            |p| p.display().to_string(),
        ),
    }
}

/// Read a single env var, degrading to `"(none)"` when unset or invalid UTF-8.
fn env_or_none(key: &str) -> String {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => v,
        Ok(_) => {
            tracing::debug!("about: env {key} is set but empty");
            "(none)".into()
        }
        Err(std::env::VarError::NotPresent) => "(none)".into(),
        Err(std::env::VarError::NotUnicode(_)) => {
            tracing::warn!("about: env {key} is not valid UTF-8");
            "(none)".into()
        }
    }
}

/// Read the first present env var from a priority list, degrading to
/// `"(none)"` when none are set. Used for `USER`/`LOGNAME` and `LC_ALL`/`LANG`
/// where a POSIX fallback exists.
fn env_or(primary: &str, fallback: &str) -> String {
    if let Ok(v) = std::env::var(primary)
        && !v.is_empty()
    {
        return v;
    }
    env_or_none(fallback)
}

/// Resolve the toride log file path. Mirrors `main.rs::log_file_path` exactly:
/// `$TORIDE_LOG_FILE` overrides, else `dirs::cache_dir()/toride/toride.log`.
/// Returns `None` only if neither the env var nor a cache dir is available.
fn log_file_path() -> Option<std::path::PathBuf> {
    if let Ok(p) = std::env::var("TORIDE_LOG_FILE") {
        return Some(std::path::PathBuf::from(p));
    }
    dirs::cache_dir().map(|d| d.join("toride").join("toride.log"))
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::{
        Capabilities, DaemonStatus, DiskIoSnapshot, DiskStatus, HardwareInventory, LoadAverage,
        MemoryStatus, NetworkStatus, OsInfo, ProcessSnapshot, SensorSnapshot, SshStatus,
        StaticInfo, SystemStatus, TorideStatus, VirtualizationSnapshot,
    };
    use std::time::{Duration, SystemTime};

    /// Process-global env vars are mutated by several tests below. Acquire this
    /// lock at the top of every env-mutating test so they cannot run
    /// concurrently and race each other (cargo runs `#[test]`s in parallel
    /// threads within the binary). Mirrors the `HOME_LOCK` pattern in
    /// `ssh_data.rs`. Poisoning is tolerated: a prior panic still releases the
    /// mutex, and we take the guard regardless so the suite doesn't deadlock.
    fn env_test_lock() -> std::sync::MutexGuard<'static, ()> {
        static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Build a minimal-but-populated [`TorideStatus`] for the convert tests.
    #[expect(
        clippy::too_many_lines,
        reason = "fixture builds a fully-populated status"
    )]
    #[expect(
        clippy::duration_suboptimal_units,
        reason = "stable std lacks larger-unit constructors"
    )]
    fn sample_status() -> TorideStatus {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        TorideStatus {
            system: SystemStatus {
                cpu_usage: Some(10.0),
                memory: MemoryStatus {
                    used_bytes: 8 * 1024 * 1024 * 1024,
                    total_bytes: 16 * 1024 * 1024 * 1024,
                    percentage: 50.0,
                    free_bytes: 8 * 1024 * 1024 * 1024,
                    available_bytes: 8 * 1024 * 1024 * 1024,
                    cached_bytes: 0,
                    buffers_bytes: 0,
                },
                disk: DiskStatus {
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
                load_average: Some(LoadAverage {
                    one: 1.5,
                    five: 1.2,
                    fifteen: 1.0,
                }),
                uptime_secs: Some(3661),
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
                    cpu_brand: "Intel Xeon E5-2680 v4".into(),
                    cpu_vendor: String::new(),
                    cpu_frequency: 0,
                    physical_cores: None,
                    logical_cores: 8,
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

    // ── convert_system ──────────────────────────────────────────────────────

    #[test]
    fn convert_system_populates_hostname() {
        let s = convert_system(&sample_status());
        assert_eq!(s.hostname, "edge-prod-01");
    }

    #[test]
    fn convert_system_joins_os_name_and_version() {
        let s = convert_system(&sample_status());
        assert_eq!(s.os, "Ubuntu 24.04 LTS");
    }

    #[test]
    fn convert_system_takes_kernel_from_os_info() {
        let s = convert_system(&sample_status());
        assert_eq!(s.kernel, "6.8.0");
    }

    #[test]
    fn convert_system_prefers_physical_cores() {
        let s = convert_system(&sample_status());
        assert_eq!(s.cores, "4");
    }

    #[test]
    fn convert_system_falls_back_to_logical_cores() {
        let mut st = sample_status();
        st.system.physical_cores = None;
        st.system.static_info.physical_cores = None;
        let s = convert_system(&st);
        assert_eq!(s.cores, "8 (logical)");
    }

    #[test]
    fn convert_system_formats_memory_total() {
        let s = convert_system(&sample_status());
        assert_eq!(s.mem_total, "16.0 GiB");
    }

    #[test]
    fn convert_system_formats_uptime() {
        let s = convert_system(&sample_status());
        // 3661s = 1h 1m 1s
        assert_eq!(s.uptime, "1h 1m 1s");
    }

    #[test]
    fn convert_system_formats_load_average() {
        let s = convert_system(&sample_status());
        assert_eq!(s.load, "1.50 1.20 1.00");
    }

    #[test]
    fn convert_system_empty_hostname_yields_placeholder() {
        let mut st = sample_status();
        st.system.hostname.clear();
        let s = convert_system(&st);
        assert_eq!(s.hostname, "(unknown)");
    }

    #[test]
    fn convert_system_none_load_yields_placeholder() {
        let mut st = sample_status();
        st.system.load_average = None;
        let s = convert_system(&st);
        assert_eq!(s.load, "(unknown)");
    }

    #[test]
    fn convert_system_arch_falls_back_to_static_info() {
        // os_info.arch empty, static_info.os.arch populated → use the fallback.
        let mut st = sample_status();
        st.system.os_info.arch.clear();
        st.system.static_info.os.arch = "aarch64".into();
        let s = convert_system(&st);
        assert_eq!(s.arch, "aarch64");
    }

    #[test]
    fn convert_system_never_returns_blank_field() {
        // Strip every probe to confirm each field degrades to a placeholder
        // rather than an empty string.
        let mut st = sample_status();
        st.system.hostname.clear();
        st.system.os_info.name = None;
        st.system.os_info.version = None;
        st.system.os_info.kernel_version = None;
        st.system.static_info.kernel_version = None;
        st.system.os_info.arch.clear();
        st.system.static_info.os.arch.clear();
        st.system.static_info.cpu_brand.clear();
        st.system.physical_cores = None;
        st.system.static_info.physical_cores = None;
        st.system.static_info.logical_cores = 0;
        st.system.memory.total_bytes = 0;
        st.system.static_info.memory_total_bytes = 0;
        st.system.uptime_secs = None;
        st.system.load_average = None;

        let s = convert_system(&st);
        for (label, value) in [
            ("hostname", &s.hostname),
            ("os", &s.os),
            ("kernel", &s.kernel),
            ("arch", &s.arch),
            ("cpu_brand", &s.cpu_brand),
            ("cores", &s.cores),
            ("mem_total", &s.mem_total),
            ("uptime", &s.uptime),
            ("load", &s.load),
        ] {
            assert!(
                !value.is_empty(),
                "{label} must never be blank (placeholder expected): {value:?}"
            );
        }
    }

    // ── convert_app ─────────────────────────────────────────────────────────

    #[test]
    fn convert_app_name_matches_version_module() {
        let a = convert_app();
        assert_eq!(a.name, version::NAME);
        assert_eq!(a.version, version::VERSION);
    }

    #[test]
    fn convert_app_profile_is_debug_or_release() {
        let a = convert_app();
        assert!(a.profile == "debug" || a.profile == "release");
    }

    #[test]
    fn convert_app_homepage_and_authors_never_blank() {
        let a = convert_app();
        assert!(!a.homepage.is_empty(), "homepage must never be blank");
        assert!(!a.authors.is_empty(), "authors must never be blank");
    }

    // ── convert_runtime ─────────────────────────────────────────────────────

    #[test]
    fn convert_runtime_never_returns_blank_field() {
        let r = convert_runtime();
        for (label, value) in [
            ("term", &r.term),
            ("term_program", &r.term_program),
            ("shell", &r.shell),
            ("user", &r.user),
            ("lang", &r.lang),
            ("home", &r.home),
            ("cwd", &r.cwd),
            ("config_dir", &r.config_dir),
            ("data_dir", &r.data_dir),
            ("log_path", &r.log_path),
        ] {
            assert!(
                !value.is_empty(),
                "{label} must never be blank (placeholder expected): {value:?}"
            );
        }
    }

    #[test]
    fn convert_runtime_log_path_respects_env_override() {
        // Process-global env mutation: hold ENV_LOCK so this cannot run
        // concurrently with the other env-touching tests below.
        let _env = env_test_lock();
        unsafe {
            std::env::set_var("TORIDE_LOG_FILE", "/tmp/toride-convert-test.log");
        }
        let r = convert_runtime();
        unsafe {
            std::env::remove_var("TORIDE_LOG_FILE");
        }
        assert_eq!(r.log_path, "/tmp/toride-convert-test.log");
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    #[test]
    fn env_or_none_returns_none_for_unset_var() {
        // Use an unlikely var name so the test is deterministic.
        let v = env_or_none("TORIDE_ABOUT_CONVERT_DEFINITELY_UNSET_VAR");
        assert_eq!(v, "(none)");
    }

    #[test]
    fn env_or_prefers_primary() {
        let _env = env_test_lock();
        unsafe {
            std::env::set_var("TORIDE_ABOUT_PRIMARY", "primary-val");
            std::env::set_var("TORIDE_ABOUT_FALLBACK", "fallback-val");
        }
        let v = env_or("TORIDE_ABOUT_PRIMARY", "TORIDE_ABOUT_FALLBACK");
        unsafe {
            std::env::remove_var("TORIDE_ABOUT_PRIMARY");
            std::env::remove_var("TORIDE_ABOUT_FALLBACK");
        }
        assert_eq!(v, "primary-val");
    }

    #[test]
    fn env_or_falls_back_when_primary_unset() {
        let _env = env_test_lock();
        unsafe {
            std::env::set_var("TORIDE_ABOUT_FALLBACK2", "fallback-val");
        }
        let v = env_or("TORIDE_ABOUT_PRIMARY2", "TORIDE_ABOUT_FALLBACK2");
        unsafe {
            std::env::remove_var("TORIDE_ABOUT_FALLBACK2");
        }
        assert_eq!(v, "fallback-val");
    }

    #[test]
    fn log_file_path_prefers_env_override() {
        let _env = env_test_lock();
        unsafe {
            std::env::set_var("TORIDE_LOG_FILE", "/custom/path.log");
        }
        assert_eq!(
            log_file_path(),
            Some(std::path::PathBuf::from("/custom/path.log"))
        );
        unsafe {
            std::env::remove_var("TORIDE_LOG_FILE");
        }
    }
}
