//! Layered VM / container detection — decides whether to neutralize cosmetic
//! animations for the current host.
//!
//! ## Why
//!
//! Over a high-latency SSH link to a VPS, the ~30fps animation redraw loop
//! (see `App::run`) forces a full `terminal.draw` + network flush every tick,
//! which is the actual source of the lag. When this module reports the host
//! looks virtualized / containerized, [`App`](crate::app::App) sets
//! `reduced_motion` and the tick is gated to fire only on real state changes,
//! cutting redraws from ~30/s to a handful.
//!
//! ## How — layered OR-combine, no single signal trusted alone
//!
//! The adversarial research (`detect_vm_*` in systemd `src/basic/virt.c`,
//! provider docs, live provider tests) established that **no single signal is
//! reliable as a sole gate**. systemd-detect-virt has high *precision* when it
//! positively fires, but a `none` result is indistinguishable from an AWS
//! Graviton VM, macOS, or Alpine. So the layers are OR-combined and a
//! **negative result is treated as "indeterminate", never "confirmed bare
//! metal"** — this matches the asymmetric cost model where a *false negative*
//! (leaving heavy animations on a laggy VPS) is the actual bug being fixed,
//! while a *false positive* (freezing animations on capable metal) is merely
//! an annoying-but-safe annoyance the user can override.
//!
//! 1. **`SYSTEMD_VIRTUALIZATION` env** — if systemd already probed, skip the fork.
//! 2. **`systemd-detect-virt --vm` / `--container`** — positive fire only;
//!    absence / `none` falls through.
//! 3. **DMI vendor strings** (`/sys/class/dmi/id/*`, all `0444` — no root) +
//!    `/sys/hypervisor/type` (Xen). AWS `.metal` bare-metal guard.
//! 4. **Container / WSL markers** — `/.dockerenv`, `/run/.containerenv`,
//!    `/run/host/container-manager`, `/proc/sys/kernel/osrelease`.
//! 5. **ARM/PPC device-tree** (`/proc/device-tree/hypervisor/compatible`) — the
//!    canonical path that catches Graviton/Ampere where DMI is absent and
//!    systemd-detect-virt silently returns `none`. The kernel does not
//!    synthesize this node on bare metal, so false-positive risk is ~nil.
//!
//! CPUID (`/proc/cpuinfo` `hypervisor` flag or `raw-cpuid`) is deliberately
//! **omitted**: it is the one signal with a large false-positive class
//! (Windows VBS / Credential Guard sets the hypervisor-present bit on bare
//! metal), toride is Linux-focused, and layers 1–5 already cover the space.
//!
//! Zero new dependencies — `std::fs`, `std::process`, `std::env` only.

use std::sync::OnceLock;

/// The outcome of a one-shot virtualization probe at startup.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VirtProbe {
    /// `true` when the host looks like a VM, container, or WSL session — i.e. a
    /// remote / headless environment where the 30fps redraw loop should be
    /// neutralized to avoid multiplying network round-trips.
    pub reduce_motion: bool,
    /// Short classifier for diagnostics / dashboard display
    /// (e.g. `"kvm"`, `"container"`, `"wsl"`, `"amazon"`). `None` when no layer
    /// fired (host appears to be bare metal).
    pub label: Option<&'static str>,
}

/// Abstraction over the three probe inputs so [`detect_with`] is fully
/// unit-testable against a fixture table without touching the real host.
///
/// Every method is best-effort and returns `None` on any failure (missing
/// path, non-zero exit, unset var) — the layered combiner treats `None` as
/// "this signal is absent", never as "bare metal confirmed".
pub trait Probe {
    /// Best-effort full contents of the file at `path`. `None` if missing /
    /// unreadable. Callers trim and lower-case as needed.
    fn read(&self, path: &str) -> Option<String>;
    /// Run `program` with `args`, returning the trimmed stdout **only** when the
    /// process exited 0. `None` if the binary is absent, exited non-zero, or
    /// failed for any IO reason.
    fn cmd(&self, program: &str, args: &[&str]) -> Option<String>;
    /// Read an environment variable, or `None` if unset / invalid UTF-8.
    fn env(&self, key: &str) -> Option<String>;
}

/// Real-host probe backed by `std::fs`, `std::process::Command`, and `std::env`.
struct RealProbe;

impl Probe for RealProbe {
    fn read(&self, path: &str) -> Option<String> {
        std::fs::read_to_string(path).ok()
    }

    fn cmd(&self, program: &str, args: &[&str]) -> Option<String> {
        std::process::Command::new(program)
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    }

    fn env(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
}

/// Detect once and cache for the process lifetime.
///
/// A process cannot migrate between VMs, and systemd itself caches detection
/// this way (a `thread_local`/once in `detect_virtualization`).
#[must_use]
pub fn detect() -> VirtProbe {
    static CACHE: OnceLock<VirtProbe> = OnceLock::new();
    *CACHE.get_or_init(|| detect_with(&RealProbe))
}

/// Run the layered probe against `probe`. Public so tests can drive it with a
/// fixture table (see `FixtureProbe` in the test module).
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn detect_with(probe: &dyn Probe) -> VirtProbe {
    // ── Layer 0: SYSTEMD_VIRTUALIZATION env (skip the fork if systemd set it)
    if let Some(raw) = probe.env("SYSTEMD_VIRTUALIZATION") {
        let v = raw.trim();
        if let Some(rest) = v
            .strip_prefix("vm:")
            .map(str::trim)
            .filter(|s| !s.is_empty() && *s != "none")
        {
            return VirtProbe {
                reduce_motion: true,
                label: Some(vm_label(rest)),
            };
        }
        let container = v
            .strip_prefix("container:")
            .map(str::trim)
            .is_some_and(|s| !s.is_empty() && s != "none");
        if container {
            return VirtProbe {
                reduce_motion: true,
                label: Some("container"),
            };
        }
    }

    // ── Layer 1: systemd-detect-virt binary.
    // A POSITIVE fire is reliable; absence / "none" is NOT bare metal → fall through.
    if let Some(id) = probe
        .cmd("systemd-detect-virt", &["--vm"])
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s != "none")
    {
        return VirtProbe {
            reduce_motion: true,
            label: Some(vm_label(&id)),
        };
    }
    if let Some(id) = probe
        .cmd("systemd-detect-virt", &["--container"])
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s != "none")
    {
        let _ = id;
        // A container shares the host kernel but implies a constrained / headless
        // session — reduce motion for the same latency reason.
        return VirtProbe {
            reduce_motion: true,
            label: Some("container"),
        };
    }

    // ── Layer 2: DMI vendor strings (world-readable 0444, no root) + Xen.
    // First the AWS .metal bare-metal guard: i3.metal / c5.metal share EC2
    // vendor strings, and product_name's ".metal" suffix is the unprivileged
    // disambiguator.
    let is_aws_metal = probe
        .read("/sys/class/dmi/id/product_name")
        .is_some_and(|s| s.trim().to_ascii_lowercase().contains(".metal"));
    if !is_aws_metal {
        for key in &[
            "product_name",
            "sys_vendor",
            "bios_vendor",
            "board_vendor",
            "product_version",
        ] {
            let Some(raw) = probe.read(&format!("/sys/class/dmi/id/{key}")) else {
                continue;
            };
            let v = raw.trim().to_ascii_lowercase();
            if v.is_empty() {
                continue;
            }
            if let Some(&sig) = VENDOR_SIGS.iter().find(|&&sig| v.contains(sig)) {
                // The DMI layer returns the matched vendor sig as-is (e.g.
                // "qemu"); the systemd-binary layer normalizes via vm_label
                // (e.g. "kvm"). This intentional difference is exercised by
                // the systemd_detect_virt_none_falls_through_to_dmi test.
                return VirtProbe {
                    reduce_motion: true,
                    label: Some(sig),
                };
            }
        }
        if let Some(raw) = probe.read("/sys/hypervisor/type")
            && raw.trim().eq_ignore_ascii_case("xen")
        {
            return VirtProbe {
                reduce_motion: true,
                label: Some("xen"),
            };
        }
    }

    // ── Layer 3: container + WSL markers.
    // Containers share the host kernel so DMI/CPUID reflect the host; detect
    // them via their own file markers. A local dev container on a fast
    // workstation is a (safe-annoying) false positive the user can override.
    if probe.read("/run/.containerenv").is_some()
        || probe.read("/.dockerenv").is_some()
        || probe.read("/run/host/container-manager").is_some()
    {
        return VirtProbe {
            reduce_motion: true,
            label: Some("container"),
        };
    }
    if let Some(raw) = probe.read("/proc/sys/kernel/osrelease") {
        let r = raw.to_ascii_lowercase();
        if r.contains("microsoft") || r.contains("wsl") {
            return VirtProbe {
                reduce_motion: true,
                label: Some("wsl"),
            };
        }
    }

    // ── Layer 4: ARM/PPC/RISC-V device-tree. The kernel does NOT synthesize
    // /proc/device-tree/hypervisor on bare metal — the hypervisor injects it —
    // so this is near-zero false-positive and is the canonical path that
    // catches AWS Graviton / Ampere (DMI absent, systemd returns "none").
    if let Some(raw) = probe.read("/proc/device-tree/hypervisor/compatible") {
        let v = raw.to_ascii_lowercase();
        if v.contains("kvm")
            || v.contains("xen")
            || v.contains("vmware")
            || v.contains("dummy-virt")
        {
            return VirtProbe {
                reduce_motion: true,
                label: Some("kvm"),
            };
        }
    }

    VirtProbe {
        reduce_motion: false,
        label: None,
    }
}

/// Map a systemd VM id to a short diagnostic label. Unknown ids collapse to
/// `"vm"` (still a positive virtualization signal).
fn vm_label(id: &str) -> &'static str {
    match id {
        "kvm" | "qemu" | "uml" => "kvm",
        "xen" => "xen",
        "microsoft" => "hyperv",
        "vmware" => "vmware",
        "oracle" | "virtualbox" => "virtualbox",
        "amazon" => "amazon",
        "google" => "google",
        "parallels" => "parallels",
        "apple" => "apple",
        _ => "vm",
    }
}

/// Lowercase substrings matched against DMI vendor strings. Each is a
/// `&'static str` so it doubles as the probe label. Curated from systemd's
/// `detect_vm_dmi_vendor` table and documented cloud-provider SMBIOS values.
const VENDOR_SIGS: &[&str] = &[
    "qemu",
    "kvm",
    "xen",
    "vmware",
    "vmware virtual platform",
    "virtualbox",
    "innotek",
    "oracle",
    "microsoft corporation",
    "hyper-v",
    "virtual machine",
    "bochs",
    "parallels",
    "bhyve",
    "amazon",
    "google compute engine",
    "google",
    "digitalocean",
    "droplet",
    "vultr",
    "hetzner",
    "upcloud",
    "scaleway",
    "linode",
    "akamai",
    "openstack",
    "kubevirt",
    "3ds outscale",
    "seabios",
    "linux,dummy-virt",
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// In-memory `Probe` backed by fixture tables. Absent paths / commands /
    /// env keys yield `None` exactly like the real probe on a missing file.
    struct FixtureProbe {
        files: HashMap<&'static str, &'static str>,
        cmds: HashMap<String, &'static str>,
        envs: HashMap<&'static str, &'static str>,
    }

    impl FixtureProbe {
        fn new() -> Self {
            Self {
                files: HashMap::new(),
                cmds: HashMap::new(),
                envs: HashMap::new(),
            }
        }
    }

    impl Probe for FixtureProbe {
        fn read(&self, path: &str) -> Option<String> {
            self.files.get(path).map(|s| (*s).to_string())
        }

        fn cmd(&self, program: &str, args: &[&str]) -> Option<String> {
            let mut key = program.to_string();
            for a in args {
                key.push(' ');
                key.push_str(a);
            }
            self.cmds.get(&key).map(|s| s.trim().to_string())
        }

        fn env(&self, key: &str) -> Option<String> {
            self.envs.get(key).map(|s| (*s).to_string())
        }
    }

    #[test]
    fn bare_metal_yields_no_reduce_motion() {
        // No env, no commands, no files → every layer is absent → indeterminate.
        let p = FixtureProbe::new();
        let r = detect_with(&p);
        assert!(!r.reduce_motion);
        assert!(r.label.is_none());
    }

    #[test]
    fn systemd_detect_virt_kvm_fires() {
        // The user's actual case: a real KVM VPS reports kvm via the binary.
        let mut p = FixtureProbe::new();
        p.cmds.insert("systemd-detect-virt --vm".to_string(), "kvm");
        let r = detect_with(&p);
        assert!(r.reduce_motion);
        assert_eq!(r.label, Some("kvm"));
    }

    #[test]
    fn systemd_detect_virt_none_falls_through_to_dmi() {
        // systemd returning "none" must NOT be treated as bare metal (Graviton
        // silent-fail). Here DMI then catches it.
        let mut p = FixtureProbe::new();
        p.cmds
            .insert("systemd-detect-virt --vm".to_string(), "none");
        p.files.insert("/sys/class/dmi/id/sys_vendor", "QEMU");
        let r = detect_with(&p);
        assert!(r.reduce_motion);
        assert_eq!(r.label, Some("qemu"));
    }

    #[test]
    fn systemd_detect_virt_absent_falls_through() {
        // Binary not on PATH (Alpine/musl) → cmd returns None → fall through.
        let mut p = FixtureProbe::new();
        p.files
            .insert("/sys/class/dmi/id/product_name", "VirtualBox");
        let r = detect_with(&p);
        assert!(r.reduce_motion);
    }

    #[test]
    fn systemd_env_vm_signal_skips_fork() {
        let mut p = FixtureProbe::new();
        p.envs.insert("SYSTEMD_VIRTUALIZATION", "vm:xen");
        let r = detect_with(&p);
        assert!(r.reduce_motion);
        assert_eq!(r.label, Some("xen"));
    }

    #[test]
    fn systemd_env_container_signal_fires() {
        let mut p = FixtureProbe::new();
        p.envs.insert("SYSTEMD_VIRTUALIZATION", "container:lxc");
        let r = detect_with(&p);
        assert!(r.reduce_motion);
        assert_eq!(r.label, Some("container"));
    }

    #[test]
    fn dmi_google_compute_engine() {
        let mut p = FixtureProbe::new();
        p.files
            .insert("/sys/class/dmi/id/product_name", "Google Compute Engine");
        let r = detect_with(&p);
        assert!(r.reduce_motion);
    }

    #[test]
    fn dmi_amazon_ec2_virtualized() {
        let mut p = FixtureProbe::new();
        p.files.insert("/sys/class/dmi/id/sys_vendor", "Amazon EC2");
        p.files
            .insert("/sys/class/dmi/id/product_name", "t3.medium");
        let r = detect_with(&p);
        assert!(r.reduce_motion);
        assert_eq!(r.label, Some("amazon"));
    }

    #[test]
    fn aws_metal_bare_metal_not_flagged() {
        // i3.metal shares EC2 vendor strings — the ".metal" guard must keep it
        // as bare metal so a powerful metal instance isn't wrongly frozen.
        let mut p = FixtureProbe::new();
        p.files.insert("/sys/class/dmi/id/sys_vendor", "Amazon EC2");
        p.files.insert("/sys/class/dmi/id/product_name", "i3.metal");
        let r = detect_with(&p);
        assert!(!r.reduce_motion, "AWS .metal should be bare metal: {r:?}");
    }

    #[test]
    fn sys_hypervisor_type_xen_fires() {
        let mut p = FixtureProbe::new();
        p.files.insert("/sys/hypervisor/type", "xen");
        let r = detect_with(&p);
        assert!(r.reduce_motion);
        assert_eq!(r.label, Some("xen"));
    }

    #[test]
    fn dockerenv_fires_container() {
        let mut p = FixtureProbe::new();
        p.files.insert("/.dockerenv", "");
        let r = detect_with(&p);
        assert!(r.reduce_motion);
        assert_eq!(r.label, Some("container"));
    }

    #[test]
    fn podman_containerenv_fires() {
        let mut p = FixtureProbe::new();
        p.files.insert("/run/.containerenv", "");
        let r = detect_with(&p);
        assert!(r.reduce_motion);
    }

    #[test]
    fn wsl_osrelease_fires() {
        let mut p = FixtureProbe::new();
        p.files.insert(
            "/proc/sys/kernel/osrelease",
            "5.15.153.1-microsoft-standard-WSL2",
        );
        let r = detect_with(&p);
        assert!(r.reduce_motion);
        assert_eq!(r.label, Some("wsl"));
    }

    #[test]
    fn arm_device_tree_kvm_fires() {
        // AWS Graviton: no DMI, systemd silent — device-tree is the catcher.
        let mut p = FixtureProbe::new();
        p.files.insert(
            "/proc/device-tree/hypervisor/compatible",
            "linux,kvm-virt,arm",
        );
        let r = detect_with(&p);
        assert!(r.reduce_motion);
        assert_eq!(r.label, Some("kvm"));
    }

    #[test]
    fn arm_device_tree_xen_fires() {
        let mut p = FixtureProbe::new();
        p.files
            .insert("/proc/device-tree/hypervisor/compatible", "xen");
        let r = detect_with(&p);
        assert!(r.reduce_motion);
    }

    #[test]
    fn non_rgb_unrelated_dmi_does_not_false_positive() {
        // A bare-metal board with innocuous vendor strings must not match.
        let mut p = FixtureProbe::new();
        p.files
            .insert("/sys/class/dmi/id/sys_vendor", "ASUSTeK Computer Inc.");
        p.files
            .insert("/sys/class/dmi/id/product_name", "ROG STRIX X670E");
        let r = detect_with(&p);
        assert!(!r.reduce_motion, "consumer bare metal: {r:?}");
    }

    #[test]
    fn layer_precedence_env_wins_over_dmi() {
        // Layer 0 short-circuits; the DMI signal below is never consulted.
        let mut p = FixtureProbe::new();
        p.envs.insert("SYSTEMD_VIRTUALIZATION", "vm:qemu");
        p.files.insert("/sys/class/dmi/id/sys_vendor", "QEMU");
        let r = detect_with(&p);
        assert!(r.reduce_motion);
        assert_eq!(r.label, Some("kvm"));
    }
}
