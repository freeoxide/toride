//! Dashboard domain models and honest empty seed data.
//!
//! These are lightweight presentation models that drive the dashboard screen.
//! [`DashboardData::empty`] seeds an honest cold-start skeleton (no fabricated
//! host info, modules, updates, activity, or sidebar badges); live
//! [`TorideStatus`](crate::status::TorideStatus) data is layered on top by the
//! screen where available (header gauges, system info card) via the
//! `DashboardScreen::set_*` setters as collectors report.

use crate::ui::theme::Palette;
use ratatui::style::Color;

// ── Module ───────────────────────────────────────────────────────────────────

/// Installation / runtime state of a managed [`Module`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModuleStatus {
    /// Installed but not necessarily running.
    Installed,
    /// Installed and actively running.
    Active,
    /// Configured and ready to use.
    Ready,
    /// Available but reporting elevated findings (warnings/errors).
    Degraded,
    /// Backend unavailable / not reachable — the section cannot be inspected.
    Offline,
}

impl ModuleStatus {
    /// Short human label (e.g. `installed`).
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            ModuleStatus::Installed => "installed",
            ModuleStatus::Active => "active",
            ModuleStatus::Ready => "ready",
            ModuleStatus::Degraded => "degraded",
            ModuleStatus::Offline => "offline",
        }
    }

    /// Status glyph shown before the label.
    #[must_use]
    pub fn glyph(self) -> &'static str {
        match self {
            ModuleStatus::Installed | ModuleStatus::Active | ModuleStatus::Ready => "✓",
            ModuleStatus::Degraded => "!",
            ModuleStatus::Offline => "✗",
        }
    }

    /// Palette colour for the status text.
    #[must_use]
    pub fn color(self, p: Palette) -> Color {
        match self {
            ModuleStatus::Installed => p.ok,
            ModuleStatus::Active => p.accent3,
            ModuleStatus::Ready => p.info,
            ModuleStatus::Degraded => p.warn,
            ModuleStatus::Offline => p.err,
        }
    }
}

/// A managed module shown as a card in the dashboard grid.
#[derive(Clone, Debug)]
pub struct Module {
    /// Decorative glyph rendered before the name.
    pub icon: &'static str,
    /// Display name (e.g. `ssh hardening`).
    pub name: String,
    /// Installation / runtime status.
    pub status: ModuleStatus,
    /// One-line summary line.
    pub summary: String,
    /// Secondary detail line (e.g. `· port 2202 · 2 keys`).
    pub detail: String,
}

// ── Sidebar ──────────────────────────────────────────────────────────────────

/// A navigable section selected from the sidebar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Section {
    /// The main dashboard (the only fully-implemented section for now).
    Dashboard,
    /// Tools catalogue.
    Tools,
    /// Templates.
    Templates,
    /// SSH management.
    Ssh,
    /// Firewall management.
    Firewall,
    /// fail2ban management.
    Fail2ban,
    /// Tailscale mesh VPN management (read-only).
    Tailscale,
    /// Kernel-hardening management (sysctl profiles, shm mounts, doctor).
    Harden,
    /// `WireGuard` VPN tunnel management (read-only).
    WireGuard,
    /// Automatic security updates management (read-only).
    Updates,
    /// User & access-control management (read-only).
    Users,
    /// Audit daemon / AIDE integrity / log aggregation (read-only).
    Audit,
    /// Outbound traffic monitoring & anomaly detection (read-only).
    Monitor,
    /// Backup scheduling & repository management via restic/borg (read-only).
    Backup,
    /// Reverse proxy, TLS certs & WAF management (read-only).
    Proxy,
    /// Cloud provider security groups / firewalls / agent (read-only).
    Cloud,
    /// Mise runtime version manager (installed tools, outdated, config, doctor).
    Mise,
    /// Logs viewer.
    Logs,
    /// About screen.
    About,
    /// Settings.
    Settings,
}

impl Section {
    /// Human label shown in the sidebar.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Section::Dashboard => "Dashboard",
            Section::Tools => "Tools",
            Section::Templates => "Templates",
            Section::Ssh => "SSH",
            Section::Firewall => "Firewall",
            Section::Fail2ban => "fail2ban",
            Section::Tailscale => "Tailscale",
            Section::Harden => "Harden",
            Section::WireGuard => "WireGuard",
            Section::Updates => "Updates",
            Section::Users => "Users",
            Section::Audit => "Audit",
            Section::Monitor => "Monitor",
            Section::Backup => "Backup",
            Section::Proxy => "Proxy",
            Section::Cloud => "Cloud",
            Section::Mise => "Mise",
            Section::Logs => "Logs",
            Section::About => "About",
            Section::Settings => "Settings",
        }
    }
}

// ── SshSection ───────────────────────────────────────────────────────────────

/// Sub-tabs within the SSH management content area.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SshSection {
    /// Security overview dashboard (landing tab).
    Security,
    /// SSH key management (list, generate, delete, rename, etc.).
    Keys,
    /// Trusted hosts from `known_hosts`.
    KnownHosts,
    /// SSH config host blocks.
    Config,
    /// SSH agent status and loaded keys.
    Agent,
    /// Active port forwarding sessions.
    Forwarding,
    /// SSH health diagnostics.
    Diagnostics,
    /// `authorized_keys` management (who can SSH into this machine).
    AuthorizedKeys,
    /// SSH certificate inspection and revocation.
    Certificates,
}

impl SshSection {
    /// Human label shown in the sub-tab bar.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            SshSection::Security => "Security",
            SshSection::Keys => "Keys",
            SshSection::KnownHosts => "Hosts",
            SshSection::Config => "Config",
            SshSection::Agent => "Agent",
            SshSection::Forwarding => "Fwd",
            SshSection::Diagnostics => "Diag",
            SshSection::AuthorizedKeys => "Auth",
            SshSection::Certificates => "Certs",
        }
    }

    /// All sub-tabs in display order.
    #[must_use]
    pub fn all() -> &'static [SshSection] {
        &[
            SshSection::Security,
            SshSection::Keys,
            SshSection::KnownHosts,
            SshSection::Config,
            SshSection::Agent,
            SshSection::Forwarding,
            SshSection::Diagnostics,
            SshSection::AuthorizedKeys,
            SshSection::Certificates,
        ]
    }

    /// Next sub-tab in order (wraps).
    #[must_use]
    pub fn next(self) -> Self {
        let all = Self::all();
        let idx = all.iter().position(|&s| s == self).unwrap_or(0);
        all[(idx + 1) % all.len()]
    }

    /// Previous sub-tab in order (wraps).
    #[must_use]
    pub fn prev(self) -> Self {
        let all = Self::all();
        let idx = all.iter().position(|&s| s == self).unwrap_or(0);
        all[(idx + all.len() - 1) % all.len()]
    }
}

/// A single entry in the sidebar nav list.
#[derive(Clone, Debug)]
pub struct SidebarItem {
    /// Decorative glyph.
    pub icon: &'static str,
    /// The section this item navigates to.
    pub section: Section,
    /// Optional trailing badge (count or version label).
    pub badge: Option<String>,
}

// ── Host info ────────────────────────────────────────────────────────────────

/// Host summary shown in the top-right system info card. All fields default to
/// the honest placeholder `—` until live [`TorideStatus`](crate::status::TorideStatus)
/// data is available, so nothing fabricated flashes before the first poll.
#[derive(Clone, Debug)]
pub struct HostInfo {
    /// Hostname.
    pub hostname: String,
    /// OS string (e.g. `Ubuntu 24.04.1 LTS`).
    pub os: String,
    /// CPU brand (e.g. `Intel Xeon E5-2680 v4`).
    pub cpu: String,
    /// Logical CPU count label (e.g. `4 vCPU`).
    pub vcpu: String,
    /// Used memory label (e.g. `8 GB`).
    pub mem_used: String,
    /// Total memory label (e.g. `80 GB`).
    pub mem_total: String,
    /// Uptime label (e.g. `12d 4h 17m`).
    pub uptime: String,
    /// Load average label (e.g. `0.93 0.87 1.22`).
    pub load: String,
}

impl HostInfo {
    /// Honest empty host info: every field is the `—` placeholder so the system
    /// card never shows fabricated hostname / OS / CPU / memory values at cold
    /// start. [`DashboardScreen::set_status`] overlays live values once the
    /// first [`TorideStatus`](crate::status::TorideStatus) lands.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            hostname: "—".into(),
            os: "—".into(),
            cpu: "—".into(),
            vcpu: "—".into(),
            mem_used: "—".into(),
            mem_total: "—".into(),
            uptime: "—".into(),
            load: "—".into(),
        }
    }
}

// ── Aggregate ────────────────────────────────────────────────────────────────

/// All data backing the dashboard screen.
#[derive(Clone, Debug)]
pub struct DashboardData {
    /// Sidebar navigation items.
    pub sidebar: Vec<SidebarItem>,
    /// Module cards.
    pub modules: Vec<Module>,
    /// Host summary.
    pub host: HostInfo,
}

impl DashboardData {
    /// Honest empty/skeleton default for cold start.
    ///
    /// Every field is empty or a placeholder: NO fabricated host info, module
    /// cards, or sidebar badges. Collectors overlay live values as they report
    /// (see `DashboardScreen::set_*`); until then the dashboard renders honest
    /// `—` / "collecting…" / empty states rather than mock data that flashes
    /// for ~2s and could be mistaken for real host state.
    ///
    /// The single "collecting system status…" sentinel module gives the empty
    /// grid a non-blank first card so keyboard navigation has a valid bound
    /// before the live managed-services snapshot lands.
    ///
    /// NOTE: the old `modules_installed` / `modules_total` / `staged` /
    /// `updates` / `activity` fields were removed — they were never populated
    /// with real data (all live data lives in the per-section content structs)
    /// and were pure dead public-API surface. The two dashboard reads that
    /// referenced them now use literal `0` / the live `pending_total` Option.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn empty() -> Self {
        let sidebar = vec![
            SidebarItem {
                icon: "◑",
                section: Section::Dashboard,
                badge: None,
            },
            SidebarItem {
                icon: "▣",
                section: Section::Tools,
                badge: None,
            },
            SidebarItem {
                icon: "▲",
                section: Section::Templates,
                badge: None,
            },
            SidebarItem {
                icon: "◆",
                section: Section::Ssh,
                badge: None,
            },
            SidebarItem {
                icon: "▦",
                section: Section::Firewall,
                badge: None,
            },
            SidebarItem {
                icon: "✦",
                section: Section::Fail2ban,
                badge: None,
            },
            SidebarItem {
                icon: "⛓",
                section: Section::Tailscale,
                badge: None,
            },
            SidebarItem {
                icon: "⚙",
                section: Section::Harden,
                badge: None,
            },
            SidebarItem {
                icon: "◇",
                section: Section::WireGuard,
                badge: None,
            },
            SidebarItem {
                icon: "↻",
                section: Section::Updates,
                badge: None,
            },
            SidebarItem {
                icon: "◉",
                section: Section::Users,
                badge: None,
            },
            SidebarItem {
                icon: "⚖",
                section: Section::Audit,
                badge: None,
            },
            SidebarItem {
                icon: "◎",
                section: Section::Monitor,
                badge: None,
            },
            SidebarItem {
                icon: "▣",
                section: Section::Backup,
                badge: None,
            },
            SidebarItem {
                icon: "⊕",
                section: Section::Proxy,
                badge: None,
            },
            SidebarItem {
                icon: "☁",
                section: Section::Cloud,
                badge: None,
            },
            SidebarItem {
                icon: "Ⓜ",
                section: Section::Mise,
                badge: None,
            },
            SidebarItem {
                icon: "≡",
                section: Section::Logs,
                badge: None,
            },
            SidebarItem {
                icon: "◇",
                section: Section::About,
                badge: None,
            },
            SidebarItem {
                icon: "⚙",
                section: Section::Settings,
                badge: None,
            },
        ];

        let modules = vec![Module {
            icon: "·",
            name: "collecting system status…".into(),
            status: ModuleStatus::Offline,
            summary: "live sections appear once backends report.".into(),
            detail: "· waiting for collectors".into(),
        }];

        Self {
            sidebar,
            modules,
            host: HostInfo::empty(),
        }
    }
}

impl Default for DashboardData {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_has_honest_defaults() {
        let d = DashboardData::empty();
        // A single honest sentinel module (so the grid is not blank and
        // keyboard navigation has a valid bound before collectors report).
        assert_eq!(d.modules.len(), 1, "exactly one collecting-sentinel module");
        // Host info is the honest `—` placeholder everywhere.
        assert_eq!(d.host.hostname, "—");
        assert_eq!(d.host.os, "—");
        assert_eq!(d.host.uptime, "—");
    }

    #[test]
    fn sidebar_starts_with_dashboard() {
        let d = DashboardData::empty();
        assert_eq!(d.sidebar[0].section, Section::Dashboard);
        assert_eq!(d.sidebar.len(), 20);
    }

    #[test]
    fn sidebar_has_no_fabricated_badges() {
        // No hardcoded badge strings at cold start — every badge is None until
        // a live collector reports. (The previous mock seeded "78"/"active"/"12".)
        let d = DashboardData::empty();
        for item in &d.sidebar {
            assert!(
                item.badge.is_none(),
                "section {:?} must not carry a fabricated badge at cold start",
                item.section,
            );
        }
    }

    #[test]
    fn status_colors_differ_by_variant() {
        let p = Palette::default();
        assert_ne!(
            ModuleStatus::Installed.color(p),
            ModuleStatus::Active.color(p)
        );
    }

    /// Regression for the green-✓-on-offline bug: `offline` must not share the
    /// installed glyph (`✓`) or ok colour, and `degraded` must use the warn
    /// glyph (`!`) / colour rather than the ready `✓` / info colour.
    #[test]
    fn offline_and_degraded_have_distinct_glyphs_and_colors() {
        let p = Palette::default();
        // Offline: ✗ in err, never the healthy ✓ / ok.
        assert_eq!(ModuleStatus::Offline.glyph(), "✗");
        assert_eq!(ModuleStatus::Offline.label(), "offline");
        assert_eq!(ModuleStatus::Offline.color(p), p.err);
        assert_ne!(
            ModuleStatus::Offline.glyph(),
            ModuleStatus::Installed.glyph()
        );
        assert_ne!(
            ModuleStatus::Offline.color(p),
            ModuleStatus::Installed.color(p)
        );
        // Degraded: ! in warn, never the ready ✓ / info.
        assert_eq!(ModuleStatus::Degraded.glyph(), "!");
        assert_eq!(ModuleStatus::Degraded.label(), "degraded");
        assert_eq!(ModuleStatus::Degraded.color(p), p.warn);
        assert_ne!(ModuleStatus::Degraded.glyph(), ModuleStatus::Ready.glyph());
        assert_ne!(
            ModuleStatus::Degraded.color(p),
            ModuleStatus::Ready.color(p)
        );
    }
}
