//! Dashboard domain models and mock seed data.
//!
//! These are lightweight presentation models that drive the dashboard screen.
//! The first iteration is seeded with static mock data via [`DashboardData::mock`]
//! that mirrors the design mockup; live [`TorideStatus`](crate::status::TorideStatus)
//! data is layered on top by the screen where available (header gauges, system
//! info card).

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
}

impl ModuleStatus {
    /// Short human label (e.g. `installed`).
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            ModuleStatus::Installed => "installed",
            ModuleStatus::Active => "active",
            ModuleStatus::Ready => "ready",
        }
    }

    /// Status glyph shown before the label.
    #[must_use]
    pub fn glyph(self) -> &'static str {
        "✓"
    }

    /// Palette colour for the status text.
    #[must_use]
    pub fn color(self, p: Palette) -> Color {
        match self {
            ModuleStatus::Installed => p.ok,
            ModuleStatus::Active => p.accent3,
            ModuleStatus::Ready => p.info,
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

// ── Update ───────────────────────────────────────────────────────────────────

/// An available package/module update listed in the "Updates Available" panel.
#[derive(Clone, Debug)]
pub struct ModuleUpdate {
    /// Package / module name.
    pub name: String,
    /// Current version, if known (`None` renders as `—`).
    pub from: Option<String>,
    /// Target version to upgrade to.
    pub to: String,
    /// Source/tag badge (e.g. `apt`, `curl`, `compose`).
    pub badge: String,
}

// ── Activity ─────────────────────────────────────────────────────────────────

/// Outcome kind of a [`ActivityEntry`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivityKind {
    /// Succeeded.
    Ok,
    /// Warning / advisory.
    Warn,
    /// In-progress / process action.
    Process,
}

impl ActivityKind {
    /// Leading glyph for the entry.
    #[must_use]
    pub fn glyph(self) -> &'static str {
        match self {
            ActivityKind::Ok => "✓",
            ActivityKind::Warn => "!",
            ActivityKind::Process => "↻",
        }
    }

    /// Palette colour for the glyph.
    #[must_use]
    pub fn color(self, p: Palette) -> Color {
        match self {
            ActivityKind::Ok => p.ok,
            ActivityKind::Warn => p.warn,
            ActivityKind::Process => p.accent3,
        }
    }
}

/// A timestamped entry in the "Recently Installed" activity log.
#[derive(Clone, Debug)]
pub struct ActivityEntry {
    /// Wall-clock time label (e.g. `14:32`).
    pub time: String,
    /// Outcome kind.
    pub kind: ActivityKind,
    /// Message describing what happened.
    pub message: String,
    /// Duration label (e.g. `2.1s`).
    pub duration: String,
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
            Section::Logs => "Logs",
            Section::About => "About",
            Section::Settings => "Settings",
        }
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

/// Host summary shown in the top-right system info card. Mock values are used
/// until live [`TorideStatus`](crate::status::TorideStatus) data is available.
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

// ── Aggregate ────────────────────────────────────────────────────────────────

/// All data backing the dashboard screen.
#[derive(Clone, Debug)]
pub struct DashboardData {
    /// Number of installed modules (numerator of the stat card).
    pub modules_installed: usize,
    /// Total number of modules (denominator of the stat card).
    pub modules_total: usize,
    /// Number of staged changes.
    pub staged: usize,
    /// Sidebar navigation items.
    pub sidebar: Vec<SidebarItem>,
    /// Module cards.
    pub modules: Vec<Module>,
    /// Available updates.
    pub updates: Vec<ModuleUpdate>,
    /// Recent activity log.
    pub activity: Vec<ActivityEntry>,
    /// Host summary.
    pub host: HostInfo,
    /// Connected SSH user@host shown at the bottom of the sidebar.
    pub ssh_target: String,
}

impl DashboardData {
    /// Number of available updates (drives the `· N` label).
    #[must_use]
    pub fn updates_count(&self) -> usize {
        self.updates.len()
    }

    /// Seed the dashboard with static mock data mirroring the design mockup.
    #[must_use]
    #[expect(clippy::too_many_lines, reason = "static seed data is verbose but flat")]
    pub fn mock() -> Self {
        let sidebar = vec![
            SidebarItem { icon: "◑", section: Section::Dashboard, badge: None },
            SidebarItem { icon: "▣", section: Section::Tools, badge: Some("78".into()) },
            SidebarItem { icon: "▲", section: Section::Templates, badge: None },
            SidebarItem { icon: "◆", section: Section::Ssh, badge: None },
            SidebarItem { icon: "▦", section: Section::Firewall, badge: Some("active".into()) },
            SidebarItem { icon: "✦", section: Section::Fail2ban, badge: Some("12".into()) },
            SidebarItem { icon: "≡", section: Section::Logs, badge: None },
            SidebarItem { icon: "◇", section: Section::About, badge: None },
            SidebarItem { icon: "⚙", section: Section::Settings, badge: None },
        ];

        let modules = vec![
            Module {
                icon: "◆",
                name: "ssh hardening".into(),
                status: ModuleStatus::Installed,
                summary: "PermitRootLogin no · PasswordAuth no.".into(),
                detail: "· port 2202 · 2 keys".into(),
            },
            Module {
                icon: "▦",
                name: "ufw firewall".into(),
                status: ModuleStatus::Active,
                summary: "Default deny in, only HTTP(S) + SSH open.".into(),
                detail: "· 6 rules".into(),
            },
            Module {
                icon: "✦",
                name: "fail2ban".into(),
                status: ModuleStatus::Active,
                summary: "sshd + traefik-auth jails, 1h ban.".into(),
                detail: "· 12 bans/24h".into(),
            },
            Module {
                icon: "›",
                name: "traefik".into(),
                status: ModuleStatus::Ready,
                summary: "Cloudflare-only mode · DNS-01 cert.".into(),
                detail: "· v3.2 · CF-only".into(),
            },
            Module {
                icon: "◉",
                name: "dokploy".into(),
                status: ModuleStatus::Active,
                summary: "panel.kaito.dev · 8 containers.".into(),
                detail: "· v0.18.2".into(),
            },
            Module {
                icon: "▶",
                name: "system packages".into(),
                status: ModuleStatus::Installed,
                summary: "tmux, neovim, btop, fzf, ripgrep, bat…".into(),
                detail: "· 28 pkgs".into(),
            },
            Module {
                icon: "◆",
                name: "bun runtime".into(),
                status: ModuleStatus::Installed,
                summary: "Bun JS runtime + package manager.".into(),
                detail: "· 1.1.34".into(),
            },
            Module {
                icon: "◆",
                name: "docker engine".into(),
                status: ModuleStatus::Active,
                summary: "Docker CE + compose plugin.".into(),
                detail: "· 27.4.1".into(),
            },
        ];

        let updates = vec![
            ModuleUpdate { name: "bun".into(), from: Some("1.1.34".into()), to: "1.2.0".into(), badge: "curl".into() },
            ModuleUpdate { name: "dokploy".into(), from: Some("0.18.2".into()), to: "0.19.0".into(), badge: "compose".into() },
            ModuleUpdate { name: "neovim".into(), from: Some("0.10.0".into()), to: "0.10.2".into(), badge: "apt".into() },
            ModuleUpdate { name: "docker-ce".into(), from: Some("27.4.1".into()), to: "27.4.2".into(), badge: "apt".into() },
            ModuleUpdate { name: "ripgrep".into(), from: None, to: "14.1.1".into(), badge: "apt".into() },
        ];

        let activity = vec![
            ActivityEntry { time: "14:32".into(), kind: ActivityKind::Ok, message: "fail2ban: jail [sshd] active".into(), duration: "2.1s".into() },
            ActivityEntry { time: "14:31".into(), kind: ActivityKind::Ok, message: "ufw: enabled with 6 rules".into(), duration: "0.4s".into() },
            ActivityEntry { time: "14:30".into(), kind: ActivityKind::Warn, message: "ssh: rotated host keys — old fp purged".into(), duration: "1.8s".into() },
            ActivityEntry { time: "14:28".into(), kind: ActivityKind::Process, message: "apt-get update && dist-upgrade".into(), duration: "31s".into() },
            ActivityEntry { time: "14:24".into(), kind: ActivityKind::Ok, message: "docker-ce 27.4.1 + compose plugin".into(), duration: "44s".into() },
            ActivityEntry { time: "13:52".into(), kind: ActivityKind::Ok, message: "bun 1.1.34 → /home/kaito/.bun".into(), duration: "12s".into() },
            ActivityEntry { time: "13:49".into(), kind: ActivityKind::Ok, message: "apt: tmux neovim btop fzf ripgrep bat".into(), duration: "8.2s".into() },
        ];

        let host = HostInfo {
            hostname: "shimokita-edge".into(),
            os: "Ubuntu 24.04.1 LTS".into(),
            cpu: "Intel Xeon E5-2680 v4".into(),
            vcpu: "4 vCPU".into(),
            mem_used: "8 GB".into(),
            mem_total: "80 GB".into(),
            uptime: "12d 4h 17m".into(),
            load: "0.93 0.87 1.22".into(),
        };

        Self {
            modules_installed: 8,
            modules_total: 8,
            staged: 0,
            sidebar,
            modules,
            updates,
            activity,
            host,
            ssh_target: "kaito@shimokita-edge".into(),
        }
    }
}

impl Default for DashboardData {
    fn default() -> Self {
        Self::mock()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_has_expected_counts() {
        let d = DashboardData::mock();
        assert_eq!(d.modules.len(), d.modules_installed);
        assert_eq!(d.modules_installed, 8);
        assert_eq!(d.modules_total, 8);
        assert_eq!(d.updates_count(), 5);
        assert_eq!(d.staged, 0);
    }

    #[test]
    fn sidebar_starts_with_dashboard() {
        let d = DashboardData::mock();
        assert_eq!(d.sidebar[0].section, Section::Dashboard);
        assert_eq!(d.sidebar.len(), 9);
    }

    #[test]
    fn first_update_without_from_renders_dash_intent() {
        let d = DashboardData::mock();
        // ripgrep has no current version.
        let rg = d.updates.iter().find(|u| u.name == "ripgrep").unwrap();
        assert!(rg.from.is_none());
    }

    #[test]
    fn status_colors_differ_by_variant() {
        let p = Palette::default();
        assert_ne!(ModuleStatus::Installed.color(p), ModuleStatus::Active.color(p));
        assert_ne!(ActivityKind::Ok.color(p), ActivityKind::Warn.color(p));
    }
}
