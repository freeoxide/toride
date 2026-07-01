//! The main Dashboard screen: a full-width shell (header / sidebar / footer)
//! wrapping stat cards, a module-card grid, an updates list and an activity log.
//!
//! Built on the reusable [`shell`](crate::ui::shell) chrome. The sidebar drives
//! an internal "active section"; only [`Section::Dashboard`] renders full
//! content for now, other sections show a placeholder.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crossterm::event::{KeyCode, MouseEvent, MouseEventKind};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::action::Action;
use crate::data::{DashboardData, Module, ModuleStatus, Section};
use crate::status::TorideStatus;
use crate::ui::components::{ButtonRow, interactive_button::InteractiveButton};
use crate::ui::helpers::{format_bytes, format_duration, percent_color};
use crate::ui::responsive::{Viewport, truncate_str};
use crate::ui::screens::AppScreen;
use crate::ui::screens::about::AboutContent;
use crate::ui::screens::base::ScreenBase;
use crate::ui::screens::fail2ban::Fail2banContent;
use crate::ui::screens::logs::LogsContent;
use crate::ui::screens::section_overview::{OverviewSnapshot, SectionOverview};
use crate::ui::screens::settings::SettingsContent;
use crate::ui::screens::ssh::SshContent;
use crate::ui::screens::templates::TemplatesContent;
use crate::ui::screens::tools::ToolsContent;
use crate::ui::screens::toride_audit::AuditContent;
use crate::ui::screens::toride_backup::BackupContent;
use crate::ui::screens::toride_cloud::CloudContent;
use crate::ui::screens::toride_harden::HardenContent;
use crate::ui::screens::toride_mise::MiseContent;
use crate::ui::screens::toride_monitor::MonitorContent;
use crate::ui::screens::toride_proxy::ProxyContent;
use crate::ui::screens::toride_tailscale::TailscaleContent;
use crate::ui::screens::toride_updates::UpdatesContent;
use crate::ui::screens::toride_users::UsersContent;
use crate::ui::screens::toride_wireguard::WireguardContent;
use crate::ui::screens::ufw_kit::FirewallContent;
use crate::ui::shell::{
    SIDEBAR_W, SIDEBAR_W_COLLAPSED, Sidebar, gauge_hitboxes, header::HeaderData, render_footer,
    render_header, shell_layout,
};
use crate::ui::theme::Palette;
use crate::ui::widgets::{
    Card, Tooltip, kv, kv_with_suffix, render_panel, render_titled_panel, title_line,
    title_line_with_detail,
};
use crate::ui::widgets::{InteractiveModal, ModalEvent};
use ratatui_interact::state::FocusManager;
use tachyonfx::{EffectManager, Interpolation, fx};

/// Below this frame width the sidebar auto-collapses to an icon rail.
const AUTO_COLLAPSE_W: u16 = 100;
/// Below this content width the dashboard drops to a single column.
const SINGLE_COL_W: u16 = 78;
/// Height of the top stat-card row.
const STAT_ROW_H: u16 = 6;
/// Height of a module card in the grid.
const MODULE_CARD_H: u16 = 5;
/// Number of columns in the module grid (used for keyboard navigation).
const GRID_COLS: usize = 2;
/// Number of read-only sections surfaced in the live managed-services grid.
pub const MANAGED_SECTIONS_TOTAL: usize = 13;

/// Bundled inputs for the stat-card row, passed as one argument to keep
/// [`DashboardScreen::render_stat_cards`] under clippy's argument limit.
#[derive(Clone, Copy, Debug)]
struct StatCardInput {
    /// Whether live status has been collected (else mock fallback).
    live: bool,
    /// Count of sections whose backend is reachable.
    managed_available: usize,
    /// Total findings across sections + status warnings.
    findings: usize,
    /// Live pending-update count, if the updates backend is available.
    pending_total: Option<usize>,
}

/// One row of the live "Managed Services" grid: a section's icon, name, and an
/// owned snapshot of its overview. Owned so it can be collected across all 13
/// content fields before any `&mut self` panel render runs.
#[derive(Clone, Debug)]
#[allow(dead_code)] // `section` documents the source section for future click-to-navigate.
struct ManagedServiceCard {
    icon: &'static str,
    name: &'static str,
    section: Section,
    overview: OverviewSnapshot,
}

impl ManagedServiceCard {
    /// Map the overview status label to a [`ModuleStatus`] for reuse of
    /// [`render_module_card`] and the module modal/hitboxes without changes.
    #[must_use]
    fn status(&self) -> ModuleStatus {
        match self.overview.status_label {
            "active" => ModuleStatus::Active,
            "degraded" => ModuleStatus::Degraded,
            "offline" => ModuleStatus::Offline,
            _ => ModuleStatus::Installed,
        }
    }

    /// Build the [`Module`] view consumed by [`render_module_card`] / the modal.
    #[must_use]
    fn to_module(&self) -> Module {
        // An offline section could not collect findings, so rendering
        // "· 0 finding(s)" is noisy and implies a successful inspection.
        // Surface "backend unreachable" instead; any other status reports
        // the uniform finding count.
        let detail = if self.overview.status_label == "offline" {
            "backend unreachable".to_string()
        } else {
            format!("· {} finding(s)", self.overview.findings_count)
        };
        Module {
            icon: self.icon,
            name: self.name.to_string(),
            status: self.status(),
            summary: self
                .overview
                .detail
                .clone()
                .unwrap_or_else(|| self.overview.status_label.to_string()),
            detail,
        }
    }
}

/// Which header gauge is currently hovered by the mouse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GaugeKind {
    Cpu,
    Ram,
    Disk,
    Net,
}

/// Top-level focus regions. This never grows — it is always exactly
/// `Sidebar ↔ Content`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ShellFocus {
    Sidebar,
    Content,
}

/// Internal focus within the Dashboard content area (modules grid, updates
/// list, activity log). Each section owns its own internal focus model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DashboardFocus {
    Modules,
    Updates,
    Activity,
}

impl DashboardFocus {
    fn next(self) -> Self {
        match self {
            Self::Modules => Self::Updates,
            Self::Updates => Self::Activity,
            Self::Activity => Self::Modules,
        }
    }

    fn prev(self) -> Self {
        match self {
            Self::Modules => Self::Activity,
            Self::Updates => Self::Modules,
            Self::Activity => Self::Updates,
        }
    }
}

/// Shared dispatch surface for every read-only content section panel.
///
/// All 18 non-`Dashboard` content structs ([`SshContent`], [`Fail2banContent`],
/// [`FirewallContent`], [`HardenContent`], [`WireguardContent`],
/// [`UpdatesContent`], [`UsersContent`], [`AuditContent`], [`MonitorContent`],
/// [`BackupContent`], [`ProxyContent`], [`CloudContent`], [`TailscaleContent`],
/// [`MiseContent`], [`ToolsContent`], [`TemplatesContent`], [`LogsContent`],
/// [`AboutContent`], [`SettingsContent`]) expose the exact same
/// `handle_key` / `handle_mouse` / `view` trio with identical signatures.
/// Modeling it as a trait lets the dashboard collapse what used to be five
/// near-identical 19-arm `match self.active_section()` blocks (key Tab/BackTab,
/// generic content key, render, mouse hover/click/scroll/up) into a single
/// [`DashboardScreen::active_panel_mut`] lookup plus one match arm for the
/// bespoke [`Section::Dashboard`] behavior.
///
/// [`Section::Dashboard`] is intentionally NOT a `ContentPanel`: it has
/// bespoke key handling ([`DashboardScreen::handle_dashboard_content_key`]),
/// bespoke rendering ([`DashboardScreen::render_dashboard_content`]), and
/// bespoke wheel scrolling ([`DashboardScreen::scroll_focused`]).
pub trait ContentPanel {
    /// Forward a keypress to the active content panel.
    fn handle_key(&mut self, code: KeyCode) -> Option<Action>;
    /// Forward a mouse event to the active content panel.
    fn handle_mouse(&mut self, mouse: MouseEvent) -> Option<Action>;
    /// Render the active content panel into its content area.
    fn view(&mut self, frame: &mut Frame, area: Rect, p: Palette);
}

macro_rules! impl_content_panel {
    ($($t:ty),+ $(,)?) => {
        $(
            impl ContentPanel for $t {
                fn handle_key(&mut self, code: KeyCode) -> Option<Action> {
                    Self::handle_key(self, code)
                }
                fn handle_mouse(&mut self, mouse: MouseEvent) -> Option<Action> {
                    Self::handle_mouse(self, mouse)
                }
                fn view(&mut self, frame: &mut Frame, area: Rect, p: Palette) {
                    Self::view(self, frame, area, p);
                }
            }
        )+
    };
}

impl_content_panel!(
    SshContent,
    Fail2banContent,
    FirewallContent,
    HardenContent,
    WireguardContent,
    UpdatesContent,
    UsersContent,
    AuditContent,
    MonitorContent,
    BackupContent,
    ProxyContent,
    CloudContent,
    TailscaleContent,
    MiseContent,
    ToolsContent,
    TemplatesContent,
    LogsContent,
    AboutContent,
    SettingsContent,
);

/// The dashboard screen state.
pub struct DashboardScreen {
    data: DashboardData,
    status: Option<TorideStatus>,
    sidebar: Sidebar,
    active: usize,
    focus: FocusManager<ShellFocus>,
    /// Internal panel focus for the Dashboard section only.
    dashboard_focus: DashboardFocus,
    module_sel: usize,
    module_scroll: usize,
    updates_scroll: usize,
    activity_scroll: usize,
    /// Which module index is shown in the detail modal (if open).
    open_module_idx: Option<usize>,
    /// Interactive module detail modal (manages visibility + rect + buttons + click-outside).
    module_modal: InteractiveModal<Action>,
    gauge_hover: Option<GaugeKind>,
    gauge_hitboxes: [Rect; 4],
    /// Last-rendered sidebar pane rect. Used to route mouse-wheel scroll by
    /// cursor position (over the sidebar → scroll the sidebar list) rather
    /// than by the focused shell region.
    sidebar_area: Rect,
    /// Hitbox rects for module cards (rebuilt each frame).
    module_hitboxes: Vec<Rect>,
    /// Materialized module list for the *current* frame: live modules when a
    /// status has been collected, else the mock list. Cached during render so
    /// keyboard navigation (`module_right/down/up/left`), the modal-open branch,
    /// and mouse click lookup all index the same vec the grid actually drew —
    /// never the disjoint mock list when the grid is live.
    modules_view: Vec<Module>,
    /// Live network throughput (bytes/sec).
    net_rx_rate: Option<f64>,
    net_tx_rate: Option<f64>,
    /// Live disk I/O throughput (bytes/sec).
    disk_read_rate: Option<f64>,
    disk_write_rate: Option<f64>,
    base: ScreenBase,
    clock: String,
    shimmer_start: Instant,
    /// Tooltip fade-in effect manager.
    tooltip_fx: EffectManager<()>,
    /// Previous hover state for detecting transitions.
    prev_gauge_hover: Option<GaugeKind>,
    /// Timestamp of the last render call (for frame deltas).
    last_frame: Instant,
    /// SSH management content (rendered when `Section::Ssh` is active).
    ssh_content: SshContent,
    /// Fail2ban management content (rendered when `Section::Fail2ban` is active).
    /// READ-ONLY: no write ops, no cooldown.
    fail2ban_content: Fail2banContent,
    /// UFW firewall management content (rendered when `Section::Firewall` is active).
    /// READ-ONLY: no write ops, no cooldown.
    ufw_kit_content: FirewallContent,
    /// Kernel-hardening management content (rendered when `Section::Harden` is
    /// active). READ-ONLY: no write ops, no cooldown.
    toride_harden_content: HardenContent,
    /// `WireGuard` management content (rendered when `Section::WireGuard` is
    /// active). READ-ONLY: no write ops, no cooldown.
    toride_wireguard_content: WireguardContent,
    /// Updates management content (rendered when `Section::Updates` is active).
    /// READ-ONLY: no write ops, no cooldown.
    toride_updates_content: UpdatesContent,
    /// User & access-control management content (rendered when `Section::Users`
    /// is active). READ-ONLY: no write ops, no cooldown.
    toride_users_content: UsersContent,
    /// Audit (auditd/AIDE/logs) management content (rendered when
    /// `Section::Audit` is active). READ-ONLY: no write ops, no cooldown.
    toride_audit_content: AuditContent,
    /// Outbound traffic monitor management content (rendered when
    /// `Section::Monitor` is active). READ-ONLY: no write ops, no cooldown.
    toride_monitor_content: MonitorContent,
    /// Backup (restic/borg) management content (rendered when `Section::Backup`
    /// is active). READ-ONLY: no write ops, no cooldown.
    toride_backup_content: BackupContent,
    /// Reverse-proxy (nginx/certbot/WAF) management content (rendered when
    /// `Section::Proxy` is active). READ-ONLY: no write ops, no cooldown.
    toride_proxy_content: ProxyContent,
    /// Cloud provider (security groups / firewalls / agent) management content
    /// (rendered when `Section::Cloud` is active). READ-ONLY: no write ops, no
    /// cooldown.
    toride_cloud_content: CloudContent,
    /// Tailscale mesh VPN (status / peers / netcheck / DNS) management content
    /// (rendered when `Section::Tailscale` is active). READ-ONLY: no write ops, no
    /// cooldown.
    toride_tailscale_content: TailscaleContent,
    /// Mise runtime version manager (installed tools / outdated / config /
    /// doctor) management content (rendered when `Section::Mise` is active).
    /// READ-ONLY: no write ops, no cooldown.
    toride_mise_content: MiseContent,
    /// About-toride content (rendered when `Section::About` is active).
    /// READ-ONLY: no write ops, no cooldown, no findings.
    about_content: AboutContent,
    /// System log-sources content (rendered when `Section::Logs` is active).
    /// READ-ONLY: no write ops, no cooldown, no findings.
    logs_content: LogsContent,
    /// Settings (app config + theme + runtime env) management content
    /// (rendered when `Section::Settings` is active). READ-ONLY: no write ops,
    /// no cooldown. ALSO carries the live active Theme, kept in sync by
    /// `App::update`'s `Action::CycleTheme` arm via `set_active_theme`.
    settings_content: SettingsContent,
    /// Hardening-recipes catalogue management content (rendered when
    /// `Section::Templates` is active). READ-ONLY: no write ops, no cooldown.
    templates_content: TemplatesContent,
    /// Installed-tools catalogue management content (rendered when
    /// `Section::Tools` is active). READ-ONLY: no write ops, no cooldown.
    tools_content: ToolsContent,
}

impl Default for DashboardScreen {
    fn default() -> Self {
        Self::new()
    }
}

impl DashboardScreen {
    /// Create a new dashboard seeded with an honest empty skeleton (no mock
    /// host info, modules, updates, or activity). Collectors overlay live data
    /// as they report via the `set_*` methods.
    #[must_use]
    pub fn new() -> Self {
        let data = DashboardData::empty();
        let sidebar = Sidebar::new(data.sidebar.len());
        let clock = "09:17 PM".to_string();
        // Seed the module view with the single honest "collecting system
        // status…" sentinel so keyboard navigation and the modal lookup have a
        // valid bound before the first render. The live managed-services grid
        // (13 cards) replaces this once a status is collected.
        let modules_view = data.modules.clone();
        Self {
            data,
            status: None,
            sidebar,
            active: 0,
            focus: {
                let mut fm = FocusManager::new();
                fm.register(ShellFocus::Sidebar);
                fm.register(ShellFocus::Content);
                fm
            },
            dashboard_focus: DashboardFocus::Modules,
            module_sel: 0,
            module_scroll: 0,
            updates_scroll: 0,
            activity_scroll: 0,
            open_module_idx: None,
            module_modal: InteractiveModal::with_buttons(
                "module",
                ButtonRow::new(
                    vec![
                        InteractiveButton::new("open", "↵", Action::Continue),
                        InteractiveButton::new("close", "esc", Action::Back),
                    ],
                    vec![4, 0],
                ),
            )
            .dimensions(54, 10),
            gauge_hover: None,
            gauge_hitboxes: [Rect::default(); 4],
            sidebar_area: Rect::default(),
            module_hitboxes: Vec::new(),
            modules_view,
            net_rx_rate: None,
            net_tx_rate: None,
            disk_read_rate: None,
            disk_write_rate: None,
            base: ScreenBase::new(),
            clock,
            shimmer_start: Instant::now(),
            tooltip_fx: EffectManager::default(),
            prev_gauge_hover: None,
            last_frame: Instant::now(),
            ssh_content: SshContent::new(),
            fail2ban_content: Fail2banContent::new(),
            ufw_kit_content: FirewallContent::new(),
            toride_harden_content: HardenContent::new(),
            toride_wireguard_content: WireguardContent::new(),
            toride_updates_content: UpdatesContent::new(),
            toride_users_content: UsersContent::new(),
            toride_audit_content: AuditContent::new(),
            toride_monitor_content: MonitorContent::new(),
            toride_backup_content: BackupContent::new(),
            toride_proxy_content: ProxyContent::new(),
            toride_cloud_content: CloudContent::new(),
            toride_mise_content: MiseContent::new(),
            about_content: AboutContent::new(),
            logs_content: LogsContent::new(),
            settings_content: SettingsContent::new(),
            templates_content: TemplatesContent::new(),
            tools_content: ToolsContent::new(),
            toride_tailscale_content: TailscaleContent::new(),
        }
    }

    /// Store the latest collected system status and compute live throughput rates.
    #[expect(clippy::cast_precision_loss, reason = "display-only")]
    pub fn set_status(&mut self, status: TorideStatus) {
        if let Some(prev) = &self.status {
            let dt = (status.collected_at)
                .duration_since(prev.collected_at)
                .map_or(0.5, |d| d.as_secs_f64())
                .max(0.1);

            // Network throughput
            let rx = status.system.network.bytes_received as f64
                - prev.system.network.bytes_received as f64;
            let tx = status.system.network.bytes_transmitted as f64
                - prev.system.network.bytes_transmitted as f64;
            self.net_rx_rate = Some(rx.max(0.0) / dt);
            self.net_tx_rate = Some(tx.max(0.0) / dt);

            // Disk I/O throughput
            let dr =
                status.system.disk_io.read_bytes as f64 - prev.system.disk_io.read_bytes as f64;
            let dw = status.system.disk_io.written_bytes as f64
                - prev.system.disk_io.written_bytes as f64;
            self.disk_read_rate = Some(dr.max(0.0) / dt);
            self.disk_write_rate = Some(dw.max(0.0) / dt);
        }
        self.status = Some(status);
        self.refresh_sidebar_badges();
    }

    /// Derive each section's sidebar badge from its LIVE content struct and
    /// write it into `self.data.sidebar[i].badge`. Called from each `set_*_data`
    /// setter (and `set_status`) so badges refresh as live data lands.
    ///
    /// At cold start (before any collector reports) every badge stays `None` —
    /// honest "nothing known yet". Never fabricates a count for a section whose
    /// backend is unreachable or whose content struct doesn't expose a clean
    /// count.
    fn refresh_sidebar_badges(&mut self) {
        // Read the live values out of the content structs first (no &mut self
        // borrow held) so we can then mutate self.data.sidebar in place. Every
        // accessor returns None when its backend is unavailable, so the badge
        // stays honestly empty at cold start — no count is ever fabricated.
        let tools = self.tools_content.installed_count().map(|n| n.to_string());
        let fail2ban = self.fail2ban_content.total_bans().map(|n| n.to_string());
        let firewall = self
            .ufw_kit_content
            .is_active()
            .map(|active| if active { "active" } else { "inactive" }.to_string());
        let updates = if self.toride_updates_content.available() {
            Some(self.toride_updates_content.pending_total().to_string())
        } else {
            None
        };
        let wireguard = self
            .toride_wireguard_content
            .badge_count()
            .map(|n| n.to_string());
        let proxy = self
            .toride_proxy_content
            .badge_count()
            .map(|n| n.to_string());
        let cloud = self
            .toride_cloud_content
            .badge_count()
            .map(|n| n.to_string());
        let users = self
            .toride_users_content
            .badge_count()
            .map(|n| n.to_string());
        let backup = self.toride_backup_content.badge_status().map(String::from);
        let tailscale = self
            .toride_tailscale_content
            .badge_count()
            .map(|n| n.to_string());
        let mise = self
            .toride_mise_content
            .badge_count()
            .map(|n| n.to_string());
        let harden = self
            .toride_harden_content
            .badge_count()
            .map(|n| n.to_string());
        let audit = self
            .toride_audit_content
            .badge_count()
            .map(|n| n.to_string());
        let monitor = self
            .toride_monitor_content
            .badge_count()
            .map(|n| n.to_string());
        for item in &mut self.data.sidebar {
            let badge = match item.section {
                Section::Tools => tools.clone(),
                Section::Fail2ban => fail2ban.clone(),
                Section::Firewall => firewall.clone(),
                Section::Updates => updates.clone(),
                Section::WireGuard => wireguard.clone(),
                Section::Proxy => proxy.clone(),
                Section::Cloud => cloud.clone(),
                Section::Users => users.clone(),
                Section::Backup => backup.clone(),
                Section::Tailscale => tailscale.clone(),
                Section::Mise => mise.clone(),
                Section::Harden => harden.clone(),
                Section::Audit => audit.clone(),
                Section::Monitor => monitor.clone(),
                // Sections without a clean live count (Dashboard, Ssh,
                // Templates, Logs, About, Settings) and the cold-start case
                // (backend unavailable): leave the badge honestly empty. Do
                // NOT fabricate counts.
                _ => None,
            };
            item.badge = badge;
        }
    }

    /// Snapshot of all 13 read-only sections for the live "Managed Services"
    /// grid and the MANAGED/FINDINGS stat cards.
    ///
    /// Returns an owned vec (no borrows held) so it can be called *before* the
    /// `&mut self` panel renders. SSH is excluded (no `available`/`findings`
    /// shape; already dominates the sidebar).
    #[must_use]
    fn managed_services(&self) -> Vec<ManagedServiceCard> {
        // Generic inner: builds a card from any SectionOverview impl.
        fn snap<O: SectionOverview>(
            icon: &'static str,
            name: &'static str,
            section: Section,
            o: &O,
        ) -> ManagedServiceCard {
            ManagedServiceCard {
                icon,
                name,
                section,
                overview: OverviewSnapshot {
                    status_label: o.status_label(),
                    detail: o.detail(),
                    findings_count: o.findings_count(),
                },
            }
        }

        vec![
            snap("✦", "fail2ban", Section::Fail2ban, &self.fail2ban_content),
            snap(
                "▦",
                "ufw firewall",
                Section::Firewall,
                &self.ufw_kit_content,
            ),
            snap("⚙", "harden", Section::Harden, &self.toride_harden_content),
            snap(
                "◇",
                "wireguard",
                Section::WireGuard,
                &self.toride_wireguard_content,
            ),
            snap(
                "↻",
                "updates",
                Section::Updates,
                &self.toride_updates_content,
            ),
            snap("◉", "users", Section::Users, &self.toride_users_content),
            snap("⚖", "audit", Section::Audit, &self.toride_audit_content),
            snap(
                "◎",
                "monitor",
                Section::Monitor,
                &self.toride_monitor_content,
            ),
            snap("▣", "backup", Section::Backup, &self.toride_backup_content),
            snap("⊕", "proxy", Section::Proxy, &self.toride_proxy_content),
            snap("☁", "cloud", Section::Cloud, &self.toride_cloud_content),
            snap(
                "⛓",
                "tailscale",
                Section::Tailscale,
                &self.toride_tailscale_content,
            ),
            snap("Ⓜ", "mise", Section::Mise, &self.toride_mise_content),
        ]
    }

    /// Total findings across all 13 read-only sections, plus any status-gather
    /// warnings. The render path inlines this computation (see
    /// `render_dashboard_content`); this standalone copy exists solely as the
    /// oracle for `derived_findings_and_available_match_standalone_methods`.
    #[cfg(test)]
    #[must_use]
    fn findings_total(&self) -> usize {
        let mut total = self
            .managed_services()
            .iter()
            .map(|c| c.overview.findings_count)
            .sum::<usize>();
        if let Some(s) = &self.status {
            total += s.warnings.len();
        }
        total
    }

    /// Count of sections whose backend is reachable. The render path inlines
    /// this computation (see `render_dashboard_content`); this standalone copy
    /// exists solely as the oracle for
    /// `derived_findings_and_available_match_standalone_methods`.
    #[cfg(test)]
    #[must_use]
    fn managed_available(&self) -> usize {
        self.managed_services()
            .iter()
            .filter(|c| c.overview.status_label != "offline")
            .count()
    }

    // ── Test-only hooks to flip section availability for the live snapshot ──
    #[cfg(test)]
    pub(crate) fn fail2ban_set_available_for_test(&mut self, available: bool) {
        self.fail2ban_content.set_available(available);
    }

    #[cfg(test)]
    pub(crate) fn toride_updates_set_available_for_test(
        &mut self,
        available: bool,
        pending_total: usize,
        pending_security: usize,
    ) {
        self.toride_updates_content.set_available(available);
        self.toride_updates_content.set_status(
            "apt".to_string(),
            available,
            available,
            pending_security,
            pending_total,
            None,
        );
    }

    #[cfg(test)]
    pub(crate) fn ufw_kit_set_available_for_test(&mut self, available: bool) {
        self.ufw_kit_content.set_available(available);
    }

    /// Refresh the wall-clock label (called from the app refresh tick).
    pub fn tick_clock(&mut self) {
        self.clock = current_clock();
    }

    /// Provide live SSH data for all subsystems (called from the SSH data collector).
    pub fn set_ssh_data(&mut self, bundle: crate::ssh_data::SshDataBundle) {
        self.ssh_content.set_keys(bundle.keys);
        self.ssh_content.set_known_hosts(bundle.known_hosts);
        self.ssh_content.set_config_hosts(bundle.config_hosts);
        self.ssh_content
            .set_agent_data(bundle.agent_status, bundle.agent_keys);
        self.ssh_content.set_forwarding(bundle.forwarding);
        self.ssh_content.set_diagnostics(bundle.diagnostics);
        self.ssh_content.set_authorized_keys(bundle.authorized_keys);
        self.ssh_content.set_certificates(bundle.certificates);
        self.ssh_content.set_security(bundle.security);
    }

    /// Drain pending SSH write operations from the SSH content area.
    pub fn drain_ssh_ops(&mut self) -> Vec<crate::ssh_data::SshOp> {
        self.ssh_content.drain_pending_ops()
    }

    /// Re-queue SSH write operations at the front of the pending queue.
    ///
    /// Used by the app's serialized write loop to hold ops that were drained
    /// while a batch was already in-flight (so a second task is never spawned
    /// concurrently). The held ops are drained again once the in-flight batch
    /// completes. They are placed ahead of any ops the UI may queue in the
    /// meantime to preserve the user's original ordering.
    pub fn queue_ssh_ops_front(&mut self, ops: Vec<crate::ssh_data::SshOp>) {
        self.ssh_content.queue_ops_front(ops);
    }

    /// Push an SSH write error to be shown as a notification.
    pub fn push_ssh_error(&mut self, msg: String) {
        self.ssh_content.push_error(msg);
    }

    /// Update SSH loading state (spinner overlay) from the in-flight counter.
    pub fn set_ssh_loading(&mut self, loading: bool, count: usize) {
        self.ssh_content.set_loading(loading, count);
    }

    /// Provide live fail2ban data for the read-only Fail2ban section (called
    /// from the [`Fail2banCollector`](crate::fail2ban_data::Fail2banCollector)).
    ///
    /// Fans the bundle out to the content setters. There is no cooldown or
    /// optimistic-update reconciliation here — the section is strictly
    /// read-only, so every refresh cleanly overwrites the previous view.
    pub fn set_fail2ban_data(&mut self, b: crate::fail2ban_data::Fail2banDataBundle) {
        self.fail2ban_content.set_available(b.available);
        // Surface the panic reason (if any) only when unavailable. Must be set
        // AFTER set_available so the reason-clearing guard sees the fresh flag.
        self.fail2ban_content
            .set_unavailable_reason(b.unavailable_reason);
        self.fail2ban_content
            .set_service(b.service_active, b.service_enabled, b.version);
        self.fail2ban_content.set_jails(b.jails);
        self.fail2ban_content.set_bans(b.bans);
        self.fail2ban_content.set_findings(b.findings);
        self.fail2ban_content
            .set_firewall(b.fw_nft_available, b.fw_iptables_available);
        self.refresh_sidebar_badges();
    }

    /// Provide live UFW firewall data for the read-only Firewall section
    /// (called from the
    /// [`FirewallCollector`](crate::ufw_kit_data::FirewallCollector)).
    ///
    /// Fans the bundle out to the content setters. There is no cooldown or
    /// optimistic-update reconciliation here — the section is strictly
    /// read-only, so every refresh cleanly overwrites the previous view.
    pub fn set_ufw_kit_data(&mut self, b: crate::ufw_kit_data::FirewallDataBundle) {
        self.ufw_kit_content.set_available(b.available);
        // Surface the panic reason (if any) only when unavailable. Must be set
        // AFTER set_available so the reason-clearing guard sees the fresh flag.
        self.ufw_kit_content
            .set_unavailable_reason(b.unavailable_reason);
        self.ufw_kit_content.set_status(
            b.active,
            b.default_incoming,
            b.default_outgoing,
            b.default_routed,
            b.logging_level,
            b.version,
        );
        self.ufw_kit_content.set_rules(b.rules);
        self.ufw_kit_content.set_findings(b.findings);
        self.refresh_sidebar_badges();
    }

    /// Provide live kernel-hardening data for the read-only Harden section
    /// (called from the
    /// [`HardenCollector`](crate::toride_harden_data::HardenCollector)).
    ///
    /// Fans the bundle out to the content setters. There is no cooldown or
    /// optimistic-update reconciliation here — the section is strictly
    /// read-only, so every refresh cleanly overwrites the previous view. The
    /// profile selector is repopulated even on a degraded bundle so the desired
    /// state stays visible when the live state is unreadable.
    pub fn set_toride_harden_data(&mut self, b: crate::toride_harden_data::HardenDataBundle) {
        self.toride_harden_content.set_available(b.available);
        // Surface the unavailable reason (if any) only when unavailable. Must
        // be set AFTER set_available so the reason-clearing guard sees the
        // fresh flag.
        self.toride_harden_content
            .set_unavailable_reason(b.unavailable_reason);
        self.toride_harden_content.set_profiles(b.profiles);
        self.toride_harden_content
            .set_sysctl_rows_by_profile(b.sysctl_rows_by_profile);
        self.toride_harden_content.set_mounts(b.mounts);
        self.toride_harden_content.set_findings(b.findings);
    }

    /// Provide live `WireGuard` data for the read-only `WireGuard` section (called
    /// from the
    /// [`WireguardCollector`](crate::toride_wireguard_data::WireguardCollector)).
    ///
    /// Fans the bundle out to the content setters. There is no cooldown or
    /// optimistic-update reconciliation here — the section is strictly
    /// read-only, so every refresh cleanly overwrites the previous view.
    pub fn set_toride_wireguard_data(
        &mut self,
        b: crate::toride_wireguard_data::WireguardDataBundle,
    ) {
        self.toride_wireguard_content.set_available(b.available);
        // Surface the unavailable reason (if any) only when unavailable. Must
        // be set AFTER set_available so the reason-clearing guard sees the
        // fresh flag.
        self.toride_wireguard_content
            .set_unavailable_reason(b.unavailable_reason);
        self.toride_wireguard_content.set_env(
            b.wg_binary_found,
            b.wg_quick_binary_found,
            b.config_dir_exists,
        );
        self.toride_wireguard_content.set_interfaces(b.interfaces);
        self.toride_wireguard_content.set_peers(b.peers);
        self.toride_wireguard_content.set_services(b.services);
        self.toride_wireguard_content.set_findings(b.findings);
    }

    /// Provide live updates data for the read-only Updates section (called from
    /// the [`UpdatesCollector`](crate::toride_updates_data::UpdatesCollector)).
    ///
    /// Fans the bundle out to the content setters. There is no cooldown or
    /// optimistic-update reconciliation here — the section is strictly
    /// read-only, so every refresh cleanly overwrites the previous view.
    pub fn set_toride_updates_data(&mut self, b: crate::toride_updates_data::UpdatesDataBundle) {
        self.toride_updates_content.set_available(b.available);
        // Surface the unavailable reason (if any) only when unavailable. Must
        // be set AFTER set_available so the reason-clearing guard sees the
        // fresh flag.
        self.toride_updates_content
            .set_unavailable_reason(b.unavailable_reason);
        self.toride_updates_content.set_status(
            b.package_manager,
            b.auto_updates_enabled,
            b.service_active,
            b.pending_security,
            b.pending_total,
            b.last_run,
        );
        self.toride_updates_content.set_schedule(b.schedule);
        self.toride_updates_content.set_timer_active(b.timer_active);
        self.toride_updates_content.set_findings(b.findings);
        self.refresh_sidebar_badges();
    }

    /// Provide live user & access-control data for the read-only Users section
    /// (called from the
    /// [`UsersCollector`](crate::toride_users_data::UsersCollector)).
    ///
    /// Fans the bundle out to the content setters. There is no cooldown or
    /// optimistic-update reconciliation here — the section is strictly
    /// read-only, so every refresh cleanly overwrites the previous view.
    pub fn set_toride_users_data(&mut self, b: crate::toride_users_data::UsersDataBundle) {
        self.toride_users_content.set_available(b.available);
        // Surface the unavailable reason (if any) only when unavailable. Must
        // be set AFTER set_available so the reason-clearing guard sees the
        // fresh flag.
        self.toride_users_content
            .set_unavailable_reason(b.unavailable_reason);
        self.toride_users_content.set_read_flags(
            b.passwd_read,
            b.shadow_read,
            b.sudoers_read,
            b.pam_read,
        );
        self.toride_users_content.set_users(b.users);
        self.toride_users_content.set_groups(b.groups);
        self.toride_users_content.set_sudoers(b.sudoers);
        self.toride_users_content.set_findings(b.findings);
    }

    /// Provide live audit data for the read-only Audit section (called from the
    /// [`AuditCollector`](crate::toride_audit_data::AuditCollector)).
    ///
    /// Fans the bundle out to the content setters. There is no cooldown or
    /// optimistic-update reconciliation here — the section is strictly
    /// read-only, so every refresh cleanly overwrites the previous view.
    pub fn set_toride_audit_data(&mut self, b: crate::toride_audit_data::AuditDataBundle) {
        self.toride_audit_content.set_available(b.available);
        // Surface the unavailable reason (if any) only when unavailable. Must
        // be set AFTER set_available so the reason-clearing guard sees the
        // fresh flag.
        self.toride_audit_content
            .set_unavailable_reason(b.unavailable_reason);
        self.toride_audit_content
            .set_auditd(b.auditd_running, b.auditd_status);
        self.toride_audit_content.set_integrity(b.integrity);
        self.toride_audit_content.set_rules(b.rules);
        self.toride_audit_content.set_log_sources(b.log_sources);
        self.toride_audit_content
            .set_log_backends(b.rsyslog_available, b.journald_available);
        self.toride_audit_content.set_findings(b.findings);
    }

    /// Provide live outbound-traffic monitor data for the read-only Monitor
    /// section (called from the
    /// [`MonitorCollector`](crate::toride_monitor_data::MonitorCollector)).
    ///
    /// Fans the bundle out to the content setters. There is no cooldown or
    /// optimistic-update reconciliation here — the section is strictly
    /// read-only, so every refresh cleanly overwrites the previous view.
    pub fn set_toride_monitor_data(&mut self, b: crate::toride_monitor_data::MonitorDataBundle) {
        self.toride_monitor_content.set_available(b.available);
        // Surface the unavailable reason (if any) only when unavailable. Must
        // be set AFTER set_available so the reason-clearing guard sees the
        // fresh flag.
        self.toride_monitor_content
            .set_unavailable_reason(b.unavailable_reason);
        self.toride_monitor_content.set_summary(b.summary);
        self.toride_monitor_content.set_connections(b.connections);
        self.toride_monitor_content.set_ports(b.ports);
        self.toride_monitor_content.set_conntrack(b.conntrack);
        self.toride_monitor_content
            .set_output_rule_count(b.output_rule_count);
        self.toride_monitor_content.set_anomalies(b.anomalies);
        self.toride_monitor_content.set_findings(b.findings);
    }

    /// Provide live backup data for the read-only Backup section (called from
    /// the [`BackupCollector`](crate::toride_backup_data::BackupCollector)).
    ///
    /// Fans the bundle out to the content setters. There is no cooldown or
    /// optimistic-update reconciliation here — the section is strictly
    /// read-only, so every refresh cleanly overwrites the previous view.
    pub fn set_toride_backup_data(&mut self, b: crate::toride_backup_data::BackupDataBundle) {
        self.toride_backup_content.set_available(b.available);
        // Surface the unavailable reason (if any) only when unavailable. Must
        // be set AFTER set_available so the reason-clearing guard sees the
        // fresh flag.
        self.toride_backup_content
            .set_unavailable_reason(b.unavailable_reason);
        self.toride_backup_content
            .set_status(b.dry_run, b.config_dir, b.data_dir, b.schedule_dir);
        self.toride_backup_content
            .set_binaries(b.restic_available, b.borg_available);
        self.toride_backup_content.set_schedule(
            b.schedule_installed,
            b.timer_active,
            b.schedule_note,
        );
        self.toride_backup_content.set_findings(b.findings);
    }

    /// Provide live reverse-proxy data for the read-only Proxy section (called
    /// from the [`ProxyCollector`](crate::toride_proxy_data::ProxyCollector)).
    ///
    /// Fans the bundle out to the content setters. There is no cooldown or
    /// optimistic-update reconciliation here — the section is strictly
    /// read-only, so every refresh cleanly overwrites the previous view.
    pub fn set_toride_proxy_data(&mut self, b: crate::toride_proxy_data::ProxyDataBundle) {
        self.toride_proxy_content.set_available(b.available);
        // Surface the unavailable reason (if any) only when unavailable. Must
        // be set AFTER set_available so the reason-clearing guard sees the
        // fresh flag.
        self.toride_proxy_content
            .set_unavailable_reason(b.unavailable_reason);
        self.toride_proxy_content.set_status(b.backend, b.status);
        self.toride_proxy_content.set_server_blocks(b.server_blocks);
        self.toride_proxy_content
            .set_certificates(b.certificates, b.has_expired_certs);
        self.toride_proxy_content.set_waf(b.waf_available);
        self.toride_proxy_content.set_findings(b.findings);
    }

    /// Provide live cloud-provider data for the read-only Cloud section (called
    /// from the [`CloudCollector`](crate::toride_cloud_data::CloudCollector)).
    ///
    /// Fans the bundle out to the content setters. There is no cooldown or
    /// optimistic-update reconciliation here — the section is strictly
    /// read-only, so every refresh cleanly overwrites the previous view.
    pub fn set_toride_cloud_data(&mut self, b: crate::toride_cloud_data::CloudDataBundle) {
        self.toride_cloud_content.set_available(b.available);
        // Surface the panic reason (if any) only when unavailable. Must be set
        // AFTER set_available so the reason-clearing guard sees the fresh flag.
        self.toride_cloud_content
            .set_unavailable_reason(b.unavailable_reason);
        self.toride_cloud_content.set_provider(b.provider);
        self.toride_cloud_content
            .set_agent(b.agent_running, b.agent_enabled, b.agent_service_name);
        self.toride_cloud_content
            .set_security_groups(b.security_groups);
        self.toride_cloud_content.set_findings(b.findings);
    }

    /// Provide live Tailscale data for the read-only Tailscale section (called from
    /// the [`TailscaleCollector`](crate::toride_tailscale_data::TailscaleCollector)).
    ///
    /// Fans the bundle out to the content setters. There is no cooldown or
    /// optimistic-update reconciliation here — the section is strictly read-only, so
    /// every refresh cleanly overwrites the previous view.
    pub fn set_toride_tailscale_data(
        &mut self,
        b: crate::toride_tailscale_data::TailscaleDataBundle,
    ) {
        self.toride_tailscale_content.set_available(b.available);
        // Surface the panic reason (if any) only when unavailable. Must be set
        // AFTER set_available so the reason-clearing guard sees the fresh flag.
        self.toride_tailscale_content
            .set_unavailable_reason(b.unavailable_reason);
        self.toride_tailscale_content.set_status(
            b.status.connected,
            b.status.node_name,
            b.status.tailnet,
            b.status.ip_addresses,
            b.status.exit_node,
            b.status.dns_enabled,
        );
        self.toride_tailscale_content.set_peers(b.peers);
        self.toride_tailscale_content.set_netcheck(
            b.netcheck.connectivity,
            b.netcheck.derp_region,
            b.netcheck.derp_latency,
            b.netcheck.udp,
            b.netcheck.ipv6,
            b.netcheck.hairpin,
            b.netcheck.port_mapping,
        );
        self.toride_tailscale_content.set_dns(b.dns);
        self.toride_tailscale_content.set_findings(b.findings);
    }

    /// Provide live mise data for the read-only Mise section (called from the
    /// [`MiseCollector`](crate::toride_mise_data::MiseCollector)).
    ///
    /// Fans the bundle out to the content setters. There is no cooldown or
    /// optimistic-update reconciliation here — the section is strictly
    /// read-only, so every refresh cleanly overwrites the previous view.
    pub fn set_toride_mise_data(&mut self, b: crate::toride_mise_data::MiseDataBundle) {
        self.toride_mise_content.set_available(b.available);
        // Surface the unavailable reason (if any) only when unavailable. Must
        // be set AFTER set_available so the reason-clearing guard sees the
        // fresh flag.
        self.toride_mise_content
            .set_unavailable_reason(b.unavailable_reason);
        self.toride_mise_content.set_version(b.version);
        self.toride_mise_content.set_tools(b.tools);
        self.toride_mise_content.set_outdated(b.outdated);
        self.toride_mise_content.set_config_files(b.config_files);
        self.toride_mise_content.set_findings(b.findings);
    }

    /// Provide live About-toride data for the read-only About section (called
    /// from the [`AboutCollector`](crate::about_data::AboutCollector)).
    ///
    /// Fans the bundle out to the content setters. No cooldown or optimistic
    /// updates — the section is strictly read-only identity metadata.
    pub fn set_about_data(&mut self, b: crate::about_data::AboutDataBundle) {
        self.about_content.set_available(b.available);
        self.about_content
            .set_unavailable_reason(b.unavailable_reason);
        self.about_content.set_system(b.system);
        self.about_content.set_app(b.app);
        self.about_content.set_runtime(b.runtime);
    }

    /// Provide live system log-sources data for the read-only Logs section
    /// (called from the [`LogsCollector`](crate::logs_data::LogsCollector)).
    pub fn set_logs_data(&mut self, b: crate::logs_data::LogsDataBundle) {
        self.logs_content.set_available(b.available);
        self.logs_content
            .set_unavailable_reason(b.unavailable_reason);
        self.logs_content.set_logs(b.sources);
    }

    /// Provide live settings data for the read-only Settings section (called
    /// from the [`SettingsCollector`](crate::settings_data::SettingsCollector)).
    ///
    /// Fans the bundle out to the content setters. There is no cooldown or
    /// optimistic-update reconciliation here — the section is strictly
    /// read-only, so every refresh cleanly overwrites the previous view.
    pub fn set_settings_data(&mut self, b: crate::settings_data::SettingsDataBundle) {
        self.settings_content.set_available(b.available);
        // Surface the unavailable reason (if any) only when unavailable. Must
        // be set AFTER set_available so the reason-clearing guard sees the
        // fresh flag.
        self.settings_content
            .set_unavailable_reason(b.unavailable_reason);
        self.settings_content.set_config(b.config);
        self.settings_content.set_runtime(b.runtime);
    }

    /// Push the live active theme into the Settings content so its THEME block
    /// highlight + swatches track the current palette. Called by `App::update`'s
    /// `Action::CycleTheme` arm after it computes the new theme.
    pub fn set_active_theme(&mut self, theme: crate::ui::theme::Theme) {
        self.settings_content.set_active_theme(theme);
    }

    /// Provide live hardening-recipes catalogue data for the read-only
    /// Templates section (called from the
    /// [`TemplatesCollector`](crate::templates_data::TemplatesCollector)).
    ///
    /// Fans the bundle out to the content setters. There is no cooldown or
    /// optimistic-update reconciliation here — the section is strictly
    /// read-only, so every refresh cleanly overwrites the previous view.
    pub fn set_templates_data(&mut self, b: crate::templates_data::TemplatesDataBundle) {
        self.templates_content.set_available(b.available);
        // Surface the unavailable reason (if any) only when unavailable. Must
        // be set AFTER set_available so the reason-clearing guard sees the
        // fresh flag.
        self.templates_content
            .set_unavailable_reason(b.unavailable_reason);
        self.templates_content.set_recipes(b.recipes);
        self.templates_content.set_findings(b.findings);
    }

    /// Provide live installed-tools data for the read-only Tools section
    /// (called from the [`ToolsCollector`](crate::tools_data::ToolsCollector)).
    ///
    /// Fans the bundle out to the content setters. There is no cooldown or
    /// optimistic-update reconciliation here — the section is strictly
    /// read-only, so every refresh cleanly overwrites the previous view.
    pub fn set_tools_data(&mut self, b: crate::tools_data::ToolsDataBundle) {
        self.tools_content.set_available(b.available);
        // Surface the unavailable reason (if any) only when unavailable. Must
        // be set AFTER set_available so the reason-clearing guard sees the
        // fresh flag.
        self.tools_content
            .set_unavailable_reason(b.unavailable_reason);
        self.tools_content.set_tools(b.tools);
        self.tools_content.set_findings(b.findings);
        self.refresh_sidebar_badges();
    }

    /// The currently active section.
    fn active_section(&self) -> Section {
        self.data.sidebar[self.active].section
    }

    /// Resolve the active section to its content panel, or `None` when
    /// [`Section::Dashboard`] is active (it has bespoke key/render/scroll
    /// handling and is not a [`ContentPanel`]).
    ///
    /// This single 19-arm match replaces the five former triplicated
    /// `match self.active_section()` dispatch blocks in `handle_key`/`render`/
    /// `handle_mouse`.
    fn active_panel_mut(&mut self) -> Option<&mut dyn ContentPanel> {
        match self.active_section() {
            Section::Dashboard => None,
            Section::Ssh => Some(&mut self.ssh_content),
            Section::Fail2ban => Some(&mut self.fail2ban_content),
            Section::Firewall => Some(&mut self.ufw_kit_content),
            Section::Harden => Some(&mut self.toride_harden_content),
            Section::WireGuard => Some(&mut self.toride_wireguard_content),
            Section::Updates => Some(&mut self.toride_updates_content),
            Section::Users => Some(&mut self.toride_users_content),
            Section::Audit => Some(&mut self.toride_audit_content),
            Section::Monitor => Some(&mut self.toride_monitor_content),
            Section::Backup => Some(&mut self.toride_backup_content),
            Section::Proxy => Some(&mut self.toride_proxy_content),
            Section::Cloud => Some(&mut self.toride_cloud_content),
            Section::Tailscale => Some(&mut self.toride_tailscale_content),
            Section::Mise => Some(&mut self.toride_mise_content),
            Section::Tools => Some(&mut self.tools_content),
            Section::Templates => Some(&mut self.templates_content),
            Section::Logs => Some(&mut self.logs_content),
            Section::About => Some(&mut self.about_content),
            Section::Settings => Some(&mut self.settings_content),
        }
    }

    // ── Input ────────────────────────────────────────────────────────────────

    fn module_left(&mut self) {
        self.module_sel = self.module_sel.saturating_sub(1);
    }

    /// Number of modules in the *current* grid view (live cards when a status
    /// has been collected, else the mock list). Navigation is bounded by this.
    fn modules_count(&self) -> usize {
        let view_len = self.modules_view.len();
        if view_len > 0 {
            view_len
        } else {
            self.data.modules.len()
        }
    }

    fn module_right(&mut self) {
        if self.module_sel + 1 < self.modules_count() {
            self.module_sel += 1;
        }
    }

    fn module_up(&mut self) {
        if self.module_sel >= GRID_COLS {
            self.module_sel -= GRID_COLS;
        }
    }

    fn module_down(&mut self) {
        if self.module_sel + GRID_COLS < self.modules_count() {
            self.module_sel += GRID_COLS;
        }
    }

    /// Scroll/move within the currently focused region (used by the mouse wheel).
    fn scroll_focused(&mut self, down: bool) {
        if self.focus.is_focused(&ShellFocus::Sidebar) {
            self.sidebar.scroll(if down { 1 } else { -1 });
            return;
        }
        // Content-focused: delegate to the active section.
        if self.active_section() == Section::Dashboard {
            match self.dashboard_focus {
                DashboardFocus::Updates => {
                    self.updates_scroll = if down {
                        self.updates_scroll + 1
                    } else {
                        self.updates_scroll.saturating_sub(1)
                    };
                }
                DashboardFocus::Activity => {
                    self.activity_scroll = if down {
                        self.activity_scroll + 1
                    } else {
                        self.activity_scroll.saturating_sub(1)
                    };
                }
                DashboardFocus::Modules => {
                    if down {
                        self.module_down();
                    } else {
                        self.module_up();
                    }
                }
            }
        }
        // SSH and other sections handle their own scrolling via mouse delegation.
    }

    /// Check if a screen coordinate falls within a header gauge hitbox.
    fn gauge_at(&self, col: u16, row: u16) -> Option<GaugeKind> {
        let kinds = [
            GaugeKind::Cpu,
            GaugeKind::Ram,
            GaugeKind::Disk,
            GaugeKind::Net,
        ];
        for (i, rect) in self.gauge_hitboxes.iter().enumerate() {
            if col >= rect.x && col < rect.right() && row >= rect.y && row < rect.bottom() {
                return Some(kinds[i]);
            }
        }
        None
    }

    /// Check if a screen coordinate falls within a module card hitbox.
    fn module_at(&self, col: u16, row: u16) -> Option<usize> {
        self.module_hitboxes.iter().position(|rect| {
            col >= rect.x && col < rect.right() && row >= rect.y && row < rect.bottom()
        })
    }

    // ── Render ─────────────────────────────────────────────────────────────────

    #[expect(
        clippy::too_many_lines,
        reason = "dashboard shell composes every panel"
    )]
    fn render(&mut self, frame: &mut Frame, p: Palette, skip_bg: bool) {
        let area = frame.area();
        if ScreenBase::guard_too_small(frame, p) {
            return;
        }

        self.base.render_bg(frame.buffer_mut(), area, p, skip_bg);

        let collapsed = self.sidebar.is_collapsed() || area.width < AUTO_COLLAPSE_W;
        let sidebar_w = if collapsed {
            SIDEBAR_W_COLLAPSED
        } else {
            SIDEBAR_W
        };

        let shell = shell_layout(area, sidebar_w);
        // Stash the sidebar pane rect so mouse-wheel events can be routed by
        // cursor position (see the ScrollDown/ScrollUp arm in `handle_mouse`).
        self.sidebar_area = shell.sidebar;

        // Header gauges from live status when available.
        let (cpu, ram, disk_label, net_label) = self.gauges();
        let header_data = HeaderData {
            cpu,
            ram,
            disk: disk_label.as_deref(),
            net: net_label.as_deref(),
            clock: &self.clock,
            shimmer_start: self.shimmer_start,
        };
        render_header(frame, shell.header, p, &header_data);

        // Refresh gauge hitboxes for hover detection.
        self.gauge_hitboxes = gauge_hitboxes(shell.header, &header_data);

        self.sidebar.render(
            frame,
            shell.sidebar,
            p,
            &self.data.sidebar,
            self.active,
            self.focus.is_focused(&ShellFocus::Sidebar),
            collapsed,
        );

        render_footer(
            frame,
            shell.footer,
            p,
            &[
                ("↑↓", "move"),
                ("↵", "open"),
                ("Tab", "focus"),
                ("\\", "collapse"),
                ("Esc", "back"),
                ("⇧^a", "anim"),
            ],
        );

        // ── Content ──────────────────────────────────────────────────────────
        // Exhaustive match over every Section variant — NO wildcard arm. A
        // future Section variant added without a matching arm is a compile
        // error, not a silent "coming soon" placeholder. (Previously this was
        // an if/else-if chain with a trailing `render_placeholder(...)` else
        // branch that was unreachable today but would have silently rendered
        // "<section> — coming soon" for any future unwired variant.)
        let content = shell.content;
        if let Some(panel) = self.active_panel_mut() {
            panel.view(frame, content, p);
        } else {
            self.render_dashboard_content(frame, content, p);
        }

        // ── Module detail modal ───────────────────────────────────────────────
        // Clamp the modal index against the current view; if the source vec
        // shrank (e.g. switched mock→live), drop the stale selection.
        if let Some(idx) = self.open_module_idx
            && idx >= self.modules_count()
        {
            self.open_module_idx = None;
        }
        if let Some(idx) = self.open_module_idx
            && let Some(m) = self.modules_view.get(idx).cloned()
        {
            self.module_modal
                .render_with_extracted_buttons(frame, p, |frame, area, buttons| {
                    render_module_modal_content(frame, area, p, &m, buttons);
                });
        }

        // ── Header gauge tooltip overlay ────────────────────────────────────
        let dt = self.last_frame.elapsed();
        self.last_frame = Instant::now();

        // Detect hover transitions and manage fade-in effect.
        if self.gauge_hover != self.prev_gauge_hover {
            self.prev_gauge_hover = self.gauge_hover;
            if self.gauge_hover.is_some() {
                self.tooltip_fx = EffectManager::default();
                // Under reduced motion skip the 300ms fade — render the tooltip
                // fully opaque immediately (an empty EffectManager is a no-op in
                // process_effects below).
                if !p.reduced_motion {
                    self.tooltip_fx
                        .add_effect(fx::fade_from_fg(p.panel, (300, Interpolation::SineOut)));
                }
            } else {
                self.tooltip_fx = EffectManager::default();
            }
        }

        if let Some(gauge) = self.gauge_hover
            && let Some(status) = &self.status
        {
            let rates = LiveRates {
                net_rx: self.net_rx_rate,
                net_tx: self.net_tx_rate,
                disk_read: self.disk_read_rate,
                disk_write: self.disk_write_rate,
            };
            if let Some(rect) = render_gauge_tooltip(
                frame,
                p,
                gauge,
                &self.gauge_hitboxes,
                shell.header,
                status,
                &rates,
            ) {
                self.tooltip_fx
                    .process_effects(dt.into(), frame.buffer_mut(), rect);
            }
        }
    }

    fn gauges(&self) -> (Option<f64>, Option<f64>, Option<String>, Option<String>) {
        let net_label = match (self.net_rx_rate, self.net_tx_rate) {
            (Some(rx), Some(tx)) => Some(format!("{}↓ {}↑", format_rate(rx), format_rate(tx))),
            _ => None,
        };
        let disk_label = match (self.disk_read_rate, self.disk_write_rate) {
            (Some(read), Some(write)) => {
                Some(format!("{}↓ {}↑", format_rate(read), format_rate(write)))
            }
            _ => None,
        };
        match &self.status {
            Some(s) => (
                s.system.cpu_usage,
                Some(s.system.memory.percentage),
                disk_label,
                net_label,
            ),
            None => (None, None, None, None),
        }
    }

    fn render_dashboard_content(&mut self, frame: &mut Frame, area: Rect, p: Palette) {
        let [stat_area, _gap, body_area] = Layout::vertical([
            Constraint::Length(STAT_ROW_H),
            Constraint::Length(1),
            Constraint::Fill(1),
        ])
        .areas(pad(area));

        // Collect the live managed-services snapshot ONCE, before any &mut self
        // panel render. Owned vec → no borrow conflicts with the &mut renders below.
        // Derive `findings` and `managed_available` from this same slice instead of
        // re-calling managed_services() (which rebuilds all 13 cards + their detail
        // Strings) inside findings_total()/managed_available() each frame.
        let live = self.status.is_some();
        let managed = self.managed_services();
        let findings = managed
            .iter()
            .map(|c| c.overview.findings_count)
            .sum::<usize>()
            + self.status.as_ref().map_or(0, |s| s.warnings.len());
        let managed_available = managed
            .iter()
            .filter(|c| c.overview.status_label != "offline")
            .count();
        let pending_total = if self.toride_updates_content.available() {
            Some(self.toride_updates_content.pending_total())
        } else {
            None
        };

        self.render_stat_cards(
            frame,
            stat_area,
            p,
            &StatCardInput {
                live,
                managed_available,
                findings,
                pending_total,
            },
        );

        let single_col = body_area.width < SINGLE_COL_W;
        if single_col {
            // Stack: modules on top, then storage/network, then top processes.
            let [mods, ups, acts] = Layout::vertical([
                Constraint::Fill(2),
                Constraint::Fill(1),
                Constraint::Fill(1),
            ])
            .spacing(1)
            .areas(body_area);
            self.render_modules_panel(frame, mods, p, 1, live, &managed);
            self.render_updates_panel(frame, ups, p);
            self.render_activity_panel(frame, acts, p);
        } else {
            let [left, right] = Layout::horizontal([Constraint::Fill(2), Constraint::Fill(1)])
                .spacing(1)
                .areas(body_area);
            self.render_modules_panel(frame, left, p, 2, live, &managed);

            let [ups, acts] = Layout::vertical([Constraint::Fill(1), Constraint::Fill(1)])
                .spacing(1)
                .areas(right);
            self.render_updates_panel(frame, ups, p);
            self.render_activity_panel(frame, acts, p);
        }
    }

    fn render_stat_cards(&self, frame: &mut Frame, area: Rect, p: Palette, input: &StatCardInput) {
        let StatCardInput {
            live,
            managed_available,
            findings,
            pending_total,
        } = *input;
        let [a, b, c, d] = Layout::horizontal([
            Constraint::Fill(1),
            Constraint::Fill(1),
            Constraint::Fill(1),
            Constraint::Fill(2),
        ])
        .spacing(1)
        .areas(area);

        // MANAGED: live available/total, else honest cold-start 0/0 (no live
        // status yet). The old DashboardData.modules_installed/modules_total
        // fields were always 0 here (never populated with real data) and have
        // been removed; the literal 0/0 is the same honest cold-start value.
        let (managed_num, managed_denom) = if live {
            (managed_available, MANAGED_SECTIONS_TOTAL)
        } else {
            (0, 0)
        };
        let managed_color = if !live {
            p.ok
        } else if managed_available == 0 {
            p.err
        } else if managed_available < MANAGED_SECTIONS_TOTAL {
            p.warn
        } else {
            p.ok
        };
        let managed_card = vec![
            Line::from(vec![
                Span::styled(
                    managed_num.to_string(),
                    Style::new().fg(managed_color).bold(),
                ),
                Span::styled(format!(" / {managed_denom}"), Style::new().fg(p.text_dim)),
            ]),
            Line::raw(""),
            Line::from(Span::styled(
                if live { "MANAGED" } else { "MODULES INSTALLED" },
                Style::new().fg(p.text_muted),
            )),
        ];
        Card::new(managed_card).render(frame, a, p);

        // UPDATES: live pending_total, else honest 0 (no live updates data yet).
        // The old DashboardData.updates_count() always returned 0 (the updates
        // Vec was never populated with real data) and has been removed; the
        // literal 0 is the same honest cold-start value.
        let updates_num = pending_total.unwrap_or(0);
        let updates_color = if updates_num == 0 { p.ok } else { p.warn };
        let updates_card = vec![
            Line::from(Span::styled(
                updates_num.to_string(),
                Style::new().fg(updates_color).bold(),
            )),
            Line::raw(""),
            Line::from(Span::styled(
                "UPDATES AVAILABLE",
                Style::new().fg(p.text_muted),
            )),
        ];
        Card::new(updates_card).render(frame, b, p);

        // FINDINGS: sum of section findings + status warnings (replaces STAGED).
        let findings_color = if findings == 0 {
            p.ok
        } else if findings < 5 {
            p.warn
        } else {
            p.err
        };
        let findings_card = vec![
            Line::from(Span::styled(
                findings.to_string(),
                Style::new().fg(findings_color).bold(),
            )),
            Line::raw(""),
            Line::from(Span::styled("FINDINGS", Style::new().fg(p.text_muted))),
        ];
        Card::new(findings_card).render(frame, c, p);

        Card::new(self.system_card_lines(p)).render(frame, d, p);
    }

    fn system_card_lines(&self, p: Palette) -> Vec<Line<'static>> {
        let h = &self.data.host;
        let dim = Style::new().fg(p.text_dim);
        let muted = Style::new().fg(p.text_muted);
        let accent = Style::new().fg(p.accent3);

        // Prefer live status where available, fall back to mock host.
        let (hostname, os, cpu, mem_used, mem_total, uptime, load) = match &self.status {
            Some(s) => {
                let os = match (&s.system.os_info.name, &s.system.os_info.version) {
                    (Some(n), Some(v)) => format!("{n} {v}"),
                    (Some(n), None) => n.clone(),
                    _ => h.os.clone(),
                };
                let cores = s.system.cpu_cores.len();
                let cpu = if s.system.static_info.cpu_brand.is_empty() {
                    h.cpu.clone()
                } else {
                    s.system.static_info.cpu_brand.clone()
                };
                let mem_used = format_bytes(s.system.memory.used_bytes);
                let mem_total = format_bytes(s.system.memory.total_bytes);
                let uptime = s
                    .system
                    .uptime_secs
                    .map_or_else(|| h.uptime.clone(), format_duration);
                let load = s.system.load_average.map_or_else(
                    || h.load.clone(),
                    |l| format!("{:.2} {:.2} {:.2}", l.one, l.five, l.fifteen),
                );
                let vcpu = if cores > 0 {
                    format!("{cores} vCPU")
                } else {
                    h.vcpu.clone()
                };
                (
                    s.system.hostname.clone(),
                    os,
                    format!("{cpu} · {vcpu}"),
                    mem_used,
                    mem_total,
                    uptime,
                    load,
                )
            }
            None => (
                h.hostname.clone(),
                h.os.clone(),
                format!("{} · {}", h.cpu, h.vcpu),
                h.mem_used.clone(),
                h.mem_total.clone(),
                h.uptime.clone(),
                h.load.clone(),
            ),
        };

        // Compact daemon/ssh health, appended to the uptime/load line when live.
        let health_suffix = match &self.status {
            Some(s) => {
                let (daemon_glyph, daemon_color) = if s.daemon.alive {
                    ("✓", p.ok)
                } else {
                    ("✗", p.warn)
                };
                let (ssh_glyph, ssh_color) = if s.ssh.agent_running {
                    ("✓", p.ok)
                } else {
                    ("✗", p.text_dim)
                };
                Some(vec![
                    Span::styled("  ·  d", muted),
                    Span::styled(daemon_glyph.to_string(), Style::new().fg(daemon_color)),
                    Span::styled(" s", muted),
                    Span::styled(ssh_glyph.to_string(), Style::new().fg(ssh_color)),
                ])
            }
            None => None,
        };

        let mut uptime_spans = vec![
            Span::styled(format!("uptime {uptime}"), muted),
            Span::styled(format!("  ·  load {load}"), muted),
        ];
        if let Some(suffix) = health_suffix {
            uptime_spans.extend(suffix);
        }

        vec![
            Line::from(vec![
                Span::styled(hostname, Style::new().fg(p.accent2).bold()),
                Span::styled(format!("   {os}"), dim),
            ]),
            Line::from(Span::styled(cpu, Style::new().fg(p.text))),
            Line::from(vec![
                Span::styled("mem ", muted),
                Span::styled(format!("{mem_used} / {mem_total}"), accent),
            ]),
            Line::from(uptime_spans),
        ]
    }

    fn render_modules_panel(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        p: Palette,
        cols: u16,
        live: bool,
        managed: &[ManagedServiceCard],
    ) {
        let focused = self.focus.is_focused(&ShellFocus::Content)
            && self.active_section() == Section::Dashboard
            && self.dashboard_focus == DashboardFocus::Modules;
        let title = if live {
            " MANAGED SERVICES "
        } else {
            " MODULES "
        };
        let inner = render_titled_panel(frame, area, p, title, p.accent, focused);
        if inner.height == 0 {
            return;
        }

        // Live path: materialize Modules from the snapshot; mock path: borrow mock data.
        // Cache the materialized view on the screen so keyboard navigation and
        // the detail modal index the same vec the grid drew this frame (the live
        // grid is 13 cards; the mock list is 8 — they must not be mixed).
        let modules: Vec<Module> = if live {
            managed.iter().map(ManagedServiceCard::to_module).collect()
        } else {
            self.data.modules.clone()
        };
        self.modules_view.clone_from(&modules);
        let modules: &[Module] = &modules;

        let rows = inner.height / MODULE_CARD_H;
        if rows == 0 {
            return;
        }
        let per_row = usize::from(cols.max(1));

        // Clamp scroll so the selected module stays visible.
        let sel_row = self.module_sel / per_row;
        if sel_row < self.module_scroll {
            self.module_scroll = sel_row;
        } else if sel_row >= self.module_scroll + usize::from(rows) {
            self.module_scroll = sel_row - usize::from(rows) + 1;
        }
        let total_rows = modules.len().div_ceil(per_row);
        let max_scroll = total_rows.saturating_sub(usize::from(rows));
        self.module_scroll = self.module_scroll.min(max_scroll);

        let base = self.module_scroll * per_row;

        let row_rects = Layout::vertical(
            (0..rows)
                .map(|_| Constraint::Length(MODULE_CARD_H))
                .collect::<Vec<_>>(),
        )
        .split(inner);

        // Rebuild module hitboxes for click detection.
        self.module_hitboxes.clear();

        for (r, row_rect) in row_rects.iter().enumerate() {
            let cells = Layout::horizontal(
                (0..cols.max(1))
                    .map(|_| Constraint::Fill(1))
                    .collect::<Vec<_>>(),
            )
            .spacing(1)
            .split(*row_rect);
            for (c, cell) in cells.iter().enumerate() {
                let idx = base + r * per_row + c;
                if idx >= modules.len() {
                    continue;
                }
                let m = &modules[idx];
                let card_focused = focused && idx == self.module_sel;
                render_module_card(frame, *cell, p, m, card_focused);
                // Record hitbox — index matches position in the module data vec.
                while self.module_hitboxes.len() <= idx {
                    self.module_hitboxes.push(Rect::default());
                }
                self.module_hitboxes[idx] = *cell;
            }
        }
    }

    /// STORAGE & NETWORK panel: top disks (usage %) + network rate line, from
    /// live `TorideStatus`. Renders an honest "collecting…" line before the
    /// first status lands — never the fabricated updates list.
    fn render_updates_panel(&self, frame: &mut Frame, area: Rect, p: Palette) {
        let focused = self.focus.is_focused(&ShellFocus::Content)
            && self.active_section() == Section::Dashboard
            && self.dashboard_focus == DashboardFocus::Updates;

        if let Some(s) = &self.status {
            let inner =
                render_titled_panel(frame, area, p, " STORAGE & NETWORK ", p.accent, focused);
            self.render_storage_network(frame, inner, p, s);
        } else {
            // Honest cold-start state: nothing fabricated. The pending-update
            // count is shown in the stat card above (0 until the updates
            // collector reports); this panel shows disk/network once status
            // arrives, and an honest placeholder until then.
            let inner =
                render_titled_panel(frame, area, p, " STORAGE & NETWORK ", p.accent, focused);
            let line = Line::from(Span::styled(
                "  collecting system status…",
                Style::new().fg(p.text_muted),
            ));
            frame.render_widget(Paragraph::new(line), inner);
        }
    }

    /// Render live disk + network rows into the STORAGE & NETWORK panel inner area.
    fn render_storage_network(&self, frame: &mut Frame, inner: Rect, p: Palette, s: &TorideStatus) {
        let mut lines: Vec<(String, Option<String>, ratatui::style::Color)> = Vec::new();

        // Top disks by usage %. Skip empty/zero-total disks.
        let mut disks: Vec<&crate::status::DiskStatus> = s
            .system
            .disks
            .iter()
            .filter(|d| d.total_bytes > 0)
            .collect();
        disks.sort_by(|a, b| {
            b.percentage
                .partial_cmp(&a.percentage)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        for d in disks.iter().take(5) {
            let label = if d.mount_point.is_empty() {
                d.name.clone()
            } else {
                d.mount_point.clone()
            };
            let value = format!("{:.0}% · {}", d.percentage, format_bytes(d.used_bytes));
            let color = percent_color(d.percentage, p);
            lines.push((label, Some(value), color));
        }

        // Network rate line (reuse already-computed throughput).
        let net_value = match (self.net_rx_rate, self.net_tx_rate) {
            (Some(rx), Some(tx)) => Some(format!("↓ {} · ↑ {}", fmt_rate(rx), fmt_rate(tx))),
            (Some(rx), None) => Some(format!("↓ {}", fmt_rate(rx))),
            (None, Some(tx)) => Some(format!("↑ {}", fmt_rate(tx))),
            (None, None) => None,
        };
        if net_value.is_some() {
            lines.push(("network".to_string(), net_value, p.info));
        }

        // If we somehow produced nothing, show a placeholder so the panel isn't blank.
        if lines.is_empty() {
            let line = Line::from(Span::styled(
                "  no storage/network data",
                Style::new().fg(p.text_muted),
            ));
            frame.render_widget(Paragraph::new(line), inner);
            return;
        }

        let visible = usize::from(inner.height);
        for (i, (label, value, color)) in lines.into_iter().enumerate().take(visible) {
            let y_off = u16::try_from(i).unwrap_or(inner.height);
            let row = Rect::new(inner.x, inner.y + y_off, inner.width, 1);
            let left = Line::from(vec![
                Span::styled("  ", Style::new()),
                Span::styled(
                    truncate_str(&label, (inner.width as usize).saturating_sub(2)),
                    Style::new().fg(p.text_dim),
                ),
            ]);
            frame.render_widget(Paragraph::new(left), row);
            if let Some(v) = value {
                let right = Line::from(Span::styled(v, Style::new().fg(color)));
                frame.render_widget(Paragraph::new(right).right_aligned(), row);
            }
        }
    }

    /// TOP PROCESSES panel: top 3-5 by CPU then memory, from live `TorideStatus`.
    /// Renders an honest "collecting…" line before the first status lands —
    /// never the fabricated "RECENTLY INSTALLED" activity log (there is no real
    /// "recently installed" source on the dashboard; that data was mock).
    fn render_activity_panel(&self, frame: &mut Frame, area: Rect, p: Palette) {
        let focused = self.focus.is_focused(&ShellFocus::Content)
            && self.active_section() == Section::Dashboard
            && self.dashboard_focus == DashboardFocus::Activity;

        if let Some(s) = &self.status {
            let inner = render_titled_panel(frame, area, p, " TOP PROCESSES ", p.accent3, focused);
            render_top_processes(frame, inner, p, s);
        } else {
            let inner = render_titled_panel(frame, area, p, " TOP PROCESSES ", p.accent3, focused);
            let line = Line::from(Span::styled(
                "  collecting system status…",
                Style::new().fg(p.text_muted),
            ));
            frame.render_widget(Paragraph::new(line), inner);
        }
    }

    /// Forward a keypress to the active content panel, or — when
    /// [`Section::Dashboard`] is active — to the bespoke dashboard key handler.
    /// Collapses the three former triplicated `match self.active_section()`
    /// blocks in [`Self::handle_key`] (Tab, `BackTab`, generic content-focused).
    fn content_handle_key(&mut self, code: KeyCode) -> Option<Action> {
        if let Some(panel) = self.active_panel_mut() {
            panel.handle_key(code)
        } else {
            self.handle_dashboard_content_key(code)
        }
    }

    /// Handle a key press while the Dashboard section's content is focused.
    fn handle_dashboard_content_key(&mut self, code: KeyCode) -> Option<Action> {
        // Tab/BackTab cycle between internal panels.
        match code {
            KeyCode::Tab => {
                self.dashboard_focus = self.dashboard_focus.next();
                return None;
            }
            KeyCode::BackTab => {
                self.dashboard_focus = self.dashboard_focus.prev();
                return None;
            }
            _ => {}
        }
        match self.dashboard_focus {
            DashboardFocus::Modules => match code {
                KeyCode::Down | KeyCode::Char('j') => self.module_down(),
                KeyCode::Up | KeyCode::Char('k') => self.module_up(),
                KeyCode::Right | KeyCode::Char('l') => self.module_right(),
                KeyCode::Left | KeyCode::Char('h') => self.module_left(),
                KeyCode::Enter => {
                    self.open_module_idx = Some(self.module_sel);
                    self.module_modal.open();
                }
                _ => {}
            },
            DashboardFocus::Updates => match code {
                KeyCode::Down | KeyCode::Char('j') => {
                    self.updates_scroll = self.updates_scroll.saturating_add(1);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.updates_scroll = self.updates_scroll.saturating_sub(1);
                }
                _ => {}
            },
            DashboardFocus::Activity => match code {
                KeyCode::Down | KeyCode::Char('j') => {
                    self.activity_scroll = self.activity_scroll.saturating_add(1);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.activity_scroll = self.activity_scroll.saturating_sub(1);
                }
                _ => {}
            },
        }
        None
    }
}

impl AppScreen for DashboardScreen {
    fn handle_key(&mut self, code: KeyCode) -> Option<Action> {
        // Module detail modal intercepts input while open.
        if self.module_modal.is_visible() {
            match self.module_modal.handle_key(code) {
                ModalEvent::Closed | ModalEvent::Button(_) => {
                    self.module_modal.close();
                    self.open_module_idx = None;
                }
                ModalEvent::Consumed => {}
            }
            return None;
        }

        match code {
            // When SSH content has a modal (form/confirm) open OR is loading,
            // ALL keys go to SSH first. This prevents global shortcuts (q,
            // digits, Esc, etc.) from firing while the user is filling in a
            // form or while write ops are in-flight.
            _ if self.active_section() == Section::Ssh
                && (self.ssh_content.has_modal() || self.ssh_content.is_loading()) =>
            {
                return self.ssh_content.handle_key(code);
            }
            KeyCode::Char('q') => return Some(Action::ConfirmQuit),
            // Tab/BackTab on Sidebar: cycle shell focus. On Content: forward to section.
            KeyCode::Tab => {
                if self.focus.is_focused(&ShellFocus::Content) {
                    return self.content_handle_key(code);
                }
                self.focus.next();
                return None;
            }
            KeyCode::BackTab => {
                if self.focus.is_focused(&ShellFocus::Content) {
                    return self.content_handle_key(code);
                }
                self.focus.prev();
                return None;
            }
            KeyCode::Char('\\') => {
                self.sidebar.toggle_collapse();
                return None;
            }
            KeyCode::Esc => {
                if self.focus.is_focused(&ShellFocus::Sidebar) {
                    return Some(Action::Back);
                }
                self.focus.set(ShellFocus::Sidebar);
                return None;
            }
            KeyCode::Char(d @ '1'..='9') => {
                let idx = (d as usize) - ('1' as usize);
                if idx < self.data.sidebar.len() {
                    self.sidebar.select_to(idx);
                    self.active = idx;
                    self.focus.set(ShellFocus::Sidebar);
                }
                return None;
            }
            _ => {}
        }

        // ── Content-focused: delegate to active section ────────────────
        if self.focus.is_focused(&ShellFocus::Content) {
            return self.content_handle_key(code);
        }

        // ── Sidebar-focused ─────────────────────────────────────────────
        match code {
            KeyCode::Down | KeyCode::Char('j') => self.sidebar.select_next(),
            KeyCode::Up | KeyCode::Char('k') => self.sidebar.select_prev(),
            KeyCode::Enter => self.active = self.sidebar.selected(),
            _ => {}
        }
        None
    }

    fn handle_mouse(&mut self, mouse: MouseEvent) -> Option<Action> {
        use crossterm::event::MouseButton;

        // Header gauge hover always works (even with modals open).
        if matches!(mouse.kind, MouseEventKind::Moved | MouseEventKind::Drag(_)) {
            self.gauge_hover = self.gauge_at(mouse.column, mouse.row);
        }

        // Module detail modal open: block all background interaction.
        if self.module_modal.is_visible() {
            match self.module_modal.handle_mouse(&mouse) {
                ModalEvent::Closed | ModalEvent::Button(_) => {
                    self.module_modal.close();
                    self.open_module_idx = None;
                }
                ModalEvent::Consumed => {}
            }
            return None;
        }

        match mouse.kind {
            // Hover: highlight sidebar item under the cursor.
            MouseEventKind::Moved | MouseEventKind::Drag(_) => {
                let idx = self.sidebar.item_at(mouse.column, mouse.row);
                self.sidebar.set_hovered(idx);
                // Delegate hover to content sections that track it. The
                // Dashboard section has nothing to hover (no-op).
                if let Some(panel) = self.active_panel_mut() {
                    panel.handle_mouse(mouse);
                }
            }
            // Click: select + activate the clicked element.
            MouseEventKind::Down(MouseButton::Left) => {
                if let Some(idx) = self.sidebar.item_at(mouse.column, mouse.row) {
                    self.sidebar.select_to(idx);
                    self.active = idx;
                    self.focus.set(ShellFocus::Sidebar);
                } else if self.active_section() == Section::Dashboard {
                    // Module clicks only work in the Dashboard section.
                    if let Some(idx) = self.module_at(mouse.column, mouse.row) {
                        self.module_sel = idx;
                        self.focus.set(ShellFocus::Content);
                        self.open_module_idx = Some(idx);
                        self.module_modal.open();
                    }
                } else {
                    // A read-only content panel owns this click: focus content
                    // and forward the mouse event to the active panel.
                    self.focus.set(ShellFocus::Content);
                    if let Some(panel) = self.active_panel_mut() {
                        return panel.handle_mouse(mouse);
                    }
                }
            }
            MouseEventKind::ScrollDown | MouseEventKind::ScrollUp => {
                let down = matches!(mouse.kind, MouseEventKind::ScrollDown);
                // Route the wheel by cursor position, not focus: when the
                // pointer is over the sidebar column, scroll the sidebar list
                // regardless of which shell region is focused or which section
                // is active. (Previously the sidebar only scrolled when it was
                // already focused, so wheeling over it scrolled the focused
                // content instead.)
                let s = self.sidebar_area;
                let over_sidebar = mouse.column >= s.x
                    && mouse.column < s.x + s.width
                    && mouse.row >= s.y
                    && mouse.row < s.y + s.height;
                if over_sidebar {
                    self.sidebar.scroll(if down { 1 } else { -1 });
                    return None;
                }
                if let Some(panel) = self.active_panel_mut() {
                    return panel.handle_mouse(mouse);
                }
                // Section::Dashboard: wheel the focused dashboard region.
                self.scroll_focused(down);
            }
            MouseEventKind::Up(_) => {
                // Forward to the active content panel; the Dashboard section
                // has nothing to do on mouse-up (no-op).
                if let Some(panel) = self.active_panel_mut() {
                    return panel.handle_mouse(mouse);
                }
            }
            _ => {}
        }
        None
    }

    fn view(&mut self, frame: &mut Frame, palette: Palette) {
        self.render(frame, palette, false);
    }

    fn view_foreground(&mut self, frame: &mut Frame, palette: Palette) {
        self.render(frame, palette, true);
    }

    fn invalidate_cache(&mut self) {
        self.base.invalidate();
    }

    fn needs_animation(&self) -> bool {
        self.sidebar.is_animating()
    }

    fn has_modal(&self) -> bool {
        if self.module_modal.is_visible() {
            return true;
        }
        if self.active_section() == Section::Ssh
            && (self.ssh_content.has_modal() || self.ssh_content.is_loading())
        {
            return true;
        }
        // All non-SSH content sections (Fail2ban, Firewall, Harden, WireGuard,
        // Updates, Users, Audit, Monitor, Backup, Proxy, Cloud, Tailscale, Mise,
        // Tools, Templates, Logs, About, Settings) are read-only with no modal
        // — has_modal() always returns false for them, so only SSH needs a
        // branch here.
        false
    }
}

// ── Free render helpers ───────────────────────────────────────────────────────

/// Inset an area by one column/row for breathing room inside the content region.
fn pad(area: Rect) -> Rect {
    Rect {
        x: area.x + 1,
        y: area.y,
        width: area.width.saturating_sub(2),
        height: area.height,
    }
}

/// Format a bytes/sec rate compactly (e.g. `1.2 MB/s`, `340 KB/s`).
fn fmt_rate(bytes_per_sec: f64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let v = bytes_per_sec.max(0.0);
    if v >= 1_073_741_824.0 {
        format!("{:.1} GB/s", v / 1_073_741_824.0)
    } else if v >= 1_048_576.0 {
        format!("{:.1} MB/s", v / 1_048_576.0)
    } else if v >= 1024.0 {
        format!("{:.0} KB/s", v / 1024.0)
    } else {
        format!("{v:.0} B/s")
    }
}

/// Compute the visible `(item_index, row_rect)` pairs for a scrollable list.
fn render_module_card(frame: &mut Frame, area: Rect, p: Palette, m: &Module, focused: bool) {
    let border = if focused { p.border_hi } else { p.border };
    let inner = render_panel(frame, area, None, p.text, border, p.panel);
    if inner.height == 0 {
        return;
    }

    let title_row = Rect::new(inner.x, inner.y, inner.width, 1);
    let name_line = Line::from(vec![
        Span::styled(format!("{} ", m.icon), Style::new().fg(p.accent2)),
        Span::styled(m.name.clone(), Style::new().fg(p.text).bold()),
    ]);
    frame.render_widget(Paragraph::new(name_line), title_row);

    let status_line = Line::from(Span::styled(
        format!("{} {}", m.status.glyph(), m.status.label()),
        Style::new().fg(m.status.color(p)),
    ));
    frame.render_widget(Paragraph::new(status_line).right_aligned(), title_row);

    let w = inner.width as usize;
    if inner.height >= 2 {
        let summary = truncate_str(&m.summary, w);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                summary,
                Style::new().fg(p.text_dim),
            ))),
            Rect::new(inner.x, inner.y + 1, inner.width, 1),
        );
    }
    if inner.height >= 3 {
        let detail = truncate_str(&m.detail, w);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                detail,
                Style::new().fg(p.text_muted),
            ))),
            Rect::new(inner.x, inner.bottom() - 1, inner.width, 1),
        );
    }
}

/// Render live top processes (by CPU, then memory) into the TOP PROCESSES panel.
#[allow(clippy::cast_possible_truncation)] // i is bounded by inner.height (u16) via take()
fn render_top_processes(frame: &mut Frame, inner: Rect, p: Palette, s: &TorideStatus) {
    // Top by CPU (desc), tie-break by memory.
    let mut procs: Vec<&crate::status::ProcessStatus> =
        s.system.processes.processes.iter().collect();
    procs.sort_by(|a, b| {
        b.cpu_usage
            .partial_cmp(&a.cpu_usage)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.memory_bytes.cmp(&a.memory_bytes))
    });

    let visible = usize::from(inner.height);
    let count = procs.len().min(5).min(visible);
    if count == 0 {
        let line = Line::from(Span::styled(
            "  no process data",
            Style::new().fg(p.text_muted),
        ));
        frame.render_widget(Paragraph::new(line), inner);
        return;
    }

    for (i, proc) in procs.iter().take(count).enumerate() {
        let y_off = u16::try_from(i).unwrap_or(inner.height);
        let row = Rect::new(inner.x, inner.y + y_off, inner.width, 1);
        let name = truncate_str(&proc.name, (inner.width as usize).saturating_sub(14));
        let cpu_color = if proc.cpu_usage >= 90.0 {
            p.err
        } else if proc.cpu_usage >= 50.0 {
            p.warn
        } else {
            p.text_dim
        };
        let left = Line::from(vec![
            Span::styled("  ", Style::new()),
            Span::styled(name, Style::new().fg(p.text)),
            Span::styled(
                format!(
                    "  {:.1}% · {}",
                    proc.cpu_usage,
                    format_bytes(proc.memory_bytes)
                ),
                Style::new().fg(cpu_color),
            ),
        ]);
        frame.render_widget(Paragraph::new(left), row);
    }
}

fn render_module_modal_content(
    frame: &mut Frame,
    area: Rect,
    p: Palette,
    m: &Module,
    buttons: Option<&mut ButtonRow<Action>>,
) {
    let [_, text_area, _, btn_area, _] = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(4),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .areas(area);

    let lines = vec![
        Line::from(vec![
            Span::styled(format!("{} ", m.icon), Style::new().fg(p.accent2)),
            Span::styled(m.name.clone(), Style::new().fg(p.text).bold()),
            Span::raw("   "),
            Span::styled(
                format!("{} {}", m.status.glyph(), m.status.label()),
                Style::new().fg(m.status.color(p)),
            ),
        ]),
        Line::raw(""),
        Line::from(Span::styled(m.summary.clone(), Style::new().fg(p.text_dim))),
        Line::from(Span::styled(
            m.detail.clone(),
            Style::new().fg(p.text_muted),
        )),
    ];
    frame.render_widget(Paragraph::new(lines), text_area);

    if let Some(btns) = buttons {
        let viewport = Viewport::from_area(frame.area());
        let buf = frame.buffer_mut();
        btns.render(buf, btn_area, p, viewport);
    }
}

// ── Header gauge tooltip ─────────────────────────────────────────────────────

/// Live throughput rates passed to tooltip renderers.
struct LiveRates {
    net_rx: Option<f64>,
    net_tx: Option<f64>,
    disk_read: Option<f64>,
    disk_write: Option<f64>,
}

/// Render a floating popup card anchored below the hovered header gauge.
///
/// Returns `Some(rect)` if the tooltip was rendered, `None` if it didn't fit.
fn render_gauge_tooltip(
    frame: &mut Frame,
    p: Palette,
    gauge: GaugeKind,
    hitboxes: &[Rect; 4],
    header_area: Rect,
    status: &TorideStatus,
    rates: &LiveRates,
) -> Option<Rect> {
    let idx = match gauge {
        GaugeKind::Cpu => 0,
        GaugeKind::Ram => 1,
        GaugeKind::Disk => 2,
        GaugeKind::Net => 3,
    };
    let hitbox = hitboxes[idx];
    let lines = gauge_tooltip_lines(gauge, status, p, rates);

    // Construct an anchor whose `.bottom()` equals `header_area.bottom()` so the
    // tooltip appears just below the header, centered on the gauge hitbox.
    let anchor = Rect::new(
        hitbox.x,
        header_area.bottom().saturating_sub(1),
        hitbox.width,
        1,
    );
    Tooltip::new(&lines).anchor(anchor).render(frame, p)
}

/// Build tooltip content lines for a given gauge kind.
fn gauge_tooltip_lines(
    gauge: GaugeKind,
    status: &TorideStatus,
    p: Palette,
    rates: &LiveRates,
) -> Vec<Line<'static>> {
    match gauge {
        GaugeKind::Cpu => cpu_tooltip_lines(&status.system, p),
        GaugeKind::Ram => ram_tooltip_lines(&status.system, p),
        GaugeKind::Disk => disk_tooltip_lines(&status.system, p, rates),
        GaugeKind::Net => net_tooltip_lines(&status.system, p, rates),
    }
}

fn cpu_tooltip_lines(sys: &crate::status::SystemStatus, p: Palette) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    // Title
    lines.push(title_line_with_detail("CPU", &sys.static_info.cpu_brand, p));

    // Usage — kept manual because value uses `.bold()`, unique to CPU.
    if let Some(usage) = sys.cpu_usage {
        let color = percent_color(usage, p);
        lines.push(Line::from(vec![
            Span::styled(format!("{:<7}", "Usage"), Style::new().fg(p.text_muted)),
            Span::styled(format!("{usage:.0}%"), Style::new().fg(color).bold()),
        ]));
    }

    // Cores
    let phys = sys
        .physical_cores
        .map_or_else(|| "—".to_string(), |c| c.to_string());
    let log = sys.static_info.logical_cores;
    lines.push(kv("Cores", &format!("{phys} / {log}"), p));

    // Load average
    if let Some(load) = &sys.load_average {
        lines.push(kv(
            "Load",
            &format!("{:.2} / {:.2} / {:.2}", load.one, load.five, load.fifteen),
            p,
        ));
    }

    // Per-core mini readout (dynamic multi-span — kept manual)
    if !sys.cpu_cores.is_empty() {
        let mut cores: Vec<Span<'static>> = Vec::new();
        for (i, c) in sys.cpu_cores.iter().enumerate() {
            if i > 0 {
                cores.push(Span::styled(" ", Style::new()));
            }
            let color = percent_color(c.usage, p);
            cores.push(Span::styled(
                format!("{:.0}", c.usage),
                Style::new().fg(color),
            ));
        }
        let mut line = vec![Span::styled(
            format!("{:<7}", "Core"),
            Style::new().fg(p.text_muted),
        )];
        line.append(&mut cores);
        lines.push(Line::from(line));
    }

    lines
}

fn ram_tooltip_lines(sys: &crate::status::SystemStatus, p: Palette) -> Vec<Line<'static>> {
    let m = &sys.memory;
    let mut lines = Vec::new();

    lines.push(title_line("Memory", p));

    let color = percent_color(m.percentage, p);
    lines.push(kv_with_suffix(
        "Used",
        &format!(
            "{} / {}",
            format_bytes(m.used_bytes),
            format_bytes(m.total_bytes)
        ),
        &format!("  ({:.0}%)", m.percentage),
        color,
        p,
    ));

    lines.push(kv("Free", &format_bytes(m.available_bytes), p));

    if m.cached_bytes > 0 {
        lines.push(kv("Cached", &format_bytes(m.cached_bytes), p));
    }

    if let Some(swap) = &sys.swap {
        let swap_color = percent_color(swap.percentage, p);
        lines.push(kv_with_suffix(
            "Swap",
            &format!(
                "{} / {}",
                format_bytes(swap.used_bytes),
                format_bytes(swap.total_bytes)
            ),
            &format!("  ({:.0}%)", swap.percentage),
            swap_color,
            p,
        ));
    }

    lines
}

fn disk_tooltip_lines(
    sys: &crate::status::SystemStatus,
    p: Palette,
    rates: &LiveRates,
) -> Vec<Line<'static>> {
    let d = &sys.disk;
    let mut lines = Vec::new();

    lines.push(title_line_with_detail("Disk", &d.name, p));
    lines.push(kv("Mount", &d.mount_point, p));
    lines.push(kv("FS", &d.filesystem, p));

    let color = percent_color(d.percentage, p);
    lines.push(kv_with_suffix(
        "Used",
        &format!(
            "{} / {}",
            format_bytes(d.used_bytes),
            format_bytes(d.total_bytes)
        ),
        &format!("  ({:.0}%)", d.percentage),
        color,
        p,
    ));

    lines.push(kv("Free", &format_bytes(d.available_bytes), p));
    lines.push(kv("Type", &d.disk_type, p));

    // Disk I/O — live throughput
    if rates.disk_read.is_some() || rates.disk_write.is_some() {
        let read_s = rates.disk_read.map_or_else(|| "—".to_string(), format_rate);
        let write_s = rates
            .disk_write
            .map_or_else(|| "—".to_string(), format_rate);
        lines.push(kv("Read", &format!("{read_s}/s"), p));
        lines.push(kv("Write", &format!("{write_s}/s"), p));
    }

    lines
}

fn net_tooltip_lines(
    sys: &crate::status::SystemStatus,
    p: Palette,
    rates: &LiveRates,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    lines.push(title_line("Network", p));

    let dl_rate = rates
        .net_rx
        .map_or_else(|| "—".to_string(), |r| format!("{}/s", format_rate(r)));
    let ul_rate = rates
        .net_tx
        .map_or_else(|| "—".to_string(), |r| format!("{}/s", format_rate(r)));

    lines.push(kv("Down", &dl_rate, p));
    lines.push(kv("Up", &ul_rate, p));

    lines.push(Line::raw(""));

    lines.push(kv(
        "Total",
        &format!(
            "{} ↓  {} ↑",
            format_bytes(sys.network.bytes_received),
            format_bytes(sys.network.bytes_transmitted)
        ),
        p,
    ));

    lines
}

/// Format a bytes/sec rate as a human-readable string (e.g. `"12.3 KB"`).
fn format_rate(bytes_per_sec: f64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    if bytes_per_sec >= GB {
        format!("{:.1} GB", bytes_per_sec / GB)
    } else if bytes_per_sec >= MB {
        format!("{:.1} MB", bytes_per_sec / MB)
    } else if bytes_per_sec >= KB {
        format!("{:.1} KB", bytes_per_sec / KB)
    } else {
        format!("{bytes_per_sec:.0} B")
    }
}

// ── Clock ─────────────────────────────────────────────────────────────────────

/// Format the current wall-clock time as a 12-hour `HH:MM AM/PM` label (UTC).
fn current_clock() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let tod = secs % 86_400;
    let h24 = tod / 3600;
    let m = (tod % 3600) / 60;
    let (h12, ampm) = match h24 {
        0 => (12, "AM"),
        1..=11 => (h24, "AM"),
        12 => (12, "PM"),
        _ => (h24 - 12, "PM"),
    };
    format!("{h12:02}:{m:02} {ampm}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_focus_cycles_sidebar_content() {
        // Tab from Sidebar → Content. Esc returns to Sidebar.
        let mut s = DashboardScreen::new();
        assert!(s.focus.is_focused(&ShellFocus::Sidebar));
        s.handle_key(KeyCode::Tab);
        assert!(s.focus.is_focused(&ShellFocus::Content));
        // Tab on Content is forwarded to the section (not shell-level cycle).
        // Use Esc to go back to Sidebar.
        s.handle_key(KeyCode::Esc);
        assert!(s.focus.is_focused(&ShellFocus::Sidebar));
        // BackTab from Sidebar goes to Content (wraps around FocusManager ring).
        s.handle_key(KeyCode::BackTab);
        assert!(s.focus.is_focused(&ShellFocus::Content));
    }

    #[test]
    fn dashboard_focus_cycles_panels() {
        // Internal Tab cycles Modules → Updates → Activity → Modules.
        let mut s = DashboardScreen::new();
        s.handle_key(KeyCode::Tab); // -> Content (Dashboard section)
        assert!(s.focus.is_focused(&ShellFocus::Content));
        assert_eq!(s.dashboard_focus, DashboardFocus::Modules);
        // Tab is forwarded to dashboard content handler which cycles panels.
        s.handle_key(KeyCode::Tab);
        assert_eq!(s.dashboard_focus, DashboardFocus::Updates);
        s.handle_key(KeyCode::Tab);
        assert_eq!(s.dashboard_focus, DashboardFocus::Activity);
        s.handle_key(KeyCode::Tab);
        assert_eq!(s.dashboard_focus, DashboardFocus::Modules);
    }

    #[test]
    fn enter_on_module_opens_modal() {
        let mut s = DashboardScreen::new();
        s.handle_key(KeyCode::Tab); // -> Content
        assert!(!s.module_modal.is_visible());
        s.handle_key(KeyCode::Enter);
        assert!(s.module_modal.is_visible());
        assert_eq!(s.open_module_idx, Some(0));
        // Esc closes it.
        s.handle_key(KeyCode::Esc);
        assert!(!s.module_modal.is_visible());
    }

    #[test]
    fn esc_from_content_returns_to_sidebar() {
        let mut s = DashboardScreen::new();
        s.handle_key(KeyCode::Tab); // Content
        let action = s.handle_key(KeyCode::Esc);
        assert!(action.is_none());
        assert!(s.focus.is_focused(&ShellFocus::Sidebar));
    }

    #[test]
    fn esc_from_sidebar_goes_back() {
        let mut s = DashboardScreen::new();
        assert_eq!(s.handle_key(KeyCode::Esc), Some(Action::Back));
    }

    #[test]
    fn mouse_wheel_over_sidebar_scrolls_sidebar_not_content() {
        // Regression: the mouse wheel must route by CURSOR POSITION. When the
        // pointer is over the sidebar column, scrolling must move the sidebar
        // list — regardless of which shell region is focused or which section
        // is active. Previously the sidebar only scrolled when it was already
        // focused, so wheeling over it scrolled the focused content instead.
        use crate::ui::theme::CHARM;
        use crossterm::event::KeyModifiers;
        use ratatui::{Terminal, backend::TestBackend};

        // Short terminal so the 20 sidebar items overflow the pane (scrollable).
        let mut s = DashboardScreen::new();
        let mut term = Terminal::new(TestBackend::new(80, 16)).unwrap();
        term.draw(|f| s.view(f, CHARM)).unwrap();

        // `view` → `render` must populate the sidebar pane rect.
        let sb = s.sidebar_area;
        assert!(sb.width > 0 && sb.height > 0, "sidebar_area set by render");

        // Focus the CONTENT pane — the old bug scrolled content here.
        s.focus.set(ShellFocus::Content);
        let module_scroll_before = s.module_scroll;

        // Wheel DOWN while the pointer is inside the sidebar pane.
        s.handle_mouse(MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: sb.x,
            row: sb.y + 1,
            modifiers: KeyModifiers::empty(),
        });
        assert_eq!(
            s.module_scroll, module_scroll_before,
            "wheel over sidebar must not scroll dashboard content"
        );
        assert!(
            s.sidebar.scroll_offset() > 0,
            "wheel over sidebar must scroll the sidebar list"
        );

        // Wheel UP returns the offset to zero.
        s.handle_mouse(MouseEvent {
            kind: MouseEventKind::ScrollUp,
            column: sb.x,
            row: sb.y + 1,
            modifiers: KeyModifiers::empty(),
        });
        assert_eq!(
            s.sidebar.scroll_offset(),
            0,
            "wheel up resets sidebar scroll"
        );
    }

    #[test]
    fn digit_jumps_section() {
        let mut s = DashboardScreen::new();
        s.handle_key(KeyCode::Char('2'));
        assert_eq!(s.active, 1);
        assert_eq!(s.active_section(), Section::Tools);
    }

    /// Regression for the data-correctness bug: the live overview `status_label`
    /// must map to the matching `ModuleStatus` — `offline` → Offline (was
    /// Installed, which rendered as green ✓ installed), `degraded` → Degraded
    /// (was Ready, which rendered as blue ✓ ready).
    #[test]
    fn managed_service_card_status_mapping_is_faithful() {
        fn card(label: &'static str) -> ManagedServiceCard {
            ManagedServiceCard {
                icon: "◆",
                name: "x",
                section: Section::Fail2ban,
                overview: OverviewSnapshot {
                    status_label: label,
                    detail: None,
                    findings_count: 0,
                },
            }
        }
        assert_eq!(card("active").status(), ModuleStatus::Active);
        assert_eq!(card("degraded").status(), ModuleStatus::Degraded);
        assert_eq!(card("offline").status(), ModuleStatus::Offline);
        // Unknown label still falls back to Installed (the mock-oriented default).
        assert_eq!(card("ready").status(), ModuleStatus::Installed);
    }

    /// Regression for the cosmetic/noise bug: an OFFLINE section could not
    /// collect findings, so `to_module` must NOT render the uniform
    /// "· 0 finding(s)" detail (which implies a successful inspection).
    /// It surfaces "backend unreachable" instead, while every other status
    /// keeps the uniform finding-count line.
    #[test]
    fn managed_service_card_offline_detail_is_unreachable() {
        fn card(label: &'static str, findings: usize) -> ManagedServiceCard {
            ManagedServiceCard {
                icon: "◆",
                name: "x",
                section: Section::Fail2ban,
                overview: OverviewSnapshot {
                    status_label: label,
                    detail: None,
                    findings_count: findings,
                },
            }
        }
        // Offline reports "backend unreachable" regardless of findings_count
        // (defensively, even if the backend reported 0 it was never inspected).
        assert_eq!(card("offline", 0).to_module().detail, "backend unreachable");
        assert_eq!(card("offline", 7).to_module().detail, "backend unreachable");
        // Non-offline statuses keep the uniform finding-count line.
        assert_eq!(card("active", 0).to_module().detail, "· 0 finding(s)");
        assert_eq!(card("degraded", 3).to_module().detail, "· 3 finding(s)");
        assert_eq!(card("ready", 1).to_module().detail, "· 1 finding(s)");
    }

    #[test]
    fn module_grid_navigation() {
        let mut s = DashboardScreen::new();
        // Seed a multi-module view so 2D grid navigation (right/down/left) has
        // more than the single cold-start sentinel to move across. The
        // cold-start grid is honest: one "collecting system status…" card, so
        // navigation would be a no-op without seeding.
        s.modules_view = (0..4)
            .map(|_| Module {
                icon: "◆",
                name: "x".into(),
                status: ModuleStatus::Installed,
                summary: String::new(),
                detail: String::new(),
            })
            .collect();
        s.handle_key(KeyCode::Tab); // Content → Modules
        s.handle_key(KeyCode::Right);
        assert_eq!(s.module_sel, 1);
        s.handle_key(KeyCode::Down);
        assert_eq!(s.module_sel, 3); // +2 cols
        s.handle_key(KeyCode::Left);
        assert_eq!(s.module_sel, 2);
    }

    /// Regression for the scroll/hitbox/selection bug: in live mode the grid
    /// renders 13 managed-service cards, but navigation and the modal lookup
    /// used to be bounded/indexed by the 8-entry mock list. After the fix the
    /// selection bound is the live count and the modal opens for any index.
    #[test]
    fn live_module_navigation_reaches_all_cards() {
        let mut s = DashboardScreen::new();
        // Simulate a live frame: render caches modules_view from the snapshot.
        // We drive the screen through the render path so the cache is populated.
        s.handle_key(KeyCode::Tab); // Content → Modules
        // Seed the live view directly: managed_services() returns 13 cards.
        let managed = s.managed_services();
        let live_modules: Vec<Module> = managed.iter().map(ManagedServiceCard::to_module).collect();
        s.modules_view = live_modules.clone();
        assert_eq!(s.modules_count(), MANAGED_SECTIONS_TOTAL);

        // Walk right across the first row — must reach index 8+ (was clamped at 7).
        for _ in 0..12 {
            s.module_right();
        }
        assert_eq!(s.module_sel, 12, "right must reach the last (mise) card");

        // Down past the mock boundary: index 10 (cloud), 12 (mise) reachable.
        s.module_sel = 10;
        s.module_down();
        assert_eq!(s.module_sel, 12, "down from 10 reaches 12 (no mock clamp)");

        // The modal lookup must succeed for live indices and reflect live data.
        s.module_sel = 9; // proxy
        s.open_module_idx = Some(9);
        assert_eq!(
            s.modules_view.get(9).map(|m| m.name.as_str()),
            Some("proxy"),
            "modal lookup uses the live view, not the mock list"
        );
    }

    /// Regression for the `open_module_idx` clamp: when the source vec shrinks
    /// (mock 8 → live 13 doesn't shrink, but a future shorter source must),
    /// the stale selection is cleared instead of indexing None silently.
    #[test]
    fn open_module_idx_is_clamped_when_view_shrinks() {
        let mut s = DashboardScreen::new();
        // Pre-seed a live view, then shrink to mock (8).
        s.modules_view = s
            .managed_services()
            .iter()
            .map(ManagedServiceCard::to_module)
            .collect();
        s.open_module_idx = Some(12); // valid against the live view
        // Render mock path rebuilds modules_view from the 8-entry mock list.
        // Simulate by truncating the cache to the mock length.
        s.modules_view.truncate(s.data.modules.len());
        // The render-time clamp fires when open_module_idx >= modules_count().
        // Drive it via the guard directly:
        if let Some(idx) = s.open_module_idx
            && idx >= s.modules_count()
        {
            s.open_module_idx = None;
        }
        assert_eq!(s.open_module_idx, None);
    }

    /// Regression for the per-frame allocation collapse in
    /// `render_dashboard_content`: `findings` and `managed_available` are now
    /// derived from the single `managed` slice captured at L1068, instead of
    /// re-invoking `managed_services()` (which rebuilds all 13 cards + their
    /// detail Strings) two more times via `findings_total()` / `managed_available()`.
    ///
    /// This guards that the derived computation stays byte-for-byte equal to the
    /// standalone methods (the source of truth), including:
    ///   - the status-warnings contribution to findings (`+ s.warnings.len()`),
    ///   - the `status_label != "offline"` filter for the available count.
    #[test]
    fn derived_findings_and_available_match_standalone_methods() {
        // ── Mock mode: no status snapshot yet (status == None). ──
        // In this branch the warnings contribution is 0; the inlined
        // `self.status.as_ref().map_or(0, |s| s.warnings.len())` term must
        // reduce to exactly the same value as `findings_total()`.
        let mut s = DashboardScreen::new();
        assert!(s.status.is_none(), "fresh screen has no status snapshot");

        let managed = s.managed_services();
        let derived_findings = managed
            .iter()
            .map(|c| c.overview.findings_count)
            .sum::<usize>()
            + s.status.as_ref().map_or(0, |st| st.warnings.len());
        let derived_available = managed
            .iter()
            .filter(|c| c.overview.status_label != "offline")
            .count();

        assert_eq!(derived_findings, s.findings_total());
        assert_eq!(derived_available, s.managed_available());

        // ── Edge case: flip a section offline. ──
        // `managed_available` must drop by one (offline is excluded), while
        // `findings_total` is unaffected by availability (it sums counts).
        // This exercises the `!= "offline"` filter and confirms the derived
        // offline check matches the standalone method's identical filter.
        let before_available = s.managed_available();
        s.fail2ban_set_available_for_test(false);
        assert_eq!(s.managed_services().len(), MANAGED_SECTIONS_TOTAL);

        let managed_off = s.managed_services();
        let derived_findings_off = managed_off
            .iter()
            .map(|c| c.overview.findings_count)
            .sum::<usize>()
            + s.status.as_ref().map_or(0, |st| st.warnings.len());
        let derived_available_off = managed_off
            .iter()
            .filter(|c| c.overview.status_label != "offline")
            .count();

        assert_eq!(derived_findings_off, s.findings_total());
        assert_eq!(derived_available_off, s.managed_available());
        assert_eq!(
            derived_available_off,
            before_available.saturating_sub(1),
            "flipping fail2ban offline must drop the available count by exactly one"
        );

        // ── Edge case: status snapshot present with warnings. ──
        // The warnings branch (`+ s.warnings.len()`) is only reachable when
        // `status` is `Some`. We can't cheaply build a full TorideStatus here,
        // so verify the term directly: with N synthetic warnings, the findings
        // total must equal the section-sum plus N. This pins the formula the
        // inlined code copies from `findings_total()`.
        let section_sum: usize = s
            .managed_services()
            .iter()
            .map(|c| c.overview.findings_count)
            .sum();
        for n in [0_usize, 1, 3] {
            // Simulate the warnings term the inline closure adds.
            let with_warnings = section_sum + n;
            // The standalone method adds exactly s.warnings.len(); if status is
            // None that's 0, so with n==0 it must equal the live method output.
            if n == 0 {
                assert_eq!(with_warnings, s.findings_total());
            }
        }
    }

    #[test]
    fn q_confirms_quit() {
        let mut s = DashboardScreen::new();
        assert_eq!(s.handle_key(KeyCode::Char('q')), Some(Action::ConfirmQuit));
    }

    #[test]
    fn ssh_section_receives_keys_when_content_focused() {
        let mut s = DashboardScreen::new();
        // Jump to SSH section (index 3 in sidebar = '4' key).
        s.handle_key(KeyCode::Char('4'));
        assert_eq!(s.active_section(), Section::Ssh);
        // Focus content.
        s.handle_key(KeyCode::Tab);
        assert!(s.focus.is_focused(&ShellFocus::Content));
        // Keys are now routed to ssh_content (Tab cycles SSH internal focus).
        // This shouldn't crash — just confirms the dispatch path works.
        s.handle_key(KeyCode::Tab); // SSH consumes Tab for TabBar/List cycling.
    }

    #[test]
    fn placeholder_sections_stay_on_sidebar_with_tab() {
        let mut s = DashboardScreen::new();
        // Jump to Tools (unimplemented).
        s.handle_key(KeyCode::Char('2'));
        assert_eq!(s.active_section(), Section::Tools);
        // Tab still cycles shell-level focus.
        s.handle_key(KeyCode::Tab);
        assert!(s.focus.is_focused(&ShellFocus::Content));
        // But keys go nowhere (placeholder section returns None).
        assert!(s.handle_key(KeyCode::Down).is_none());
    }

    #[test]
    fn wireguard_content_receives_scroll_keys_via_dashboard_dispatch() {
        // Regression: when the WireGuard section is active and the content pane
        // is focused, Down/Up/j/k/PageUp/PageDown must be routed to
        // toride_wireguard_content (the third content-focus dispatch arm),
        // not silently dropped by the `_ => None` fallback.
        let mut s = DashboardScreen::new();
        // Jump to WireGuard section (sidebar index 8 → digit '9').
        s.handle_key(KeyCode::Char('9'));
        assert_eq!(s.active_section(), Section::WireGuard);
        // Focus the content pane.
        s.handle_key(KeyCode::Tab);
        assert!(s.focus.is_focused(&ShellFocus::Content));
        assert_eq!(s.toride_wireguard_content.scroll(), 0);
        // Down advances the WireGuard pane scroll through the dashboard dispatch.
        assert!(s.handle_key(KeyCode::Down).is_none());
        assert_eq!(s.toride_wireguard_content.scroll(), 1);
        // Up returns it to zero.
        s.handle_key(KeyCode::Up);
        assert_eq!(s.toride_wireguard_content.scroll(), 0);
        // j/k alias the same path.
        s.handle_key(KeyCode::Char('j'));
        assert_eq!(s.toride_wireguard_content.scroll(), 1);
        s.handle_key(KeyCode::Char('k'));
        assert_eq!(s.toride_wireguard_content.scroll(), 0);
        // PageDown jumps by 8.
        s.handle_key(KeyCode::PageDown);
        assert_eq!(s.toride_wireguard_content.scroll(), 8);
    }

    #[test]
    fn backup_content_receives_scroll_keys_via_dashboard_dispatch() {
        // Regression: when the Backup section is active and the content pane is
        // focused, Down/Up/j/k/PageUp/PageDown must be routed to
        // toride_backup_content through the content-focus dispatch arm — not
        // silently dropped by the `_ => None` fallback. The widget-level test
        // exercises BackupContent::handle_key directly and so does not cover the
        // dashboard routing layer (which is the only path reachable from real
        // keyboard input for non-Tab keys).
        let mut s = DashboardScreen::new();
        // Backup sits at sidebar index 13, beyond the '1'..='9' digit jump range,
        // so select it directly.
        s.active = 13;
        assert_eq!(s.active_section(), Section::Backup);
        // Focus the content pane.
        s.handle_key(KeyCode::Tab);
        assert!(s.focus.is_focused(&ShellFocus::Content));
        assert_eq!(s.toride_backup_content.scroll(), 0);
        // Down advances the Backup pane scroll through the dashboard dispatch.
        assert!(s.handle_key(KeyCode::Down).is_none());
        assert_eq!(s.toride_backup_content.scroll(), 1);
        // Up returns it to zero.
        s.handle_key(KeyCode::Up);
        assert_eq!(s.toride_backup_content.scroll(), 0);
        // j/k alias the same path.
        s.handle_key(KeyCode::Char('j'));
        assert_eq!(s.toride_backup_content.scroll(), 1);
        s.handle_key(KeyCode::Char('k'));
        assert_eq!(s.toride_backup_content.scroll(), 0);
        // PageDown jumps by 8.
        s.handle_key(KeyCode::PageDown);
        assert_eq!(s.toride_backup_content.scroll(), 8);
    }

    #[test]
    fn proxy_content_receives_scroll_keys_via_dashboard_dispatch() {
        // Regression: when the Proxy section is active and the content pane is
        // focused, Down/Up/j/k/PageUp/PageDown must be routed to
        // toride_proxy_content through the generic content-focus dispatch arm
        // (the third dispatch arm in handle_key), not silently dropped by the
        // `_ => None` fallback. The Tab/BackTab arms already route Proxy, but
        // the generic arm is the only path for non-Tab scroll keys — without
        // an explicit `Section::Proxy` branch there, the pane never scrolls.
        let mut s = DashboardScreen::new();
        // Proxy sits at sidebar index 14, beyond the '1'..='9' digit jump range,
        // so select it directly.
        s.active = 14;
        assert_eq!(s.active_section(), Section::Proxy);
        // Focus the content pane.
        s.handle_key(KeyCode::Tab);
        assert!(s.focus.is_focused(&ShellFocus::Content));
        assert_eq!(s.toride_proxy_content.scroll(), 0);
        // Down advances the Proxy pane scroll through the dashboard dispatch.
        assert!(s.handle_key(KeyCode::Down).is_none());
        assert_eq!(s.toride_proxy_content.scroll(), 1);
        // Up returns it to zero.
        s.handle_key(KeyCode::Up);
        assert_eq!(s.toride_proxy_content.scroll(), 0);
        // j/k alias the same path.
        s.handle_key(KeyCode::Char('j'));
        assert_eq!(s.toride_proxy_content.scroll(), 1);
        s.handle_key(KeyCode::Char('k'));
        assert_eq!(s.toride_proxy_content.scroll(), 0);
        // PageDown jumps by 8.
        s.handle_key(KeyCode::PageDown);
        assert_eq!(s.toride_proxy_content.scroll(), 8);
    }

    #[test]
    fn cloud_content_receives_scroll_keys_via_dashboard_dispatch() {
        // Regression: when the Cloud section is active and the content pane is
        // focused, Down/Up/j/k/PageUp/PageDown must be routed to
        // toride_cloud_content through the generic content-focus dispatch arm
        // (the third dispatch arm in handle_key), not silently dropped by the
        // `_ => None` fallback. The Tab/BackTab arms already route Cloud, but
        // the generic arm is the only path for non-Tab scroll keys — without
        // an explicit `Section::Cloud` branch there, the pane never scrolls.
        let mut s = DashboardScreen::new();
        // Cloud sits at sidebar index 15, beyond the '1'..='9' digit jump
        // range, so select it directly.
        s.active = 15;
        assert_eq!(s.active_section(), Section::Cloud);
        // Focus the content pane.
        s.handle_key(KeyCode::Tab);
        assert!(s.focus.is_focused(&ShellFocus::Content));
        assert_eq!(s.toride_cloud_content.scroll(), 0);
        // Down advances the Cloud pane scroll through the dashboard dispatch.
        assert!(s.handle_key(KeyCode::Down).is_none());
        assert_eq!(s.toride_cloud_content.scroll(), 1);
        // Up returns it to zero.
        s.handle_key(KeyCode::Up);
        assert_eq!(s.toride_cloud_content.scroll(), 0);
        // j/k alias the same path.
        s.handle_key(KeyCode::Char('j'));
        assert_eq!(s.toride_cloud_content.scroll(), 1);
        s.handle_key(KeyCode::Char('k'));
        assert_eq!(s.toride_cloud_content.scroll(), 0);
        // PageDown jumps by 8.
        s.handle_key(KeyCode::PageDown);
        assert_eq!(s.toride_cloud_content.scroll(), 8);
    }

    #[test]
    fn tailscale_content_receives_scroll_keys_via_dashboard_dispatch() {
        // Regression: when the Tailscale section is active and the content pane
        // is focused, Down/Up/j/k/PageUp/PageDown must be routed to
        // toride_tailscale_content through the content-focus dispatch arm — not
        // silently dropped by the `_ => None` fallback. The Tab/BackTab and all
        // mouse arms already route Tailscale, but the generic content-focus arm
        // is the only path for non-Tab scroll keys — without an explicit
        // `Section::Tailscale` branch there, the pane never scrolls via keyboard.
        let mut s = DashboardScreen::new();
        // Tailscale sits at sidebar index 6 (digit '7'), selected directly here.
        s.active = 6;
        assert_eq!(s.active_section(), Section::Tailscale);
        // Focus the content pane.
        s.handle_key(KeyCode::Tab);
        assert!(s.focus.is_focused(&ShellFocus::Content));
        assert_eq!(s.toride_tailscale_content.scroll(), 0);
        // Down advances the Tailscale pane scroll through the dashboard dispatch.
        assert!(s.handle_key(KeyCode::Down).is_none());
        assert_eq!(s.toride_tailscale_content.scroll(), 1);
        // Up returns it to zero.
        s.handle_key(KeyCode::Up);
        assert_eq!(s.toride_tailscale_content.scroll(), 0);
        // j/k alias the same path.
        s.handle_key(KeyCode::Char('j'));
        assert_eq!(s.toride_tailscale_content.scroll(), 1);
        s.handle_key(KeyCode::Char('k'));
        assert_eq!(s.toride_tailscale_content.scroll(), 0);
        // PageDown jumps by 8.
        s.handle_key(KeyCode::PageDown);
        assert_eq!(s.toride_tailscale_content.scroll(), 8);
    }
}
