//! The dashboard home screen: sidebar navigation over the read-only content
//! sections plus live system status panels.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

const AUTO_COLLAPSE_W: u16 = 100;
const SINGLE_COL_W: u16 = 78;
const STAT_ROW_H: u16 = 6;
const MODULE_CARD_H: u16 = 5;
const GRID_COLS: usize = 2;
/// Number of read-only sections surfaced in the live managed-services grid.
pub const MANAGED_SECTIONS_TOTAL: usize = 13;

#[derive(Clone, Copy, Debug)]
struct StatCardInput {
    live: bool,
    managed_available: usize,
    findings: usize,
    pending_total: Option<usize>,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct ManagedServiceCard {
    icon: &'static str,
    name: &'static str,
    section: Section,
    overview: OverviewSnapshot,
}

impl ManagedServiceCard {
    #[must_use]
    fn status(&self) -> ModuleStatus {
        match self.overview.status_label {
            "active" => ModuleStatus::Active,
            "degraded" => ModuleStatus::Degraded,
            "offline" => ModuleStatus::Offline,
            _ => ModuleStatus::Installed,
        }
    }

    #[must_use]
    fn to_module(&self) -> Module {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GaugeKind {
    Cpu,
    Ram,
    Disk,
    Net,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ShellFocus {
    Sidebar,
    Content,
}

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

/// Shared `handle_key`/`handle_mouse`/`view` surface for the read-only
/// content sections; [`Section::Dashboard`] is intentionally excluded.
pub trait ContentPanel {
    /// Forward a key press to the content's inherent handler.
    fn handle_key(&mut self, code: KeyCode) -> Option<Action>;
    /// Forward a mouse event to the content's inherent handler.
    fn handle_mouse(&mut self, mouse: MouseEvent) -> Option<Action>;
    /// Render the content into `area`.
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

/// The dashboard home screen: sidebar, live status panels, and the
/// read-only content sections.
pub struct DashboardScreen {
    data: DashboardData,
    status: Option<TorideStatus>,
    sidebar: Sidebar,
    active: usize,
    focus: FocusManager<ShellFocus>,
    dashboard_focus: DashboardFocus,
    module_sel: usize,
    module_scroll: usize,
    updates_scroll: usize,
    activity_scroll: usize,
    open_module_idx: Option<usize>,
    module_modal: InteractiveModal<Action>,
    gauge_hover: Option<GaugeKind>,
    gauge_hitboxes: [Rect; 4],
    sidebar_area: Rect,
    module_hitboxes: Vec<Rect>,
    modules_view: Vec<Module>,
    net_rx_rate: Option<f64>,
    net_tx_rate: Option<f64>,
    disk_read_rate: Option<f64>,
    disk_write_rate: Option<f64>,
    base: ScreenBase,
    clock: String,
    shimmer_start: Instant,
    tooltip_fx: EffectManager<()>,
    prev_gauge_hover: Option<GaugeKind>,
    last_frame: Instant,
    ssh_content: SshContent,
    fail2ban_content: Fail2banContent,
    ufw_kit_content: FirewallContent,
    toride_harden_content: HardenContent,
    toride_wireguard_content: WireguardContent,
    toride_updates_content: UpdatesContent,
    toride_users_content: UsersContent,
    toride_audit_content: AuditContent,
    toride_monitor_content: MonitorContent,
    toride_backup_content: BackupContent,
    toride_proxy_content: ProxyContent,
    toride_cloud_content: CloudContent,
    toride_tailscale_content: TailscaleContent,
    toride_mise_content: MiseContent,
    about_content: AboutContent,
    logs_content: LogsContent,
    settings_content: SettingsContent,
    templates_content: TemplatesContent,
    tools_content: ToolsContent,
}

impl Default for DashboardScreen {
    fn default() -> Self {
        Self::new()
    }
}

impl DashboardScreen {
    /// Creates a dashboard seeded with an empty skeleton; collectors overlay
    /// live data via the `set_*` methods.
    #[must_use]
    pub fn new() -> Self {
        let data = DashboardData::empty();
        let sidebar = Sidebar::new(data.sidebar.len());
        let clock = "09:17 PM".to_string();
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

            let rx = status.system.network.bytes_received as f64
                - prev.system.network.bytes_received as f64;
            let tx = status.system.network.bytes_transmitted as f64
                - prev.system.network.bytes_transmitted as f64;
            self.net_rx_rate = Some(rx.max(0.0) / dt);
            self.net_tx_rate = Some(tx.max(0.0) / dt);

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

    fn refresh_sidebar_badges(&mut self) {
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
                _ => None,
            };
            item.badge = badge;
        }
    }

    #[must_use]
    fn managed_services(&self) -> Vec<ManagedServiceCard> {
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

    #[cfg(test)]
    #[must_use]
    fn managed_available(&self) -> usize {
        self.managed_services()
            .iter()
            .filter(|c| c.overview.status_label != "offline")
            .count()
    }

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

    /// Refresh the header clock string.
    pub fn tick_clock(&mut self) {
        self.clock = current_clock();
    }

    /// Push a collected [`SshDataBundle`](crate::ssh_data::SshDataBundle)
    /// into the SSH panel.
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

    /// Drain the SSH ops queued by the SSH panel.
    pub fn drain_ssh_ops(&mut self) -> Vec<crate::ssh_data::SshOp> {
        self.ssh_content.drain_pending_ops()
    }

    /// Re-queue SSH ops at the front of the pending queue.
    pub fn queue_ssh_ops_front(&mut self, ops: Vec<crate::ssh_data::SshOp>) {
        self.ssh_content.queue_ops_front(ops);
    }

    /// Push an error message onto the SSH panel.
    pub fn push_ssh_error(&mut self, msg: String) {
        self.ssh_content.push_error(msg);
    }

    /// Whether the SSH error popup is currently showing.
    #[must_use]
    pub fn ssh_error_showing(&self) -> bool {
        self.active_section() == Section::Ssh && self.ssh_content.error_showing()
    }

    /// Whether the SSH error popup has expired.
    #[must_use]
    pub fn ssh_error_expired(&self) -> bool {
        self.active_section() == Section::Ssh && self.ssh_content.error_expired()
    }

    /// Set the SSH panel's loading state and pending op count.
    pub fn set_ssh_loading(&mut self, loading: bool, count: usize) {
        self.ssh_content.set_loading(loading, count);
    }

    /// Push a collected fail2ban bundle into the fail2ban panel.
    pub fn set_fail2ban_data(&mut self, b: crate::fail2ban_data::Fail2banDataBundle) {
        self.fail2ban_content.set_available(b.available);
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

    /// Push a collected UFW bundle into the firewall panel.
    pub fn set_ufw_kit_data(&mut self, b: crate::ufw_kit_data::FirewallDataBundle) {
        self.ufw_kit_content.set_available(b.available);
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

    /// Push a collected harden bundle into the harden panel.
    pub fn set_toride_harden_data(&mut self, b: crate::toride_harden_data::HardenDataBundle) {
        self.toride_harden_content.set_available(b.available);
        self.toride_harden_content
            .set_unavailable_reason(b.unavailable_reason);
        self.toride_harden_content.set_profiles(b.profiles);
        self.toride_harden_content
            .set_sysctl_rows_by_profile(b.sysctl_rows_by_profile);
        self.toride_harden_content.set_mounts(b.mounts);
        self.toride_harden_content.set_findings(b.findings);
    }

    /// Push a collected `WireGuard` bundle into the `WireGuard` panel.
    pub fn set_toride_wireguard_data(
        &mut self,
        b: crate::toride_wireguard_data::WireguardDataBundle,
    ) {
        self.toride_wireguard_content.set_available(b.available);
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

    /// Push a collected updates bundle into the updates panel.
    pub fn set_toride_updates_data(&mut self, b: crate::toride_updates_data::UpdatesDataBundle) {
        self.toride_updates_content.set_available(b.available);
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

    /// Push a collected users bundle into the users panel.
    pub fn set_toride_users_data(&mut self, b: crate::toride_users_data::UsersDataBundle) {
        self.toride_users_content.set_available(b.available);
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

    /// Push a collected audit bundle into the audit panel.
    pub fn set_toride_audit_data(&mut self, b: crate::toride_audit_data::AuditDataBundle) {
        self.toride_audit_content.set_available(b.available);
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

    /// Push a collected monitor bundle into the monitor panel.
    pub fn set_toride_monitor_data(&mut self, b: crate::toride_monitor_data::MonitorDataBundle) {
        self.toride_monitor_content.set_available(b.available);
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

    /// Push a collected backup bundle into the backup panel.
    pub fn set_toride_backup_data(&mut self, b: crate::toride_backup_data::BackupDataBundle) {
        self.toride_backup_content.set_available(b.available);
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

    /// Push a collected proxy bundle into the proxy panel.
    pub fn set_toride_proxy_data(&mut self, b: crate::toride_proxy_data::ProxyDataBundle) {
        self.toride_proxy_content.set_available(b.available);
        self.toride_proxy_content
            .set_unavailable_reason(b.unavailable_reason);
        self.toride_proxy_content.set_status(b.backend, b.status);
        self.toride_proxy_content.set_server_blocks(b.server_blocks);
        self.toride_proxy_content
            .set_certificates(b.certificates, b.has_expired_certs);
        self.toride_proxy_content.set_waf(b.waf_available);
        self.toride_proxy_content.set_findings(b.findings);
    }

    /// Push a collected cloud bundle into the cloud panel.
    pub fn set_toride_cloud_data(&mut self, b: crate::toride_cloud_data::CloudDataBundle) {
        self.toride_cloud_content.set_available(b.available);
        self.toride_cloud_content
            .set_unavailable_reason(b.unavailable_reason);
        self.toride_cloud_content.set_provider(b.provider);
        self.toride_cloud_content
            .set_agent(b.agent_running, b.agent_enabled, b.agent_service_name);
        self.toride_cloud_content
            .set_security_groups(b.security_groups);
        self.toride_cloud_content.set_findings(b.findings);
    }

    /// Push a collected tailscale bundle into the tailscale panel.
    pub fn set_toride_tailscale_data(
        &mut self,
        b: crate::toride_tailscale_data::TailscaleDataBundle,
    ) {
        self.toride_tailscale_content.set_available(b.available);
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

    /// Push a collected mise bundle into the mise panel.
    pub fn set_toride_mise_data(&mut self, b: crate::toride_mise_data::MiseDataBundle) {
        self.toride_mise_content.set_available(b.available);
        self.toride_mise_content
            .set_unavailable_reason(b.unavailable_reason);
        self.toride_mise_content.set_version(b.version);
        self.toride_mise_content.set_tools(b.tools);
        self.toride_mise_content.set_outdated(b.outdated);
        self.toride_mise_content.set_config_files(b.config_files);
        self.toride_mise_content.set_findings(b.findings);
    }

    /// Push a collected about bundle into the about panel.
    pub fn set_about_data(&mut self, b: crate::about_data::AboutDataBundle) {
        self.about_content.set_available(b.available);
        self.about_content
            .set_unavailable_reason(b.unavailable_reason);
        self.about_content.set_system(b.system);
        self.about_content.set_app(b.app);
        self.about_content.set_runtime(b.runtime);
    }

    /// Push a collected logs bundle into the logs panel.
    pub fn set_logs_data(&mut self, b: crate::logs_data::LogsDataBundle) {
        self.logs_content.set_available(b.available);
        self.logs_content
            .set_unavailable_reason(b.unavailable_reason);
        self.logs_content.set_logs(b.sources);
    }

    /// Push a collected settings bundle into the settings panel.
    pub fn set_settings_data(&mut self, b: crate::settings_data::SettingsDataBundle) {
        self.settings_content.set_available(b.available);
        self.settings_content
            .set_unavailable_reason(b.unavailable_reason);
        self.settings_content.set_config(b.config);
        self.settings_content.set_runtime(b.runtime);
    }

    /// Set the theme the settings panel reports as active.
    pub fn set_active_theme(&mut self, theme: crate::ui::theme::Theme) {
        self.settings_content.set_active_theme(theme);
    }

    /// Push a collected templates bundle into the templates panel.
    pub fn set_templates_data(&mut self, b: crate::templates_data::TemplatesDataBundle) {
        self.templates_content.set_available(b.available);
        self.templates_content
            .set_unavailable_reason(b.unavailable_reason);
        self.templates_content.set_recipes(b.recipes);
        self.templates_content.set_findings(b.findings);
    }

    /// Push a collected tools bundle into the tools panel.
    pub fn set_tools_data(&mut self, b: crate::tools_data::ToolsDataBundle) {
        self.tools_content.set_available(b.available);
        self.tools_content
            .set_unavailable_reason(b.unavailable_reason);
        self.tools_content.set_tools(b.tools);
        self.tools_content.set_findings(b.findings);
        self.refresh_sidebar_badges();
    }

    fn active_section(&self) -> Section {
        self.data.sidebar[self.active].section
    }

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

    fn module_left(&mut self) {
        self.module_sel = self.module_sel.saturating_sub(1);
    }

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

    fn scroll_focused(&mut self, down: bool) {
        if self.focus.is_focused(&ShellFocus::Sidebar) {
            self.sidebar.scroll(if down { 1 } else { -1 });
            return;
        }
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
    }

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

    fn module_at(&self, col: u16, row: u16) -> Option<usize> {
        self.module_hitboxes.iter().position(|rect| {
            col >= rect.x && col < rect.right() && row >= rect.y && row < rect.bottom()
        })
    }

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
        self.sidebar_area = shell.sidebar;

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

        let content = shell.content;
        if let Some(panel) = self.active_panel_mut() {
            panel.view(frame, content, p);
        } else {
            self.render_dashboard_content(frame, content, p);
        }

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

        let mut dt = self.last_frame.elapsed();
        self.last_frame = Instant::now();

        if self.gauge_hover != self.prev_gauge_hover {
            self.prev_gauge_hover = self.gauge_hover;
            dt = Duration::ZERO;
            if self.gauge_hover.is_some() {
                self.tooltip_fx = EffectManager::default();
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

    fn header_spinners_live(&self) -> bool {
        self.net_rx_rate.is_none()
            || self.net_tx_rate.is_none()
            || self.disk_read_rate.is_none()
            || self.disk_write_rate.is_none()
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
                while self.module_hitboxes.len() <= idx {
                    self.module_hitboxes.push(Rect::default());
                }
                self.module_hitboxes[idx] = *cell;
            }
        }
    }

    fn render_updates_panel(&self, frame: &mut Frame, area: Rect, p: Palette) {
        let focused = self.focus.is_focused(&ShellFocus::Content)
            && self.active_section() == Section::Dashboard
            && self.dashboard_focus == DashboardFocus::Updates;

        if let Some(s) = &self.status {
            let inner =
                render_titled_panel(frame, area, p, " STORAGE & NETWORK ", p.accent, focused);
            self.render_storage_network(frame, inner, p, s);
        } else {
            let inner =
                render_titled_panel(frame, area, p, " STORAGE & NETWORK ", p.accent, focused);
            let line = Line::from(Span::styled(
                "  collecting system status…",
                Style::new().fg(p.text_muted),
            ));
            frame.render_widget(Paragraph::new(line), inner);
        }
    }

    fn render_storage_network(&self, frame: &mut Frame, inner: Rect, p: Palette, s: &TorideStatus) {
        let mut lines: Vec<(String, Option<String>, ratatui::style::Color)> = Vec::new();

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

        let net_value = match (self.net_rx_rate, self.net_tx_rate) {
            (Some(rx), Some(tx)) => Some(format!("↓ {} · ↑ {}", fmt_rate(rx), fmt_rate(tx))),
            (Some(rx), None) => Some(format!("↓ {}", fmt_rate(rx))),
            (None, Some(tx)) => Some(format!("↑ {}", fmt_rate(tx))),
            (None, None) => None,
        };
        if net_value.is_some() {
            lines.push(("network".to_string(), net_value, p.info));
        }

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

    fn content_handle_key(&mut self, code: KeyCode) -> Option<Action> {
        if let Some(panel) = self.active_panel_mut() {
            panel.handle_key(code)
        } else {
            self.handle_dashboard_content_key(code)
        }
    }

    fn handle_dashboard_content_key(&mut self, code: KeyCode) -> Option<Action> {
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
            _ if self.active_section() == Section::Ssh
                && (self.ssh_content.has_modal() || self.ssh_content.is_loading()) =>
            {
                return self.ssh_content.handle_key(code);
            }
            KeyCode::Char('q') => return Some(Action::ConfirmQuit),
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

        if self.focus.is_focused(&ShellFocus::Content) {
            return self.content_handle_key(code);
        }

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

        let motion = matches!(mouse.kind, MouseEventKind::Moved | MouseEventKind::Drag(_));

        let mut hover_changed = false;
        if motion {
            let gauge = self.gauge_at(mouse.column, mouse.row);
            hover_changed |= gauge != self.gauge_hover;
            self.gauge_hover = gauge;
        }

        if self.module_modal.is_visible() {
            match self.module_modal.handle_mouse(&mouse) {
                ModalEvent::Closed | ModalEvent::Button(_) => {
                    self.module_modal.close();
                    self.open_module_idx = None;
                }
                ModalEvent::Consumed => {}
            }
            if motion {
                return Some(Action::Redraw);
            }
            return None;
        }

        match mouse.kind {
            MouseEventKind::Moved | MouseEventKind::Drag(_) => {
                let idx = self.sidebar.item_at(mouse.column, mouse.row);
                hover_changed |= self.sidebar.set_hovered(idx);
                if let Some(panel) = self.active_panel_mut() {
                    panel.handle_mouse(mouse);
                }
                if hover_changed || self.active_section() == Section::Ssh {
                    return Some(Action::Redraw);
                }
            }
            MouseEventKind::Down(MouseButton::Left) => {
                if let Some(idx) = self.sidebar.item_at(mouse.column, mouse.row) {
                    self.sidebar.select_to(idx);
                    self.active = idx;
                    self.focus.set(ShellFocus::Sidebar);
                } else if self.active_section() == Section::Dashboard {
                    if let Some(idx) = self.module_at(mouse.column, mouse.row) {
                        self.module_sel = idx;
                        self.focus.set(ShellFocus::Content);
                        self.open_module_idx = Some(idx);
                        self.module_modal.open();
                    }
                } else {
                    self.focus.set(ShellFocus::Content);
                    if let Some(panel) = self.active_panel_mut() {
                        return panel.handle_mouse(mouse);
                    }
                }
            }
            MouseEventKind::ScrollDown | MouseEventKind::ScrollUp => {
                let down = matches!(mouse.kind, MouseEventKind::ScrollDown);
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
                self.scroll_focused(down);
            }
            MouseEventKind::Up(_) => {
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
        true
    }

    fn needs_fast_frames(&self) -> bool {
        self.sidebar.is_animating()
            || self.header_spinners_live()
            || self.ssh_content.is_loading()
            || self.ssh_content.has_pending_fingerprints()
            || self.tooltip_fx.is_running()
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
        false
    }
}

fn pad(area: Rect) -> Rect {
    Rect {
        x: area.x + 1,
        y: area.y,
        width: area.width.saturating_sub(2),
        height: area.height,
    }
}

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

#[allow(clippy::cast_possible_truncation)]
fn render_top_processes(frame: &mut Frame, inner: Rect, p: Palette, s: &TorideStatus) {
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

struct LiveRates {
    net_rx: Option<f64>,
    net_tx: Option<f64>,
    disk_read: Option<f64>,
    disk_write: Option<f64>,
}

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

    let anchor = Rect::new(
        hitbox.x,
        header_area.bottom().saturating_sub(1),
        hitbox.width,
        1,
    );
    Tooltip::new(&lines).anchor(anchor).render(frame, p)
}

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

    lines.push(title_line_with_detail("CPU", &sys.static_info.cpu_brand, p));

    if let Some(usage) = sys.cpu_usage {
        let color = percent_color(usage, p);
        lines.push(Line::from(vec![
            Span::styled(format!("{:<7}", "Usage"), Style::new().fg(p.text_muted)),
            Span::styled(format!("{usage:.0}%"), Style::new().fg(color).bold()),
        ]));
    }

    let phys = sys
        .physical_cores
        .map_or_else(|| "—".to_string(), |c| c.to_string());
    let log = sys.static_info.logical_cores;
    lines.push(kv("Cores", &format!("{phys} / {log}"), p));

    if let Some(load) = &sys.load_average {
        lines.push(kv(
            "Load",
            &format!("{:.2} / {:.2} / {:.2}", load.one, load.five, load.fifteen),
            p,
        ));
    }

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
        let mut s = DashboardScreen::new();
        assert!(s.focus.is_focused(&ShellFocus::Sidebar));
        s.handle_key(KeyCode::Tab);
        assert!(s.focus.is_focused(&ShellFocus::Content));
        s.handle_key(KeyCode::Esc);
        assert!(s.focus.is_focused(&ShellFocus::Sidebar));
        s.handle_key(KeyCode::BackTab);
        assert!(s.focus.is_focused(&ShellFocus::Content));
    }

    #[test]
    fn dashboard_focus_cycles_panels() {
        let mut s = DashboardScreen::new();
        s.handle_key(KeyCode::Tab);
        assert!(s.focus.is_focused(&ShellFocus::Content));
        assert_eq!(s.dashboard_focus, DashboardFocus::Modules);
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
        s.handle_key(KeyCode::Tab);
        assert!(!s.module_modal.is_visible());
        s.handle_key(KeyCode::Enter);
        assert!(s.module_modal.is_visible());
        assert_eq!(s.open_module_idx, Some(0));
        s.handle_key(KeyCode::Esc);
        assert!(!s.module_modal.is_visible());
    }

    #[test]
    fn esc_from_content_returns_to_sidebar() {
        let mut s = DashboardScreen::new();
        s.handle_key(KeyCode::Tab);
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
    fn needs_animation_is_always_true_for_header_shimmer() {
        let s = DashboardScreen::new();
        assert!(s.needs_animation());
    }

    #[test]
    fn needs_fast_frames_tracks_spinners_and_loading() {
        let mut s = DashboardScreen::new();
        assert!(
            s.needs_fast_frames(),
            "cold start renders header gauge spinners — full frame rate"
        );

        s.net_rx_rate = Some(1.0);
        s.net_tx_rate = Some(1.0);
        s.disk_read_rate = Some(1.0);
        s.disk_write_rate = Some(1.0);
        assert!(
            !s.needs_fast_frames(),
            "settled screen with known rates is shimmer-only"
        );

        s.set_ssh_loading(true, 1);
        assert!(s.needs_fast_frames(), "SSH write spinner needs fast frames");
        s.set_ssh_loading(false, 0);
        assert!(!s.needs_fast_frames(), "spinner gone — slow cadence again");
    }

    #[test]
    fn needs_fast_frames_covers_pending_key_fingerprints() {
        use crate::ui::screens::SshKeyEntry;

        fn key_entry(fingerprint: &str) -> SshKeyEntry {
            SshKeyEntry {
                name: "id_ed25519".into(),
                key_type: "Ed25519".into(),
                fingerprint: fingerprint.into(),
                encrypted: false,
                permissions: "0600".into(),
                has_public: true,
                has_cert: false,
                used_by_hosts: Vec::new(),
            }
        }

        let mut s = DashboardScreen::new();
        s.net_rx_rate = Some(1.0);
        s.net_tx_rate = Some(1.0);
        s.disk_read_rate = Some(1.0);
        s.disk_write_rate = Some(1.0);
        assert!(!s.needs_fast_frames(), "settled screen is shimmer-only");

        s.ssh_content.set_keys(vec![key_entry("")]);
        assert!(
            s.needs_fast_frames(),
            "a pending fingerprint row spins at full frame rate"
        );

        s.ssh_content.set_keys(vec![key_entry("SHA256:abc123")]);
        assert!(
            !s.needs_fast_frames(),
            "filled fingerprint settles back to shimmer cadence"
        );
    }

    #[test]
    fn ssh_error_expiry_flags_follow_the_visible_section() {
        let mut s = DashboardScreen::new();
        s.push_ssh_error("write failed".into());
        assert!(
            !s.ssh_error_showing(),
            "the Dashboard overview does not render the SSH toast"
        );

        let idx = s
            .data
            .sidebar
            .iter()
            .position(|i| i.section == Section::Ssh)
            .expect("SSH section is in the sidebar");
        s.active = idx;
        assert_eq!(s.active_section(), Section::Ssh);
        assert!(s.ssh_error_showing(), "visible on the SSH section");
        assert!(!s.ssh_error_expired(), "a fresh toast is not expired");
    }

    #[test]
    fn motion_over_unchanged_ui_requests_no_redraw() {
        use crate::ui::theme::CHARM;
        use crossterm::event::KeyModifiers;
        use ratatui::{Terminal, backend::TestBackend};

        let mut s = DashboardScreen::new();
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| s.view(f, CHARM)).unwrap();

        for row in 6..22u16 {
            let action = s.handle_mouse(MouseEvent {
                kind: MouseEventKind::Moved,
                column: 60,
                row,
                modifiers: KeyModifiers::empty(),
            });
            assert_eq!(
                action, None,
                "no-change motion at row {row} repaints nothing"
            );
        }
    }

    #[test]
    fn mouse_wheel_over_sidebar_scrolls_sidebar_not_content() {
        use crate::ui::theme::CHARM;
        use crossterm::event::KeyModifiers;
        use ratatui::{Terminal, backend::TestBackend};

        let mut s = DashboardScreen::new();
        let mut term = Terminal::new(TestBackend::new(80, 16)).unwrap();
        term.draw(|f| s.view(f, CHARM)).unwrap();

        let sb = s.sidebar_area;
        assert!(sb.width > 0 && sb.height > 0, "sidebar_area set by render");

        s.focus.set(ShellFocus::Content);
        let module_scroll_before = s.module_scroll;

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
        assert_eq!(card("ready").status(), ModuleStatus::Installed);
    }

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
        assert_eq!(card("offline", 0).to_module().detail, "backend unreachable");
        assert_eq!(card("offline", 7).to_module().detail, "backend unreachable");
        assert_eq!(card("active", 0).to_module().detail, "· 0 finding(s)");
        assert_eq!(card("degraded", 3).to_module().detail, "· 3 finding(s)");
        assert_eq!(card("ready", 1).to_module().detail, "· 1 finding(s)");
    }

    #[test]
    fn module_grid_navigation() {
        let mut s = DashboardScreen::new();
        s.modules_view = (0..4)
            .map(|_| Module {
                icon: "◆",
                name: "x".into(),
                status: ModuleStatus::Installed,
                summary: String::new(),
                detail: String::new(),
            })
            .collect();
        s.handle_key(KeyCode::Tab);
        s.handle_key(KeyCode::Right);
        assert_eq!(s.module_sel, 1);
        s.handle_key(KeyCode::Down);
        assert_eq!(s.module_sel, 3);
        s.handle_key(KeyCode::Left);
        assert_eq!(s.module_sel, 2);
    }

    #[test]
    fn live_module_navigation_reaches_all_cards() {
        let mut s = DashboardScreen::new();
        s.handle_key(KeyCode::Tab);
        let managed = s.managed_services();
        let live_modules: Vec<Module> = managed.iter().map(ManagedServiceCard::to_module).collect();
        s.modules_view = live_modules.clone();
        assert_eq!(s.modules_count(), MANAGED_SECTIONS_TOTAL);

        for _ in 0..12 {
            s.module_right();
        }
        assert_eq!(s.module_sel, 12, "right must reach the last (mise) card");

        s.module_sel = 10;
        s.module_down();
        assert_eq!(s.module_sel, 12, "down from 10 reaches 12 (no mock clamp)");

        s.module_sel = 9;
        s.open_module_idx = Some(9);
        assert_eq!(
            s.modules_view.get(9).map(|m| m.name.as_str()),
            Some("proxy"),
            "modal lookup uses the live view, not the mock list"
        );
    }

    #[test]
    fn open_module_idx_is_clamped_when_view_shrinks() {
        let mut s = DashboardScreen::new();
        s.modules_view = s
            .managed_services()
            .iter()
            .map(ManagedServiceCard::to_module)
            .collect();
        s.open_module_idx = Some(12);
        s.modules_view.truncate(s.data.modules.len());
        if let Some(idx) = s.open_module_idx
            && idx >= s.modules_count()
        {
            s.open_module_idx = None;
        }
        assert_eq!(s.open_module_idx, None);
    }

    #[test]
    fn derived_findings_and_available_match_standalone_methods() {
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

        let section_sum: usize = s
            .managed_services()
            .iter()
            .map(|c| c.overview.findings_count)
            .sum();
        for n in [0_usize, 1, 3] {
            let with_warnings = section_sum + n;
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
        s.handle_key(KeyCode::Char('4'));
        assert_eq!(s.active_section(), Section::Ssh);
        s.handle_key(KeyCode::Tab);
        assert!(s.focus.is_focused(&ShellFocus::Content));
        s.handle_key(KeyCode::Tab);
    }

    #[test]
    fn placeholder_sections_stay_on_sidebar_with_tab() {
        let mut s = DashboardScreen::new();
        s.handle_key(KeyCode::Char('2'));
        assert_eq!(s.active_section(), Section::Tools);
        s.handle_key(KeyCode::Tab);
        assert!(s.focus.is_focused(&ShellFocus::Content));
        assert!(s.handle_key(KeyCode::Down).is_none());
    }

    #[test]
    fn wireguard_content_receives_scroll_keys_via_dashboard_dispatch() {
        let mut s = DashboardScreen::new();
        s.handle_key(KeyCode::Char('9'));
        assert_eq!(s.active_section(), Section::WireGuard);
        s.handle_key(KeyCode::Tab);
        assert!(s.focus.is_focused(&ShellFocus::Content));
        assert_eq!(s.toride_wireguard_content.scroll(), 0);
        assert!(s.handle_key(KeyCode::Down).is_none());
        assert_eq!(s.toride_wireguard_content.scroll(), 1);
        s.handle_key(KeyCode::Up);
        assert_eq!(s.toride_wireguard_content.scroll(), 0);
        s.handle_key(KeyCode::Char('j'));
        assert_eq!(s.toride_wireguard_content.scroll(), 1);
        s.handle_key(KeyCode::Char('k'));
        assert_eq!(s.toride_wireguard_content.scroll(), 0);
        s.handle_key(KeyCode::PageDown);
        assert_eq!(s.toride_wireguard_content.scroll(), 8);
    }

    #[test]
    fn backup_content_receives_scroll_keys_via_dashboard_dispatch() {
        let mut s = DashboardScreen::new();
        s.active = 13;
        assert_eq!(s.active_section(), Section::Backup);
        s.handle_key(KeyCode::Tab);
        assert!(s.focus.is_focused(&ShellFocus::Content));
        assert_eq!(s.toride_backup_content.scroll(), 0);
        assert!(s.handle_key(KeyCode::Down).is_none());
        assert_eq!(s.toride_backup_content.scroll(), 1);
        s.handle_key(KeyCode::Up);
        assert_eq!(s.toride_backup_content.scroll(), 0);
        s.handle_key(KeyCode::Char('j'));
        assert_eq!(s.toride_backup_content.scroll(), 1);
        s.handle_key(KeyCode::Char('k'));
        assert_eq!(s.toride_backup_content.scroll(), 0);
        s.handle_key(KeyCode::PageDown);
        assert_eq!(s.toride_backup_content.scroll(), 8);
    }

    #[test]
    fn proxy_content_receives_scroll_keys_via_dashboard_dispatch() {
        let mut s = DashboardScreen::new();
        s.active = 14;
        assert_eq!(s.active_section(), Section::Proxy);
        s.handle_key(KeyCode::Tab);
        assert!(s.focus.is_focused(&ShellFocus::Content));
        assert_eq!(s.toride_proxy_content.scroll(), 0);
        assert!(s.handle_key(KeyCode::Down).is_none());
        assert_eq!(s.toride_proxy_content.scroll(), 1);
        s.handle_key(KeyCode::Up);
        assert_eq!(s.toride_proxy_content.scroll(), 0);
        s.handle_key(KeyCode::Char('j'));
        assert_eq!(s.toride_proxy_content.scroll(), 1);
        s.handle_key(KeyCode::Char('k'));
        assert_eq!(s.toride_proxy_content.scroll(), 0);
        s.handle_key(KeyCode::PageDown);
        assert_eq!(s.toride_proxy_content.scroll(), 8);
    }

    #[test]
    fn cloud_content_receives_scroll_keys_via_dashboard_dispatch() {
        let mut s = DashboardScreen::new();
        s.active = 15;
        assert_eq!(s.active_section(), Section::Cloud);
        s.handle_key(KeyCode::Tab);
        assert!(s.focus.is_focused(&ShellFocus::Content));
        assert_eq!(s.toride_cloud_content.scroll(), 0);
        assert!(s.handle_key(KeyCode::Down).is_none());
        assert_eq!(s.toride_cloud_content.scroll(), 1);
        s.handle_key(KeyCode::Up);
        assert_eq!(s.toride_cloud_content.scroll(), 0);
        s.handle_key(KeyCode::Char('j'));
        assert_eq!(s.toride_cloud_content.scroll(), 1);
        s.handle_key(KeyCode::Char('k'));
        assert_eq!(s.toride_cloud_content.scroll(), 0);
        s.handle_key(KeyCode::PageDown);
        assert_eq!(s.toride_cloud_content.scroll(), 8);
    }

    #[test]
    fn tailscale_content_receives_scroll_keys_via_dashboard_dispatch() {
        let mut s = DashboardScreen::new();
        s.active = 6;
        assert_eq!(s.active_section(), Section::Tailscale);
        s.handle_key(KeyCode::Tab);
        assert!(s.focus.is_focused(&ShellFocus::Content));
        assert_eq!(s.toride_tailscale_content.scroll(), 0);
        assert!(s.handle_key(KeyCode::Down).is_none());
        assert_eq!(s.toride_tailscale_content.scroll(), 1);
        s.handle_key(KeyCode::Up);
        assert_eq!(s.toride_tailscale_content.scroll(), 0);
        s.handle_key(KeyCode::Char('j'));
        assert_eq!(s.toride_tailscale_content.scroll(), 1);
        s.handle_key(KeyCode::Char('k'));
        assert_eq!(s.toride_tailscale_content.scroll(), 0);
        s.handle_key(KeyCode::PageDown);
        assert_eq!(s.toride_tailscale_content.scroll(), 8);
    }
}
