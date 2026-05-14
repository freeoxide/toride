use std::collections::{BTreeMap, HashMap, VecDeque};

use crate::tui::caps::TerminalCaps;
use crate::tui::theme::Theme;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Profile {
    Basic,
    Sandbox,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum ModuleId {
    SystemUpdate,
    Swap,
    UserSsh,
    Ufw,
    Docker,
    Mise,
    Fail2Ban,
    UnattendedUpgrades,
    Tailscale,
    CloudflareHttp,
    SysctlHardening,
    Hostname,
    Timezone,
    Dokploy,
    Coolify,
    Caddy,
    Nginx,
    Traefik,
    CloudflareTunnel,
    Wireguard,
    Restic,
    Borg,
    Rclone,
    NodeExporter,
    UptimeKuma,
    Netdata,
    Prometheus,
    Grafana,
    DbDump,
    PluginRecipe,
}

impl ModuleId {
    pub fn all() -> &'static [ModuleId] {
        &[
            ModuleId::SystemUpdate,
            ModuleId::Swap,
            ModuleId::UserSsh,
            ModuleId::Ufw,
            ModuleId::Docker,
            ModuleId::Mise,
            ModuleId::Fail2Ban,
            ModuleId::UnattendedUpgrades,
            ModuleId::Tailscale,
            ModuleId::CloudflareHttp,
            ModuleId::SysctlHardening,
            ModuleId::Hostname,
            ModuleId::Timezone,
            ModuleId::Dokploy,
            ModuleId::Coolify,
            ModuleId::Caddy,
            ModuleId::Nginx,
            ModuleId::Traefik,
            ModuleId::CloudflareTunnel,
            ModuleId::Wireguard,
            ModuleId::Restic,
            ModuleId::Borg,
            ModuleId::Rclone,
            ModuleId::NodeExporter,
            ModuleId::UptimeKuma,
            ModuleId::Netdata,
            ModuleId::Prometheus,
            ModuleId::Grafana,
            ModuleId::DbDump,
            ModuleId::PluginRecipe,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::SystemUpdate => "System Update",
            Self::Swap => "Swap",
            Self::UserSsh => "Users & SSH",
            Self::Ufw => "UFW Firewall",
            Self::Docker => "Docker",
            Self::Mise => "Language Runtimes (mise)",
            Self::Fail2Ban => "Fail2Ban",
            Self::UnattendedUpgrades => "Auto Security Updates",
            Self::Tailscale => "Tailscale",
            Self::CloudflareHttp => "Cloudflare-only HTTP/S",
            Self::SysctlHardening => "Kernel Hardening",
            Self::Hostname => "Hostname",
            Self::Timezone => "Timezone",
            Self::Dokploy => "Dokploy",
            Self::Coolify => "Coolify",
            Self::Caddy => "Caddy",
            Self::Nginx => "NGINX",
            Self::Traefik => "Traefik",
            Self::CloudflareTunnel => "Cloudflare Tunnel",
            Self::Wireguard => "WireGuard",
            Self::Restic => "Restic",
            Self::Borg => "BorgBackup",
            Self::Rclone => "Rclone",
            Self::NodeExporter => "Node Exporter",
            Self::UptimeKuma => "Uptime Kuma",
            Self::Netdata => "Netdata",
            Self::Prometheus => "Prometheus",
            Self::Grafana => "Grafana",
            Self::DbDump => "Database Dump",
            Self::PluginRecipe => "Plugin Recipe",
        }
    }

    pub fn category(&self) -> Category {
        match self {
            Self::SystemUpdate | Self::Swap | Self::Hostname | Self::Timezone | Self::UnattendedUpgrades => Category::SystemBasics,
            Self::UserSsh => Category::UsersAndSsh,
            Self::Ufw | Self::Fail2Ban | Self::CloudflareHttp | Self::SysctlHardening => Category::FirewallAndSecurity,
            Self::Mise => Category::DeveloperRuntimes,
            Self::Docker => Category::Containers,
            Self::Tailscale | Self::CloudflareTunnel | Self::Wireguard => Category::Networking,
            Self::Dokploy | Self::Coolify => Category::ServerManagers,
            Self::Caddy | Self::Nginx | Self::Traefik => Category::ReverseProxy,
            Self::Restic | Self::Borg | Self::Rclone | Self::DbDump => Category::Backup,
            Self::NodeExporter | Self::UptimeKuma | Self::Netdata | Self::Prometheus | Self::Grafana => Category::Monitoring,
            Self::PluginRecipe => Category::Plugins,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Category {
    SystemBasics,
    UsersAndSsh,
    FirewallAndSecurity,
    DeveloperRuntimes,
    Containers,
    Networking,
    ServerManagers,
    ReverseProxy,
    Backup,
    Monitoring,
    Plugins,
}

impl Category {
    pub fn label(&self) -> &'static str {
        match self {
            Self::SystemBasics => "System Basics",
            Self::UsersAndSsh => "Users & SSH",
            Self::FirewallAndSecurity => "Firewall & Security",
            Self::DeveloperRuntimes => "Developer Runtimes",
            Self::Containers => "Containers",
            Self::Networking => "Networking",
            Self::ServerManagers => "Server Managers",
            Self::ReverseProxy => "Reverse Proxy",
            Self::Backup => "Backup",
            Self::Monitoring => "Monitoring",
            Self::Plugins => "Plugins",
        }
    }

    pub fn all() -> &'static [Category] {
        &[
            Category::SystemBasics,
            Category::UsersAndSsh,
            Category::FirewallAndSecurity,
            Category::DeveloperRuntimes,
            Category::Containers,
            Category::Networking,
            Category::ServerManagers,
            Category::ReverseProxy,
            Category::Backup,
            Category::Monitoring,
            Category::Plugins,
        ]
    }
}

#[derive(Debug, Clone)]
pub struct ModuleState {
    pub id: ModuleId,
    pub selected: bool,
    pub expanded: bool,
    pub status: ModuleStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleStatus {
    Idle,
    Pending,
    Running,
    Done,
    Failed,
    Skipped,
}

#[derive(Debug, Clone)]
pub struct SelectionState {
    pub modules: BTreeMap<ModuleId, ModuleState>,
}

impl Default for SelectionState {
    fn default() -> Self {
        Self::new()
    }
}

impl SelectionState {
    pub fn new() -> Self {
        let modules = ModuleId::all()
            .iter()
            .map(|id| {
                (
                    *id,
                    ModuleState {
                        id: *id,
                        selected: false,
                        expanded: false,
                        status: ModuleStatus::Idle,
                    },
                )
            })
            .collect();
        Self { modules }
    }

    pub fn toggle(&mut self, id: ModuleId) {
        if let Some(m) = self.modules.get_mut(&id) {
            m.selected = !m.selected;
        }
    }

    pub fn select_all(&mut self) {
        for m in self.modules.values_mut() {
            m.selected = true;
        }
    }

    pub fn select_none(&mut self) {
        for m in self.modules.values_mut() {
            m.selected = false;
        }
    }

    pub fn invert(&mut self) {
        for m in self.modules.values_mut() {
            m.selected = !m.selected;
        }
    }

    pub fn selected_ids(&self) -> Vec<ModuleId> {
        self.modules
            .values()
            .filter(|m| m.selected)
            .map(|m| m.id)
            .collect()
    }

    pub fn set_from_profile(&mut self, ids: &[ModuleId]) {
        self.select_none();
        for id in ids {
            if let Some(m) = self.modules.get_mut(id) {
                m.selected = true;
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Screen {
    Welcome,
    ProfileSelect,
    ModuleSelect,
    Configure,
    Preflight,
    Apply,
    Summary,
    Help,
    Palette,
    Search,
    Confirm(ConfirmSpec),
}

impl Screen {
    pub fn is_overlay(&self) -> bool {
        matches!(self, Screen::Help | Screen::Palette | Screen::Search | Screen::Confirm(_))
    }

    pub fn title(&self) -> &'static str {
        match self {
            Screen::Welcome => "Welcome",
            Screen::ProfileSelect => "Profile Selection",
            Screen::ModuleSelect => "Module Selection",
            Screen::Configure => "Configuration",
            Screen::Preflight => "Preflight Check",
            Screen::Apply => "Apply",
            Screen::Summary => "Summary",
            Screen::Help => "Help",
            Screen::Palette => "Command Palette",
            Screen::Search => "Search",
            Screen::Confirm(_) => "Confirm",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConfirmSpec {
    pub action_label: &'static str,
    pub description: &'static str,
    pub confirm_label: &'static str,
    pub cancel_label: &'static str,
    pub is_destructive: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FocusId {
    ProfileList,
    ModuleList,
    Sidebar,
    ModuleCard,
    Form(FormField),
    ConfirmDialog,
    PaletteInput,
    SearchInput,
    HelpContent,
    StatusBar,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FormField {
    Username,
    SshPublicKey,
    SwapSize,
    SshPort,
    Hostname,
    Timezone,
}

#[derive(Debug, Clone)]
pub struct FormData {
    pub fields: HashMap<FormField, String>,
    pub errors: HashMap<FormField, String>,
}

impl Default for FormData {
    fn default() -> Self {
        Self::new()
    }
}

impl FormData {
    pub fn new() -> Self {
        Self {
            fields: HashMap::new(),
            errors: HashMap::new(),
        }
    }

    pub fn get(&self, field: FormField) -> &str {
        self.fields.get(&field).map(|s| s.as_str()).unwrap_or("")
    }

    pub fn set(&mut self, field: FormField, value: String) {
        self.fields.insert(field, value);
        self.errors.remove(&field);
    }

    pub fn validate(&mut self, field: FormField, validator: fn(&str) -> Result<(), String>) {
        if let Some(value) = self.fields.get(&field)
            && let Err(e) = validator(value) {
                self.errors.insert(field, e);
            }
    }

    pub fn validate_all(&mut self) -> HashMap<FormField, String> {
        let validators = crate::tui::forms::validators();
        self.errors.clear();
        for (field, validator) in &validators {
            if let Some(value) = self.fields.get(field)
                && let Err(e) = validator(value) {
                    self.errors.insert(*field, e);
                }
        }
        self.errors.clone()
    }
}

#[derive(Debug, Clone)]
pub struct Toast {
    pub message: String,
    pub kind: ToastKind,
    pub created_at: std::time::Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToastKind {
    Info,
    Success,
    Warning,
    Error,
}

#[derive(Debug, Clone)]
pub struct LogLine {
    pub timestamp: std::time::Instant,
    pub module_id: Option<ModuleId>,
    pub level: LogLevel,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone)]
pub struct SystemInfo {
    pub os_name: String,
    pub os_version: String,
    pub is_root: bool,
    pub current_user: String,
    pub public_ip: Option<String>,
    pub memory_mb: u64,
    pub disk_gb: u64,
    pub existing_tools: Vec<String>,
    pub has_systemd: bool,
}

impl Default for SystemInfo {
    fn default() -> Self {
        Self {
            os_name: String::new(),
            os_version: String::new(),
            is_root: false,
            current_user: String::new(),
            public_ip: None,
            memory_mb: 0,
            disk_gb: 0,
            existing_tools: Vec::new(),
            has_systemd: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub actions: Vec<PlanAction>,
    pub generated_at: std::time::Instant,
}

#[derive(Debug, Clone)]
pub struct PlanAction {
    pub module_id: ModuleId,
    pub label: String,
    pub status: PlanActionStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanActionStatus {
    Pending,
    Running,
    Done,
    Failed,
    Skipped,
}

#[derive(Debug, Clone)]
pub enum RunState {
    Idle,
    Active {
        current_step: usize,
        total_steps: usize,
        cancel_token_id: u64,
    },
    Done(Outcome),
}

#[derive(Debug, Clone)]
pub enum Outcome {
    Success,
    PartialSuccess { failed: Vec<ModuleId> },
    Failed { error: String },
    Cancelled,
}

#[derive(Debug, Clone)]
pub enum ProgressEvent {
    StepStart { action_idx: usize, label: String },
    StepLog { action_idx: usize, line: String },
    StepDone { action_idx: usize, exit_code: i32, duration_ms: u64 },
    StepFail { action_idx: usize, error: String },
}

#[derive(Debug, Clone)]
pub struct RingBuffer<T> {
    data: VecDeque<T>,
    cap: usize,
}

impl<T> RingBuffer<T> {
    pub fn new(cap: usize) -> Self {
        Self {
            data: VecDeque::with_capacity(cap),
            cap,
        }
    }

    pub fn push(&mut self, item: T) {
        if self.data.len() == self.cap {
            self.data.pop_front();
        }
        self.data.push_back(item);
    }

    pub fn iter(&self) -> std::collections::vec_deque::Iter<'_, T> {
        self.data.iter()
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn last(&self) -> Option<&T> {
        self.data.back()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaletteCmd {
    Plan,
    Apply,
    DryRun,
    Save,
    Load,
    Reset,
    Theme,
    Log,
    Export,
    Quit,
}

impl PaletteCmd {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Plan => ":plan",
            Self::Apply => ":apply",
            Self::DryRun => ":dry-run",
            Self::Save => ":save",
            Self::Load => ":load",
            Self::Reset => ":reset",
            Self::Theme => ":theme",
            Self::Log => ":log",
            Self::Export => ":export",
            Self::Quit => ":quit",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Plan => "Preview plan",
            Self::Apply => "Run apply",
            Self::DryRun => "Run in dry-run mode",
            Self::Save => "Save config",
            Self::Load => "Load config",
            Self::Reset => "Reset to profile defaults",
            Self::Theme => "Switch theme",
            Self::Log => "Toggle log panel",
            Self::Export => "Export plan",
            Self::Quit => "Quit",
        }
    }

    pub fn all() -> &'static [PaletteCmd] {
        &[
            PaletteCmd::Plan,
            PaletteCmd::Apply,
            PaletteCmd::DryRun,
            PaletteCmd::Save,
            PaletteCmd::Load,
            PaletteCmd::Reset,
            PaletteCmd::Theme,
            PaletteCmd::Log,
            PaletteCmd::Export,
            PaletteCmd::Quit,
        ]
    }
}

pub struct Model {
    pub screen_stack: Vec<Screen>,
    pub system: SystemInfo,
    pub profile: Option<Profile>,
    pub selection: SelectionState,
    pub forms: FormData,
    pub plan: Option<Plan>,
    pub run: RunState,
    pub log: RingBuffer<LogLine>,
    pub toasts: VecDeque<Toast>,
    pub theme: Theme,
    pub caps: TerminalCaps,
    pub focus: FocusId,
    pub needs_render: bool,
    pub should_quit: bool,
    pub reduced_motion: bool,
    pub search_query: Option<String>,
    pub palette_query: Option<String>,
    pub dry_run: bool,
    pub list_scroll: usize,
    pub log_panel_visible: bool,
    pub follow_tail: bool,
    pub category_collapsed: HashMap<Category, bool>,
    pub pending_confirm: Option<PendingConfirmAction>,
    pub confirm_focused_confirm: bool,
    pub reboot_required: bool,
    pub screen_states: HashMap<Screen, ScreenState>,
    pub ssh_verify_phase: Option<SshVerifyPhase>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingConfirmAction {
    Quit,
    ApplyPlan,
    CancelInstall,
    EnableUfw,
    DisableRootSsh,
    DisablePasswordSsh,
    EnableCloudflareHttp,
    ChangeSshPort,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Default)]
pub enum ScreenState {
    #[default]
    Loading,
    Empty,
    Error(String),
    Ready,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshVerifyPhase {
    CreateUser,
    AddKey,
    TestConnect,
    HardenedConfig,
    ReloadSshd,
    VerifyConnect,
    Complete,
}

impl Model {
    pub fn initial(caps: TerminalCaps) -> Self {
        let theme = Theme::new(&caps);
        let reduced_motion = std::env::var("TORIDE_NO_ANIM")
            .map(|v| v == "1")
            .unwrap_or(false);

        Self {
            screen_stack: vec![Screen::Welcome],
            system: SystemInfo::default(),
            profile: None,
            selection: SelectionState::new(),
            forms: FormData::new(),
            plan: None,
            run: RunState::Idle,
            log: RingBuffer::new(5000),
            toasts: VecDeque::new(),
            theme,
            caps,
            focus: FocusId::ProfileList,
            needs_render: true,
            should_quit: false,
            reduced_motion,
            search_query: None,
            palette_query: None,
            dry_run: false,
            list_scroll: 0,
            log_panel_visible: false,
            follow_tail: true,
            category_collapsed: HashMap::new(),
            pending_confirm: None,
            confirm_focused_confirm: false,
            reboot_required: false,
            screen_states: HashMap::new(),
            ssh_verify_phase: None,
        }
    }

    pub fn initial_for_test() -> Self {
        let caps = TerminalCaps::for_test();
        Self::initial(caps)
    }

    pub fn current_screen(&self) -> &Screen {
        self.screen_stack.last().unwrap_or(&Screen::Welcome)
    }

    pub fn push_screen(&mut self, screen: Screen) {
        self.screen_stack.push(screen);
        self.needs_render = true;
    }

    pub fn pop_screen(&mut self) {
        if self.screen_stack.len() > 1 {
            self.screen_stack.pop();
            self.needs_render = true;
        }
    }

    pub fn replace_screen(&mut self, screen: Screen) {
        if let Some(last) = self.screen_stack.last_mut() {
            *last = screen;
            self.needs_render = true;
        }
    }

    pub fn add_toast(&mut self, message: String, kind: ToastKind) {
        self.toasts.push_back(Toast {
            message,
            kind,
            created_at: std::time::Instant::now(),
        });
        if self.toasts.len() > 5 {
            self.toasts.pop_front();
        }
        self.needs_render = true;
    }

    pub fn dismiss_toast(&mut self) {
        self.toasts.pop_front();
        self.needs_render = true;
    }

    pub fn is_test_mode(&self) -> bool {
        std::env::var("TORIDE_E2E")
            .map(|v| v == "1")
            .unwrap_or(false)
    }
}
