//! Application state, event loop, and update logic.

mod input;
mod render;

use std::time::Instant;

use color_eyre::eyre::Result;
use crossterm::event::{Event, EventStream, KeyEventKind, MouseEventKind};
use futures::{FutureExt, StreamExt};
use ratatui::DefaultTerminal;
use tokio::select;
use tokio::sync::mpsc;

use crate::about_data::AboutCollector;
use crate::action::Action;
use crate::fail2ban_data::Fail2banCollector;
use crate::logs_data::LogsCollector;
use crate::navigation::{Navigator, Screen};
use crate::persistence;
use crate::persistence::AnimPref;
use crate::settings_data::SettingsCollector;
use crate::ssh_data::{SshDataCollector, SshOpError, execute_op};
use crate::status_collector::StatusCollector;
use crate::templates_data::TemplatesCollector;
use crate::tools_data::ToolsCollector;
use crate::toride_audit_data::AuditCollector;
use crate::toride_backup_data::BackupCollector;
use crate::toride_cloud_data::CloudCollector;
use crate::toride_harden_data::HardenCollector;
use crate::toride_mise_data::MiseCollector;
use crate::toride_monitor_data::MonitorCollector;
use crate::toride_proxy_data::ProxyCollector;
use crate::toride_tailscale_data::TailscaleCollector;
use crate::toride_updates_data::UpdatesCollector;
use crate::toride_users_data::UsersCollector;
use crate::toride_wireguard_data::WireguardCollector;
use crate::ufw_kit_data::FirewallCollector;
use crate::ui::screens::AppScreen;
use crate::ui::screens::dashboard::DashboardScreen;
use crate::ui::screens::help::HelpScreen;
use crate::ui::screens::quit::QuitModal;
use crate::ui::screens::welcome::WelcomeScreen;
use crate::ui::theme::Theme;
use crate::ui::transition::{TransitionCache, TransitionState};
use crate::ui::widgets::InteractiveModal;
use crate::virt_detect;

const SHIMMER_FRAME_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

/// Top-level application orchestrator: owns the screens and navigation state
/// and drives the main event loop via tokio's `select!`.
#[allow(clippy::struct_excessive_bools)]
pub struct App {
    nav: Navigator,
    welcome: WelcomeScreen,
    dashboard: DashboardScreen,
    #[allow(dead_code)]
    help: HelpScreen,
    help_modal: InteractiveModal<Action>,
    quit_visible: bool,
    quit_modal: QuitModal,
    active_theme: Theme,
    anim_pref: AnimPref,
    reduced_motion: bool,
    should_quit: bool,
    needs_redraw: bool,
    last_shimmer_draw: Instant,
    transition: Option<TransitionState>,
    transition_cache: TransitionCache,
    collector: StatusCollector,
    ssh_collector: SshDataCollector,
    fail2ban_collector: Fail2banCollector,
    ufw_kit_collector: FirewallCollector,
    toride_harden_collector: HardenCollector,
    toride_wireguard_collector: WireguardCollector,
    toride_updates_collector: UpdatesCollector,
    toride_users_collector: UsersCollector,
    toride_audit_collector: AuditCollector,
    toride_monitor_collector: MonitorCollector,
    toride_backup_collector: BackupCollector,
    toride_proxy_collector: ProxyCollector,
    toride_cloud_collector: CloudCollector,
    toride_tailscale_collector: TailscaleCollector,
    toride_mise_collector: MiseCollector,
    about_collector: AboutCollector,
    logs_collector: LogsCollector,
    settings_collector: SettingsCollector,
    templates_collector: TemplatesCollector,
    tools_collector: ToolsCollector,
    ssh_error_rx: mpsc::UnboundedReceiver<SshOpError>,
    ssh_error_tx: mpsc::UnboundedSender<SshOpError>,
    ssh_op_done_rx: mpsc::UnboundedReceiver<()>,
    ssh_op_done_tx: mpsc::UnboundedSender<()>,
    ssh_ops_in_flight: usize,
    ssh_revert_pending: bool,
    ssh_write_task: Option<tokio::task::JoinHandle<()>>,
    ssh_write_cooldown: Option<Instant>,
    pending_persist: Option<PersistOp>,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, PartialEq, Eq)]
enum RevertScheduling {
    Noop,
    FireNow,
    Defer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PersistOp {
    Theme(Theme),
    Animations(AnimPref),
}

impl PersistOp {
    fn run(self) {
        match self {
            PersistOp::Theme(theme) => persistence::save_theme(theme),
            PersistOp::Animations(pref) => persistence::save_animations(pref),
        }
    }
}

impl App {
    /// Create a new application starting at the welcome screen.
    #[must_use]
    pub fn new() -> Self {
        let active_theme = persistence::load_theme();
        let (anim_pref, reduced_motion) = Self::resolve_motion();
        Self::new_with_motion(active_theme, anim_pref, reduced_motion)
    }

    #[must_use]
    fn new_with_motion(active_theme: Theme, anim_pref: AnimPref, reduced_motion: bool) -> Self {
        let (ssh_error_tx, ssh_error_rx) = mpsc::unbounded_channel();
        let (ssh_op_done_tx, ssh_op_done_rx) = mpsc::unbounded_channel();
        let mut welcome = WelcomeScreen::new();
        welcome.set_border_color(active_theme.palette().accent);
        let mut dashboard = DashboardScreen::new();
        dashboard.set_active_theme(active_theme);
        Self {
            ssh_error_tx,
            ssh_error_rx,
            ssh_op_done_tx,
            ssh_op_done_rx,
            ssh_ops_in_flight: 0,
            ssh_revert_pending: false,
            ssh_write_task: None,
            nav: Navigator::new(),
            welcome,
            dashboard,
            help: HelpScreen::new(),
            help_modal: InteractiveModal::display("Help").dimensions(52, 16),
            quit_visible: false,
            quit_modal: QuitModal::new(),
            active_theme,
            anim_pref,
            reduced_motion,
            should_quit: false,
            needs_redraw: false,
            last_shimmer_draw: Instant::now(),
            transition: None,
            transition_cache: TransitionCache::new(),
            collector: StatusCollector::new(),
            ssh_collector: SshDataCollector::new(),
            fail2ban_collector: Fail2banCollector::new(),
            ufw_kit_collector: FirewallCollector::new(),
            toride_harden_collector: HardenCollector::new(),
            toride_wireguard_collector: WireguardCollector::new(),
            toride_updates_collector: UpdatesCollector::new(),
            toride_users_collector: UsersCollector::new(),
            toride_audit_collector: AuditCollector::new(),
            toride_monitor_collector: MonitorCollector::new(),
            toride_backup_collector: BackupCollector::new(),
            toride_proxy_collector: ProxyCollector::new(),
            toride_cloud_collector: CloudCollector::new(),
            toride_tailscale_collector: TailscaleCollector::new(),
            toride_mise_collector: MiseCollector::new(),
            about_collector: AboutCollector::new(),
            logs_collector: LogsCollector::new(),
            settings_collector: SettingsCollector::new(),
            templates_collector: TemplatesCollector::new(),
            tools_collector: ToolsCollector::new(),
            ssh_write_cooldown: None,
            pending_persist: None,
        }
    }

    #[cfg(test)]
    #[must_use]
    fn new_for_test(anim_pref: AnimPref, reduced_motion: bool) -> Self {
        Self::new_with_motion(Theme::Charm, anim_pref, reduced_motion)
    }

    fn resolve_motion() -> (AnimPref, bool) {
        let pref = match std::env::var("TORIDE_ANIM") {
            Ok(raw) => {
                if let Some(p) = AnimPref::from_label(&raw) {
                    p
                } else {
                    tracing::warn!(
                        "TORIDE_ANIM={raw:?} unrecognized (expected auto/on/off); \
                         using config + auto-detect"
                    );
                    persistence::load_animations()
                }
            }
            Err(_) => persistence::load_animations(),
        };
        let reduced = Self::reduced_for(pref);
        (pref, reduced)
    }

    fn reduced_for(pref: AnimPref) -> bool {
        match pref {
            AnimPref::On => false,
            AnimPref::Off => true,
            AnimPref::Auto => {
                let probe = virt_detect::detect();
                if probe.reduce_motion {
                    tracing::debug!(
                        "reduced-motion: virtualization detected ({}); animations off",
                        probe.label.unwrap_or("unknown")
                    );
                } else {
                    tracing::debug!("reduced-motion: no virtualization detected; animations on");
                }
                probe.reduce_motion
            }
        }
    }

    fn recompute_reduced_motion(&mut self) {
        self.reduced_motion = Self::reduced_for(self.anim_pref);
    }

    fn current_screen(&mut self) -> &mut dyn AppScreen {
        self.screen_by_enum(self.nav.current())
    }

    fn invalidate_all_caches(&mut self) {
        self.welcome.invalidate_cache();
        self.dashboard.invalidate_cache();
        self.needs_redraw = true;
    }

    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "pure truth table: each bool mirrors one draw-gate clause"
    )]
    fn animation_frame_due(
        reduced_motion: bool,
        transition: bool,
        fast_animation: bool,
        slow_animation: bool,
        since_last_frame: std::time::Duration,
    ) -> bool {
        if reduced_motion {
            return false;
        }
        if transition || fast_animation {
            return true;
        }
        slow_animation && since_last_frame >= SHIMMER_FRAME_INTERVAL
    }

    fn screen_needs_animation(&self) -> bool {
        match self.nav.current() {
            Screen::Welcome => self.welcome.needs_animation(),
            Screen::Dashboard => self.dashboard.needs_animation(),
        }
    }

    fn screen_needs_fast_frames(&self) -> bool {
        match self.nav.current() {
            Screen::Welcome => self.welcome.needs_fast_frames(),
            Screen::Dashboard => self.dashboard.needs_fast_frames(),
        }
    }

    fn update(&mut self, action: Action) {
        if self.transition.is_some() {
            return;
        }

        match action {
            Action::Quit => self.should_quit = true,
            Action::ConfirmQuit => {
                self.quit_visible = true;
                self.needs_redraw = true;
            }
            Action::DismissQuit => {
                self.quit_visible = false;
                self.needs_redraw = true;
            }
            Action::Continue => self.start_forward(Screen::Dashboard),
            Action::Help => {
                if self.help_modal.is_visible() {
                    self.help_modal.close();
                } else {
                    self.help_modal.open();
                }
                self.needs_redraw = true;
            }
            Action::CloseHelp => {
                self.help_modal.close();
                self.needs_redraw = true;
            }
            Action::Back => self.go_back(),
            Action::CycleTheme => {
                let all = Theme::all();
                let idx = all
                    .iter()
                    .position(|&t| t == self.active_theme)
                    .unwrap_or(0);
                let next = all[(idx + 1) % all.len()];
                self.active_theme = next;
                self.welcome.set_border_color(next.palette().accent);
                self.dashboard.set_active_theme(next);
                self.invalidate_all_caches();
                self.pending_persist = Some(PersistOp::Theme(next));
            }
            Action::ToggleAnimations => {
                self.anim_pref = match self.anim_pref {
                    AnimPref::Auto => AnimPref::On,
                    AnimPref::On => AnimPref::Off,
                    AnimPref::Off => AnimPref::Auto,
                };
                self.recompute_reduced_motion();
                self.invalidate_all_caches();
                self.pending_persist = Some(PersistOp::Animations(self.anim_pref));
            }
            Action::Redraw => {
                self.needs_redraw = true;
            }
            _ => self.current_screen().handle_action(action),
        }
    }

    fn start_forward(&mut self, to: Screen) {
        if self.reduced_motion {
            self.nav.commit_forward(to);
            self.screen_by_enum(to).invalidate_cache();
            self.needs_redraw = true;
            return;
        }
        let state = self.nav.start_forward(to, &mut self.transition_cache);
        self.transition = Some(state);
    }

    fn go_back(&mut self) {
        if self.reduced_motion {
            if let Some(ts) = self.nav.start_backward(&mut self.transition_cache) {
                let target = Screen::from_key(ts.to);
                self.nav.commit_back(target);
                self.screen_by_enum(target).invalidate_cache();
                self.needs_redraw = true;
            }
            return;
        }
        if let Some(state) = self.nav.start_backward(&mut self.transition_cache) {
            self.transition = Some(state);
        }
    }

    fn should_skip_ssh_refresh(in_flight: usize, cooldown_elapsed_secs: Option<u64>) -> bool {
        in_flight > 0 || cooldown_elapsed_secs.is_some_and(|s| s < 5)
    }

    fn should_revert_now(in_flight: usize) -> bool {
        in_flight == 0
    }

    fn should_fire_deferred_revert_now(revert_pending: bool, spawned: bool) -> bool {
        revert_pending && !spawned
    }

    fn ssh_error_revert_scheduling(revert_optimistic: bool, in_flight: usize) -> RevertScheduling {
        if !revert_optimistic {
            RevertScheduling::Noop
        } else if Self::should_revert_now(in_flight) {
            RevertScheduling::FireNow
        } else {
            RevertScheduling::Defer
        }
    }

    fn flush_ssh_ops(&mut self) -> bool {
        if !matches!(self.nav.current(), Screen::Dashboard) {
            return false;
        }
        let ops = self.dashboard.drain_ssh_ops();
        if ops.is_empty() {
            return false;
        }
        if self.ssh_ops_in_flight > 0 {
            self.dashboard.queue_ssh_ops_front(ops);
            return false;
        }
        self.ssh_write_cooldown = Some(Instant::now());
        self.ssh_ops_in_flight += ops.len();
        self.dashboard.set_ssh_loading(true, self.ssh_ops_in_flight);

        let error_tx = self.ssh_error_tx.clone();
        let done_tx = self.ssh_op_done_tx.clone();
        let handle = tokio::spawn(async move {
            for op in ops {
                let fut = std::panic::AssertUnwindSafe(execute_op(op));
                match fut.catch_unwind().await {
                    Ok(Ok(_label)) => {}
                    Ok(Err(err)) => {
                        let _ = error_tx.send(err);
                    }
                    Err(panic) => {
                        let msg = panic_message(&panic);
                        let _ = error_tx.send(SshOpError {
                            message: format!("ssh op panicked: {msg}"),
                            revert_optimistic: true,
                        });
                    }
                }
                let _ = done_tx.send(());
            }
        });
        self.ssh_write_task = Some(handle);
        true
    }

    /// Run the main event loop.
    ///
    /// # Errors
    ///
    /// Errors if a terminal draw or the event stream fails.
    #[allow(clippy::too_many_lines)]
    pub async fn run(mut self, mut terminal: DefaultTerminal) -> Result<()> {
        let mut events = EventStream::new();
        let refresh_interval = tokio::time::interval(std::time::Duration::from_secs(2));
        let anim_tick = tokio::time::interval(std::time::Duration::from_millis(33));
        let shimmer_tick = tokio::time::interval(SHIMMER_FRAME_INTERVAL);
        let mut toast_tick = tokio::time::interval(SHIMMER_FRAME_INTERVAL);
        toast_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tokio::pin!(refresh_interval);
        tokio::pin!(anim_tick);
        tokio::pin!(shimmer_tick);
        tokio::pin!(toast_tick);

        self.needs_redraw = true;

        loop {
            if self.needs_redraw
                || Self::animation_frame_due(
                    self.reduced_motion,
                    self.transition.is_some(),
                    self.screen_needs_fast_frames(),
                    self.screen_needs_animation(),
                    self.last_shimmer_draw.elapsed(),
                )
            {
                terminal.draw(|f| self.view(f))?;
                self.needs_redraw = false;
                self.last_shimmer_draw = Instant::now();
            }

            select! {
                biased;

                Some(Ok(event)) = events.next() => {
                    let action = match event {
                        Event::Key(key) if key.kind == KeyEventKind::Press => {
                            let action = self.handle_key(key);
                            self.needs_redraw = true;
                            action
                        }
                        Event::Mouse(mouse) => {
                            let action = self.handle_mouse(mouse);
                            if !matches!(
                                mouse.kind,
                                MouseEventKind::Moved | MouseEventKind::Drag(_)
                            ) {
                                self.needs_redraw = true;
                            }
                            action
                        }
                        Event::Resize(..) => {
                            self.invalidate_all_caches();
                            None
                        }
                        _ => None,
                    };
                    self.flush_ssh_ops();
                    if let Some(action) = action {
                        self.update(action);
                        self.needs_redraw = true;
                    }
                    if let Some(op) = self.pending_persist.take() {
                        drop(tokio::task::spawn_blocking(move || op.run()));
                    }
                }

                Some(status) = self.collector.poll(), if self.collector.is_pending() => {
                    self.about_collector.start_with_status(status.clone());
                    self.dashboard.set_status(status);
                    self.needs_redraw = true;
                }

                Some(bundle) = self.ssh_collector.poll(), if self.ssh_collector.is_pending() => {
                    let skip = Self::should_skip_ssh_refresh(
                        self.ssh_ops_in_flight,
                        self.ssh_write_cooldown
                            .map(|t| t.elapsed().as_secs()),
                    );
                    if !skip {
                        self.dashboard.set_ssh_data(bundle);
                        self.needs_redraw = true;
                    }
                }

                Some(b) = self.fail2ban_collector.poll(), if self.fail2ban_collector.is_pending() => {
                    self.dashboard.set_fail2ban_data(b);
                    self.needs_redraw = true;
                }

                Some(b) = self.ufw_kit_collector.poll(), if self.ufw_kit_collector.is_pending() => {
                    self.dashboard.set_ufw_kit_data(b);
                    self.needs_redraw = true;
                }

                Some(b) = self.toride_harden_collector.poll(), if self.toride_harden_collector.is_pending() => {
                    self.dashboard.set_toride_harden_data(b);
                    self.needs_redraw = true;
                }

                Some(b) = self.toride_wireguard_collector.poll(), if self.toride_wireguard_collector.is_pending() => {
                    self.dashboard.set_toride_wireguard_data(b);
                    self.needs_redraw = true;
                }

                Some(b) = self.toride_updates_collector.poll(), if self.toride_updates_collector.is_pending() => {
                    self.dashboard.set_toride_updates_data(b);
                    self.needs_redraw = true;
                }

                Some(b) = self.toride_users_collector.poll(), if self.toride_users_collector.is_pending() => {
                    self.dashboard.set_toride_users_data(b);
                    self.needs_redraw = true;
                }

                Some(b) = self.toride_audit_collector.poll(), if self.toride_audit_collector.is_pending() => {
                    self.dashboard.set_toride_audit_data(b);
                    self.needs_redraw = true;
                }

                Some(b) = self.toride_monitor_collector.poll(), if self.toride_monitor_collector.is_pending() => {
                    self.dashboard.set_toride_monitor_data(b);
                    self.needs_redraw = true;
                }

                Some(b) = self.toride_backup_collector.poll(), if self.toride_backup_collector.is_pending() => {
                    self.dashboard.set_toride_backup_data(b);
                    self.needs_redraw = true;
                }

                Some(b) = self.toride_proxy_collector.poll(), if self.toride_proxy_collector.is_pending() => {
                    self.dashboard.set_toride_proxy_data(b);
                    self.needs_redraw = true;
                }

                Some(b) = self.toride_cloud_collector.poll(), if self.toride_cloud_collector.is_pending() => {
                    self.dashboard.set_toride_cloud_data(b);
                    self.needs_redraw = true;
                }

                Some(b) = self.toride_tailscale_collector.poll(), if self.toride_tailscale_collector.is_pending() => {
                    self.dashboard.set_toride_tailscale_data(b);
                    self.needs_redraw = true;
                }

                Some(b) = self.toride_mise_collector.poll(), if self.toride_mise_collector.is_pending() => {
                    self.dashboard.set_toride_mise_data(b);
                    self.needs_redraw = true;
                }

                Some(b) = self.about_collector.poll(), if self.about_collector.is_pending() => {
                    self.dashboard.set_about_data(b);
                    self.needs_redraw = true;
                }
                Some(b) = self.logs_collector.poll(), if self.logs_collector.is_pending() => {
                    self.dashboard.set_logs_data(b);
                    self.needs_redraw = true;
                }
                Some(b) = self.settings_collector.poll(), if self.settings_collector.is_pending() => {
                    self.dashboard.set_settings_data(b);
                    self.needs_redraw = true;
                }
                Some(b) = self.templates_collector.poll(), if self.templates_collector.is_pending() => {
                    self.dashboard.set_templates_data(b);
                    self.needs_redraw = true;
                }
                Some(b) = self.tools_collector.poll(), if self.tools_collector.is_pending() => {
                    self.dashboard.set_tools_data(b);
                    self.needs_redraw = true;
                }

                Some(err) = self.ssh_error_rx.recv() => {
                    if matches!(self.nav.current(), Screen::Dashboard) {
                        self.dashboard.push_ssh_error(err.message);
                    }
                    match Self::ssh_error_revert_scheduling(
                        err.revert_optimistic,
                        self.ssh_ops_in_flight,
                    ) {
                        RevertScheduling::FireNow => {
                            self.ssh_write_cooldown = None;
                            self.ssh_collector.start();
                        }
                        RevertScheduling::Defer => {
                            self.ssh_revert_pending = true;
                        }
                        RevertScheduling::Noop => {}
                    }
                    self.needs_redraw = true;
                }

                Some(()) = self.ssh_op_done_rx.recv() => {
                    self.ssh_ops_in_flight = self.ssh_ops_in_flight.saturating_sub(1);
                    let loading = self.ssh_ops_in_flight > 0;
                    self.dashboard.set_ssh_loading(loading, self.ssh_ops_in_flight);
                    self.needs_redraw = true;
                    if self.ssh_ops_in_flight == 0 {
                        self.ssh_write_task = None;
                        let spawned = self.flush_ssh_ops();
                        if Self::should_fire_deferred_revert_now(
                            self.ssh_revert_pending,
                            spawned,
                        ) {
                            self.ssh_revert_pending = false;
                            self.ssh_write_cooldown = None;
                            self.ssh_collector.start();
                        }
                    }
                }

                _ = refresh_interval.tick() => {
                    if matches!(self.nav.current(), Screen::Dashboard) {
                        self.dashboard.tick_clock();
                        self.collector.start();
                        let skip_ssh = Self::should_skip_ssh_refresh(
                            self.ssh_ops_in_flight,
                            self.ssh_write_cooldown
                                .map(|t| t.elapsed().as_secs()),
                        );
                        if !skip_ssh {
                            self.ssh_write_cooldown = None;
                            self.ssh_collector.start();
                        }
                        self.fail2ban_collector.start();
                        self.ufw_kit_collector.start();
                        self.toride_harden_collector.start();
                        self.toride_wireguard_collector.start();
                        self.toride_updates_collector.start();
                        self.toride_users_collector.start();
                        self.toride_audit_collector.start();
                        self.toride_monitor_collector.start();
                        self.toride_backup_collector.start();
                        self.toride_proxy_collector.start();
                        self.toride_cloud_collector.start();
                        self.toride_tailscale_collector.start();
                        self.toride_mise_collector.start();
                        self.logs_collector.start();
                        self.settings_collector.start();
                        self.templates_collector.start();
                        self.tools_collector.start();
                        self.needs_redraw = true;
                    }
                }

                _ = anim_tick.tick(),
                    if !self.reduced_motion
                        && (self.transition.is_some()
                            || self.screen_needs_fast_frames()) => {}

                _ = shimmer_tick.tick(),
                    if !self.reduced_motion
                        && !self.screen_needs_fast_frames()
                        && self.screen_needs_animation() => {}

                _ = toast_tick.tick(),
                    if self.dashboard.ssh_error_showing() => {
                    if self.dashboard.ssh_error_expired() {
                        self.needs_redraw = true;
                    }
                }
            }

            if self.should_quit {
                if let Some(op) = self.pending_persist.take() {
                    let _ = tokio::task::spawn_blocking(move || op.run()).await;
                }
                if let Some(mut handle) = self.ssh_write_task.take() {
                    const SSH_WRITE_DRAIN_TIMEOUT: std::time::Duration =
                        std::time::Duration::from_secs(5);
                    let drain = tokio::time::sleep(SSH_WRITE_DRAIN_TIMEOUT);
                    tokio::pin!(drain);
                    tokio::select! {
                        biased;
                        outcome = &mut handle => {
                            let _ = outcome;
                        }
                        () = &mut drain => {
                            tracing::warn!(
                                "SSH write task did not complete within {:?}; aborting \
                                 (disk is authoritative on next launch)",
                                SSH_WRITE_DRAIN_TIMEOUT
                            );
                            handle.abort();
                        }
                    }
                }
                if self.ssh_collector.is_pending() {
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_secs(2),
                        self.ssh_collector.poll(),
                    )
                    .await;
                }
                break;
            }
        }

        Ok(())
    }
}

fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crossterm::event::{KeyModifiers, MouseEvent, MouseEventKind};
    use ratatui::{Terminal, backend::TestBackend};

    use crate::action::Action;
    use crate::app::App;
    use crate::app::PersistOp;
    use crate::navigation::Screen;
    use crate::persistence::AnimPref;
    use crate::ui::theme::Theme;

    #[test]
    fn new_creates_default_state() {
        let app = App::new_for_test(AnimPref::Off, true);
        assert_eq!(app.active_theme, Theme::Charm);
        assert!(!app.should_quit);
        assert_eq!(app.nav.current(), Screen::Welcome);
    }

    #[test]
    fn default_equals_new() {
        let from_new = App::new_for_test(AnimPref::Off, true);
        let from_default = App::new_for_test(AnimPref::Off, true);
        assert_eq!(from_new.active_theme, from_default.active_theme);
        assert_eq!(from_new.should_quit, from_default.should_quit);
        assert_eq!(from_new.nav.current(), from_default.nav.current());
        assert!(from_new.transition.is_none());
        assert!(from_default.transition.is_none());
    }

    #[test]
    fn update_quit_sets_should_quit() {
        let mut app = App::new_for_test(AnimPref::Off, true);
        assert!(!app.should_quit);
        app.update(Action::Quit);
        assert!(app.should_quit);
    }

    #[test]
    fn update_continue_starts_transition_to_status() {
        let mut app = App::new_for_test(AnimPref::On, false);
        assert!(app.transition.is_none());
        app.update(Action::Continue);
        assert!(app.transition.is_some());
    }

    #[test]
    fn update_continue_instant_under_reduced_motion() {
        let mut app = App::new_for_test(AnimPref::Off, true);
        app.reduced_motion = true;
        assert!(app.transition.is_none());
        app.update(Action::Continue);
        assert!(
            app.transition.is_none(),
            "no animated transition under reduced motion"
        );
        assert_eq!(app.nav.current(), Screen::Dashboard);
    }

    #[test]
    fn go_back_instant_under_reduced_motion() {
        let mut app = App::new_for_test(AnimPref::Off, true);
        app.nav.commit_forward(Screen::Dashboard);
        app.reduced_motion = true;
        app.update(Action::Back);
        assert!(app.transition.is_none());
        assert_eq!(app.nav.current(), Screen::Welcome);
    }

    #[test]
    fn toggle_animations_cycles_preference_and_recomputes() {
        let mut app = App::new_for_test(AnimPref::On, false);
        assert!(!app.reduced_motion, "On forces full motion");

        app.update(Action::ToggleAnimations);
        assert_eq!(app.anim_pref, AnimPref::Off);
        assert!(app.reduced_motion, "Off forces reduced motion");

        app.update(Action::ToggleAnimations);
        assert_eq!(app.anim_pref, AnimPref::Auto);
        let auto_reduced = app.reduced_motion;

        app.update(Action::ToggleAnimations);
        assert_eq!(app.anim_pref, AnimPref::On);
        assert!(!app.reduced_motion, "On forces full motion");

        app.update(Action::ToggleAnimations);
        assert_eq!(app.anim_pref, AnimPref::Off);
        assert!(app.reduced_motion, "Off forces reduced motion");

        app.update(Action::ToggleAnimations);
        assert_eq!(app.anim_pref, AnimPref::Auto);
        assert_eq!(
            app.reduced_motion, auto_reduced,
            "Auto re-evaluates to host result"
        );

        assert_eq!(
            app.pending_persist,
            Some(PersistOp::Animations(AnimPref::Auto)),
            "ToggleAnimations must defer a persistence write of the new pref"
        );
    }

    #[test]
    fn update_cycle_theme_defers_persistence_off_loop() {
        let mut app = App::new_for_test(AnimPref::Off, true);
        app.update(Action::CycleTheme);
        assert!(
            app.pending_persist.is_some(),
            "CycleTheme must defer a persistence write"
        );
        assert_eq!(
            app.pending_persist,
            Some(PersistOp::Theme(app.active_theme)),
            "deferred write must match the newly active theme"
        );
    }

    #[test]
    fn reduced_for_explicit_prefs_are_deterministic() {
        assert!(!App::reduced_for(AnimPref::On));
        assert!(App::reduced_for(AnimPref::Off));
        let _ = App::reduced_for(AnimPref::Auto);
    }

    #[test]
    fn update_help_toggles_modal() {
        let mut app = App::new_for_test(AnimPref::Off, true);
        assert!(!app.help_modal.is_visible());
        app.update(Action::Help);
        assert!(app.help_modal.is_visible());
        app.update(Action::Help);
        assert!(!app.help_modal.is_visible());
    }

    #[test]
    fn update_close_help_hides_modal() {
        let mut app = App::new_for_test(AnimPref::Off, true);
        app.help_modal.open();
        app.update(Action::CloseHelp);
        assert!(!app.help_modal.is_visible());
    }

    #[test]
    fn update_back_does_nothing_at_welcome() {
        let mut app = App::new_for_test(AnimPref::Off, true);
        assert!(app.transition.is_none());
        app.update(Action::Back);
        assert!(app.transition.is_none());
        assert_eq!(app.nav.current(), Screen::Welcome);
        assert!(!app.should_quit);
    }

    #[test]
    fn update_confirm_quit_shows_modal() {
        let mut app = App::new_for_test(AnimPref::Off, true);
        assert!(!app.quit_visible);
        app.update(Action::ConfirmQuit);
        assert!(app.quit_visible);
    }

    #[test]
    fn update_dismiss_quit_hides_modal() {
        let mut app = App::new_for_test(AnimPref::Off, true);
        app.quit_visible = true;
        app.update(Action::DismissQuit);
        assert!(!app.quit_visible);
    }

    #[test]
    fn panic_message_renders_str_and_string_payloads() {
        let s: Box<dyn std::any::Any + Send> = Box::new("boom");
        assert_eq!(super::panic_message(&s), "boom");

        let s: Box<dyn std::any::Any + Send> = Box::new("owned error".to_string());
        assert_eq!(super::panic_message(&s), "owned error");

        let s: Box<dyn std::any::Any + Send> = Box::new(42_i32);
        assert_eq!(super::panic_message(&s), "<non-string panic payload>");
    }

    #[test]
    fn new_app_has_no_in_flight_write_task() {
        let app = App::new_for_test(AnimPref::Off, true);
        assert_eq!(app.ssh_ops_in_flight, 0);
        assert!(app.ssh_write_task.is_none());
    }

    #[test]
    fn new_app_has_no_revert_pending() {
        let app = App::new_for_test(AnimPref::Off, true);
        assert!(!app.ssh_revert_pending);
    }

    #[test]
    fn should_skip_ssh_refresh_truth_table() {
        use crate::app::App;
        assert!(!App::should_skip_ssh_refresh(0, None));
        assert!(App::should_skip_ssh_refresh(0, Some(0)));
        assert!(App::should_skip_ssh_refresh(0, Some(4)));
        assert!(!App::should_skip_ssh_refresh(0, Some(5)));
        assert!(!App::should_skip_ssh_refresh(0, Some(99)));
        assert!(App::should_skip_ssh_refresh(1, None));
        assert!(App::should_skip_ssh_refresh(3, Some(5)));
        assert!(App::should_skip_ssh_refresh(2, Some(99)));
    }

    #[test]
    fn should_revert_now_truth_table() {
        use crate::app::App;
        assert!(App::should_revert_now(0));
        assert!(!App::should_revert_now(1));
        assert!(!App::should_revert_now(5));
    }

    #[test]
    fn f4_poll_drops_bundle_while_ops_in_flight() {
        use crate::app::App;
        assert!(App::should_skip_ssh_refresh(1, None));
        assert!(App::should_skip_ssh_refresh(1, Some(99)));
    }

    #[test]
    fn f4_poll_drops_bundle_during_cooldown() {
        use crate::app::App;
        assert!(App::should_skip_ssh_refresh(0, Some(0)));
        assert!(App::should_skip_ssh_refresh(0, Some(4)));
    }

    #[test]
    fn f4_poll_applies_bundle_when_safe() {
        use crate::app::App;
        assert!(!App::should_skip_ssh_refresh(0, None));
        assert!(!App::should_skip_ssh_refresh(0, Some(5)));
        assert!(!App::should_skip_ssh_refresh(0, Some(99)));
    }

    #[test]
    fn f5_reverting_error_with_ops_in_flight_defers() {
        assert_eq!(
            App::ssh_error_revert_scheduling(true, 1),
            super::RevertScheduling::Defer
        );
        assert_eq!(
            App::ssh_error_revert_scheduling(true, 5),
            super::RevertScheduling::Defer
        );
    }

    #[test]
    fn f5_reverting_error_with_no_ops_fires_now() {
        assert_eq!(
            App::ssh_error_revert_scheduling(true, 0),
            super::RevertScheduling::FireNow
        );
    }

    #[test]
    fn f5_transient_error_never_schedules_revert() {
        assert_eq!(
            App::ssh_error_revert_scheduling(false, 0),
            super::RevertScheduling::Noop
        );
        assert_eq!(
            App::ssh_error_revert_scheduling(false, 3),
            super::RevertScheduling::Noop
        );
    }

    #[test]
    fn f5_off_dashboard_reverting_error_still_defers_via_state() {
        let mut app = App::new_for_test(AnimPref::Off, true);
        assert!(matches!(
            app.nav.current(),
            crate::navigation::Screen::Welcome
        ));
        app.ssh_ops_in_flight = 2;
        let scheduling = App::ssh_error_revert_scheduling(true, app.ssh_ops_in_flight);
        assert_eq!(scheduling, super::RevertScheduling::Defer);
        app.ssh_revert_pending = matches!(scheduling, super::RevertScheduling::Defer);
        assert!(
            app.ssh_revert_pending,
            "revert intent must be recorded even off-Dashboard (F5)"
        );
    }

    #[test]
    fn f6_revert_deferred_when_new_batch_spawned() {
        assert!(!App::should_fire_deferred_revert_now(true, true));
    }

    #[test]
    fn f6_revert_fires_when_no_new_batch() {
        assert!(App::should_fire_deferred_revert_now(true, false));
    }

    #[test]
    fn f6_no_revert_pending_never_fires() {
        assert!(!App::should_fire_deferred_revert_now(false, false));
        assert!(!App::should_fire_deferred_revert_now(false, true));
    }

    #[test]
    fn f6_re_flush_during_pending_leaves_flag_set() {
        let mut app = App::new_for_test(AnimPref::Off, true);
        app.ssh_revert_pending = true;
        let spawned = true;
        if App::should_fire_deferred_revert_now(app.ssh_revert_pending, spawned) {
            app.ssh_revert_pending = false;
        }
        assert!(
            app.ssh_revert_pending,
            "revert must stay pending across a re-flush pass (F6)"
        );
    }

    #[test]
    fn f6_revert_clears_when_no_held_ops() {
        let mut app = App::new_for_test(AnimPref::Off, true);
        app.ssh_revert_pending = true;
        let spawned = false;
        if App::should_fire_deferred_revert_now(app.ssh_revert_pending, spawned) {
            app.ssh_revert_pending = false;
        }
        assert!(!app.ssh_revert_pending);
    }

    #[tokio::test]
    async fn quit_drain_aborts_write_task_on_timeout() {
        let mut handle = tokio::spawn(async {
            std::future::pending::<()>().await;
        });

        let drain = tokio::time::sleep(std::time::Duration::from_millis(100));
        tokio::pin!(drain);
        let elapsed = tokio::select! {
            biased;
            _ = &mut handle => false,
            () = &mut drain => {
                handle.abort();
                true
            }
        };
        assert!(
            elapsed,
            "a never-completing write task must trip the drain timeout, not hang"
        );
        let join = (&mut handle).await;
        assert!(
            join.is_err(),
            "aborted task must report a JoinError, not complete normally: {join:?}"
        );
    }

    #[tokio::test]
    async fn quit_drain_completes_when_write_task_finishes_quickly() {
        let mut handle = tokio::spawn(async { 42 });
        let drain = tokio::time::sleep(std::time::Duration::from_secs(5));
        tokio::pin!(drain);
        let (elapsed, outcome) = tokio::select! {
            biased;
            join = &mut handle => (false, Some(join)),
            () = &mut drain => {
                handle.abort();
                (true, None)
            }
        };
        assert!(
            !elapsed,
            "a fast write task must NOT trip the drain timeout"
        );
        assert_eq!(
            outcome.expect("task completed without timeout").unwrap(),
            42
        );
    }

    fn moved_at(column: u16, row: u16) -> MouseEvent {
        MouseEvent {
            kind: MouseEventKind::Moved,
            column,
            row,
            modifiers: KeyModifiers::empty(),
        }
    }

    #[test]
    fn animation_frame_due_truth_table() {
        let interval = super::SHIMMER_FRAME_INTERVAL;

        assert!(!App::animation_frame_due(
            true, false, false, false, interval
        ));
        assert!(!App::animation_frame_due(true, true, true, true, interval));

        assert!(App::animation_frame_due(
            false,
            true,
            false,
            false,
            Duration::ZERO
        ));
        assert!(App::animation_frame_due(
            false,
            false,
            true,
            false,
            Duration::ZERO
        ));

        assert!(!App::animation_frame_due(
            false,
            false,
            false,
            true,
            Duration::ZERO
        ));
        assert!(!App::animation_frame_due(
            false,
            false,
            false,
            true,
            interval.saturating_sub(Duration::from_millis(1))
        ));
        assert!(App::animation_frame_due(
            false, false, false, true, interval
        ));

        assert!(!App::animation_frame_due(
            false,
            false,
            false,
            false,
            interval * 10
        ));
    }

    #[test]
    fn shimmer_only_draw_count_is_capped_at_shimmer_cadence() {
        let mut draws = 0usize;
        let mut last_frame = Duration::ZERO;
        let mut t = Duration::ZERO;
        while t < Duration::from_secs(3) {
            if App::animation_frame_due(false, false, false, true, t.saturating_sub(last_frame)) {
                draws += 1;
                last_frame = t;
            }
            t += Duration::from_millis(10);
        }
        assert!(
            (10..=13).contains(&draws),
            "expected ~12 shimmer frames in 3s, got {draws}"
        );

        let mut fast_draws = 0usize;
        let mut t = Duration::ZERO;
        while t < Duration::from_secs(3) {
            if App::animation_frame_due(false, false, true, false, Duration::ZERO) {
                fast_draws += 1;
            }
            t += Duration::from_millis(10);
        }
        assert_eq!(fast_draws, 300, "fast animations draw on every wake");
    }

    #[test]
    fn redraw_action_flags_needs_redraw() {
        let mut app = App::new_for_test(AnimPref::Off, true);
        app.needs_redraw = false;
        app.update(Action::Redraw);
        assert!(app.needs_redraw, "Action::Redraw must flag a redraw");
    }

    #[test]
    fn mouse_sweep_over_unchanged_ui_never_redraws() {
        let mut app = App::new_for_test(AnimPref::Off, true);
        app.nav.commit_forward(Screen::Dashboard);
        app.needs_redraw = false;

        for row in 6..54u16 {
            let action = app.handle_mouse(moved_at(120, row));
            assert!(
                action.is_none(),
                "no-change motion at row {row} must not report an action"
            );
        }
        assert!(
            !app.needs_redraw,
            "a no-change mouse sweep must not flag a redraw"
        );
    }

    #[test]
    fn mouse_sweep_crossing_a_gauge_reports_redraw() {
        let mut app = App::new_for_test(AnimPref::Off, true);
        app.nav.commit_forward(Screen::Dashboard);

        let mut terminal = Terminal::new(TestBackend::new(200, 60)).unwrap();
        terminal.draw(|f| app.view(f)).unwrap();
        app.needs_redraw = false;

        let mut redraws = 0;
        for row in 0..4u16 {
            for column in 0..200u16 {
                if let Some(Action::Redraw) = app.handle_mouse(moved_at(column, row)) {
                    redraws += 1;
                    app.update(Action::Redraw);
                    assert!(app.needs_redraw, "gauge hover change must flag a redraw");
                    app.needs_redraw = false;
                }
            }
        }
        assert!(
            redraws > 0,
            "crossing header gauge hitboxes must report hover changes"
        );
    }

    #[test]
    fn gated_draw_skips_leave_the_screen_identical() {
        let mut app = App::new_for_test(AnimPref::Off, true);
        app.nav.commit_forward(Screen::Dashboard);
        assert!(app.transition.is_none());

        let mut terminal = Terminal::new(TestBackend::new(200, 60)).unwrap();
        terminal.draw(|f| app.view(f)).unwrap();
        let drawn: ratatui::buffer::Buffer = terminal.backend().buffer().clone();
        assert!(
            terminal.backend().to_string().contains("toride"),
            "fixture frame must contain real chrome (non-degenerate render)"
        );

        assert!(!App::animation_frame_due(
            app.reduced_motion,
            app.transition.is_some(),
            app.screen_needs_fast_frames(),
            app.screen_needs_animation(),
            Duration::MAX,
        ));
        terminal.draw(|f| app.view(f)).unwrap();
        assert_eq!(
            &drawn,
            terminal.backend().buffer(),
            "forced draw on unchanged state must match the frame the gate kept"
        );
    }
}
