//! Application state, event loop, and update logic.
//!
//! The [`App`] struct is the top-level orchestrator that owns all screen
//! instances, navigation state, and drives the main event loop via tokio's
//! `select!`.

mod input;
mod render;

use std::time::Instant;

use color_eyre::eyre::Result;
use crossterm::event::{Event, EventStream, KeyEventKind};
use futures::{FutureExt, StreamExt};
use ratatui::DefaultTerminal;
use tokio::select;
use tokio::sync::mpsc;

use crate::action::Action;
use crate::navigation::{Navigator, Screen};
use crate::persistence;
use crate::ssh_data::{SshDataCollector, SshOpError, execute_op};
use crate::fail2ban_data::Fail2banCollector;
use crate::ufw_kit_data::FirewallCollector;
use crate::toride_harden_data::HardenCollector;
use crate::toride_monitor_data::MonitorCollector;
use crate::toride_proxy_data::ProxyCollector;
use crate::toride_audit_data::AuditCollector;
use crate::toride_backup_data::BackupCollector;
use crate::toride_cloud_data::CloudCollector;
use crate::toride_updates_data::UpdatesCollector;
use crate::toride_users_data::UsersCollector;
use crate::toride_wireguard_data::WireguardCollector;
use crate::toride_tailscale_data::TailscaleCollector;
use crate::toride_mise_data::MiseCollector;
use crate::about_data::AboutCollector;
use crate::logs_data::LogsCollector;
use crate::settings_data::SettingsCollector;
use crate::templates_data::TemplatesCollector;
use crate::tools_data::ToolsCollector;
use crate::status_collector::StatusCollector;
use crate::ui::screens::AppScreen;
use crate::ui::screens::help::HelpScreen;
use crate::ui::screens::quit::QuitModal;
use crate::ui::screens::dashboard::DashboardScreen;
use crate::ui::screens::welcome::WelcomeScreen;
use crate::ui::theme::Theme;
use crate::ui::transition::{TransitionCache, TransitionState};
use crate::ui::widgets::InteractiveModal;

/// Top-level application orchestrator.
///
/// Owns all screen instances, the navigation state, and drives the main
/// event loop via tokio's `select!`.
pub struct App {
    nav: Navigator,
    welcome: WelcomeScreen,
    dashboard: DashboardScreen,
    #[allow(dead_code)] // will be used when help screen gets interactive content
    help: HelpScreen,
    /// Interactive help modal (manages visibility + rect + click-outside).
    help_modal: InteractiveModal<Action>,
    quit_visible: bool,
    quit_modal: QuitModal,
    active_theme: Theme,
    should_quit: bool,
    needs_redraw: bool,
    transition: Option<TransitionState>,
    transition_cache: TransitionCache,
    collector: StatusCollector,
    ssh_collector: SshDataCollector,
    /// Fail2ban read-only data collector (no write path, no cooldown).
    fail2ban_collector: Fail2banCollector,
    /// UFW firewall read-only data collector (no write path, no cooldown).
    ufw_kit_collector: FirewallCollector,
    /// Kernel-hardening read-only data collector (no write path, no cooldown).
    toride_harden_collector: HardenCollector,
    /// WireGuard read-only data collector (no write path, no cooldown).
    toride_wireguard_collector: WireguardCollector,
    /// Updates read-only data collector (no write path, no cooldown).
    toride_updates_collector: UpdatesCollector,
    /// User & access-control read-only data collector (no write path, no
    /// cooldown).
    toride_users_collector: UsersCollector,
    /// Audit (auditd/AIDE/logs) read-only data collector (no write path, no
    /// cooldown).
    toride_audit_collector: AuditCollector,
    /// Outbound traffic monitor read-only data collector (no write path, no
    /// cooldown).
    toride_monitor_collector: MonitorCollector,
    /// Backup (restic/borg) read-only data collector (no write path, no
    /// cooldown).
    toride_backup_collector: BackupCollector,
    /// Reverse-proxy (nginx/certbot/WAF) read-only data collector (no write
    /// path, no cooldown).
    toride_proxy_collector: ProxyCollector,
    /// Cloud provider (security groups / firewalls / agent) read-only data
    /// collector (no write path, no cooldown).
    toride_cloud_collector: CloudCollector,
    /// Tailscale mesh VPN (status / peers / netcheck / DNS) read-only data
    /// collector. Queries the local daemon over HTTP (localhost:41642) — no write
    /// path, no cooldown. Each network probe is individually timeout-bounded so an
    /// absent `tailscaled` cannot hang collection.
    toride_tailscale_collector: TailscaleCollector,
    /// Mise runtime version manager read-only data collector (no write path,
    /// no cooldown). Shells out to the local `mise` binary via its async runner;
    /// each command is timeout-bounded so an absent mise degrades to
    /// `available == false` rather than hanging the collector task.
    toride_mise_collector: MiseCollector,
    /// About-toride read-only data collector (system + app identity). No write
    /// path, no cooldown, no findings cache — reuses TorideStatus::collect via
    /// spawn_blocking exactly like StatusCollector.
    about_collector: AboutCollector,
    /// System log sources read-only data collector (no write path, no cooldown,
    /// no findings cache — simple oneshot that probes journald/syslog/presence).
    logs_collector: LogsCollector,
    /// Settings (app config + theme + runtime env) read-only data collector
    /// (no write path, no cooldown, no findings cache — the simple variant like
    /// StatusCollector, since the section has no doctor/findings concept).
    settings_collector: SettingsCollector,
    /// Hardening-recipes catalogue read-only data collector (no write path,
    /// no cooldown). Sweeps the constant recipe catalogue via `which::which`
    /// in a single spawn_blocking; findings (missing-target recipes) are
    /// cached for 60s for consistency with the other read-only sections.
    templates_collector: TemplatesCollector,
    /// Installed-tools catalogue (PATH scan of a curated CLI tool list)
    /// read-only data collector (no write path, no cooldown). Treats the
    /// catalogue scan as the doctor; findings (one tools.missing.<name>
    /// warning per missing expected tool) are cached for 60s.
    tools_collector: ToolsCollector,
    /// Receiver for SSH write operation error messages.
    ssh_error_rx: mpsc::UnboundedReceiver<SshOpError>,
    /// Sender clone passed to spawned SSH write tasks.
    ssh_error_tx: mpsc::UnboundedSender<SshOpError>,
    /// Receiver for SSH write operation completion signals.
    ssh_op_done_rx: mpsc::UnboundedReceiver<()>,
    /// Sender clone passed to spawned SSH write tasks (signals completion).
    ssh_op_done_tx: mpsc::UnboundedSender<()>,
    /// Number of SSH write ops currently in-flight.
    ssh_ops_in_flight: usize,
    /// Set when a reverting SSH write error lands while a batch is still
    /// in-flight. The immediate revert-refresh must be deferred until
    /// `ssh_ops_in_flight` reaches zero — otherwise the independent collector
    /// refresh re-reads disk while later ops in the same batch are still
    /// pending and wholesale overwrites still-pending optimistic UI state.
    /// Drained in the `ssh_op_done_rx` arm when the counter hits zero.
    ssh_revert_pending: bool,
    /// The currently running serialized SSH write task, if any. Stored so that
    /// on quit the in-flight op can run to completion before the runtime tears
    /// down (avoids losing a partially-applied config edit + its cooldown
    /// reconciliation). See `should_quit` handling in `run`.
    ssh_write_task: Option<tokio::task::JoinHandle<()>>,
    /// Time of the last SSH write op — suppresses data refresh to avoid
    /// overwriting optimistic in-memory updates before the async write lands.
    ssh_write_cooldown: Option<Instant>,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

/// What the `ssh_error_rx` arm should do about a reverting error. Pure
/// function so the F5 truth table is unit-testable.
///
/// Critically (F5), this decision is INDEPENDENT of the current screen:
/// a reverting error arriving off-Dashboard still means disk truth diverges
/// from optimistic state, so the revert intent must be recorded (Defer) or
/// acted on (FireNow) regardless of where the user is. Only the UI toast is
/// screen-gated. Before F5, the entire arm — including this scheduling —
/// was gated on `Screen::Dashboard`, so a reverting error off-Dashboard was
/// silently dropped.
#[derive(Debug, PartialEq, Eq)]
enum RevertScheduling {
    /// Not a reverting error — nothing to schedule.
    Noop,
    /// Reverting; no ops in-flight → start the revert-refresh immediately.
    FireNow,
    /// Reverting; ops still in-flight → set `ssh_revert_pending` and let the
    /// DONE arm fire the refresh once the batch drains.
    Defer,
}

impl App {
    /// Create a new application starting at the welcome screen.
    #[must_use]
    pub fn new() -> Self {
        // Restore the persisted theme so the selected choice survives restarts.
        // Falls back to the default on any error (missing / corrupt config).
        let active_theme = persistence::load_theme();
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
            should_quit: false,
            needs_redraw: false,
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
        }
    }

    /// Return a mutable reference to the current screen as `dyn AppScreen`.
    fn current_screen(&mut self) -> &mut dyn AppScreen {
        self.screen_by_enum(self.nav.current())
    }

    /// Invalidate all screen caches and flag a full redraw.
    fn invalidate_all_caches(&mut self) {
        self.welcome.invalidate_cache();
        self.dashboard.invalidate_cache();
        self.needs_redraw = true;
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
                // Persist the new theme so it survives the next launch. Best
                // effort: a write failure (read-only HOME, no config dir) is
                // logged inside save_theme and swallowed — the choice simply
                // reverts to the default on next launch instead of crashing.
                persistence::save_theme(next);
            }
            // Scroll actions (and any future screen-local actions) are routed
            // to the current screen via `handle_action`.
            _ => self.current_screen().handle_action(action),
        }
    }

    fn start_forward(&mut self, to: Screen) {
        let state = self.nav.start_forward(to, &mut self.transition_cache);
        self.transition = Some(state);
    }

    fn go_back(&mut self) {
        if let Some(state) = self.nav.start_backward(&mut self.transition_cache) {
            self.transition = Some(state);
        }
    }

    /// Decide whether the periodic refresh tick should SKIP an SSH data
    /// refresh. Pure function (no `self`) so the truth table is unit-testable.
    ///
    /// Refresh is skipped whenever a write could clobber optimistic in-memory
    /// state: if any op is still in-flight (a write slower than the cooldown
    /// must not lose its skip), or while the post-write cooldown has not yet
    /// elapsed (the async write may not have landed on disk).
    fn should_skip_ssh_refresh(in_flight: usize, cooldown_elapsed_secs: Option<u64>) -> bool {
        in_flight > 0 || cooldown_elapsed_secs.is_some_and(|s| s < 5)
    }

    /// Decide whether a reverting-error refresh should run NOW or be deferred.
    /// Pure function so the truth table is unit-testable.
    ///
    /// Run now only when no ops remain in-flight — otherwise the independent
    /// collector refresh re-reads disk and wholesale overwrites still-pending
    /// optimistic state for later ops in the same batch.
    fn should_revert_now(in_flight: usize) -> bool {
        in_flight == 0
    }

    /// Decide whether a deferred revert-refresh should fire now, in the DONE arm
    /// where an in-flight batch just drained. Pure function so the F6 truth table
    /// is unit-testable.
    ///
    /// Fire now only when a revert is pending AND no new batch was just spawned
    /// by the flush that follows. If a fresh batch spawned, the revert must be
    /// deferred to that batch's completion: the new batch's writes would race
    /// the revert-refresh's disk read (and, post-F4, the revert's result could
    /// itself be dropped by the in-flight guard). This mirrors the old
    /// `should_revert_now` semantics extended with the re-flush case.
    fn should_fire_deferred_revert_now(revert_pending: bool, spawned: bool) -> bool {
        revert_pending && !spawned
    }

    /// Pure scheduling decision for the `ssh_error_rx` arm (F5). Screen-
    /// independent by construction.
    fn ssh_error_revert_scheduling(revert_optimistic: bool, in_flight: usize) -> RevertScheduling {
        if !revert_optimistic {
            RevertScheduling::Noop
        } else if Self::should_revert_now(in_flight) {
            RevertScheduling::FireNow
        } else {
            RevertScheduling::Defer
        }
    }

    /// Drain pending SSH write operations and run them in a SINGLE serialized
    /// background task.
    ///
    /// All drained ops are coalesced into one spawned task that awaits each
    /// `execute_op` strictly in order. This is critical for correctness: the
    /// `sshd::edit()` write path is a non-atomic load→mutate→save, so two ops
    /// drained in the same flush would otherwise both load the original config
    /// and clobber each other (a lost-update race). One task + sequential
    /// awaits guarantees no two writes — and in particular no two sshd writes
    /// — ever run concurrently *within* a batch.
    ///
    /// The across-batch invariant is enforced here: if a batch is still
    /// in-flight, freshly drained ops are pushed back onto the queue and NOT
    /// spawned. They will be drained again after the in-flight batch's last
    /// `done` signal arrives (the `ssh_op_done_rx` arm re-runs the flush). This
    /// prevents a confirm-modal 'y' during a write from launching a second
    /// concurrent batch that would race the first.
    ///
    /// Done/error accounting stays per-logical-op: the task sends one `()`
    /// per op to `ssh_op_done_tx` and one error per failed op to
    /// `ssh_error_tx`. Each `execute_op` is wrapped in `catch_unwind` so that
    /// even a panic inside the write path still emits its completion signal
    /// (plus a reverting error) — otherwise the in-flight counter would never
    /// return to zero and the loading spinner would wedge forever. A 5-second
    /// cooldown on SSH data refresh prevents the next refresh from overwriting
    /// optimistic in-memory updates before the async writes land on disk.
    ///
    /// Returns `true` if a new serialized write batch was actually spawned, and
    /// `false` otherwise (not on Dashboard, nothing to drain, or held back
    /// because a batch is already in-flight). The DONE arm uses this to decide
    /// whether a deferred revert-refresh should fire now or be deferred again
    /// to the new batch's completion (F6: a revert-refresh must never race a
    /// freshly re-flushed batch).
    fn flush_ssh_ops(&mut self) -> bool {
        if !matches!(self.nav.current(), Screen::Dashboard) {
            return false;
        }
        let ops = self.dashboard.drain_ssh_ops();
        if ops.is_empty() {
            return false;
        }
        // A batch is already in-flight: hold these ops rather than spawning a
        // second concurrent task. They are re-queued (prepend-style: put back
        // ahead of any future drains) and will be flushed once the in-flight
        // batch completes — see the `ssh_op_done_rx` arm below.
        if self.ssh_ops_in_flight > 0 {
            self.dashboard.queue_ssh_ops_front(ops);
            return false;
        }
        // Set cooldown: skip SSH data refresh for 5 seconds to avoid
        // clobbering the optimistic in-memory update with stale disk state.
        self.ssh_write_cooldown = Some(Instant::now());
        self.ssh_ops_in_flight += ops.len();
        self.dashboard.set_ssh_loading(true, self.ssh_ops_in_flight);

        let error_tx = self.ssh_error_tx.clone();
        let done_tx = self.ssh_op_done_tx.clone();
        // ONE task for the whole batch — ops run sequentially inside it. Each
        // op is wrapped in catch_unwind so a panic cannot strand the remaining
        // ops' done signals.
        let handle = tokio::spawn(async move {
            for op in ops {
                let fut = std::panic::AssertUnwindSafe(execute_op(op));
                match fut.catch_unwind().await {
                    Ok(Ok(_label)) => {}
                    Ok(Err(err)) => {
                        let _ = error_tx.send(err);
                    }
                    Err(panic) => {
                        // The op panicked: disk state for a config write is
                        // unknown, but we must still account for this op so the
                        // loading spinner unwedges. Treat it as a reverting
                        // error so a refresh reconciles any optimistic state.
                        let msg = panic_message(&panic);
                        let _ = error_tx.send(SshOpError {
                            message: format!("ssh op panicked: {msg}"),
                            revert_optimistic: true,
                        });
                    }
                }
                // Signal completion for this logical op regardless of outcome.
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
    /// Returns an error if the terminal draw fails or the event stream encounters an error.
    pub async fn run(mut self, mut terminal: DefaultTerminal) -> Result<()> {
        let mut events = EventStream::new();
        let refresh_interval = tokio::time::interval(std::time::Duration::from_secs(2));
        let anim_tick = tokio::time::interval(std::time::Duration::from_millis(33)); // ~30fps
        tokio::pin!(refresh_interval);
        tokio::pin!(anim_tick);

        loop {
            terminal.draw(|f| self.view(f))?;
            self.needs_redraw = false;

            select! {
                // Prioritize terminal events and status results over timer
                biased;

                Some(Ok(event)) = events.next() => {
                    let action = match event {
                        Event::Key(key) if key.kind == KeyEventKind::Press => {
                            self.handle_key(key)
                        }
                        Event::Mouse(mouse) => self.handle_mouse(mouse),
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
                }

                // Receive collected status data
                Some(status) = self.collector.poll(), if self.collector.is_pending() => {
                    self.dashboard.set_status(status);
                    self.needs_redraw = true;
                }

                // Receive collected SSH data
                Some(bundle) = self.ssh_collector.poll(), if self.ssh_collector.is_pending() => {
                    // Re-check the skip condition at the apply site (F4). A
                    // collection started ~100ms-2s before a/d/r completes would
                    // wholesale-replace access_info with stale disk truth even
                    // though a write is in-flight. The in-flight gate at
                    // `ssh_collector.start()` only prevents NEW collections
                    // from starting; it cannot recall a collection that is
                    // already in-flight. Drop the bundle here when a write is
                    // in-flight or the post-write cooldown is still active, so
                    // optimistic in-memory state is never clobbered. The next
                    // eligible refresh (cooldown elapsed, no ops in-flight)
                    // re-reads disk truth cleanly.
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

                // Receive collected fail2ban data (read-only: no cooldown, no
                // optimistic-update reconciliation — every refresh cleanly
                // overwrites the previous view).
                Some(b) = self.fail2ban_collector.poll(), if self.fail2ban_collector.is_pending() => {
                    self.dashboard.set_fail2ban_data(b);
                    self.needs_redraw = true;
                }

                // Receive collected UFW firewall data (read-only: no cooldown,
                // no optimistic-update reconciliation — every refresh cleanly
                // overwrites the previous view).
                Some(b) = self.ufw_kit_collector.poll(), if self.ufw_kit_collector.is_pending() => {
                    self.dashboard.set_ufw_kit_data(b);
                    self.needs_redraw = true;
                }

                // Receive collected kernel-hardening data (read-only: no
                // cooldown, no optimistic-update reconciliation — every refresh
                // cleanly overwrites the previous view).
                Some(b) = self.toride_harden_collector.poll(), if self.toride_harden_collector.is_pending() => {
                    self.dashboard.set_toride_harden_data(b);
                    self.needs_redraw = true;
                }

                // Receive collected WireGuard data (read-only: no cooldown, no
                // optimistic-update reconciliation — every refresh cleanly
                // overwrites the previous view).
                Some(b) = self.toride_wireguard_collector.poll(), if self.toride_wireguard_collector.is_pending() => {
                    self.dashboard.set_toride_wireguard_data(b);
                    self.needs_redraw = true;
                }

                // Receive collected updates data (read-only: no cooldown, no
                // optimistic-update reconciliation — every refresh cleanly
                // overwrites the previous view).
                Some(b) = self.toride_updates_collector.poll(), if self.toride_updates_collector.is_pending() => {
                    self.dashboard.set_toride_updates_data(b);
                    self.needs_redraw = true;
                }

                // Receive collected user & access-control data (read-only: no
                // cooldown, no optimistic-update reconciliation — every refresh
                // cleanly overwrites the previous view). Per-file read failures
                // degrade that field but keep available == true; only a
                // collection panic flips the panel to the degraded state.
                Some(b) = self.toride_users_collector.poll(), if self.toride_users_collector.is_pending() => {
                    self.dashboard.set_toride_users_data(b);
                    self.needs_redraw = true;
                }

                // Receive collected audit data (read-only: no cooldown, no
                // optimistic-update reconciliation — every refresh cleanly
                // overwrites the previous view). Same 60s findings cache as
                // the other read-only sections.
                Some(b) = self.toride_audit_collector.poll(), if self.toride_audit_collector.is_pending() => {
                    self.dashboard.set_toride_audit_data(b);
                    self.needs_redraw = true;
                }

                // Receive collected outbound-traffic monitor data (read-only:
                // no cooldown, no optimistic-update reconciliation — every
                // refresh cleanly overwrites the previous view). Same 60s
                // findings cache as the other read-only sections.
                Some(b) = self.toride_monitor_collector.poll(), if self.toride_monitor_collector.is_pending() => {
                    self.dashboard.set_toride_monitor_data(b);
                    self.needs_redraw = true;
                }

                // Receive collected backup data (read-only: no cooldown, no
                // optimistic-update reconciliation — every refresh cleanly
                // overwrites the previous view). Same 60s findings cache as
                // the other read-only sections.
                Some(b) = self.toride_backup_collector.poll(), if self.toride_backup_collector.is_pending() => {
                    self.dashboard.set_toride_backup_data(b);
                    self.needs_redraw = true;
                }

                // Receive collected reverse-proxy data (read-only: no cooldown,
                // no optimistic-update reconciliation — every refresh cleanly
                // overwrites the previous view). Same 60s findings cache as
                // the other read-only sections.
                Some(b) = self.toride_proxy_collector.poll(), if self.toride_proxy_collector.is_pending() => {
                    self.dashboard.set_toride_proxy_data(b);
                    self.needs_redraw = true;
                }

                // Receive collected cloud-provider data (read-only: no cooldown,
                // no optimistic-update reconciliation — every refresh cleanly
                // overwrites the previous view). Same 60s findings cache as
                // the other read-only sections.
                Some(b) = self.toride_cloud_collector.poll(), if self.toride_cloud_collector.is_pending() => {
                    self.dashboard.set_toride_cloud_data(b);
                    self.needs_redraw = true;
                }

                // Receive collected Tailscale data (read-only: no cooldown, no
                // optimistic-update reconciliation — every refresh cleanly
                // overwrites the previous view). Same 60s findings cache as the
                // other read-only sections. Probes are individually timeout-bounded
                // so an absent tailscaled degrades to findings (available == true)
                // rather than hanging the collector task.
                Some(b) = self.toride_tailscale_collector.poll(), if self.toride_tailscale_collector.is_pending() => {
                    self.dashboard.set_toride_tailscale_data(b);
                    self.needs_redraw = true;
                }

                // Receive collected mise data (read-only: no cooldown, no
                // optimistic-update reconciliation — every refresh cleanly
                // overwrites the previous view). Same 60s findings cache as the
                // other read-only sections. Each mise command is individually
                // timeout-bounded so an absent mise degrades to available ==
                // false (BinaryNotFound) or to findings rather than hanging.
                Some(b) = self.toride_mise_collector.poll(), if self.toride_mise_collector.is_pending() => {
                    self.dashboard.set_toride_mise_data(b);
                    self.needs_redraw = true;
                }

                // Receive collected About-toride data (read-only: no cooldown,
                // no optimistic updates — every refresh cleanly overwrites the
                // previous view). Simple collector: no findings cache.
                Some(b) = self.about_collector.poll(), if self.about_collector.is_pending() => {
                    self.dashboard.set_about_data(b);
                    self.needs_redraw = true;
                }
                // Receive collected system log-sources data (read-only: no
                // cooldown, no optimistic updates — every refresh cleanly
                // overwrites the previous view). Simple oneshot collector.
                Some(b) = self.logs_collector.poll(), if self.logs_collector.is_pending() => {
                    self.dashboard.set_logs_data(b);
                    self.needs_redraw = true;
                }
                // Receive collected settings data (read-only: no cooldown, no
                // optimistic-update reconciliation — every refresh cleanly
                // overwrites the previous view). No findings cache (the simple
                // variant, like StatusCollector) since the section has no
                // doctor concept.
                Some(b) = self.settings_collector.poll(), if self.settings_collector.is_pending() => {
                    self.dashboard.set_settings_data(b);
                    self.needs_redraw = true;
                }
                // Receive collected hardening-recipes catalogue data
                // (read-only: no cooldown, no optimistic-update reconciliation
                // — every refresh cleanly overwrites the previous view). Same
                // 60s findings cache as the other read-only sections.
                Some(b) = self.templates_collector.poll(), if self.templates_collector.is_pending() => {
                    self.dashboard.set_templates_data(b);
                    self.needs_redraw = true;
                }
                // Receive collected installed-tools data (read-only: no
                // cooldown, no optimistic-update reconciliation — every refresh
                // cleanly overwrites the previous view). Same 60s findings cache
                // as the other read-only sections. The PATH scan always runs so
                // available stays true; only a collection panic flips the panel
                // to the degraded state.
                Some(b) = self.tools_collector.poll(), if self.tools_collector.is_pending() => {
                    self.dashboard.set_tools_data(b);
                    self.needs_redraw = true;
                }

                // Receive SSH write errors from the serialized write task.
                // On a reverting error (disk state known unchanged → the
                // optimistic UI update is now a lie) clear the write cooldown
                // and force an immediate SSH data refresh so disk truth
                // overwrites the stale in-memory state right away instead of
                // waiting out the 5s cooldown. On a transient error, just
                // surface the message (the cooldown reconciles it).
                Some(err) = self.ssh_error_rx.recv() => {
                    // F5: revert scheduling MUST run regardless of the current
                    // screen. A reverting error arriving off-Dashboard still
                    // means disk truth diverges from optimistic state, so the
                    // revert-refresh intent must be recorded (and acted on
                    // immediately if no ops are in-flight) even if the toast
                    // cannot be shown right now. Only the UI toast push is
                    // gated on the Dashboard.
                    if matches!(self.nav.current(), Screen::Dashboard) {
                        self.dashboard.push_ssh_error(err.message);
                    }
                    match Self::ssh_error_revert_scheduling(
                        err.revert_optimistic,
                        self.ssh_ops_in_flight,
                    ) {
                        RevertScheduling::FireNow => {
                            // Disk is unchanged: the optimistic UI update is
                            // now a lie. No ops in-flight, so refresh now.
                            self.ssh_write_cooldown = None;
                            self.ssh_collector.start();
                        }
                        RevertScheduling::Defer => {
                            // Ops still in-flight: a refresh now would re-read
                            // disk and clobber still-pending optimistic state.
                            // Defer until the counter drains to zero (see the
                            // `ssh_op_done_rx` arm).
                            self.ssh_revert_pending = true;
                        }
                        RevertScheduling::Noop => {}
                    }
                    self.needs_redraw = true;
                }

                // Receive SSH write op completion signals
                Some(()) = self.ssh_op_done_rx.recv() => {
                    self.ssh_ops_in_flight = self.ssh_ops_in_flight.saturating_sub(1);
                    let loading = self.ssh_ops_in_flight > 0;
                    self.dashboard.set_ssh_loading(loading, self.ssh_ops_in_flight);
                    self.needs_redraw = true;
                    // When an in-flight batch fully drains, immediately flush
                    // any ops that were held back because a batch was running.
                    // This re-drains them into a fresh serialized task now that
                    // no write is concurrent. The task handle is also cleared
                    // (its future completed).
                    if self.ssh_ops_in_flight == 0 {
                        // The batch finished: drop our handle (its future has
                        // already completed, so this is a cheap no-op).
                        self.ssh_write_task = None;
                        // F6: a deferred revert-refresh must NOT fire in the
                        // same pass that re-flushes a new batch. If held ops
                        // exist, flushing them now spawns a fresh serialized
                        // task whose writes would race the revert-refresh's
                        // disk read (and, post-F4, the revert's result could
                        // itself be dropped). So flush FIRST; if a new batch
                        // spawned, leave `ssh_revert_pending` set so the
                        // revert fires at THAT batch's completion. Only when
                        // no new batch started is the revert safe to run now.
                        let spawned = self.flush_ssh_ops();
                        if Self::should_fire_deferred_revert_now(
                            self.ssh_revert_pending,
                            spawned,
                        ) {
                            // No new batch: the revert is safe now.
                            self.ssh_revert_pending = false;
                            self.ssh_write_cooldown = None;
                            self.ssh_collector.start();
                        }
                        // If revert_pending is true but spawned is also true,
                        // leave the flag set: the new batch's DONE pass will
                        // re-evaluate (and defer again if yet another batch
                        // spawns).
                    }
                }

                // Periodic status refresh
                _ = refresh_interval.tick() => {
                    if matches!(self.nav.current(), Screen::Dashboard) {
                        self.dashboard.tick_clock();
                        self.collector.start();
                        // Skip SSH data refresh during write cooldown to prevent
                        // overwriting optimistic in-memory updates with stale
                        // disk state. Cooldown expires after 5 seconds. Also
                        // skip while ops are in-flight: a write slower than the
                        // cooldown would otherwise let a mid-write refresh
                        // clobber optimistic state.
                        let skip_ssh = Self::should_skip_ssh_refresh(
                            self.ssh_ops_in_flight,
                            self.ssh_write_cooldown
                                .map(|t| t.elapsed().as_secs()),
                        );
                        if !skip_ssh {
                            self.ssh_write_cooldown = None;
                            self.ssh_collector.start();
                        }
                        // Fail2ban is read-only: no cooldown, no optimistic
                        // updates. The collector's internal 60s findings cache
                        // throttles the expensive doctor suite.
                        self.fail2ban_collector.start();
                        // UFW firewall is read-only: no cooldown, no optimistic
                        // updates. Same 60s findings cache as fail2ban.
                        self.ufw_kit_collector.start();
                        // Kernel-hardening is read-only: no cooldown, no
                        // optimistic updates. Same 60s findings cache as
                        // fail2ban / ufw-kit.
                        self.toride_harden_collector.start();
                        // WireGuard is read-only: no cooldown, no optimistic
                        // updates. Same 60s findings cache as fail2ban /
                        // ufw-kit / harden.
                        self.toride_wireguard_collector.start();
                        // Updates is read-only: no cooldown, no optimistic
                        // updates. Same 60s findings cache as the other
                        // read-only sections.
                        self.toride_updates_collector.start();
                        // Users is read-only: no cooldown, no optimistic
                        // updates. Same 60s findings cache as the other
                        // read-only sections. Per-file read failures on
                        // macOS (/etc/shadow, /etc/sudoers, /etc/pam.d) are
                        // degraded per-field, not fatal.
                        self.toride_users_collector.start();
                        // Audit is read-only: no cooldown, no optimistic
                        // updates. Same 60s findings cache as the other
                        // read-only sections.
                        self.toride_audit_collector.start();
                        // Monitor is read-only: no cooldown, no optimistic
                        // updates. Same 60s findings cache as the other
                        // read-only sections. Degrades to available=false on
                        // macOS (iptables/conntrack/ss/journalctl missing).
                        self.toride_monitor_collector.start();
                        // Backup is read-only: no cooldown, no optimistic
                        // updates. Same 60s findings cache as the other
                        // read-only sections. Degrades per-field when binaries
                        // are missing (surfaces as Critical doctor findings,
                        // keeping available == true).
                        self.toride_backup_collector.start();
                        // Reverse-proxy is read-only: no cooldown, no
                        // optimistic updates. Same 60s findings cache as the
                        // other read-only sections. Degrades to available=false
                        // on macOS (nginx/certbot/systemctl missing) and to
                        // Critical findings when only some binaries are absent.
                        self.toride_proxy_collector.start();
                        // Cloud is read-only: no cooldown, no optimistic
                        // updates. Same 60s findings cache as the other
                        // read-only sections. On a macOS dev box with no cloud
                        // VM, provider resolves to Unknown (env vars + DMI files
                        // don't match) and the section stays available == true
                        // so the operator sees the provider.unknown Warning
                        // finding rather than a blank panel.
                        self.toride_cloud_collector.start();
                        // Tailscale is read-only: no cooldown, no optimistic
                        // updates. Same 60s findings cache as the other read-only
                        // sections. The backend talks to the local daemon over HTTP
                        // (localhost:41642); each probe is timeout-bounded so an
                        // absent tailscaled degrades to a critical finding rather
                        // than hanging the collector.
                        self.toride_tailscale_collector.start();
                        // Mise is read-only: no cooldown, no optimistic updates.
                        // Same 60s findings cache as the other read-only sections.
                        // The backend shells out to the local `mise` binary via its
                        // async runner; each command is timeout-bounded so an absent
                        // mise degrades to available == false rather than hanging.
                        self.toride_mise_collector.start();
                        // About-toride is read-only: no cooldown, no optimistic
                        // updates. No findings cache (identity metadata, not a
                        // health check). Reuses TorideStatus::collect via
                        // spawn_blocking like StatusCollector.
                        self.about_collector.start();
                        // Logs is read-only: no cooldown, no optimistic updates.
                        // Simple oneshot collector; re-probes log sources fresh.
                        self.logs_collector.start();
                        // Settings is read-only: no cooldown, no optimistic
                        // updates. No findings cache (simple variant) so every
                        // refresh re-reads the config file + env fresh.
                        self.settings_collector.start();
                        // Templates (hardening-recipes catalogue) is read-only:
                        // no cooldown, no optimistic updates. Same 60s findings
                        // cache as the other read-only sections. The recipe
                        // definitions are constant app data; only the per-recipe
                        // readiness (which::which sweep) is live.
                        self.templates_collector.start();
                        // Tools is read-only: no cooldown, no optimistic
                        // updates. Same 60s findings cache as the other
                        // read-only sections. The catalogue scan resolves ~30
                        // binaries on the blocking pool; a missing tool surfaces
                        // as a tools.missing.<name> warning finding rather than
                        // degrading the panel.
                        self.tools_collector.start();
                        self.needs_redraw = true;
                    }
                }

                // Animation tick (~30fps for shimmer, border, spinner, and transitions)
                _ = anim_tick.tick(),
                    if self.transition.is_some()
                        || self.needs_redraw
                        || matches!(self.nav.current(), Screen::Welcome | Screen::Dashboard) => {}
            }

            if self.should_quit {
                // Before tearing down the runtime, let any in-flight SSH write
                // op run to completion. Each op is independently validated and
                // backed-up before install, so finishing the current op leaves
                // disk consistent and lets the user's last change land instead
                // of being lost to runtime shutdown with stale optimistic UI.
                if let Some(handle) = self.ssh_write_task.take() {
                    let _ = handle.await;
                }
                // If a deferred revert-refresh (or any collector refresh) is
                // still pending, await it once with a bounded timeout so the
                // disk-truth reconcile lands before the runtime tears down.
                // Cosmetic: disk is authoritative on next launch either way, so
                // a bounded wait avoids hanging the process if the collection
                // stalls.
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

/// Render a `catch_unwind` panic payload as a best-effort string.
///
/// `Box<dyn Any + Send>` payloads are usually `&'static str` or `String`, but
/// fall back to a generic marker for anything else so the error toast is never
/// empty.
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
    use crate::action::Action;
    use crate::app::App;
    use crate::navigation::Screen;
    use crate::ui::theme::Theme;

    #[test]
    fn new_creates_default_state() {
        let app = App::new();
        assert_eq!(app.active_theme, Theme::Charm);
        assert!(!app.should_quit);
        assert_eq!(app.nav.current(), Screen::Welcome);
    }

    #[test]
    fn default_equals_new() {
        let from_new = App::new();
        let from_default = App::default();
        assert_eq!(from_new.active_theme, from_default.active_theme);
        assert_eq!(from_new.should_quit, from_default.should_quit);
        assert_eq!(from_new.nav.current(), from_default.nav.current());
        assert!(from_new.transition.is_none());
        assert!(from_default.transition.is_none());
    }

    #[test]
    fn update_quit_sets_should_quit() {
        let mut app = App::new();
        assert!(!app.should_quit);
        app.update(Action::Quit);
        assert!(app.should_quit);
    }

    #[test]
    fn update_continue_starts_transition_to_status() {
        let mut app = App::new();
        assert!(app.transition.is_none());
        app.update(Action::Continue);
        assert!(app.transition.is_some());
    }

    #[test]
    fn update_help_toggles_modal() {
        let mut app = App::new();
        assert!(!app.help_modal.is_visible());
        app.update(Action::Help);
        assert!(app.help_modal.is_visible());
        app.update(Action::Help);
        assert!(!app.help_modal.is_visible());
    }

    #[test]
    fn update_close_help_hides_modal() {
        let mut app = App::new();
        app.help_modal.open();
        app.update(Action::CloseHelp);
        assert!(!app.help_modal.is_visible());
    }

    #[test]
    fn update_back_does_nothing_at_welcome() {
        let mut app = App::new();
        assert!(app.transition.is_none());
        app.update(Action::Back);
        assert!(app.transition.is_none());
        assert_eq!(app.nav.current(), Screen::Welcome);
        assert!(!app.should_quit);
    }

    #[test]
    fn update_confirm_quit_shows_modal() {
        let mut app = App::new();
        assert!(!app.quit_visible);
        app.update(Action::ConfirmQuit);
        assert!(app.quit_visible);
    }

    #[test]
    fn update_dismiss_quit_hides_modal() {
        let mut app = App::new();
        app.quit_visible = true;
        app.update(Action::DismissQuit);
        assert!(!app.quit_visible);
    }

    #[test]
    fn panic_message_renders_str_and_string_payloads() {
        // catch_unwind hands back a Box<dyn Any + Send>. The helper must
        // recover the common (&'static str / String) payloads so the error
        // toast is informative, and never empty for anything else.
        let s: Box<dyn std::any::Any + Send> = Box::new("boom");
        assert_eq!(super::panic_message(&s), "boom");

        let s: Box<dyn std::any::Any + Send> = Box::new("owned error".to_string());
        assert_eq!(super::panic_message(&s), "owned error");

        let s: Box<dyn std::any::Any + Send> = Box::new(42_i32);
        assert_eq!(super::panic_message(&s), "<non-string panic payload>");
    }

    #[test]
    fn new_app_has_no_in_flight_write_task() {
        // The stored JoinHandle starts empty; the quit-drain path relies on
        // this so it only awaits a task that actually exists.
        let app = App::new();
        assert_eq!(app.ssh_ops_in_flight, 0);
        assert!(app.ssh_write_task.is_none());
    }

    #[test]
    fn new_app_has_no_revert_pending() {
        // The deferred-revert flag starts false; the DONE arm only fires a
        // revert-refresh when a reverting error set it true first.
        let app = App::new();
        assert!(!app.ssh_revert_pending);
    }

    #[test]
    fn should_skip_ssh_refresh_truth_table() {
        use crate::app::App;
        // No writes, no cooldown → refresh proceeds.
        assert!(!App::should_skip_ssh_refresh(0, None));
        // Cooldown fresh (< 5s) → skip even with no ops in-flight.
        assert!(App::should_skip_ssh_refresh(0, Some(0)));
        assert!(App::should_skip_ssh_refresh(0, Some(4)));
        // Cooldown elapsed (>= 5s), no ops → refresh proceeds.
        assert!(!App::should_skip_ssh_refresh(0, Some(5)));
        assert!(!App::should_skip_ssh_refresh(0, Some(99)));
        // Ops in-flight → ALWAYS skip, regardless of cooldown. This is the
        // slow-write guard: a write slower than the 5s cooldown must not lose
        // its skip and let a mid-write refresh clobber optimistic state.
        assert!(App::should_skip_ssh_refresh(1, None));
        assert!(App::should_skip_ssh_refresh(3, Some(5)));
        assert!(App::should_skip_ssh_refresh(2, Some(99)));
    }

    #[test]
    fn should_revert_now_truth_table() {
        use crate::app::App;
        // No ops in-flight → a reverting error refresh is safe to run now.
        assert!(App::should_revert_now(0));
        // Ops still in-flight → must defer: a refresh now would re-read disk
        // and clobber still-pending optimistic state for later ops in the batch.
        assert!(!App::should_revert_now(1));
        assert!(!App::should_revert_now(5));
    }

    // ----- F4: poll-arm must drop a stale collection result during a write
    // window. The poll arm re-checks `should_skip_ssh_refresh` at the apply
    // site. These tests lock the predicate combinations that gate the bundle
    // application; reverting F4 (removing the re-check) would make these
    // assertions describe behavior the poll arm no longer has, and the
    // dedicated contract test below asserts the gating value is `true` in
    // every case that must drop the bundle.
    #[test]
    fn f4_poll_drops_bundle_while_ops_in_flight() {
        use crate::app::App;
        // A collection started ~100ms before a/d/r completes and returns its
        // bundle while ssh_ops_in_flight == 1. The poll arm must drop it.
        // This is the exact predicate the poll arm now consults.
        assert!(App::should_skip_ssh_refresh(1, None));
        // Even with cooldown elapsed, in-flight still forces a drop.
        assert!(App::should_skip_ssh_refresh(1, Some(99)));
    }

    #[test]
    fn f4_poll_drops_bundle_during_cooldown() {
        use crate::app::App;
        // No ops in-flight but the post-write cooldown is still fresh: a
        // late-arriving collection would overwrite optimistic state before
        // the async write lands on disk. Must drop.
        assert!(App::should_skip_ssh_refresh(0, Some(0)));
        assert!(App::should_skip_ssh_refresh(0, Some(4)));
    }

    #[test]
    fn f4_poll_applies_bundle_when_safe() {
        use crate::app::App;
        // No ops in-flight AND cooldown elapsed (or absent): the bundle is
        // disk truth and may be applied. This is the negative space of F4 —
        // a correct fix must NOT over-drop and starve the UI of data.
        assert!(!App::should_skip_ssh_refresh(0, None));
        assert!(!App::should_skip_ssh_refresh(0, Some(5)));
        assert!(!App::should_skip_ssh_refresh(0, Some(99)));
    }

    // ----- F5: revert scheduling must be screen-independent. A reverting
    // error arriving off-Dashboard still has to record its intent (Defer) or
    // fire immediately (FireNow); only the toast is screen-gated. These
    // tests assert the scheduling decision is independent of any screen
    // argument (the function takes none by design) and produces Defer when
    // ops are in-flight.
    #[test]
    fn f5_reverting_error_with_ops_in_flight_defers() {
        // The scheduling function takes NO screen argument: by construction
        // it cannot depend on the current screen. A reverting error with ops
        // in-flight always defers — this would have been skipped entirely
        // pre-F5 when off-Dashboard.
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
        // No ops in-flight → FireNow regardless of screen.
        assert_eq!(
            App::ssh_error_revert_scheduling(true, 0),
            super::RevertScheduling::FireNow
        );
    }

    #[test]
    fn f5_transient_error_never_schedules_revert() {
        // Non-reverting errors never touch the revert machinery.
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
        // End-to-end-ish: simulate the arm's effect on App state for a
        // reverting error that arrives while NOT on Dashboard (we stay on
        // Welcome) and ops are in-flight. F5 requires ssh_revert_pending to
        // be set so the revert eventually fires. Pre-F5 the whole arm was
        // Dashboard-gated and this never happened.
        let mut app = App::new();
        // Force off-Dashboard + in-flight.
        assert!(matches!(app.nav.current(), crate::navigation::Screen::Welcome));
        app.ssh_ops_in_flight = 2;
        let scheduling = App::ssh_error_revert_scheduling(true, app.ssh_ops_in_flight);
        assert_eq!(scheduling, super::RevertScheduling::Defer);
        app.ssh_revert_pending = matches!(scheduling, super::RevertScheduling::Defer);
        assert!(
            app.ssh_revert_pending,
            "revert intent must be recorded even off-Dashboard (F5)"
        );
    }

    // ----- F6: a deferred revert-refresh must not fire in the same DONE pass
    // that re-flushes a new batch. These tests lock the truth table of the
    // pure helper the DONE arm now consults.
    #[test]
    fn f6_revert_deferred_when_new_batch_spawned() {
        // Revert pending AND flush just spawned a new batch → defer (leave
        // ssh_revert_pending set). The revert must NOT fire now; it fires at
        // the new batch's completion.
        assert!(!App::should_fire_deferred_revert_now(true, true));
    }

    #[test]
    fn f6_revert_fires_when_no_new_batch() {
        // Revert pending AND no new batch spawned → safe to fire now.
        assert!(App::should_fire_deferred_revert_now(true, false));
    }

    #[test]
    fn f6_no_revert_pending_never_fires() {
        // Nothing pending → never fire (regardless of spawn state).
        assert!(!App::should_fire_deferred_revert_now(false, false));
        assert!(!App::should_fire_deferred_revert_now(false, true));
    }

    #[test]
    fn f6_re_flush_during_pending_leaves_flag_set() {
        // End-to-end-ish: simulate the DONE arm's bookkeeping when held ops
        // exist (spawned == true) and a revert is pending. The flag must
        // REMAIN set so the new batch's completion re-evaluates it.
        let mut app = App::new();
        app.ssh_revert_pending = true;
        let spawned = true; // flush_ssh_ops re-spawned a held batch
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
        // The complementary case: DONE pass with no held ops → revert fires
        // and the flag clears.
        let mut app = App::new();
        app.ssh_revert_pending = true;
        let spawned = false;
        if App::should_fire_deferred_revert_now(app.ssh_revert_pending, spawned) {
            app.ssh_revert_pending = false;
        }
        assert!(!app.ssh_revert_pending);
    }
}
