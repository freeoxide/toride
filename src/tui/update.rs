use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::tui::model::*;
use crate::tui::model::ScreenState;
use crate::tui::model::SshVerifyPhase;
use crate::tui::theme::Theme;

#[derive(Debug)]
pub enum Action {
    Init,
    Tick,
    AnimationTick,
    Quit,

    Key(KeyEvent),
    Resize(u16, u16),
    FocusGained,
    FocusLost,
    Paste(String),

    Push(Screen),
    Pop,
    Replace(Screen),

    ToggleModule(ModuleId),
    SelectAll,
    SelectNone,
    InvertSelection,
    ResetProfileDefaults,

    FormFieldChanged(FormField, String),
    FormSubmit,

    OpenSearch,
    SearchInput(String),
    OpenPalette,
    PaletteInput(String),
    PaletteExec(PaletteCmd),
    OpenHelp,
    CloseOverlay,

    OsDetected(SystemInfo),
    PlanReady(Plan),
    InstallProgress(ProgressEvent),
    InstallDone(Outcome),
    Error(String),
    Toast { message: String, kind: ToastKind },

    SshVerifyProceed,
    SshVerifyRetry,
    SshVerifySkip,
    SshPhaseDone(SshVerifyPhase),
}

#[derive(Debug)]
pub enum Effect {
    DetectSystem,
    GeneratePlan(Vec<ModuleId>),
    RunInstall(Plan),
    CancelInstall,
    WriteConfig(std::path::PathBuf),
    LoadConfig(std::path::PathBuf),
    OpenUrl(String),
    Sleep(std::time::Duration, Box<Action>),
    PushFx(tachyonfx::Effect),
    SshRunPhase(SshVerifyPhase),
}

pub fn update(model: &mut Model, action: Action) -> Vec<Effect> {
    let mut effects = Vec::new();

    match action {
        Action::Init => {
            effects.push(Effect::DetectSystem);
            model.needs_render = true;
        }

        Action::Tick => {
            model.toasts.retain(|t| t.created_at.elapsed() < std::time::Duration::from_secs(5));
        }

        Action::AnimationTick => {}

        Action::Quit => {
            if matches!(model.run, RunState::Active { .. }) {
                let spec = ConfirmSpec {
                    action_label: "Quit",
                    description: "An installation is in progress. Quitting may leave the system in an inconsistent state.",
                    confirm_label: "Quit anyway",
                    cancel_label: "Continue",
                    is_destructive: true,
                };
                model.pending_confirm = Some(PendingConfirmAction::Quit);
                model.push_screen(Screen::Confirm(spec));
            } else {
                model.should_quit = true;
            }
        }

        Action::Key(key) => {
            handle_key(model, key, &mut effects);
        }

        Action::Resize(w, h) => {
            model.caps.width = w;
            model.caps.height = h;
            model.needs_render = true;
        }

        Action::FocusGained | Action::FocusLost => {}

        Action::Paste(text) => {
            if let Some(field) = current_form_field(model) {
                let existing = model.forms.get(field).to_string();
                model.forms.set(field, existing + &text);
                model.needs_render = true;
            }
        }

        Action::Push(screen) => {
            model.push_screen(screen);
        }

        Action::Pop => {
            model.pop_screen();
        }

        Action::Replace(screen) => {
            model.replace_screen(screen);
        }

        Action::ToggleModule(id) => {
            model.selection.toggle(id);
            model.needs_render = true;
        }

        Action::SelectAll => {
            model.selection.select_all();
            model.needs_render = true;
        }

        Action::SelectNone => {
            model.selection.select_none();
            model.needs_render = true;
        }

        Action::InvertSelection => {
            model.selection.invert();
            model.needs_render = true;
        }

        Action::ResetProfileDefaults => {
            if let Some(profile) = model.profile {
                let defaults = crate::profiles::profile_defaults(profile);
                model.selection.set_from_profile(&defaults);
                model.needs_render = true;
            }
        }

        Action::FormFieldChanged(field, value) => {
            model.forms.set(field, value);
            model.needs_render = true;
        }

        Action::FormSubmit => {
            let errors = model.forms.validate_all();
            if errors.is_empty() {
                model.push_screen(Screen::Preflight);
                model.focus = FocusId::ModuleList;
            } else {
                model.add_toast(
                    errors.values().next().unwrap().clone(),
                    ToastKind::Error,
                );
            }
            model.needs_render = true;
        }

        Action::OpenSearch => {
            model.search_query = Some(String::new());
            model.focus = FocusId::SearchInput;
            model.needs_render = true;
        }

        Action::SearchInput(query) => {
            model.search_query = Some(query);
            model.needs_render = true;
        }

        Action::OpenPalette => {
            model.palette_query = Some(String::new());
            model.focus = FocusId::PaletteInput;
            model.needs_render = true;
        }

        Action::PaletteInput(query) => {
            model.palette_query = Some(query);
            model.needs_render = true;
        }

        Action::PaletteExec(cmd) => {
            model.palette_query = None;
            handle_palette_cmd(model, cmd, &mut effects);
        }

        Action::OpenHelp => {
            model.push_screen(Screen::Help);
            model.focus = FocusId::HelpContent;
        }

        Action::CloseOverlay => {
            if model.current_screen().is_overlay() {
                model.pop_screen();
            } else {
                model.pop_screen();
            }
        }

        Action::OsDetected(info) => {
            model.system = info;
            model.screen_states.insert(Screen::Welcome, ScreenState::Ready);
            model.screen_states.insert(Screen::ProfileSelect, ScreenState::Ready);
            model.needs_render = true;
            // Auto-advance from Welcome to ProfileSelect after system detection
            if matches!(model.current_screen(), Screen::Welcome) {
                model.push_screen(Screen::ProfileSelect);
                model.focus = FocusId::ProfileList;
            }
        }

        Action::PlanReady(plan) => {
            model.plan = Some(plan);
            model.screen_states.insert(Screen::Preflight, ScreenState::Ready);
            model.needs_render = true;
        }

        Action::InstallProgress(event) => {
            match &event {
                ProgressEvent::StepLog { line, .. } => {
                    model.log.push(LogLine {
                        timestamp: std::time::Instant::now(),
                        module_id: None,
                        level: LogLevel::Info,
                        message: line.clone(),
                    });
                }
                ProgressEvent::StepFail { error, .. } => {
                    model.log.push(LogLine {
                        timestamp: std::time::Instant::now(),
                        module_id: None,
                        level: LogLevel::Error,
                        message: error.clone(),
                    });
                }
                _ => {}
            }
            model.needs_render = true;
        }

        Action::InstallDone(outcome) => {
            model.run = RunState::Done(outcome);
            model.reboot_required = std::path::Path::new("/var/run/reboot-required").exists();
            model.needs_render = true;
        }

        Action::Error(msg) => {
            let screen = *model.current_screen();
            model.screen_states.insert(screen, ScreenState::Error(msg.clone()));
            model.add_toast(msg, ToastKind::Error);
        }

        Action::SshVerifyProceed => {
            let phase = model.ssh_verify_phase.unwrap_or(SshVerifyPhase::CreateUser);
            effects.push(Effect::SshRunPhase(phase));
            model.needs_render = true;
        }

        Action::SshVerifyRetry => {
            if let Some(phase) = model.ssh_verify_phase {
                effects.push(Effect::SshRunPhase(phase));
                model.needs_render = true;
            }
        }

        Action::SshVerifySkip => {
            model.ssh_verify_phase = None;
            model.add_toast("SSH hardening skipped. Root/password login remains enabled.".into(), ToastKind::Warning);
            model.needs_render = true;
        }

        Action::SshPhaseDone(phase) => {
            let next = match phase {
                SshVerifyPhase::CreateUser => Some(SshVerifyPhase::AddKey),
                SshVerifyPhase::AddKey => Some(SshVerifyPhase::TestConnect),
                SshVerifyPhase::TestConnect => Some(SshVerifyPhase::HardenedConfig),
                SshVerifyPhase::HardenedConfig => Some(SshVerifyPhase::ReloadSshd),
                SshVerifyPhase::ReloadSshd => Some(SshVerifyPhase::VerifyConnect),
                SshVerifyPhase::VerifyConnect => Some(SshVerifyPhase::Complete),
                SshVerifyPhase::Complete => None,
            };
            model.ssh_verify_phase = next;
            if let Some(next_phase) = next {
                if !matches!(next_phase, SshVerifyPhase::TestConnect | SshVerifyPhase::VerifyConnect) {
                    effects.push(Effect::SshRunPhase(next_phase));
                }
            }
            model.needs_render = true;
        }

        Action::Toast { message, kind } => {
            model.add_toast(message, kind);
        }
    }

    effects
}

fn current_form_field(model: &Model) -> Option<FormField> {
    match model.focus {
        FocusId::Form(f) => Some(f),
        _ => None,
    }
}

fn handle_key(model: &mut Model, key: KeyEvent, effects: &mut Vec<Effect>) {
    let screen = *model.current_screen();

    match screen {
        Screen::Confirm(_) => effects.extend(handle_confirm_keys(model, key)),
        Screen::Help => handle_help_keys(model, key),
        Screen::Palette => handle_palette_keys(model, key, effects),
        Screen::Search => handle_search_keys(model, key),
        _ => handle_screen_keys(model, key, screen, effects),
    }
}

fn handle_confirm_keys(model: &mut Model, key: KeyEvent) -> Vec<Effect> {
    let mut effects = Vec::new();
    match key.code {
        KeyCode::Left | KeyCode::Char('h') => {
            model.focus = FocusId::ConfirmDialog;
        }
        KeyCode::Right | KeyCode::Char('l') => {
            model.focus = FocusId::ConfirmDialog;
        }
        KeyCode::Enter => {
            model.pop_screen();
            match model.pending_confirm.take() {
                Some(PendingConfirmAction::Quit) => model.should_quit = true,
                Some(PendingConfirmAction::ApplyPlan) => {
                    if let Some(ref plan) = model.plan {
                        let plan = plan.clone();
                        model.run = RunState::Active {
                            current_step: 0,
                            total_steps: plan.actions.len(),
                            cancel_token_id: 0,
                        };
                        model.push_screen(Screen::Apply);
                        effects.push(Effect::RunInstall(plan));
                    }
                }
                Some(PendingConfirmAction::CancelInstall) => {
                    effects.push(Effect::CancelInstall);
                    model.run = RunState::Done(Outcome::Cancelled);
                }
                None => model.should_quit = true,
            }
        }
        KeyCode::Esc => {
            model.pop_screen();
        }
        _ => {}
    }
    model.needs_render = true;
    effects
}

fn handle_help_keys(model: &mut Model, key: KeyEvent) {
    match key.code {
        KeyCode::Char('?') | KeyCode::Esc | KeyCode::Char('q') => {
            model.pop_screen();
        }
        KeyCode::Char('j') | KeyCode::Down => {
            model.list_scroll = model.list_scroll.saturating_add(1);
        }
        KeyCode::Char('k') | KeyCode::Up => {
            model.list_scroll = model.list_scroll.saturating_sub(1);
        }
        _ => {}
    }
    model.needs_render = true;
}

fn handle_palette_keys(model: &mut Model, key: KeyEvent, effects: &mut Vec<Effect>) {
    match key.code {
        KeyCode::Esc => {
            model.palette_query = None;
            model.pop_screen();
        }
        KeyCode::Enter => {
            if let Some(cmd) = fuzzy_match_palette(model.palette_query.as_deref()) {
                model.palette_query = None;
                model.pop_screen();
                handle_palette_cmd(model, cmd, effects);
            }
        }
        KeyCode::Up | KeyCode::Char('k') => {
            model.list_scroll = model.list_scroll.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            model.list_scroll = model.list_scroll.saturating_add(1);
        }
        KeyCode::Char(c) => {
            if let Some(ref mut q) = model.palette_query {
                q.push(c);
            }
        }
        KeyCode::Backspace => {
            if let Some(ref mut q) = model.palette_query {
                q.pop();
            }
        }
        _ => {}
    }
    model.needs_render = true;
}

fn handle_search_keys(model: &mut Model, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            model.search_query = None;
            model.pop_screen();
        }
        KeyCode::Char(c) => {
            if let Some(ref mut q) = model.search_query {
                q.push(c);
            }
        }
        KeyCode::Backspace => {
            if let Some(ref mut q) = model.search_query {
                q.pop();
                if q.is_empty() {
                    model.search_query = None;
                    model.pop_screen();
                }
            }
        }
        KeyCode::Enter => {
            model.search_query = None;
            model.pop_screen();
        }
        _ => {}
    }
    model.needs_render = true;
}

fn handle_screen_keys(model: &mut Model, key: KeyEvent, screen: Screen, effects: &mut Vec<Effect>) {
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        match key.code {
            KeyCode::Char('c') => {
                if matches!(model.run, RunState::Active { .. }) {
                    effects.push(Effect::CancelInstall);
                } else {
                    model.should_quit = true;
                }
                return;
            }
            KeyCode::Char('s') => {
                let path = std::path::PathBuf::from("toride.toml");
                effects.push(Effect::WriteConfig(path));
                model.add_toast("Config saved".into(), ToastKind::Success);
                return;
            }
            KeyCode::Char('l') => {
                model.log_panel_visible = !model.log_panel_visible;
                model.needs_render = true;
                return;
            }
            KeyCode::Char('t') => {
                model.dismiss_toast();
                return;
            }
            KeyCode::Char('r') => {
                let path = std::path::PathBuf::from("toride.toml");
                effects.push(Effect::LoadConfig(path));
                return;
            }
            _ => {}
        }
    }

    match key.code {
        KeyCode::Char('q') => {
            model.should_quit = true;
        }
        KeyCode::Char('?') | KeyCode::F(1) => {
            model.push_screen(Screen::Help);
            model.focus = FocusId::HelpContent;
        }
        KeyCode::Char(':') => {
            model.push_screen(Screen::Palette);
            model.palette_query = Some(String::new());
            model.focus = FocusId::PaletteInput;
        }
        KeyCode::Char('/') => {
            model.push_screen(Screen::Search);
            model.search_query = Some(String::new());
            model.focus = FocusId::SearchInput;
        }
        KeyCode::Esc => {
            model.pop_screen();
        }
        KeyCode::Tab => {
            model.focus = next_focus(model.focus);
            model.needs_render = true;
        }
        KeyCode::BackTab => {
            model.focus = prev_focus(model.focus);
            model.needs_render = true;
        }
        KeyCode::F(2) => {
            // cycle theme — for now just toggle no_color
            model.caps.no_color = !model.caps.no_color;
            model.theme = Theme::new(&model.caps);
            model.needs_render = true;
        }
        _ => {
            handle_screen_specific_keys(model, key, screen, effects);
        }
    }
}

fn handle_screen_specific_keys(model: &mut Model, key: KeyEvent, screen: Screen, effects: &mut Vec<Effect>) {
    match screen {
        Screen::ProfileSelect => {
            match key.code {
                KeyCode::Enter | KeyCode::Char('l') | KeyCode::Right => {
                    let selected_profile = model.profile.unwrap_or(Profile::Basic);
                    let defaults = crate::profiles::profile_defaults(selected_profile);
                    model.selection.set_from_profile(&defaults);
                    model.push_screen(Screen::ModuleSelect);
                    model.focus = FocusId::ModuleList;
                }
                KeyCode::Char('j') | KeyCode::Down => {
                    model.profile = Some(Profile::Custom);
                    model.needs_render = true;
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    model.profile = Some(Profile::Basic);
                    model.needs_render = true;
                }
                _ => {}
            }
        }
        Screen::ModuleSelect => {
            match key.code {
                KeyCode::Char(' ') => {
                    let visible: Vec<ModuleId> = model.selection.selected_ids();
                    if let Some(&id) = visible.first() {
                        model.selection.toggle(id);
                        model.needs_render = true;
                    }
                }
                KeyCode::Char('a') => {
                    model.selection.select_all();
                    model.needs_render = true;
                }
                KeyCode::Char('n') => {
                    model.selection.select_none();
                    model.needs_render = true;
                }
                KeyCode::Char('i') => {
                    model.selection.invert();
                    model.needs_render = true;
                }
                KeyCode::Char('r') => {
                    if let Some(profile) = model.profile {
                        let defaults = crate::profiles::profile_defaults(profile);
                        model.selection.set_from_profile(&defaults);
                        model.needs_render = true;
                    }
                }
                KeyCode::Char('p') => {
                    let selected = model.selection.selected_ids();
                    effects.push(Effect::GeneratePlan(selected));
                    model.push_screen(Screen::Preflight);
                }
                KeyCode::Char('d') => {
                    model.dry_run = !model.dry_run;
                    model.add_toast(
                        format!("Dry run {}", if model.dry_run { "enabled" } else { "disabled" }),
                        ToastKind::Info,
                    );
                }
                KeyCode::Char('x') => {
                    let selected = model.selection.selected_ids();
                    effects.push(Effect::GeneratePlan(selected));
                    model.push_screen(Screen::Preflight);
                }
                KeyCode::Char('j') | KeyCode::Down => {
                    model.list_scroll = model.list_scroll.saturating_add(1);
                    model.needs_render = true;
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    model.list_scroll = model.list_scroll.saturating_sub(1);
                    model.needs_render = true;
                }
                KeyCode::Char('l') | KeyCode::Right | KeyCode::Enter => {
                    model.focus = FocusId::ModuleCard;
                    model.needs_render = true;
                }
                KeyCode::Char('h') | KeyCode::Left => {
                    model.focus = FocusId::Sidebar;
                    model.needs_render = true;
                }
                KeyCode::Char('c') => {
                    let current_idx = model.list_scroll.min(ModuleId::all().len() - 1);
                    let cat = ModuleId::all()[current_idx].category();
                    let entry = model.category_collapsed.entry(cat).or_insert(false);
                    *entry = !*entry;
                    model.needs_render = true;
                }
                KeyCode::Char('G') => {
                    model.list_scroll = ModuleId::all().len().saturating_sub(1);
                    model.needs_render = true;
                }
                KeyCode::PageDown => {
                    model.list_scroll = model.list_scroll.saturating_add(10);
                    model.needs_render = true;
                }
                KeyCode::PageUp => {
                    model.list_scroll = model.list_scroll.saturating_sub(10);
                    model.needs_render = true;
                }
                _ => {}
            }
        }
        Screen::Configure => {
            match key.code {
                KeyCode::Enter => {
                    model.push_screen(Screen::Preflight);
                }
                KeyCode::Tab => {
                    model.focus = next_form_field(model.focus);
                    model.needs_render = true;
                }
                KeyCode::BackTab => {
                    model.focus = prev_form_field(model.focus);
                    model.needs_render = true;
                }
                KeyCode::Char(c) => {
                    if let FocusId::Form(field) = model.focus {
                        let existing = model.forms.get(field).to_string();
                        model.forms.set(field, existing + &c.to_string());
                        model.needs_render = true;
                    }
                }
                KeyCode::Backspace => {
                    if let FocusId::Form(field) = model.focus {
                        let mut val = model.forms.get(field).to_string();
                        val.pop();
                        model.forms.set(field, val);
                        model.needs_render = true;
                    }
                }
                KeyCode::Delete => {
                    // Cursor is at end, same as backspace
                    if let FocusId::Form(field) = model.focus {
                        let mut val = model.forms.get(field).to_string();
                        val.pop();
                        model.forms.set(field, val);
                        model.needs_render = true;
                    }
                }
                KeyCode::Home => {
                    // Move to first field
                    model.focus = FocusId::Form(FormField::Username);
                    model.needs_render = true;
                }
                KeyCode::End => {
                    // Move to last field
                    model.focus = FocusId::Form(FormField::SshPort);
                    model.needs_render = true;
                }
                _ => {}
            }
        }
        Screen::Preflight => {
            match key.code {
                KeyCode::Enter => {
                    if let Some(ref plan) = model.plan {
                        let spec = ConfirmSpec {
                            action_label: "Apply setup plan",
                            description: "This will make changes to your system. Ensure you have reviewed the plan.",
                            confirm_label: "Apply",
                            cancel_label: "Cancel",
                            is_destructive: true,
                        };
                        model.push_screen(Screen::Confirm(spec));
                    }
                }
                _ => {}
            }
        }
        Screen::Apply => {
            match key.code {
                KeyCode::Char('j') | KeyCode::Down => {
                    model.follow_tail = false;
                    model.list_scroll = model.list_scroll.saturating_add(1);
                    model.needs_render = true;
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    model.follow_tail = false;
                    model.list_scroll = model.list_scroll.saturating_sub(1);
                    model.needs_render = true;
                }
                KeyCode::Enter => {
                    model.needs_render = true;
                }
                KeyCode::Char('f') => {
                    model.follow_tail = !model.follow_tail;
                    model.needs_render = true;
                }
                KeyCode::Char('s') | KeyCode::Char('R') => {
                    // skip/retry — only meaningful during active install
                    model.needs_render = true;
                }
                _ => {}
            }
        }
        Screen::Summary => {
            match key.code {
                KeyCode::Char('q') => {
                    model.should_quit = true;
                }
                _ => {}
            }
        }
        _ => {}
    }
}

fn handle_palette_cmd(model: &mut Model, cmd: PaletteCmd, effects: &mut Vec<Effect>) {
    match cmd {
        PaletteCmd::Plan => {
            let selected = model.selection.selected_ids();
            effects.push(Effect::GeneratePlan(selected));
        }
        PaletteCmd::Apply => {
            if let Some(ref plan) = model.plan {
                let plan = plan.clone();
                model.run = RunState::Active {
                    current_step: 0,
                    total_steps: plan.actions.len(),
                    cancel_token_id: 0,
                };
                model.push_screen(Screen::Apply);
                effects.push(Effect::RunInstall(plan));
            }
        }
        PaletteCmd::DryRun => {
            model.dry_run = true;
            let selected = model.selection.selected_ids();
            effects.push(Effect::GeneratePlan(selected));
            model.add_toast("Dry run mode".into(), ToastKind::Info);
        }
        PaletteCmd::Save => {
            let path = std::path::PathBuf::from("toride.toml");
            effects.push(Effect::WriteConfig(path));
        }
        PaletteCmd::Load => {
            let path = std::path::PathBuf::from("toride.toml");
            effects.push(Effect::LoadConfig(path));
        }
        PaletteCmd::Reset => {
            if let Some(profile) = model.profile {
                let defaults = crate::profiles::profile_defaults(profile);
                model.selection.set_from_profile(&defaults);
            }
            model.needs_render = true;
        }
        PaletteCmd::Theme => {
            model.caps.no_color = !model.caps.no_color;
            model.theme = Theme::new(&model.caps);
            model.needs_render = true;
        }
        PaletteCmd::Log => {
            model.log_panel_visible = !model.log_panel_visible;
            model.needs_render = true;
        }
        PaletteCmd::Export => {
            model.add_toast("Export not yet implemented".into(), ToastKind::Warning);
        }
        PaletteCmd::Quit => {
            model.should_quit = true;
        }
    }
}

fn fuzzy_match_palette(query: Option<&str>) -> Option<PaletteCmd> {
    let query = query?.to_lowercase();
    PaletteCmd::all()
        .iter()
        .find(|cmd| cmd.label().contains(&query) || cmd.description().to_lowercase().contains(&query))
        .copied()
}

fn next_focus(current: FocusId) -> FocusId {
    match current {
        FocusId::Sidebar => FocusId::ModuleList,
        FocusId::ModuleList => FocusId::ModuleCard,
        FocusId::ModuleCard => FocusId::Sidebar,
        _ => FocusId::ModuleList,
    }
}

fn prev_focus(current: FocusId) -> FocusId {
    match current {
        FocusId::Sidebar => FocusId::ModuleCard,
        FocusId::ModuleList => FocusId::Sidebar,
        FocusId::ModuleCard => FocusId::ModuleList,
        _ => FocusId::Sidebar,
    }
}

fn next_form_field(current: FocusId) -> FocusId {
    match current {
        FocusId::Form(FormField::Username) => FocusId::Form(FormField::SshPublicKey),
        FocusId::Form(FormField::SshPublicKey) => FocusId::Form(FormField::SwapSize),
        FocusId::Form(FormField::SwapSize) => FocusId::Form(FormField::SshPort),
        FocusId::Form(FormField::SshPort) => FocusId::Form(FormField::Username),
        _ => FocusId::Form(FormField::Username),
    }
}

fn prev_form_field(current: FocusId) -> FocusId {
    match current {
        FocusId::Form(FormField::Username) => FocusId::Form(FormField::SshPort),
        FocusId::Form(FormField::SshPublicKey) => FocusId::Form(FormField::Username),
        FocusId::Form(FormField::SwapSize) => FocusId::Form(FormField::SshPublicKey),
        FocusId::Form(FormField::SshPort) => FocusId::Form(FormField::SwapSize),
        _ => FocusId::Form(FormField::Username),
    }
}
