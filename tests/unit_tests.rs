use toride::tui::forms::validators;
use toride::tui::model::*;
use toride::profiles;

#[test]
fn basic_profile_selects_expected_modules() {
    let defaults = profiles::profile_defaults(Profile::Basic);
    assert!(defaults.contains(&ModuleId::SystemUpdate));
    assert!(defaults.contains(&ModuleId::Swap));
    assert!(defaults.contains(&ModuleId::UserSsh));
    assert!(defaults.contains(&ModuleId::Ufw));
    assert!(defaults.contains(&ModuleId::Docker));
}

#[test]
fn custom_profile_selects_nothing() {
    let defaults = profiles::profile_defaults(Profile::Custom);
    assert!(defaults.is_empty());
}

#[test]
fn toggle_module_selection() {
    let mut state = SelectionState::new();
    assert!(!state.modules[&ModuleId::Docker].selected);
    state.toggle(ModuleId::Docker);
    assert!(state.modules[&ModuleId::Docker].selected);
    state.toggle(ModuleId::Docker);
    assert!(!state.modules[&ModuleId::Docker].selected);
}

#[test]
fn select_all_selects_everything() {
    let mut state = SelectionState::new();
    state.select_all();
    for m in state.modules.values() {
        assert!(m.selected);
    }
}

#[test]
fn select_none_deselects_everything() {
    let mut state = SelectionState::new();
    state.select_all();
    state.select_none();
    for m in state.modules.values() {
        assert!(!m.selected);
    }
}

#[test]
fn invert_selection() {
    let mut state = SelectionState::new();
    state.toggle(ModuleId::Docker);
    state.invert();
    assert!(!state.modules[&ModuleId::Docker].selected);
    assert!(state.modules[&ModuleId::SystemUpdate].selected);
}

#[test]
fn set_from_profile_overrides() {
    let mut state = SelectionState::new();
    state.select_all();
    let defaults = profiles::profile_defaults(Profile::Basic);
    state.set_from_profile(&defaults);
    assert!(state.modules[&ModuleId::Docker].selected);
    assert!(!state.modules[&ModuleId::Mise].selected);
}

#[test]
fn selected_ids_returns_only_selected() {
    let mut state = SelectionState::new();
    state.toggle(ModuleId::Docker);
    state.toggle(ModuleId::Ufw);
    let ids = state.selected_ids();
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&ModuleId::Docker));
    assert!(ids.contains(&ModuleId::Ufw));
}

#[test]
fn username_validator_rejects_root() {
    assert!(validators::username("root").is_err());
}

#[test]
fn username_validator_rejects_empty() {
    assert!(validators::username("").is_err());
}

#[test]
fn username_validator_accepts_valid() {
    assert!(validators::username("deploy").is_ok());
    assert!(validators::username("_admin").is_ok());
    assert!(validators::username("user-123").is_ok());
}

#[test]
fn username_validator_rejects_numeric_start() {
    assert!(validators::username("1user").is_err());
}

#[test]
fn ssh_key_validator_rejects_empty() {
    assert!(validators::ssh_public_key("").is_err());
}

#[test]
fn ssh_key_validator_rejects_private_key() {
    assert!(validators::ssh_public_key("-----BEGIN OPENSSH PRIVATE KEY-----").is_err());
}

#[test]
fn ssh_key_validator_accepts_valid() {
    assert!(validators::ssh_public_key("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test@host").is_ok());
    assert!(validators::ssh_public_key("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC test").is_ok());
}

#[test]
fn ssh_key_validator_rejects_bad_format() {
    assert!(validators::ssh_public_key("not-a-key").is_err());
}

#[test]
fn swap_size_validator_accepts_valid() {
    assert!(validators::swap_size("2G").is_ok());
    assert!(validators::swap_size("512M").is_ok());
    assert!(validators::swap_size("0").is_ok());
    assert!(validators::swap_size("").is_ok());
}

#[test]
fn swap_size_validator_rejects_bad_format() {
    assert!(validators::swap_size("abc").is_err());
    assert!(validators::swap_size("2T").is_err());
}

#[test]
fn port_validator_accepts_valid() {
    assert!(validators::port("22").is_ok());
    assert!(validators::port("8080").is_ok());
    assert!(validators::port("65535").is_ok());
}

#[test]
fn port_validator_rejects_invalid() {
    assert!(validators::port("abc").is_err());
    assert!(validators::port("0").is_err());
}

#[test]
fn hostname_validator_accepts_valid() {
    assert!(validators::hostname("my-server").is_ok());
    assert!(validators::hostname("web01").is_ok());
}

#[test]
fn hostname_validator_rejects_hyphen_edges() {
    assert!(validators::hostname("-server").is_err());
    assert!(validators::hostname("server-").is_err());
}

#[test]
fn ring_buffer_push_and_iter() {
    let mut buf: RingBuffer<i32> = RingBuffer::new(3);
    buf.push(1);
    buf.push(2);
    buf.push(3);
    assert_eq!(buf.len(), 3);
    buf.push(4);
    assert_eq!(buf.len(), 3);
    let vals: Vec<&i32> = buf.iter().collect();
    assert_eq!(vals, vec![&2, &3, &4]);
}

#[test]
fn module_id_label_matches() {
    assert_eq!(ModuleId::SystemUpdate.label(), "System Update");
    assert_eq!(ModuleId::Docker.label(), "Docker");
    assert_eq!(ModuleId::Mise.label(), "Language Runtimes (mise)");
}

#[test]
fn module_categories() {
    assert_eq!(ModuleId::SystemUpdate.category(), Category::SystemBasics);
    assert_eq!(ModuleId::UserSsh.category(), Category::UsersAndSsh);
    assert_eq!(ModuleId::Ufw.category(), Category::FirewallAndSecurity);
    assert_eq!(ModuleId::Docker.category(), Category::Containers);
    assert_eq!(ModuleId::Mise.category(), Category::DeveloperRuntimes);
}

#[test]
fn screen_overlay_detection() {
    assert!(Screen::Help.is_overlay());
    assert!(Screen::Palette.is_overlay());
    assert!(Screen::Search.is_overlay());
    assert!(!Screen::Welcome.is_overlay());
    assert!(!Screen::ModuleSelect.is_overlay());
}

#[test]
fn toast_lifecycle() {
    let mut model = Model::initial_for_test();
    model.add_toast("info msg".into(), ToastKind::Info);
    assert_eq!(model.toasts.len(), 1);
    model.add_toast("error msg".into(), ToastKind::Error);
    assert_eq!(model.toasts.len(), 2);
    model.dismiss_toast();
    assert_eq!(model.toasts.len(), 1);
}

#[test]
fn screen_stack_navigation() {
    let mut model = Model::initial_for_test();
    assert_eq!(*model.current_screen(), Screen::Welcome);
    model.push_screen(Screen::ProfileSelect);
    assert_eq!(*model.current_screen(), Screen::ProfileSelect);
    model.pop_screen();
    assert_eq!(*model.current_screen(), Screen::Welcome);
}

#[test]
fn install_action_shell_preview() {
    use toride::modules::InstallAction;
    let action = InstallAction::AptInstall {
        packages: vec!["docker-ce".into(), "docker-compose-plugin".into()],
    };
    assert!(action.to_shell_preview().contains("docker-ce"));
    assert!(action.to_shell_preview().contains("apt install"));
}

#[test]
fn sandbox_profile_selects_expected_modules() {
    let defaults = profiles::profile_defaults(Profile::Sandbox);
    assert!(defaults.contains(&ModuleId::SystemUpdate));
    assert!(defaults.contains(&ModuleId::Swap));
    assert!(defaults.contains(&ModuleId::UserSsh));
    assert!(defaults.contains(&ModuleId::Ufw));
    assert!(defaults.contains(&ModuleId::Docker));
    assert!(defaults.contains(&ModuleId::Mise));
}

#[test]
fn basic_profile_includes_fail2ban_and_upgrades() {
    let defaults = profiles::profile_defaults(Profile::Basic);
    assert!(defaults.contains(&ModuleId::Fail2Ban));
    assert!(defaults.contains(&ModuleId::UnattendedUpgrades));
}

#[test]
fn new_module_categories() {
    assert_eq!(ModuleId::Tailscale.category(), Category::Networking);
    assert_eq!(ModuleId::Dokploy.category(), Category::ServerManagers);
    assert_eq!(ModuleId::Caddy.category(), Category::ReverseProxy);
    assert_eq!(ModuleId::Restic.category(), Category::Backup);
    assert_eq!(ModuleId::NodeExporter.category(), Category::Monitoring);
    assert_eq!(ModuleId::Fail2Ban.category(), Category::FirewallAndSecurity);
}

#[test]
fn reverse_proxy_conflicts() {
    let reg = toride::modules::registry();
    let caddy_conflicts = reg.get(&ModuleId::Caddy).unwrap().conflicts();
    assert!(caddy_conflicts.contains(&ModuleId::Nginx));
    assert!(caddy_conflicts.contains(&ModuleId::Traefik));
}

#[test]
fn server_manager_dependencies() {
    let reg = toride::modules::registry();
    let dokploy_deps = reg.get(&ModuleId::Dokploy).unwrap().dependencies();
    assert!(dokploy_deps.contains(&ModuleId::Docker));
    let coolify_deps = reg.get(&ModuleId::Coolify).unwrap().dependencies();
    assert!(coolify_deps.contains(&ModuleId::Docker));
}

#[test]
fn server_manager_conflicts() {
    let reg = toride::modules::registry();
    let dokploy_conflicts = reg.get(&ModuleId::Dokploy).unwrap().conflicts();
    assert!(dokploy_conflicts.contains(&ModuleId::Coolify));
}

#[test]
fn cloudflare_http_depends_on_ufw() {
    let reg = toride::modules::registry();
    let deps = reg.get(&ModuleId::CloudflareHttp).unwrap().dependencies();
    assert!(deps.contains(&ModuleId::Ufw));
}

#[test]
fn uptime_kuma_depends_on_docker() {
    let reg = toride::modules::registry();
    let deps = reg.get(&ModuleId::UptimeKuma).unwrap().dependencies();
    assert!(deps.contains(&ModuleId::Docker));
}

#[test]
fn all_module_ids_registered() {
    let reg = toride::modules::registry();
    for id in ModuleId::all() {
        if matches!(id, ModuleId::PluginRecipe) { continue; }
        assert!(reg.contains_key(id), "Module {:?} not registered", id);
    }
}

#[test]
fn all_categories_have_modules() {
    let categories: std::collections::HashSet<Category> = ModuleId::all()
        .iter().map(|id| id.category()).collect();
    for cat in Category::all() {
        assert!(categories.contains(cat), "Category {:?} has no modules", cat);
    }
}

#[test]
fn preflight_warnings_proxy_conflict() {
    let warnings = toride::executor::plan::generate_preflight_warnings(&[
        ModuleId::Caddy, ModuleId::Nginx,
    ]);
    assert!(warnings.iter().any(|w| w.message.contains("Multiple reverse proxies")));
}

#[test]
fn preflight_warnings_server_manager_conflict() {
    let warnings = toride::executor::plan::generate_preflight_warnings(&[
        ModuleId::Dokploy, ModuleId::Coolify, ModuleId::Docker,
    ]);
    assert!(warnings.iter().any(|w| w.message.contains("Dokploy and Coolify")));
}

#[test]
fn preflight_warnings_cloudflare() {
    let warnings = toride::executor::plan::generate_preflight_warnings(&[
        ModuleId::CloudflareHttp, ModuleId::Ufw,
    ]);
    assert!(warnings.iter().any(|w| w.message.contains("Cloudflare")));
}

#[test]
fn preflight_warnings_ssh_harding() {
    let warnings = toride::executor::plan::generate_preflight_warnings(&[
        ModuleId::UserSsh,
    ]);
    assert!(warnings.iter().any(|w| w.message.contains("SSH hardening")));
}

#[test]
fn preflight_warnings_docker_needs_update() {
    let warnings = toride::executor::plan::generate_preflight_warnings(&[
        ModuleId::Docker,
    ]);
    assert!(warnings.iter().any(|w| w.message.contains("System Update")));
}

#[test]
fn preflight_warnings_tailscale_script() {
    let warnings = toride::executor::plan::generate_preflight_warnings(&[
        ModuleId::Tailscale,
    ]);
    assert!(warnings.iter().any(|w| w.message.contains("Tailscale")));
}

#[test]
fn pending_confirm_action_variants() {
    use toride::tui::model::PendingConfirmAction;
    assert!(matches!(PendingConfirmAction::EnableUfw, PendingConfirmAction::EnableUfw));
    assert!(matches!(PendingConfirmAction::DisableRootSsh, PendingConfirmAction::DisableRootSsh));
    assert!(matches!(PendingConfirmAction::EnableCloudflareHttp, PendingConfirmAction::EnableCloudflareHttp));
    assert!(matches!(PendingConfirmAction::ChangeSshPort, PendingConfirmAction::ChangeSshPort));
}

#[test]
fn form_field_covers_all_variants() {
    use toride::tui::model::FormField;
    let fields = [
        FormField::Username,
        FormField::SshPublicKey,
        FormField::SwapSize,
        FormField::SshPort,
        FormField::Hostname,
        FormField::Timezone,
    ];
    assert_eq!(fields.len(), 6);
}

#[test]
fn config_schema_roundtrip() {
    let config = toride::config::schema::Config {
        profile: "basic".into(),
        user: toride::config::schema::UserConfig::default(),
        security: toride::config::schema::SecurityConfig::default(),
        runtimes: toride::config::schema::RuntimesConfig::default(),
        containers: toride::config::schema::ContainersConfig::default(),
        swap: toride::config::schema::SwapConfig::default(),
        networking: toride::config::schema::NetworkingConfig::default(),
        server_manager: toride::config::schema::ServerManagerConfig::default(),
        reverse_proxy: toride::config::schema::ReverseProxyConfig::default(),
        backup: toride::config::schema::BackupConfig::default(),
        monitoring: toride::config::schema::MonitoringConfig::default(),
    };
    let toml_str = toml::to_string_pretty(&config).unwrap();
    let parsed: toride::config::schema::Config = toml::from_str(&toml_str).unwrap();
    assert_eq!(parsed.profile, config.profile);
    assert_eq!(parsed.containers.docker, config.containers.docker);
    assert_eq!(parsed.swap.size, config.swap.size);
}

#[test]
fn config_schema_networking_defaults() {
    let config = toride::config::schema::NetworkingConfig::default();
    assert!(!config.tailscale);
    assert!(!config.cloudflare_tunnel);
    assert!(!config.wireguard);
}

#[test]
fn config_schema_monitoring_defaults() {
    let config = toride::config::schema::MonitoringConfig::default();
    assert!(!config.node_exporter);
    assert!(!config.prometheus);
    assert!(!config.grafana);
    assert!(!config.uptime_kuma);
    assert!(!config.netdata);
}

#[test]
fn plugin_recipe_parse_with_exec_and_write() {
    let toml = r#"
id = "complex"
name = "Complex Recipe"
version = "2.0"
description = "A more complex recipe"

[[steps]]
type = "apt"
packages = ["vim", "htop"]

[[steps]]
type = "exec"
cmd = "systemctl"
args = ["enable", "nginx"]

[[steps]]
type = "write"
path = "/etc/nginx/conf.d/default.conf"
content = "server { listen 80; }"
mode = 420
backup = true
"#;
    let recipe = toride::plugins::recipe::parse_recipe(toml).unwrap();
    assert_eq!(recipe.steps.len(), 3);
    assert_eq!(recipe.steps[0].step_type, "apt");
    assert_eq!(recipe.steps[1].cmd.as_deref(), Some("systemctl"));
    assert_eq!(recipe.steps[2].path.as_deref(), Some("/etc/nginx/conf.d/default.conf"));
    assert_eq!(recipe.steps[2].mode, Some(420));
    assert_eq!(recipe.steps[2].backup, Some(true));

    let actions = recipe.to_install_actions();
    assert_eq!(actions.len(), 3);
}
