//! Toride — terminal user interface for hardened Linux host management.
//!
//! This crate implements the Elm-inspired TUI app: an [`app::App`] orchestrator
//! that owns all screen instances and drives the main event loop, plus the
//! rendering widgets, themes, and per-section data collectors that back each
//! dashboard panel.

#![expect(
    clippy::must_use_candidate,
    reason = "constructors and pure fns in TUI scaffolding"
)]
#![expect(
    clippy::many_single_char_names,
    reason = "color math uses r/g/b/t variable names"
)]
#![warn(missing_docs)]

pub mod about_convert;
pub mod about_data;
pub mod action;
pub mod app;
pub mod config;
pub mod data;
pub mod fail2ban_convert;
pub mod fail2ban_data;
pub mod logs_convert;
pub mod logs_data;
pub mod navigation;
pub mod persistence;
pub mod prediction;
pub mod settings_convert;
pub mod settings_data;
pub mod ssh_convert;
pub mod ssh_data;
pub mod status_collector;
pub mod templates_convert;
pub mod templates_data;
pub mod tools_convert;
pub mod tools_data;
pub use toride_status as status;
pub mod toride_audit_convert;
pub mod toride_audit_data;
pub mod toride_backup_convert;
pub mod toride_backup_data;
pub mod toride_cloud_convert;
pub mod toride_cloud_data;
pub mod toride_harden_convert;
pub mod toride_harden_data;
pub mod toride_mise_convert;
pub mod toride_mise_data;
pub mod toride_monitor_convert;
pub mod toride_monitor_data;
pub mod toride_proxy_convert;
pub mod toride_proxy_data;
pub mod toride_tailscale_convert;
pub mod toride_tailscale_data;
pub mod toride_updates_convert;
pub mod toride_updates_data;
pub mod toride_users_convert;
pub mod toride_users_data;
pub mod toride_wireguard_convert;
pub mod toride_wireguard_data;
pub mod ufw_kit_convert;
pub mod ufw_kit_data;
/// Rendering layer: screens, widgets, theme, transitions, and layout helpers.
pub mod ui;
pub mod version;
pub mod virt_detect;
