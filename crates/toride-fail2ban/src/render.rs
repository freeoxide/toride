//! Render typed specs into Fail2Ban-compatible INI `.local` file content.
//!
//! This module provides pure functions that convert [`JailSpec`], [`FilterSpec`],
//! and [`ActionSpec`] into the INI-like text format that Fail2Ban reads from
//! `.local` override files. Generated output includes a managed header so the
//! config layer can distinguish owned files from human-edited or stock files.
//!
//! # File naming convention
//!
//! All generated files follow the pattern `{namespace}-{name}.local` and are
//! written into the standard Fail2Ban config directories:
//!
//! - `jail.d/` for jail configs
//! - `filter.d/` for filter configs
//! - `action.d/` for action configs
//!
//! # Multi-line values
//!
//! Fail2Ban uses leading whitespace for continuation lines. This renderer
//! emits continuation lines with consistent indentation to match Fail2Ban's
//! expectations.

use std::fmt::Write;

use crate::spec::{ActionKind, ActionSpec, Backend, FilterSpec, JailSpec, Protocol, UseDns};

/// Returns the standard header comment placed at the top of every generated
/// `.local` file.
///
/// This header is used by the config layer to identify files that are safe to
/// overwrite or remove. Files without this header must never be mutated.
pub fn managed_header() -> &'static str {
    indoc::indoc! {"
        # Managed by fail2ban-kit.
        # Do not edit manually unless you also disable this manager.
    "}
}

/// Renders a [`JailSpec`] into the contents of a jail `.local` file.
///
/// The output follows Fail2Ban's INI-like format with multi-line continuation
/// for lists (log paths, actions, ignore IPs). Only fields that have non-default
/// values or are semantically required are included to keep generated files
/// minimal and readable.
///
/// # Arguments
///
/// * `spec` - The typed jail specification to render.
/// * `namespace` - Manager namespace. A filter with inline `failregex` is
///   written to `filter.d/{namespace}-{name}.local` by the config layer, so
///   the jail references it under that namespaced name; a filter without
///   inline patterns references the bare stock name. Custom actions are
///   namespaced the same way.
///
/// # Example output
///
/// ```ini
/// # Managed by fail2ban-kit.
/// # Do not edit manually unless you also disable this manager.
///
/// [myapp]
/// enabled = true
/// filter = myapp-auth[mode=aggressive]
/// backend = auto
/// logpath = /var/log/myapp/auth.log
/// port = 80, 443
/// protocol = tcp
/// bantime = 10m
/// findtime = 10m
/// maxretry = 5
/// usedns = no
/// ignoreip = 127.0.0.1/8 ::1
/// action = nftables-multiport
/// ```
pub fn render_jail_local(spec: &JailSpec, namespace: &str) -> String {
    let mut out = String::with_capacity(512);

    let _ = writeln!(out, "{}", managed_header());

    let _ = writeln!(out, "[{}]", spec.name);

    let _ = writeln!(out, "enabled = {}", spec.enabled);

    let filter_ref = if spec.filter.failregex.is_empty() {
        spec.filter.name.to_string()
    } else {
        format!("{namespace}-{}", spec.filter.name)
    };
    if let Some(mode) = &spec.filter.mode {
        let _ = writeln!(out, "filter = {filter_ref}[mode={mode}]");
    } else {
        let _ = writeln!(out, "filter = {filter_ref}");
    }

    if spec.backend != Backend::default() {
        let _ = writeln!(out, "backend = {}", spec.backend);
    }

    if !spec.log_paths.is_empty() {
        let _ = writeln!(out, "logpath = {}", spec.log_paths[0]);
        for path in &spec.log_paths[1..] {
            let _ = writeln!(out, "        {path}");
        }
    }

    if !spec.journal_matches.is_empty() {
        let _ = writeln!(out, "journalmatch = {}", spec.journal_matches[0]);
        for jm in &spec.journal_matches[1..] {
            let _ = writeln!(out, "               {jm}");
        }
    }

    if !spec.ports.is_empty() {
        let _ = writeln!(
            out,
            "port = {}",
            spec.ports
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    if spec.protocol != Protocol::default() {
        let _ = writeln!(out, "protocol = {}", spec.protocol);
    }

    let _ = writeln!(out, "bantime = {}", spec.bantime);

    let _ = writeln!(out, "findtime = {}", spec.findtime);

    if spec.maxretry != 5 {
        let _ = writeln!(out, "maxretry = {}", spec.maxretry);
    }

    if spec.usedns != UseDns::default() {
        let _ = writeln!(out, "usedns = {}", spec.usedns);
    }

    if !spec.ignore_ips.is_empty() {
        let _ = write!(out, "ignoreip =");
        for ip in spec.ignore_ips.iter() {
            let _ = write!(out, " {ip}");
        }
        let _ = writeln!(out);
    }

    if let Some(maxlines) = spec.maxlines {
        let _ = writeln!(out, "maxlines = {maxlines}");
    }

    render_actions_section(&mut out, &spec.actions, namespace);

    let mut extras: Vec<_> = spec.extra_options.iter().collect();
    extras.sort_by_key(|(k, _)| *k);
    for (key, val) in extras {
        let _ = writeln!(out, "{key} = {val}");
    }

    out
}

/// Renders a [`FilterSpec`] into the contents of a filter `.local` file.
///
/// Only fields that carry a value are included. The `failregex` list is
/// rendered with Fail2Ban-style continuation lines (leading whitespace).
/// The section is `[Definition]`, which is what Fail2Ban's filter reader
/// requires.
///
/// # Arguments
///
/// * `spec` - The typed filter specification to render.
/// * `_namespace` - Unused for filter bodies; the namespace appears only in
///   the file name and the referencing jail.
///
/// # Example output
///
/// ```ini
/// # Managed by fail2ban-kit.
/// # Do not edit manually unless you also disable this manager.
///
/// [Definition]
/// prefregex = ^<F-MLFID>.*</F-MLFID>
/// failregex = ^Authentication failure from <HOST>$
///             ^Invalid user .* from <HOST>$
/// ignoreregex = ^.*known-good.*$
/// datepattern = {^LN-BEG}
/// ```
pub fn render_filter_local(spec: &FilterSpec, _namespace: &str) -> String {
    let mut out = String::with_capacity(512);

    let _ = writeln!(out, "{}", managed_header());

    let _ = writeln!(out, "[Definition]");

    if let Some(pref) = &spec.prefregex {
        let _ = writeln!(out, "prefregex = {pref}");
    }

    if !spec.failregex.is_empty() {
        let _ = writeln!(out, "failregex = {}", spec.failregex[0]);
        for re in &spec.failregex[1..] {
            let _ = writeln!(out, "            {re}");
        }
    }

    if !spec.ignoreregex.is_empty() {
        let _ = writeln!(out, "ignoreregex = {}", spec.ignoreregex[0]);
        for re in &spec.ignoreregex[1..] {
            let _ = writeln!(out, "             {re}");
        }
    }

    if let Some(dp) = &spec.datepattern {
        let _ = writeln!(out, "datepattern = {dp}");
    }

    if let Some(jm) = &spec.journalmatch {
        let _ = writeln!(out, "journalmatch = {jm}");
    }

    if let Some(mode) = &spec.mode {
        let _ = writeln!(out, "mode = {mode}");
    }

    let mut extras: Vec<_> = spec.extra_options.iter().collect();
    extras.sort_by_key(|(k, _)| *k);
    for (key, val) in extras {
        let _ = writeln!(out, "{key} = {val}");
    }

    out
}

/// Renders an [`ActionSpec`] into the contents of an action `.local` file.
///
/// Stock actions reference a built-in action name and may include parameter
/// overrides. Custom actions provide their own command templates. The section
/// is `[Definition]`, which is what Fail2Ban's action reader requires.
///
/// # Arguments
///
/// * `spec` - The typed action specification to render.
/// * `_namespace` - Unused for action bodies; the namespace appears only in
///   the file name and the referencing jail.
///
/// # Example output
///
/// ```ini
/// # Managed by fail2ban-kit.
/// # Do not edit manually unless you also disable this manager.
///
/// [Definition]
/// actionstart = /usr/local/bin/f2b-hook start
/// actionstop = /usr/local/bin/f2b-hook stop
/// actioncheck =
/// actionban = /usr/local/bin/f2b-hook ban <ip>
/// actionunban = /usr/local/bin/f2b-hook unban <ip>
/// timeout = 30
/// ```
pub fn render_action_local(spec: &ActionSpec, _namespace: &str) -> String {
    let mut out = String::with_capacity(512);

    let _ = writeln!(out, "{}", managed_header());

    let _ = writeln!(out, "[Definition]");

    if let Some(cmd) = &spec.actionstart {
        let _ = writeln!(out, "actionstart = {cmd}");
    }
    if let Some(cmd) = &spec.actionstop {
        let _ = writeln!(out, "actionstop = {cmd}");
    }
    if let Some(cmd) = &spec.actioncheck {
        let _ = writeln!(out, "actioncheck = {cmd}");
    }
    if let Some(cmd) = &spec.actionban {
        let _ = writeln!(out, "actionban = {cmd}");
    }
    if let Some(cmd) = &spec.actionunban {
        let _ = writeln!(out, "actionunban = {cmd}");
    }

    if let Some(dur) = spec.timeout {
        let secs = dur.as_secs();
        let _ = writeln!(out, "timeout = {secs}");
    }

    let mut params: Vec<_> = spec.parameters.iter().collect();
    params.sort_by_key(|(k, _)| *k);
    for (key, val) in params {
        let _ = writeln!(out, "{key} = {val}");
    }

    out
}

/// Returns the filename for a generated jail `.local` file.
///
/// Format: `{namespace}-{name}.local`
///
/// # Example
///
/// ```
/// # use toride_fail2ban::render::render_jail_filename;
/// assert_eq!(render_jail_filename("myapp", "managed-by-fail2ban-kit"),
///            "managed-by-fail2ban-kit-myapp.local");
/// ```
pub fn render_jail_filename(name: &str, namespace: &str) -> String {
    format!("{namespace}-{name}.local")
}

/// Returns the filename for a generated filter `.local` file.
///
/// Format: `{namespace}-{name}.local`
///
/// # Example
///
/// ```
/// # use toride_fail2ban::render::render_filter_filename;
/// assert_eq!(render_filter_filename("myapp-auth", "managed-by-fail2ban-kit"),
///            "managed-by-fail2ban-kit-myapp-auth.local");
/// ```
pub fn render_filter_filename(name: &str, namespace: &str) -> String {
    format!("{namespace}-{name}.local")
}

/// Returns the filename for a generated action `.local` file.
///
/// Format: `{namespace}-{name}.local`
///
/// # Example
///
/// ```
/// # use toride_fail2ban::render::render_action_filename;
/// assert_eq!(render_action_filename("my-hook", "managed-by-fail2ban-kit"),
///            "managed-by-fail2ban-kit-my-hook.local");
/// ```
pub fn render_action_filename(name: &str, namespace: &str) -> String {
    format!("{namespace}-{name}.local")
}

/// Renders the `action = ...` section of a jail config.
///
/// Stock actions are rendered as their stock name, optionally with parameters.
/// Custom actions are rendered under their namespaced name (the file the
/// config layer writes for them), optionally with parameters. Each action
/// appears on its own line, with additional actions on continuation lines
/// indented with leading whitespace per Fail2Ban convention.
fn render_actions_section(out: &mut String, actions: &[ActionSpec], namespace: &str) {
    if actions.is_empty() {
        return;
    }

    let rendered: Vec<String> = actions
        .iter()
        .map(|a| format_action_reference(a, namespace))
        .collect();

    let _ = writeln!(out, "action = {}", rendered[0]);
    for action_str in &rendered[1..] {
        let _ = writeln!(out, "        {action_str}");
    }
}

/// Formats an action into its Fail2Ban config representation.
///
/// Stock actions: `stockname[param1=val1, param2=val2]`
/// Custom actions: `{namespace}-name[param1=val1]`
/// Parameters are sorted alphabetically for deterministic output.
fn format_action_reference(action: &ActionSpec, namespace: &str) -> String {
    let display_name = match (action.kind, action.stock_name.as_deref()) {
        (ActionKind::Stock, Some(stock)) => stock.to_owned(),
        (ActionKind::Custom, _) => format!("{namespace}-{}", action.name),
        (ActionKind::Stock, None) => action.name.as_str().to_owned(),
    };

    if action.parameters.is_empty() {
        return display_name;
    }

    let mut params: Vec<_> = action.parameters.iter().collect();
    params.sort_by_key(|(k, _)| *k);

    let param_str = params
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(", ");

    format!("{display_name}[{param_str}]")
}

#[cfg(test)]
#[path = "render.test.rs"]
mod tests;
