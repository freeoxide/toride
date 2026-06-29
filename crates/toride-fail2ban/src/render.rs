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

use crate::spec::*;

// ---------------------------------------------------------------------------
// Managed header
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Jail rendering
// ---------------------------------------------------------------------------

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
/// * `namespace` - Manager namespace used in the filter reference
///   (`filter = <name>[<mode>]`). This is not part of the section header;
///   the section name is always `spec.name`.
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

    // Header
    let _ = writeln!(out, "{}", managed_header());

    // Section header
    let _ = writeln!(out, "[{}]", spec.name);

    // enabled — always emit since it is the primary toggle
    let _ = writeln!(out, "enabled = {}", spec.enabled);

    // filter — always required; include mode if the filter specifies one
    if let Some(mode) = &spec.filter.mode {
        let _ = writeln!(out, "filter = {}[mode={}]", spec.filter.name, mode);
    } else {
        let _ = writeln!(out, "filter = {}", spec.filter.name);
    }

    // backend — emit unless it is the default (Auto)
    if spec.backend != Backend::default() {
        let _ = writeln!(out, "backend = {}", spec.backend);
    }

    // logpath — one path per continuation line
    if !spec.log_paths.is_empty() {
        let _ = writeln!(out, "logpath = {}", spec.log_paths[0]);
        for path in &spec.log_paths[1..] {
            let _ = writeln!(out, "        {}", path);
        }
    }

    // journalmatch — emit each match on a continuation line
    if !spec.journal_matches.is_empty() {
        let _ = writeln!(out, "journalmatch = {}", spec.journal_matches[0]);
        for jm in &spec.journal_matches[1..] {
            let _ = writeln!(out, "               {}", jm);
        }
    }

    // port — space-separated list of port specs
    if !spec.ports.is_empty() {
        let _ = writeln!(
            out,
            "port = {}",
            spec.ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    // protocol — emit unless it is the default (Tcp)
    if spec.protocol != Protocol::default() {
        let _ = writeln!(out, "protocol = {}", spec.protocol);
    }

    // bantime — always required
    let _ = writeln!(out, "bantime = {}", spec.bantime);

    // findtime — always required
    let _ = writeln!(out, "findtime = {}", spec.findtime);

    // maxretry — emit unless it is the default (5)
    if spec.maxretry != 5 {
        let _ = writeln!(out, "maxretry = {}", spec.maxretry);
    }

    // usedns — emit unless it is the default (No), which is the secure default
    if spec.usedns != UseDns::default() {
        let _ = writeln!(out, "usedns = {}", spec.usedns);
    }

    // ignoreip — space-separated list
    if !spec.ignore_ips.is_empty() {
        let _ = write!(out, "ignoreip =");
        for ip in spec.ignore_ips.iter() {
            let _ = write!(out, " {ip}");
        }
        let _ = writeln!(out);
    }

    // maxlines — only if set
    if let Some(maxlines) = spec.maxlines {
        let _ = writeln!(out, "maxlines = {}", maxlines);
    }

    // actions — each action on its own line with continuation
    render_actions_section(&mut out, &spec.actions, namespace);

    // extra_options — sorted for deterministic output
    let mut extras: Vec<_> = spec.extra_options.iter().collect();
    extras.sort_by_key(|(k, _)| *k);
    for (key, val) in extras {
        let _ = writeln!(out, "{key} = {val}");
    }

    out
}

// ---------------------------------------------------------------------------
// Filter rendering
// ---------------------------------------------------------------------------

/// Renders a [`FilterSpec`] into the contents of a filter `.local` file.
///
/// Only fields that carry a value are included. The `failregex` list is
/// rendered with Fail2Ban-style continuation lines (leading whitespace).
///
/// # Arguments
///
/// * `spec` - The typed filter specification to render.
/// * `_namespace` - Reserved for future namespace-scoped rendering; currently
///   unused for filter files.
///
/// # Example output
///
/// ```ini
/// # Managed by fail2ban-kit.
/// # Do not edit manually unless you also disable this manager.
///
/// [myapp-auth]
/// prefregex = ^<F-MLFID>.*</F-MLFID>
/// failregex = ^Authentication failure from <HOST>$
///             ^Invalid user .* from <HOST>$
/// ignoreregex = ^.*known-good.*$
/// datepattern = {^LN-BEG}
/// ```
pub fn render_filter_local(spec: &FilterSpec, _namespace: &str) -> String {
    let mut out = String::with_capacity(512);

    // Header
    let _ = writeln!(out, "{}", managed_header());

    // Section header
    let _ = writeln!(out, "[{}]", spec.name);

    // prefregex
    if let Some(pref) = &spec.prefregex {
        let _ = writeln!(out, "prefregex = {}", pref);
    }

    // failregex — always present for a meaningful filter
    if !spec.failregex.is_empty() {
        let _ = writeln!(out, "failregex = {}", spec.failregex[0]);
        for re in &spec.failregex[1..] {
            let _ = writeln!(out, "            {re}");
        }
    }

    // ignoreregex — continuation lines
    if !spec.ignoreregex.is_empty() {
        let _ = writeln!(out, "ignoreregex = {}", spec.ignoreregex[0]);
        for re in &spec.ignoreregex[1..] {
            let _ = writeln!(out, "             {re}");
        }
    }

    // datepattern
    if let Some(dp) = &spec.datepattern {
        let _ = writeln!(out, "datepattern = {}", dp);
    }

    // journalmatch
    if let Some(jm) = &spec.journalmatch {
        let _ = writeln!(out, "journalmatch = {}", jm);
    }

    // mode
    if let Some(mode) = &spec.mode {
        let _ = writeln!(out, "mode = {}", mode);
    }

    // extra_options — sorted for deterministic output
    let mut extras: Vec<_> = spec.extra_options.iter().collect();
    extras.sort_by_key(|(k, _)| *k);
    for (key, val) in extras {
        let _ = writeln!(out, "{key} = {val}");
    }

    out
}

// ---------------------------------------------------------------------------
// Action rendering
// ---------------------------------------------------------------------------

/// Renders an [`ActionSpec`] into the contents of an action `.local` file.
///
/// Stock actions reference a built-in action name and may include parameter
/// overrides. Custom actions provide their own command templates.
///
/// # Arguments
///
/// * `spec` - The typed action specification to render.
/// * `_namespace` - Reserved for future namespace-scoped rendering; currently
///   unused for action files.
///
/// # Example output
///
/// ```ini
/// # Managed by fail2ban-kit.
/// # Do not edit manually unless you also disable this manager.
///
/// [my-hook]
/// actionstart = /usr/local/bin/f2b-hook start
/// actionstop = /usr/local/bin/f2b-hook stop
/// actioncheck =
/// actionban = /usr/local/bin/f2b-hook ban <ip>
/// actionunban = /usr/local/bin/f2b-hook unban <ip>
/// timeout = 30
/// ```
pub fn render_action_local(spec: &ActionSpec, _namespace: &str) -> String {
    let mut out = String::with_capacity(512);

    // Header
    let _ = writeln!(out, "{}", managed_header());

    // Section header
    let _ = writeln!(out, "[{}]", spec.name);

    // Action command templates — only emit when set
    if let Some(cmd) = &spec.actionstart {
        let _ = writeln!(out, "actionstart = {}", cmd);
    }
    if let Some(cmd) = &spec.actionstop {
        let _ = writeln!(out, "actionstop = {}", cmd);
    }
    if let Some(cmd) = &spec.actioncheck {
        let _ = writeln!(out, "actioncheck = {}", cmd);
    }
    if let Some(cmd) = &spec.actionban {
        let _ = writeln!(out, "actionban = {}", cmd);
    }
    if let Some(cmd) = &spec.actionunban {
        let _ = writeln!(out, "actionunban = {}", cmd);
    }

    // timeout — in seconds
    if let Some(dur) = spec.timeout {
        let secs = dur.as_secs();
        let _ = writeln!(out, "timeout = {}", secs);
    }

    // parameters — sorted for deterministic output
    let mut params: Vec<_> = spec.parameters.iter().collect();
    params.sort_by_key(|(k, _)| *k);
    for (key, val) in params {
        let _ = writeln!(out, "{key} = {val}");
    }

    out
}

// ---------------------------------------------------------------------------
// Filename helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Renders the `action = ...` section of a jail config.
///
/// Stock actions are rendered as their stock name, optionally with parameters.
/// Custom actions are rendered as their action name, optionally with parameters.
/// Each action appears on its own line, with additional actions on continuation
/// lines indented with leading whitespace per Fail2Ban convention.
fn render_actions_section(out: &mut String, actions: &[ActionSpec], _namespace: &str) {
    if actions.is_empty() {
        return;
    }

    // Build the display form for each action.
    let rendered: Vec<String> = actions.iter().map(|a| format_action_reference(a)).collect();

    let _ = writeln!(out, "action = {}", rendered[0]);
    for action_str in &rendered[1..] {
        let _ = writeln!(out, "        {action_str}");
    }
}

/// Formats an action into its Fail2Ban config representation.
///
/// Stock actions: `stockname[param1=val1, param2=val2]`
/// Custom actions: `name[param1=val1]`
/// Parameters are sorted alphabetically for deterministic output.
fn format_action_reference(action: &ActionSpec) -> String {
    let display_name = action
        .stock_name
        .as_deref()
        .unwrap_or_else(|| action.name.as_str());

    if action.parameters.is_empty() {
        return display_name.to_owned();
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "render.test.rs"]
mod tests;
