//! UFW config file management (`/etc/default/ufw`).
//!
//! Provides safe key-value editing with comment preservation.

use std::fmt::Write;

use crate::spec::UfwConfig;

/// Parse `/etc/default/ufw` content.
pub fn parse_default_ufw(content: &str) -> UfwConfig {
    let mut config = UfwConfig::default();

    for line in content.lines() {
        let trimmed = line.trim();

        // Skip comments and empty lines
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some((key, value)) = parse_kv(trimmed) {
            let val = value.trim_matches('"').trim();
            match key {
                "IPV6" => config.ipv6 = Some(val == "yes"),
                "DEFAULT_INPUT_POLICY" => config.default_input_policy = Some(val.to_string()),
                "DEFAULT_OUTPUT_POLICY" => config.default_output_policy = Some(val.to_string()),
                "DEFAULT_FORWARD_POLICY" => config.default_forward_policy = Some(val.to_string()),
                "ENABLED" => config.enabled = Some(val == "yes"),
                "IPT_SYSCTL" => config.ipt_sysctl = Some(val.to_string()),
                "IPT_MODULES" => config.ipt_modules = Some(val.to_string()),
                "MANAGE_BUILTINS" => config.manage_builtins = Some(val == "yes"),
                _ => {}
            }
        }
    }

    config
}

/// Update a key in the config content, preserving comments and order.
pub fn update_config_key(content: &str, key: &str, value: &str) -> String {
    let mut found = false;
    let mut result = String::new();

    for line in content.lines() {
        let trimmed = line.trim();

        if let Some((k, _)) = parse_kv(trimmed) {
            if k == key {
                let _ = writeln!(result, "{key}={value}");
                found = true;
                continue;
            }
        }

        result.push_str(line);
        result.push('\n');
    }

    if !found {
        let _ = writeln!(result, "{key}={value}");
    }

    result
}

fn parse_kv(line: &str) -> Option<(&str, &str)> {
    if line.starts_with('#') || line.starts_with(';') {
        return None;
    }

    let eq = line.find('=')?;
    let key = line[..eq].trim();
    let value = line[eq + 1..].trim();

    Some((key, value))
}

#[cfg(test)]
#[path = "config.test.rs"]
mod tests;
