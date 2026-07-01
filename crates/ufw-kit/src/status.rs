//! UFW status parsing.
//!
//! Parses the output of `ufw status`, `ufw status verbose`, and
//! `ufw status numbered` into structured types.

use crate::error::Result;
use crate::spec::{
    Action, AddedRule, AppDefaultPolicy, Direction, ListeningPort, LoggingLevel, ParsedRule,
    Policy, UfwStatus,
};

/// Parse `ufw status verbose` output.
pub fn parse_status_verbose(output: &str) -> Result<UfwStatus> {
    let mut status = UfwStatus {
        active: false,
        default_incoming: None,
        default_outgoing: None,
        default_routed: None,
        logging_level: None,
        new_app_profiles: None,
        rules: Vec::new(),
    };

    for line in output.lines() {
        let trimmed = line.trim();

        // Check active/inactive
        if trimmed.starts_with("Status:") {
            status.active = trimmed.contains("active") && !trimmed.contains("inactive");
            continue;
        }

        // Check default policies
        if let Some(rest) = trimmed.strip_prefix("Default:") {
            // Format: "Default: deny (incoming), allow (outgoing), disabled (routed)"
            for part in rest.split(',') {
                let part = part.trim();
                if let Some(policy_str) = extract_policy_before_label(part, "incoming") {
                    status.default_incoming = parse_policy(policy_str);
                } else if let Some(policy_str) = extract_policy_before_label(part, "outgoing") {
                    status.default_outgoing = parse_policy(policy_str);
                } else if let Some(policy_str) = extract_policy_before_label(part, "routed") {
                    status.default_routed = parse_policy(policy_str);
                }
            }
            continue;
        }

        // Check logging level
        if trimmed.starts_with("Logging:") {
            let rest = trimmed.strip_prefix("Logging:").unwrap().trim();
            status.logging_level = Some(parse_logging_level(rest));
            continue;
        }

        // Check new app profiles
        if trimmed.starts_with("New profiles:") {
            let rest = trimmed.strip_prefix("New profiles:").unwrap().trim();
            status.new_app_profiles = parse_app_default_policy(rest);
            continue;
        }

        // Parse rule lines
        if !trimmed.is_empty()
            && !is_separator_line(trimmed)
            && !trimmed.starts_with("To")
            && !trimmed.starts_with("Action")
        {
            if let Some(rule) = parse_rule_line(trimmed, false) {
                status.rules.push(rule);
            }
        }
    }

    Ok(status)
}

/// Parse `ufw status` (non-verbose) output.
pub fn parse_status(output: &str) -> Result<UfwStatus> {
    let mut status = UfwStatus {
        active: false,
        default_incoming: None,
        default_outgoing: None,
        default_routed: None,
        logging_level: None,
        new_app_profiles: None,
        rules: Vec::new(),
    };

    for line in output.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("Status:") {
            status.active = trimmed.contains("active") && !trimmed.contains("inactive");
            continue;
        }

        if !trimmed.is_empty()
            && !is_separator_line(trimmed)
            && !trimmed.starts_with("To")
            && !trimmed.starts_with("Action")
        {
            if let Some(rule) = parse_rule_line(trimmed, false) {
                status.rules.push(rule);
            }
        }
    }

    Ok(status)
}

/// Check if a line is a table separator (e.g., "---  ------  ----").
fn is_separator_line(line: &str) -> bool {
    // A separator line is one where most non-space characters are dashes
    let non_space: usize = line.chars().filter(|c| !c.is_whitespace()).count();
    if non_space == 0 {
        return false;
    }
    let dashes: usize = line.chars().filter(|c| *c == '-').count();
    // If at least 80% of non-space chars are dashes, it's a separator
    dashes * 100 / non_space >= 80
}

/// Parse `ufw status numbered` output.
pub fn parse_status_numbered(output: &str) -> Result<UfwStatus> {
    let mut status = UfwStatus {
        active: false,
        default_incoming: None,
        default_outgoing: None,
        default_routed: None,
        logging_level: None,
        new_app_profiles: None,
        rules: Vec::new(),
    };

    for line in output.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("Status:") {
            status.active = trimmed.contains("active") && !trimmed.contains("inactive");
            continue;
        }

        if !trimmed.is_empty()
            && !is_separator_line(trimmed)
            && !trimmed.starts_with("To")
            && !trimmed.starts_with("Action")
        {
            if let Some(rule) = parse_numbered_rule_line(trimmed) {
                status.rules.push(rule);
            }
        }
    }

    Ok(status)
}

/// Parse `ufw show listening` output.
///
/// Expects output of the form:
///
/// ```text
/// Listening:
///  tcp 0.0.0.0:22
///  tcp [::]:22
/// ```
pub fn parse_show_listening(raw: &str) -> Vec<ListeningPort> {
    let mut ports = Vec::new();
    let mut past_header = false;

    for line in raw.lines() {
        let trimmed = line.trim();

        if !past_header {
            if trimmed.starts_with("Listening:") {
                past_header = true;
            }
            continue;
        }

        if trimmed.is_empty() {
            continue;
        }

        // Each data line: "proto address" (separated by whitespace).
        let mut segments = trimmed.splitn(2, char::is_whitespace);
        let proto = match segments.next() {
            Some(p) => p.to_string(),
            None => continue,
        };
        let address = match segments.next() {
            Some(a) => a.to_string(),
            None => continue,
        };

        if proto.is_empty() || address.is_empty() {
            continue;
        }

        ports.push(ListeningPort { proto, address });
    }

    ports
}

/// Parse `ufw show added` output.
///
/// Expects output of the form:
///
/// ```text
/// Added user rules (see 'ufw status'):
/// allow 22/tcp
/// deny 53/udp
/// ```
pub fn parse_show_added(raw: &str) -> Vec<AddedRule> {
    let mut rules = Vec::new();
    let mut past_header = false;

    for line in raw.lines() {
        let trimmed = line.trim();

        if !past_header {
            // The header line starts with "Added user rules"
            if trimmed.starts_with("Added user rules") || trimmed.starts_with("Added") {
                past_header = true;
            }
            continue;
        }

        if trimmed.is_empty() {
            continue;
        }

        rules.push(AddedRule {
            raw: trimmed.to_string(),
        });
    }

    rules
}

/// Parse a single rule line from non-numbered status.
///
/// Real `ufw status` / `ufw status numbered` output is column-oriented:
///
/// ```text
/// To                         Action      From
/// --                         ------      ----
/// 22/tcp                     ALLOW IN    Anywhere
/// [ 1] 22/tcp                ALLOW IN    Anywhere
/// ```
///
/// So the action token (ALLOW/DENY/REJECT/LIMIT) is NOT necessarily at the
/// start of the line — it typically follows the destination port/target. We
/// locate the action token by scanning whitespace-delimited tokens, which
/// keeps the parser correct regardless of column width or leading `[N]`.
fn parse_rule_line(line: &str, _is_numbered: bool) -> Option<ParsedRule> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Determine if this is an IPv6 rule (UFW marks them with "(v6)" on some systems)
    let ipv6 = trimmed.contains("(v6)") || trimmed.contains("v6");

    // Determine if this is a route rule
    let is_route = trimmed.contains("ROUTE") || trimmed.contains("route");

    // Find the action token (ALLOW/DENY/REJECT/LIMIT) by scanning
    // whitespace-delimited tokens. UFW uppercases these keywords in status
    // output; we match case-insensitively to be tolerant.
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    let (action, action_idx) = tokens
        .iter()
        .enumerate()
        .find_map(|(i, tok)| match tok.to_ascii_lowercase().as_str() {
            "allow" => Some((Some(Action::Allow), i)),
            "deny" => Some((Some(Action::Deny), i)),
            "reject" => Some((Some(Action::Reject), i)),
            "limit" => Some((Some(Action::Limit), i)),
            _ => None,
        })
        .unwrap_or((None, 0));

    // Direction (IN/OUT/FWD) immediately follows the action token, if present.
    let direction = if action.is_some() && action_idx + 1 < tokens.len() {
        match tokens[action_idx + 1] {
            "IN" | "in" => Some(Direction::In),
            "OUT" | "out" => Some(Direction::Out),
            "FWD" | "fwd" => Some(Direction::Routed),
            _ => None,
        }
    } else {
        None
    };

    // Extract comment if present (UFW appends "comment <text>").
    let comment = trimmed
        .find("comment")
        .map(|idx| trimmed[idx + "comment".len()..].trim().to_string());

    Some(ParsedRule {
        number: None,
        raw: trimmed.to_string(),
        action,
        direction,
        protocol: None,
        from: None,
        to: None,
        comment,
        ipv6,
        is_route,
    })
}

/// Parse a numbered rule line.
fn parse_numbered_rule_line(line: &str) -> Option<ParsedRule> {
    let trimmed = line.trim();

    // Numbered format: "[ 1] ALLOW IN    Anywhere       ..."
    // or with brackets: "[ 1] 22/tcp ALLOW IN Anywhere"
    if !trimmed.starts_with('[') {
        return parse_rule_line(trimmed, true);
    }

    let bracket_end = trimmed.find(']')?;
    let number_str = trimmed[1..bracket_end].trim();
    let number: u32 = number_str.parse().ok()?;
    let rest = trimmed[bracket_end + 1..].trim();

    let mut rule = parse_rule_line(rest, true)?;
    rule.number = Some(number);
    Some(rule)
}

/// Extract the policy value before a label in parentheses.
///
/// For "deny (incoming)" with label "incoming", returns "deny".
fn extract_policy_before_label<'a>(text: &'a str, label: &str) -> Option<&'a str> {
    // Look for "(label)" pattern
    let paren_label = format!("({label})");
    let idx = text.find(&paren_label)?;
    let before = text[..idx].trim();
    if before.is_empty() {
        return None;
    }
    Some(before)
}

/// Parse a policy string.
fn parse_policy(s: &str) -> Option<Policy> {
    match s.trim().to_lowercase().as_str() {
        "allow" | "accept" => Some(Policy::Allow),
        "deny" | "drop" => Some(Policy::Deny),
        "reject" => Some(Policy::Reject),
        _ => None,
    }
}

/// Parse a logging level string.
///
/// Handles formats like "on (low)", "on", "off", "low", "medium", "high", "full".
fn parse_logging_level(s: &str) -> LoggingLevel {
    let lower = s.trim().to_lowercase();

    // Handle "on (level)" format first — extract the parenthesized level
    if let Some(start) = lower.find('(') {
        if let Some(end) = lower.find(')') {
            let level_str = lower[start + 1..end].trim();
            return match level_str {
                "full" => LoggingLevel::Full,
                "high" => LoggingLevel::High,
                "medium" => LoggingLevel::Medium,
                "low" => LoggingLevel::Low,
                "off" => LoggingLevel::Off,
                _ => LoggingLevel::On,
            };
        }
    }

    // Plain values
    if lower.contains("full") {
        LoggingLevel::Full
    } else if lower.contains("high") {
        LoggingLevel::High
    } else if lower.contains("medium") {
        LoggingLevel::Medium
    } else if lower.contains("low") {
        LoggingLevel::Low
    } else if lower.contains("on") || lower.contains("yes") {
        LoggingLevel::On
    } else {
        LoggingLevel::Off
    }
}

/// Parse app default policy string.
fn parse_app_default_policy(s: &str) -> Option<AppDefaultPolicy> {
    match s.trim().to_lowercase().as_str() {
        "skip" => Some(AppDefaultPolicy::Skip),
        "allow" => Some(AppDefaultPolicy::Allow),
        "deny" => Some(AppDefaultPolicy::Deny),
        _ => None,
    }
}

#[cfg(test)]
#[path = "status.test.rs"]
mod tests;
