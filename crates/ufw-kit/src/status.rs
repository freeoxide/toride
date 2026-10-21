//! UFW status parsing.
//!
//! Parses the output of `ufw status`, `ufw status verbose`, and
//! `ufw status numbered` into structured types. Rule lines are split into
//! their `To` / `Action` / `From` table columns; [`ParsedRule::to`] and
//! [`ParsedRule::from`] carry the column text (with the `(v6)` suffix
//! stripped into [`ParsedRule::ipv6`]) so callers can match structurally
//! instead of by raw substring.

use crate::error::Result;
use crate::spec::{
    Action, AddedRule, Address, AppDefaultPolicy, Direction, ListeningPort, LoggingLevel,
    ParsedRule, Policy, PortSpec, Protocol, ProtocolFilter, UfwStatus,
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
        if !trimmed.is_empty() && !is_separator_line(trimmed) && !is_table_header(trimmed) {
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

        if !trimmed.is_empty() && !is_separator_line(trimmed) && !is_table_header(trimmed) {
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

/// Check whether a line is the status table header.
///
/// The header is exactly the `To` / `Action` / `From` token triple; a rule
/// whose To column merely starts with those letters (an app profile named
/// `Tomcat`) must not be skipped.
fn is_table_header(line: &str) -> bool {
    let mut tokens = line.split_whitespace();
    tokens.next().is_some_and(|t| t.eq_ignore_ascii_case("To"))
        && tokens
            .next()
            .is_some_and(|t| t.eq_ignore_ascii_case("Action"))
        && tokens
            .next()
            .is_some_and(|t| t.eq_ignore_ascii_case("From"))
        && tokens.next().is_none()
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

        if !trimmed.is_empty() && !is_separator_line(trimmed) && !is_table_header(trimmed) {
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
/// [ 1] 22/tcp                ALLOW IN    Anywhere (v6)
/// ```
///
/// The action token (ALLOW/DENY/REJECT/LIMIT) is located by scanning
/// whitespace-delimited tokens, so column width and a leading `[N]` do not
/// matter. Everything before the action is the To column; the direction
/// token (IN/OUT/FWD) and the From column follow it. A standalone `comment`
/// token terminates the From column. The To/From column text is stored on
/// the rule with the `(v6)` suffix stripped; the suffix sets [`ParsedRule::ipv6`].
fn parse_rule_line(line: &str, _is_numbered: bool) -> Option<ParsedRule> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut action = None;
    let mut action_start = trimmed.len();
    let mut action_end = trimmed.len();
    let mut is_route = false;
    let bytes = trimmed.as_bytes();
    let mut cursor = 0;
    'scan: while cursor < bytes.len() {
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        let start = cursor;
        while cursor < bytes.len() && !bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if start == cursor {
            break 'scan;
        }
        let token = &trimmed[start..cursor];
        if let Some(a) = action_from_token(token) {
            action = Some(a);
            action_start = start;
            action_end = cursor;
            break 'scan;
        }
        if token.eq_ignore_ascii_case("route") {
            is_route = true;
        }
    }

    if action.is_none() {
        return Some(ParsedRule {
            number: None,
            raw: trimmed.to_string(),
            action: None,
            direction: None,
            protocol: None,
            from: None,
            to: interned_column(trimmed),
            comment: None,
            ipv6: false,
            is_route,
        });
    }

    let to_column = trimmed[..action_start].trim_end();
    let mut tail = trimmed[action_end..].trim_start();

    let mut direction = None;
    let tok_len = tail.find(char::is_whitespace).unwrap_or(tail.len());
    let dir_token = &tail[..tok_len];
    if dir_token.eq_ignore_ascii_case("in") {
        direction = Some(Direction::In);
    } else if dir_token.eq_ignore_ascii_case("out") {
        direction = Some(Direction::Out);
    } else if dir_token.eq_ignore_ascii_case("fwd") {
        direction = Some(Direction::Routed);
    }
    if direction.is_some() {
        tail = tail[tok_len..].trim_start();
    }

    let (from_column, comment, tail_is_route) = split_comment_marker(tail);
    let is_route = is_route || tail_is_route;

    let ipv6 = to_column.ends_with("(v6)") || from_column.ends_with("(v6)");
    let to_column = to_column.strip_suffix(" (v6)").unwrap_or(to_column);
    let from_column = from_column.strip_suffix(" (v6)").unwrap_or(from_column);

    Some(ParsedRule {
        number: None,
        raw: trimmed.to_string(),
        action,
        direction,
        protocol: protocol_of_column(to_column),
        from: interned_column(from_column),
        to: interned_column(to_column),
        comment,
        ipv6,
        is_route,
    })
}

/// Match a whitespace-delimited token against the UFW action keywords.
fn action_from_token(token: &str) -> Option<Action> {
    if token.eq_ignore_ascii_case("allow") {
        Some(Action::Allow)
    } else if token.eq_ignore_ascii_case("deny") {
        Some(Action::Deny)
    } else if token.eq_ignore_ascii_case("reject") {
        Some(Action::Reject)
    } else if token.eq_ignore_ascii_case("limit") {
        Some(Action::Limit)
    } else {
        None
    }
}

/// Split a From column at a standalone `comment` marker token.
///
/// Returns the From column text, the comment text that follows the marker,
/// and whether the tail carried a standalone `route` marker token. A From
/// host like `commentary.example.com` is not a marker: only a
/// whitespace-delimited `comment` token qualifies.
fn split_comment_marker(tail: &str) -> (&str, Option<String>, bool) {
    let bytes = tail.as_bytes();
    let mut cursor = 0;
    while cursor < bytes.len() {
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        let start = cursor;
        while cursor < bytes.len() && !bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if start == cursor {
            break;
        }
        let token = &tail[start..cursor];
        if token.eq_ignore_ascii_case("comment") {
            let before = tail[..start].trim_end();
            let after = tail[cursor..].trim_start();
            let comment = (!after.is_empty()).then(|| after.to_string());
            return (before, comment, false);
        }
        if token.eq_ignore_ascii_case("route") {
            return (tail, None, true);
        }
    }
    (tail, None, false)
}

/// Wrap a column as shared text, interning the dominant `Anywhere` value so
/// per-rule clones never allocate for it.
fn interned_column(column: &str) -> Option<std::sync::Arc<str>> {
    static ANYWHERE: std::sync::OnceLock<std::sync::Arc<str>> = std::sync::OnceLock::new();
    if column.is_empty() {
        return None;
    }
    if column == "Anywhere" {
        let shared = ANYWHERE.get_or_init(|| std::sync::Arc::from("Anywhere"));
        return Some(std::sync::Arc::clone(shared));
    }
    Some(std::sync::Arc::from(column))
}

/// Derive the protocol from a To column whose port token carries a
/// `/tcp` or `/udp` suffix.
fn protocol_of_column(to_column: &str) -> Option<Protocol> {
    let token = match to_column.rsplit_once(' ') {
        Some((_, last)) => last,
        None => to_column,
    };
    let proto = token.rsplit_once('/')?.1;
    if proto.eq_ignore_ascii_case("tcp") {
        Some(Protocol::Tcp)
    } else if proto.eq_ignore_ascii_case("udp") {
        Some(Protocol::Udp)
    } else {
        None
    }
}

/// Whether a status-table column targets `port` by token equality.
///
/// A token matches when its port part is `port`, a comma-separated list
/// containing `port`, or an inclusive `start:end` range covering `port`.
/// `8022/tcp` therefore never matches port `22`.
pub(crate) fn column_targets_port(column: &str, port: u16) -> bool {
    column.split_whitespace().any(|token| {
        let (ports, _proto) = split_port_proto(token);
        ports
            .split(',')
            .any(|part| part.parse::<u16>().is_ok_and(|p| p == port) || range_covers(part, port))
    })
}

/// Whether a status-table column matches a spec's destination port exactly.
///
/// Unlike [`column_targets_port`] this requires token equality (a range or
/// list covering the port is rule drift, not a match), and a spec protocol
/// must agree with an explicit `/proto` suffix on the token.
pub(crate) fn to_column_matches_port_spec(
    column: &str,
    spec: &PortSpec,
    spec_protocol: ProtocolFilter,
) -> bool {
    match spec {
        PortSpec::Any => true,
        PortSpec::Single(port) => column.split_whitespace().any(|token| {
            let (ports, proto) = split_port_proto(token);
            protocol_agrees(proto, spec_protocol)
                && ports.split(',').any(|p| p.parse::<u16>().is_ok_and(|v| v == *port))
        }),
        PortSpec::Range { start, end } => column.split_whitespace().any(|token| {
            let (ports, proto) = split_port_proto(token);
            protocol_agrees(proto, spec_protocol)
                && ports.split(',').any(|p| {
                    let Some((s, e)) = p.split_once(':') else {
                        return false;
                    };
                    matches!((s.parse::<u16>(), e.parse::<u16>()), (Ok(s), Ok(e)) if s == *start && e == *end)
                })
        }),
        PortSpec::List(_) => {
            let rendered = spec.to_string();
            column.split_whitespace().any(|token| {
                let (ports, proto) = split_port_proto(token);
                protocol_agrees(proto, spec_protocol) && ports == rendered
            })
        }
        PortSpec::ServiceName(name) => {
            column.eq_ignore_ascii_case(name)
                || column
                    .split_whitespace()
                    .any(|t| t.eq_ignore_ascii_case(name))
        }
    }
}

/// Whether a column targets `port` over `proto` by exact token equality,
/// or names the `service` alias.
pub(crate) fn column_targets_port_proto(
    column: &str,
    port: u16,
    proto: &str,
    service: &str,
) -> bool {
    if column.eq_ignore_ascii_case(service) {
        return true;
    }
    column.split_whitespace().any(|token| {
        let (ports, token_proto) = split_port_proto(token);
        token_proto.is_some_and(|p| p.eq_ignore_ascii_case(proto))
            && ports
                .split(',')
                .any(|p| p.parse::<u16>().is_ok_and(|v| v == port))
    })
}

fn split_port_proto(token: &str) -> (&str, Option<&str>) {
    match token.split_once('/') {
        Some((ports, proto)) => (ports, Some(proto)),
        None => (token, None),
    }
}

fn protocol_agrees(column_proto: Option<&str>, spec: ProtocolFilter) -> bool {
    match spec {
        ProtocolFilter::Any => true,
        ProtocolFilter::Specific(Protocol::Tcp) => {
            column_proto.is_none_or(|p| p.eq_ignore_ascii_case("tcp"))
        }
        ProtocolFilter::Specific(Protocol::Udp) => {
            column_proto.is_none_or(|p| p.eq_ignore_ascii_case("udp"))
        }
        ProtocolFilter::Specific(_) => column_proto.is_none(),
    }
}

fn range_covers(part: &str, target: u16) -> bool {
    let Some((lo, hi)) = part.split_once(':') else {
        return false;
    };
    match (lo.parse::<u16>(), hi.parse::<u16>()) {
        (Ok(lo), Ok(hi)) => lo <= target && target <= hi,
        _ => false,
    }
}

/// Whether a status-table column contains the address as a whole token.
///
/// `10.0.0.10` therefore never matches `10.0.0.1`.
pub(crate) fn column_matches_address(column: &str, addr: &Address) -> bool {
    match addr {
        Address::Any => true,
        Address::Ip(ip) => column.split_whitespace().any(|t| {
            t.parse::<std::net::IpAddr>()
                .is_ok_and(|parsed| parsed == *ip)
        }),
        Address::Net(net) => column
            .split_whitespace()
            .any(|t| t.parse::<ipnet::IpNet>().is_ok_and(|parsed| parsed == *net)),
    }
}

/// Whether a parsed rule allows traffic (Allow or Limit action).
pub(crate) fn rule_is_allow(rule: &ParsedRule) -> bool {
    if matches!(rule.action, Some(Action::Allow | Action::Limit)) {
        return true;
    }
    rule.action.is_none() && {
        let raw = rule.raw.to_lowercase();
        raw.contains("allow") || raw.contains("limit")
    }
}

/// Whether a parsed rule is inbound.
///
/// A rule with no direction token is inbound, which matches how ufw treats
/// direction-less rules; `allow out` carries an explicit OUT token.
pub(crate) fn rule_is_inbound(rule: &ParsedRule) -> bool {
    !matches!(rule.direction, Some(Direction::Out | Direction::Routed))
}

/// Whether the To column of a parsed rule targets an SSH port or the
/// `ssh` service name.
pub(crate) fn rule_targets_ssh(rule: &ParsedRule, ssh_ports: &[u16]) -> bool {
    let Some(to) = rule.to.as_deref() else {
        let raw = rule.raw.to_lowercase();
        return raw.contains("ssh")
            || ssh_ports
                .iter()
                .any(|p| raw.contains(&format!("{p}/tcp")) || raw.contains(&format!("{p}/udp")));
    };
    if to.eq_ignore_ascii_case("ssh") {
        return true;
    }
    ssh_ports.iter().any(|&p| column_targets_port(to, p))
}

/// Whether the From column of a parsed rule allows any source.
pub(crate) fn rule_source_unrestricted(rule: &ParsedRule) -> bool {
    rule.from
        .as_deref()
        .is_none_or(|f| f.eq_ignore_ascii_case("anywhere"))
}

/// Whether a parsed rule matches a spec's app-profile target.
pub(crate) fn rule_matches_app_profile(rule: &ParsedRule, app: &str) -> bool {
    rule.to
        .as_deref()
        .is_some_and(|to| to.eq_ignore_ascii_case(app))
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

    // Handle "on (level)" format first: extract the parenthesized level
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
