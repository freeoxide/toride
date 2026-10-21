//! Rule rendering: converts typed `RuleSpec` into UFW argument vectors.
//!
//! This module never produces shell strings. All output is argument arrays
//! suitable for passing directly to `duct::cmd` or similar.

use crate::spec::{
    Action, Address, DeleteOptions, PortSpec, ProtocolFilter, RouteRuleSpec, RuleLogging,
    RulePosition, RuleSpec,
};

/// Render a `RuleSpec` into UFW argument vector.
///
/// Returns `(program, args)` where program is always `"ufw"`.
///
/// The argv order follows the ufw grammar: an optional `delete` or
/// position prefix, the action, then the direction / `on <interface>`
/// clause, then `log` / `log-all`, protocol, source, destination, and
/// comment. A deleted rule takes no position prefix: ufw rejects
/// `delete insert N allow ...` at the action check.
#[must_use]
pub fn render_rule_args(spec: &RuleSpec) -> Vec<String> {
    let mut args = Vec::new();

    if spec.delete {
        args.push("delete".into());
    } else {
        match spec.position {
            RulePosition::Append => {}
            RulePosition::Prepend => args.push("prepend".into()),
            RulePosition::Insert(n) => {
                args.push("insert".into());
                args.push(n.to_string());
            }
        }
    }

    // Action
    args.push(spec.action.to_string());

    // Direction and interface clause precede the logging keyword; ufw
    // raises "Invalid interface clause" for `allow log in on eth0 ...`.
    if let Some(dir) = spec.direction {
        args.push(dir.to_string());
    }

    if let Some(iface) = &spec.interface {
        args.push("on".into());
        args.push(iface.clone());
    }

    match spec.logging {
        RuleLogging::None => {}
        RuleLogging::Log => args.push("log".into()),
        RuleLogging::LogAll => args.push("log-all".into()),
    }

    // Protocol
    match &spec.protocol {
        ProtocolFilter::Any => {}
        ProtocolFilter::Specific(proto) => {
            args.push("proto".into());
            args.push(proto.to_string());
        }
    }

    // Source
    if spec.from_addr != Address::Any || !matches!(spec.from_port, PortSpec::Any) {
        args.push("from".into());
        args.push(spec.from_addr.to_string());

        if !matches!(spec.from_port, PortSpec::Any) {
            args.push("port".into());
            args.push(spec.from_port.to_string());
        }
    }

    // Destination
    if spec.to_addr != Address::Any
        || !matches!(spec.to_port, PortSpec::Any)
        || spec.app_profile.is_some()
    {
        args.push("to".into());

        if let Some(app) = &spec.app_profile {
            args.push("app".into());
            args.push(app.clone());
        } else {
            args.push(spec.to_addr.to_string());

            if !matches!(spec.to_port, PortSpec::Any) {
                args.push("port".into());
                args.push(spec.to_port.to_string());
            }
        }
    }

    // Comment
    if let Some(comment) = &spec.comment {
        args.push("comment".into());
        args.push(comment.clone());
    }

    args
}

/// Render a simple rule in shorthand syntax.
///
/// Examples: `allow 22/tcp`, `deny 53`, `limit ssh/tcp`
#[must_use]
pub fn render_simple_rule(action: Action, target: &str) -> Vec<String> {
    vec![action.to_string(), target.to_string()]
}

/// Render a `RouteRuleSpec` into UFW argument vector.
#[must_use]
pub fn render_route_rule_args(spec: &RouteRuleSpec) -> Vec<String> {
    let mut args = Vec::new();

    if spec.delete {
        args.push("delete".into());
    }

    args.push("route".into());
    args.push(spec.action.to_string());

    // In interface
    if let Some(iface) = &spec.in_interface {
        args.push("in".into());
        args.push("on".into());
        args.push(iface.clone());
    }

    // Out interface
    if let Some(iface) = &spec.out_interface {
        args.push("out".into());
        args.push("on".into());
        args.push(iface.clone());
    }

    // Protocol
    match &spec.protocol {
        ProtocolFilter::Any => {}
        ProtocolFilter::Specific(proto) => {
            args.push("proto".into());
            args.push(proto.to_string());
        }
    }

    // Source
    if spec.from_addr != Address::Any {
        args.push("from".into());
        args.push(spec.from_addr.to_string());
    }

    // Destination
    if spec.to_addr != Address::Any || !matches!(spec.to_port, PortSpec::Any) {
        args.push("to".into());
        args.push(spec.to_addr.to_string());

        if !matches!(spec.to_port, PortSpec::Any) {
            args.push("port".into());
            args.push(spec.to_port.to_string());
        }
    }

    // Comment
    if let Some(comment) = &spec.comment {
        args.push("comment".into());
        args.push(comment.clone());
    }

    args
}

/// Render delete args for a rule by exact match.
#[must_use]
pub fn render_delete_args(spec: &RuleSpec) -> Vec<String> {
    let mut spec = spec.clone();
    spec.delete = true;
    render_rule_args(&spec)
}

/// Render delete args for a rule by number.
#[must_use]
pub fn render_delete_number_args(number: u32, _opts: &DeleteOptions) -> Vec<String> {
    vec!["delete".into(), number.to_string()]
}

/// Render default policy args.
#[must_use]
pub fn render_default_policy_args(
    direction: crate::spec::Direction,
    policy: crate::spec::Policy,
) -> Vec<String> {
    vec!["default".into(), direction.to_string(), policy.to_string()]
}

/// Render logging level args.
#[must_use]
pub fn render_logging_args(level: crate::spec::LoggingLevel) -> Vec<String> {
    vec!["logging".into(), level.to_string()]
}

/// Render app default policy args.
#[must_use]
pub fn render_app_default_args(policy: crate::spec::AppDefaultPolicy) -> Vec<String> {
    vec!["app".into(), "default".into(), policy.to_string()]
}

#[cfg(test)]
#[path = "rule.test.rs"]
mod tests;
