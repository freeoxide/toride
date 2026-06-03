//! Rendering functions for sysctl configuration files.
//!
//! Generates properly formatted sysctl.conf content and sysctl.d drop-in files.

use crate::spec::SysctlParam;

/// Render a list of parameters as a complete `sysctl.conf` file.
///
/// Each parameter is rendered with its description as a preceding comment.
/// Output is sorted by key for deterministic output.
///
/// # Example
///
/// ```
/// use toride_harden::render::render_sysctl_conf;
/// use toride_harden::spec::SysctlParam;
///
/// let params = vec![
///     SysctlParam::new("kernel.kptr_restrict", "1", "Restrict kernel pointer exposure"),
/// ];
/// let content = render_sysctl_conf(&params);
/// assert!(content.contains("kernel.kptr_restrict = 1"));
/// ```
pub fn render_sysctl_conf(params: &[SysctlParam]) -> String {
    let mut sorted: Vec<&SysctlParam> = params.iter().collect();
    sorted.sort_by(|a, b| a.key.cmp(&b.key));

    let mut lines = Vec::new();
    lines.push("# Managed by toride-harden.".into());
    lines.push("# Do not edit manually unless you also disable this manager.".into());
    lines.push(String::new());

    for p in &sorted {
        if !p.description.is_empty() {
            lines.push(format!("# {}", p.description));
        }
        lines.push(format!("{} = {}", p.key, p.value));
        lines.push(String::new());
    }

    lines.join("\n")
}

/// Render a sysctl.d drop-in file with a header identifying the source.
///
/// The `name` parameter is used in the header comment for traceability.
/// Output follows the same format as `/etc/sysctl.d/` drop-in files.
///
/// # Example
///
/// ```
/// use toride_harden::render::render_sysctl_d_dropin;
/// use toride_harden::spec::SysctlParam;
///
/// let params = vec![
///     SysctlParam::new("kernel.kptr_restrict", "1", "Restrict kptr"),
/// ];
/// let content = render_sysctl_d_dropin("99-harden-kernel", &params);
/// assert!(content.contains("99-harden-kernel"));
/// assert!(content.contains("kernel.kptr_restrict = 1"));
/// ```
pub fn render_sysctl_d_dropin(name: &str, params: &[SysctlParam]) -> String {
    let mut sorted: Vec<&SysctlParam> = params.iter().collect();
    sorted.sort_by(|a, b| a.key.cmp(&b.key));

    let mut lines = Vec::new();
    lines.push(format!("# Managed by toride-harden: {name}"));
    lines.push("# Do not edit manually.".into());
    lines.push(String::new());

    for p in &sorted {
        if !p.description.is_empty() {
            lines.push(format!("# {}", p.description));
        }
        lines.push(format!("{} = {}", p.key, p.value));
    }

    lines.push(String::new());
    lines.join("\n")
}

/// Render a single sysctl key=value assignment (for `sysctl -w`).
pub fn render_sysctl_w(key: &str, value: &str) -> String {
    format!("{key}={value}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_sysctl_conf_sorts_and_formats() {
        let params = vec![
            SysctlParam::new("net.ipv4.ip_forward", "0", "Disable IP forwarding"),
            SysctlParam::new("kernel.kptr_restrict", "1", "Restrict kptr"),
        ];
        let content = render_sysctl_conf(&params);
        assert!(content.contains("# Managed by toride-harden"));
        assert!(content.contains("kernel.kptr_restrict = 1"));
        assert!(content.contains("net.ipv4.ip_forward = 0"));
        // kernel comes before net in sorted order
        let kpos = content.find("kernel.kptr_restrict").unwrap();
        let npos = content.find("net.ipv4.ip_forward").unwrap();
        assert!(kpos < npos);
    }

    #[test]
    fn render_sysctl_d_dropin_includes_name() {
        let params = vec![SysctlParam::new("kernel.aslr", "2", "ASLR")];
        let content = render_sysctl_d_dropin("99-hardening", &params);
        assert!(content.contains("99-hardening"));
        assert!(content.contains("kernel.aslr = 2"));
    }

    #[test]
    fn render_sysctl_w_formats_assignment() {
        assert_eq!(
            render_sysctl_w("kernel.kptr_restrict", "1"),
            "kernel.kptr_restrict=1"
        );
    }
}
