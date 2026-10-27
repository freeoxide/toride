//! Rendering functions for sysctl configuration files.
//!
//! Generates properly formatted sysctl.conf content and sysctl.d drop-in
//! files. Both renderers validate their parameters: keys and values must
//! pass [`validate_sysctl_key`] / [`validate_sysctl_value`], and
//! descriptions must be single-line, because the files are parsed by root
//! at boot and a newline in a description would inject arbitrary
//! assignment lines.

use crate::error::{Error, Result};
use crate::spec::SysctlParam;
use crate::validate::{validate_sysctl_key, validate_sysctl_value};

/// Validate one parameter for rendering into a root-parsed config file.
fn validate_param_for_render(param: &SysctlParam) -> Result<()> {
    validate_sysctl_key(&param.key)?;
    validate_sysctl_value(&param.key, &param.value)?;
    if param.description.contains('\n') || param.description.contains('\r') {
        return Err(Error::ConfigWrite(format!(
            "description for '{}' must be a single line: {:?}",
            param.key, param.description
        )));
    }
    Ok(())
}

/// Render a list of parameters as a complete `sysctl.conf` file.
///
/// Each parameter is rendered with its description as a preceding comment.
/// Output is sorted by key for deterministic output.
///
/// # Errors
///
/// Returns an error when any parameter's key or value fails validation, or
/// a description contains a newline (which would inject assignment lines
/// into the root-parsed file).
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
/// let content = render_sysctl_conf(&params).unwrap();
/// assert!(content.contains("kernel.kptr_restrict = 1"));
/// ```
pub fn render_sysctl_conf(params: &[SysctlParam]) -> Result<String> {
    let mut sorted: Vec<&SysctlParam> = params.iter().collect();
    sorted.sort_by(|a, b| a.key.cmp(&b.key));

    let mut lines = Vec::new();
    lines.push("# Managed by toride-harden.".into());
    lines.push("# Do not edit manually unless you also disable this manager.".into());
    lines.push(String::new());

    for p in &sorted {
        validate_param_for_render(p)?;
        if !p.description.is_empty() {
            lines.push(format!("# {}", p.description));
        }
        lines.push(format!("{} = {}", p.key, p.value));
        lines.push(String::new());
    }

    Ok(lines.join("\n"))
}

/// Render a sysctl.d drop-in file with a header identifying the source.
///
/// The `name` parameter is used in the header comment for traceability.
/// Output follows the same format as `/etc/sysctl.d/` drop-in files.
///
/// # Errors
///
/// As [`render_sysctl_conf`].
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
/// let content = render_sysctl_d_dropin("99-harden-kernel", &params).unwrap();
/// assert!(content.contains("99-harden-kernel"));
/// assert!(content.contains("kernel.kptr_restrict = 1"));
/// ```
pub fn render_sysctl_d_dropin(name: &str, params: &[SysctlParam]) -> Result<String> {
    let mut sorted: Vec<&SysctlParam> = params.iter().collect();
    sorted.sort_by(|a, b| a.key.cmp(&b.key));

    let mut lines = Vec::new();
    lines.push(format!("# Managed by toride-harden: {name}"));
    lines.push("# Do not edit manually.".into());
    lines.push(String::new());

    for p in &sorted {
        validate_param_for_render(p)?;
        if !p.description.is_empty() {
            lines.push(format!("# {}", p.description));
        }
        lines.push(format!("{} = {}", p.key, p.value));
    }

    lines.push(String::new());
    Ok(lines.join("\n"))
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
        let content = render_sysctl_conf(&params).unwrap();
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
        let content = render_sysctl_d_dropin("99-hardening", &params).unwrap();
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

    #[test]
    fn render_rejects_newline_description_injection() {
        // Regression: a description containing a newline injected arbitrary
        // assignment lines into a root-parsed /etc/sysctl.d file.
        let params = vec![SysctlParam::new(
            "kernel.kptr_restrict",
            "1",
            "harmless\nkernel.dmesg_restrict = 0",
        )];
        assert!(render_sysctl_d_dropin("99-evil", &params).is_err());
        assert!(render_sysctl_conf(&params).is_err());
    }

    #[test]
    fn render_rejects_invalid_key_and_value() {
        let bad_key = vec![SysctlParam::new("NOT.A.KEY", "1", "")];
        assert!(render_sysctl_conf(&bad_key).is_err());
        let bad_value = vec![SysctlParam::new("kernel.dmesg_restrict", "9", "")];
        assert!(render_sysctl_d_dropin("99-evil", &bad_value).is_err());
    }

    #[cfg(feature = "config")]
    #[test]
    fn write_dropin_rejects_newline_description() {
        use crate::paths::HardenPaths;
        let dir = assert_fs::TempDir::new().unwrap();
        let paths = HardenPaths::with_root(dir.path());
        let params = vec![SysctlParam::new(
            "kernel.kptr_restrict",
            "1",
            "harmless\nkernel.dmesg_restrict = 0",
        )];
        assert!(crate::config::write_dropin(&paths, "99-evil", &params).is_err());
        assert!(
            !paths.sysctl_d.join("99-evil.conf").exists(),
            "the rejected drop-in must not reach /etc/sysctl.d"
        );
    }
}
