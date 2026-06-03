//! Sysctl read/write operations.
//!
//! Provides functions to read, write, and enumerate kernel parameters
//! through the `sysctl` command via the [`toride_runner::Runner`] trait.

use crate::error::{Error, Result};
use crate::parse::{parse_single_value, parse_sysctl_output};
use toride_runner::{CommandSpec, Runner};

/// Read a single sysctl parameter value.
///
/// Executes `sysctl -n <key>` and returns the trimmed value.
///
/// # Errors
///
/// Returns [`Error::CommandFailed`] if sysctl exits non-zero,
/// or [`Error::SysctlParse`] if the output is empty.
pub fn read_sysctl(runner: &dyn Runner, key: &str) -> Result<String> {
    let spec = CommandSpec::new("sysctl").arg("-n").arg(key);
    let output = runner.run_checked(&spec)?;
    parse_single_value(&output.stdout)
}

/// Write a sysctl parameter value at runtime.
///
/// Executes `sysctl -w <key>=<value>`. This change is transient
/// and will not survive a reboot. For persistent changes, write
/// to `/etc/sysctl.conf` or a `/etc/sysctl.d/` drop-in.
///
/// # Errors
///
/// Returns [`Error::CommandFailed`] if sysctl exits non-zero.
pub fn write_sysctl(runner: &dyn Runner, key: &str, value: &str) -> Result<()> {
    let assignment = format!("{key}={value}");
    let spec = CommandSpec::new("sysctl").arg("-w").arg(&assignment);
    runner.run_checked(&spec)?;
    tracing::info!("sysctl: set {key}={value}");
    Ok(())
}

/// Read all sysctl parameters.
///
/// Executes `sysctl -a` and parses the output into key-value pairs.
///
/// # Errors
///
/// Returns [`Error::CommandFailed`] if sysctl exits non-zero.
pub fn read_all(runner: &dyn Runner) -> Result<Vec<(String, String)>> {
    let spec = CommandSpec::new("sysctl").arg("-a");
    let output = runner.run_checked(&spec)?;
    Ok(parse_sysctl_output(&output.stdout))
}

/// Apply a sysctl parameter if it differs from the current value.
///
/// Returns `true` if the value was changed, `false` if it was already set.
///
/// # Errors
///
/// Returns errors from reading or writing sysctl.
pub fn apply_if_needed(runner: &dyn Runner, key: &str, value: &str) -> Result<bool> {
    match read_sysctl(runner, key) {
        Ok(current) if current == value => {
            tracing::debug!("sysctl: {key} already set to {value}, skipping");
            Ok(false)
        }
        Ok(current) => {
            tracing::info!("sysctl: changing {key} from {current} to {value}");
            write_sysctl(runner, key, value)?;
            Ok(true)
        }
        Err(Error::CommandFailed { .. }) => {
            // Key might not exist yet (e.g. module not loaded)
            tracing::info!("sysctl: setting {key}={value} (key was not readable)");
            write_sysctl(runner, key, value)?;
            Ok(true)
        }
        Err(e) => Err(e),
    }
}

/// Find the `sysctl` binary on the system.
///
/// Returns the path to the binary, or an error if not found.
pub fn find_sysctl(runner: &dyn Runner) -> Result<String> {
    let spec = CommandSpec::new("which").arg("sysctl");
    match runner.run_checked(&spec) {
        Ok(output) => {
            let path = output.stdout.trim().to_string();
            if path.is_empty() {
                return Err(Error::BinaryNotFound("sysctl".into()));
            }
            Ok(path)
        }
        Err(_) => Err(Error::BinaryNotFound("sysctl".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use toride_runner::CommandOutput;
    use toride_runner::fake::FakeRunner;

    fn sysctl_read_runner() -> FakeRunner {
        FakeRunner::new().push_response(CommandOutput::from_stdout("1\n"))
    }

    fn sysctl_write_runner() -> FakeRunner {
        FakeRunner::new().push_response(CommandOutput::from_stdout(""))
    }

    fn sysctl_read_all_runner() -> FakeRunner {
        FakeRunner::new().push_response(CommandOutput::from_stdout(
            "kernel.kptr_restrict = 1\nnet.ipv4.ip_forward = 0\n",
        ))
    }

    fn which_runner() -> FakeRunner {
        FakeRunner::new().push_response(CommandOutput::from_stdout("/usr/sbin/sysctl\n"))
    }

    #[test]
    fn read_sysctl_returns_value() {
        let runner = sysctl_read_runner();
        let val = read_sysctl(&runner, "kernel.kptr_restrict").unwrap();
        assert_eq!(val, "1");
    }

    #[test]
    fn read_all_parses_output() {
        let runner = sysctl_read_all_runner();
        let all = read_all(&runner).unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn find_sysctl_locates_binary() {
        let runner = which_runner();
        let path = find_sysctl(&runner).unwrap();
        assert_eq!(path, "/usr/sbin/sysctl");
    }
}
