//! Error mapping — converts [`toride_runner::Error`] into [`MiseError`].
//!
//! This module isolates the `From`-style conversion so that the rest of the
//! crate can work entirely in terms of [`MiseError`]. Call [`map_runner_error`]
//! directly when you need an explicit conversion instead of `.into()`.

use crate::error::MiseError;

/// Convert a [`toride_runner::Error`] into a [`MiseError`].
///
/// `command` is a human-readable label (e.g. `"mise ls --output=json"`) that
/// is embedded in the resulting error variant for easier debugging.
pub fn map_runner_error(error: toride_runner::Error, _command: &str) -> MiseError {
    match error {
        toride_runner::Error::BinaryNotFound(_) => MiseError::BinaryNotFound,

        toride_runner::Error::SpawnFailed { ref detail, .. } => {
            let lower = detail.to_ascii_lowercase();
            if lower.contains("not found") || lower.contains("no such file") {
                MiseError::BinaryNotFound
            } else {
                MiseError::Io(std::io::Error::other(format!(
                    "failed to spawn process: {detail}"
                )))
            }
        }

        toride_runner::Error::CommandFailed {
            program,
            args,
            exit_code,
            stderr,
        } => {
            let full = format_command(&program, &args);
            MiseError::CommandFailed {
                command: full,
                exit_code,
                stdout: String::new(),
                stderr,
            }
        }

        toride_runner::Error::CommandTimeout {
            program,
            args,
            timeout: _,
        } => {
            let full = if args.is_empty() {
                program
            } else {
                format!("{program} {}", args.join(" "))
            };
            MiseError::Timeout { command: full }
        }

        toride_runner::Error::Io(msg) => MiseError::Io(std::io::Error::other(msg)),

        // Fallback for any variants we do not map explicitly.
        other => MiseError::Io(std::io::Error::other(other.to_string())),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a human-readable command string from program + args.
fn format_command(program: &str, args: &str) -> String {
    if args.is_empty() {
        program.to_owned()
    } else {
        format!("{program} {args}")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn binary_not_found() {
        let err = toride_runner::Error::BinaryNotFound("mise".into());
        let mapped = map_runner_error(err, "mise ls");
        assert!(matches!(mapped, MiseError::BinaryNotFound));
    }

    #[test]
    fn command_failed() {
        let err = toride_runner::Error::CommandFailed {
            program: "mise".into(),
            args: "ls --output=json".into(),
            exit_code: Some(1),
            stderr: "error: unknown flag".into(),
        };
        let mapped = map_runner_error(err, "mise ls --output=json");
        match mapped {
            MiseError::CommandFailed {
                command,
                exit_code,
                stdout,
                stderr,
            } => {
                assert_eq!(command, "mise ls --output=json");
                assert_eq!(exit_code, Some(1));
                assert!(stdout.is_empty());
                assert_eq!(stderr, "error: unknown flag");
            }
            other => panic!("expected CommandFailed, got {other:?}"),
        }
    }

    #[test]
    fn command_timeout() {
        let err = toride_runner::Error::CommandTimeout {
            program: "mise".into(),
            args: vec!["install".into(), "node".into()],
            timeout: Duration::from_secs(10),
        };
        let mapped = map_runner_error(err, "mise install node");
        match mapped {
            MiseError::Timeout { command } => {
                assert_eq!(command, "mise install node");
            }
            other => panic!("expected Timeout, got {other:?}"),
        }
    }

    #[test]
    fn spawn_failed_with_not_found_maps_to_binary_not_found() {
        let err = toride_runner::Error::SpawnFailed {
            program: "mise".into(),
            detail: "No such file or directory".into(),
        };
        let mapped = map_runner_error(err, "mise current");
        assert!(matches!(mapped, MiseError::BinaryNotFound));
    }

    #[test]
    fn spawn_failed_with_permission_denied_maps_to_io() {
        let err = toride_runner::Error::SpawnFailed {
            program: "mise".into(),
            detail: "permission denied".into(),
        };
        let mapped = map_runner_error(err, "mise current");
        match mapped {
            MiseError::Io(e) => assert!(e.to_string().contains("permission denied")),
            other => panic!("expected Io, got {other:?}"),
        }
    }

    #[test]
    fn io_error() {
        let err = toride_runner::Error::Io("broken pipe".into());
        let mapped = map_runner_error(err, "mise where node");
        match mapped {
            MiseError::Io(e) => assert!(e.to_string().contains("broken pipe")),
            other => panic!("expected Io, got {other:?}"),
        }
    }

    #[test]
    fn other_variants_fall_through() {
        let err = toride_runner::Error::OutputParse("bad output".into());
        let mapped = map_runner_error(err, "mise ls");
        match mapped {
            MiseError::Io(e) => assert!(e.to_string().contains("bad output")),
            other => panic!("expected Io fallback, got {other:?}"),
        }
    }
}
