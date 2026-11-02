//! Shared execution helper for the shadow-utils wrappers.
//!
//! Every wrapper needs the same behavior that `duct::Expression::read`
//! cannot provide: on a non-zero exit the merged stdout/stderr and the exit
//! code must still be captured, so callers can map documented exit codes
//! (useradd 9, shadow's 6, visudo 4) to typed error variants.

use std::path::Path;

use crate::Error;

/// Run `bin` with `args`, capturing merged stdout+stderr and the exit code
/// even when the command exits non-zero.
///
/// # Errors
///
/// Returns [`Error::CommandFailed`] with `code: None` when the process cannot
/// be started at all.
pub(crate) fn run_captured(
    program: &str,
    bin: &Path,
    args: &[String],
) -> Result<std::process::Output, Error> {
    duct::cmd(bin, args)
        .stderr_to_stdout()
        .unchecked()
        .run()
        .map_err(|e| Error::CommandFailed {
            program: program.to_owned(),
            code: None,
            stderr: e.to_string(),
        })
}

/// Decode a captured command's merged output as trimmed text.
pub(crate) fn merged_output_text(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}
