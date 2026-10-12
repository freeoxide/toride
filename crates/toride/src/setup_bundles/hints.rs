//! Config-hint application: the only setup-bundles code that touches the
//! filesystem; the write-path tripwires scope their bans to this file.

use std::path::PathBuf;

use super::ConfigHint;

/// The outcome of [`apply_hint`]: the expanded destination and whether bytes
/// were written or an existing file was left untouched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HintResult {
    /// The hint's exact bytes were written atomically to `path`.
    Written {
        /// The expanded destination the bytes landed on.
        path: PathBuf,
    },
    /// `path` already existed; nothing was written.
    SkippedExisting {
        /// The expanded destination that was left untouched.
        path: PathBuf,
    },
}

/// Apply a config hint: expand `~` via toride-fs, report
/// [`HintResult::SkippedExisting`] when the destination already exists —
/// existence is probed from metadata, so any pre-existing bytes (invalid
/// UTF-8 included) are left untouched — and otherwise write the exact bytes
/// through [`toride_fs::atomic_write`]. Never modifies an existing file,
/// merges into one, or creates directories.
///
/// # Errors
///
/// [`toride_fs::Error`] when existence cannot be probed or the atomic write
/// fails — including a missing parent directory.
pub fn apply_hint(hint: &ConfigHint) -> Result<HintResult, toride_fs::Error> {
    apply_hint_with(hint, toride_fs::expand_tilde)
}

pub(super) fn apply_hint_with(
    hint: &ConfigHint,
    expand: impl Fn(&str) -> PathBuf,
) -> Result<HintResult, toride_fs::Error> {
    let path = expand(hint.path);
    if path.try_exists().map_err(toride_fs::Error::Io)? {
        return Ok(HintResult::SkippedExisting { path });
    }
    toride_fs::atomic_write(&path, hint.content)?;
    Ok(HintResult::Written { path })
}
