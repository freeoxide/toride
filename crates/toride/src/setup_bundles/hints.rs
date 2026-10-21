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
/// [`HintResult::SkippedExisting`] when the destination already exists, and
/// otherwise create the destination with `O_EXCL` and write the exact bytes
/// through that handle. Never modifies an existing file, merges into one, or
/// creates directories. A file that appears between the existence check and
/// the create is refused by `O_EXCL`, not clobbered.
///
/// # Errors
///
/// [`toride_fs::Error`] when the destination cannot be created or written:
/// including a missing parent directory.
pub fn apply_hint(hint: &ConfigHint) -> Result<HintResult, toride_fs::Error> {
    apply_hint_with(hint, toride_fs::expand_tilde)
}

pub(super) fn apply_hint_with(
    hint: &ConfigHint,
    expand: impl Fn(&str) -> PathBuf,
) -> Result<HintResult, toride_fs::Error> {
    use std::io::ErrorKind;

    let path = expand(hint.path);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = match options.open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            return Ok(HintResult::SkippedExisting { path });
        }
        Err(e) => return Err(toride_fs::Error::Io(e)),
    };
    std::io::Write::write_all(&mut file, hint.content.as_bytes()).map_err(toride_fs::Error::Io)?;
    file.sync_all().map_err(toride_fs::Error::Io)?;
    Ok(HintResult::Written { path })
}
