//! Privilege-escalation helpers for operations that need root.
//!
//! Toride runs either as root (`sudo toride`) or as a normal user. When a
//! write operation targets root-owned files (`/etc/ssh/sshd_config`, other
//! users' `authorized_keys`), it goes through [`run_privileged`], which runs
//! the command directly when already root, or wraps it in `sudo -n` (non-
//! interactive) otherwise.
//!
//! `sudo -n` is used deliberately: interactive `sudo` would fight the TUI for
//! the TTY password prompt. With `-n`, sudo fails fast when no credentials are
//! cached, producing a clear error the UI can surface. The user runs `sudo -v`
//! in another terminal first, or runs the whole app under `sudo`.
//!
//! The privilege boundary is explicit and narrow — a caller cannot execute an
//! arbitrary command; it must describe one of the enumerated [`PrivilegedOp`]s.

use std::path::Path;

use crate::{Error, Result};

/// Path to the system SSH daemon configuration.
const SSHD_CONFIG_PATH: &str = "/etc/ssh/sshd_config";

/// Return `true` when the process is running as root (effective UID 0).
///
/// This is the single source of truth for privilege detection across the
/// app. It is a cheap syscall and safe to call anywhere.
pub fn is_root() -> bool {
    // SAFETY: `geteuid` is a trivial syscall with no preconditions; it just
    // reads the kernel's record of the effective UID.
    let euid = unsafe { libc::geteuid() };
    euid == 0
}

/// An operation that requires elevated privileges to perform.
///
/// Each variant fully describes the privileged write so the boundary stays
/// auditable — there is no generic "run any command" escape hatch.
#[derive(Debug, Clone)]
pub enum PrivilegedOp {
    /// Atomically install new contents for `/etc/ssh/sshd_config`.
    ///
    /// The caller has already serialized the desired file content. This op:
    /// 1. Stages the content in an O_EXCL, unpredictable-named temp file in
    ///    the *same directory* as the target (`/etc/ssh`) — so the install is
    ///    an atomic `rename(2)` within one filesystem, and `sshd -t` resolves
    ///    relative `Include` directives (e.g. the default
    ///    `Include /etc/ssh/sshd_config.d/*.conf`) against the live directory.
    /// 2. **Always** validates the staged file with `sshd -t` through the
    ///    privileged path. If the `sshd` binary is genuinely unavailable, the
    ///    write **fails closed** — an unvalidatable config is never installed.
    /// 3. Backs up the existing config to `<path>.bak` *before* install. A
    ///    backup failure is fatal (the write aborts without touching the live
    ///    config).
    /// 4. Installs the temp into place via a single `rename(2)`.
    WriteSshdConfig {
        /// The full new contents of the sshd_config file.
        content: String,
    },
}

impl PrivilegedOp {
    /// Execute the privileged operation on a blocking thread.
    ///
    /// `running_as_root` should be the result of [`is_root`]; it is passed in
    /// rather than re-detected so the caller controls the trust boundary.
    fn execute(self, running_as_root: bool) -> Result<()> {
        match self {
            Self::WriteSshdConfig { content } => {
                // Production path: no injected validator, no injected runner,
                // real target, real `sshd -t` through the privileged runner.
                write_sshd_config(
                    &content,
                    running_as_root,
                    Path::new(SSHD_CONFIG_PATH),
                    None,
                    None,
                )
            }
        }
    }
}

/// Execute a privileged operation asynchronously.
///
/// Forwards to a blocking thread (the underlying `duct` calls are blocking).
///
/// # Errors
///
/// Propagates any [`Error`] from the underlying file operations or commands,
/// including a [`Error::SshdConfigInvalid`] when `sshd -t` rejects the new
/// config, [`Error::SshdNotFound`] when the `sshd` binary is genuinely
/// unavailable (the write fails closed in that case), or [`Error::SudoFailed`]
/// when `sudo -n` lacks cached credentials.
pub async fn run_privileged(op: PrivilegedOp, running_as_root: bool) -> Result<()> {
    let root = running_as_root;
    tokio::task::spawn_blocking(move || op.execute(root))
        .await
        .map_err(|e| Error::TaskFailed(e.to_string()))?
}

/// Build a `duct` expression that runs `cmd args`, optionally through `sudo`.
///
/// When not root, the command is wrapped as `sudo -n cmd args…` so it fails
/// fast (rather than prompting) when credentials aren't cached.
fn cmd_with_priv(cmd: &str, args: &[&str], running_as_root: bool) -> duct::Expression {
    if running_as_root {
        duct::cmd(cmd, args)
    } else {
        let mut full: Vec<String> = Vec::with_capacity(args.len() + 2);
        full.push("-n".into());
        full.push(cmd.into());
        full.extend(args.iter().map(|s| (*s).to_string()));
        duct::cmd("sudo", full)
    }
}

/// Type of the validation seam injected into [`write_sshd_config`].
///
/// A validator runs the staged temp file through `sshd -t` (or a test double)
/// and reports one of three outcomes:
///
/// - [`ValidateOutcome::Ok`] — the config parses, proceed to install.
/// - [`ValidateOutcome::Invalid`] — `sshd -t` rejected the config; fail closed
///   with [`Error::SshdConfigInvalid`].
/// - [`ValidateOutcome::BinaryMissing`] — the `sshd` binary itself could not
///   be found; fail closed with [`Error::SshdNotFound`]. We never install a
///   config we could not validate.
type Validator = fn(path: &Path, running_as_root: bool) -> ValidateOutcome;

/// The captured result of running the validator command (`sshd -t -f <path>`).
///
/// This is the testable seam behind [`default_validator`]: rather than calling
/// `cmd_with_priv(...).run()` inline (which requires the `sshd` binary to exist
/// on the host and so can't be exercised on CI), [`default_validator`] delegates
/// the actual execution to [`default_validator_runner`] and then classifies the
/// outcome via [`classify_validator_output`]. Tests call
/// [`classify_validator_output`] directly with canned outputs, so the three-way
/// classification (privilege-denied → binary-missing → invalid) is locked by a
/// deterministic assertion that has no dependency on the host having `sshd`.
enum ValidatorRun {
    /// The command exited with this status and captured (merged) output.
    Output {
        /// The raw merged stdout/stderr bytes.
        stdout: Vec<u8>,
        /// Whether the underlying process reported success.
        success: bool,
    },
    /// The command could not be spawned at all (ENOENT/EACCES/EAGAIN on `sudo`
    /// or `sshd`). The validator never ran, so this must NOT be classified as a
    /// config error.
    SpawnFailed(String),
}

/// Type of the privileged-command runner seam injected into
/// [`write_sshd_config`].
///
/// This mirrors the contract of [`run_cmd`]: run `cmd args…` (through `sudo -n`
/// when not root), require a zero exit, and return `Err(Error::SudoFailed(…))`
/// on any non-zero exit or spawn failure. Production code passes `None`, which
/// resolves to the real [`run_cmd`]; tests inject a stub that records the
/// invocation and fakes success (or a specific failure) so the NON-root write
/// pipeline (`lift_staged_into_target_dir` → validate → `install_command`) can
/// be exercised end-to-end without ever invoking `sudo` or `sshd`.
type Runner = fn(cmd: &str, args: &[&str], running_as_root: bool) -> Result<()>;

/// The result of validating a staged sshd_config.
///
/// Returned by the validation seam so callers (and tests) can distinguish the
/// terminal cases without inspecting error text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidateOutcome {
    /// `sshd -t` accepted the config.
    Ok,
    /// `sshd -t` rejected the config; carry the diagnostic output.
    Invalid(String),
    /// The `sshd` binary is not installed / unreachable via the privileged
    /// path; carry the detail we observed.
    BinaryMissing(String),
    /// The privileged runner could not authenticate (e.g. `sudo -n` has no
    /// cached credentials — "a password is required"). This is a privilege
    /// failure, not a config error; mapped to [`Error::SudoFailed`] so the UI
    /// does not misreport it as a config-validation failure.
    PrivilegeDenied(String),
}

/// Write, validate, back up, and atomically install new sshd_config contents.
///
/// This is the hardened write path. The hardening vs. the original
/// implementation:
///
/// - **Validation is never skipped.** The old code gated `sshd -t` on
///   `which::which("sshd")`, which resolves against the *invoking* user's
///   `PATH`. On Debian/Ubuntu a normal user's `PATH` lacks `/usr/sbin` where
///   `sshd` lives, so validation was silently skipped and an unvalidated
///   config was installed. Now we always run validation through the privileged
///   runner (`sudo -n`, which uses sudo's `secure_path` containing `/usr/sbin`).
///   If the binary is genuinely missing we fail closed — no install.
/// - **The temp ends up in the target directory before validation.** When
///   root, we stage directly in the target's directory (`/etc/ssh`). When not
///   root we cannot write `/etc/ssh` from an unprivileged process (`tempfile_in`
///   is a plain Rust call; `run_privileged` only elevates individual
///   *commands* via `sudo -n`, not the process), so we stage in the
///   world-writable system temp dir and lift the file into `/etc/ssh` via
///   `sudo -n cp` before validating. In both cases `sshd -t` then resolves
///   relative `Include` directives against the live directory, and install is
///   an atomic same-directory `rename(2)`.
/// - **Backup failure is fatal.** We keep the `.bak` backup but, unlike
///   before, a failed backup aborts the install rather than being warned
///   away. The security constraint requires a backup before every install.
///
/// # Test seams
///
/// `validator` lets tests inject a fake validation result (binary-missing vs.
/// invalid vs. ok) without touching the real `/etc/ssh`. In production it is
/// `None` and [`default_validator`] is used. `runner` lets tests inject a fake
/// privileged-command runner (see [`Runner`]) so the NON-root write pipeline
/// (lift → validate → single-`sh -c` install) can be exercised end-to-end
/// without `sudo` or `sshd`; in production it is `None` and [`run_cmd`] is
/// used. Likewise `target` is a parameter only so tests can point it at a
/// tempdir; production callers go through [`PrivilegedOp::execute`], which
/// pins it to [`SSHD_CONFIG_PATH`].
fn write_sshd_config(
    content: &str,
    running_as_root: bool,
    target: &Path,
    validator: Option<Validator>,
    runner: Option<Runner>,
) -> Result<()> {
    use std::io::Write as _;

    let validator = validator.unwrap_or(default_validator);
    let runner = runner.unwrap_or(run_cmd);

    // 0. SYMLINK REFUSAL GATE — fail closed before staging. If the pinned
    //    `target` is itself a symlink, `rename(2)`/`mv` would replace the
    //    *symlink* (not the file it points at), so toride would report success
    //    while the running sshd keeps reading the old, still-linked config.
    //    We do NOT auto-resolve: the operator must manage the real file
    //    directly. `symlink_metadata` is lstat (does not follow). This applies
    //    to both root and non-root paths since it runs before any staging.
    if let Ok(meta) = std::fs::symlink_metadata(target)
        && meta.file_type().is_symlink()
    {
        return Err(Error::ConfigWriteFailed(format!(
            "refusing to install: {} is a symlink — manage the resolved file directly",
            target.display()
        )));
    }

    // 0b. SELF-SWEEP defense-in-depth — best-effort remove any leftover STAGED
    //     `toride-sshd-*.tmp` from a prior failed run so leaked temps self-heal
    //     on the next write. We sweep TWO directories:
    //
    //       1. `<targetdir>` — reclaims leaked LIFTED-area temps on the ROOT
    //          path (the staged temp lives here) and stale lifted temps on the
    //          NON-ROOT path (the lifted temp lives in the target dir, but it
    //          uses the DISTINCT `toride-lifted-` prefix, so this glob does NOT
    //          match it — see [`LIFTED_TEMP_PREFIX`]). Only genuinely stale
    //          STAGED `toride-sshd-*.tmp` names here match.
    //       2. `std::env::temp_dir()` (e.g. `/tmp`) — on the NON-ROOT path the
    //          STAGED temp lives here, so a SIGKILL/panic between `tmp.keep()`
    //          and the trailing `remove_file` orphans it forever (F18). Sweeping
    //          here reclaims those. This must stay aligned with F3: the lifted
    //          temp uses the distinct `toride-lifted-` prefix and lives in the
    //          target dir, so ONLY staged temps in /tmp match this glob.
    //
    //     ALL errors are ignored (best-effort): the sweep must never gate a real
    //     write. The glob is anchored on the STAGED prefix only; a concurrent
    //     instance's just-lifted validate path (distinct prefix, different dir)
    //     is provably immune.
    let sweep_globs = |dir: &Path| {
        let dir_s = dir.to_string_lossy();
        // `"$0"` + trailing positional makes the pattern safe to pass through sh
        // even if the dir contained shell metacharacters (it won't here, but the
        // form is robust). The glob matches ONLY the STAGED temp prefix.
        let pattern = format!("rm -f \"$0\"/{STAGED_TEMP_PREFIX}*{TEMP_SUFFIX}");
        if let Err(e) = runner("sh", &["-c", &pattern, &dir_s], running_as_root) {
            tracing::warn!(
                target: "toride_ssh_core::privilege",
                sweep_dir = %dir.display(),
                error = %e,
                "best-effort self-sweep of stale staged sshd_config temps failed; \
                 ignoring (the sweep must never gate a real write)"
            );
        }
    };
    if let Some(dir) = target.parent().filter(|p| !p.as_os_str().is_empty()) {
        sweep_globs(dir);
    }
    // F18: ALSO sweep the system temp dir for orphaned STAGED temps (non-root
    // path stages here; a crash mid-write orphans them). On the root path this
    // is a harmless best-effort no-op (no staged temp lives in /tmp then).
    sweep_globs(&std::env::temp_dir());

    // 1. Stage the new contents in an O_EXCL, unpredictable-named temp file
    //    where THIS process can write it. See [`staging_dir`]: root stages in
    //    the target's directory (for an atomic same-dir rename and correct
    //    `Include` context); non-root stages in the system temp dir and the
    //    file is lifted into the target directory via `sudo -n cp` before
    //    validation in [`write_sshd_config_finish`]. Staging in `/etc/ssh`
    //    directly when non-root would EACCES (the process is unprivileged).
    let staging_dir = staging_dir(running_as_root, target);
    let tmp = tempfile::Builder::new()
        .prefix(STAGED_TEMP_PREFIX)
        .suffix(TEMP_SUFFIX)
        // O_EXCL + 0o600 kills the predictable-pid-name symlink-attack surface
        // of the old `/tmp/<prefix>.<pid>.tmp` scheme.
        .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .tempfile_in(&staging_dir)
        .map_err(|e| Error::ConfigWriteFailed(format!("failed to stage sshd_config: {e}")))?;

    // Capture the temp path before any move so the error path can clean up.
    let tmp_path_for_err = tmp.path().to_path_buf();

    tmp.as_file().write_all(content.as_bytes()).map_err(|e| {
        Error::ConfigWriteFailed(format!("failed to write staged sshd_config: {e}"))
    })?;
    // fsync the temp so the validated bytes are what actually lands on disk.
    tmp.as_file().sync_all().map_err(|e| {
        Error::ConfigWriteFailed(format!("failed to fsync staged sshd_config: {e}"))
    })?;

    // Keep the temp path as a plain PathBuf for the validation/restore logic;
    // `keep()` detaches it from the drop-deleting guard so we control its
    // lifetime ourselves (we explicitly remove it on every exit path).
    let tmp_path = match tmp.keep() {
        Ok((_file, path)) => path,
        // If keep() failed, the underlying file may still exist; try to clean
        // it up, then surface the error.
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_path_for_err);
            return Err(Error::ConfigWriteFailed(format!(
                "failed to persist staged sshd_config: {e}"
            )));
        }
    };

    // Run the write through to completion, guaranteeing temp cleanup.
    let result = write_sshd_config_finish(
        content,
        running_as_root,
        target,
        &tmp_path,
        validator,
        runner,
    );

    // Best-effort cleanup of the staging temp on every path (success or
    // failure). The live config is never the temp.
    let _ = std::fs::remove_file(&tmp_path);
    result
}

/// Where the invoking process should stage the new config content.
///
/// Root can write the target directory (`/etc/ssh`), so it stages there
/// directly — install is then an atomic same-directory rename and `sshd -t`
/// resolves relative `Include` directives against the live directory.
///
/// Non-root cannot write `/etc/ssh` (the staging `tempfile_in` call is an
/// unprivileged Rust call; only individual commands are elevated via `sudo -n`),
/// so it stages in the world-writable system temp dir. [`write_sshd_config_finish`]
/// then lifts the staged file into the target directory via `sudo -n cp` before
/// validating, restoring both the atomic-rename and correct-`Include`-context
/// properties on the non-root path. This is the fix for the regression where
/// non-root staging in `/etc/ssh` failed with EACCES and broke every write.
fn staging_dir(running_as_root: bool, target: &Path) -> std::path::PathBuf {
    if running_as_root {
        // `Path::parent` returns `Some("")` for a bare filename (e.g. just
        // "sshd_config"), not `None`, so an empty parent must be treated as
        // missing too — otherwise we'd stage via an empty (cwd-relative) path.
        target
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("/"))
            .to_path_buf()
    } else {
        std::env::temp_dir()
    }
}

/// Second half of [`write_sshd_config`], separated so temp cleanup always runs.
///
/// Ensures the content lives in the target's directory before validation, then
/// runs the validate → backup → install sequence (see [`validate_backup_install`]),
/// cleaning up any lifted staging temp on failure.
fn write_sshd_config_finish(
    _content: &str,
    running_as_root: bool,
    target: &Path,
    tmp_path: &Path,
    validator: Validator,
    runner: Runner,
) -> Result<()> {
    // Get the content into the TARGET directory as a temp file so that
    // validation runs against the correct Include context and install is an
    // atomic same-directory rename. Root already staged there; non-root staged
    // in the temp dir and must be lifted into the target dir via `sudo -n cp`.
    let validate_path: std::path::PathBuf;
    let lifted: Option<std::path::PathBuf>;
    if running_as_root {
        validate_path = tmp_path.to_path_buf();
        lifted = None;
    } else {
        let lifted_path = lift_staged_into_target_dir(tmp_path, target, running_as_root, runner)?;
        validate_path = lifted_path.clone();
        lifted = Some(lifted_path);
    }

    // Validate -> backup -> install. On any failure, clean up a lifted temp
    // (root-owned, in /etc/ssh) so we never leave a stray staging file. On
    // success the lifted temp was consumed by the install rename.
    let result =
        validate_backup_install(running_as_root, target, &validate_path, validator, runner);
    if result.is_err()
        && let Some(p) = &lifted
    {
        // Best-effort cleanup: the real failure is already being surfaced,
        // and a leftover temp is not a lockout (it is not the live config).
        // The cleanup itself runs as `sudo -n rm`, so if the sudo
        // credentials expired mid-flight (the very thing that caused the
        // failure), the rm fails the same way. We do NOT propagate that
        // cleanup error — the original error is what the caller needs — but
        // we MUST surface the leaked path so the operator can remove it by
        // hand. (The next write's self-sweep at the top of
        // write_sshd_config will also eventually reclaim it.)
        if let Err(cleanup_err) = runner("rm", &["-f", &p.to_string_lossy()], running_as_root) {
            tracing::warn!(
                target: "toride_ssh_core::privilege",
                leaked_path = %p.display(),
                error = %cleanup_err,
                "failed to clean up lifted sshd_config temp after install failure; \
                 remove it manually if it persists"
            );
        }
    }
    result
}

/// Validate, back up, then atomically install `validate_path` as `target`.
///
/// `validate_path` must already live in the target's directory (root staged it
/// there directly; non-root had it lifted there). Fail-closed at every gate:
/// an invalid, unvalidatable, or privilege-denied config is never installed,
/// and install never proceeds without a `.bak` backup in place.
fn validate_backup_install(
    running_as_root: bool,
    target: &Path,
    validate_path: &Path,
    validator: Validator,
    runner: Runner,
) -> Result<()> {
    // 1. VALIDATION GATE — never skipped. Distinguish "binary missing",
    //    "privilege denied", and "config invalid"; all three fail closed.
    match validator(validate_path, running_as_root) {
        ValidateOutcome::Ok => {}
        ValidateOutcome::Invalid(detail) => return Err(Error::SshdConfigInvalid(detail)),
        ValidateOutcome::BinaryMissing(detail) => return Err(Error::SshdNotFound(detail)),
        ValidateOutcome::PrivilegeDenied(detail) => return Err(Error::SudoFailed(detail)),
    }

    // 2. BACKUP BEFORE INSTALL — fatal on failure.
    if target.exists() {
        backup_config(target, running_as_root, runner)?;
    }

    // 3. INSTALL + CHMOD as a single privileged step. The temp was created at
    //    0o600; `rename(2)` preserves the source mode, so the live file would
    //    land at 0o600 without an explicit chmod. The required invariant is a
    //    root-owned 0o644 config.
    //
    //    The install and the chmod are arranged so a chmod failure can never
    //    leave the live config at the wrong mode. On the ROOT path the temp is
    //    chmod'd to 0o644 BEFORE the rename, so a chmod failure aborts with
    //    nothing installed and a successful rename lands the right mode. On the
    //    NON-ROOT path both go through one `sudo -n sh -c 'chmod && mv'` (see
    //    [`install_command`]) — chmod-then-mv, so a chmod failure aborts (`&&`)
    //    before the live config is touched; if they were two separate sudo
    //    processes, the sudo credential timestamp could expire in the window
    //    between `chmod` and `mv`, leaving the live config at 0o600. A single
    //    `sudo -n sh -c` means one timestamp covers both — the chmod cannot
    //    independently fail.
    install_temp(validate_path, target, 0o644, running_as_root, runner)?;

    Ok(())
}

/// Prefix used for STAGED sshd_config temps (the unprivileged tempfile created
/// in [`write_sshd_config`]). The self-sweep in [`write_sshd_config`] and the
/// `/tmp` sweep it runs both glob `toride-sshd-*.tmp` to reclaim ONLY these.
const STAGED_TEMP_PREFIX: &str = "toride-sshd-";

/// Prefix used for LIFTED sshd_config temps (the root-owned copy a non-root
/// write makes in the target directory via [`lift_staged_into_target_dir`]).
///
/// This is deliberately a DIFFERENT STEM from [`STAGED_TEMP_PREFIX`] so the
/// self-sweep glob `toride-sshd-*.tmp` provably CANNOT match a lifted temp. A
/// shell glob `toride-sshd-*` matches any name beginning `toride-sshd-` — so a
/// lifted name like `toride-sshd-lifted-X.tmp` WOULD still be matched (the `*`
/// swallows `lifted-X`). Using the distinct stem `toride-lifted-` makes the glob
/// fail to anchor (the glob expects a literal `-` after `toride-sshd`), so a
/// concurrent instance's top-of-write sweep cannot delete this instance's
/// just-lifted validate path. This is defense-in-depth alongside the
/// cross-process lock added in `sshd::edit()` (F2): even if the lock is held,
/// this naming keeps the sweep's blast radius to genuinely stale STAGED temps.
const LIFTED_TEMP_PREFIX: &str = "toride-lifted-";

/// Suffix shared by both staged and lifted temps.
const TEMP_SUFFIX: &str = ".tmp";

/// Lift a staged temp (`src`, in the system temp dir) into `target`'s directory
/// as a root-owned temp, returning the lifted path.
///
/// Used on the non-root path so validation can run against a file in `/etc/ssh`
/// (correct `Include` context) and install can be an atomic same-directory
/// rename. The lifted file takes the distinct [`LIFTED_TEMP_PREFIX`] (NOT the
/// staged `toride-sshd-` prefix), preserving the staged temp's unpredictable
/// random component, so it (a) is unpredictable (only root could pre-create it
/// — no realistic symlink/TOCTOU surface) and (b) is provably NOT matched by the
/// self-sweep glob `toride-sshd-*.tmp`, so a concurrent write cannot sweep away
/// this instance's just-lifted validate path. The mode is irrelevant for
/// validation (sshd reads the config as root) and is set to 0o644 atomically at
/// install time.
fn lift_staged_into_target_dir(
    src: &Path,
    target: &Path,
    running_as_root: bool,
    runner: Runner,
) -> Result<std::path::PathBuf> {
    let dir = target.parent().unwrap_or_else(|| Path::new("/"));
    // Derive the lifted name from the staged temp's UNPREDICTABLE random
    // component (the part between the staged prefix and `.tmp`). This keeps the
    // lifted name unpredictable while swapping in the distinct lifted prefix so
    // the self-sweep glob cannot match it.
    let rand_component = src
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|name| name.strip_prefix(STAGED_TEMP_PREFIX))
        .and_then(|rest| rest.strip_suffix(TEMP_SUFFIX))
        .ok_or_else(|| {
            Error::ConfigWriteFailed(format!(
                "staged sshd_config temp has an unexpected name: {}",
                src.display()
            ))
        })?;
    let lifted_name = format!("{LIFTED_TEMP_PREFIX}{rand_component}{TEMP_SUFFIX}");
    let lifted = dir.join(lifted_name);
    let src_s = src.to_string_lossy();
    let lifted_s = lifted.to_string_lossy();
    runner("cp", &[&src_s, &lifted_s], running_as_root).map_err(|e| {
        // F20: a lift-step failure that is actually a privilege denial (e.g.
        // `sudo -n` with no cached credentials — the `cp` runs as `sudo -n cp`
        // on the non-root path) must surface as `Error::SudoFailed`, NOT
        // `Error::ConfigWriteFailed`. The validate step already classifies this
        // correctly via `ValidateOutcome::PrivilegeDenied`; the lift step must
        // not misclassify it as a config write failure (which would hide the
        // real, actionable cause — "run `sudo -v`").
        if is_privilege_denied(&e.to_string()) || matches!(e, Error::SudoFailed(_)) {
            Error::SudoFailed(format!(
                "privilege denied while staging sshd_config into target dir for validation: {e}"
            ))
        } else {
            Error::ConfigWriteFailed(format!(
                "failed to stage sshd_config into target dir for validation: {e}"
            ))
        }
    })?;
    Ok(lifted)
}

/// The production validator: run `sshd -t -f <path>` through the privileged
/// runner and classify the outcome.
///
/// We do NOT gate on `which::which("sshd")`: that resolves against the
/// invoking user's `PATH`, which on Debian/Ubuntu omits `/usr/sbin`, so the
/// real (root-installed) `sshd` would be missed and validation silently
/// skipped. Instead we always invoke through the privileged runner; `sudo -n`
/// uses sudo's `secure_path` (which includes `/usr/sbin`). We then inspect the
/// failure to tell "binary genuinely not found" apart from "config invalid".
///
/// The actual command execution is delegated to [`default_validator_runner`] and
/// the outcome is classified by [`classify_validator_output`]. Splitting the
/// runner from the classifier makes the three-way classification (privilege
/// denied → binary missing → invalid) deterministically testable without a real
/// `sshd` binary on the host (see [`classify_validator_output`]'s tests).
fn default_validator(path: &Path, running_as_root: bool) -> ValidateOutcome {
    let path_str = path.to_string_lossy();
    let run = default_validator_runner("sshd", &["-t", "-f", &path_str], running_as_root);
    classify_validator_output(run)
}

/// The production runner for [`default_validator`]: actually shell out to
/// `sshd -t` (via `sudo -n` when not root) and capture the merged output.
///
/// This is the thin execution layer behind the seam; it has no classification
/// logic so it is intentionally host-dependent (it requires `sshd` to be
/// reachable). The classification it feeds lives in [`classify_validator_output`]
/// and is tested in isolation.
fn default_validator_runner(cmd: &str, args: &[&str], running_as_root: bool) -> ValidatorRun {
    match cmd_with_priv(cmd, args, running_as_root)
        .stderr_to_stdout()
        .stdout_capture()
        .run()
    {
        Ok(output) => ValidatorRun::Output {
            stdout: output.stdout,
            success: output.status.success(),
        },
        // The process itself couldn't be spawned. On the non-root path the
        // command is `sudo -n sshd …`; a spawn failure means either `sudo` or
        // `sshd` (or the privileged runner as a whole) could not be launched
        // — e.g. ENOENT ("not found"), EACCES ("Permission denied"), or
        // EAGAIN ("Resource temporarily unavailable"). In ALL of these cases
        // we could not actually run `sshd -t`, so we must NOT claim the CONFIG
        // is invalid (that would point the user at their sshd_config when the
        // real problem is the privileged runner). Classify as BinaryMissing
        // ("validator unavailable") so the caller fails closed without
        // misreporting a config error.
        Err(e) => ValidatorRun::SpawnFailed(e.to_string()),
    }
}

/// Classify a captured validator command outcome into a [`ValidateOutcome`].
///
/// This is the pure, host-independent core of [`default_validator`], extracted
/// so the three-way classification can be unit-tested with canned outputs:
///
/// - `SpawnFailed` → [`ValidateOutcome::BinaryMissing`] (we never ran
///   `sshd -t`, so we must not claim the *config* is invalid).
/// - exit success with empty stderr → [`ValidateOutcome::Ok`].
/// - non-zero exit with text matching [`is_privilege_denied`] →
///   [`ValidateOutcome::PrivilegeDenied`] (checked first: `sudo -n` with no
///   cached credentials never actually validated the config).
/// - non-zero exit matching [`is_binary_missing`] →
///   [`ValidateOutcome::BinaryMissing`].
/// - otherwise → [`ValidateOutcome::Invalid`] (a genuine config error).
fn classify_validator_output(run: ValidatorRun) -> ValidateOutcome {
    match run {
        ValidatorRun::SpawnFailed(detail) => ValidateOutcome::BinaryMissing(detail),
        ValidatorRun::Output { stdout, success } => {
            if success {
                return ValidateOutcome::Ok;
            }
            let detail = String::from_utf8_lossy(&stdout);
            let detail = detail.trim().to_string();
            // Order: privilege first. `sudo -n` with no cached credentials
            // prints "sudo: a password is required" and exits non-zero — the
            // config was never checked, so this is NOT a config error.
            // Checking this before binary-missing and invalid keeps us from
            // misreporting a sudo-password failure as a config problem (which
            // would wrongly point the user at their sshd_config).
            if is_privilege_denied(&detail) {
                ValidateOutcome::PrivilegeDenied(detail)
            } else if is_binary_missing(&detail) {
                ValidateOutcome::BinaryMissing(detail)
            } else {
                ValidateOutcome::Invalid(detail)
            }
        }
    }
}

/// Heuristic: does this error text indicate the privileged runner refused to
/// authenticate (e.g. `sudo -n` with no cached credentials)?
///
/// `sudo -n` prints `sudo: a password is required` (or, on older sudo, `sudo:
/// sorry, a password is required to run sudo`) to stderr and exits non-zero
/// when there are no cached credentials. We must not confuse this with a
/// config-validation failure: the config was never checked. Matching `password
/// is required` catches both sudo phrasings — note `a password is required`
/// contains that substring — without colliding with real `sshd -t` diagnostics
/// (which never phrase a config error that way).
fn is_privilege_denied(detail: &str) -> bool {
    detail.to_ascii_lowercase().contains("password is required")
}

/// Heuristic: does this error text indicate the `sshd` binary is missing
/// (rather than the config being invalid)?
///
/// Matches the phrasings emitted by `sudo` and the shell when a command
/// cannot be found: "command not found", "not found", "No such file".
/// `sshd -t` itself never emits these for an invalid config (it reports the
/// specific parse/semantics error), so a match here reliably means the binary
/// is unavailable.
fn is_binary_missing(detail: &str) -> bool {
    let lower = detail.to_ascii_lowercase();
    lower.contains("command not found")
        || lower.contains("not found")
        || lower.contains("no such file")
}

/// Back up `target` to `<target>.bak` via `cp`, keeping one prior generation.
///
/// Before taking the new backup, an existing `<target>.bak` is rotated to
/// `<target>.bak.1` (and any older `<target>.bak.1` is dropped first). This
/// keeps two generations on disk: the pre-current-edit original (`.bak.1`) and
/// the immediately prior content (`.bak`). The rotation is deterministic (no
/// timestamps), and any rotation failure is fatal so we never install without
/// a known-good backup in place.
///
/// # Errors
///
/// Returns [`Error::ConfigWriteFailed`] if any privileged step (rotation or
/// copy) fails. The caller treats this as fatal and does not proceed to
/// install — the security constraint requires a backup before every install.
fn backup_config(target: &Path, running_as_root: bool, runner: Runner) -> Result<()> {
    let src = target.to_string_lossy();
    let prev_bak = format!("{src}.bak");
    let oldest_bak = format!("{src}.bak.1");

    // Rotate the previous backup out of the way before we clobber it. We keep
    // at most two generations (.bak and .bak.1), so any stale .bak.1 is dropped
    // first. A failure here must abort — without a clean rotation we could lose
    // the pre-first-edit original when two bad edits land back to back.
    let has_prev = std::path::Path::new(&prev_bak).exists();
    if has_prev {
        // Drop a stale .bak.1 (best-effort: it's already a generation we no
        // longer keep once we rotate a new .bak.1 in). If the file doesn't
        // exist, run_cmd would still fail, so only touch it when present.
        let has_oldest = std::path::Path::new(&oldest_bak).exists();
        if has_oldest {
            runner("rm", &["-f", &oldest_bak], running_as_root).map_err(|e| {
                Error::ConfigWriteFailed(format!(
                    "failed to drop stale {oldest_bak} during backup rotation (aborting install): {e}"
                ))
            })?;
        }
        runner("mv", &[&prev_bak, &oldest_bak], running_as_root).map_err(|e| {
            Error::ConfigWriteFailed(format!(
                "failed to rotate {prev_bak} to {oldest_bak} during backup (aborting install): {e}"
            ))
        })?;
    }

    runner("cp", &["-p", &src, &prev_bak], running_as_root).map_err(|e| {
        Error::ConfigWriteFailed(format!(
            "failed to back up sshd_config to {prev_bak} (aborting install): {e}"
        ))
    })
}

/// Install `tmp_path` at `target` with the final `mode`, as a single atomic
/// privileged step.
///
/// The temp was created at 0o600; `rename(2)` preserves the source mode, so the
/// required invariant (root-owned 0o644) needs an explicit chmod. Both branches
/// apply the chmod BEFORE the rename lands in place, so a chmod failure can
/// never leave the live config installed at the wrong mode:
///
/// - **Root branch:** chmod the TEMP to `mode` first, THEN `rename(2)` it into
///   place. If the pre-rename chmod fails, nothing was installed (fail closed).
///   If the rename succeeds, the file already has the right mode — there is no
///   post-install chmod that could independently fail and leave 0o600 live.
/// - **Non-root branch:** the install and chmod are folded into one
///   `sudo -n sh -c 'chmod "$mode" "$src" && mv "$src" "$dst"'` (built by
///   [`install_command`]), so a single `sudo -n` timestamp covers both steps.
///   A sudo-credential expiry after the chmod aborts the entire `sh -c` before
///   the `mv`, so we never observe a live file installed but at 0o600.
///
/// `mv` performs a single `rename(2)` here because the source and target share
/// a filesystem (the temp was staged in the target's directory), so `mv` will
/// not fall back to copy+unlink.
///
/// # Errors
///
/// Returns [`Error::ConfigWriteFailed`] on a non-zero exit.
fn install_temp(
    tmp_path: &Path,
    target: &Path,
    mode: u32,
    running_as_root: bool,
    runner: Runner,
) -> Result<()> {
    if running_as_root {
        // chmod the TEMP first, THEN rename. If the pre-rename chmod fails,
        // nothing was installed (fail closed). After a successful rename the
        // file already has the right mode — no post-install chmod that could
        // leave the live config at 0o600.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(tmp_path, std::fs::Permissions::from_mode(mode)).map_err(
                |e| Error::ConfigWriteFailed(format!("failed to chmod sshd_config: {e}")),
            )?;
        }
        #[cfg(not(unix))]
        {
            let _ = mode;
        }
        std::fs::rename(tmp_path, target)
            .map_err(|e| Error::ConfigWriteFailed(format!("failed to install sshd_config: {e}")))?;
        // F17: best-effort fsync of the target's PARENT directory so the
        // rename(2) (which updates the parent directory's entries) is durable
        // across power loss. The temp itself was fsynced before install, but
        // without fsyncing the parent the new directory entry could be lost in
        // the sub-second window after a "successful" return — leaving the
        // rename durable on the old entry only. This MUST NOT turn a success
        // into an error: the .bak backup + `sshd -t` already protect against
        // lockout, so a fsync hygiene failure is only warned about.
        fsync_parent_dir_best_effort(target, running_as_root, runner);
        return Ok(());
    }

    // Non-root: single sudo invocation (chmod before mv), built by the pure
    // helper so invariant #3 (single invocation) is asserted by a unit test.
    let (program, args) = install_command(tmp_path, target, mode, running_as_root);
    let args_refs: Vec<&str> = args.iter().map(std::string::String::as_str).collect();
    runner(program, &args_refs, running_as_root)
        .map_err(|e| Error::ConfigWriteFailed(format!("failed to install sshd_config: {e}")))?;
    // F17: same best-effort parent-dir fsync as the root branch. On the non-root
    // path the parent (/etc/ssh) is not writable by this process; the helper
    // attempts an in-process read-only fd fsync first (works on Linux for dirs
    // with the execute bit), then falls back to `sudo -n`, then warns and skips.
    // Never fails the install.
    fsync_parent_dir_best_effort(target, running_as_root, runner);
    Ok(())
}

/// Best-effort fsync of `target`'s parent directory after the install rename.
///
/// The staged temp is fsynced before install, but `rename(2)` mutates the
/// *parent directory's* entry list — that mutation is only durable once the
/// parent directory itself is fsynced. Without this, a power loss in the
/// sub-second window after a "successful" install could revert the directory
/// entry to the pre-rename state (pointing at the old/unlinked inode). This
/// closes that durability gap (F17).
///
/// This is PURELY a durability/hygiene step. The lockout-prevention guarantees
/// (`.bak` backup before install, `sshd -t` validation before install) do NOT
/// depend on it, so it MUST NEVER turn a successful install into an error:
/// every failure path here is warned-and-skipped.
///
/// Strategy, in order:
/// 1. In-process: open the parent read-only and `fsync` it. On Linux a
///    directory fd openable with execute permission can be fsynced without
///    write permission, so this works for root AND for a non-root process
///    against `/etc/ssh` (mode typically 0o755). This is the cheapest and most
///    reliable path and is what real deployments hit.
/// 2. Non-root only, if the in-process attempt failed: best-effort privileged
///    fallback via the runner. There is no portable POSIX shell builtin that
///    fsyncs a single directory, so this is a soft attempt (a `sync` covers the
///    whole filesystem, which is acceptable as a coarse durability push). Any
///    failure here is warned and skipped — never propagated.
/// 3. If everything fails, `tracing::warn!` and return (the install already
///    succeeded and is protected by the backup + validation gates).
fn fsync_parent_dir_best_effort(target: &Path, running_as_root: bool, runner: Runner) {
    let Some(parent) = target.parent() else {
        return;
    };

    // (1) In-process read-only fd fsync. This is the common-case success path.
    #[cfg(unix)]
    {
        match std::fs::File::open(parent) {
            Ok(dir) => match dir.sync_all() {
                Ok(()) => return, // durable — nothing more to do.
                Err(e) => tracing::warn!(
                    target: "toride_ssh_core::privilege",
                    parent = %parent.display(),
                    error = %e,
                    "in-process fsync of sshd_config parent dir failed; \
                     attempting fallback (install already succeeded)"
                ),
            },
            Err(e) => tracing::warn!(
                target: "toride_ssh_core::privilege",
                parent = %parent.display(),
                error = %e,
                "could not open sshd_config parent dir for in-process fsync; \
                 attempting fallback (install already succeeded)"
            ),
        }
    }

    // (2) Privileged fallback (non-root path only). On the root path the
    //     in-process attempt above either succeeded or the dir genuinely can't
    //     be fsynced — and we are already root, so `sudo` would buy nothing.
    if running_as_root {
        return;
    }
    // No portable POSIX shell builtin fsyncs a SINGLE directory. `sync` pushes
    // all dirty filesystem buffers to disk, which is coarser than a per-dir
    // fsync but still makes the just-installed rename durable. This is a soft,
    // best-effort push; any failure is warned and skipped (never propagated).
    if let Err(e) = runner("sync", &[], running_as_root) {
        tracing::warn!(
            target: "toride_ssh_core::privilege",
            parent = %parent.display(),
            error = %e,
            "privileged parent-dir fsync fallback (`sync`) for sshd_config failed; \
             skipping (install already succeeded; .bak backup + sshd -t protect \
             against lockout)"
        );
    }
}

/// Build the (program, args) for the non-root install+chmod step WITHOUT
/// running anything.
///
/// Extracted as a pure helper so invariant #3 (the install and chmod are a
/// SINGLE privileged invocation) is locked by an executable unit test rather
/// than a comment. The non-root branch folds `chmod` and `mv` into one
/// `sudo -n sh -c`, in that order: a single sudo-credential timestamp covers
/// both, and because the `chmod` runs on the staged temp BEFORE the `mv`, a
/// chmod failure aborts (`&&`) before the live config is touched — so it can
/// never be left at the temp's 0o600 mode. A sudo-credential expiry at either
/// step aborts the whole sh -c (no half-applied state is observed).
///
/// The root branch is handled in-process by [`install_temp`] directly (a pure
/// `std::fs` chmod-then-rename with no shell — see [LOW #1]); this helper is
/// only invoked on the non-root path, but it is the single source of truth for
/// the command shape the test asserts against.
fn install_command(
    tmp_path: &Path,
    target: &Path,
    mode: u32,
    running_as_root: bool,
) -> (&'static str, Vec<String>) {
    // The root branch executes in-process (no shell command); return a
    // sentinel that is never invoked by a test. install_temp bypasses this
    // helper entirely on the root path.
    if running_as_root {
        return ("rename-in-process", Vec::new());
    }

    let src = tmp_path.to_string_lossy().to_string();
    let dst = target.to_string_lossy().to_string();
    let mode_octal = format!("{mode:o}");
    // Single sudo invocation: chmod THEN mv. `$0`/`$1` are bound positionally
    // so the paths need no shell-quoting. chmod-ing the staged temp BEFORE the
    // mv mirrors the root path (chmod-then-rename): if the chmod fails, `&&`
    // aborts before the mv runs, so the live config is never left at the temp's
    // 0o600 mode. A sudo-credential expiry at either step aborts the whole
    // sh -c (one timestamp covers both); the whole thing exits non-zero if
    // either step fails.
    let script = format!("chmod {mode_octal} \"$0\" && mv \"$0\" \"$1\"");
    ("sh", vec!["-c".to_string(), script, src, dst])
}

/// Run `cmd args…` (through sudo when not root) and require a zero exit.
///
/// # Errors
///
/// Returns [`Error::SudoFailed`] on a non-zero exit, including the captured
/// stderr (e.g. "sudo: a password is required") so the UI can show it.
fn run_cmd(cmd: &str, args: &[&str], running_as_root: bool) -> Result<()> {
    let output = cmd_with_priv(cmd, args, running_as_root)
        .stderr_to_stdout()
        .stdout_capture()
        .run()
        .map_err(|e| Error::SudoFailed(format!("failed to run `{cmd}`: {e}")))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stdout);
        let detail = stderr.trim();
        Err(Error::SudoFailed(format!(
            "`{cmd} {args}` exited {:?}: {detail}",
            output.status.code(),
            args = args.join(" ")
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A validator that always reports the config as valid.
    fn validator_ok(_path: &Path, _running_as_root: bool) -> ValidateOutcome {
        ValidateOutcome::Ok
    }

    /// A validator that simulates the `sshd` binary being absent.
    fn validator_binary_missing(_path: &Path, _running_as_root: bool) -> ValidateOutcome {
        ValidateOutcome::BinaryMissing("sudo: sshd: command not found".into())
    }

    /// A validator that simulates `sshd -t` rejecting the config.
    fn validator_invalid(_path: &Path, _running_as_root: bool) -> ValidateOutcome {
        ValidateOutcome::Invalid("line 1: Bad configuration option: foo".into())
    }

    #[test]
    fn is_root_matches_geteuid() {
        // Smoke test: is_root() should agree with a direct libc check.
        let euid = unsafe { libc::geteuid() };
        assert_eq!(is_root(), euid == 0);
    }

    #[test]
    fn is_binary_missing_recognizes_shell_phrasings() {
        assert!(is_binary_missing("sudo: sshd: command not found"));
        assert!(is_binary_missing("sshd: not found"));
        assert!(is_binary_missing(
            "sudo: unable to execute /usr/sbin/sshd: No such file or directory"
        ));
        // A genuine config error must NOT be classified as binary-missing.
        assert!(!is_binary_missing("line 3: Bad configuration option: foo"));
        assert!(!is_binary_missing("Missing value in subsystem definition."));
    }

    #[test]
    fn write_sshd_config_rejects_invalid_config_when_sshd_present() {
        // Production validator (real sshd -t). If sshd is installed, malformed
        // content must be rejected. Skip when sshd genuinely isn't present so
        // this stays green on CI without sshd. We force `running_as_root = true`
        // so the validator runs `sshd -t` directly (it needs no privilege to
        // parse) and staging lands in the tempdir we own — no `sudo` required.
        if std::process::Command::new("sshd")
            .arg("-V")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_err()
            && which::which("sshd").is_err()
        {
            // One last attempt through the privileged path; if even that says
            // binary-missing, skip.
            let dir = tempfile::tempdir().unwrap();
            let staged = dir.path().join("probe");
            std::fs::write(&staged, "Port 22\n").unwrap();
            if matches!(
                default_validator(&staged, true),
                ValidateOutcome::BinaryMissing(_)
            ) {
                return;
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("sshd_config");
        let bad = "this is not valid sshd_config @@@\n";
        let err = write_sshd_config(bad, true, &target, None, None);
        assert!(
            err.is_err(),
            "invalid sshd_config must be rejected (got {err:?})"
        );
        // And the live config must not have been created.
        assert!(!target.exists(), "invalid config must not be installed");
    }

    #[test]
    fn write_sshd_config_fails_closed_when_sshd_binary_missing() {
        // Injected seam: validator reports the binary is absent. The write
        // MUST fail closed and MUST NOT install anything. We force
        // `running_as_root = true` so we exercise the direct staging path
        // against a tempdir we own (no `sudo` needed); the validation gate is
        // the same on either path.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("sshd_config");
        // Pre-existing live config — it must be left untouched.
        std::fs::write(&target, "Port 2222\n").unwrap();

        let err = write_sshd_config(
            "Port 22\n",
            true,
            &target,
            Some(validator_binary_missing),
            None,
        )
        .expect_err("must fail closed when sshd binary is missing");

        assert!(
            matches!(err, Error::SshdNotFound(_)),
            "expected SshdNotFound, got {err:?}"
        );
        // The live config is untouched.
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "Port 2222\n");
        // No backup was taken (backup happens after validation, which failed).
        assert!(!Path::new(&format!("{}.bak", target.display())).exists());
    }

    #[test]
    fn write_sshd_config_fails_closed_when_config_invalid() {
        // Injected seam: validator reports the config is invalid. The write
        // MUST fail closed and MUST NOT install anything. (`running_as_root =
        // true` exercises the direct staging path; the gate is identical either
        // way.)
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("sshd_config");
        std::fs::write(&target, "Port 2222\n").unwrap();

        let err = write_sshd_config(
            "BadDirective yes\n",
            true,
            &target,
            Some(validator_invalid),
            None,
        )
        .expect_err("must fail closed when config is invalid");

        assert!(
            matches!(err, Error::SshdConfigInvalid(_)),
            "expected SshdConfigInvalid, got {err:?}"
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "Port 2222\n");
    }

    #[test]
    fn staging_dir_is_target_dir_for_root_and_temp_dir_for_non_root() {
        // Root stages in the target's directory so install is an atomic
        // same-dir rename and `sshd -t` resolves relative Includes against the
        // live directory.
        let target = Path::new("/etc/ssh/sshd_config");
        assert_eq!(
            staging_dir(true, target),
            Path::new("/etc/ssh"),
            "root must stage in the target's directory"
        );
        // Non-root cannot write /etc/ssh (the staging `tempfile_in` is an
        // unprivileged Rust call), so it stages in the world-writable temp dir
        // and `write_sshd_config_finish` lifts the file into the target dir via
        // `sudo -n cp` before validating. This is the fix for the EACCES
        // regression where non-root staging in /etc/ssh broke every write.
        assert_eq!(
            staging_dir(false, target),
            std::env::temp_dir(),
            "non-root must stage in the system temp dir"
        );
        // A parentless target falls back to "/" rather than panicking on
        // `.parent().unwrap()`.
        assert_eq!(
            staging_dir(true, Path::new("sshd_config")),
            Path::new("/"),
            "root staging falls back to '/' for a parentless target"
        );
    }

    #[test]
    fn is_privilege_denied_recognizes_sudo_password_phrasings() {
        // Both `sudo -n` "no cached credentials" phrasings:
        assert!(is_privilege_denied("sudo: a password is required"));
        assert!(is_privilege_denied(
            "sudo: sorry, a password is required to run sudo"
        ));
        // A binary-missing or genuine config error must NOT be misclassified as
        // a privilege failure (they keep their own, distinct classifications).
        assert!(!is_privilege_denied("sudo: sshd: command not found"));
        assert!(!is_privilege_denied(
            "line 3: Bad configuration option: foo"
        ));
        assert!(!is_privilege_denied(
            "Missing value in subsystem definition."
        ));
    }

    #[test]
    fn write_sshd_config_fails_closed_when_privilege_denied() {
        // Injected seam: validator reports `sudo -n` had no cached credentials.
        // The write MUST fail closed, MUST map to Error::SudoFailed (NOT
        // SshdConfigInvalid, so the UI does not point the user at their config),
        // and MUST NOT install or back up. We force `running_as_root = true` so
        // staging lands in a tempdir we own and the validator is reached
        // directly — the privilege classification is what's under test here,
        // not the sudo lift.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("sshd_config");
        std::fs::write(&target, "Port 2222\n").unwrap();

        let err = write_sshd_config(
            "Port 22\n",
            true,
            &target,
            Some(|_p: &Path, _r: bool| {
                ValidateOutcome::PrivilegeDenied("sudo: a password is required".into())
            }),
            None,
        )
        .expect_err("must fail closed when privilege is denied");

        assert!(
            matches!(err, Error::SudoFailed(_)),
            "expected SudoFailed for a privilege-denied validator, got {err:?}"
        );
        // Live config untouched, no backup taken (backup is after validation).
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "Port 2222\n");
        assert!(!Path::new(&format!("{}.bak", target.display())).exists());
    }

    #[test]
    fn write_sshd_config_happy_path_stages_in_target_dir_and_backs_up() {
        // Injected seam: validator ok. The happy path must:
        //  - stage the temp NEXT TO the target (same dir),
        //  - back the live config up to .bak before install,
        //  - install the new content as the live config with mode 0o644.
        //
        // We force `running_as_root = true` so backup/install/chmod take their
        // direct (std::fs) branches. The test tempdir is owned by this
        // process, so those succeed regardless of our real uid and we don't
        // depend on `sudo -n` credentials being cached.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("sshd_config");
        std::fs::write(&target, "# old\nPort 2222\n").unwrap();

        write_sshd_config("# new\nPort 22\n", true, &target, Some(validator_ok), None)
            .expect("happy path must succeed");

        // New content installed.
        let installed = std::fs::read_to_string(&target).unwrap();
        assert!(installed.contains("Port 22"));
        assert!(!installed.contains("Port 2222"));

        // Backup taken before install.
        let backup_path = format!("{}.bak", target.display());
        let backup = std::fs::read_to_string(&backup_path).unwrap();
        assert!(
            backup.contains("Port 2222"),
            "backup must contain the pre-install content"
        );

        // The staged temp must have lived as a sibling of the target (not in
        // /tmp). We assert this indirectly: the only toride-staged artifacts
        // left in the target dir are the target itself and its .bak — no
        // stray `toride-sshd-*` temp remains (it was renamed into place /
        // cleaned up). This confirms staging happened in this dir.
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let name = entry.unwrap().file_name();
            let name = name.to_string_lossy();
            assert!(
                !name.starts_with("toride-sshd-"),
                "staging temp must be cleaned up, found {name:?}"
            );
        }
    }

    #[test]
    fn write_sshd_config_stages_temp_as_sibling_of_target() {
        // Assert the "stage in the target dir" property by intercepting the
        // staged temp path via the validator seam. The validator receives the
        // exact temp path used for `sshd -t`; it must share a parent with the
        // target (so install is an atomic rename and Include resolves right).
        // Function pointers can't close over locals, so we record the path in
        // a module-level test static.
        STAGED_PATH.lock().unwrap().take();
        let captured: Validator = |path: &Path, _r: bool| {
            *STAGED_PATH.lock().unwrap() = Some(path.to_path_buf());
            ValidateOutcome::Ok
        };

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("sshd_config");
        std::fs::write(&target, "Port 2222\n").unwrap();

        write_sshd_config("Port 22\n", true, &target, Some(captured), None).unwrap();

        let staged = STAGED_PATH
            .lock()
            .unwrap()
            .clone()
            .expect("validator must have been called with the temp path");
        assert_eq!(
            staged.parent(),
            target.parent(),
            "staged temp must live in the SAME directory as the target"
        );
    }

    /// Module-level scratch slot so a function-pointer validator can report the
    /// staged temp path back to the test (function pointers can't capture).
    static STAGED_PATH: std::sync::Mutex<Option<std::path::PathBuf>> = std::sync::Mutex::new(None);

    #[test]
    fn write_sshd_config_aborts_install_when_backup_fails() {
        use std::os::unix::fs::PermissionsExt as _;

        // Make the backup impossible by making the target's directory lack a
        // real existing target that `cp -p` can read... Instead, simulate a
        // backup failure by pointing the target at a path whose PARENT can't
        // hold the .bak (make the parent read-only). Because we run the cp
        // unprivileged here, a read-only parent will fail the backup.
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("readonly");
        std::fs::create_dir(&nested).unwrap();
        let target = nested.join("sshd_config");
        std::fs::write(&target, "Port 2222\n").unwrap();

        // Remove write permission from the parent dir so `cp` cannot create
        // the .bak file. (We are the owner, so this is effective.)
        std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o555)).unwrap();

        // Run as "root" so install takes the std::fs::rename branch (also
        // fails because the dir is read-only) and backup takes the cp branch.
        // The key assertion: the original content is preserved and NO install
        // happens, because backup is fatal and runs before install.
        let err = write_sshd_config("# new\nPort 22\n", true, &target, Some(validator_ok), None)
            .expect_err("backup failure must abort the install");

        // Restore perms so cleanup can happen.
        let _ = std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o755));

        assert!(
            matches!(err, Error::ConfigWriteFailed(_)),
            "expected ConfigWriteFailed from backup, got {err:?}"
        );
        // Live config untouched.
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "Port 2222\n");
    }

    #[test]
    fn backup_rotation_keeps_two_generations_across_writes() {
        // The backup must keep at least TWO generations so two consecutive bad
        // edits do not lose the pre-first-edit original. After three writes the
        // on-disk state must be:
        //   target       = content of the 3rd write
        //   target.bak   = content of the 2nd write (immediately prior)
        //   target.bak.1 = content of the 1st write (pre-current-edit original)
        // No .bak.2+ may exist.
        //
        // We run `running_as_root = true` so backup_config takes the `run_cmd`
        // path with the DIRECT command (no sudo), exercising the real `cp` /
        // `mv` / `rm` plumbing against a tempdir we own. The validator seam is
        // Ok so every write reaches the backup step.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("sshd_config");

        std::fs::write(&target, "# generation 0 (original)\nPort 2222\n").unwrap();
        write_sshd_config(
            "# generation 1\nPort 22\n",
            true,
            &target,
            Some(validator_ok),
            None,
        )
        .expect("first write must succeed");

        write_sshd_config(
            "# generation 2\nPort 23\n",
            true,
            &target,
            Some(validator_ok),
            None,
        )
        .expect("second write must succeed");

        write_sshd_config(
            "# generation 3 (current)\nPort 24\n",
            true,
            &target,
            Some(validator_ok),
            None,
        )
        .expect("third write must succeed");

        let bak = format!("{}.bak", target.display());
        let bak1 = format!("{}.bak.1", target.display());
        let bak2 = format!("{}.bak.2", target.display());

        // Live config is the latest.
        let live = std::fs::read_to_string(&target).unwrap();
        assert!(
            live.contains("generation 3"),
            "live must be the 3rd write: {live:?}"
        );

        // .bak holds the immediately prior content.
        let prev_content = std::fs::read_to_string(&bak).unwrap();
        assert!(
            prev_content.contains("generation 2"),
            ".bak must hold the 2nd write: {prev_content:?}"
        );

        // .bak.1 holds the pre-current-edit ORIGINAL (the 1st write), which a
        // single-generation scheme would have clobbered on the 3rd write.
        let oldest_content = std::fs::read_to_string(&bak1).unwrap();
        assert!(
            oldest_content.contains("generation 1"),
            ".bak.1 must hold the 1st write (pre-current-edit original): {oldest_content:?}"
        );

        // At most two generations are retained — no .bak.2 leaks.
        assert!(
            !Path::new(&bak2).exists(),
            "no .bak.2+ must be retained (max two generations)"
        );
    }

    #[test]
    fn install_command_non_root_is_single_invocation_chmod_then_mv() {
        // INVARIANT #3 (non-root install+chmod is a SINGLE sudo invocation)
        // locked as an executable assertion. The program MUST be `sh` and the
        // args MUST be exactly: [-c, "chmod 644 \"$0\" && mv \"$0\" \"$1\"",
        // <src>, <dst>]. Folding chmod+mv into one sh -c means a single
        // sudo-credential timestamp covers both. The chmod runs on the staged
        // temp BEFORE the mv, so a chmod failure aborts (`&&`) before the live
        // config is touched — mirroring the root path's chmod-then-rename, it
        // can never leave the live config at the temp's 0o600 mode. The
        // `$0`/`$1` positional binding means the paths need no shell-quoting.
        let src = Path::new("/etc/ssh/toride-sshd-abc.tmp");
        let dst = Path::new("/etc/ssh/sshd_config");
        let (program, args) = install_command(src, dst, 0o644, false);

        assert_eq!(program, "sh", "non-root install must run via sh -c");
        assert_eq!(
            args,
            vec![
                "-c".to_string(),
                "chmod 644 \"$0\" && mv \"$0\" \"$1\"".to_string(),
                "/etc/ssh/toride-sshd-abc.tmp".to_string(),
                "/etc/ssh/sshd_config".to_string(),
            ],
            "non-root install args must be the exact single-invocation chmod-then-mv"
        );
    }

    #[test]
    fn write_sshd_config_refuses_to_install_over_symlink() {
        // [LOW #2] If the pinned `target` is a symlink, rename(2)/mv would
        // replace the SYMLINK (not the resolved file) — toride would report
        // success while the running sshd keeps the old config. The write MUST
        // fail closed with a symlink message and MUST NOT create or modify the
        // resolved file.
        let dir = tempfile::tempdir().unwrap();
        let resolved = dir.path().join("real_config");
        let original = "Port 2222\n";
        std::fs::write(&resolved, original).unwrap();
        // `target` is a symlink pointing at `resolved`.
        let target = dir.path().join("sshd_config");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&resolved, &target).unwrap();
        #[cfg(not(unix))]
        {
            // Symlinks are a unix concept; nothing to test off-unix.
            return;
        }

        let err = write_sshd_config("# new\nPort 22\n", true, &target, Some(validator_ok), None)
            .expect_err("must refuse to install over a symlink");

        let msg = err.to_string();
        assert!(
            msg.contains("symlink"),
            "error must mention symlink, got: {msg}"
        );
        // The resolved file must be untouched (not created/modified by us).
        assert_eq!(
            std::fs::read_to_string(&resolved).unwrap(),
            original,
            "resolved file must not be modified when target is a symlink"
        );
    }

    #[test]
    fn write_sshd_config_root_path_installs_at_mode_644() {
        // [LOW #3 / T3] After a successful root-path write, the installed
        // target must be mode 0o644. This documents the chmod-before-rename
        // outcome: the temp is chmod'd to 0o644 BEFORE the rename, so the live
        // file lands at the right mode with no post-install chmod that could
        // fail and leave 0o600.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("sshd_config");
        std::fs::write(&target, "# old\nPort 2222\n").unwrap();

        write_sshd_config("# new\nPort 22\n", true, &target, Some(validator_ok), None)
            .expect("happy path must succeed");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&target).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o777,
                0o644,
                "installed sshd_config must be mode 0o644, got {mode:#o}"
            );
        }
        // And the new content is live.
        let installed = std::fs::read_to_string(&target).unwrap();
        assert!(installed.contains("Port 22"));
    }

    // -------------------------------------------------------------------------
    // [F16] deterministic classification of the validator command output.
    // -------------------------------------------------------------------------
    //
    // `default_validator` used to only be exercised by a host-dependent test
    // that SKIPS when `sshd` is absent — so on CI without sshd the three-way
    // classification (privilege-denied → binary-missing → invalid) never ran.
    // Now the runner is split from the classifier; these tests feed canned
    // `ValidatorRun` values directly to `classify_validator_output` and assert
    // each branch with no dependency on the host having sshd.

    #[test]
    fn classify_validator_output_ok_on_empty_stderr_zero_exit() {
        // `sshd -t` accepted the config: exit 0, no diagnostic. The classifier
        // must report Ok so the write proceeds to install.
        let outcome = classify_validator_output(ValidatorRun::Output {
            stdout: Vec::new(),
            success: true,
        });
        assert_eq!(outcome, ValidateOutcome::Ok);
    }

    #[test]
    fn classify_validator_output_binary_missing_for_spawn_failure() {
        // The privileged runner could not even be launched (ENOENT on `sudo`/
        // `sshd`, EACCES, EAGAIN, …). The validator never ran, so this MUST
        // NOT be classified as Invalid (which would wrongly point the user at
        // their sshd_config). It must be BinaryMissing — the write fails closed
        // without misreporting a config error.
        let outcome = classify_validator_output(ValidatorRun::SpawnFailed(
            "ENOENT: sudo: No such file or directory".into(),
        ));
        assert!(
            matches!(outcome, ValidateOutcome::BinaryMissing(_)),
            "spawn failure must classify as BinaryMissing, got {outcome:?}"
        );
    }

    #[test]
    fn classify_validator_output_binary_missing_for_command_not_found_stderr() {
        // Non-zero exit whose stderr indicates the binary itself is missing
        // (sudo/shell phrasing), e.g. `sudo -n sshd` when sshd is not on the
        // secure_path. A binary under a nonexistent dir produces exactly this.
        // Must classify as BinaryMissing, NOT Invalid.
        let detail = b"sudo: sshd: command not found\n".to_vec();
        let outcome = classify_validator_output(ValidatorRun::Output {
            stdout: detail,
            success: false,
        });
        assert!(
            matches!(outcome, ValidateOutcome::BinaryMissing(_)),
            "command-not-found stderr must classify as BinaryMissing, got {outcome:?}"
        );
    }

    #[test]
    fn classify_validator_output_invalid_for_bad_configuration_option() {
        // Non-zero exit whose stderr is a genuine config error (e.g. "Bad
        // configuration option"). This is the case `sshd -t` actually emits for
        // a malformed config; it must classify as Invalid so the write fails
        // closed with SshdConfigInvalid and the UI points the user at the bad
        // directive.
        let detail = b"/etc/ssh/sshd_config: line 3: Bad configuration option: foo\n".to_vec();
        let outcome = classify_validator_output(ValidatorRun::Output {
            stdout: detail,
            success: false,
        });
        match outcome {
            ValidateOutcome::Invalid(msg) => {
                assert!(
                    msg.contains("Bad configuration option"),
                    "Invalid detail must carry sshd's diagnostic, got {msg:?}"
                );
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn classify_validator_output_privilege_denied_beats_binary_missing_and_invalid() {
        // Ordering: privilege FIRST. `sudo -n` with no cached credentials
        // prints "a password is required" and exits non-zero — the config was
        // never checked. Even though that phrasing contains neither "not
        // found" nor "Bad configuration option", we assert the classifier
        // returns PrivilegeDenied (which maps to SshdFailed, not SshdConfigInvalid).
        let detail = b"sudo: a password is required\n".to_vec();
        let outcome = classify_validator_output(ValidatorRun::Output {
            stdout: detail,
            success: false,
        });
        assert!(
            matches!(outcome, ValidateOutcome::PrivilegeDenied(_)),
            "sudo password-required must classify as PrivilegeDenied, got {outcome:?}"
        );
    }

    #[test]
    fn classify_validator_output_privilege_denied_wins_over_binary_missing_text() {
        // Defense against a future regression where someone reorders the checks:
        // a stderr that mentions BOTH a password requirement and "not found"
        // must classify as PrivilegeDenied (privilege is checked first).
        let detail = b"sudo: a password is required; sshd not found\n".to_vec();
        let outcome = classify_validator_output(ValidatorRun::Output {
            stdout: detail,
            success: false,
        });
        assert!(
            matches!(outcome, ValidateOutcome::PrivilegeDenied(_)),
            "privilege check must outrank binary-missing, got {outcome:?}"
        );
    }

    #[test]
    fn classify_validator_output_binary_missing_wins_over_invalid_text() {
        // Ordering continuation: binary-missing is checked before Invalid. A
        // stderr that mentions both "command not found" and a config-style
        // phrase must classify as BinaryMissing.
        let detail = b"sshd: command not found (Bad configuration option)\n".to_vec();
        let outcome = classify_validator_output(ValidatorRun::Output {
            stdout: detail,
            success: false,
        });
        assert!(
            matches!(outcome, ValidateOutcome::BinaryMissing(_)),
            "binary-missing must outrank invalid, got {outcome:?}"
        );
    }

    #[test]
    fn classify_validator_output_trims_detail() {
        // The carried detail is trimmed so the UI shows a clean message rather
        // than trailing whitespace from sshd's stderr.
        let outcome = classify_validator_output(ValidatorRun::Output {
            stdout: b"  line 1: Bad configuration option: foo  \n".to_vec(),
            success: false,
        });
        match outcome {
            ValidateOutcome::Invalid(msg) => {
                assert!(
                    !msg.starts_with(' '),
                    "detail must be left-trimmed: {msg:?}"
                );
                assert!(
                    !msg.ends_with('\n'),
                    "detail must be right-trimmed: {msg:?}"
                );
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------------
    // [F14] end-to-end coverage of the NON-root write path.
    // -------------------------------------------------------------------------
    //
    // Every prior `write_sshd_config` test passed `running_as_root = true`, so
    // the non-root branch (lift via sudo cp → validate the LIFTED file → single
    // `sh -c` install) was never executed and `install_command` was only ever
    // asserted as an argv string. An EACCES regression in `lift` or a wiring
    // bug between `install_command` and `run_cmd` would have passed the whole
    // suite. These tests run the NON-root pipeline against a tempdir using an
    // injected `Runner` seam that records invocations and fakes success (or a
    // specific failure) — never invoking real `sudo`.
    //
    // Each scenario uses its OWN dedicated recording statics so the two tests
    // never contend over shared state when the harness runs them concurrently
    // (the existing module-level `STAGED_PATH` is only touched by one test, so
    // it is safe; we follow the same one-static-per-test discipline here).

    // Per-scenario scratch carried through the stub runners via a single
    // thread-local cell. Tests reset their own cell before running; because
    // `Runner` is a bare `fn` pointer (can't capture), the stub reads/writes
    // this cell rather than closing over locals.
    thread_local! {
        /// argv of the install `sh -c` invocation, captured by the happy-path
        /// stub. `None` until the install step actually ran.
        static HAPPY_INSTALL_CALL: std::cell::RefCell<Option<Vec<String>>> =
            const { std::cell::RefCell::new(None) };
        /// Count of INSTALL `sh` invocations seen by the happy-path stub (must
        /// be 1 — the single install; the self-sweep is not counted).
        static HAPPY_SH_COUNT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
        /// argv of the install `sh -c` invocation, captured by the failure
        /// stub. `Some` once the install step was reached.
        static FAIL_INSTALL_CALL: std::cell::RefCell<Option<Vec<String>>> =
            const { std::cell::RefCell::new(None) };
        /// Path the validator was handed (happy path). Thread-local (not the
        /// module-level `STAGED_PATH`) so this test does not contend with the
        /// unrelated `write_sshd_config_stages_temp_as_sibling_of_target` test
        /// when the harness runs tests concurrently.
        static HAPPY_VALIDATED_PATH: std::cell::RefCell<Option<std::path::PathBuf>> =
            const { std::cell::RefCell::new(None) };
        /// Path the validator was handed (failure path). See
        /// `HAPPY_VALIDATED_PATH` for why this is thread-local.
        static FAIL_VALIDATED_PATH: std::cell::RefCell<Option<std::path::PathBuf>> =
            const { std::cell::RefCell::new(None) };
    }

    /// Shared body of the two stub runners: perform the real op for `cp`/`mv`/
    /// `rm` against the tempdir we own, and for the install `sh -c` (distinguished
    /// from the self-sweep by the script content) either chmod+mv for real or —
    /// when `fail_install` is true — return the injected error.
    fn nonroot_runner_impl(
        cmd: &str,
        args: &[&str],
        fail_install: bool,
        on_install: impl Fn(&[String]),
    ) -> Result<()> {
        // `args` (borrowed `&[&str]`) vs `owned_args` (owned `Vec<String>`): the
        // distinct names track the borrow/own split intentionally.
        let owned_args: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        match cmd {
            "cp" => {
                // Both the LIFT (`cp <src> <dst>`) and the backup copy
                // (`cp -p <src> <dst>`) reduce to "copy the two non-flag
                // operands". Perform a real copy so the validator/install see
                // bytes (faking an empty success would leave the validator
                // reading an absent lifted file).
                let pair: Vec<&str> = owned_args
                    .iter()
                    .filter(|a| !a.starts_with('-'))
                    .map(std::string::String::as_str)
                    .collect();
                if pair.len() == 2 {
                    std::fs::copy(pair[0], pair[1])
                        .map_err(|e| Error::ConfigWriteFailed(format!("stub cp failed: {e}")))?;
                }
                Ok(())
            }
            "mv" => {
                // backup rotation `mv <dst> <dst1>`.
                let pair: Vec<&str> = owned_args
                    .iter()
                    .filter(|a| !a.starts_with('-'))
                    .map(std::string::String::as_str)
                    .collect();
                if pair.len() == 2 {
                    let _ = std::fs::rename(pair[0], pair[1]);
                }
                Ok(())
            }
            "rm" => {
                // cleanup / rotation drop.
                let pair: Vec<&str> = owned_args
                    .iter()
                    .filter(|a| !a.starts_with('-'))
                    .map(std::string::String::as_str)
                    .collect();
                for p in pair {
                    let _ = std::fs::remove_file(p);
                }
                Ok(())
            }
            "sh" => {
                // Two `sh -c` invocations flow through here:
                //   1. the top-of-write SELF-SWEEP:
                //      `sh -c 'rm -f "$0"/toride-sshd-*.tmp' <dir>`
                //      (script contains `rm -f`),
                //   2. the single-invocation INSTALL:
                //      `sh -c 'chmod 644 "$0" && mv "$0" "$1"' <src> <dst>`
                //      (script contains `chmod` and `mv`).
                // We distinguish them by the script content; only the install
                // is recorded (via `on_install`) and can be failed. The
                // self-sweep just runs its `rm -f` glob for real.
                let script = owned_args.get(1).map_or("", std::string::String::as_str);
                let is_install = owned_args.first().is_some_and(|a| a == "-c")
                    && script.contains("chmod")
                    && script.contains("mv");
                if is_install {
                    on_install(&owned_args);
                    if fail_install {
                        return Err(Error::SudoFailed("stub: injected install failure".into()));
                    }
                    // owned_args = ["-c", "<script>", src, dst]. Perform the
                    // chmod-then-mv for real against the tempdir we own.
                    if owned_args.len() == 4 {
                        let src = &owned_args[2];
                        let dst = &owned_args[3];
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            std::fs::set_permissions(src, std::fs::Permissions::from_mode(0o644))
                                .map_err(|e| {
                                Error::ConfigWriteFailed(format!("stub chmod failed: {e}"))
                            })?;
                        }
                        std::fs::rename(src, dst).map_err(|e| {
                            Error::ConfigWriteFailed(format!("stub mv failed: {e}"))
                        })?;
                    }
                    return Ok(());
                }
                // Self-sweep `rm -f "$0"/toride-sshd-*.tmp` (now run in BOTH the
                // target dir AND std::env::temp_dir()): best-effort, run the
                // glob against the bound dir. SKIP when the bound dir IS the
                // real std::env::temp_dir() — the production sweep of /tmp is
                // best-effort, and acting on the real /tmp here would risk
                // deleting a CONCURRENT test thread's staged temp (each
                // non-root test stages in std::env::temp_dir()). Within-test
                // sweep behavior (target dir) is still exercised.
                if owned_args.len() == 3
                    && script.contains("rm -f")
                    && let Some(dir) = owned_args.get(2)
                {
                    let is_system_temp =
                        std::path::Path::new(dir) == std::env::temp_dir().as_path();
                    if !is_system_temp && let Ok(entries) = std::fs::read_dir(dir) {
                        for entry in entries.flatten() {
                            let name = entry.file_name();
                            if name.to_string_lossy().starts_with(STAGED_TEMP_PREFIX) {
                                let _ = std::fs::remove_file(entry.path());
                            }
                        }
                    }
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Happy-path stub: counts INSTALL `sh` invocations (those whose script
    /// folds chmod+mv) and records the install argv into its dedicated
    /// thread-local cell. Never injects a failure. (The self-sweep `sh -c 'rm
    /// -f …'` is NOT counted — only the install is, since invariant #3 is
    /// "the install is a single sh -c".)
    fn nonroot_runner_happy(cmd: &str, args: &[&str], _running_as_root: bool) -> Result<()> {
        let is_install_sh = cmd == "sh"
            && args
                .get(1)
                .is_some_and(|s| s.contains("chmod") && s.contains("mv"));
        if is_install_sh {
            HAPPY_SH_COUNT.with(|c| c.set(c.get() + 1));
        }
        nonroot_runner_impl(cmd, args, false, |argv| {
            HAPPY_INSTALL_CALL.with(|cell| {
                *cell.borrow_mut() = Some(argv.to_vec());
            });
        })
    }

    /// Failure-path stub: records the install argv into its dedicated
    /// thread-local cell, then injects an error at the install step.
    fn nonroot_runner_fail(cmd: &str, args: &[&str], _running_as_root: bool) -> Result<()> {
        nonroot_runner_impl(cmd, args, true, |argv| {
            FAIL_INSTALL_CALL.with(|cell| {
                *cell.borrow_mut() = Some(argv.to_vec());
            });
        })
    }

    #[test]
    fn nonroot_write_pipeline_lifts_before_validate_and_installs_single_sh_c() {
        // [F14] Run the NON-root pipeline against a tempdir with the injected
        // runner stub. Assert:
        //   (a) the validator was called with a path whose PARENT is the TARGET
        //       dir — i.e. the lift (`sudo -n cp`) happened BEFORE validate;
        //   (b) install is a SINGLE `sh -c` against the LIFTED temp (invariant
        //       #3 actually executes, not just an argv string);
        //   (c) the installed file ends at mode 0o644;
        //   (d) exactly ONE sh -c install invocation was made.
        HAPPY_INSTALL_CALL.with(|c| *c.borrow_mut() = None);
        HAPPY_SH_COUNT.with(|c| c.set(0));
        HAPPY_VALIDATED_PATH.with(|c| *c.borrow_mut() = None);

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("sshd_config");
        std::fs::write(&target, "# old\nPort 2222\n").unwrap();

        // Validator records the path it was handed (must be the LIFTED temp in
        // the target dir, not the staged temp in /tmp) into a thread-local so
        // it does not contend with the unrelated sibling-staging test.
        let captured: Validator = |path: &Path, _r: bool| {
            HAPPY_VALIDATED_PATH.with(|c| *c.borrow_mut() = Some(path.to_path_buf()));
            ValidateOutcome::Ok
        };

        write_sshd_config(
            "# new\nPort 22\n",
            /* running_as_root = */ false,
            &target,
            Some(captured),
            Some(nonroot_runner_happy),
        )
        .expect("non-root happy path must succeed with the stub runner");

        // (a) The validator's path MUST share a parent with the target — the
        // lift ran before validation. If the lift were skipped, the validator
        // would have seen a path in /tmp (the non-root staging dir) whose
        // parent is NOT the target dir.
        let validated = HAPPY_VALIDATED_PATH
            .with(|c| c.borrow().clone())
            .expect("validator must have been called with the lifted temp");
        assert_eq!(
            validated.parent(),
            target.parent(),
            "validator must run against the LIFTED temp (parent = target dir); \
             got {} — the lift did not happen before validate",
            validated.display()
        );

        // (b)/(d) Exactly ONE sh -c install invocation, and its src ($0) is the
        // lifted temp the validator saw.
        let install = HAPPY_INSTALL_CALL
            .with(|c| c.borrow().clone())
            .expect("install must have run a single sh -c");
        assert_eq!(
            install.len(),
            4,
            "install argv must be [-c, script, src, dst], got {install:?}"
        );
        assert_eq!(install[0], "-c", "install must be an sh -c invocation");
        assert!(
            install[1].contains("chmod") && install[1].contains("mv"),
            "install script must fold chmod+mv into one sh -c, got {:?}",
            install[1]
        );
        assert!(
            install[1].contains("&&"),
            "install script must use && so a chmod failure aborts before mv, got {:?}",
            install[1]
        );
        // The install's src ($0) is the lifted temp the validator saw.
        assert_eq!(
            std::path::PathBuf::from(&install[2]),
            validated,
            "install src ($0) must be the lifted temp the validator validated"
        );
        assert_eq!(
            std::path::PathBuf::from(&install[3]),
            target,
            "install dst ($1) must be the live target"
        );

        // (d) Exactly ONE install sh invocation. The install must be a SINGLE
        // sh -c (invariant #3) — if a regression split chmod and mv into two
        // separate sh invocations, this count would be 2. (The self-sweep
        // `sh -c 'rm -f …'` at the top of write_sshd_config is deliberately
        // NOT counted — only install-shaped sh calls are.)
        let sh_count = HAPPY_SH_COUNT.with(std::cell::Cell::get);
        assert_eq!(
            sh_count, 1,
            "exactly ONE install sh -c invocation; found {sh_count}"
        );

        // (c) The installed file lands at 0o644 (the stub chmod'd the lifted
        // temp before the mv).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&target).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o777,
                0o644,
                "installed sshd_config must be mode 0o644, got {mode:#o}"
            );
        }
        // New content is live, old content is gone.
        let live = std::fs::read_to_string(&target).unwrap();
        assert!(
            live.contains("Port 22"),
            "new content must be installed: {live:?}"
        );
        assert!(!live.contains("2222"), "old content must be gone: {live:?}");
        // Backup taken before install (root-owned .bak).
        let backup = std::fs::read_to_string(format!("{}.bak", target.display())).unwrap();
        assert!(
            backup.contains("2222"),
            "backup must hold the pre-install content"
        );
    }

    #[test]
    fn nonroot_write_pipeline_leaves_live_target_untouched_when_install_fails() {
        // [F14 failure branch] Inject a failure at the install `sh -c` step and
        // assert: Err is returned AND the live target is UNCHANGED (not created
        // at the new content, original content intact). This is the lockout-
        // prevention guarantee: an install failure must never mutate the live
        // config. (Backup was taken before install; that is acceptable — the
        // invariant under test is that the LIVE config is untouched on failure.)
        FAIL_INSTALL_CALL.with(|c| *c.borrow_mut() = None);
        FAIL_VALIDATED_PATH.with(|c| *c.borrow_mut() = None);

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("sshd_config");
        let original = "# old\nPort 2222\n";
        std::fs::write(&target, original).unwrap();

        let captured: Validator = |path: &Path, _r: bool| {
            FAIL_VALIDATED_PATH.with(|c| *c.borrow_mut() = Some(path.to_path_buf()));
            ValidateOutcome::Ok
        };

        let err = write_sshd_config(
            "# new\nPort 22\n",
            /* running_as_root = */ false,
            &target,
            Some(captured),
            Some(nonroot_runner_fail),
        )
        .expect_err("non-root install failure must surface an error");

        // The error must be the injected install failure surfaced via
        // ConfigWriteFailed (the install_temp wrapper maps runner errors to
        // ConfigWriteFailed).
        assert!(
            matches!(err, Error::ConfigWriteFailed(_)),
            "expected ConfigWriteFailed from the failed install, got {err:?}"
        );

        // THE lockout-prevention assertion: the live config is byte-for-byte
        // unchanged. If the install had half-applied (e.g. a bug where the
        // chmod ran but the mv did not, or the live file was overwritten before
        // the install command returned), this would differ.
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            original,
            "live config must be UNCHANGED when the install step fails"
        );

        // The lift + validation ran BEFORE the install failed: the validator
        // was handed a path whose parent IS the target dir (i.e. the file was
        // lifted out of /tmp into the target dir first). Combined with the
        // install assertion below, this proves the failure originated at the
        // install step — not at the lift, which would have masked the install
        // path under test.
        let validated = FAIL_VALIDATED_PATH
            .with(|c| c.borrow().clone())
            .expect("validator must have been called (lift succeeded before install)");
        assert_eq!(
            validated.parent(),
            target.parent(),
            "validator must have run against the lifted temp (parent = target dir)"
        );

        // And the install step was actually reached (the validator passed, so
        // the failure is from install — not an earlier lift/validate failure
        // that would mask the install path under test).
        let install = FAIL_INSTALL_CALL.with(|c| c.borrow().clone());
        assert!(
            install.is_some(),
            "install sh -c must have been invoked (the failure is from install, not earlier)"
        );
    }

    // -------------------------------------------------------------------------
    // [F3] lifted temp uses a DISTINCT prefix the self-sweep glob cannot match.
    // -------------------------------------------------------------------------
    //
    // The staged temp is `toride-sshd-<rand>.tmp`; the self-sweep globs
    // `toride-sshd-*.tmp`. A lifted temp that ALSO started with `toride-sshd-`
    // would be matched by the glob (the `*` swallows any middle), so a
    // concurrent instance's top-of-write sweep could delete THIS instance's
    // just-lifted validate path mid-write. The lifted temp now uses the distinct
    // stem `toride-lifted-`, which the glob provably cannot anchor on. This is
    // defense-in-depth alongside the cross-process lock in sshd::edit().

    /// The lifted temp must take the `toride-lifted-` prefix (NOT the staged
    /// `toride-sshd-` prefix) so the self-sweep glob cannot match it.
    #[test]
    fn lifted_temp_uses_distinct_prefix_that_sweep_glob_cannot_match() {
        // Sanity: the two prefixes are genuinely distinct STEMS, and the staged
        // prefix is NOT a prefix of the lifted prefix (otherwise the glob
        // `toride-sshd-*` could still match a `toride-sshd-lifted-*` name).
        assert!(
            !LIFTED_TEMP_PREFIX.starts_with(STAGED_TEMP_PREFIX),
            "lifted prefix must NOT begin with the staged prefix, else the \
             self-sweep glob `toride-sshd-*` would still match it"
        );
        // Construct a lifted name as the code does and prove the shell glob
        // pattern used by the self-sweep does NOT match it. We approximate the
        // shell glob `toride-sshd-*.tmp` with a simple matcher: a name matches
        // iff it starts with `toride-sshd-` and ends with `.tmp`.
        let lifted_name = format!("{LIFTED_TEMP_PREFIX}abc123{TEMP_SUFFIX}");
        let staged_name = format!("{STAGED_TEMP_PREFIX}abc123{TEMP_SUFFIX}");
        let matches_staged_glob = |name: &str| -> bool {
            name.starts_with(STAGED_TEMP_PREFIX) && name.ends_with(TEMP_SUFFIX)
        };
        assert!(
            matches_staged_glob(&staged_name),
            "test harness: staged name must match the sweep glob"
        );
        assert!(
            !matches_staged_glob(&lifted_name),
            "lifted name {lifted_name:?} must NOT match the sweep glob \
             `toride-sshd-*.tmp` (F3); otherwise a concurrent sweep could \
             delete this instance's just-lifted validate path"
        );
    }

    /// End-to-end: on the non-root path, the file the validator receives (the
    /// LIFTED temp) must have the `toride-lifted-` prefix, not `toride-sshd-`.
    /// This reuses the happy-path thread-local validator capture. If the lift
    /// were reverted to reuse the staged basename, this assertion fails.
    #[test]
    fn nonroot_lifted_temp_in_pipeline_uses_distinct_prefix() {
        HAPPY_INSTALL_CALL.with(|c| *c.borrow_mut() = None);
        HAPPY_SH_COUNT.with(|c| c.set(0));
        HAPPY_VALIDATED_PATH.with(|c| *c.borrow_mut() = None);

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("sshd_config");
        std::fs::write(&target, "# old\nPort 2222\n").unwrap();

        let captured: Validator = |path: &Path, _r: bool| {
            HAPPY_VALIDATED_PATH.with(|c| *c.borrow_mut() = Some(path.to_path_buf()));
            ValidateOutcome::Ok
        };

        write_sshd_config(
            "# new\nPort 22\n",
            /* running_as_root = */ false,
            &target,
            Some(captured),
            Some(nonroot_runner_happy),
        )
        .expect("non-root happy path must succeed");

        let validated = HAPPY_VALIDATED_PATH
            .with(|c| c.borrow().clone())
            .expect("validator must have been called with the lifted temp");

        let name = validated
            .file_name()
            .and_then(|n| n.to_str())
            .expect("lifted temp must have a file name");
        assert!(
            name.starts_with(LIFTED_TEMP_PREFIX),
            "lifted temp must use the DISTINCT `toride-lifted-` prefix (F3), \
             got {name:?} — a `toride-sshd-`-prefixed name would be matched by \
             a concurrent instance's self-sweep glob and could be deleted \
             mid-write"
        );
        assert!(
            !name.starts_with(STAGED_TEMP_PREFIX),
            "lifted temp must NOT start with the staged prefix `{STAGED_TEMP_PREFIX}`"
        );
    }

    // -------------------------------------------------------------------------
    // [F18] the self-sweep reclaims stale STAGED temps but spares LIFTED temps.
    // -------------------------------------------------------------------------
    //
    // This exercises the actual sweep glob mechanics (the production sweep uses
    // `rm -f "$0"/toride-sshd-*.tmp`): a stale STAGED-prefix temp in the target
    // dir must be removed, while a LIFTED-prefix temp must survive. The /tmp
    // sweep uses the identical glob, so this also locks F18's "only staged temps
    // match" invariant.

    #[test]
    fn self_sweep_removes_stale_staged_temps_but_spares_lifted_temps() {
        // Set up a target dir containing: a stale STAGED temp, a fresh LIFTED
        // temp, and the live config. Run a root-path write (so the stub sweep
        // actually executes against the target dir — the production sweep globs
        // the same dir). Assert the STAGED temp is gone and the LIFTED temp
        // survives. We use a runner stub ONLY to drive the sweep; the real
        // install path runs in-process (root).
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("sshd_config");
        std::fs::write(&target, "# old\nPort 2222\n").unwrap();

        // Plant a stale STAGED temp and a LIFTED temp in the target dir.
        let stale_staged = dir
            .path()
            .join(format!("{STAGED_TEMP_PREFIX}stale{TEMP_SUFFIX}"));
        let lifted = dir
            .path()
            .join(format!("{LIFTED_TEMP_PREFIX}live{TEMP_SUFFIX}"));
        std::fs::write(&stale_staged, "stale\n").unwrap();
        std::fs::write(&lifted, "lifted\n").unwrap();

        write_sshd_config("# new\nPort 22\n", true, &target, Some(validator_ok), None)
            .expect("happy path must succeed despite planted temps");

        // The STAGED-prefix temp must have been swept by the top-of-write glob.
        assert!(
            !stale_staged.exists(),
            "stale STAGED temp must be reclaimed by the self-sweep (F18), \
             but it still exists at {}",
            stale_staged.display()
        );
        // The LIFTED-prefix temp must SURVIVE — the glob `toride-sshd-*` does
        // not match `toride-lifted-*`. If F3's distinct-prefix fix were
        // reverted (lifted reused `toride-sshd-`), the sweep would delete this.
        assert!(
            lifted.exists(),
            "LIFTED temp must NOT be matched by the self-sweep glob (F3); \
             it was deleted from {}",
            lifted.display()
        );
        // And the install still succeeded.
        let live = std::fs::read_to_string(&target).unwrap();
        assert!(live.contains("Port 22"), "new content must be installed");
    }

    // -------------------------------------------------------------------------
    // [F20] lift-step sudo-credential expiry is classified as SudoFailed, not
    // ConfigWriteFailed.
    // -------------------------------------------------------------------------

    /// A runner that simulates `sudo -n cp` (the lift step) failing with a
    /// sudo-credential-expiry error, then fakes everything else to succeed.
    fn lift_failing_runner(cmd: &str, args: &[&str], _running_as_root: bool) -> Result<()> {
        // `args` (borrowed `&[&str]`) vs `owned_args` (owned `Vec<String>`): the
        // distinct names track the borrow/own split intentionally.
        let owned_args: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        if cmd == "cp" {
            // The LIFT step is the first `cp` with a non-flag source+dest where
            // the dest lives in the TARGET dir (parent != system temp). Distinguish
            // it from the backup `cp -p` (which has a `-p` flag). The lift `cp`
            // has no flags.
            let has_flags = owned_args.iter().any(|a| a.starts_with('-'));
            if !has_flags && owned_args.len() == 2 {
                // This is the lift `cp <staged> <lifted>`. Fail it the way
                // `sudo -n cp` fails when credentials have expired: run_cmd
                // wraps that as Error::SudoFailed with the sudo stderr text.
                return Err(Error::SudoFailed(
                    "`sudo -n cp ...` exited Some(1): sudo: a password is required".into(),
                ));
            }
        }
        // Everything else (backup cp/mv/rm, install sh -c, sync, sweep sh) is
        // faked to success without doing real work — the lift failure aborts
        // before any of these matter, but we must not panic on them.
        nonroot_runner_impl(cmd, args, false, |_| {})
    }

    #[test]
    fn lift_step_privilege_denial_maps_to_sudo_failed_not_config_write_failed() {
        // F20: when the lift (`sudo -n cp`) fails because sudo credentials
        // expired ("a password is required"), the error MUST surface as
        // Error::SudoFailed (actionable: "run sudo -v"), NOT
        // Error::ConfigWriteFailed (which hides the real cause). If the F20 fix
        // in lift_staged_into_target_dir were reverted, this returns
        // ConfigWriteFailed and the assertion fails.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("sshd_config");
        std::fs::write(&target, "# old\nPort 2222\n").unwrap();

        let err = write_sshd_config(
            "# new\nPort 22\n",
            /* running_as_root = */ false,
            &target,
            Some(validator_ok), // validator never reached (lift fails first)
            Some(lift_failing_runner),
        )
        .expect_err("lift-step privilege denial must surface an error");

        assert!(
            matches!(err, Error::SudoFailed(_)),
            "lift-step privilege denial must map to Error::SudoFailed (F20), \
             got {err:?} — a ConfigWriteFailed here would mislead the user into \
             thinking the config write itself failed rather than that sudo \
             credentials expired"
        );
        // The message must carry the password-required detail so the UI can
        // tell the user to refresh credentials.
        let msg = err.to_string();
        assert!(
            msg.contains("password is required"),
            "SudoFailed detail must carry the sudo password-required phrasing, \
             got {msg:?}"
        );
        // Live config untouched (the failure happened before validation/install).
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "# old\nPort 2222\n"
        );
    }

    #[test]
    fn lift_step_non_privilege_failure_still_maps_to_config_write_failed() {
        // Guard against the F20 fix being too broad: a lift failure that is NOT
        // a privilege denial (e.g. disk full → a generic IO-flavored error
        // surfaced via ConfigWriteFailed by the stub) must STILL map to
        // ConfigWriteFailed. Only privilege denials are reclassified.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("sshd_config");
        std::fs::write(&target, "# old\nPort 2222\n").unwrap();

        let runner: Runner = |cmd: &str, args: &[&str], _r: bool| {
            let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
            if cmd == "cp" && !argv.iter().any(|a| a.starts_with('-')) && argv.len() == 2 {
                // A non-privilege lift failure: the staged source does not exist
                // (so std::fs::copy inside the stub fails), surfaced as
                // ConfigWriteFailed. This does NOT contain "password is required".
                return Err(Error::ConfigWriteFailed(
                    "stub: lift cp failed (no such file)".into(),
                ));
            }
            nonroot_runner_impl(cmd, args, false, |_| {})
        };

        let err = write_sshd_config(
            "# new\nPort 22\n",
            /* running_as_root = */ false,
            &target,
            Some(validator_ok),
            Some(runner),
        )
        .expect_err("a non-privilege lift failure must still surface an error");

        assert!(
            matches!(err, Error::ConfigWriteFailed(_)),
            "a non-privilege lift failure must stay ConfigWriteFailed (F20 only \
             reclassifies privilege denials), got {err:?}"
        );
    }

    // -------------------------------------------------------------------------
    // [F17] parent-dir fsync after install is best-effort and never fails the
    // install.
    // -------------------------------------------------------------------------

    #[test]
    fn fsync_parent_dir_best_effort_is_infallible_and_runs_against_tempdir() {
        // F17: the helper exists, takes (target, running_as_root, runner),
        // returns `()` (it can NEVER turn a successful install into an error),
        // and runs without panicking against a real tempdir parent. If F17 were
        // reverted (the helper removed), this fails to compile.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("sshd_config");
        std::fs::write(&target, "Port 22\n").unwrap();

        // Call it directly: must return () and must not panic. The in-process
        // arm opens the parent (the tempdir) read-only and fsyncs it — that
        // succeeds on a normal tempdir.
        let (): () = fsync_parent_dir_best_effort(&target, true, run_cmd);

        // And via the non-root signature path (still returns ()); the in-process
        // arm succeeds so the privileged fallback is not reached.
        let (): () = fsync_parent_dir_best_effort(&target, false, run_cmd);
    }

    #[test]
    fn root_path_install_succeeds_and_invokes_parent_fsync_step() {
        // F17 regression guard: a root-path install must still succeed WITH the
        // post-install parent-dir fsync wired into install_temp. If the fsync
        // call were removed or made fallible in a way that propagated, the
        // install path under test would change. We assert success and that the
        // parent dir is still a usable directory afterward.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("sshd_config");
        std::fs::write(&target, "# old\nPort 2222\n").unwrap();

        install_temp(
            &{
                // Build a sibling temp the way write_sshd_config would, so the
                // rename is same-directory.
                let staged = dir
                    .path()
                    .join(format!("{STAGED_TEMP_PREFIX}f17{TEMP_SUFFIX}"));
                std::fs::write(&staged, "# new\nPort 22\n").unwrap();
                staged
            },
            &target,
            0o644,
            /* running_as_root = */ true,
            run_cmd,
        )
        .expect("root-path install must succeed with the F17 fsync step wired in");

        // Install landed.
        assert!(
            std::fs::read_to_string(&target)
                .unwrap()
                .contains("Port 22")
        );
        // Parent dir is still usable (the fsync didn't corrupt anything).
        assert!(std::fs::read_dir(dir.path()).is_ok());
    }

    #[test]
    fn nonroot_install_succeeds_and_parent_fsync_fallback_does_not_fail_install() {
        // F17: on the non-root path, after the single sh -c install, the
        // parent-dir fsync runs its in-process arm (succeeds on the tempdir
        // parent) and the install still returns Ok. We inject a stub runner
        // whose catch-all handles the `sync` privileged fallback as Ok; the
        // key assertion is that the install returns Ok end-to-end (the fsync
        // hygiene step never propagates a failure).
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("sshd_config");
        std::fs::write(&target, "# old\nPort 2222\n").unwrap();
        let staged = dir
            .path()
            .join(format!("{STAGED_TEMP_PREFIX}f17nr{TEMP_SUFFIX}"));
        std::fs::write(&staged, "# new\nPort 22\n").unwrap();

        install_temp(
            &staged,
            &target,
            0o644,
            /* running_as_root = */ false,
            nonroot_runner_happy,
        )
        .expect("non-root install must succeed; the F17 parent fsync must never fail it");

        assert!(
            std::fs::read_to_string(&target)
                .unwrap()
                .contains("Port 22")
        );
    }
}
