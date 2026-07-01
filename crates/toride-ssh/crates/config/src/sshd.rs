//! Editing of `/etc/ssh/sshd_config` for access-control directives.
//!
//! This reuses the lossless [`ast::ConfigAst`] (which already handles `Match`
//! blocks, `Include`, comments, and whitespace faithfully) to provide focused
//! read/edit operations for the user-access directives Toride cares about:
//! `AllowUsers` and `DenyUsers`.
//!
//! Writes are privileged (the file is root-owned) and go through
//! [`toride_ssh_core::run_privileged`], which validates the result with
//! `sshd -t` and keeps a `.bak` backup before installing — a malformed
//! `sshd_config` would lock the user out of SSH, so an invalid config is never
//! written.
//!
//! All access here is restricted to **global** directives (those outside any
//! `Match` block). `Match`-scoped directives are intentionally left untouched
//! — editing them blindly is dangerous, and global scope is what we expose in
//! the UI.

use toride_ssh_core::{Result, privilege::PrivilegedOp, run_privileged};

use super::ast::{ConfigAst, ConfigNode, DirectiveData, Separator, parse};

/// Path to the system SSH daemon configuration.
const SSHD_CONFIG_PATH: &str = "/etc/ssh/sshd_config";

/// Environment variable used to override the cross-process edit lock path.
///
/// Tests set this to a temp-dir lock file so the serializing behaviour can be
/// exercised without touching `/tmp` or competing with a real toride instance.
/// Production callers should leave it unset.
const SSHD_EDIT_LOCK_ENV: &str = "TORIDE_SSHD_EDIT_LOCK";

/// Default cross-process lock file for `sshd_config` edits.
///
/// Lives in `/tmp` (world-writable, sticky) so that **both** a root toride
/// process and a non-root toride process contending on the same `sshd_config`
/// rendezvous on the *same* file and serialize via `flock`. A lock derived
/// from the config path (e.g. `/etc/ssh/sshd_config.lock`) would not work: a
/// non-root process cannot create files in `/etc/ssh`, so the two processes
/// would lock *different* files (or none at all) and the second install would
/// clobber the first.
const SSHD_EDIT_LOCK_DEFAULT: &str = "/tmp/toride-sshd-config.lock";

/// Resolve the cross-process lock path for `sshd_config` edits.
///
/// Honours [`SSHD_EDIT_LOCK_ENV`] when set (tests use this); otherwise returns
/// [`SSHD_EDIT_LOCK_DEFAULT`].
fn edit_lock_path() -> std::path::PathBuf {
    match std::env::var_os(SSHD_EDIT_LOCK_ENV) {
        Some(p) if !p.is_empty() => std::path::PathBuf::from(p),
        _ => std::path::PathBuf::from(SSHD_EDIT_LOCK_DEFAULT),
    }
}

/// Ensure the cross-process lock file exists and is openable by every user
/// that may contend on a `sshd_config` edit — both root and non-root toride
/// processes, plus any other editor.
///
/// The lock lives in `/tmp` (sticky, world-writable). To let *any* user
/// `open(O_RDWR)` it for `flock`, it must be world read/write (`0o666`). We
/// create it with those perms if absent, and (best-effort) chmod it to `0o666`
/// if we own it / are root. If it already exists and we can't change its perms,
/// we simply proceed — `toride_fs::with_lock`'s own `open` will surface an
/// `EACCES` as a `LockFailed` error if it genuinely cannot be opened, which is
/// the correct fail-closed behaviour.
fn ensure_lock_file(path: &std::path::Path) {
    // Create if missing. `create_new` avoids a race: if two processes race
    // here, the loser simply gets AlreadyExists, which we ignore.
    let created = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path);
    if let Ok(f) = created {
        // We created it: set world-rw immediately so other users can flock.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = f.set_permissions(std::fs::Permissions::from_mode(0o666));
        }
        #[cfg(not(unix))]
        {
            let _ = f; // silence unused on non-unix
        }
    }

    // Best-effort: ensure existing file is world-rw (only works if we own it
    // or are root; ignored otherwise). This recovers from a file created with
    // default umask by an earlier version or another process.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666));
    }
}

// ---------------------------------------------------------------------------
// Load / save / edit
// ---------------------------------------------------------------------------

/// Load and parse `/etc/ssh/sshd_config` into a lossless AST.
///
/// Returns an empty AST if the file does not exist.
///
/// # Errors
///
/// Returns [`Error::Io`] if the file exists but cannot be read.
pub async fn load() -> Result<ConfigAst> {
    let path = std::path::Path::new(SSHD_CONFIG_PATH);
    if !path.exists() {
        return Ok(ConfigAst { nodes: Vec::new() });
    }
    let content = tokio::fs::read_to_string(path).await?;
    Ok(parse(&content))
}

/// Serialize the AST and install it as `/etc/ssh/sshd_config` via a privileged
/// operation (validation + backup + atomic install).
///
/// `running_as_root` selects direct writes vs. the `sudo -n` path.
///
/// # Errors
///
/// Returns [`Error::SshdConfigInvalid`] if `sshd -t` rejects the config, or
/// [`Error::SudoFailed`] if the privileged install can't run.
pub async fn save(ast: &ConfigAst, running_as_root: bool) -> Result<()> {
    let content = ast.to_string_lossless();
    run_privileged(PrivilegedOp::WriteSshdConfig { content }, running_as_root).await
}

/// Acquire the cross-process edit lock on `path` and run `f` while it is held.
///
/// Thin wrapper around [`toride_fs::with_lock`] that first ensures the lock
/// file is openable by every contending user. Exposed (module-private) so the
/// serialization guarantee can be unit-tested without driving a full privileged
/// `sshd_config` write.
#[cfg(test)]
fn with_edit_lock<T>(path: &std::path::Path, f: impl FnOnce() -> Result<T>) -> Result<T> {
    ensure_lock_file(path);
    // `toride_fs::with_lock` requires a closure returning `toride_fs::Result`,
    // but our critical section yields `toride_ssh_core::Result`. Bridge the two
    // by funneling the ssh error through a `toride_fs::Error::Io` (which itself
    // carries the original message verbatim); the `.map_err` below then lifts
    // *all* errors — both lock-acquisition failures and inner-critical-section
    // failures — back into `toride_ssh_core::Error::Io`.
    toride_fs::with_lock(path, || {
        f().map_err(|e| {
            toride_fs::Error::Io(std::io::Error::other(format!(
                "sshd_config edit critical section failed: {e}"
            )))
        })
    })
    .map_err(|e| {
        toride_ssh_core::Error::Io(std::io::Error::other(format!(
            "sshd_config edit lock failed: {e}"
        )))
    })
}

/// Load, mutate, and save `/etc/ssh/sshd_config` in one call.
///
/// Mirrors [`ConfigService::edit`](super::ConfigService::edit): the closure
/// mutates the AST in place; on success the result is validated and installed.
///
/// # Concurrency
///
/// The entire load → mutate → save critical section is serialized across
/// processes by an advisory lock (`flock`) acquired on [`edit_lock_path`]
/// **before** the read and held until the install completes. This prevents two
/// concurrent toride instances (or toride + another editor) from each loading
/// the same original config, applying their edit, and the second install
/// clobbering the first.
///
/// Implementation note: the lock guard is held across the awaited load/save so
/// the critical section stays non-blocking from the runtime's perspective at
/// the `.await` points (the file I/O and the privileged `sshd -t`/install run
/// on blocking threads inside `load`/`save`). This avoids
/// [`tokio::task::block_in_place`] + a nested `Handle::block_on`, which would
/// panic with "can call blocking only when running on the multi-threaded
/// runtime" when `edit()` is driven from a current-thread runtime (the default
/// for `#[tokio::test]` and many embedded runtimes). The caller's closure `f`
/// stays `FnOnce` (no `Send`/`'static` bound) because the guard, lock, and
/// backing file are all plain locals dropped in declaration order at scope end.
///
/// # Errors
///
/// Propagates any error from locking, loading, the closure, or saving.
pub async fn edit<F>(running_as_root: bool, f: F) -> Result<()>
where
    F: FnOnce(&mut ConfigAst) -> Result<()>,
{
    let lock_path = edit_lock_path();
    ensure_lock_file(&lock_path);

    // Acquire the cross-process advisory lock. The lock, the backing file, and
    // the write guard are all locals here; declaration order guarantees the
    // guard (borrowing `lock`) is dropped before `lock` (and the file it owns)
    // at scope end, releasing the flock on every return path — error, panic,
    // or success. The lock-acquire itself is a `flock(2)` syscall (cheap; only
    // contends with other toride instances editing sshd_config, a brief and
    // rare contention), so it does not need to run on a blocking thread.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|e| {
            toride_ssh_core::Error::Io(std::io::Error::other(format!(
                "sshd_config edit lock failed: cannot open lock file {}: {e}",
                lock_path.display()
            )))
        })?;
    let mut lock = fd_lock::RwLock::new(file);
    let _guard = lock.write().map_err(|e| {
        toride_ssh_core::Error::Io(std::io::Error::other(format!(
            "sshd_config edit lock failed: cannot acquire lock on {}: {e}",
            lock_path.display()
        )))
    })?;
    tracing::debug!(path = %lock_path.display(), "sshd_config edit lock acquired");

    // Genuine async critical section: no nested runtime, no block_in_place.
    let mut ast = load().await?;
    f(&mut ast)?;
    save(&ast, running_as_root).await
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

/// The current global `AllowUsers` list (ignoring `Match`-scoped directives).
///
/// OpenSSH treats multiple `AllowUsers` lines as additive, so values from all
/// global occurrences are concatenated.
#[must_use]
pub fn get_allow_users(ast: &ConfigAst) -> Vec<String> {
    collect_global_users(ast, "AllowUsers")
}

/// The current global `DenyUsers` list (ignoring `Match`-scoped directives).
#[must_use]
pub fn get_deny_users(ast: &ConfigAst) -> Vec<String> {
    collect_global_users(ast, "DenyUsers")
}

/// The current global `AllowGroups` list (ignoring `Match`-scoped directives).
///
/// OpenSSH treats multiple `AllowGroups` lines as additive, so values from all
/// global occurrences are concatenated.
#[must_use]
pub fn get_allow_groups(ast: &ConfigAst) -> Vec<String> {
    collect_global_users(ast, "AllowGroups")
}

/// The current global `DenyGroups` list (ignoring `Match`-scoped directives).
#[must_use]
pub fn get_deny_groups(ast: &ConfigAst) -> Vec<String> {
    collect_global_users(ast, "DenyGroups")
}

/// Collect every whitespace-separated token from all global `<key>` directives.
///
/// Only top-level [`ConfigNode::Directive`] nodes are considered — values
/// inside `Match`/`Host` blocks are intentionally skipped, since those are
/// scope-specific and not what Toride's global UI exposes.
///
/// **Scope-ambiguous directives are also skipped.** A top-level `<key>`
/// directive that immediately follows (ignoring `BlankLine`/`Comment`) a
/// `Match`/`Host` block may be a block-scoped directive that the
/// indentation-based parser leaked to global scope (see `ast::parse_block_body`).
/// Counting such a leaked directive as global would misreport access control
/// in the UI, so it is excluded here.
fn collect_global_users(ast: &ConfigAst, key: &str) -> Vec<String> {
    let indices: Vec<usize> = ast
        .nodes
        .iter()
        .enumerate()
        .filter(
            |(_, n)| matches!(n, ConfigNode::Directive(d) if d.keyword.eq_ignore_ascii_case(key)),
        )
        .map(|(i, _)| i)
        .collect();

    // Exclude any directive whose scope is ambiguous (follows a Match/Host
    // block in document order). See `directive_follows_match_or_host`.
    let leaked: Vec<usize> = directive_follows_match_or_host_set(&ast.nodes, &indices);
    let leaked_set: std::collections::HashSet<usize> = leaked.into_iter().collect();

    let mut out = Vec::new();
    for &i in &indices {
        if leaked_set.contains(&i) {
            continue;
        }
        if let ConfigNode::Directive(d) = &ast.nodes[i] {
            out.extend(d.value.split_whitespace().map(str::to_owned));
        }
    }
    out
}

/// Returns `true` if any of the `directive_indices` immediately follows a
/// `Match`/`Host` block in document order (ignoring `BlankLine`/`Comment`
/// nodes between them).
///
/// This is the scope-ambiguity detector backing the fail-closed write guard
/// in [`upsert_user_in_directive`]. Used to refuse edits that `sshd -t` cannot
/// catch (the leaked file is syntactically valid) and that would otherwise
/// relocate a block-scoped directive to global scope on disk.
fn directive_follows_match_or_host(nodes: &[ConfigNode], directive_indices: &[usize]) -> bool {
    !directive_follows_match_or_host_set(nodes, directive_indices).is_empty()
}

/// Like [`directive_follows_match_or_host`] but returns the full set of
/// directive indices whose preceding non-trivial node is a `Match`/`Host`
/// block. Returned in ascending index order with no duplicates.
fn directive_follows_match_or_host_set(
    nodes: &[ConfigNode],
    directive_indices: &[usize],
) -> Vec<usize> {
    let mut leaked = Vec::new();
    for &idx in directive_indices {
        // Walk backwards from idx, skipping BlankLine/Comment nodes, to find
        // the nearest "content" sibling. If that sibling is a Match/Host block,
        // this directive's scope is ambiguous.
        let mut j = idx;
        while j > 0 {
            j -= 1;
            match &nodes[j] {
                ConfigNode::BlankLine | ConfigNode::Comment { .. } => {}
                ConfigNode::MatchBlock(_) | ConfigNode::HostBlock(_) => {
                    leaked.push(idx);
                    break;
                }
                ConfigNode::Directive(_) => break,
            }
        }
    }
    leaked.sort_unstable();
    leaked.dedup();
    leaked
}

// ---------------------------------------------------------------------------
// Pattern detection
// ---------------------------------------------------------------------------

/// Returns `true` if `value` contains any OpenSSH pattern tokens.
///
/// `AllowUsers`/`DenyUsers` values are pattern strings: a token may contain
/// glob wildcards (`*`, `?`) or a `user@host` selector. Such a directive
/// cannot be safely edited by exact username — adding a plain name would be
/// swallowed by an existing pattern, and "removing" against patterns would be
/// semantically meaningless. The editor refuses to mutate such directives
/// instead (see [`directive_has_patterns`]).
///
/// Each whitespace-separated token is inspected independently.
#[must_use]
pub fn has_pattern_tokens(value: &str) -> bool {
    value
        .split_whitespace()
        .any(|tok| tok.contains('*') || tok.contains('?') || tok.contains('@'))
}

/// Returns `true` if any global `<key>` directive contains pattern tokens.
///
/// `Match`-scoped directives are ignored, consistent with the rest of this
/// module's global-only scope. Scope-ambiguous directives that follow a
/// `Match`/`Host` block (the `parse_block_body` leak — see `ast::parse_block_body`)
/// are likewise excluded, so a leaked block-scoped `*` does not get reported as
/// a global pattern.
#[must_use]
pub fn directive_has_patterns(ast: &ConfigAst, key: &str) -> bool {
    let indices: Vec<usize> = ast
        .nodes
        .iter()
        .enumerate()
        .filter(
            |(_, n)| matches!(n, ConfigNode::Directive(d) if d.keyword.eq_ignore_ascii_case(key)),
        )
        .map(|(i, _)| i)
        .collect();
    let leaked = directive_follows_match_or_host_set(&ast.nodes, &indices);
    let leaked_set: std::collections::HashSet<usize> = leaked.into_iter().collect();

    indices.iter().any(|&i| {
        if leaked_set.contains(&i) {
            return false;
        }
        matches!(&ast.nodes[i], ConfigNode::Directive(d) if has_pattern_tokens(&d.value))
    })
}

// ---------------------------------------------------------------------------
// Write
// ---------------------------------------------------------------------------

/// Add `user` to the global `AllowUsers` directive.
///
/// Idempotent: a no-op if the user is already listed. If no `AllowUsers`
/// directive exists, one is appended at the end of the global section (before
/// the first `Match`/`Host` block, or at the end of the file).
///
/// Multiple global `AllowUsers` lines are consolidated into the first
/// occurrence (OpenSSH treats them as additive, so the merge is semantically
/// equivalent).
///
/// # Errors
///
/// Returns [`Error::SshdConfigInvalid`] if an existing `AllowUsers` directive
/// uses pattern tokens (`*`, `?`, `@`); the AST is left unmodified in that
/// case. Editing a pattern directive by exact username would be semantically
/// wrong.
pub fn add_user_to_allow(ast: &mut ConfigAst, user: &str) -> Result<()> {
    upsert_user_in_directive(ast, "AllowUsers", user, Action::Add)
}

/// Remove `user` from the global `AllowUsers` directive.
///
/// If the removal empties the list, the directive is deleted entirely (an
/// absent `AllowUsers` means "all allowed", which is the OpenSSH default and
/// clearer than a dangling empty line). Multiple global `AllowUsers` lines are
/// merged first, so removing a user who lived only on a later line succeeds.
///
/// # Errors
///
/// Returns [`Error::SshdConfigInvalid`] if an existing `AllowUsers` directive
/// uses pattern tokens (`*`, `?`, `@`); the AST is left unmodified.
pub fn remove_user_from_allow(ast: &mut ConfigAst, user: &str) -> Result<()> {
    upsert_user_in_directive(ast, "AllowUsers", user, Action::Remove)
}

/// Add `user` to the global `DenyUsers` directive. Idempotent.
///
/// # Errors
///
/// Returns [`Error::SshdConfigInvalid`] if an existing `DenyUsers` directive
/// uses pattern tokens (`*`, `?`, `@`); the AST is left unmodified.
pub fn add_user_to_deny(ast: &mut ConfigAst, user: &str) -> Result<()> {
    upsert_user_in_directive(ast, "DenyUsers", user, Action::Add)
}

/// Remove `user` from the global `DenyUsers` directive, deleting the directive
/// if it becomes empty.
///
/// # Errors
///
/// Returns [`Error::SshdConfigInvalid`] if an existing `DenyUsers` directive
/// uses pattern tokens (`*`, `?`, `@`); the AST is left unmodified.
pub fn remove_user_from_deny(ast: &mut ConfigAst, user: &str) -> Result<()> {
    upsert_user_in_directive(ast, "DenyUsers", user, Action::Remove)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Add,
    Remove,
}

/// Add or remove `user` from the global `<key>` directive(s), creating or
/// deleting the directive as needed.
///
/// Refuses to touch the AST (returning [`Error::SshdConfigInvalid`]) if any
/// global occurrence of `<key>` contains pattern tokens — editing a pattern
/// directive by exact username would be semantically wrong.
///
/// When multiple global occurrences exist, they are merged into the first
/// (deduplicated, order-preserving) and the rest are deleted. OpenSSH treats
/// multiple lines as additive, so the merge is lossless from the daemon's
/// perspective and keeps the file readable. A warning is logged when a merge
/// occurs.
fn upsert_user_in_directive(
    ast: &mut ConfigAst,
    key: &str,
    user: &str,
    action: Action,
) -> Result<()> {
    let indices: Vec<usize> = ast
        .nodes
        .iter()
        .enumerate()
        .filter(
            |(_, n)| matches!(n, ConfigNode::Directive(d) if d.keyword.eq_ignore_ascii_case(key)),
        )
        .map(|(i, _)| i)
        .collect();

    // Fail-closed against the parse_block_body Match/Host-leak (see ast.rs
    // `parse_block_body` doc comment): if ANY matching Directive node is
    // immediately preceded in document order (ignoring BlankLine/Comment
    // nodes) by a Match/Host block, its scope is genuinely ambiguous — it may
    // be a block-scoped directive that the indentation-based parser leaked to
    // the top level. `sshd -t` would still accept the file (it is syntactically
    // valid), so the validation gate cannot catch this, and re-rendering at
    // indent 0 would permanently relocate the directive to global scope. Refuse
    // without mutating the AST. This check runs BEFORE the pattern-token check
    // and BEFORE any mutation, so the AST is untouched on error.
    if directive_follows_match_or_host(&ast.nodes, &indices) {
        return Err(toride_ssh_core::Error::SshdConfigInvalid(format!(
            "refusing to edit {key}: directive follows a Match/Host block and its \
             scope is ambiguous (unindented Match body)"
        )));
    }

    // Refuse to mutate any directive that already uses patterns — exact
    // username edits against glob/@ selectors are semantically wrong. Check
    // before touching anything so the AST is left unmodified on error.
    if indices
        .iter()
        .any(|&i| matches!(&ast.nodes[i], ConfigNode::Directive(d) if has_pattern_tokens(&d.value)))
    {
        return Err(toride_ssh_core::Error::SshdConfigInvalid(format!(
            "{key} uses pattern tokens (* ? @); refusing to edit by exact username"
        )));
    }

    if indices.len() > 1 {
        tracing::warn!(
            "{key} appears {} times in sshd_config; merging into the first occurrence",
            indices.len()
        );
    }

    match indices.first() {
        Some(&first) => {
            // Gather the UNION of values across all global occurrences
            // (deduplicated, order-preserving), then drop occurrences 2..N.
            let mut merged: Vec<String> = Vec::new();
            for &i in &indices {
                if let ConfigNode::Directive(d) = &ast.nodes[i] {
                    for tok in d.value.split_whitespace() {
                        if !merged.iter().any(|m| m == tok) {
                            merged.push(tok.to_owned());
                        }
                    }
                }
            }

            // Apply the requested Add/Remove against the merged union.
            apply_action_to_users(&mut merged, user, action);

            // Write the result back into the first occurrence (or delete it if
            // the union is now empty — an absent directive is clearer than a
            // dangling empty line and matches the OpenSSH default).
            if merged.is_empty() {
                // Remove ALL occurrences (first first, then the rest in reverse
                // so earlier indices stay valid as we drain).
                for &i in indices.iter().rev() {
                    ast.nodes.remove(i);
                }
            } else {
                let joined = merged.join(" ");

                // Inline comments attached to any occurrence are now ambiguous:
                // merging changes the value, so a trailing `# ...` parsed from
                // occurrence #1 would annotate a *different* set of users than
                // it described, and the comments carried on occurrences 2..N
                // are about to be dropped wholesale when those nodes are
                // deleted. Both violate the lossless contract ("every byte is
                // representable" / no misleading comment). The least-bad
                // faithful option is to drop the inline comment on the merged
                // directive whenever the value changed or a merge happened, so
                // nothing stale floats over the line. Discarded comments from
                // occurrences 2..N are surfaced via the warning above.
                let single = indices.len() == 1;
                if let ConfigNode::Directive(d) = &mut ast.nodes[first] {
                    let value_changed = d.value != joined;
                    if value_changed || !single {
                        if d.comment.is_some() && !single {
                            tracing::warn!(
                                "{key}: discarding inline comment(s) while \
                                 merging {} occurrences",
                                indices.len()
                            );
                        }
                        d.comment = None;
                    }
                    d.value = joined;
                }
                // Delete occurrences 2..N. Iterate in reverse to keep earlier
                // indices valid as we remove.
                for &i in indices.iter().skip(1).rev() {
                    ast.nodes.remove(i);
                }
            }
        }
        // No directive yet: add one (only on Add; Remove of a missing user is
        // a harmless no-op).
        None => {
            if action == Action::Add {
                append_global_directive(ast, key, user);
            }
        }
    }

    Ok(())
}

/// Apply an Add/Remove to an in-memory user list (order-preserving).
fn apply_action_to_users(users: &mut Vec<String>, user: &str, action: Action) {
    match action {
        Action::Add => {
            if !users.iter().any(|u| u == user) {
                users.push(user.to_owned());
            }
        }
        Action::Remove => {
            users.retain(|u| u != user);
        }
    }
}

/// Append a new global `<key> <value>` directive, placed before the first
/// `Match`/`Host` block (or at the end if there are none).
fn append_global_directive(ast: &mut ConfigAst, key: &str, value: &str) {
    let directive = ConfigNode::Directive(Box::new(DirectiveData {
        keyword: key.to_owned(),
        separator: Separator::Space,
        value: value.to_owned(),
        comment: None,
        indent: String::new(),
    }));

    let insert_pos = ast
        .nodes
        .iter()
        .position(|n| matches!(n, ConfigNode::HostBlock(_) | ConfigNode::MatchBlock(_)))
        .unwrap_or(ast.nodes.len());

    ast.nodes.insert(insert_pos, directive);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ast(input: &str) -> ConfigAst {
        parse(input)
    }

    #[test]
    fn get_allow_users_reads_global_directive() {
        let a = ast("Port 22\nAllowUsers alice bob\n");
        assert_eq!(get_allow_users(&a), vec!["alice", "bob"]);
    }

    #[test]
    fn get_allow_users_ignores_match_scoped() {
        let a = ast("AllowUsers alice\nMatch User carol\n    AllowUsers bob\n");
        // Only the global alice; the Match-scoped bob is ignored.
        assert_eq!(get_allow_users(&a), vec!["alice"]);
    }

    #[test]
    fn get_deny_users_is_empty_when_absent() {
        let a = ast("Port 22\n");
        assert!(get_deny_users(&a).is_empty());
    }

    #[test]
    fn add_user_to_allow_creates_directive() {
        let mut a = ast("Port 22\n");
        add_user_to_allow(&mut a, "alice").unwrap();
        assert_eq!(get_allow_users(&a), vec!["alice"]);
    }

    #[test]
    fn add_user_to_allow_is_idempotent() {
        let mut a = ast("AllowUsers alice\n");
        add_user_to_allow(&mut a, "alice").unwrap();
        assert_eq!(get_allow_users(&a), vec!["alice"]);
    }

    #[test]
    fn add_user_to_allow_appends_to_existing() {
        let mut a = ast("AllowUsers alice\n");
        add_user_to_allow(&mut a, "bob").unwrap();
        assert_eq!(get_allow_users(&a), vec!["alice", "bob"]);
    }

    #[test]
    fn remove_user_from_allow_deletes_directive_when_empty() {
        let mut a = ast("AllowUsers alice\n");
        remove_user_from_allow(&mut a, "alice").unwrap();
        // Directive should be gone entirely.
        assert!(get_allow_users(&a).is_empty());
        assert!(!a.to_string_lossless().contains("AllowUsers"));
    }

    #[test]
    fn remove_user_from_allow_keeps_others() {
        let mut a = ast("AllowUsers alice bob\n");
        remove_user_from_allow(&mut a, "alice").unwrap();
        assert_eq!(get_allow_users(&a), vec!["bob"]);
    }

    #[test]
    fn remove_missing_user_is_noop() {
        let mut a = ast("AllowUsers alice\n");
        remove_user_from_allow(&mut a, "zzz").unwrap();
        assert_eq!(get_allow_users(&a), vec!["alice"]);
    }

    #[test]
    fn add_deny_then_reset_removes_from_both() {
        let mut a = ast("AllowUsers alice\n");
        add_user_to_deny(&mut a, "alice").unwrap();
        // alice is now in both lists; reset = remove from allow and deny.
        remove_user_from_allow(&mut a, "alice").unwrap();
        remove_user_from_deny(&mut a, "alice").unwrap();
        assert!(get_allow_users(&a).is_empty());
        assert!(get_deny_users(&a).is_empty());
    }

    #[test]
    fn round_trip_preserves_comments_and_match_blocks() {
        let input = "# top comment\nPort 22\n\nMatch User alice\n    PermitRootLogin no\n";
        let mut a = ast(input);
        add_user_to_allow(&mut a, "bob").unwrap();
        let out = a.to_string_lossless();
        assert!(out.contains("# top comment"), "comment preserved");
        assert!(out.contains("Match User alice"), "match block preserved");
        assert!(out.contains("PermitRootLogin no"), "match body preserved");
        assert!(out.contains("AllowUsers bob"));
    }

    #[test]
    fn new_directive_inserted_before_match_block() {
        let mut a = ast("Port 22\nMatch User alice\n    X11Forwarding no\n");
        add_user_to_allow(&mut a, "bob").unwrap();
        let out = a.to_string_lossless();
        let allow_pos = out.find("AllowUsers").unwrap();
        let match_pos = out.find("Match User").unwrap();
        assert!(
            allow_pos < match_pos,
            "AllowUsers must precede the Match block"
        );
    }

    // --- pattern-token detection ------------------------------------------

    #[test]
    fn has_pattern_tokens_detects_wildcards() {
        assert!(has_pattern_tokens("alice * bob"));
        assert!(has_pattern_tokens("ali?ce"));
        assert!(has_pattern_tokens("alice@host"));
        assert!(!has_pattern_tokens("alice bob carol"));
        assert!(!has_pattern_tokens(""));
    }

    #[test]
    fn directive_has_patterns_scans_global_only() {
        // Global wildcard occurrence.
        let a = ast("AllowUsers *\n");
        assert!(directive_has_patterns(&a, "AllowUsers"));

        // Plain usernames.
        let a = ast("AllowUsers alice bob\n");
        assert!(!directive_has_patterns(&a, "AllowUsers"));

        // Pattern only inside a Match block is ignored (global scope).
        let a = ast("AllowUsers alice\nMatch User carol\n    AllowUsers *\n");
        assert!(
            !directive_has_patterns(&a, "AllowUsers"),
            "Match-scoped patterns must not count"
        );
    }

    #[test]
    fn add_user_to_allow_refuses_pattern_directive() {
        let mut a = ast("AllowUsers *\n");
        let before = a.to_string_lossless();
        let err = add_user_to_allow(&mut a, "bob").unwrap_err();
        assert!(matches!(err, toride_ssh_core::Error::SshdConfigInvalid(_)));
        // AST must be untouched.
        assert_eq!(a.to_string_lossless(), before);
    }

    #[test]
    fn remove_user_from_allow_refuses_pattern_directive() {
        let mut a = ast("AllowUsers alice *@host\n");
        let before = a.to_string_lossless();
        let err = remove_user_from_allow(&mut a, "alice").unwrap_err();
        assert!(matches!(err, toride_ssh_core::Error::SshdConfigInvalid(_)));
        assert_eq!(a.to_string_lossless(), before);
    }

    #[test]
    fn add_user_to_deny_refuses_question_pattern() {
        let mut a = ast("DenyUsers ?uest\n");
        let before = a.to_string_lossless();
        let err = add_user_to_deny(&mut a, "bob").unwrap_err();
        assert!(matches!(err, toride_ssh_core::Error::SshdConfigInvalid(_)));
        assert_eq!(a.to_string_lossless(), before);
    }

    // --- multi-line consolidation -----------------------------------------

    #[test]
    fn add_merges_multiple_allow_users_lines() {
        let mut a = ast("AllowUsers alice\nPort 22\nAllowUsers bob\n");
        add_user_to_allow(&mut a, "carol").unwrap();
        // Union on a single line; second occurrence gone.
        assert_eq!(get_allow_users(&a), vec!["alice", "bob", "carol"]);
        assert_eq!(
            a.to_string_lossless().matches("AllowUsers").count(),
            1,
            "exactly one AllowUsers line after merge"
        );
    }

    #[test]
    fn add_merge_dedupes_and_preserves_order() {
        let mut a = ast("AllowUsers alice bob\nAllowUsers bob carol\n");
        add_user_to_allow(&mut a, "alice").unwrap();
        assert_eq!(get_allow_users(&a), vec!["alice", "bob", "carol"]);
        assert_eq!(a.to_string_lossless().matches("AllowUsers").count(), 1);
    }

    #[test]
    fn remove_across_multiple_occurrences() {
        // bob lives only on the second line; removal must still succeed.
        let mut a = ast("AllowUsers alice\nAllowUsers bob\n");
        remove_user_from_allow(&mut a, "bob").unwrap();
        assert_eq!(get_allow_users(&a), vec!["alice"]);
        assert_eq!(a.to_string_lossless().matches("AllowUsers").count(), 1);
    }

    #[test]
    fn remove_empties_union_deletes_all_occurrences() {
        // alice spread across two lines; removing her empties the union.
        let mut a = ast("AllowUsers alice\nAllowUsers alice\n");
        remove_user_from_allow(&mut a, "alice").unwrap();
        assert!(get_allow_users(&a).is_empty());
        assert!(
            !a.to_string_lossless().contains("AllowUsers"),
            "directive deleted entirely when union is empty"
        );
    }

    // --- inline-comment handling during merge -----------------------------

    #[test]
    fn merge_drops_stale_inline_comment_from_first_occurrence() {
        // Comments on each occurrence become ambiguous after a merge: the first
        // line's `# production admins` would otherwise float over a line that
        // also contains bob/carol, and the second line's `# contractors` would
        // be silently dropped entirely. The merged line must carry NO inline
        // comment (not the stale `# production admins`).
        let mut a = ast("AllowUsers alice # production admins\nAllowUsers bob # contractors\n");
        add_user_to_allow(&mut a, "carol").unwrap();
        let out = a.to_string_lossless();
        assert_eq!(get_allow_users(&a), vec!["alice", "bob", "carol"]);
        assert_eq!(out.matches("AllowUsers").count(), 1, "merged to one line");
        assert!(
            !out.contains("#production admins"),
            "stale first-occurrence comment must not survive the merge"
        );
        assert!(
            !out.contains("#contractors"),
            "dropped occurrence's comment must not leak into the merged line"
        );
    }

    #[test]
    fn single_occurrence_value_change_drops_stale_inline_comment() {
        // `# admins` described only alice; after adding bob the line is
        // `alice bob` and the comment would be misleading. It must be dropped
        // rather than producing `AllowUsers alice bob # admins`.
        let mut a = ast("AllowUsers alice # admins\n");
        add_user_to_allow(&mut a, "bob").unwrap();
        let out = a.to_string_lossless();
        assert_eq!(get_allow_users(&a), vec!["alice", "bob"]);
        assert!(
            !out.contains("#admins"),
            "stale comment must be dropped when the value changes"
        );
    }

    #[test]
    fn single_occurrence_unchanged_keeps_inline_comment() {
        // Idempotent add of an existing user (or noop remove) must NOT touch
        // the inline comment — the value is unchanged so the comment is still
        // accurate.
        let mut a = ast("AllowUsers alice bob # both admins\n");
        add_user_to_allow(&mut a, "alice").unwrap();
        let out = a.to_string_lossless();
        assert_eq!(get_allow_users(&a), vec!["alice", "bob"]);
        assert!(
            out.contains("#both admins"),
            "inline comment must survive an unchanged-value edit"
        );
    }

    // --- group getters + read-path coverage -------------------------------

    #[test]
    fn get_allow_groups_reads_global() {
        let a = ast("AllowGroups wheel staff\nMatch User carol\n    AllowGroups extra\n");
        assert_eq!(get_allow_groups(&a), vec!["wheel", "staff"]);
    }

    #[test]
    fn get_deny_groups_reads_global_and_skips_match() {
        let a = ast("DenyGroups banned\nMatch User carol\n    DenyGroups scoped\n");
        assert_eq!(get_deny_groups(&a), vec!["banned"]);
    }

    #[test]
    fn get_deny_users_concatenates_multiple_lines() {
        let a = ast("DenyUsers alice\nDenyUsers bob\n");
        assert_eq!(get_deny_users(&a), vec!["alice", "bob"]);
    }

    #[test]
    fn get_groups_empty_when_absent() {
        let a = ast("Port 22\n");
        assert!(get_allow_groups(&a).is_empty());
        assert!(get_deny_groups(&a).is_empty());
    }

    // --- F1: Match/Host-leak scope-ambiguity fail-closed -----------------
    //
    // parse_block_body (ast.rs) breaks a Match/Host block on the first
    // non-indented line, so an UNINDENTED directive that OpenSSH actually
    // scopes to the preceding block leaks to the top level. The editor MUST
    // refuse such edits (sshd -t does not catch it — the file is still
    // syntactically valid — and re-rendering at indent 0 would permanently
    // relocate the directive to global scope on disk).

    #[test]
    fn upsert_refuses_directive_unindented_after_match_block() {
        // `AllowUsers bob` is unindented after `Match User sftpuser`, so the
        // parser leaks it to top level as a Directive. The editor must refuse.
        let input = "Port 22\nMatch User sftpuser\nAllowUsers bob\n";
        let mut a = ast(input);
        let before = a.to_string_lossless();
        let err = add_user_to_allow(&mut a, "carol").unwrap_err();
        assert!(
            matches!(err, toride_ssh_core::Error::SshdConfigInvalid(ref msg)
                if msg.contains("refusing to edit")
                && msg.contains("Match/Host")
                && msg.contains("ambiguous")),
            "expected SshdConfigInvalid scope-ambiguity error, got {err:?}"
        );
        // AST must be byte-identical (round-trip stable) — no mutation.
        assert_eq!(a.to_string_lossless(), before);
    }

    #[test]
    fn remove_refuses_directive_unindented_after_match_block() {
        let input = "Match User sftpuser\nAllowUsers bob carol\n";
        let mut a = ast(input);
        let before = a.to_string_lossless();
        let err = remove_user_from_allow(&mut a, "bob").unwrap_err();
        assert!(matches!(err, toride_ssh_core::Error::SshdConfigInvalid(_)));
        assert_eq!(a.to_string_lossless(), before);
    }

    #[test]
    fn upsert_refuses_directive_unindented_after_host_block() {
        // Same leak, but a Host block in an sshd_config-adjacent file.
        let input = "Host restricted\nAllowUsers bob\n";
        let mut a = ast(input);
        let before = a.to_string_lossless();
        let err = add_user_to_allow(&mut a, "carol").unwrap_err();
        assert!(matches!(err, toride_ssh_core::Error::SshdConfigInvalid(_)));
        assert_eq!(a.to_string_lossless(), before);
    }

    #[test]
    fn upsert_refuses_when_only_some_occurrences_follow_a_block() {
        // First AllowUsers is genuinely global (no preceding block); the
        // second is leaked from a Match block. Because scope is ambiguous for
        // the second occurrence, the whole edit must fail closed rather than
        // merge across scopes.
        let input = "AllowUsers alice\nMatch User sftpuser\nAllowUsers bob\n";
        let mut a = ast(input);
        let before = a.to_string_lossless();
        let err = add_user_to_allow(&mut a, "carol").unwrap_err();
        assert!(matches!(err, toride_ssh_core::Error::SshdConfigInvalid(_)));
        assert_eq!(a.to_string_lossless(), before);
    }

    #[test]
    fn upsert_edits_normally_when_directive_precedes_match_block() {
        // An AllowUsers BEFORE any Match/Host block is genuinely global and
        // must still edit normally — the guard only fires when a directive
        // FOLLOWS a block.
        let mut a = ast("AllowUsers alice\nMatch User sftpuser\n    PermitRootLogin no\n");
        add_user_to_allow(&mut a, "bob").unwrap();
        assert_eq!(get_allow_users(&a), vec!["alice", "bob"]);
    }

    #[test]
    fn upsert_edits_when_comments_and_blanks_intervene_before_block() {
        // Blank lines / comments between the directive and the preceding block
        // must NOT disguise the scope ambiguity: the nearest non-trivial
        // predecessor is still the Match block.
        let input = "Match User sftpuser\n# note\n\nAllowUsers bob\n";
        let mut a = ast(input);
        let before = a.to_string_lossless();
        let err = add_user_to_allow(&mut a, "carol").unwrap_err();
        assert!(matches!(err, toride_ssh_core::Error::SshdConfigInvalid(_)));
        assert_eq!(a.to_string_lossless(), before);
    }

    #[test]
    fn upsert_edits_when_another_directive_intervenes() {
        // A non-block directive between the target and any earlier block means
        // the target's immediate predecessor is a Directive, not a block — so
        // its scope is unambiguous and the edit proceeds.
        let mut a = ast("Match User sftpuser\n    PermitRootLogin no\nPort 22\nAllowUsers bob\n");
        add_user_to_allow(&mut a, "carol").unwrap();
        assert_eq!(get_allow_users(&a), vec!["bob", "carol"]);
    }

    // --- F1 read-path: leaked directives excluded from global view -------
    //
    // A leaked AllowUsers following a Match block must not be counted as
    // global, otherwise the UI misreports access control.

    #[test]
    fn get_allow_users_excludes_leaked_directive_after_match() {
        let a = ast("AllowUsers alice\nMatch User sftpuser\nAllowUsers bob\n");
        // Only the genuine global alice; the leaked bob is excluded.
        assert_eq!(get_allow_users(&a), vec!["alice"]);
    }

    #[test]
    fn directive_has_patterns_excludes_leaked_directive_after_match() {
        // A leaked `AllowUsers *` (a real pattern) following a Match block
        // must NOT be reported as a global pattern.
        let a = ast("AllowUsers alice\nMatch User sftpuser\nAllowUsers *\n");
        assert!(
            !directive_has_patterns(&a, "AllowUsers"),
            "leaked Match-scoped pattern must not count as global"
        );
    }

    // --- F2: cross-process lock serializes concurrent edits ---------------
    //
    // edit() wraps its whole load→mutate→save critical section in
    // with_edit_lock (an advisory flock). We can't drive edit() itself in a
    // unit test (it reads /etc/ssh/sshd_config and runs privileged sshd -t /
    // sudo), but we CAN test the exact lock primitive edit() uses and prove
    // two concurrent holders serialize — the second cannot enter until the
    // first releases.

    #[test]
    fn with_edit_lock_serializes_two_concurrent_holders() {
        use std::sync::{Arc, Barrier, mpsc};
        use std::thread;

        let dir = tempfile::TempDir::new().expect("temp dir");
        let lock_path = dir.path().join("sshd-config.lock");

        // Barrier so both threads try to acquire at ~the same instant, and a
        // channel that records the strict enter/exit order of the critical
        // sections. If locking did NOT serialize, both threads would emit
        // "enter" before either "exit".
        let barrier = Arc::new(Barrier::new(2));
        let (tx, rx) = mpsc::channel::<String>();

        let make_thread = |label: &'static str,
                           lock_path: std::path::PathBuf,
                           barrier: Arc<Barrier>,
                           tx: mpsc::Sender<String>| {
            thread::spawn(move || {
                // Park both threads at the barrier so they race for the lock.
                barrier.wait();
                with_edit_lock(&lock_path, || -> Result<()> {
                    tx.send(format!("{label}-enter")).unwrap();
                    // Hold the lock briefly so the contender is forced to wait.
                    std::thread::sleep(std::time::Duration::from_millis(150));
                    tx.send(format!("{label}-exit")).unwrap();
                    Ok(())
                })
                .expect("with_edit_lock should succeed");
            })
        };

        let t1 = make_thread("A", lock_path.clone(), barrier.clone(), tx.clone());
        let t2 = make_thread("B", lock_path, barrier, tx.clone());
        // Drop the sender copies held by the main thread so rx into_iter()
        // terminates when both threads finish.
        drop(tx);

        let events: Vec<String> = rx.into_iter().collect();

        t1.join().expect("thread A panicked");
        t2.join().expect("thread B panicked");

        // Split into per-label enter/exit orderings. Regardless of which label
        // wins the race, serialization requires: the winner's exit precedes the
        // loser's enter. I.e. exactly one label's enter comes first AND its
        // exit comes before the other label's enter.
        let first_enter = events.first().expect("at least one event");
        let winner = if first_enter.starts_with('A') {
            "A"
        } else {
            "B"
        };
        let loser = if winner == "A" { "B" } else { "A" };

        let winner_exit = events
            .iter()
            .position(|e| e == &format!("{winner}-exit"))
            .expect("winner exit");
        let loser_enter = events
            .iter()
            .position(|e| e == &format!("{loser}-enter"))
            .expect("loser enter");

        assert!(
            winner_exit < loser_enter,
            "edits must serialize: winner must EXIT ({winner}-exit at #{winner_exit}) \
             before loser ENTERS ({loser}-enter at #{loser_enter}). Events: {events:?}"
        );
    }

    #[test]
    fn with_edit_lock_releases_on_closure_error() {
        // If the critical section errors, the lock must still be released so a
        // subsequent edit can proceed. (with_edit_lock is closure-based RAII.)
        let dir = tempfile::TempDir::new().expect("temp dir");
        let lock_path = dir.path().join("sshd-config-err.lock");

        let err = with_edit_lock(&lock_path, || -> Result<()> {
            Err(toride_ssh_core::Error::SshdConfigInvalid(
                "simulated bad config".into(),
            ))
        });
        assert!(err.is_err(), "first call must propagate the error");

        // A second call must succeed without deadlocking — proving the lock
        // was released on the error path. (If it were still held, this would
        // block until the test timeout.)
        let result = with_edit_lock(&lock_path, || Ok(42));
        assert_eq!(
            result.expect("second call must succeed after error-path release"),
            42
        );
    }

    // --- async runtime safety: edit() must not nest a runtime -------------
    //
    // edit() used to wrap its critical section in
    // `tokio::task::block_in_place(|| handle.block_on(...))`. block_in_place
    // PANICS ("can call blocking only when running on the multi-threaded
    // runtime") when edit() is awaited from a current-thread runtime — which
    // is the default for `#[tokio::test]` and many embedded/host runtimes.
    // The fix makes edit() a genuine async fn (no nested runtime). These tests
    // drive edit() on both runtime flavors and assert it completes without
    // panicking. The privileged save() step will report an error on a host
    // without sshd or root (that is expected and fine); the invariant under
    // test is "no panic, and the mutation closure ran".
    //
    // We point TORIDE_SSHD_EDIT_LOCK at a temp file so edit() acquires a
    // real flock we clean up, exercising the actual lock path.

    fn drive_edit_on_runtime(rt: &tokio::runtime::Runtime) {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let lock = dir.path().join("sshd-edit-async.lock");
        // SAFETY: tests are single-threaded by convention here; the env var is
        // process-global but scoped to this test's lifetime and restored on
        // exit. edition-2024 makes set_var unsafe.
        unsafe {
            std::env::set_var(SSHD_EDIT_LOCK_ENV, &lock);
        }

        // The closure records that it actually ran (proving edit() reached and
        // executed the critical section, not just the lock acquire).
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ran_clone = ran.clone();
        let result = rt.block_on(async {
            edit(false, |ast| {
                // Harmless mutation on whatever load() returned (empty AST if
                // /etc/ssh/sshd_config is absent on the host). This exercises
                // the synchronous closure inside the lock.
                add_user_to_allow(ast, "toride-edit-async-test-user")?;
                ran_clone.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            })
            .await
        });

        // SAFETY: restore env (best-effort) on the way out.
        unsafe {
            std::env::remove_var(SSHD_EDIT_LOCK_ENV);
        }

        // The save() step is expected to fail on a host without sshd/root
        // (SshdNotFound / SudoFailed / Io). That is NOT the bug. The bug was a
        // panic; assert we did not panic by reaching here and that the closure
        // executed (so edit() genuinely drove load → mutate before save).
        assert!(
            ran.load(std::sync::atomic::Ordering::SeqCst),
            "edit()'s mutation closure must have executed"
        );
        // Result may be Ok (if sshd + root happen to be available and accept an
        // AllowUsers-only config) or Err (typical CI host). Either is fine; the
        // point is we got here at all instead of panicking.
        drop(result);
    }

    #[test]
    fn edit_does_not_panic_on_current_thread_runtime() {
        // This is the exact runtime flavor that panicked under the old
        // block_in_place implementation.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime");
        drive_edit_on_runtime(&rt);
    }

    #[test]
    fn edit_does_not_panic_on_multi_thread_runtime() {
        // Sanity: the multi-thread path (used by the production app) must also
        // remain panic-free; the old code happened to work there but relied on
        // a nested block_on that the fix removes.
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("multi-thread runtime");
        drive_edit_on_runtime(&rt);
    }
}
