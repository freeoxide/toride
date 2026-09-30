//! Process-wide, mtime-keyed memoization of parsed SSH config ASTs.
//!
//! Several subsystems read and parse `~/.ssh/config` in the same collection
//! pass — the config tab ([`crate::ConfigService::load`]), the key
//! inventory's `IdentityFile` scan, and eleven doctor checks — so an
//! unchanged config was being re-parsed up to thirteen times per pass.
//! Parsing is a pure function of the file bytes, so the parsed AST is
//! memoized per path.
//!
//! Invalidation is **content-keyed via the file's `(mtime, len)` stamp**,
//! never a TTL: any write that changes the file length or its modification
//! time (including every atomic temp-file + rename this crate performs on
//! save) misses the cache and re-parses. If the modification time cannot be
//! determined the cache is bypassed entirely so an unmeasurable file is
//! never served stale.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::time::UNIX_EPOCH;

use crate::ast;

/// A cache entry: the stamp the AST was parsed at, plus the shared AST.
struct CachedAst {
    /// `(mtime_ns, len)` of the file when it was parsed.
    stamp: FileStamp,
    /// The parsed AST shared by every consumer.
    ast: Arc<ast::ConfigAst>,
}

/// Freshness stamp for a config file: nanosecond mtime plus length.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct FileStamp {
    /// Nanoseconds since the Unix epoch of the last modification.
    mtime_ns: u128,
    /// File length in bytes.
    len: u64,
}

/// Compute a file's freshness stamp, or `None` when the modification time is
/// unavailable (cache bypassed for such files).
fn stamp_of(metadata: &std::fs::Metadata) -> Option<FileStamp> {
    let mtime_ns = metadata
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_nanos();
    Some(FileStamp {
        mtime_ns,
        len: metadata.len(),
    })
}

/// Memoized parse results, keyed by config path.
static AST_CACHE: LazyLock<Mutex<HashMap<PathBuf, CachedAst>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Read and parse the SSH config at `path`, memoized on the file's
/// `(mtime, len)` stamp.
///
/// Concurrent callers for the same unchanged file share one
/// [`Arc<ast::ConfigAst>`]; a changed file re-parses.
///
/// The cache is process-wide and grows with the set of distinct config
/// paths parsed during the process lifetime (entries are small and keyed by
/// path); within the TUI that set is a single `~/.ssh/config`.
///
/// # Errors
///
/// Error semantics match `std::fs::read_to_string`: a missing or unreadable
/// file returns `Err(io::Error)` with the same `ErrorKind`, so callers can
/// keep using their existing "config absent" branches unchanged.
///
/// # Panics
///
/// Panics if the internal cache mutex is poisoned (a prior holder panicked
/// while holding it); the cache is process-local so this is unrecoverable.
pub fn load_cached_ast(path: &Path) -> std::io::Result<Arc<ast::ConfigAst>> {
    let metadata = std::fs::metadata(path)?;
    // An unmeasurable mtime must never be cached: the stamp could collide
    // across different contents.
    let Some(stamp) = stamp_of(&metadata) else {
        return read_and_parse(path).map(Arc::new);
    };

    {
        let cache = AST_CACHE.lock().expect("config AST cache mutex poisoned");
        if let Some(entry) = cache.get(path)
            && entry.stamp == stamp
        {
            return Ok(Arc::clone(&entry.ast));
        }
    }

    let ast = Arc::new(read_and_parse(path)?);
    AST_CACHE
        .lock()
        .expect("config AST cache mutex poisoned")
        .insert(
            path.to_path_buf(),
            CachedAst {
                stamp,
                ast: Arc::clone(&ast),
            },
        );
    Ok(ast)
}

/// Read the file and parse it into an AST.
fn read_and_parse(path: &Path) -> std::io::Result<ast::ConfigAst> {
    let content = std::fs::read_to_string(path)?;
    Ok(ast::parse(&content))
}

/// Drop every cached AST. Test hook: benchmark and unit tests need a clean
/// cache so a previous test's entry for the same path cannot serve as a hit.
#[cfg(test)]
pub(crate) fn clear_cache_for_tests() {
    AST_CACHE
        .lock()
        .expect("config AST cache mutex poisoned")
        .clear();
}

#[cfg(test)]
#[path = "cache.test.rs"]
mod tests;
