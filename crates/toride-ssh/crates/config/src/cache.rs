//! Process-wide, mtime-keyed memoization of SSH config reads and parses.
//!
//! Several subsystems read `~/.ssh/config` in the same collection pass —
//! the config tab ([`crate::ConfigService::load`]), the key inventory's
//! `IdentityFile` scan, and the doctor checks — so an unchanged config was
//! being re-read and re-parsed up to thirteen times per pass. Reading and
//! parsing are pure functions of the file bytes, so both the raw content
//! and the parsed AST are memoized per path: an unchanged config costs one
//! read plus one parse per process, shared by every consumer.
//!
//! Invalidation is **content-keyed via the file's `(mtime, len)` stamp**,
//! never a TTL: any write that changes the file length or its modification
//! time (including every atomic temp-file + rename this crate performs on
//! save) misses the cache and re-reads. If the modification time cannot be
//! determined the cache is bypassed entirely so an unmeasurable file is
//! never served stale.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::time::UNIX_EPOCH;

use crate::ast;

/// A cache entry: the stamp the content was read at, the shared content,
/// and the AST parsed from it (filled on the first AST consumer).
struct CachedConfig {
    /// `(mtime_ns, len)` of the file when it was read.
    stamp: FileStamp,
    /// The raw file content shared by every consumer (raw readers and the
    /// lazy AST parse alike).
    content: Arc<String>,
    /// The parsed AST, parsed once from `content` on first demand.
    ast: Option<Arc<ast::ConfigAst>>,
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

/// Memoized reads/parses, keyed by config path.
static CONFIG_CACHE: LazyLock<Mutex<HashMap<PathBuf, CachedConfig>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Outcome of a stamp-matched cache probe in [`load_cached_ast`].
enum Probe {
    /// The AST is already parsed for this stamp.
    Parsed(Arc<ast::ConfigAst>),
    /// Only the raw content is memoized; parse these cached bytes.
    Content(Arc<String>),
}

/// Read and parse the SSH config at `path`, memoized on the file's
/// `(mtime, len)` stamp.
///
/// Concurrent callers for the same unchanged file share one
/// [`Arc<ast::ConfigAst>`]; a changed file re-reads and re-parses. If only
/// the raw content was memoized so far (see [`load_cached_content`]), the
/// AST is parsed from those already-cached bytes — no second read.
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
        return Ok(Arc::new(read_and_parse(path)?));
    };

    // Probe under the lock, then act with the lock released so it is never
    // held across a parse or any I/O.
    let probe = {
        let cache = CONFIG_CACHE.lock().expect("config cache mutex poisoned");
        cache
            .get(path)
            .filter(|entry| entry.stamp == stamp)
            .map(|entry| match &entry.ast {
                Some(ast) => Probe::Parsed(Arc::clone(ast)),
                None => Probe::Content(Arc::clone(&entry.content)),
            })
    };
    match probe {
        Some(Probe::Parsed(ast)) => return Ok(ast),
        Some(Probe::Content(content)) => {
            let ast = Arc::new(ast::parse(&content));
            // Re-check the stamp before filling: another thread may have
            // replaced the entry while the lock was released.
            if let Some(entry) = CONFIG_CACHE
                .lock()
                .expect("config cache mutex poisoned")
                .get_mut(path)
                && entry.stamp == stamp
            {
                entry.ast = Some(Arc::clone(&ast));
            }
            return Ok(ast);
        }
        None => {}
    }

    let content = Arc::new(std::fs::read_to_string(path)?);
    let ast = Arc::new(ast::parse(&content));
    CONFIG_CACHE
        .lock()
        .expect("config cache mutex poisoned")
        .insert(
            path.to_path_buf(),
            CachedConfig {
                stamp,
                content: Arc::clone(&content),
                ast: Some(Arc::clone(&ast)),
            },
        );
    Ok(ast)
}

/// Read the SSH config at `path` as raw content, memoized on the file's
/// `(mtime, len)` stamp.
///
/// For consumers that scan raw lines rather than the AST (e.g. the
/// doctor's `VerifyHostKeyDNS` line scan): an unchanged file is served
/// from the cache, and a later [`load_cached_ast`] for the same stamp
/// parses the very same shared content — the file is read at most once
/// per mutation however it is consumed.
///
/// # Errors
///
/// Error semantics match `std::fs::read_to_string`: a missing or unreadable
/// file returns `Err(io::Error)` with the same `ErrorKind`.
///
/// # Panics
///
/// Panics if the internal cache mutex is poisoned (a prior holder panicked
/// while holding it); the cache is process-local so this is unrecoverable.
pub fn load_cached_content(path: &Path) -> std::io::Result<Arc<String>> {
    let metadata = std::fs::metadata(path)?;
    let Some(stamp) = stamp_of(&metadata) else {
        return Ok(Arc::new(std::fs::read_to_string(path)?));
    };

    {
        let cache = CONFIG_CACHE.lock().expect("config cache mutex poisoned");
        if let Some(entry) = cache.get(path)
            && entry.stamp == stamp
        {
            return Ok(Arc::clone(&entry.content));
        }
    }

    let content = Arc::new(std::fs::read_to_string(path)?);
    CONFIG_CACHE
        .lock()
        .expect("config cache mutex poisoned")
        .insert(
            path.to_path_buf(),
            CachedConfig {
                stamp,
                content: Arc::clone(&content),
                ast: None,
            },
        );
    Ok(content)
}

/// Read the file and parse it into an AST (cache-bypass path only).
fn read_and_parse(path: &Path) -> std::io::Result<ast::ConfigAst> {
    let content = std::fs::read_to_string(path)?;
    Ok(ast::parse(&content))
}

/// Drop every cached read/parse. Test hook: benchmark and unit tests need a
/// clean cache so a previous test's entry for the same path cannot serve as
/// a hit.
#[cfg(test)]
pub(crate) fn clear_cache_for_tests() {
    CONFIG_CACHE
        .lock()
        .expect("config cache mutex poisoned")
        .clear();
}

#[cfg(test)]
#[path = "cache.test.rs"]
mod tests;
