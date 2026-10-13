//! Process-wide memoization of SSH config reads and parses, keyed by the
//! file's `(mtime, len)` stamp; an unmeasurable mtime bypasses the cache.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::time::UNIX_EPOCH;

use crate::ast;

struct CachedConfig {
    stamp: FileStamp,
    content: Arc<String>,
    ast: Option<Arc<ast::ConfigAst>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct FileStamp {
    mtime_ns: u128,
    len: u64,
}

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

static CONFIG_CACHE: LazyLock<Mutex<HashMap<PathBuf, CachedConfig>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Upper bound on cached entries. A full cache evicts an arbitrary entry
/// before inserting so deleted or renamed config files cannot grow the
/// process-wide cache without limit.
const CONFIG_CACHE_CAP: usize = 256;

/// Insert an entry, evicting an arbitrary victim first when at capacity.
fn insert_bounded(cache: &mut HashMap<PathBuf, CachedConfig>, path: &Path, entry: CachedConfig) {
    if cache.len() >= CONFIG_CACHE_CAP
        && let Some(victim) = cache.keys().next().cloned()
    {
        cache.remove(&victim);
    }
    cache.insert(path.to_path_buf(), entry);
}

enum Probe {
    Parsed(Arc<ast::ConfigAst>),
    Content(Arc<String>),
}

/// Read and parse the config at `path`, memoized on its `(mtime, len)` stamp.
///
/// # Errors
/// As `std::fs::metadata` / `std::fs::read_to_string` on the underlying
/// file. A `NotFound` metadata error also drops any stale entry for the
/// path.
///
/// # Panics
/// Only if the cache mutex is poisoned.
pub fn load_cached_ast(path: &Path) -> std::io::Result<Arc<ast::ConfigAst>> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                CONFIG_CACHE
                    .lock()
                    .expect("config cache mutex poisoned")
                    .remove(path);
            }
            return Err(e);
        }
    };
    let Some(stamp) = stamp_of(&metadata) else {
        return Ok(Arc::new(read_and_parse(path)?));
    };

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
    let mut cache = CONFIG_CACHE.lock().expect("config cache mutex poisoned");
    insert_bounded(
        &mut cache,
        path,
        CachedConfig {
            stamp,
            content: Arc::clone(&content),
            ast: Some(Arc::clone(&ast)),
        },
    );
    Ok(ast)
}

/// Read the config at `path` as raw content, memoized on its `(mtime, len)`
/// stamp.
///
/// # Errors
/// As `std::fs::metadata` / `std::fs::read_to_string` on the underlying
/// file.
///
/// # Panics
/// Only if the cache mutex is poisoned.
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
    let mut cache = CONFIG_CACHE.lock().expect("config cache mutex poisoned");
    insert_bounded(
        &mut cache,
        path,
        CachedConfig {
            stamp,
            content: Arc::clone(&content),
            ast: None,
        },
    );
    Ok(content)
}

fn read_and_parse(path: &Path) -> std::io::Result<ast::ConfigAst> {
    let content = std::fs::read_to_string(path)?;
    Ok(ast::parse(&content))
}

#[cfg(test)]
pub(crate) fn clear_cache_for_tests(path: &Path) {
    CONFIG_CACHE
        .lock()
        .expect("config cache mutex poisoned")
        .remove(path);
}

#[cfg(test)]
pub(crate) fn clear_all_cache_for_tests() {
    CONFIG_CACHE
        .lock()
        .expect("config cache mutex poisoned")
        .clear();
}

#[cfg(test)]
pub(crate) fn cache_len_for_tests() -> usize {
    CONFIG_CACHE
        .lock()
        .expect("config cache mutex poisoned")
        .len()
}

#[cfg(test)]
pub(crate) fn cache_contains_for_tests(path: &Path) -> bool {
    CONFIG_CACHE
        .lock()
        .expect("config cache mutex poisoned")
        .contains_key(path)
}

#[cfg(test)]
#[path = "cache.test.rs"]
mod tests;
