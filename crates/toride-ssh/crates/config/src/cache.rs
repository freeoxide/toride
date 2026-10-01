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

enum Probe {
    Parsed(Arc<ast::ConfigAst>),
    Content(Arc<String>),
}

/// Read and parse the config at `path`, memoized on its `(mtime, len)` stamp.
///
/// # Errors
/// As `std::fs::metadata` / `std::fs::read_to_string` on the underlying file.
///
/// # Panics
/// Only if the cache mutex is poisoned.
pub fn load_cached_ast(path: &Path) -> std::io::Result<Arc<ast::ConfigAst>> {
    let metadata = std::fs::metadata(path)?;
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

/// Read the config at `path` as raw content, memoized on its `(mtime, len)`
/// stamp.
///
/// # Errors
/// As `std::fs::metadata` / `std::fs::read_to_string` on the underlying file.
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
#[path = "cache.test.rs"]
mod tests;
