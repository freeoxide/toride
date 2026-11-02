//! Single cross-module lock serializing every test that mutates a
//! process-global env var (`HOME`, `TORIDE_LOG_FILE`, ...), so parallel
//! `#[test]` threads in this crate cannot observe another test's env.

/// Acquire the lock from a sync (`#[test]`) context.
///
/// # Panics
///
/// Panics when called from inside a tokio runtime; async tests must use
/// [`lock_async`] instead.
pub(crate) fn lock_blocking() -> tokio::sync::MutexGuard<'static, ()> {
    ENV_LOCK.blocking_lock()
}

/// Acquire the lock from an async (`#[tokio::test]`) context; the guard may
/// be held across `.await` points.
pub(crate) async fn lock_async() -> tokio::sync::MutexGuard<'static, ()> {
    ENV_LOCK.lock().await
}

static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
