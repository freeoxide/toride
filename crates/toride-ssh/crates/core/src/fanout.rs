//! Bounded-concurrency fan-out over an iterator of futures.
//!
//! Every subsystem that spawns one subprocess per candidate (remote doctor
//! checks, `ssh -O check` sweeps) funnels through [`join_all_bounded`] so the
//! process-wide cap on concurrent ssh handshakes is expressed in one place.

/// Run every future in `futs` concurrently, holding at most `limit` in
/// flight, and return the results in input order.
///
/// One future failing (or panicking into an `Err`) never cancels its
/// siblings; callers zip the results against their inputs by position.
pub async fn join_all_bounded<I, T>(limit: usize, futs: I) -> Vec<T>
where
    I: IntoIterator,
    I::Item: std::future::Future<Output = T>,
{
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(limit));
    let guarded = futs.into_iter().map(|fut| {
        let semaphore = std::sync::Arc::clone(&semaphore);
        async move {
            let _permit = semaphore.acquire_owned().await.ok();
            fut.await
        }
    });
    futures::future::join_all(guarded).await
}
