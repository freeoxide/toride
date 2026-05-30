//! Collector for periodic status snapshots and delta computation.
//!
//! [`Collector`] manages periodic collection of system status and
//! computes deltas between consecutive snapshots for rate-based metrics.
//!
//! # Delta computation
//!
//! When two consecutive snapshots are taken, [`SystemDelta`] computes:
//! - **CPU usage delta**: the change in CPU percentage between snapshots.
//! - **Network byte deltas**: the number of bytes received/transmitted
//!   since the last snapshot.
//! - **Network rates**: bytes per second, calculated as
//!   `delta_bytes / elapsed_seconds`.
//!
//! The first call to [`Collector::collect`] always returns `None` for the
//! delta because there is no previous snapshot to compare against.
//!
//! # Examples
//!
//! Periodic collection with delta tracking:
//!
//! ```no_run
//! use std::time::Duration;
//! use toride::status::collector::Collector;
//! use toride::status::presets::Preset;
//!
//! let mut collector = Collector::new(Duration::from_secs(1), Preset::Diagnostics);
//!
//! // First call: no delta available.
//! let (status, delta) = collector.collect();
//! assert!(delta.is_none());
//!
//! // Second call: delta computed from previous snapshot.
//! std::thread::sleep(Duration::from_secs(1));
//! let (status, delta) = collector.collect();
//! if let Some(d) = delta {
//!     println!("Network RX rate: {:.1} B/s", d.bytes_received_rate);
//! }
//! ```
//!
//! Blocking collection that waits for the interval:
//!
//! ```no_run
//! use std::time::Duration;
//! use toride::status::collector::Collector;
//!
//! let mut collector = Collector::default_collector();
//! loop {
//!     let (status, delta) = collector.collect_after_interval();
//!     // Process status and delta...
//!     break; // Remove this in real usage
//! }
//! ```

use std::time::{Duration, Instant};

use serde::Serialize;

use crate::status::presets::Preset;
use crate::status::system::SystemStatus;
use crate::status::TorideStatus;

/// Collector for periodic status snapshots.
pub struct Collector {
    interval: Duration,
    preset: Preset,
    previous: Option<(Instant, SystemStatus)>,
}

/// Delta between two system snapshots, used for rate calculations.
///
/// Computed by [`Collector::collect`] when a previous snapshot exists.
/// Contains both absolute deltas (bytes received/transmitted) and
/// per-second rates for network I/O.
///
/// # Examples
///
/// ```no_run
/// use std::time::Duration;
/// use toride::status::collector::Collector;
///
/// let mut collector = Collector::default_collector();
/// collector.collect(); // First call, no delta.
/// std::thread::sleep(Duration::from_secs(1));
/// let (_, delta) = collector.collect();
///
/// if let Some(d) = delta {
///     println!("Elapsed: {:.2?}", d.elapsed);
///     println!("RX rate: {:.1} B/s", d.bytes_received_rate);
///     println!("TX rate: {:.1} B/s", d.bytes_transmitted_rate);
///     if let Some(cpu_delta) = d.cpu_usage_delta {
///         println!("CPU delta: {cpu_delta:+.1}%");
///     }
/// }
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct SystemDelta {
    /// Time elapsed between snapshots.
    pub elapsed: Duration,
    /// CPU usage change.
    pub cpu_usage_delta: Option<f64>,
    /// Network bytes received since last snapshot.
    pub bytes_received_delta: u64,
    /// Network bytes transmitted since last snapshot.
    pub bytes_transmitted_delta: u64,
    /// Network bytes received per second.
    pub bytes_received_rate: f64,
    /// Network bytes transmitted per second.
    pub bytes_transmitted_rate: f64,
}

impl Collector {
    /// Create a new collector with the given interval and preset.
    ///
    /// The `interval` determines the minimum time between snapshots when
    /// using [`collect_after_interval`](Self::collect_after_interval).
    /// The `preset` controls which metrics are included in each snapshot.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// use toride::status::collector::Collector;
    /// use toride::status::presets::Preset;
    ///
    /// let collector = Collector::new(Duration::from_secs(5), Preset::Minimal);
    /// assert_eq!(collector.interval(), Duration::from_secs(5));
    /// assert_eq!(collector.preset(), Preset::Minimal);
    /// ```
    #[must_use]
    pub const fn new(interval: Duration, preset: Preset) -> Self {
        Self {
            interval,
            preset,
            previous: None,
        }
    }

    /// Create a collector with default settings (1 second interval, Diagnostics preset).
    ///
    /// This is a convenience constructor equivalent to:
    /// ```ignore
    /// Collector::new(Duration::from_secs(1), Preset::Diagnostics)
    /// ```
    ///
    /// # Examples
    ///
    /// ```
    /// use toride::status::collector::Collector;
    ///
    /// let collector = Collector::default_collector();
    /// ```
    #[must_use]
    pub fn default_collector() -> Self {
        Self::new(Duration::from_secs(1), Preset::default())
    }

    /// Get the collection interval.
    #[must_use]
    pub const fn interval(&self) -> Duration {
        self.interval
    }

    /// Get the current preset.
    #[must_use]
    pub const fn preset(&self) -> Preset {
        self.preset
    }

    /// Collect a snapshot and compute delta from the previous one.
    ///
    /// On the first call, returns `None` for the delta because there is
    /// no previous snapshot to compare against. Subsequent calls return
    /// a [`SystemDelta`] containing the differences and rates.
    ///
    /// This method returns immediately without waiting for the interval.
    /// Use [`collect_after_interval`](Self::collect_after_interval) to
    /// enforce the configured interval between snapshots.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use toride::status::collector::Collector;
    ///
    /// let mut collector = Collector::default_collector();
    /// let (status, delta) = collector.collect();
    /// assert!(delta.is_none()); // First call has no delta.
    /// ```
    pub fn collect(&mut self) -> (TorideStatus, Option<SystemDelta>) {
        let status = TorideStatus::collect();
        let now = Instant::now();
        let delta = self.previous.as_ref().map(|(prev_time, prev_status)| {
            compute_delta(prev_status, &status.system, prev_time.elapsed())
        });
        self.previous = Some((now, status.system.clone()));
        (status, delta)
    }

    /// Collect a snapshot, blocking until the interval has elapsed.
    ///
    /// If enough time has already passed since the last snapshot, this
    /// method returns immediately. Otherwise, it sleeps for the remaining
    /// duration before collecting.
    ///
    /// On the first call, collects immediately and returns `None` for delta.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::time::Duration;
    /// use toride::status::collector::Collector;
    ///
    /// let mut collector = Collector::new(Duration::from_millis(100), Default::default());
    /// let (status, delta) = collector.collect_after_interval();
    /// assert!(delta.is_none()); // First call.
    /// ```
    pub fn collect_after_interval(&mut self) -> (TorideStatus, Option<SystemDelta>) {
        if let Some((prev_time, _)) = &self.previous {
            let elapsed = prev_time.elapsed();
            if let Some(remaining) = self.interval.checked_sub(elapsed) {
                std::thread::sleep(remaining);
            }
        }
        self.collect()
    }

    /// Reset the collector, clearing the previous snapshot.
    ///
    /// After reset, the next call to [`collect`](Self::collect) will
    /// return `None` for the delta, as if it were the first call.
    ///
    /// # Examples
    ///
    /// ```
    /// use toride::status::collector::Collector;
    ///
    /// let mut collector = Collector::default_collector();
    /// collector.collect();
    /// collector.reset();
    /// let (_, delta) = collector.collect();
    /// assert!(delta.is_none());
    /// ```
    pub fn reset(&mut self) {
        self.previous = None;
    }
}

#[allow(clippy::cast_precision_loss)] // u64->f64 for rate calculation display; negligible precision loss
fn compute_delta(prev: &SystemStatus, curr: &SystemStatus, elapsed: Duration) -> SystemDelta {
    let elapsed_secs = elapsed.as_secs_f64();
    let bytes_received_delta = curr
        .network
        .bytes_received
        .saturating_sub(prev.network.bytes_received);
    let bytes_transmitted_delta = curr
        .network
        .bytes_transmitted
        .saturating_sub(prev.network.bytes_transmitted);

    SystemDelta {
        elapsed,
        cpu_usage_delta: match (prev.cpu_usage, curr.cpu_usage) {
            (Some(p), Some(c)) => Some(c - p),
            _ => None,
        },
        bytes_received_delta,
        bytes_transmitted_delta,
        bytes_received_rate: if elapsed_secs > 0.0 {
            bytes_received_delta as f64 / elapsed_secs
        } else {
            0.0
        },
        bytes_transmitted_rate: if elapsed_secs > 0.0 {
            bytes_transmitted_delta as f64 / elapsed_secs
        } else {
            0.0
        },
    }
}

impl std::fmt::Display for SystemDelta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=== System Delta ===")?;
        writeln!(f, "  Elapsed: {:.2?}", self.elapsed)?;
        if let Some(cpu) = self.cpu_usage_delta {
            writeln!(f, "  CPU delta: {cpu:+.1}%")?;
        }
        writeln!(f, "  Network RX: {} bytes ({:.1} B/s)", self.bytes_received_delta, self.bytes_received_rate)?;
        writeln!(
            f,
            "  Network TX: {} bytes ({:.1} B/s)",
            self.bytes_transmitted_delta, self.bytes_transmitted_rate
        )

    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::system::{
        DiskStatus, MemoryStatus, NetworkStatus, OsInfo, ProcessSnapshot, SystemStatus,
    };

    /// Helper to construct a minimal `SystemStatus` with specific `cpu_usage` and network values.
    fn make_system_status(cpu_usage: Option<f64>, rx: u64, tx: u64) -> SystemStatus {
        SystemStatus {
            cpu_usage,
            memory: MemoryStatus { used_bytes: 0, total_bytes: 0, percentage: 0.0 },
            disk: DiskStatus {
                name: String::new(),
                mount_point: "/".to_string(),
                filesystem: String::new(),
                used_bytes: 0,
                total_bytes: 0,
                percentage: 0.0,
                is_removable: false,
            },
            network: NetworkStatus { bytes_received: rx, bytes_transmitted: tx },
            load_average: None,
            uptime_secs: None,
            hostname: String::new(),
            os_info: OsInfo { name: None, version: None, kernel_version: None, arch: String::new() },
            cpu_cores: Vec::new(),
            physical_cores: None,
            swap: None,
            disks: Vec::new(),
            network_interfaces: Vec::new(),
            sensors: Vec::new(),
            boot_time: None,
            processes: ProcessSnapshot { processes: vec![], total_count: 0 },
            gpu: vec![],
            battery: None,
        }
    }

    // ── compute_delta edge cases ──────────────────────────────────────

    #[test]
    fn compute_delta_zero_elapsed_produces_zero_rates() {
        let prev = make_system_status(Some(50.0), 1000, 500);
        let curr = make_system_status(Some(60.0), 2000, 1500);
        let delta = compute_delta(&prev, &curr, Duration::ZERO);

        assert_eq!(delta.elapsed, Duration::ZERO);
        assert_eq!(delta.bytes_received_delta, 1000);
        assert_eq!(delta.bytes_transmitted_delta, 1000);
        // Rates must be 0, not NaN or Inf from division by zero.
        assert!((delta.bytes_received_rate).abs() < f64::EPSILON);
        assert!((delta.bytes_transmitted_rate).abs() < f64::EPSILON);
        assert_eq!(delta.cpu_usage_delta, Some(10.0));
    }

    #[test]
    fn compute_delta_network_counter_wrap() {
        // Simulate u64 wrap: prev > curr. saturating_sub yields 0.
        let prev = make_system_status(None, u64::MAX - 10, u64::MAX - 5);
        let curr = make_system_status(None, 100, 200);
        let delta = compute_delta(&prev, &curr, Duration::from_secs(1));

        // saturating_sub prevents underflow; returns 0 when curr < prev.
        assert_eq!(delta.bytes_received_delta, 0);
        assert_eq!(delta.bytes_transmitted_delta, 0);
        assert!((delta.bytes_received_rate).abs() < f64::EPSILON);
        assert!((delta.bytes_transmitted_rate).abs() < f64::EPSILON);
    }

    #[test]
    fn compute_delta_both_cpu_none() {
        let prev = make_system_status(None, 100, 200);
        let curr = make_system_status(None, 300, 600);
        let delta = compute_delta(&prev, &curr, Duration::from_secs(2));

        assert!(delta.cpu_usage_delta.is_none());
        assert_eq!(delta.bytes_received_delta, 200);
        assert_eq!(delta.bytes_transmitted_delta, 400);
        assert!((delta.bytes_received_rate - 100.0).abs() < f64::EPSILON);
        assert!((delta.bytes_transmitted_rate - 200.0).abs() < f64::EPSILON);
    }

    #[test]
    fn compute_delta_one_cpu_none_one_some() {
        // prev is None, curr is Some -> should yield None
        let prev = make_system_status(None, 100, 200);
        let curr = make_system_status(Some(75.0), 300, 600);
        let delta = compute_delta(&prev, &curr, Duration::from_secs(1));
        assert!(delta.cpu_usage_delta.is_none());

        // prev is Some, curr is None -> should also yield None
        let prev = make_system_status(Some(75.0), 100, 200);
        let curr = make_system_status(None, 300, 600);
        let delta = compute_delta(&prev, &curr, Duration::from_secs(1));
        assert!(delta.cpu_usage_delta.is_none());
    }

    #[test]
    fn compute_delta_very_large_network_deltas() {
        let prev = make_system_status(Some(0.0), 0, 0);
        let curr = make_system_status(Some(100.0), u64::MAX, u64::MAX);
        let delta = compute_delta(&prev, &curr, Duration::from_secs(1));

        assert_eq!(delta.bytes_received_delta, u64::MAX);
        assert_eq!(delta.bytes_transmitted_delta, u64::MAX);
        // Rate = u64::MAX as f64 / 1.0 -- large but finite.
        assert!(delta.bytes_received_rate.is_finite());
        assert!(delta.bytes_transmitted_rate.is_finite());
        assert!(delta.bytes_received_rate > 1.0e18);
    }

    // ── Collector edge cases ──────────────────────────────────────────

    #[test]
    fn multiple_rapid_collects() {
        let mut c = Collector::default_collector();
        // First collect: no delta.
        let (_, d1) = c.collect();
        assert!(d1.is_none());

        // Rapid subsequent collects should all produce deltas (no panic, no NaN).
        for _ in 0..5 {
            let (_, delta) = c.collect();
            let d = delta.expect("subsequent collect should produce delta");
            // Elapsed may be very small but rates should be finite.
            assert!(d.bytes_received_rate.is_finite());
            assert!(d.bytes_transmitted_rate.is_finite());
        }
    }

    #[test]
    fn collect_after_long_interval() {
        let mut c = Collector::default_collector();
        c.collect();

        // Simulate a long gap by manually computing delta with a large Duration.
        // We test compute_delta directly since we can't actually sleep 24 hours.
        let prev = make_system_status(Some(10.0), 1_000_000, 500_000);
        let curr = make_system_status(Some(50.0), 1_000_000 + 86_400 * 1000, 500_000 + 86_400 * 500);
        let long_elapsed = Duration::from_hours(24);
        let delta = compute_delta(&prev, &curr, long_elapsed);

        assert_eq!(delta.elapsed, long_elapsed);
        assert_eq!(delta.cpu_usage_delta, Some(40.0));
        assert_eq!(delta.bytes_received_delta, 86_400_000);
        assert_eq!(delta.bytes_transmitted_delta, 43_200_000);
        // Rates: 86_400_000 / 86_400 = 1000.0 B/s
        assert!((delta.bytes_received_rate - 1000.0).abs() < 0.01);
        assert!((delta.bytes_transmitted_rate - 500.0).abs() < 0.01);
    }

    #[test]
    fn reset_then_collect_gives_no_delta() {
        let mut c = Collector::default_collector();
        c.collect();
        std::thread::sleep(Duration::from_millis(10));
        let (_, delta) = c.collect();
        assert!(delta.is_some(), "should have delta before reset");

        c.reset();
        let (_, delta) = c.collect();
        assert!(delta.is_none(), "after reset, first collect should yield no delta");
    }

    // ── SystemDelta Display edge cases ────────────────────────────────

    #[test]
    fn display_with_negative_cpu_delta() {
        let d = SystemDelta {
            elapsed: Duration::from_secs(2),
            cpu_usage_delta: Some(-15.3),
            bytes_received_delta: 0,
            bytes_transmitted_delta: 0,
            bytes_received_rate: 0.0,
            bytes_transmitted_rate: 0.0,
        };
        let output = format!("{d}");
        assert!(output.contains("Delta"), "should contain header");
        assert!(output.contains("-15.3"), "should contain negative CPU delta");
        assert!(output.contains("Network RX"), "should contain RX line");
        assert!(output.contains("Network TX"), "should contain TX line");
    }

    #[test]
    fn display_with_zero_deltas() {
        let d = SystemDelta {
            elapsed: Duration::from_millis(100),
            cpu_usage_delta: Some(0.0),
            bytes_received_delta: 0,
            bytes_transmitted_delta: 0,
            bytes_received_rate: 0.0,
            bytes_transmitted_rate: 0.0,
        };
        let output = format!("{d}");
        assert!(output.contains("0.0"), "should display zero values");
        assert!(output.contains("0 bytes"), "should show 0 bytes");
        assert!(output.contains("0.0 B/s"), "should show 0.0 B/s");
    }

    #[test]
    fn display_with_very_large_values() {
        let d = SystemDelta {
            elapsed: Duration::from_secs(u64::MAX / 1_000_000_000),
            cpu_usage_delta: Some(100.0),
            bytes_received_delta: u64::MAX,
            bytes_transmitted_delta: u64::MAX,
            bytes_received_rate: 1_000_000_000.0,
            bytes_transmitted_rate: 1_000_000_000.0,
        };
        let output = format!("{d}");
        assert!(output.contains("Delta"), "should contain header");
        assert!(output.contains("+100.0"), "should contain CPU delta with sign");
        // Should not panic on large values.
        assert!(!output.is_empty());
    }

    #[test]
    fn display_with_no_cpu_delta() {
        let d = SystemDelta {
            elapsed: Duration::from_secs(1),
            cpu_usage_delta: None,
            bytes_received_delta: 500,
            bytes_transmitted_delta: 300,
            bytes_received_rate: 500.0,
            bytes_transmitted_rate: 300.0,
        };
        let output = format!("{d}");
        // CPU line should be absent when cpu_usage_delta is None.
        assert!(!output.contains("CPU delta"), "should not show CPU line when None");
        assert!(output.contains("Network RX"), "should still show RX");
        assert!(output.contains("Network TX"), "should still show TX");
    }

    #[test]
    fn collect_after_interval_returns_delta() {
        let mut c = Collector::default_collector();
        let (_, delta1) = c.collect_after_interval();
        assert!(delta1.is_none(), "first collect_after_interval should have no delta");
        let (_, delta2) = c.collect_after_interval();
        assert!(delta2.is_some(), "second collect_after_interval should have delta");
    }

    #[test]
    fn collector_new_sets_interval() {
        let c = Collector::new(Duration::from_secs(5), Preset::Minimal);
        assert_eq!(c.interval(), Duration::from_secs(5));
        assert_eq!(c.preset(), Preset::Minimal);
    }

    #[test]
    fn default_collector_has_one_second_interval() {
        let c = Collector::default_collector();
        assert_eq!(c.interval(), Duration::from_secs(1));
    }

    #[test]
    fn first_collect_returns_no_delta() {
        let mut c = Collector::default_collector();
        let (_, delta) = c.collect();
        assert!(delta.is_none(), "first collect should have no delta");
    }

    #[test]
    fn second_collect_returns_delta() {
        let mut c = Collector::default_collector();
        c.collect();
        std::thread::sleep(Duration::from_millis(50));
        let (_, delta) = c.collect();
        assert!(delta.is_some(), "second collect should have delta");
    }

    #[test]
    fn delta_has_nonzero_elapsed() {
        let mut c = Collector::default_collector();
        c.collect();
        std::thread::sleep(Duration::from_millis(50));
        let (_, delta) = c.collect();
        let d = delta.unwrap();
        assert!(d.elapsed >= Duration::from_millis(40));
    }

    #[test]
    fn reset_clears_previous() {
        let mut c = Collector::default_collector();
        c.collect();
        c.reset();
        let (_, delta) = c.collect();
        assert!(delta.is_none());
    }

    #[test]
    fn delta_display() {
        let d = SystemDelta {
            elapsed: Duration::from_secs(1),
            cpu_usage_delta: Some(5.0),
            bytes_received_delta: 1024,
            bytes_transmitted_delta: 512,
            bytes_received_rate: 1024.0,
            bytes_transmitted_rate: 512.0,
        };
        let output = format!("{d}");
        assert!(output.contains("Delta"));
        assert!(output.contains("Network RX"));
    }

    #[test]
    fn serialize_to_json() {
        let d = SystemDelta {
            elapsed: Duration::from_secs(1),
            cpu_usage_delta: None,
            bytes_received_delta: 0,
            bytes_transmitted_delta: 0,
            bytes_received_rate: 0.0,
            bytes_transmitted_rate: 0.0,
        };
        assert!(serde_json::to_string(&d).is_ok());
    }

    #[test]
    fn compute_delta_zero_elapsed_no_panic() {
        let prev = make_system_status(Some(50.0), 1000, 500);
        let curr = prev.clone();
        // Zero elapsed with identical snapshots should not cause division by zero
        let delta = compute_delta(&prev, &curr, Duration::ZERO);
        assert!((delta.bytes_received_rate).abs() < f64::EPSILON);
        assert!((delta.bytes_transmitted_rate).abs() < f64::EPSILON);
        assert_eq!(delta.bytes_received_delta, 0);
        assert_eq!(delta.bytes_transmitted_delta, 0);
        assert_eq!(delta.cpu_usage_delta, Some(0.0));
    }

    #[test]
    fn compute_delta_network_counter_wrap_identical_prev() {
        let prev = make_system_status(None, u64::MAX - 100, u64::MAX - 50);
        let mut curr = prev.clone();
        curr.network.bytes_received = 50; // Wrapped around
        curr.network.bytes_transmitted = 25;
        let delta = compute_delta(&prev, &curr, Duration::from_secs(1));
        // saturating_sub yields 0 when curr < prev (counter wrap detected)
        assert_eq!(delta.bytes_received_delta, 0);
        assert_eq!(delta.bytes_transmitted_delta, 0);
        assert!((delta.bytes_received_rate).abs() < f64::EPSILON);
        assert!((delta.bytes_transmitted_rate).abs() < f64::EPSILON);
    }
}
