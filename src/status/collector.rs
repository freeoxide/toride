//! Collector for periodic status snapshots and delta computation.
//!
//! [`Collector`] manages periodic collection of system status and
//! computes deltas between consecutive snapshots for rate-based metrics.

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
    pub fn new(interval: Duration, preset: Preset) -> Self {
        Self {
            interval,
            preset,
            previous: None,
        }
    }

    /// Create a collector with default settings (1 second, Diagnostics preset).
    pub fn default_collector() -> Self {
        Self::new(Duration::from_secs(1), Preset::default())
    }

    /// Get the collection interval.
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// Get the current preset.
    pub fn preset(&self) -> Preset {
        self.preset
    }

    /// Collect a snapshot and compute delta from the previous one.
    ///
    /// On the first call, returns `None` for the delta.
    pub fn collect(&mut self) -> (TorideStatus, Option<SystemDelta>) {
        let now = Instant::now();
        let status = TorideStatus::collect();
        let delta = self.previous.as_ref().map(|(prev_time, prev_status)| {
            compute_delta(prev_status, &status.system, prev_time.elapsed())
        });
        self.previous = Some((now, status.system.clone()));
        (status, delta)
    }

    /// Collect a snapshot, blocking until the interval has elapsed.
    ///
    /// On the first call, collects immediately and returns `None` for delta.
    pub fn collect_after_interval(&mut self) -> (TorideStatus, Option<SystemDelta>) {
        if let Some((prev_time, _)) = &self.previous {
            let elapsed = prev_time.elapsed();
            if elapsed < self.interval {
                std::thread::sleep(self.interval - elapsed);
            }
        }
        self.collect()
    }

    /// Reset the collector, clearing the previous snapshot.
    pub fn reset(&mut self) {
        self.previous = None;
    }
}

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
            writeln!(f, "  CPU delta: {:+.1}%", cpu)?;
        }
        writeln!(f, "  Network RX: {} bytes ({:.1} B/s)", self.bytes_received_delta, self.bytes_received_rate)?;
        writeln!(f, "  Network TX: {} bytes ({:.1} B/s)", self.bytes_transmitted_delta, self.bytes_transmitted_rate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let output = format!("{}", d);
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
}
