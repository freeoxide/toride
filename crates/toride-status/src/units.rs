//! Type-safe unit wrappers for system status metrics.
//!
//! Prevents unit confusion between bytes/kilobytes, Hz/MHz/GHz,
//! Celsius/Fahrenheit, Watts/Volts, etc.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Wrapper for byte values (disk, memory, network counters).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Bytes(pub u64);

impl Bytes {
    pub const ZERO: Self = Self(0);

    #[must_use]
    pub fn as_u64(self) -> u64 {
        self.0
    }

    /// Return human-readable string (e.g. "1.5 GiB").
    #[must_use]
    pub fn human_readable(self) -> String {
        format_bytes(self.0)
    }
}

impl fmt::Display for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_bytes(f, self.0)
    }
}

impl From<u64> for Bytes {
    fn from(v: u64) -> Self {
        Self(v)
    }
}

/// Wrapper for frequency values in Hz.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Hertz(pub u64);

impl Hertz {
    pub const ZERO: Self = Self(0);

    #[must_use]
    pub fn as_hz(self) -> u64 {
        self.0
    }

    #[must_use]
    pub fn as_mhz(self) -> f64 {
        #[expect(
            clippy::cast_precision_loss,
            reason = "frequency in Hz fits f64 mantissa for all realistic values"
        )]
        let hz = self.0 as f64;
        hz / 1_000_000.0
    }

    #[must_use]
    pub fn as_ghz(self) -> f64 {
        #[expect(
            clippy::cast_precision_loss,
            reason = "frequency in Hz fits f64 mantissa for all realistic values"
        )]
        let hz = self.0 as f64;
        hz / 1_000_000_000.0
    }
}

impl fmt::Display for Hertz {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[expect(
            clippy::cast_precision_loss,
            reason = "frequency in Hz fits f64 mantissa for all realistic values"
        )]
        let hz = self.0 as f64;
        if self.0 >= 1_000_000_000 {
            write!(f, "{:.2} GHz", hz / 1_000_000_000.0)
        } else if self.0 >= 1_000_000 {
            write!(f, "{:.1} MHz", hz / 1_000_000.0)
        } else if self.0 >= 1_000 {
            write!(f, "{:.1} kHz", hz / 1_000.0)
        } else {
            write!(f, "{} Hz", self.0)
        }
    }
}

impl From<u64> for Hertz {
    fn from(v: u64) -> Self {
        Self(v)
    }
}

/// Wrapper for temperature in degrees Celsius.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Celsius(pub f32);

impl Celsius {
    pub const ZERO: Self = Self(0.0);

    #[must_use]
    pub fn as_f32(self) -> f32 {
        self.0
    }

    #[must_use]
    pub fn to_fahrenheit(self) -> f32 {
        self.0 * 9.0 / 5.0 + 32.0
    }
}

impl fmt::Display for Celsius {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.1}°C", self.0)
    }
}

impl From<f32> for Celsius {
    fn from(v: f32) -> Self {
        Self(v)
    }
}

/// Wrapper for power values in Watts.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Watts(pub f32);

impl Watts {
    pub const ZERO: Self = Self(0.0);

    #[must_use]
    pub fn as_f32(self) -> f32 {
        self.0
    }
}

impl fmt::Display for Watts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.1} W", self.0)
    }
}

impl From<f32> for Watts {
    fn from(v: f32) -> Self {
        Self(v)
    }
}

/// Wrapper for voltage values in Volts.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Volts(pub f32);

impl Volts {
    pub const ZERO: Self = Self(0.0);

    #[must_use]
    pub fn as_f32(self) -> f32 {
        self.0
    }
}

impl fmt::Display for Volts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.2} V", self.0)
    }
}

impl From<f32> for Volts {
    fn from(v: f32) -> Self {
        Self(v)
    }
}

/// Wrapper for fan speed in RPM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Rpm(pub u32);

impl Rpm {
    pub const ZERO: Self = Self(0);

    #[must_use]
    pub fn as_u32(self) -> u32 {
        self.0
    }
}

impl fmt::Display for Rpm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} RPM", self.0)
    }
}

impl From<u32> for Rpm {
    fn from(v: u32) -> Self {
        Self(v)
    }
}

// ── Formatting helpers ──────────────────────────────────────────────

const KB: u64 = 1024;
const MB: u64 = 1024 * KB;
const GB: u64 = 1024 * MB;
const TB: u64 = 1024 * GB;
const PB: u64 = 1024 * TB;

const KB_F: f64 = 1024.0;
const MB_F: f64 = 1024.0 * 1024.0;
const GB_F: f64 = 1024.0 * 1024.0 * 1024.0;
const TB_F: f64 = 1024.0 * 1024.0 * 1024.0 * 1024.0;
const PB_F: f64 = 1024.0 * 1024.0 * 1024.0 * 1024.0 * 1024.0;

/// Format bytes as human-readable string.
#[must_use]
pub fn format_bytes(bytes: u64) -> String {
    #[expect(
        clippy::cast_precision_loss,
        reason = "byte counts fit f64 mantissa for display purposes"
    )]
    let bytes_f = bytes as f64;
    if bytes >= PB {
        format!("{:.2} PiB", bytes_f / PB_F)
    } else if bytes >= TB {
        format!("{:.2} TiB", bytes_f / TB_F)
    } else if bytes >= GB {
        format!("{:.2} GiB", bytes_f / GB_F)
    } else if bytes >= MB {
        format!("{:.1} MiB", bytes_f / MB_F)
    } else if bytes >= KB {
        format!("{:.1} KiB", bytes_f / KB_F)
    } else {
        format!("{bytes} B")
    }
}

/// Write bytes as human-readable to a formatter.
///
/// # Errors
///
/// Returns the underlying [`fmt::Error`] if the formatter fails to accept the
/// written string (e.g. when the destination is full).
pub fn write_bytes(f: &mut fmt::Formatter<'_>, bytes: u64) -> fmt::Result {
    write!(f, "{}", format_bytes(bytes))
}

/// Format duration in seconds as human-readable string.
#[must_use]
pub fn format_duration(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;

    if days > 0 {
        format!("{days}d {hours}h {minutes}m {seconds}s")
    } else if hours > 0 {
        format!("{hours}h {minutes}m {seconds}s")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    }
}

/// Write duration to a formatter.
///
/// # Errors
///
/// Returns the underlying [`fmt::Error`] if the formatter fails to accept the
/// written string.
pub fn write_duration(f: &mut fmt::Formatter<'_>, secs: u64) -> fmt::Result {
    write!(f, "{}", format_duration(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_display() {
        assert_eq!(format!("{}", Bytes(0)), "0 B");
        assert_eq!(format!("{}", Bytes(1023)), "1023 B");
        assert_eq!(format!("{}", Bytes(1024)), "1.0 KiB");
        assert_eq!(format!("{}", Bytes(1536)), "1.5 KiB");
        assert_eq!(format!("{}", Bytes(1_048_576)), "1.0 MiB");
        assert_eq!(format!("{}", Bytes(1_073_741_824)), "1.00 GiB");
        assert_eq!(format!("{}", Bytes(1_099_511_627_776)), "1.00 TiB");
    }

    #[test]
    fn bytes_ordering() {
        assert!(Bytes(100) < Bytes(200));
        assert!(Bytes(1024) > Bytes(1023));
    }

    #[test]
    fn bytes_human_readable() {
        assert_eq!(Bytes(1_073_741_824).human_readable(), "1.00 GiB");
    }

    #[test]
    fn hertz_display() {
        assert_eq!(format!("{}", Hertz(0)), "0 Hz");
        assert_eq!(format!("{}", Hertz(1000)), "1.0 kHz");
        assert_eq!(format!("{}", Hertz(3_200_000_000)), "3.20 GHz");
        assert_eq!(format!("{}", Hertz(2_400_000_000)), "2.40 GHz");
    }

    #[test]
    fn hertz_conversions() {
        let h = Hertz(3_200_000_000);
        assert!((h.as_ghz() - 3.2).abs() < 0.01);
        assert!((h.as_mhz() - 3200.0).abs() < 0.01);
        assert_eq!(h.as_hz(), 3_200_000_000);
    }

    #[test]
    fn celsius_display() {
        assert_eq!(format!("{}", Celsius(0.0)), "0.0°C");
        assert_eq!(format!("{}", Celsius(55.5)), "55.5°C");
        assert_eq!(format!("{}", Celsius(-10.0)), "-10.0°C");
    }

    #[test]
    fn celsius_to_fahrenheit() {
        assert!((Celsius(0.0).to_fahrenheit() - 32.0).abs() < 0.01);
        assert!((Celsius(100.0).to_fahrenheit() - 212.0).abs() < 0.01);
    }

    #[test]
    fn watts_display() {
        assert_eq!(format!("{}", Watts(0.0)), "0.0 W");
        assert_eq!(format!("{}", Watts(75.5)), "75.5 W");
    }

    #[test]
    fn volts_display() {
        assert_eq!(format!("{}", Volts(0.0)), "0.00 V");
        assert_eq!(format!("{}", Volts(3.3)), "3.30 V");
        assert_eq!(format!("{}", Volts(12.0)), "12.00 V");
    }

    #[test]
    fn rpm_display() {
        assert_eq!(format!("{}", Rpm(0)), "0 RPM");
        assert_eq!(format!("{}", Rpm(1500)), "1500 RPM");
    }

    #[test]
    fn format_duration_values() {
        assert_eq!(format_duration(0), "0s");
        assert_eq!(format_duration(59), "59s");
        assert_eq!(format_duration(60), "1m 0s");
        assert_eq!(format_duration(3661), "1h 1m 1s");
        assert_eq!(format_duration(90061), "1d 1h 1m 1s");
    }
}
