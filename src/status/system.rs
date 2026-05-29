//! OS-level metrics: CPU, memory, disk, network, load average, uptime, hostname.
//!
//! Uses the [`sysinfo`] crate for cross-platform data collection. Each metric
//! returns `None` when the underlying data cannot be read (e.g. permission
//! denied on certain Linux containers).
//!
//! # Platform notes
//!
//! | Metric        | Linux | macOS | Windows |
//! |---------------|:-----:|:-----:|:-------:|
//! | CPU usage     | ✓     | ✓     | ✓       |
//! | Memory        | ✓     | ✓     | ✓       |
//! | Disk usage    | ✓     | ✓     | ✓       |
//! | Network I/O   | ✓     | ✓     | ✓       |
//! | Load average  | ✓     | ✓     | ✗       |
//! | Uptime        | ✓     | ✓     | ✓       |
//! | Hostname      | ✓     | ✓     | ✓       |
