//! Network port inspection via native OS APIs.
//!
//! Uses [`netstat2`] to enumerate TCP/UDP sockets with associated process
//! information — no shell commands or `lsof`/`ss` parsing required.
//!
//! # Types (always compiled)
//!
//! [`PortEntry`] — a single socket with address, state, and process info.
//! [`PortQuery`] — flexible filter for querying specific entries.
//!
//! # Live inspection (requires `client` feature)
//!
//! [`PortReader`] wraps [`netstat2`] to collect live socket data from the
//! kernel. Create one via [`PortReader::new`] and call the query methods.
//!
//! ```ignore
//! use toride_monitor::ports::PortReader;
//! use toride_monitor::paths::MonitorPaths;
//!
//! let reader = PortReader::new(&paths);
//! let listeners = reader.list_listening()?;
//! for entry in &listeners {
//!     println!("{entry}");
//! }
//! ```

use std::fmt;
use std::net::IpAddr;

use crate::error::{Error, Result};
use crate::paths::MonitorPaths;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Network protocol of a socket entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortProtocol {
    /// TCP socket.
    Tcp,
    /// UDP socket.
    Udp,
}

impl fmt::Display for PortProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Udp => write!(f, "udp"),
        }
    }
}

/// IP version of a socket entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpVersion {
    /// IPv4.
    V4,
    /// IPv6.
    V6,
}

impl fmt::Display for IpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4 => write!(f, "IPv4"),
            Self::V6 => write!(f, "IPv6"),
        }
    }
}

/// TCP connection state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortState {
    /// Listening for incoming connections.
    Listen,
    /// Connection established.
    Established,
    /// Waiting for remote side to close.
    CloseWait,
    /// Waiting for enough time to pass to ensure the remote side received
    /// the acknowledgement of the connection termination request.
    TimeWait,
    /// Connection synchronisation sent (active open).
    SynSent,
    /// Connection synchronisation received.
    SynRecv,
    /// Waiting for the remote side to acknowledge the termination request.
    FinWait1,
    /// Waiting for the remote side to acknowledge the termination request
    /// and then for the remote side's own termination request.
    FinWait2,
    /// Waiting for the remote side's termination acknowledgement.
    LastAck,
    /// Both sides have closed but we are still waiting for data to be
    /// acknowledged.
    Closing,
    /// Unrecognised state with the raw name preserved.
    Unknown(String),
}

impl fmt::Display for PortState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Listen => write!(f, "LISTEN"),
            Self::Established => write!(f, "ESTABLISHED"),
            Self::CloseWait => write!(f, "CLOSE_WAIT"),
            Self::TimeWait => write!(f, "TIME_WAIT"),
            Self::SynSent => write!(f, "SYN_SENT"),
            Self::SynRecv => write!(f, "SYN_RECV"),
            Self::FinWait1 => write!(f, "FIN_WAIT1"),
            Self::FinWait2 => write!(f, "FIN_WAIT2"),
            Self::LastAck => write!(f, "LAST_ACK"),
            Self::Closing => write!(f, "CLOSING"),
            Self::Unknown(s) => write!(f, "{s}"),
        }
    }
}

// ---------------------------------------------------------------------------
// PortEntry
// ---------------------------------------------------------------------------

/// A single network socket with full connection and process information.
#[derive(Debug, Clone)]
pub struct PortEntry {
    /// Protocol (TCP or UDP).
    pub protocol: PortProtocol,
    /// IP version (IPv4 or IPv6).
    pub ip_version: IpVersion,
    /// Local IP address.
    pub local_addr: IpAddr,
    /// Local port number.
    pub local_port: u16,
    /// Remote IP address.
    pub remote_addr: IpAddr,
    /// Remote port number.
    pub remote_port: u16,
    /// Socket state.
    pub state: PortState,
    /// Process name (e.g. `"nginx"`, `"sshd"`), if resolvable.
    pub process_name: Option<String>,
    /// Process ID owning the socket, if available.
    pub pid: Option<u32>,
}

impl fmt::Display for PortEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let proto = self.protocol;
        let state = &self.state;
        let local = format_addr(self.local_addr, self.local_port);
        let remote = format_addr(self.remote_addr, self.remote_port);

        match (&self.process_name, self.pid) {
            (Some(name), Some(pid)) => {
                write!(f, "{proto:<4} {local:<24} {remote:<24} {state:<14} {name} (PID {pid})")
            }
            (Some(name), None) => {
                write!(f, "{proto:<4} {local:<24} {remote:<24} {state:<14} {name}")
            }
            (None, Some(pid)) => {
                write!(f, "{proto:<4} {local:<24} {remote:<24} {state:<14} PID {pid}")
            }
            (None, None) => {
                write!(f, "{proto:<4} {local:<24} {remote:<24} {state}")
            }
        }
    }
}

/// Format an address:port pair for display.
fn format_addr(addr: IpAddr, port: u16) -> String {
    match addr {
        IpAddr::V6(_) => format!("[{addr}]:{port}"),
        IpAddr::V4(_) => format!("{addr}:{port}"),
    }
}

// ---------------------------------------------------------------------------
// PortQuery
// ---------------------------------------------------------------------------

/// Flexible filter for querying port entries.
///
/// All fields are optional — `None` means "don't filter by this dimension".
/// Multiple non-None fields are ANDed together.
#[derive(Debug, Clone, Default)]
pub struct PortQuery {
    /// Filter by port number.
    pub port: Option<u16>,
    /// Filter by protocol.
    pub protocol: Option<PortProtocol>,
    /// Filter by process name (case-insensitive substring match).
    pub process_name: Option<String>,
    /// Filter by PID.
    pub pid: Option<u32>,
    /// Filter by socket state.
    pub state: Option<PortState>,
    /// Filter by IP version.
    pub ip_version: Option<IpVersion>,
}

impl PortQuery {
    /// Create an empty query (matches everything).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by port number.
    #[must_use]
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Filter by protocol.
    #[must_use]
    pub fn protocol(mut self, protocol: PortProtocol) -> Self {
        self.protocol = Some(protocol);
        self
    }

    /// Filter by process name (case-insensitive substring).
    #[must_use]
    pub fn process_name(mut self, name: impl Into<String>) -> Self {
        self.process_name = Some(name.into());
        self
    }

    /// Filter by PID.
    #[must_use]
    pub fn pid(mut self, pid: u32) -> Self {
        self.pid = Some(pid);
        self
    }

    /// Filter by state.
    #[must_use]
    pub fn state(mut self, state: PortState) -> Self {
        self.state = Some(state);
        self
    }

    /// Filter by IP version.
    #[must_use]
    pub fn ip_version(mut self, version: IpVersion) -> Self {
        self.ip_version = Some(version);
        self
    }

    /// Check if an entry matches this query.
    pub fn matches(&self, entry: &PortEntry) -> bool {
        if let Some(port) = self.port {
            if entry.local_port != port {
                return false;
            }
        }
        if let Some(proto) = self.protocol {
            if entry.protocol != proto {
                return false;
            }
        }
        if let Some(ref name) = self.process_name {
            let matches_name = entry
                .process_name
                .as_ref()
                .is_some_and(|pn| pn.to_lowercase().contains(&name.to_lowercase()));
            if !matches_name {
                return false;
            }
        }
        if let Some(pid) = self.pid {
            if entry.pid != Some(pid) {
                return false;
            }
        }
        if let Some(ref state) = self.state {
            if entry.state != *state {
                return false;
            }
        }
        if let Some(ipv) = self.ip_version {
            if entry.ip_version != ipv {
                return false;
            }
        }
        true
    }
}

// ---------------------------------------------------------------------------
// PortReader
// ---------------------------------------------------------------------------

/// Reads network socket information from the kernel via [`netstat2`].
///
/// Follows the same borrow-based pattern as
/// [`crate::conntrack::ConntrackReader`].
pub struct PortReader<'a> {
    paths: &'a MonitorPaths,
}

impl<'a> PortReader<'a> {
    /// Create a new reader borrowing the resolved binary paths.
    #[must_use]
    pub fn new(paths: &'a MonitorPaths) -> Self {
        Self { paths }
    }

    /// List all listening TCP/UDP sockets with process info.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PortsError`] if the kernel socket enumeration fails.
    #[cfg(feature = "client")]
    pub fn list_listening(&self) -> Result<Vec<PortEntry>> {
        let all = self.collect_all()?;
        Ok(all.into_iter().filter(|e| e.state == PortState::Listen).collect())
    }

    /// List **all** network sockets (listening, established, time-wait, etc.)
    /// with process info.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PortsError`] if the kernel socket enumeration fails.
    #[cfg(feature = "client")]
    pub fn list_all(&self) -> Result<Vec<PortEntry>> {
        self.collect_all()
    }

    /// Find every socket bound to a specific port.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PortsError`] if the kernel socket enumeration fails.
    #[cfg(feature = "client")]
    pub fn find_by_port(&self, port: u16) -> Result<Vec<PortEntry>> {
        let all = self.collect_all()?;
        Ok(all.into_iter().filter(|e| e.local_port == port).collect())
    }

    /// Find every socket owned by a process whose name contains `name`
    /// (case-insensitive).
    ///
    /// # Errors
    ///
    /// Returns [`Error::PortsError`] if the kernel socket enumeration fails.
    #[cfg(feature = "client")]
    pub fn find_by_process(&self, name: &str) -> Result<Vec<PortEntry>> {
        let lower = name.to_lowercase();
        let all = self.collect_all()?;
        Ok(all
            .into_iter()
            .filter(|e| {
                e.process_name
                    .as_ref()
                    .is_some_and(|pn| pn.to_lowercase().contains(&lower))
            })
            .collect())
    }

    /// Check whether nothing is listening on `port`.
    ///
    /// Returns `Ok(true)` if the port is free, `Ok(false)` if something is
    /// listening on it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PortsError`] if the kernel socket enumeration fails.
    #[cfg(feature = "client")]
    pub fn is_port_free(&self, port: u16) -> Result<bool> {
        let listeners = self.list_listening()?;
        Ok(!listeners.iter().any(|e| e.local_port == port))
    }

    /// Flexible query — returns entries matching all non-None filters in `q`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PortsError`] if the kernel socket enumeration fails.
    #[cfg(feature = "client")]
    pub fn query(&self, q: &PortQuery) -> Result<Vec<PortEntry>> {
        let all = self.collect_all()?;
        Ok(all.into_iter().filter(|e| q.matches(e)).collect())
    }

    // -----------------------------------------------------------------------
    // Private
    // -----------------------------------------------------------------------

    /// Collect all sockets from the kernel and enrich with process names.
    #[cfg(feature = "client")]
    fn collect_all(&self) -> Result<Vec<PortEntry>> {
        use netstat2::{
            get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo,
        };

        // We don't actually use paths for netstat2 (it uses native APIs),
        // but we keep the field for API consistency and future extensions.
        let _ = &self.paths;

        let af = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
        let proto = ProtocolFlags::TCP | ProtocolFlags::UDP;

        let sockets = get_sockets_info(af, proto)
            .map_err(|e| Error::PortsError(format!("socket enumeration failed: {e}")))?;

        // Build a PID → process-name lookup via /proc or syscall.
        let mut pid_map: std::collections::HashMap<u32, String> = std::collections::HashMap::new();
        for sock in &sockets {
            for pid in &sock.associated_pids {
                if pid_map.contains_key(pid) {
                    continue;
                }
                if let Some(name) = lookup_process_name(*pid) {
                    pid_map.insert(*pid, name);
                }
            }
        }

        let entries: Vec<PortEntry> = sockets
            .into_iter()
            .filter_map(|sock| {
                let (protocol, ip_version, local_addr, local_port, remote_addr, remote_port, state) =
                    match &sock.protocol_socket_info {
                        ProtocolSocketInfo::Tcp(t) => {
                            let iv = match t.local_addr {
                                IpAddr::V4(_) => IpVersion::V4,
                                IpAddr::V6(_) => IpVersion::V6,
                            };
                            (
                                PortProtocol::Tcp,
                                iv,
                                t.local_addr,
                                t.local_port,
                                t.remote_addr,
                                t.remote_port,
                                tcp_state_to_port_state(t.state),
                            )
                        }
                        ProtocolSocketInfo::Udp(u) => {
                            let iv = match u.local_addr {
                                IpAddr::V4(_) => IpVersion::V4,
                                IpAddr::V6(_) => IpVersion::V6,
                            };
                            (
                                PortProtocol::Udp,
                                iv,
                                u.local_addr,
                                u.local_port,
                                // UDP sockets don't have remote address info.
                                u.local_addr,
                                0u16,
                                PortState::Unknown("UDP".into()),
                            )
                        }
                    };

                let (process_name, pid) = sock
                    .associated_pids
                    .first()
                    .map(|p| (pid_map.get(p).cloned(), Some(*p)))
                    .unwrap_or((None, None));

                Some(PortEntry {
                    protocol,
                    ip_version,
                    local_addr,
                    local_port,
                    remote_addr,
                    remote_port,
                    state,
                    process_name,
                    pid,
                })
            })
            .collect();

        Ok(entries)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Map a `netstat2::TcpState` to our `PortState`.
fn tcp_state_to_port_state(ts: netstat2::TcpState) -> PortState {
    match ts {
        netstat2::TcpState::Listen => PortState::Listen,
        netstat2::TcpState::Established => PortState::Established,
        netstat2::TcpState::CloseWait => PortState::CloseWait,
        netstat2::TcpState::TimeWait => PortState::TimeWait,
        netstat2::TcpState::SynSent => PortState::SynSent,
        netstat2::TcpState::FinWait1 => PortState::FinWait1,
        netstat2::TcpState::FinWait2 => PortState::FinWait2,
        netstat2::TcpState::LastAck => PortState::LastAck,
        netstat2::TcpState::Closing => PortState::Closing,
        _ => PortState::Unknown(format!("{ts:?}")),
    }
}

/// Look up a process name from its PID.
///
/// Tries `/proc/<pid>/comm` first (Linux), falls back to `sysctl` or
/// a best-effort approach. Returns `None` if the process is gone or the
/// name cannot be resolved.
#[cfg(feature = "client")]
fn lookup_process_name(pid: u32) -> Option<String> {
    // Try /proc first (Linux).
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    let name = comm.trim().to_string();
    if name.is_empty() {
        return None;
    }
    Some(name)
}

#[cfg(all(test, not(feature = "client")))]
mod tests {
    use super::*;

    #[test]
    fn port_entry_display_format() {
        let entry = PortEntry {
            protocol: PortProtocol::Tcp,
            ip_version: IpVersion::V4,
            local_addr: "0.0.0.0".parse().unwrap(),
            local_port: 80,
            remote_addr: "0.0.0.0".parse().unwrap(),
            remote_port: 0,
            state: PortState::Listen,
            process_name: Some("nginx".into()),
            pid: Some(1234),
        };
        let s = format!("{entry}");
        assert!(s.contains("tcp"));
        assert!(s.contains("0.0.0.0:80"));
        assert!(s.contains("LISTEN"));
        assert!(s.contains("nginx"));
        assert!(s.contains("1234"));
    }

    #[test]
    fn port_entry_display_no_process() {
        let entry = PortEntry {
            protocol: PortProtocol::Udp,
            ip_version: IpVersion::V6,
            local_addr: "::".parse().unwrap(),
            local_port: 5353,
            remote_addr: "::".parse().unwrap(),
            remote_port: 0,
            state: PortState::Unknown("UDP".into()),
            process_name: None,
            pid: None,
        };
        let s = format!("{entry}");
        assert!(s.contains("udp"));
        assert!(s.contains("5353"));
    }

    #[test]
    fn port_state_display() {
        assert_eq!(format!("{}", PortState::Listen), "LISTEN");
        assert_eq!(format!("{}", PortState::Established), "ESTABLISHED");
        assert_eq!(format!("{}", PortState::TimeWait), "TIME_WAIT");
        assert_eq!(
            format!("{}", PortState::Unknown("FOO".into())),
            "FOO"
        );
    }

    #[test]
    fn port_protocol_display() {
        assert_eq!(format!("{}", PortProtocol::Tcp), "tcp");
        assert_eq!(format!("{}", PortProtocol::Udp), "udp");
    }

    #[test]
    fn port_query_matches_port() {
        let entry = PortEntry {
            protocol: PortProtocol::Tcp,
            ip_version: IpVersion::V4,
            local_addr: "0.0.0.0".parse().unwrap(),
            local_port: 443,
            remote_addr: "0.0.0.0".parse().unwrap(),
            remote_port: 0,
            state: PortState::Listen,
            process_name: Some("nginx".into()),
            pid: Some(100),
        };
        assert!(PortQuery::new().port(443).matches(&entry));
        assert!(!PortQuery::new().port(80).matches(&entry));
    }

    #[test]
    fn port_query_matches_process_name() {
        let entry = PortEntry {
            protocol: PortProtocol::Tcp,
            ip_version: IpVersion::V4,
            local_addr: "0.0.0.0".parse().unwrap(),
            local_port: 22,
            remote_addr: "0.0.0.0".parse().unwrap(),
            remote_port: 0,
            state: PortState::Listen,
            process_name: Some("sshd".into()),
            pid: Some(1),
        };
        assert!(PortQuery::new().process_name("ssh").matches(&entry));
        assert!(PortQuery::new().process_name("SSHD").matches(&entry));
        assert!(!PortQuery::new().process_name("nginx").matches(&entry));
    }

    #[test]
    fn port_query_matches_combined() {
        let entry = PortEntry {
            protocol: PortProtocol::Tcp,
            ip_version: IpVersion::V4,
            local_addr: "0.0.0.0".parse().unwrap(),
            local_port: 80,
            remote_addr: "0.0.0.0".parse().unwrap(),
            remote_port: 0,
            state: PortState::Listen,
            process_name: Some("nginx".into()),
            pid: Some(42),
        };
        let q = PortQuery::new().port(80).protocol(PortProtocol::Tcp).state(PortState::Listen);
        assert!(q.matches(&entry));
        let q2 = PortQuery::new().port(80).protocol(PortProtocol::Udp);
        assert!(!q2.matches(&entry));
    }

    #[test]
    fn port_query_default_matches_everything() {
        let entry = PortEntry {
            protocol: PortProtocol::Tcp,
            ip_version: IpVersion::V4,
            local_addr: "0.0.0.0".parse().unwrap(),
            local_port: 80,
            remote_addr: "0.0.0.0".parse().unwrap(),
            remote_port: 0,
            state: PortState::Listen,
            process_name: None,
            pid: None,
        };
        assert!(PortQuery::new().matches(&entry));
    }
}
