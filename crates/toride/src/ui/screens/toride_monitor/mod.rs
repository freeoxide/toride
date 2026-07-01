//! Outbound traffic monitoring content area (live READ-ONLY).
//!
//! Renders inside the dashboard's content region when
//! [`Section::Monitor`](crate::data::Section) is the active sidebar section.
//! Mirrors the fail2ban / SSH read-only integrations MINUS the write path —
//! every line is a pure read of the `toride-monitor` backend.
//!
//! Layout (single scrollable pane, no sub-tab bar):
//! 1. Snapshot summary — total connections, unique destinations, bytes/packets.
//! 2. Outbound connections table — proto / src→dst / state / bytes.
//! 3. Listening ports — proto / addr:port / process.
//! 4. Conntrack summary — tracked count, total bytes, total packets.
//! 5. OUTPUT chain LOG rules — count of installed logging rules.
//! 6. Anomaly findings — grouped by severity (Critical > Error > Warning > Info).
//! 7. Doctor findings — grouped by severity (Critical > Error > Warning > Info).

use crossterm::event::{KeyCode, MouseEvent, MouseEventKind};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Paragraph, Wrap},
};

use crate::action::Action;
use crate::ui::responsive::truncate_str;
use crate::ui::theme::Palette;
use crate::ui::widgets::render_titled_panel;

// ── Presentation types ──────────────────────────────────────────────────────

/// A single outbound connection row (from `ss` / `conntrack`).
#[derive(Clone, Debug)]
pub struct ConnectionEntry {
    /// Protocol (e.g. "tcp", "udp").
    pub protocol: String,
    /// Source IP:port label.
    pub src: String,
    /// Destination IP:port label (port embedded via `format_addr_port`).
    pub dst: String,
    /// Connection state (e.g. "ESTABLISHED", "TIME-WAIT").
    pub state: String,
    /// Bytes transferred, if known from conntrack.
    pub bytes: Option<u64>,
}

/// A single listening socket (from `netstat2` via `PortReader`).
#[derive(Clone, Debug)]
pub struct PortEntry {
    /// Protocol label ("tcp" / "udp").
    pub protocol: String,
    /// IP version label ("IPv4" / "IPv6").
    pub ip_version: String,
    /// Local address (IP only, no port).
    pub local_addr: String,
    /// Local port.
    pub local_port: u16,
    /// Socket state label.
    pub state: String,
    /// Owning process name, if resolved.
    pub process_name: Option<String>,
    /// Owning PID, if resolved.
    pub pid: Option<u32>,
}

/// Aggregated conntrack counters.
#[derive(Clone, Debug, Default)]
pub struct ConntrackSummary {
    /// Number of currently tracked connections (`conntrack -C`).
    pub count: Option<u64>,
    /// Total bytes across tracked flows, if the table was readable.
    pub total_bytes: Option<u64>,
    /// Total packets across tracked flows, if the table was readable.
    pub total_packets: Option<u64>,
}

/// A single anomaly finding (from `MonitorClient::detect`).
#[derive(Clone, Debug)]
pub struct AnomalyEntry {
    /// Machine-readable id (e.g. "anomaly.connection-volume").
    pub id: String,
    /// Severity as a lowercase string: "info" | "warning" | "error" | "critical".
    pub severity: String,
    /// Short human-readable title.
    pub title: String,
    /// Observed value that triggered the anomaly.
    pub observed: String,
    /// Threshold that was exceeded.
    pub threshold: String,
    /// Suggested remediation, if any.
    pub fix: Option<String>,
}

/// A single doctor finding (from `Doctor::run`).
#[derive(Clone, Debug)]
pub struct FindingEntry {
    /// Machine-readable dot-separated id (e.g. "doctor.binary.iptables.missing").
    pub id: String,
    /// Severity as a lowercase string: "info" | "warning" | "error" | "critical".
    pub severity: String,
    /// Short human-readable title.
    pub title: String,
    /// Longer description / observed value.
    pub detail: String,
    /// Suggested remediation, if any.
    pub fix: Option<String>,
}

/// Aggregated snapshot counters shown in the summary panel.
#[derive(Clone, Debug, Default)]
pub struct SnapshotSummary {
    /// Total outbound connections observed.
    pub total_connections: u64,
    /// Unique destination IPs.
    pub unique_destinations: u64,
    /// Total bytes transferred, if known.
    pub total_bytes: Option<u64>,
    /// Total packets transferred, if known.
    pub total_packets: Option<u64>,
}

// ── MonitorContent ──────────────────────────────────────────────────────────

/// Outbound traffic monitoring content rendered inside the dashboard content
/// area.
///
/// READ-ONLY: there are no write operations, no optimistic updates, no loading
/// spinner, no cooldown. Data arrives via [`MonitorContent::set_*`] setters
/// driven by [`MonitorCollector`](crate::toride_monitor_data::MonitorCollector).
pub struct MonitorContent {
    /// Whether the monitor backend was reachable at all (binaries present,
    /// `MonitorClient::system()` succeeded). `false` means the section renders
    /// a degraded "unavailable" panel instead of live data.
    available: bool,
    /// Aggregated snapshot counters.
    summary: SnapshotSummary,
    /// Outbound connections table.
    connections: Vec<ConnectionEntry>,
    /// Listening ports.
    ports: Vec<PortEntry>,
    /// Conntrack counters.
    conntrack: ConntrackSummary,
    /// Number of installed OUTPUT chain LOG rules (from `iptables-save`).
    output_rule_count: Option<usize>,
    /// Anomaly findings.
    anomalies: Vec<AnomalyEntry>,
    /// Doctor findings.
    findings: Vec<FindingEntry>,
    /// Human-readable reason the backend was unreachable, surfaced in the
    /// degraded panel. Populated only when a collection task panicked or
    /// `MonitorClient::system()` returned `BinaryNotFound` (macOS).
    unavailable_reason: Option<String>,
    /// Vertical scroll offset over the whole pane.
    scroll: usize,
}

impl Default for MonitorContent {
    fn default() -> Self {
        Self::new()
    }
}

impl MonitorContent {
    /// Create a new empty content area.
    #[must_use]
    pub fn new() -> Self {
        Self {
            available: false,
            summary: SnapshotSummary::default(),
            connections: Vec::new(),
            ports: Vec::new(),
            conntrack: ConntrackSummary::default(),
            output_rule_count: None,
            anomalies: Vec::new(),
            findings: Vec::new(),
            unavailable_reason: None,
            scroll: 0,
        }
    }

    /// Whether the section has a modal open. Read-only section → never.
    #[must_use]
    pub fn has_modal(&self) -> bool {
        false
    }

    /// Live connection count for the sidebar badge. `None` when the backend
    /// is unavailable so the badge stays honestly empty.
    #[must_use]
    pub fn badge_count(&self) -> Option<usize> {
        if self.available {
            Some(self.connections.len())
        } else {
            None
        }
    }

    /// Current scroll offset (used by dashboard tests).
    #[cfg(test)]
    pub fn scroll(&self) -> usize {
        self.scroll
    }

    // ── Data setters ─────────────────────────────────────────────────────────

    /// Replace the snapshot summary.
    pub fn set_summary(&mut self, summary: SnapshotSummary) {
        self.summary = summary;
    }

    /// Replace the connections list and clamp scroll.
    pub fn set_connections(&mut self, connections: Vec<ConnectionEntry>) {
        self.connections = connections;
        self.clamp_scroll();
    }

    /// Replace the listening-ports list and clamp scroll.
    pub fn set_ports(&mut self, ports: Vec<PortEntry>) {
        self.ports = ports;
        self.clamp_scroll();
    }

    /// Replace the conntrack summary.
    pub fn set_conntrack(&mut self, conntrack: ConntrackSummary) {
        self.conntrack = conntrack;
    }

    /// Replace the OUTPUT-chain LOG-rule count.
    pub fn set_output_rule_count(&mut self, count: Option<usize>) {
        self.output_rule_count = count;
    }

    /// Replace the anomaly findings and clamp scroll.
    pub fn set_anomalies(&mut self, anomalies: Vec<AnomalyEntry>) {
        self.anomalies = anomalies;
        self.clamp_scroll();
    }

    /// Replace the doctor findings and clamp scroll.
    pub fn set_findings(&mut self, findings: Vec<FindingEntry>) {
        self.findings = findings;
        self.clamp_scroll();
    }

    /// Set the overall availability flag (false → degraded panel).
    pub fn set_available(&mut self, available: bool) {
        self.available = available;
    }

    /// Set the human-readable reason the backend was unreachable. Cleared
    /// (`None`) whenever availability flips back to `true` so a stale reason
    /// can't linger after recovery.
    pub fn set_unavailable_reason(&mut self, reason: Option<String>) {
        self.unavailable_reason = if self.available { None } else { reason };
    }

    // ── Input ────────────────────────────────────────────────────────────────

    /// Handle a key press. Returns `Some(Action)` only for navigation keys
    /// (Esc → Back); scroll keys are consumed here.
    pub fn handle_key(&mut self, code: KeyCode) -> Option<Action> {
        match code {
            KeyCode::Down | KeyCode::Char('j') => {
                self.scroll = self.scroll.saturating_add(1);
                None
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.scroll = self.scroll.saturating_sub(1);
                None
            }
            KeyCode::PageDown => {
                self.scroll = self.scroll.saturating_add(8);
                None
            }
            KeyCode::PageUp => {
                self.scroll = self.scroll.saturating_sub(8);
                None
            }
            KeyCode::Esc => Some(Action::Back),
            _ => None,
        }
    }

    /// Handle a mouse event (scroll wheel only — no click targets).
    pub fn handle_mouse(&mut self, mouse: MouseEvent) -> Option<Action> {
        match mouse.kind {
            MouseEventKind::ScrollDown => {
                self.scroll = self.scroll.saturating_add(1);
                None
            }
            MouseEventKind::ScrollUp => {
                self.scroll = self.scroll.saturating_sub(1);
                None
            }
            _ => None,
        }
    }

    /// Clamp scroll against a (post-layout) max. Called by the render path
    /// once the visible row count is known, since `view` is the only place
    /// that knows the inner pane height.
    fn clamp_scroll_to(&mut self, max_scroll: usize) {
        if self.scroll > max_scroll {
            self.scroll = max_scroll;
        }
    }

    /// Generic clamp after a data setter (defensive — the real clamp happens
    /// at render time once the pane height is known).
    #[expect(
        clippy::unused_self,
        reason = "API symmetry with other scrollable panes"
    )]
    fn clamp_scroll(&mut self) {
        // No-op body: scroll is clamped against visible rows during render.
    }

    // ── Rendering ───────────────────────────────────────────────────────────

    /// Render the full monitor content area.
    pub fn view(&mut self, frame: &mut Frame, area: Rect, p: Palette) {
        if !self.available {
            self.render_unavailable(frame, area, p);
            return;
        }

        let inner = render_titled_panel(
            frame,
            area,
            p,
            &format!(
                " MONITOR · {} conn(s) · {} port(s) · {} anomaly/ies · {} finding(s) ",
                self.connections.len(),
                self.ports.len(),
                self.anomalies.len(),
                self.findings.len(),
            ),
            p.accent,
            true,
        );

        if inner.height == 0 {
            return;
        }

        // Build the full content as a Vec<Line> then render only the visible
        // window (mirrors the SSH / fail2ban tabs' manual-scroll approach).
        let lines = self.build_lines(p);

        let visible = inner.height as usize;
        let max_scroll = lines.len().saturating_sub(visible);
        self.clamp_scroll_to(max_scroll);
        let start = self.scroll.min(max_scroll);

        for (row, line) in lines.iter().skip(start).take(visible).enumerate() {
            let y = inner.y + u16::try_from(row).unwrap_or(u16::MAX);
            if y >= inner.bottom() {
                break;
            }
            let row_area = Rect::new(inner.x, y, inner.width, 1);
            frame.render_widget(Paragraph::new(line.clone()), row_area);
        }
    }

    /// Render the degraded state when the monitor backend is unavailable on
    /// this host.
    ///
    /// `available == false` is set when `MonitorClient::system()` returned an
    /// error (typically `BinaryNotFound` on macOS, where `iptables`,
    /// `iptables-save`, `conntrack`, `ss`, or `journalctl` are missing) or
    /// when the `spawn_blocking` collection task panicked (`JoinError`). The
    /// reason string is surfaced here so the operator can see what actually
    /// went wrong; when no reason is known we fall back to a generic,
    /// accurate message.
    fn render_unavailable(&self, frame: &mut Frame, area: Rect, p: Palette) {
        let inner = render_titled_panel(frame, area, p, " MONITOR ", p.text_dim, false);
        // Symmetric defensive posture with the available `view()` path: a
        // zero-height inner rect (e.g. tiny terminal clipped after the panel
        // border is drawn) renders nothing. ratatui would no-op the Paragraph
        // writes anyway, but the early return keeps the two render paths
        // consistent and avoids the saturating centering math below.
        if inner.height == 0 {
            return;
        }
        let msg = Line::from(vec![
            Span::styled("✦ ", Style::new().fg(p.warn)),
            Span::styled(
                "monitor unavailable",
                Style::new().fg(p.text).add_modifier(Modifier::BOLD),
            ),
        ]);
        // Prefer the concrete reason (BinaryNotFound / panic); otherwise a
        // generic message that is accurate for the macOS case.
        let detail_text = self.unavailable_reason.clone().unwrap_or_else(|| {
            "monitor backend requires iptables/conntrack/ss/journalctl (Linux)".to_string()
        });
        let detail = Line::from(Span::styled(detail_text, Style::new().fg(p.text_dim)));
        let centered_msg = Rect::new(
            inner.x,
            inner.y + inner.height.saturating_sub(3) / 2,
            inner.width,
            1,
        );
        let centered_detail = Rect::new(
            inner.x,
            inner.y + inner.height.saturating_sub(3) / 2 + 1,
            inner.width,
            1,
        );
        frame.render_widget(Paragraph::new(msg).centered(), centered_msg);
        // Wrap so a long reason wraps within the panel instead of clipping.
        frame.render_widget(
            Paragraph::new(detail).centered().wrap(Wrap { trim: false }),
            centered_detail,
        );
    }

    /// Build the complete content as a flat list of lines (summary,
    /// connections, ports, conntrack, output rules, anomalies, findings).
    /// Scrolling operates over this list.
    fn build_lines(&self, p: Palette) -> Vec<Line<'static>> {
        let mut lines: Vec<Line<'static>> = Vec::new();

        self.push_summary_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_connections_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_ports_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_conntrack_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_output_rules_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_anomalies_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_findings_lines(&mut lines, p);

        lines
    }

    fn push_summary_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        lines.push(Line::from(Span::styled(
            "Snapshot",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        let total = self.summary.total_connections;
        let uniq = self.summary.unique_destinations;
        lines.push(Line::from(vec![
            Span::styled("  conns    ", Style::new().fg(p.text_muted)),
            Span::styled(format!("{total}"), Style::new().fg(p.text)),
            Span::styled(
                format!("  ({uniq} unique dst)"),
                Style::new().fg(p.text_dim),
            ),
        ]));

        let bytes_label = self
            .summary
            .total_bytes
            .map_or_else(|| "—".to_string(), format_bytes_count);
        lines.push(Line::from(vec![
            Span::styled("  bytes    ", Style::new().fg(p.text_muted)),
            Span::styled(bytes_label, Style::new().fg(p.text)),
        ]));

        let packets_label = self
            .summary
            .total_packets
            .map_or_else(|| "—".to_string(), |n| n.to_string());
        lines.push(Line::from(vec![
            Span::styled("  packets  ", Style::new().fg(p.text_muted)),
            Span::styled(packets_label, Style::new().fg(p.text)),
        ]));
    }

    fn push_connections_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        let header = format!("Outbound Connections ({})", self.connections.len());
        lines.push(Line::from(Span::styled(
            header,
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        if self.connections.is_empty() {
            lines.push(Line::from(Span::styled(
                "  no outbound connections observed",
                Style::new().fg(p.text_dim),
            )));
            return;
        }

        for conn in &self.connections {
            let proto = truncate_str(&conn.protocol, 4);
            let src = truncate_str(&conn.src, 21);
            let dst = truncate_str(&conn.dst, 21);
            let state = truncate_str(&conn.state, 12);
            let bytes = conn.bytes.map(format_bytes_count).unwrap_or_default();
            let bytes_span = if bytes.is_empty() {
                Span::raw(String::new())
            } else {
                Span::styled(format!("  {bytes}"), Style::new().fg(p.text_dim))
            };
            lines.push(Line::from(vec![
                Span::styled(format!("{proto:<4} "), Style::new().fg(p.info)),
                Span::styled(format!("{src:<21}"), Style::new().fg(p.text_muted)),
                Span::styled(" → ", Style::new().fg(p.text_dim)),
                Span::styled(format!("{dst:<21}"), Style::new().fg(p.text)),
                Span::styled(format!(" {state:<12}"), Style::new().fg(p.text_dim)),
                bytes_span,
            ]));
        }
    }

    fn push_ports_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        let header = format!("Listening Ports ({})", self.ports.len());
        lines.push(Line::from(Span::styled(
            header,
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        if self.ports.is_empty() {
            lines.push(Line::from(Span::styled(
                "  no listening sockets",
                Style::new().fg(p.text_dim),
            )));
            return;
        }

        for port in &self.ports {
            let proto = truncate_str(&port.protocol, 4);
            let addr = truncate_str(&port.local_addr, 20);
            let state = truncate_str(&port.state, 10);
            let proc_label = match (&port.process_name, port.pid) {
                (Some(name), Some(pid)) => format!("  {name} (PID {pid})"),
                (Some(name), None) => format!("  {name}"),
                (None, Some(pid)) => format!("  PID {pid}"),
                (None, None) => String::new(),
            };
            let proc_span = if proc_label.is_empty() {
                Span::raw(String::new())
            } else {
                Span::styled(proc_label, Style::new().fg(p.text_dim))
            };
            lines.push(Line::from(vec![
                Span::styled(format!("{proto:<4} "), Style::new().fg(p.accent3)),
                Span::styled(
                    format!("{addr:<20}:{:<6}", port.local_port),
                    Style::new().fg(p.text),
                ),
                Span::styled(format!(" {state:<10}"), Style::new().fg(p.text_dim)),
                proc_span,
            ]));
        }
    }

    fn push_conntrack_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        lines.push(Line::from(Span::styled(
            "Conntrack",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        let count = self
            .conntrack
            .count
            .map_or_else(|| "—".to_string(), |n| n.to_string());
        lines.push(Line::from(vec![
            Span::styled("  tracked  ", Style::new().fg(p.text_muted)),
            Span::styled(count, Style::new().fg(p.text)),
        ]));

        let bytes = self
            .conntrack
            .total_bytes
            .map_or_else(|| "—".to_string(), format_bytes_count);
        lines.push(Line::from(vec![
            Span::styled("  bytes    ", Style::new().fg(p.text_muted)),
            Span::styled(bytes, Style::new().fg(p.text)),
        ]));

        let packets = self
            .conntrack
            .total_packets
            .map_or_else(|| "—".to_string(), |n| n.to_string());
        lines.push(Line::from(vec![
            Span::styled("  packets  ", Style::new().fg(p.text_muted)),
            Span::styled(packets, Style::new().fg(p.text)),
        ]));
    }

    fn push_output_rules_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        lines.push(Line::from(Span::styled(
            "OUTPUT Chain LOG Rules",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));
        let (icon, text, color) = match self.output_rule_count {
            Some(0) => ("○", "no LOG rules installed".to_string(), p.warn),
            Some(n) => ("●", format!("{n} LOG rule(s) installed"), p.ok),
            None => ("?", "iptables-save unavailable".to_string(), p.text_dim),
        };
        lines.push(Line::from(vec![
            Span::styled("  rules    ", Style::new().fg(p.text_muted)),
            Span::styled(format!("{icon} {text}"), Style::new().fg(color)),
        ]));
    }

    fn push_anomalies_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        let header = format!("Anomaly Findings ({})", self.anomalies.len());
        lines.push(Line::from(Span::styled(
            header,
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        if self.anomalies.is_empty() {
            lines.push(Line::from(Span::styled(
                "  no anomalies detected",
                Style::new().fg(p.text_dim),
            )));
            return;
        }

        // Group by severity: Critical > Error > Warning > Info.
        let order = ["critical", "error", "warning", "info"];
        for sev in order {
            let group: Vec<&AnomalyEntry> = self
                .anomalies
                .iter()
                .filter(|f| f.severity == sev)
                .collect();
            if group.is_empty() {
                continue;
            }
            let (icon, color) = crate::ui::screens::findings::severity_style_full(sev, p);
            lines.push(Line::from(vec![
                Span::styled(
                    format!("{icon} "),
                    Style::new().fg(color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{} ({})", sev.to_uppercase(), group.len()),
                    Style::new().fg(color).add_modifier(Modifier::BOLD),
                ),
            ]));
            for a in group {
                let title = truncate_str(&a.title, 60);
                lines.push(Line::from(vec![
                    Span::styled("    · ", Style::new().fg(p.text_dim)),
                    Span::styled(title, Style::new().fg(p.text)),
                ]));
                if !a.observed.is_empty() || !a.threshold.is_empty() {
                    let detail = truncate_str(
                        &format!("observed {}  ·  threshold {}", a.observed, a.threshold),
                        74,
                    );
                    lines.push(Line::from(Span::styled(
                        format!("      {detail}"),
                        Style::new().fg(p.text_dim),
                    )));
                }
                if let Some(ref fix) = a.fix {
                    let fix = truncate_str(fix, 70);
                    lines.push(Line::from(vec![
                        Span::styled("      → ", Style::new().fg(p.accent2)),
                        Span::styled(fix, Style::new().fg(p.accent2)),
                    ]));
                }
            }
        }
    }

    fn push_findings_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        // Group by severity: Critical > Error > Warning > Info.
        const ORDER: &[&str] = &["critical", "error", "warning", "info"];
        crate::ui::screens::findings::push_findings_grouped(
            lines,
            p,
            &self.findings,
            ORDER,
            crate::ui::screens::findings::severity_style_full,
            crate::ui::screens::findings::FindingWidths::TITLE_60,
        );
    }
}

impl crate::ui::screens::section_overview::SectionOverview for MonitorContent {
    fn available(&self) -> bool {
        self.available
    }

    fn status_label(&self) -> &'static str {
        crate::ui::screens::section_overview::status_label_for(
            self.available,
            self.findings
                .iter()
                .map(|f| f.severity.as_str())
                .chain(self.anomalies.iter().map(|a| a.severity.as_str())),
        )
    }

    fn detail(&self) -> Option<String> {
        if !self.available {
            return None;
        }
        Some(format!(
            "{} conn(s) · {} port(s)",
            self.connections.len(),
            self.ports.len()
        ))
    }

    fn findings_count(&self) -> usize {
        self.findings.len() + self.anomalies.len()
    }
}

impl crate::ui::screens::findings::Finding for FindingEntry {
    fn severity(&self) -> &str {
        &self.severity
    }
    fn title(&self) -> &str {
        &self.title
    }
    fn detail(&self) -> Option<&str> {
        Some(&self.detail)
    }
    fn fix(&self) -> Option<&str> {
        self.fix.as_deref()
    }
}

/// Format a byte count as a human-readable string (B / KB / MB / GB).
#[expect(clippy::cast_precision_loss, reason = "display-only")]
fn format_bytes_count(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::theme::CHARM;
    use ratatui::{Terminal, backend::TestBackend};

    fn sample_connections() -> Vec<ConnectionEntry> {
        vec![
            ConnectionEntry {
                protocol: "tcp".into(),
                src: "10.0.0.2:54321".into(),
                dst: "93.184.216.34:443".into(),
                state: "ESTABLISHED".into(),
                bytes: Some(2048),
            },
            ConnectionEntry {
                protocol: "tcp".into(),
                src: "10.0.0.2:54322".into(),
                dst: "1.1.1.1:53".into(),
                state: "TIME-WAIT".into(),
                bytes: None,
            },
        ]
    }

    fn sample_ports() -> Vec<PortEntry> {
        vec![
            PortEntry {
                protocol: "tcp".into(),
                ip_version: "IPv4".into(),
                local_addr: "0.0.0.0".into(),
                local_port: 22,
                state: "LISTEN".into(),
                process_name: Some("sshd".into()),
                pid: Some(842),
            },
            PortEntry {
                protocol: "udp".into(),
                ip_version: "IPv6".into(),
                local_addr: "::".into(),
                local_port: 5353,
                state: "UDP".into(),
                process_name: None,
                pid: None,
            },
        ]
    }

    fn sample_anomalies() -> Vec<AnomalyEntry> {
        vec![AnomalyEntry {
            id: "anomaly.connection-volume".into(),
            severity: "warning".into(),
            title: "Outbound connection volume exceeds threshold".into(),
            observed: "650 connections".into(),
            threshold: "500 connections".into(),
            fix: Some("Investigate processes with high outbound connection counts.".into()),
        }]
    }

    fn sample_findings() -> Vec<FindingEntry> {
        vec![
            FindingEntry {
                id: "doctor.binary.iptables.missing".into(),
                severity: "critical".into(),
                title: "Required binary not found: iptables".into(),
                detail: "Expected at: /usr/sbin/iptables".into(),
                fix: Some("Install the package providing iptables.".into()),
            },
            FindingEntry {
                id: "doctor.logging.no-rules".into(),
                severity: "warning".into(),
                title: "No OUTPUT chain LOG rules configured".into(),
                detail: String::new(),
                fix: Some("Run monitor setup to install logging rules.".into()),
            },
        ]
    }

    /// Render a content area to a string (snapshot pattern from fail2ban).
    fn render_to_string(content: &mut MonitorContent, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| content.view(f, f.area(), CHARM)).unwrap();
        terminal.backend().to_string()
    }

    #[test]
    fn new_is_unavailable_and_empty() {
        let c = MonitorContent::new();
        assert!(!c.available);
        assert!(c.connections.is_empty());
        assert!(c.ports.is_empty());
        assert!(c.anomalies.is_empty());
        assert!(c.findings.is_empty());
        assert!(!c.has_modal());
    }

    #[test]
    fn default_matches_new() {
        let from_new = MonitorContent::new();
        let from_default = MonitorContent::default();
        assert_eq!(from_new.available, from_default.available);
    }

    #[test]
    fn render_unavailable_when_not_available() {
        let mut c = MonitorContent::new();
        let out = render_to_string(&mut c, 100, 24);
        assert!(out.contains("monitor unavailable"), "degraded panel: {out}");
    }

    #[test]
    fn render_unavailable_reason_is_surfaced() {
        let mut c = MonitorContent::new();
        c.set_unavailable_reason(Some("binary not found: iptables".into()));
        let out = render_to_string(&mut c, 100, 24);
        assert!(out.contains("binary not found: iptables"), "reason: {out}");
    }

    #[test]
    fn set_unavailable_reason_clears_when_available() {
        let mut c = MonitorContent::new();
        // While unavailable, the reason sticks.
        c.set_unavailable_reason(Some("boom".into()));
        assert_eq!(c.unavailable_reason.as_deref(), Some("boom"));
        // Flipping available true must clear the reason.
        c.set_available(true);
        c.set_unavailable_reason(Some("boom".into()));
        assert!(c.unavailable_reason.is_none());
    }

    #[test]
    fn render_summary_panel() {
        let mut c = MonitorContent::new();
        c.set_available(true);
        c.set_summary(SnapshotSummary {
            total_connections: 42,
            unique_destinations: 17,
            total_bytes: Some(5 * 1024 * 1024),
            total_packets: Some(9001),
        });
        let out = render_to_string(&mut c, 100, 30);
        assert!(out.contains("42"), "total conns: {out}");
        assert!(out.contains("17"), "unique dst: {out}");
        assert!(out.contains("5.0 MB"), "bytes: {out}");
        assert!(out.contains("9001"), "packets: {out}");
    }

    #[test]
    fn render_connections_table() {
        let mut c = MonitorContent::new();
        c.set_available(true);
        c.set_connections(sample_connections());
        let out = render_to_string(&mut c, 110, 36);
        assert!(out.contains("93.184.216.34:443"), "dst: {out}");
        assert!(out.contains("ESTABLISHED"), "state: {out}");
        assert!(out.contains("2.0 KB"), "bytes: {out}");
    }

    #[test]
    fn render_ports_list() {
        let mut c = MonitorContent::new();
        c.set_available(true);
        c.set_ports(sample_ports());
        let out = render_to_string(&mut c, 110, 36);
        assert!(out.contains("sshd"), "process: {out}");
        assert!(out.contains("842"), "pid: {out}");
        assert!(out.contains("5353"), "udp port: {out}");
    }

    #[test]
    fn render_conntrack_summary() {
        let mut c = MonitorContent::new();
        c.set_available(true);
        c.set_conntrack(ConntrackSummary {
            count: Some(128),
            total_bytes: Some(1024 * 1024 * 10),
            total_packets: Some(4096),
        });
        let out = render_to_string(&mut c, 100, 30);
        assert!(out.contains("128"), "count: {out}");
        assert!(out.contains("10.0 MB"), "bytes: {out}");
        assert!(out.contains("4096"), "packets: {out}");
    }

    #[test]
    fn render_output_rules_count() {
        let mut c = MonitorContent::new();
        c.set_available(true);
        c.set_output_rule_count(Some(3));
        let out = render_to_string(&mut c, 100, 30);
        assert!(out.contains("3 LOG rule(s)"), "rule count: {out}");
    }

    #[test]
    fn render_output_rules_zero() {
        let mut c = MonitorContent::new();
        c.set_available(true);
        c.set_output_rule_count(Some(0));
        let out = render_to_string(&mut c, 100, 30);
        assert!(out.contains("no LOG rules"), "zero rules: {out}");
    }

    #[test]
    fn render_anomalies_grouped_by_severity() {
        let mut c = MonitorContent::new();
        c.set_available(true);
        c.set_anomalies(sample_anomalies());
        let out = render_to_string(&mut c, 110, 40);
        assert!(out.contains("WARNING"), "severity group header: {out}");
        assert!(
            out.contains("connection volume exceeds"),
            "anomaly title: {out}"
        );
        assert!(out.contains("Investigate processes"), "fix hint: {out}");
    }

    #[test]
    fn render_findings_grouped_by_severity() {
        let mut c = MonitorContent::new();
        c.set_available(true);
        c.set_findings(sample_findings());
        let out = render_to_string(&mut c, 110, 40);
        assert!(out.contains("CRITICAL"), "critical header: {out}");
        assert!(out.contains("iptables"), "finding title: {out}");
    }

    #[test]
    fn scroll_down_consumed_and_returns_none() {
        let mut c = MonitorContent::new();
        c.set_available(true);
        assert!(c.handle_key(KeyCode::Down).is_none());
        assert_eq!(c.scroll, 1);
    }

    #[test]
    fn scroll_up_at_zero_stays_zero() {
        let mut c = MonitorContent::new();
        c.set_available(true);
        c.handle_key(KeyCode::Up);
        assert_eq!(c.scroll, 0);
    }

    #[test]
    fn esc_returns_back_action() {
        let mut c = MonitorContent::new();
        assert_eq!(c.handle_key(KeyCode::Esc), Some(Action::Back));
    }

    #[test]
    fn mouse_scroll_wheel_adjusts_scroll() {
        let mut c = MonitorContent::new();
        let down = MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: 0,
            row: 0,
            modifiers: crossterm::event::KeyModifiers::empty(),
        };
        c.handle_mouse(down);
        assert_eq!(c.scroll, 1);
    }

    #[test]
    fn tiny_terminal_does_not_panic() {
        let mut c = MonitorContent::new();
        c.set_available(true);
        c.set_connections(sample_connections());
        c.set_findings(sample_findings());
        // 20x5 — well below comfortable, must not panic.
        let _ = render_to_string(&mut c, 20, 5);
    }

    #[test]
    fn render_unavailable_zero_height_does_not_panic() {
        // Pins the `inner.height == 0` early-return guard in
        // `render_unavailable`: a clipped panel rect (the border consumes the
        // single row, leaving inner.height == 0) must render as a no-op
        // without panicking in the centering math.
        let mut c = MonitorContent::new();
        // Unavailable path is taken when available == false (the default).
        c.set_unavailable_reason(Some("clipped".into()));
        // height 1 → the panel border fills the only row, inner.height == 0.
        let _ = render_to_string(&mut c, 80, 1);
    }

    #[test]
    fn render_unavailable_zero_height_preserves_reason_without_panic() {
        // Companion to the above: even with a reason set, the zero-height
        // path must early-return before touching the reason string.
        let mut c = MonitorContent::new();
        c.set_unavailable_reason(Some("a very long reason ".repeat(50)));
        let _ = render_to_string(&mut c, 1, 1);
    }

    #[test]
    fn empty_states_render_without_panic() {
        let mut c = MonitorContent::new();
        c.set_available(true);
        let out = render_to_string(&mut c, 100, 30);
        assert!(
            out.contains("no outbound connections"),
            "empty conns: {out}"
        );
        assert!(out.contains("no listening sockets"), "empty ports: {out}");
        assert!(out.contains("no anomalies"), "empty anomalies: {out}");
        assert!(out.contains("no findings"), "empty findings: {out}");
    }

    #[test]
    fn format_bytes_count_boundaries() {
        // Table-driven boundary coverage — the render tests only assert
        // substrings like "5.0 MB", so this pins the exact unit thresholds
        // and degenerate values (0, unit boundaries, one-below boundaries).
        const KB: u64 = 1024;
        const MB: u64 = 1024 * KB;
        const GB: u64 = 1024 * MB;
        let cases: &[(u64, &str)] = &[
            (0, "0 B"),
            (1023, "1023 B"),
            (KB - 1, "1023 B"),
            (KB, "1.0 KB"),
            (MB - 1, "1024.0 KB"),
            (MB, "1.0 MB"),
            (5 * MB, "5.0 MB"),
            (GB - 1, "1024.0 MB"),
            (GB, "1.0 GB"),
        ];
        for &(input, expected) in cases {
            assert_eq!(format_bytes_count(input), expected, "input = {input}");
        }
        // u64::MAX must not panic; the helper caps at GB so it lands in the
        // GB branch (large float). Only assert the branch, not the exact
        // rendering — the float magnitude is implementation-defined.
        let max_str = format_bytes_count(u64::MAX);
        assert!(max_str.ends_with(" GB"), "u64::MAX renders as {max_str}");
    }

    /// Regression: monitor is the only section that carries two elevated-
    /// severity collections (`findings` and `anomalies`). The
    /// [`SectionOverview`](crate::ui::screens::section_overview::SectionOverview)
    /// impl must fold anomalies into BOTH the severity iteration (so a
    /// critical-only anomaly flips the status to `degraded`) and the count
    /// (so the FINDINGS stat card is bumped). Mirrors
    /// `derived_findings_and_available_match_standalone_methods` in
    /// `dashboard.rs`: with zero doctor findings but an elevated-severity
    /// anomaly, the overview must report `degraded` and the bumped count.
    #[test]
    fn overview_folds_anomalies_into_status_and_count() {
        use crate::ui::screens::section_overview::SectionOverview;

        // ── Baseline: available, no findings, no anomalies → active, 0. ──
        let mut c = MonitorContent::new();
        c.set_available(true);
        c.set_findings(Vec::new());
        c.set_anomalies(Vec::new());
        assert_eq!(c.status_label(), "active");
        assert_eq!(c.findings_count(), 0);

        // ── Critical anomaly with zero doctor findings. ──
        // Before the fix this reported `active · 0 finding(s)`, contradicting
        // the monitor screen's own anomaly grouping. Now it must be degraded
        // with the anomaly counted.
        c.set_anomalies(vec![AnomalyEntry {
            id: "anomaly.connection-volume".into(),
            severity: "critical".into(),
            title: "Outbound connection volume exceeds threshold".into(),
            observed: "650 connections".into(),
            threshold: "500 connections".into(),
            fix: Some("Investigate high outbound connection counts.".into()),
        }]);
        assert_eq!(
            c.status_label(),
            "degraded",
            "critical anomaly must flip status to degraded"
        );
        assert_eq!(
            c.findings_count(),
            1,
            "findings_count must include anomalies"
        );

        // ── Both axes populated: counts must sum. ──
        // 2 doctor findings + 1 anomaly = 3.
        c.set_findings(sample_findings());
        assert_eq!(c.findings_count(), 3);

        // ── Warning-severity anomaly also degrades (plan rule). ──
        let mut w = MonitorContent::new();
        w.set_available(true);
        w.set_anomalies(vec![AnomalyEntry {
            id: "anomaly.ports.unexpected".into(),
            severity: "warning".into(),
            title: "Unexpected listening port".into(),
            observed: "0.0.0.0:1337".into(),
            threshold: "no unbound listeners".into(),
            fix: None,
        }]);
        assert_eq!(w.status_label(), "degraded");
        assert_eq!(w.findings_count(), 1);

        // ── Info-severity anomaly alone must NOT degrade (not in the
        // elevated set), but still counts toward findings_count. ──
        let mut i = MonitorContent::new();
        i.set_available(true);
        i.set_anomalies(vec![AnomalyEntry {
            id: "anomaly.info-note".into(),
            severity: "info".into(),
            title: "informational note".into(),
            observed: "n/a".into(),
            threshold: "n/a".into(),
            fix: None,
        }]);
        assert_eq!(i.status_label(), "active");
        assert_eq!(i.findings_count(), 1);

        // ── Offline (unavailable) dominates regardless of anomalies. ──
        let mut off = MonitorContent::new();
        off.set_available(false);
        off.set_anomalies(vec![AnomalyEntry {
            id: "anomaly.connection-volume".into(),
            severity: "critical".into(),
            title: "ignored when offline".into(),
            observed: "650".into(),
            threshold: "500".into(),
            fix: None,
        }]);
        assert_eq!(off.status_label(), "offline");
        // Count is independent of availability (mirrors `findings_total()`).
        assert_eq!(off.findings_count(), 1);
    }
}
