//! Tailscale management content area (live READ-ONLY).
//!
//! Renders inside the dashboard's content region when
//! [`Section::Tailscale`](crate::data::Section) is the active sidebar section.
//! Mirrors the read-only fail2ban/cloud sections: every line is read-only, there
//! are no write operations, no optimistic updates, no loading spinner.
//!
//! Layout (single scrollable pane, no sub-tab bar):
//! 1. Status panel — connected badge, node name, tailnet, IPs, exit node.
//! 2. Peers table — name, IPs, online state, exit-node flag.
//! 3. Netcheck / DERP — UDP/IPv6/Hairpin flags + per-region DERP latencies.
//! 4. DNS — `MagicDNS`, nameservers, search domains.
//! 5. Doctor findings — grouped by severity (Critical > Warning > Info > Ok).

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

/// A single tailnet peer row.
#[derive(Clone, Debug)]
pub struct PeerEntry {
    /// Peer hostname.
    pub name: String,
    /// Tailscale IP addresses for the peer.
    pub ip_addresses: Vec<String>,
    /// Whether the peer is online and reachable.
    pub online: bool,
    /// Whether the peer is an exit node.
    pub exit_node: bool,
}

/// A single DERP region latency row.
#[derive(Clone, Debug)]
pub struct DerpLatencyEntry {
    /// Region label.
    pub region: String,
    /// Round-trip latency in milliseconds.
    pub latency_ms: f64,
}

/// A single port-mapping probe row.
#[derive(Clone, Debug)]
pub struct PortMapEntry {
    /// Probe name (e.g. `UPnP`, `PMP`, `PCP`).
    pub name: String,
    /// Whether the port-mapping method is available.
    pub open: bool,
}

/// DNS configuration summary.
#[derive(Clone, Debug)]
pub struct DnsInfo {
    /// Whether `MagicDNS` is enabled.
    pub magic_dns: bool,
    /// Custom DNS resolver addresses.
    pub nameservers: Vec<String>,
    /// Search domains appended to DNS queries.
    pub search_domains: Vec<String>,
    /// Split DNS configurations: domain -> nameserver.
    pub split_dns: Vec<(String, String)>,
}

/// A single doctor finding.
#[derive(Clone, Debug)]
pub struct TailscaleFindingEntry {
    /// Machine-readable dot-separated id (e.g. "tailscale.connected").
    pub id: String,
    /// Severity as a lowercase string: "ok" | "info" | "warning" | "critical".
    pub severity: String,
    /// Human-readable message (the backend's single `message` field).
    pub title: String,
    /// Suggested remediation, if any.
    pub fix: Option<String>,
}

// ── TailscaleContent ────────────────────────────────────────────────────────

/// Tailscale management content rendered inside the dashboard content area.
///
/// READ-ONLY: there are no write operations, no optimistic updates, no loading
/// spinner, no cooldown. Data arrives via [`TailscaleContent::set_*`] setters
/// driven by [`TailscaleCollector`](crate::toride_tailscale_data::TailscaleCollector).
#[expect(
    clippy::struct_excessive_bools,
    reason = "domain state flags, each independently sourced"
)]
pub struct TailscaleContent {
    /// Whether the Tailscale backend (local HTTP API) was reachable at all. `false`
    /// means the section renders a degraded "unavailable" panel instead of live data.
    available: bool,
    /// Whether the node is connected to the tailnet.
    connected: bool,
    /// Hostname as seen in the tailnet.
    node_name: String,
    /// Tailnet name.
    tailnet: String,
    /// Tailscale IP addresses assigned to this node.
    ip_addresses: Vec<String>,
    /// Exit node in use, if any.
    exit_node: Option<String>,
    /// Whether `MagicDNS` is enabled (from the status report).
    dns_enabled: bool,
    /// Peers in the tailnet.
    peers: Vec<PeerEntry>,
    /// Netcheck connectivity flag.
    nc_connectivity: bool,
    /// Preferred DERP region.
    nc_derp_region: Option<String>,
    /// Per-region DERP latencies (already sorted ascending by the convert layer).
    nc_derp_latency: Vec<DerpLatencyEntry>,
    /// UDP availability.
    nc_udp: bool,
    /// IPv6 availability.
    nc_ipv6: bool,
    /// Hairpin NAT availability.
    nc_hairpin: bool,
    /// Port-mapping probes.
    nc_port_mapping: Vec<PortMapEntry>,
    /// DNS configuration (from the dedicated DNS query).
    dns: DnsInfo,
    /// Doctor findings.
    findings: Vec<TailscaleFindingEntry>,
    /// Human-readable reason the backend was unreachable, surfaced in the degraded
    /// panel. Populated only when a collection task returned `available = false`.
    unavailable_reason: Option<String>,
    /// Vertical scroll offset over the whole pane.
    scroll: usize,
}

impl Default for TailscaleContent {
    fn default() -> Self {
        Self::new()
    }
}

impl TailscaleContent {
    /// Create a new empty content area.
    #[must_use]
    pub fn new() -> Self {
        Self {
            available: false,
            connected: false,
            node_name: String::new(),
            tailnet: String::new(),
            ip_addresses: Vec::new(),
            exit_node: None,
            dns_enabled: false,
            peers: Vec::new(),
            nc_connectivity: false,
            nc_derp_region: None,
            nc_derp_latency: Vec::new(),
            nc_udp: false,
            nc_ipv6: false,
            nc_hairpin: false,
            nc_port_mapping: Vec::new(),
            dns: DnsInfo {
                magic_dns: false,
                nameservers: Vec::new(),
                search_domains: Vec::new(),
                split_dns: Vec::new(),
            },
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

    /// Live peer count for the sidebar badge. `None` when the backend is
    /// unavailable so the badge stays honestly empty.
    #[must_use]
    pub fn badge_count(&self) -> Option<usize> {
        if self.available {
            Some(self.peers.len())
        } else {
            None
        }
    }

    // ── Data setters ─────────────────────────────────────────────────────────

    /// Replace the local-node status fields (drives the status panel).
    pub fn set_status(
        &mut self,
        connected: bool,
        node_name: String,
        tailnet: String,
        ip_addresses: Vec<String>,
        exit_node: Option<String>,
        dns_enabled: bool,
    ) {
        self.connected = connected;
        self.node_name = node_name;
        self.tailnet = tailnet;
        self.ip_addresses = ip_addresses;
        self.exit_node = exit_node;
        self.dns_enabled = dns_enabled;
    }

    /// Replace the peers list.
    pub fn set_peers(&mut self, peers: Vec<PeerEntry>) {
        self.peers = peers;
        self.clamp_scroll();
    }

    /// Replace the netcheck fields.
    #[expect(
        clippy::too_many_arguments,
        reason = "netcheck probe fields map 1:1 to the report"
    )]
    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "netcheck probe fields map 1:1 to the report"
    )]
    pub fn set_netcheck(
        &mut self,
        connectivity: bool,
        derp_region: Option<String>,
        derp_latency: Vec<DerpLatencyEntry>,
        udp: bool,
        ipv6: bool,
        hairpin: bool,
        port_mapping: Vec<PortMapEntry>,
    ) {
        self.nc_connectivity = connectivity;
        self.nc_derp_region = derp_region;
        self.nc_derp_latency = derp_latency;
        self.nc_udp = udp;
        self.nc_ipv6 = ipv6;
        self.nc_hairpin = hairpin;
        self.nc_port_mapping = port_mapping;
        self.clamp_scroll();
    }

    /// Replace the DNS configuration.
    pub fn set_dns(&mut self, dns: DnsInfo) {
        self.dns = dns;
        self.clamp_scroll();
    }

    /// Replace the findings list.
    pub fn set_findings(&mut self, findings: Vec<TailscaleFindingEntry>) {
        self.findings = findings;
        self.clamp_scroll();
    }

    /// Set the overall availability flag (false → degraded panel).
    pub fn set_available(&mut self, available: bool) {
        self.available = available;
    }

    /// Set the human-readable reason the backend was unreachable. Cleared
    /// (`None`) whenever availability flips back to `true` so a stale panic
    /// message can't linger after recovery.
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

    /// Clamp scroll against a (post-layout) max. Called by the render path once the
    /// visible row count is known, since `view` is the only place that knows the inner
    /// pane height.
    fn clamp_scroll_to(&mut self, max_scroll: usize) {
        if self.scroll > max_scroll {
            self.scroll = max_scroll;
        }
    }

    /// Generic clamp after a data setter (defensive — the real clamp happens at render
    /// time once the pane height is known).
    #[expect(
        clippy::unused_self,
        reason = "API symmetry with other scrollable panes"
    )]
    fn clamp_scroll(&mut self) {
        // No-op body: scroll is clamped against visible rows during render.
    }

    /// Current scroll offset (used by the dashboard dispatch regression test).
    #[cfg(test)]
    pub fn scroll(&self) -> usize {
        self.scroll
    }

    // ── Rendering ───────────────────────────────────────────────────────────

    /// Render the full Tailscale content area.
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
                " TAILSCALE · {} peer(s) · {} DERP region(s) · {} finding(s) ",
                self.peers.len(),
                self.nc_derp_latency.len(),
                self.findings.len(),
            ),
            p.accent,
            true,
        );

        if inner.height == 0 {
            return;
        }

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

    /// Render the degraded state when the Tailscale local API is unreachable.
    ///
    /// `available == false` is set when the HTTP API (localhost:41642) did not respond
    /// within the 3s timeout — i.e. tailscaled is absent or not running. The reason
    /// string (if any) is surfaced so the operator sees what went wrong; when no reason
    /// is known we fall back to an accurate "daemon unreachable" message.
    fn render_unavailable(&self, frame: &mut Frame, area: Rect, p: Palette) {
        let inner = render_titled_panel(frame, area, p, " TAILSCALE ", p.text_dim, false);
        let msg = Line::from(vec![
            Span::styled("✦ ", Style::new().fg(p.warn)),
            Span::styled(
                "tailscale unavailable",
                Style::new().fg(p.text).add_modifier(Modifier::BOLD),
            ),
        ]);
        // Prefer the reason from the bundle; otherwise the generic message that covers
        // the no-daemon and pre-first-poll cases.
        let detail_text = self
            .unavailable_reason
            .clone()
            .unwrap_or_else(|| "Tailscale daemon (localhost:41642) is not reachable".to_string());
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
        frame.render_widget(
            Paragraph::new(detail).centered().wrap(Wrap { trim: false }),
            centered_detail,
        );
    }

    /// Build the complete content as a flat list of lines (status, peers, netcheck,
    /// dns, findings). Scrolling operates over this list.
    fn build_lines(&self, p: Palette) -> Vec<Line<'static>> {
        let mut lines: Vec<Line<'static>> = Vec::new();

        self.push_status_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_peers_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_netcheck_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_dns_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_findings_lines(&mut lines, p);

        lines
    }

    fn push_status_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        lines.push(Line::from(Span::styled(
            "This Node",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        // Connected badge.
        let (conn_label, conn_color) = if self.connected {
            ("● connected", p.ok)
        } else {
            ("○ disconnected", p.err)
        };
        lines.push(Line::from(vec![
            Span::styled("  state     ", Style::new().fg(p.text_muted)),
            Span::styled(conn_label, Style::new().fg(conn_color)),
        ]));

        let node_name = if self.node_name.is_empty() {
            "(unknown)"
        } else {
            &self.node_name
        };
        lines.push(Line::from(vec![
            Span::styled("  host      ", Style::new().fg(p.text_muted)),
            Span::styled(truncate_str(node_name, 40), Style::new().fg(p.text)),
        ]));

        let tailnet = if self.tailnet.is_empty() {
            "(unknown)"
        } else {
            &self.tailnet
        };
        lines.push(Line::from(vec![
            Span::styled("  tailnet   ", Style::new().fg(p.text_muted)),
            Span::styled(truncate_str(tailnet, 40), Style::new().fg(p.text)),
        ]));

        let ips = if self.ip_addresses.is_empty() {
            "(none)".to_string()
        } else {
            self.ip_addresses.join(", ")
        };
        lines.push(Line::from(vec![
            Span::styled("  ips       ", Style::new().fg(p.text_muted)),
            Span::styled(ips, Style::new().fg(p.text)),
        ]));

        let exit = self.exit_node.clone().unwrap_or_else(|| "(none)".into());
        lines.push(Line::from(vec![
            Span::styled("  exit node ", Style::new().fg(p.text_muted)),
            Span::styled(exit, Style::new().fg(p.text)),
        ]));

        let (dns_label, dns_color) = if self.dns_enabled {
            ("● on", p.ok)
        } else {
            ("○ off", p.text_dim)
        };
        lines.push(Line::from(vec![
            Span::styled("  MagicDNS  ", Style::new().fg(p.text_muted)),
            Span::styled(dns_label, Style::new().fg(dns_color)),
        ]));
    }

    fn push_peers_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        let header = format!("Peers ({})", self.peers.len());
        lines.push(Line::from(Span::styled(
            header,
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        if self.peers.is_empty() {
            lines.push(Line::from(Span::styled(
                "  no peers discovered",
                Style::new().fg(p.text_dim),
            )));
            return;
        }

        for peer in &self.peers {
            let state_icon = if peer.online { "●" } else { "○" };
            let state_color = if peer.online { p.ok } else { p.text_dim };
            let name = truncate_str(&peer.name, 24);
            let ips = if peer.ip_addresses.is_empty() {
                String::new()
            } else {
                peer.ip_addresses.join(",")
            };
            let exit_tag = if peer.exit_node { "  [exit]" } else { "" };
            lines.push(Line::from(vec![
                Span::styled(format!("{state_icon} "), Style::new().fg(state_color)),
                Span::styled(
                    format!("{name:<24}"),
                    Style::new().fg(p.text).add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!("  {ips}{exit_tag}"), Style::new().fg(p.text_muted)),
            ]));
        }
    }

    fn push_netcheck_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        lines.push(Line::from(Span::styled(
            "Netcheck / DERP",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        // Connectivity flag.
        let (conn_label, conn_color) = if self.nc_connectivity {
            ("✓ reachable", p.ok)
        } else {
            ("✗ unreachable", p.err)
        };
        lines.push(Line::from(vec![
            Span::styled("  coord     ", Style::new().fg(p.text_muted)),
            Span::styled(conn_label, Style::new().fg(conn_color)),
        ]));

        let region = self
            .nc_derp_region
            .clone()
            .unwrap_or_else(|| "(none)".into());
        lines.push(Line::from(vec![
            Span::styled("  DERP      ", Style::new().fg(p.text_muted)),
            Span::styled(region, Style::new().fg(p.text)),
        ]));

        // Capability flags.
        Self::push_flag_line(lines, p, "UDP     ", self.nc_udp);
        Self::push_flag_line(lines, p, "IPv6    ", self.nc_ipv6);
        Self::push_flag_line(lines, p, "Hairpin ", self.nc_hairpin);

        // Port-mapping probes.
        if !self.nc_port_mapping.is_empty() {
            lines.push(Line::from(Span::styled(
                "  port map  ",
                Style::new().fg(p.text_muted),
            )));
            for pm in &self.nc_port_mapping {
                let (icon, color) = if pm.open {
                    ("✓", p.ok)
                } else {
                    ("✗", p.text_dim)
                };
                lines.push(Line::from(vec![
                    Span::styled("    ", Style::new().fg(p.text_muted)),
                    Span::styled(format!("{icon} "), Style::new().fg(color)),
                    Span::styled(pm.name.clone(), Style::new().fg(p.text)),
                ]));
            }
        }

        // DERP latencies.
        if self.nc_derp_latency.is_empty() {
            lines.push(Line::from(Span::styled(
                "  no DERP latency data",
                Style::new().fg(p.text_dim),
            )));
        } else {
            for entry in &self.nc_derp_latency {
                // Color the latency by threshold (green < 50ms, warn < 150ms, err above),
                // reusing the format helper's thresholds conceptually.
                let color = if entry.latency_ms < 50.0 {
                    p.ok
                } else if entry.latency_ms < 150.0 {
                    p.warn
                } else {
                    p.err
                };
                lines.push(Line::from(vec![
                    Span::styled("    · ", Style::new().fg(p.text_dim)),
                    Span::styled(
                        format!("{:<16}", truncate_str(&entry.region, 16)),
                        Style::new().fg(p.text),
                    ),
                    Span::styled(
                        format!(" {:>7.1} ms", entry.latency_ms),
                        Style::new().fg(color),
                    ),
                ]));
            }
        }
    }

    fn push_flag_line(lines: &mut Vec<Line<'static>>, p: Palette, label: &str, on: bool) {
        let (icon, text, color) = if on {
            ("✓", "yes", p.ok)
        } else {
            ("✗", "no", p.text_dim)
        };
        lines.push(Line::from(vec![
            Span::styled(format!("  {label} "), Style::new().fg(p.text_muted)),
            Span::styled(format!("{icon} {text}"), Style::new().fg(color)),
        ]));
    }

    fn push_dns_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        lines.push(Line::from(Span::styled(
            "DNS",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        let (magic_label, magic_color) = if self.dns.magic_dns {
            ("● on", p.ok)
        } else {
            ("○ off", p.text_dim)
        };
        lines.push(Line::from(vec![
            Span::styled("  MagicDNS  ", Style::new().fg(p.text_muted)),
            Span::styled(magic_label, Style::new().fg(magic_color)),
        ]));

        let ns = if self.dns.nameservers.is_empty() {
            "(none)".to_string()
        } else {
            self.dns.nameservers.join(", ")
        };
        lines.push(Line::from(vec![
            Span::styled("  servers   ", Style::new().fg(p.text_muted)),
            Span::styled(ns, Style::new().fg(p.text)),
        ]));

        let search = if self.dns.search_domains.is_empty() {
            "(none)".to_string()
        } else {
            self.dns.search_domains.join(", ")
        };
        lines.push(Line::from(vec![
            Span::styled("  search    ", Style::new().fg(p.text_muted)),
            Span::styled(search, Style::new().fg(p.text)),
        ]));

        if !self.dns.split_dns.is_empty() {
            for (domain, ns) in &self.dns.split_dns {
                lines.push(Line::from(vec![
                    Span::styled("  split     ", Style::new().fg(p.text_muted)),
                    Span::styled(format!("{domain} → {ns}"), Style::new().fg(p.text)),
                ]));
            }
        }
    }

    fn push_findings_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        // Group by severity: Critical > Warning > Info > Ok.
        const ORDER: &[&str] = &["critical", "warning", "info", "ok"];
        crate::ui::screens::findings::push_findings_grouped(
            lines,
            p,
            &self.findings,
            ORDER,
            crate::ui::screens::findings::severity_style_full,
            crate::ui::screens::findings::FindingWidths::TITLE_70,
        );
    }
}

impl crate::ui::screens::section_overview::SectionOverview for TailscaleContent {
    fn available(&self) -> bool {
        self.available
    }

    fn status_label(&self) -> &'static str {
        crate::ui::screens::section_overview::status_label_for(
            self.available,
            self.findings.iter().map(|f| f.severity.as_str()),
        )
    }

    fn detail(&self) -> Option<String> {
        if !self.available {
            return None;
        }
        Some(format!(
            "{} · {} peer(s)",
            if self.connected {
                "connected"
            } else {
                "disconnected"
            },
            self.peers.len()
        ))
    }

    fn findings_count(&self) -> usize {
        self.findings.len()
    }
}

impl crate::ui::screens::findings::Finding for TailscaleFindingEntry {
    fn severity(&self) -> &str {
        &self.severity
    }
    fn title(&self) -> &str {
        &self.title
    }
    fn detail(&self) -> Option<&str> {
        None
    }
    fn fix(&self) -> Option<&str> {
        self.fix.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::theme::CHARM;
    use ratatui::{Terminal, backend::TestBackend};

    fn sample_peers() -> Vec<PeerEntry> {
        vec![
            PeerEntry {
                name: "laptop".into(),
                ip_addresses: vec!["100.64.0.2".into()],
                online: true,
                exit_node: false,
            },
            PeerEntry {
                name: "exit-relay".into(),
                ip_addresses: vec!["100.64.0.3".into()],
                online: true,
                exit_node: true,
            },
            PeerEntry {
                name: "phone".into(),
                ip_addresses: vec!["100.64.0.4".into()],
                online: false,
                exit_node: false,
            },
        ]
    }

    fn sample_netcheck() -> (
        bool,
        Option<String>,
        Vec<DerpLatencyEntry>,
        bool,
        bool,
        bool,
        Vec<PortMapEntry>,
    ) {
        (
            true,
            Some("DERP-3".into()),
            vec![
                DerpLatencyEntry {
                    region: "nyc".into(),
                    latency_ms: 12.0,
                },
                DerpLatencyEntry {
                    region: "tok".into(),
                    latency_ms: 180.0,
                },
            ],
            true,
            false,
            true,
            vec![
                PortMapEntry {
                    name: "UPnP".into(),
                    open: true,
                },
                PortMapEntry {
                    name: "PMP".into(),
                    open: false,
                },
            ],
        )
    }

    fn sample_findings() -> Vec<TailscaleFindingEntry> {
        vec![
            TailscaleFindingEntry {
                id: "tailscale.connected".into(),
                severity: "ok".into(),
                title: "Connected to tailnet".into(),
                fix: None,
            },
            TailscaleFindingEntry {
                id: "tailscale.dns.nameservers".into(),
                severity: "warning".into(),
                title: "No custom DNS nameservers configured".into(),
                fix: Some("Add nameservers in the Tailscale admin console".into()),
            },
        ]
    }

    /// Render a content area to a string (snapshot pattern from ssh `keys_tab.rs`).
    fn render_to_string(content: &mut TailscaleContent, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| content.view(f, f.area(), CHARM)).unwrap();
        terminal.backend().to_string()
    }

    #[test]
    fn new_is_unavailable_and_empty() {
        let c = TailscaleContent::new();
        assert!(!c.available);
        assert!(c.peers.is_empty());
        assert!(c.findings.is_empty());
        assert!(!c.has_modal());
    }

    #[test]
    fn default_matches_new() {
        let from_new = TailscaleContent::new();
        let from_default = TailscaleContent::default();
        assert_eq!(from_new.available, from_default.available);
    }

    #[test]
    fn render_unavailable_when_not_available() {
        let mut c = TailscaleContent::new();
        let out = render_to_string(&mut c, 100, 24);
        assert!(
            out.contains("tailscale unavailable"),
            "degraded panel: {out}"
        );
    }

    #[test]
    fn render_status_panel() {
        let mut c = TailscaleContent::new();
        c.set_available(true);
        c.set_status(
            true,
            "my-host".into(),
            "example.com".into(),
            vec!["100.64.0.1".into()],
            Some("100.64.0.3".into()),
            true,
        );
        let out = render_to_string(&mut c, 100, 30);
        assert!(out.contains("connected"), "connected badge: {out}");
        assert!(out.contains("my-host"), "host name: {out}");
        assert!(out.contains("example.com"), "tailnet: {out}");
        assert!(out.contains("100.64.0.1"), "ip: {out}");
        assert!(out.contains("100.64.0.3"), "exit node: {out}");
    }

    #[test]
    fn render_peers_table() {
        let mut c = TailscaleContent::new();
        c.set_available(true);
        c.set_peers(sample_peers());
        let out = render_to_string(&mut c, 110, 40);
        assert!(out.contains("laptop"), "peer laptop: {out}");
        assert!(out.contains("exit-relay"), "exit peer: {out}");
        assert!(out.contains("phone"), "offline peer: {out}");
        assert!(out.contains("[exit]"), "exit tag: {out}");
    }

    #[test]
    fn render_netcheck() {
        let mut c = TailscaleContent::new();
        c.set_available(true);
        let (conn, region, lat, udp, ipv6, hair, pm) = sample_netcheck();
        c.set_netcheck(conn, region, lat, udp, ipv6, hair, pm);
        let out = render_to_string(&mut c, 110, 40);
        assert!(out.contains("DERP-3"), "preferred derp: {out}");
        assert!(out.contains("nyc"), "derp region nyc: {out}");
        assert!(out.contains("UPnP"), "port map UPnP: {out}");
        assert!(out.contains("reachable"), "coord reachable: {out}");
    }

    #[test]
    fn render_dns() {
        let mut c = TailscaleContent::new();
        c.set_available(true);
        c.set_dns(DnsInfo {
            magic_dns: true,
            nameservers: vec!["1.1.1.1".into()],
            search_domains: vec!["ts.example.com".into()],
            split_dns: Vec::new(),
        });
        let out = render_to_string(&mut c, 100, 30);
        assert!(out.contains("1.1.1.1"), "nameserver: {out}");
        assert!(out.contains("ts.example.com"), "search domain: {out}");
    }

    #[test]
    fn render_findings_grouped_by_severity() {
        let mut c = TailscaleContent::new();
        c.set_available(true);
        c.set_findings(sample_findings());
        let out = render_to_string(&mut c, 110, 44);
        assert!(out.contains("WARNING"), "severity group header: {out}");
        assert!(
            out.contains("No custom DNS nameservers"),
            "finding title: {out}"
        );
        assert!(
            out.contains("Add nameservers in the Tailscale admin console"),
            "fix hint: {out}"
        );
    }

    #[test]
    fn scroll_down_consumed_and_returns_none() {
        let mut c = TailscaleContent::new();
        c.set_available(true);
        assert!(c.handle_key(KeyCode::Down).is_none());
        assert_eq!(c.scroll, 1);
    }

    #[test]
    fn scroll_up_at_zero_stays_zero() {
        let mut c = TailscaleContent::new();
        c.set_available(true);
        c.handle_key(KeyCode::Up);
        assert_eq!(c.scroll, 0);
    }

    #[test]
    fn esc_returns_back_action() {
        let mut c = TailscaleContent::new();
        assert_eq!(c.handle_key(KeyCode::Esc), Some(Action::Back));
    }

    #[test]
    fn mouse_scroll_wheel_adjusts_scroll() {
        let mut c = TailscaleContent::new();
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
        let mut c = TailscaleContent::new();
        c.set_available(true);
        c.set_peers(sample_peers());
        let (conn, region, lat, udp, ipv6, hair, pm) = sample_netcheck();
        c.set_netcheck(conn, region, lat, udp, ipv6, hair, pm);
        c.set_findings(sample_findings());
        // 20x5 — well below comfortable, must not panic.
        let _ = render_to_string(&mut c, 20, 5);
    }

    #[test]
    fn empty_states_render_without_panic() {
        let mut c = TailscaleContent::new();
        c.set_available(true);
        let out = render_to_string(&mut c, 100, 40);
        assert!(out.contains("no peers discovered"), "empty peers: {out}");
        assert!(out.contains("no findings"), "empty findings: {out}");
    }
}
