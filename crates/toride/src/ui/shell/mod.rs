//! Reusable application "shell": a top header bar, a left sidebar, a main
//! content area, and a bottom footer key-bar.
//!
//! [`shell_layout`] splits a full-frame [`Rect`] into the four regions; the
//! [`header`], [`sidebar`] and [`footer`] submodules render the chrome, while
//! the calling screen fills [`ShellAreas::content`].

pub mod footer;
pub mod header;
pub mod sidebar;

pub use footer::render_footer;
pub use header::{HeaderData, render_header};
pub use sidebar::{SIDEBAR_W, SIDEBAR_W_COLLAPSED, Sidebar};

use ratatui::layout::{Constraint, Layout, Rect};

/// Header height (top border + content row + bottom border).
pub const HEADER_H: u16 = 3;
/// Footer height (top border + content row + bottom border).
pub const FOOTER_H: u16 = 3;

/// The four regions of the shell.
#[derive(Clone, Copy, Debug)]
pub struct ShellAreas {
    /// Top header bar.
    pub header: Rect,
    /// Left sidebar.
    pub sidebar: Rect,
    /// Main content area (right of the sidebar, between header and footer).
    pub content: Rect,
    /// Bottom footer key-bar.
    pub footer: Rect,
}

/// Split `area` into header / [sidebar | content] / footer regions.
#[must_use]
pub fn shell_layout(area: Rect, sidebar_width: u16) -> ShellAreas {
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(HEADER_H),
        Constraint::Fill(1),
        Constraint::Length(FOOTER_H),
    ])
    .areas(area);

    let [sidebar, content] =
        Layout::horizontal([Constraint::Length(sidebar_width), Constraint::Fill(1)]).areas(body);

    ShellAreas {
        header,
        sidebar,
        content,
        footer,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_partitions_full_area() {
        let area = Rect::new(0, 0, 100, 30);
        let s = shell_layout(area, 30);
        assert_eq!(s.header.height, HEADER_H);
        assert_eq!(s.footer.height, FOOTER_H);
        assert_eq!(s.sidebar.width, 30);
        assert_eq!(s.content.width, 70);
        // Body rows are sandwiched between header and footer.
        assert_eq!(s.content.y, HEADER_H);
        assert_eq!(s.content.height, 30 - HEADER_H - FOOTER_H);
    }
}
