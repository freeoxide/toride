//! Shared panel rendering helper.

use ratatui::{
    Frame,
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
    text::Span,
    widgets::{Block, BorderType, Borders, Padding, Widget},
};

use crate::ui::theme::Palette;

/// A render target: either the live [`Frame`] or an offscreen [`Buffer`]
/// backing a cached panel render.
pub trait RenderBuf {
    /// Render `widget` into the target at `area`.
    fn place<W: Widget>(&mut self, widget: W, area: Rect);
    /// The underlying cell buffer.
    fn cells(&mut self) -> &mut Buffer;
}

impl RenderBuf for Frame<'_> {
    fn place<W: Widget>(&mut self, widget: W, area: Rect) {
        self.render_widget(widget, area);
    }

    fn cells(&mut self) -> &mut Buffer {
        self.buffer_mut()
    }
}

impl RenderBuf for Buffer {
    fn place<W: Widget>(&mut self, widget: W, area: Rect) {
        widget.render(area, self);
    }

    fn cells(&mut self) -> &mut Buffer {
        self
    }
}

/// Render a rounded panel with an optional title and return the inner content area.
///
/// Pass `None` for `title` to render an untitled panel.
pub fn render_panel<T: RenderBuf + ?Sized>(
    frame: &mut T,
    area: Rect,
    title: Option<&str>,
    title_color: Color,
    border_color: Color,
    bg: Color,
) -> Rect {
    let mut block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(border_color))
        .style(Style::new().bg(bg))
        .padding(Padding::horizontal(1));

    if let Some(title) = title {
        block = block.title(Span::styled(
            title.to_string(),
            Style::new().fg(title_color).bold(),
        ));
    }

    let inner = block.inner(area);
    frame.place(block, area);
    inner
}

/// Render a titled rounded panel using the focused/unfocused border convention.
///
/// When `focused` is true the border uses `p.border_hi`; otherwise it uses
/// `title_color`. The background is `p.bg`.
pub fn render_titled_panel<T: RenderBuf + ?Sized>(
    frame: &mut T,
    area: Rect,
    p: Palette,
    title: &str,
    title_color: Color,
    focused: bool,
) -> Rect {
    let border_color = if focused { p.border_hi } else { title_color };
    render_panel(frame, area, Some(title), title_color, border_color, p.bg)
}

/// Render a titled rounded panel with a custom background color.
///
/// Same border convention as [`render_titled_panel`] but allows a custom `bg`.
pub fn render_titled_panel_bg<T: RenderBuf + ?Sized>(
    frame: &mut T,
    area: Rect,
    p: Palette,
    title: Option<&str>,
    title_color: Color,
    bg: Color,
    focused: bool,
) -> Rect {
    let border_color = if focused { p.border_hi } else { title_color };
    render_panel(frame, area, title, title_color, border_color, bg)
}
