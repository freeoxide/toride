use ratatui::style::{Color, Style};

/// All semantic colour slots — one `Palette` per theme, mirroring themes.js.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Palette {
    /// Base background
    pub bg: Color,
    /// Slightly lighter surface (header / footer bars)
    pub bg_alt: Color,
    /// Deeper inset (code blocks, panels)
    pub bg_inset: Color,
    /// Panel / card background
    pub panel: Color,
    /// Default border
    pub border: Color,
    /// Highlighted / focused border
    pub border_hi: Color,
    /// Primary body text
    pub text: Color,
    /// Secondary / dimmed text
    pub text_dim: Color,
    /// Muted / hint text
    pub text_muted: Color,
    /// Primary brand accent
    pub accent: Color,
    /// Secondary accent
    pub accent2: Color,
    /// Tertiary accent
    pub accent3: Color,
    pub ok: Color,
    pub warn: Color,
    pub err: Color,
    pub info: Color,
    /// Selection / hover background
    pub sel_bg: Color,
}

// ── Catppuccin Mocha ─────────────────────────────────────────────────────────
pub const CATPPUCCIN: Palette = Palette {
    bg: Color::Rgb(30, 30, 46),
    bg_alt: Color::Rgb(24, 24, 37),
    bg_inset: Color::Rgb(17, 17, 27),
    panel: Color::Rgb(35, 35, 54),
    border: Color::Rgb(69, 71, 90),
    border_hi: Color::Rgb(203, 166, 247),
    text: Color::Rgb(205, 214, 244),
    text_dim: Color::Rgb(147, 153, 178),
    text_muted: Color::Rgb(108, 112, 134),
    accent: Color::Rgb(203, 166, 247),  // mauve
    accent2: Color::Rgb(245, 194, 231), // pink
    accent3: Color::Rgb(148, 226, 213), // teal
    ok: Color::Rgb(166, 227, 161),
    warn: Color::Rgb(249, 226, 175),
    err: Color::Rgb(243, 139, 168),
    info: Color::Rgb(137, 180, 250),
    sel_bg: Color::Rgb(49, 50, 68),
};

// ── Tokyo Night ───────────────────────────────────────────────────────────────
pub const TOKYO_NIGHT: Palette = Palette {
    bg: Color::Rgb(26, 27, 38),
    bg_alt: Color::Rgb(22, 22, 30),
    bg_inset: Color::Rgb(15, 15, 23),
    panel: Color::Rgb(31, 35, 53),
    border: Color::Rgb(59, 66, 97),
    border_hi: Color::Rgb(122, 162, 247),
    text: Color::Rgb(192, 202, 245),
    text_dim: Color::Rgb(154, 165, 206),
    text_muted: Color::Rgb(86, 95, 137),
    accent: Color::Rgb(122, 162, 247),
    accent2: Color::Rgb(187, 154, 247),
    accent3: Color::Rgb(125, 207, 255),
    ok: Color::Rgb(158, 206, 106),
    warn: Color::Rgb(224, 175, 104),
    err: Color::Rgb(247, 118, 142),
    info: Color::Rgb(125, 207, 255),
    sel_bg: Color::Rgb(40, 52, 87),
};

// ── Rosé Pine ─────────────────────────────────────────────────────────────────
pub const ROSE_PINE: Palette = Palette {
    bg: Color::Rgb(25, 23, 36),
    bg_alt: Color::Rgb(31, 29, 46),
    bg_inset: Color::Rgb(22, 20, 31),
    panel: Color::Rgb(38, 35, 58),
    border: Color::Rgb(64, 61, 82),
    border_hi: Color::Rgb(235, 188, 186),
    text: Color::Rgb(224, 222, 244),
    text_dim: Color::Rgb(144, 140, 170),
    text_muted: Color::Rgb(110, 106, 134),
    accent: Color::Rgb(235, 188, 186),  // rose
    accent2: Color::Rgb(196, 167, 231), // iris
    accent3: Color::Rgb(156, 207, 216), // foam
    ok: Color::Rgb(163, 190, 140),
    warn: Color::Rgb(246, 193, 119),
    err: Color::Rgb(235, 111, 146),
    info: Color::Rgb(156, 207, 216),
    sel_bg: Color::Rgb(42, 39, 63),
};

// ── Charm ─────────────────────────────────────────────────────────────────────
pub const CHARM: Palette = Palette {
    bg: Color::Rgb(23, 19, 32),
    bg_alt: Color::Rgb(16, 16, 26),
    bg_inset: Color::Rgb(10, 10, 18),
    panel: Color::Rgb(29, 24, 48),
    border: Color::Rgb(58, 46, 84),
    border_hi: Color::Rgb(255, 95, 203),
    text: Color::Rgb(244, 240, 255),
    text_dim: Color::Rgb(182, 168, 214),
    text_muted: Color::Rgb(107, 95, 138),
    accent: Color::Rgb(255, 95, 203),   // hot-pink
    accent2: Color::Rgb(162, 119, 255), // violet
    accent3: Color::Rgb(98, 225, 255),  // cyan
    ok: Color::Rgb(124, 227, 139),
    warn: Color::Rgb(255, 203, 107),
    err: Color::Rgb(255, 95, 135),
    info: Color::Rgb(98, 225, 255),
    sel_bg: Color::Rgb(42, 31, 68),
};

// ── Nord ──────────────────────────────────────────────────────────────────────
pub const NORD: Palette = Palette {
    bg: Color::Rgb(46, 52, 64),
    bg_alt: Color::Rgb(39, 44, 54),
    bg_inset: Color::Rgb(33, 37, 46),
    panel: Color::Rgb(59, 66, 82),
    border: Color::Rgb(67, 76, 94),
    border_hi: Color::Rgb(136, 192, 208),
    text: Color::Rgb(236, 239, 244),
    text_dim: Color::Rgb(216, 222, 233),
    text_muted: Color::Rgb(123, 136, 161),
    accent: Color::Rgb(136, 192, 208),
    accent2: Color::Rgb(129, 161, 193),
    accent3: Color::Rgb(180, 142, 173),
    ok: Color::Rgb(163, 190, 140),
    warn: Color::Rgb(235, 203, 139),
    err: Color::Rgb(191, 97, 106),
    info: Color::Rgb(129, 161, 193),
    sel_bg: Color::Rgb(67, 76, 94),
};

// ── Gruvbox Dark ──────────────────────────────────────────────────────────────
pub const GRUVBOX: Palette = Palette {
    bg: Color::Rgb(40, 40, 40),
    bg_alt: Color::Rgb(29, 32, 33),
    bg_inset: Color::Rgb(23, 23, 23),
    panel: Color::Rgb(50, 48, 47),
    border: Color::Rgb(80, 73, 69),
    border_hi: Color::Rgb(250, 189, 47),
    text: Color::Rgb(235, 219, 178),
    text_dim: Color::Rgb(168, 153, 132),
    text_muted: Color::Rgb(124, 111, 100),
    accent: Color::Rgb(250, 189, 47),
    accent2: Color::Rgb(254, 128, 25),
    accent3: Color::Rgb(142, 192, 124),
    ok: Color::Rgb(184, 187, 38),
    warn: Color::Rgb(250, 189, 47),
    err: Color::Rgb(251, 73, 52),
    info: Color::Rgb(131, 165, 152),
    sel_bg: Color::Rgb(60, 56, 54),
};

// ── Theme enum ────────────────────────────────────────────────────────────────

impl Default for Palette {
    fn default() -> Self {
        CHARM
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Theme {
    Catppuccin,
    TokyoNight,
    RosePine,
    #[default]
    Charm,
    Nord,
    Gruvbox,
}

impl Theme {
    #[must_use]
    pub fn palette(self) -> &'static Palette {
        match self {
            Theme::Catppuccin => &CATPPUCCIN,
            Theme::TokyoNight => &TOKYO_NIGHT,
            Theme::RosePine => &ROSE_PINE,
            Theme::Charm => &CHARM,
            Theme::Nord => &NORD,
            Theme::Gruvbox => &GRUVBOX,
        }
    }

    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Theme::Catppuccin => "Catppuccin Mocha",
            Theme::TokyoNight => "Tokyo Night",
            Theme::RosePine => "Rosé Pine",
            Theme::Charm => "Charm",
            Theme::Nord => "Nord",
            Theme::Gruvbox => "Gruvbox Dark",
        }
    }

    #[must_use]
    pub fn all() -> &'static [Theme] {
        &[
            Theme::Catppuccin,
            Theme::TokyoNight,
            Theme::RosePine,
            Theme::Charm,
            Theme::Nord,
            Theme::Gruvbox,
        ]
    }

    /// Resolve a theme from its [`label`](Self::label), case-insensitively.
    ///
    /// Used by the persistence layer to map the `theme = "<label>"` value stored
    /// in `config.toml` back to a [`Theme`] variant. Returns `None` for an
    /// unknown / unrecognized label so the caller can fall back to the default
    /// rather than silently coercing a corrupt entry.
    #[must_use]
    pub fn from_label(label: &str) -> Option<Theme> {
        Theme::all()
            .iter()
            .copied()
            .find(|t| t.label().eq_ignore_ascii_case(label))
    }
}

// ── Keybinding style constants ────────────────────────────────────────────────

/// Background color for keyboard shortcut badges.
pub const KEY_BG: Color = Color::Rgb(32, 26, 50);

impl Palette {
    /// Style for keyboard shortcut badges (e.g. " ↵ ", " q ").
    #[must_use]
    pub fn key_style(self) -> Style {
        Style::new().fg(self.text).bg(KEY_BG)
    }

    /// Style for label text next to keybinding badges.
    #[must_use]
    pub fn label_style(self) -> Style {
        Style::new().fg(self.text_muted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_theme_is_charm() {
        assert_eq!(Theme::default(), Theme::Charm);
    }

    #[test]
    fn all_returns_six_themes_in_order() {
        let all = Theme::all();
        assert_eq!(all.len(), 6);
        assert_eq!(all[0], Theme::Catppuccin);
        assert_eq!(all[1], Theme::TokyoNight);
        assert_eq!(all[2], Theme::RosePine);
        assert_eq!(all[3], Theme::Charm);
        assert_eq!(all[4], Theme::Nord);
        assert_eq!(all[5], Theme::Gruvbox);
    }

    #[test]
    fn each_palette_bg_is_rgb() {
        for &theme in Theme::all() {
            let palette = theme.palette();
            assert!(
                matches!(palette.bg, Color::Rgb(_, _, _)),
                "{theme:?}.palette().bg is not Rgb"
            );
        }
    }

    #[test]
    fn label_non_empty_for_all_themes() {
        for &theme in Theme::all() {
            let label = theme.label();
            assert!(
                !label.is_empty(),
                "{theme:?}.label() returned an empty string"
            );
        }
    }

    #[test]
    fn key_style_and_label_style_differ() {
        for &theme in Theme::all() {
            let palette = theme.palette();
            let ks = palette.key_style();
            let ls = palette.label_style();
            assert_ne!(
                ks, ls,
                "{theme:?}: key_style and label_style should be different"
            );
        }
    }

    #[test]
    fn from_label_round_trips_every_theme() {
        for &theme in Theme::all() {
            assert_eq!(Theme::from_label(theme.label()), Some(theme));
        }
    }

    #[test]
    fn from_label_is_case_insensitive() {
        assert_eq!(Theme::from_label("charm"), Some(Theme::Charm));
        assert_eq!(Theme::from_label("TOKYO NIGHT"), Some(Theme::TokyoNight));
    }

    #[test]
    fn from_label_returns_none_for_unknown() {
        assert!(Theme::from_label("nonexistent").is_none());
        assert!(Theme::from_label("").is_none());
    }
}
