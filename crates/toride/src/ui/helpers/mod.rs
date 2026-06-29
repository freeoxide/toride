pub mod anim;
pub mod color;
/// Formatting helpers: byte/duration pretty-printing, key-value line builders,
/// and the percentage-to-colour mapping.
pub mod format;

pub use anim::AnimatedFloats;
pub use color::{dim_color, lerp_color, lerp_f64, to_rgb};
pub use format::{
    color_kv_line, format_bytes, format_duration, kv_line, percent_color, yn_kv_line,
};
