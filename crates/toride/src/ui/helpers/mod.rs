pub mod anim;
pub mod color;
pub mod format;

pub use anim::AnimatedFloats;
pub use color::{dim_color, lerp_color, to_rgb};
pub use format::{
    color_kv_line, format_bytes, format_duration, kv_line, percent_color, yn_kv_line,
};
