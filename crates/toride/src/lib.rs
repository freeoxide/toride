#![expect(clippy::must_use_candidate, reason = "constructors and pure fns in TUI scaffolding")]
#![expect(clippy::missing_errors_doc, reason = "error docs added incrementally")]
#![expect(clippy::many_single_char_names, reason = "color math uses r/g/b/t variable names")]

pub mod action;
pub mod app;
pub use toride_status as status;
pub mod ui;
