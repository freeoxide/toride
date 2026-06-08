#![expect(
    clippy::must_use_candidate,
    reason = "constructors and pure fns in TUI scaffolding"
)]
#![expect(
    clippy::many_single_char_names,
    reason = "color math uses r/g/b/t variable names"
)]
#![warn(missing_docs)]

pub mod action;
pub mod app;
pub mod config;
pub mod data;
pub mod navigation;
pub mod persistence;
pub mod prediction;
pub mod ssh_convert;
pub mod ssh_data;
pub mod status_collector;
pub use toride_status as status;
pub mod ui;
pub mod version;
