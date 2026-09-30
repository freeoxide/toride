//! F01 kernel bench: full-frame Dashboard render cost.
//!
//! Measures the per-frame work of rendering the Dashboard view — the code
//! `App::view` executes every animation tick on `Screen::Dashboard`
//! (`current_screen().view(frame, palette)`): shell chrome, stat cards, the
//! managed-services grid, storage/network gauges, and the top-processes list,
//! plus the buffer diff `Terminal::draw` runs against the previous frame.
//!
//! Hermetic by construction: the dashboard state is the fixed fixture from
//! `common` (no collectors, no host probes — `common::fixed_dashboard`), the
//! backend is ratatui's `TestBackend`, and the palette pins
//! `reduced_motion` so the frame is byte-identical across iterations.
//!
//! `App::view` itself is crate-private (`pub(super)`), so the bench drives
//! the identical public dispatch target (`AppScreen::view`) with the same
//! palette `App::view` bakes each frame (see `common::render_palette`).

mod common;

use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use ratatui::{Terminal, backend::TestBackend};

use common::{fixed_dashboard, render_palette};
use toride::ui::screens::AppScreen;

fn dashboard_render(c: &mut Criterion) {
    let mut group = c.benchmark_group("dashboard_render");
    // Tuned so the two-size suite finishes in a few seconds: ~0.5s warm-up +
    // ~2s measurement per size is ample for a sub-millisecond kernel.
    group
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2))
        .sample_size(20);

    for (width, height) in common::SIZES {
        let mut screen = fixed_dashboard();
        let palette = render_palette();
        let mut terminal = Terminal::new(TestBackend::new(width, height))
            .expect("TestBackend terminal construction cannot fail");
        group.bench_function(format!("{width}x{height}"), |b| {
            b.iter(|| {
                // A steady-state frame: render into the back buffer and diff
                // against the previous frame, exactly like the App tick loop.
                terminal
                    .draw(|f| screen.view(f, palette))
                    .expect("TestBackend draw cannot fail");
            });
        });
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = dashboard_render
}
criterion_main! { benches }
