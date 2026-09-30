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
//!
//! The `mouse_sweep` group extends the rig for the F01 draw-gating fix: a
//! full-height no-change mouse sweep across the content pane (one motion
//! event per row below the header — 20 events at 80x24, 56 at 200x60) now
//! costs only the hover hit-tests (`AppScreen::handle_mouse` returning no
//! action), while before the gating each motion event also paid the full
//! `dashboard_render` frame below — compare one sweep against that
//! per-frame number times its event count.

mod common;

use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use crossterm::event::{KeyModifiers, MouseEvent, MouseEventKind};
use ratatui::{Terminal, backend::TestBackend};

use common::{SIZES, fixed_dashboard, render_palette};
use toride::ui::screens::AppScreen;

fn dashboard_render(c: &mut Criterion) {
    let mut group = c.benchmark_group("dashboard_render");
    // Tuned so the two-size suite finishes in a few seconds: ~0.5s warm-up +
    // ~2s measurement per size is ample for a sub-millisecond kernel.
    group
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2))
        .sample_size(20);

    for (width, height) in SIZES {
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

fn dashboard_mouse_sweep(c: &mut Criterion) {
    let mut group = c.benchmark_group("dashboard_mouse_sweep");
    group
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2))
        .sample_size(20);

    for (width, height) in SIZES {
        let mut screen = fixed_dashboard();
        let palette = render_palette();
        // One frame so the shell's hit-test rects (header gauges, sidebar)
        // exist — exactly the steady state a real session sweeps over.
        let mut terminal = Terminal::new(TestBackend::new(width, height))
            .expect("TestBackend terminal construction cannot fail");
        terminal
            .draw(|f| screen.view(f, palette))
            .expect("TestBackend draw cannot fail");

        group.bench_function(format!("no_change_sweep_{width}x{height}"), |b| {
            b.iter(|| {
                // A vertical sweep through the content pane (header rows
                // skipped so no gauge hitbox is crossed, center column so
                // the sidebar is never entered): one motion event per row
                // below the header, none changing hover state. After the F01
                // gating each event costs only the hit-tests (no action
                // returned, no frame rendered); before it, every event ALSO
                // paid the full frame measured by `dashboard_render` above.
                for row in 4..height {
                    let action = screen.handle_mouse(MouseEvent {
                        kind: MouseEventKind::Moved,
                        column: width / 2,
                        row,
                        modifiers: KeyModifiers::empty(),
                    });
                    std::hint::black_box(action);
                }
            });
        });
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = dashboard_render, dashboard_mouse_sweep
}
criterion_main! { benches }
