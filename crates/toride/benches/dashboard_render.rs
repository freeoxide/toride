mod common;

use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use crossterm::event::{KeyModifiers, MouseEvent, MouseEventKind};
use ratatui::{Terminal, backend::TestBackend};

use common::{SIZES, fixed_dashboard, render_palette};
use toride::ui::screens::AppScreen;

fn dashboard_render(c: &mut Criterion) {
    let mut group = c.benchmark_group("dashboard_render");
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
        let mut terminal = Terminal::new(TestBackend::new(width, height))
            .expect("TestBackend terminal construction cannot fail");
        terminal
            .draw(|f| screen.view(f, palette))
            .expect("TestBackend draw cannot fail");

        group.bench_function(format!("no_change_sweep_{width}x{height}"), |b| {
            b.iter(|| {
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
