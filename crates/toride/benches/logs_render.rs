//! Logs-section render cost (tui-16): a fixture `LogSource` with a 200-line
//! tail rendered through `TestBackend` at both bench terminal sizes.
//!
//! Every `view` deep-clones the active source across the conversion seam,
//! builds the full owned-line list, then clones each visible row again; this
//! bench pins that per-frame cost before the borrow-and-window rework.

mod common;

use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use ratatui::{Terminal, backend::TestBackend};

use common::{SIZES, render_palette};
use toride::logs_data::LogSource;
use toride::ui::screens::logs::LogsContent;

fn fixture_source() -> LogSource {
    LogSource {
        name: "auth.log".into(),
        path: "/var/log/auth.log".into(),
        exists: true,
        size_bytes: 128 * 1024,
        mtime: Some("2026-10-13 10:00".into()),
        line_count: 200,
        lines: (1..=200)
            .map(|n| {
                format!("Oct 13 10:00:{:02} ed25519 sshd[4242]: accepted publickey for root from 203.0.113.10 port {n:04} ssh2", n % 60)
            })
            .collect(),
    }
}

fn logs_render(c: &mut Criterion) {
    let mut group = c.benchmark_group("logs_render");
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(2));
    group.sample_size(20);

    for (width, height) in SIZES {
        let mut content = LogsContent::new();
        content.set_logs(vec![fixture_source()]);
        let palette = render_palette();
        let mut terminal = Terminal::new(TestBackend::new(width, height))
            .expect("TestBackend terminal construction cannot fail");

        group.bench_function(format!("{width}x{height}"), |b| {
            b.iter(|| {
                terminal
                    .draw(|f| content.view(f, f.area(), palette))
                    .expect("TestBackend draw cannot fail");
            });
        });
    }
    group.finish();
}

criterion_group!(benches, logs_render);
criterion_main!(benches);
