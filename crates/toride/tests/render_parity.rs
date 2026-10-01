#[path = "../benches/common/mod.rs"]
mod common;

use common::{SIZES, fixed_dashboard, render_frame};
use ratatui::buffer::Buffer;

#[test]
fn unchanged_dashboard_state_renders_identical_buffers() {
    for (width, height) in SIZES {
        let mut screen = fixed_dashboard();

        let first: Buffer = render_frame(&mut screen, width, height);
        assert!(
            !first.area.is_empty(),
            "fixture frame at {width}x{height} must cover the terminal area"
        );
        let second: Buffer = render_frame(&mut screen, width, height);

        assert_eq!(
            first, second,
            "unchanged dashboard state rendered different buffers at {width}x{height}"
        );
    }
}

#[test]
fn fixture_renders_live_dashboard_content() {
    let mut screen = fixed_dashboard();
    let frame = render_frame(&mut screen, 200, 60);
    let text: String = frame
        .content
        .iter()
        .map(|cell| cell.symbol().to_string())
        .collect();
    for expected in ["toride", "MANAGED SERVICES", "TOP PROCESSES", "firefox"] {
        assert!(
            text.contains(expected),
            "live fixture frame must contain {expected:?} (got {text:?})"
        );
    }
    assert!(
        !text.contains("collecting system status"),
        "fixture must not render the cold-start sentinel"
    );
}
